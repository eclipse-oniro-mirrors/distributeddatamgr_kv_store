/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "process_notifier.h"

#include "db_errno.h"
#include "kv_store_errno.h"
#include "runtime_context.h"
namespace DistributedDB {
ProcessNotifier::ProcessNotifier(ICloudSyncer *syncer)
    : syncer_(syncer)
{
    RefObject::IncObjRef(syncer_);
}

ProcessNotifier::~ProcessNotifier()
{
    RefObject::DecObjRef(syncer_);
}

void ProcessNotifier::Init(const std::vector<std::string> &tableName,
    const std::vector<std::string> &devices, const std::vector<std::string> &users)
{
    std::lock_guard<std::mutex> autoLock(processMutex_);
    InitSyncProcess(tableName, syncProcess_);
    for (const auto &user : users) {
        SyncProcess syncProcess;
        InitSyncProcess(tableName, syncProcess);
        multiSyncProcess_[user] = syncProcess;
    }
    devices_ = devices;
}

void ProcessNotifier::InitSyncProcess(const std::vector<std::string> &tableName, SyncProcess &syncProcess)
{
    syncProcess.errCode = OK;
    syncProcess.process = ProcessStatus::PROCESSING;
    for (const auto &table: tableName) {
        TableProcessInfo tableInfo;
        tableInfo.process = ProcessStatus::PREPARED;
        syncProcess.tableProcess[table] = tableInfo;
    }
}

void ProcessNotifier::UpdateUploadRetryInfo(const ICloudSyncer::InnerProcessInfo &process)
{
    if (process.tableName.empty()) {
        return;
    }
    std::lock_guard<std::mutex> autoLock(processMutex_);
    processRetryInfo_[process.tableName] = process.retryInfo.uploadBatchRetryCount;
}

void ProcessNotifier::UpdateProcess(const ICloudSyncer::InnerProcessInfo &process)
{
    if (process.tableName.empty()) {
        return;
    }
    std::lock_guard<std::mutex> autoLock(processMutex_);
    auto &syncProcess = user_.empty() ? syncProcess_ : multiSyncProcess_[user_];
    syncProcess.tableProcess[process.tableName].process = process.tableStatus;
    UpdateErrorInfoIfNeed(process.innerCloudErrorInfo, syncProcess.cloudErrorInfo);
    if (process.downLoadInfo.batchIndex != 0u) {
        LOGD("[ProcessNotifier] update download process index: %" PRIu32, process.downLoadInfo.batchIndex);
        syncProcess.tableProcess[process.tableName].downLoadInfo = process.downLoadInfo;
    }
    if (process.upLoadInfo.batchIndex != 0u) {
        LOGD("[ProcessNotifier] update upload process index: %" PRIu32, process.upLoadInfo.batchIndex);
        syncProcess.tableProcess[process.tableName].upLoadInfo = process.upLoadInfo;
    }
}

void ProcessNotifier::UpdateErrorInfoIfNeed(CloudErrorInfo source, CloudErrorInfo &target) const
{
    if (target.cloudAction == CloudErrorAction::ACTION_DEFAULT) {
        target.cloudAction = source.cloudAction;
    }
    if (!source.errorMessage.empty() && target.errorMessage.empty()) {
        target.errorMessage = source.errorMessage;
    }
    if (source.detailCode != 0 && target.detailCode == 0) {
        // stamp the maintained stage into stage-less internal detail codes automatically
        target.detailCode = StampStageLocked(source.detailCode);
    }
}

// the report follows the latest task-level error, with one exception: when the target already
// holds an external detail it belongs to the batch failure that ended the task (a hard failure
// aborts the flow, nothing follows it before the endgame), so it beats the internal composition
// of that same errCode; a source carrying its own external detail (e.g. an unlock failure with
// the adapter detail) still wins as the latest error
void ProcessNotifier::UpdateErrorInfoToLatest(const CloudErrorInfo &source, CloudErrorInfo &target) const
{
    if (target.cloudAction == CloudErrorAction::ACTION_DEFAULT) {
        target.cloudAction = source.cloudAction;
    }
    if (IsExternalDetailCode(target.detailCode) && !IsExternalDetailCode(source.detailCode)) {
        return; // keep the accumulated external detail of the error that ended the task
    }
    target.errorMessage = source.errorMessage;
    target.detailCode = StampStageLocked(source.detailCode);
}

void ProcessNotifier::SetStage(SyncStage stage)
{
    std::lock_guard<std::mutex> autoLock(processMutex_);
    stage_ = stage;
}

SyncStage ProcessNotifier::GetStage() const
{
    std::lock_guard<std::mutex> autoLock(processMutex_);
    return stage_;
}

uint32_t ProcessNotifier::StampStage(uint32_t detailCode)
{
    std::lock_guard<std::mutex> autoLock(processMutex_);
    return StampStageLocked(detailCode);
}

uint32_t ProcessNotifier::StampStageLocked(uint32_t detailCode) const
{
    // the check is required here: codes whose stage bits are already set (stamped internal
    // codes, or external numbers occupying those bits) must not get the stages or-ed
    // together; a zero code means "no detail" and stays zero
    if (!NeedsStageStamp(detailCode)) {
        return detailCode;
    }
    return detailCode | (static_cast<uint32_t>(stage_) << DETAIL_CODE_STAGE_SHIFT);
}

void ProcessNotifier::FillProcessInfo(const ICloudSyncer::CloudTaskInfo &taskInfo,
    const ICloudSyncer::InnerProcessInfo &process)
{
    syncProcess_.errCode = TransferDBErrno(taskInfo.errCode, true);
    syncProcess_.process = taskInfo.status;
    multiSyncProcess_[user_].errCode = TransferDBErrno(taskInfo.errCode, true);
    multiSyncProcess_[user_].process = taskInfo.status;
    if (taskInfo.errCode == E_OK) {
        // final result is OK, clear accumulated error detail before notifying
        ResetErrorDetail(syncProcess_.cloudErrorInfo);
        ResetErrorDetail(multiSyncProcess_[user_].cloudErrorInfo);
    }
    CloudErrorInfo errorInfo;
    errorInfo.errorMessage = taskInfo.errorMessage;
    // the stage bits are stamped here when the error detail is written into the CloudErrorInfo
    errorInfo.detailCode = StampStageLocked(taskInfo.detailCode);
    UpdateErrorInfoToLatest(errorInfo, syncProcess_.cloudErrorInfo);
    UpdateErrorInfoToLatest(errorInfo, multiSyncProcess_[user_].cloudErrorInfo);
    UpdateUploadInfoIfNeeded(process);
}

void ProcessNotifier::ResetErrorDetail(CloudErrorInfo &errorInfo)
{
    errorInfo.detailCode = 0u;
    errorInfo.errorMessage.clear();
}

void ProcessNotifier::NotifyProcess(const ICloudSyncer::CloudTaskInfo &taskInfo,
    const ICloudSyncer::InnerProcessInfo &process, bool notifyWhenError)
{
    UpdateProcess(process);
    std::map<std::string, SyncProcess> currentProcess;
    {
        std::lock_guard<std::mutex> autoLock(processMutex_);
        if (!notifyWhenError && taskInfo.errCode != E_OK) {
            return;
        }
        FillProcessInfo(taskInfo, process);
        if (user_.empty()) {
            for (const auto &device : devices_) {
                currentProcess[device] = syncProcess_; // make sure only one device
            }
        } else {
            currentProcess = multiSyncProcess_;
        }
    }
    SyncProcessCallback callback = taskInfo.callback;
    if (!callback) {
        LOGD("[ProcessNotifier] task hasn't callback");
        return;
    }
    ICloudSyncer *syncer = syncer_;
    if (syncer == nullptr) {
        LOGW("[ProcessNotifier] cancel notify because syncer is nullptr");
        return; // should not happen
    }
    RefObject::IncObjRef(syncer);
    auto id = syncer->GetIdentify();
    int errCode = RuntimeContext::GetInstance()->ScheduleQueuedTask(id, [callback, currentProcess, syncer]() {
        LOGD("[ProcessNotifier] begin notify process");
        if (syncer->IsClosed()) {
            LOGI("[ProcessNotifier] db has closed, process return");
            RefObject::DecObjRef(syncer);
            return;
        }
        callback(currentProcess);
        RefObject::DecObjRef(syncer);
        LOGD("[ProcessNotifier] notify process finish");
    });
    if (errCode != E_OK) {
        LOGW("[ProcessNotifier] schedule notify process failed %d", errCode);
        RefObject::DecObjRef(syncer);
    }
}

std::vector<std::string> ProcessNotifier::GetDevices() const
{
    return devices_;
}

uint32_t ProcessNotifier::GetUploadBatchIndex(const std::string &tableName) const
{
    std::lock_guard<std::mutex> autoLock(processMutex_);
    auto &syncProcess = IsMultiUser() ? multiSyncProcess_.at(user_) : syncProcess_;
    if (syncProcess.tableProcess.find(tableName) == syncProcess.tableProcess.end()) {
        return 0u;
    }
    return syncProcess.tableProcess.at(tableName).upLoadInfo.batchIndex;
}

void ProcessNotifier::ResetUploadBatchIndex(const std::string &tableName)
{
    if (tableName.empty()) {
        return;
    }
    std::lock_guard<std::mutex> autoLock(processMutex_);
    auto &syncProcess = IsMultiUser() ? multiSyncProcess_.at(user_) : syncProcess_;
    if (syncProcess.tableProcess.find(tableName) == syncProcess.tableProcess.end()) {
        LOGW("[ProcessNotifier] The specified table was not found when reset UploadBatchIndex");
        return;
    }
    if (syncProcess.tableProcess[tableName].upLoadInfo.total == 0) {
        syncProcess.tableProcess[tableName].upLoadInfo.batchIndex = 0;
    }
}

void ProcessNotifier::GetLastUploadInfo(const std::string &tableName, Info &lastUploadInfo,
    ICloudSyncer::UploadRetryInfo &retryInfo) const
{
    Info lastInfo;
    std::lock_guard<std::mutex> autoLock(processMutex_);
    auto &syncProcess = IsMultiUser() ? multiSyncProcess_.at(user_) : syncProcess_;
    if (processRetryInfo_.find(tableName) != processRetryInfo_.end()) {
        retryInfo.uploadBatchRetryCount = processRetryInfo_.at(tableName);
    }
    if (syncProcess.tableProcess.find(tableName) != syncProcess_.tableProcess.end()) {
        lastInfo = syncProcess.tableProcess.at(tableName).upLoadInfo;
    }
    lastUploadInfo = lastInfo;
}

void ProcessNotifier::GetDownloadInfoByTableName(ICloudSyncer::InnerProcessInfo &process)
{
    if (process.tableName.empty()) {
        return;
    }
    std::lock_guard<std::mutex> autoLock(processMutex_);
    SyncProcess syncProcess;
    if (user_.empty()) {
        syncProcess = syncProcess_;
    } else {
        syncProcess = multiSyncProcess_[user_];
    }

    if (syncProcess.tableProcess.find(process.tableName) != syncProcess.tableProcess.end()) {
        process.downLoadInfo = syncProcess.tableProcess[process.tableName].downLoadInfo;
    }
}

void ProcessNotifier::SetUser(const std::string &user)
{
    user_ = user;
}

void ProcessNotifier::SetAllTableFinish()
{
    std::lock_guard<std::mutex> autoLock(processMutex_);
    for (auto &item : syncProcess_.tableProcess) {
        item.second.process = ProcessStatus::FINISHED;
    }
    for (auto &syncProcess : multiSyncProcess_) {
        for (auto &item : syncProcess.second.tableProcess) {
            item.second.process = ProcessStatus::FINISHED;
        }
    }
}

bool ProcessNotifier::IsMultiUser() const
{
    return !user_.empty() && multiSyncProcess_.find(user_) != multiSyncProcess_.end();
}

std::map<std::string, TableProcessInfo> ProcessNotifier::GetCurrentTableProcess() const
{
    std::lock_guard<std::mutex> autoLock(processMutex_);
    return syncProcess_.tableProcess;
}

void ProcessNotifier::UpdateUploadInfoIfNeeded(const ICloudSyncer::InnerProcessInfo &process)
{
    if (process.tableName.empty()) {
        return;
    }
    auto &syncProcess = IsMultiUser() ? multiSyncProcess_.at(user_) : syncProcess_;
    auto tableProcess = syncProcess.tableProcess.find(process.tableName);
    auto retryInfo = processRetryInfo_.find(process.tableName);
    if (tableProcess != syncProcess.tableProcess.end() && retryInfo != processRetryInfo_.end()) {
        uint32_t downloadOpCount = process.retryInfo.downloadBatchOpCount;
        uint32_t uploadRetryCount = retryInfo->second;
        tableProcess->second.upLoadInfo.successCount += std::min(uploadRetryCount, downloadOpCount);
        processRetryInfo_.erase(retryInfo);
    }
}

void ProcessNotifier::UpdateAllTablesFinally()
{
    std::lock_guard<std::mutex> autoLock(processMutex_);
    UpdateTableInfoFinally(syncProcess_.tableProcess);
    for (auto &syncProcess : multiSyncProcess_) {
        UpdateTableInfoFinally(syncProcess.second.tableProcess);
    }
}

void ProcessNotifier::UpdateTableInfoFinally(std::map<std::string, TableProcessInfo> &processInfo)
{
    for (auto &item : processInfo) {
        uint32_t uploadOpCount = item.second.upLoadInfo.successCount + item.second.upLoadInfo.failCount;
        if (item.second.upLoadInfo.total > uploadOpCount) {
            item.second.upLoadInfo.successCount = item.second.upLoadInfo.total - item.second.upLoadInfo.failCount;
        } else {
            item.second.upLoadInfo.total = uploadOpCount;
        }

        uint32_t downloadOpCount = item.second.downLoadInfo.successCount + item.second.downLoadInfo.failCount;
        if (item.second.downLoadInfo.total > downloadOpCount) {
            item.second.downLoadInfo.successCount = item.second.downLoadInfo.total - item.second.downLoadInfo.failCount;
        } else {
            item.second.downLoadInfo.total = downloadOpCount;
        }
    }
}

// ===== stateless detail code helpers =====

uint32_t ProcessNotifier::MakeDetailCode(SyncStage stage, DetailCode code)
{
    return DETAIL_CODE_INTERNAL_FLAG | (static_cast<uint32_t>(stage) << DETAIL_CODE_STAGE_SHIFT) |
        static_cast<uint32_t>(code);
}

std::string ProcessNotifier::GetStoppedMessage(StopSource source)
{
    static const std::map<StopSource, std::string> STOP_SOURCE_DESC = {
        { StopSource::REMOVE_DEVICE_DATA, "RemoveDeviceData" },
        { StopSource::STOP_TASK, "StopTask" },
        { StopSource::IMPORT, "Import" },
        { StopSource::TABLE_REFERENCE_CHANGED, "TableReferenceChanged" },
        { StopSource::USER_CHANGE, "UserChange" },
    };
    std::string msg = GetDetailMessage(DetailCode::CLOUD_SYSTEM_EVENT_STOPPED, "");
    auto it = STOP_SOURCE_DESC.find(source);
    if (it != STOP_SOURCE_DESC.end()) {
        // the marker tells which interface terminated the tasks; the base text stays first so
        // consumers matching on the historical message keep working with a prefix check
        msg += " (stopped by " + it->second + ")";
    }
    return msg;
}

bool ProcessNotifier::NeedsStageStamp(uint32_t detailCode)
{
    // stage bits occupy bits 16-21, MAX_SYNC_STAGE(0x3F) shifted becomes the field mask
    constexpr uint32_t stageMask = static_cast<uint32_t>(SyncStage::MAX_SYNC_STAGE) << DETAIL_CODE_STAGE_SHIFT;
    // the verdict looks at the content only — an empty stage field — not at the origin:
    // 1) an external code (no internal flag) whose stage bits are empty gets the maintained
    //    stage or-ed in as a debug enrichment; occupied bits belong to the external number
    //    itself (e.g. DBStatus public codes) and pass through untouched. Dropping the old
    //    internal-flag requirement keeps every internal verdict unchanged: the flag check
    //    was always true for internal layout codes (they carry bit22 by definition), its
    //    only effect was exempting external codes — verified exhaustively over the full
    //    uint32 domain by scripts/stamp_equiv_verify.c.
    // 2) a code whose stage bits are set has already been stamped (or carries its own
    //    stage); stamping again would or the stages together (e.g. DOWNLOAD|UPLOAD = 0x03)
    //    and produce an invalid mixed stage.
    // 3) zero means "no detail" and must never be stamped into existence: 0 | stage<<16
    //    would fabricate a detail code out of a successful empty detail.
    return detailCode != 0u && (detailCode & stageMask) == 0u;
}

bool ProcessNotifier::IsExternalDetailCode(uint32_t detailCode)
{
    // an unset code is neither internal nor external; a set code without the internal flag bit
    // follows the adapter-defined layout
    return detailCode != 0u && (detailCode & DETAIL_CODE_INTERNAL_FLAG) == 0u;
}

// errno to DetailCode mapping; unmapped errnos (OK/QUERY_END etc.) keep detailCode unset.
// Errnos below really flow in the sync path but are deliberately NOT mapped (exemption list,
// do not treat them as omissions):
//   -E_QUERY_END                                normal end of a cloud query, not an error
//   -E_TASK_PAUSED / -E_TASK_INTERRUPTED         not terminal for the current task, it resumes
//                                               later; queued tasks stopped by StopAllTasks get
//                                               CLOUD_SYSTEM_EVENT_STOPPED composed explicitly,
//                                               so the errno itself never needs a mapping
//   -E_FINISHED / -E_UNFINISHED                 progress signals, not errors
//   -E_NOT_SUPPORT                              capability is not supported, not a sync failure
// -E_EXPIRED_CURSOR, -E_SKIP_WHEN_CLOUD_SPACE_INSUFFICIENT and -E_LOCAL_ASSET_NOT_FOUND were
// once exempt here (record-level marks the proxy layer translates to E_OK per record); they
// are mapped now because they also resurface at task level: the expired cursor as the fatal
// errno once retries run out, and the two skip marks as the no-abort tempErrCode carried
// into the final report.
// Three flow-level DetailCodes are deliberately absent from this table too: they describe
// aggregate conditions that no single errno can express, so their failure sites compose them
// explicitly via MakeDetailCode and their messages live in GetDetailMsg:
//   CLOUD_HEARTBEAT_BLOCKED     heartbeat blocked twice       (CloudSyncer::ExecuteHeartBeatTask)
//   CLOUD_HEARTBEAT_FAILED      heartbeat failed too many     (CloudSyncer::HeartBeatFailed)
//   CLOUD_SYSTEM_EVENT_STOPPED  sync stopped by a system event (CloudSyncer::StopAllTasks)
uint32_t ProcessNotifier::MapErrnoToDetailNumber(int errCode)
{
    static const std::map<int, DetailCode> ERRNO_DETAIL_MAP = {
        {-E_INVALID_ARGS, DetailCode::GENERAL_INVALID_ARGS},
        {-E_INVALID_DB, DetailCode::GENERAL_INVALID_DB},
        {-E_INVALID_CONNECTION, DetailCode::GENERAL_INVALID_CONNECTION},
        {-E_DB_CLOSED, DetailCode::GENERAL_DB_CLOSED},
        {-E_BUSY, DetailCode::GENERAL_BUSY},
        {-E_INTERNAL_ERROR, DetailCode::GENERAL_INTERNAL_ERROR},
        {-E_NOT_FOUND, DetailCode::GENERAL_NOT_FOUND},
        {-E_NOT_SET, DetailCode::GENERAL_NOT_SET},
        // storage-layer errnos surfaced through the local sqlite wrapper
        {-E_PERMISSION, DetailCode::GENERAL_PERMISSION},
        {-E_FIRST_PAGE_CORRUPTED, DetailCode::GENERAL_FIRST_PAGE_CORRUPTED},
        {-E_INVALID_PASSWD_OR_CORRUPTED_DB, DetailCode::GENERAL_CORRUPTED_DB},
        {-E_EKEYREVOKED, DetailCode::GENERAL_EKEYREVOKED},
        {-E_SQLITE_CANT_OPEN, DetailCode::GENERAL_SQLITE_CANT_OPEN},
        {-E_CONSTRAINT, DetailCode::GENERAL_CONSTRAINT},
        {-E_DENIED_SQL, DetailCode::GENERAL_DENIED_SQL},
        {-E_CLOUD_NETWORK_ERROR, DetailCode::CLOUD_NETWORK_ERROR},
        {-E_CLOUD_ERROR, DetailCode::CLOUD_ERROR},
        {-E_CLOUD_FULL_RECORDS, DetailCode::CLOUD_FULL_RECORDS},
        {-E_CLOUD_RECORD_EXIST_CONFLICT, DetailCode::CLOUD_RECORD_CONFLICT},
        {-E_CLOUD_GID_MISMATCH, DetailCode::CLOUD_GID_MISMATCH},
        {-E_CLOUD_INVALID_ASSET, DetailCode::CLOUD_INVALID_ASSET},
        {-E_CLOUD_ASSET_NOT_FOUND, DetailCode::CLOUD_ASSET_NOT_FOUND},
        {-E_ASSET_NOT_FOUND_FOR_DOWN_ONLY, DetailCode::CLOUD_ASSET_NOT_FOUND_DOWN_ONLY},
        {-E_REMOVE_ASSETS_FAILED, DetailCode::CLOUD_REMOVE_ASSETS_FAILED},
        {-E_CLOUD_LOCK_ERROR, DetailCode::CLOUD_LOCK_ERROR},
        {-E_CLOUD_VERSION_CONFLICT, DetailCode::CLOUD_VERSION_CONFLICT},
        {-E_CLOUD_SYNC_UNSET, DetailCode::CLOUD_SYNC_UNSET},
        {-E_CLOUD_DISABLED, DetailCode::CLOUD_DISABLED},
        {-E_CLOUD_ASSET_SPACE_INSUFFICIENT, DetailCode::CLOUD_ASSET_SPACE_INSUFFICIENT},
        // flow-level marks resurfacing at task level (see the exemption notes above)
        {-E_LOCAL_ASSET_NOT_FOUND, DetailCode::CLOUD_LOCAL_ASSET_NOT_FOUND},
        {-E_SKIP_WHEN_CLOUD_SPACE_INSUFFICIENT, DetailCode::CLOUD_SPACE_INSUFFICIENT_SKIPPED},
        {-E_EXPIRED_CURSOR, DetailCode::CLOUD_EXPIRED_CURSOR},
        {-E_CLOUD_SYNC_TASK_MERGED, DetailCode::CLOUD_SYNC_TASK_MERGED},
        {-E_SCHEMA_NOTEXIST, DetailCode::SCHEMA_NOTEXIST},
        {-E_SCHEMA_MISMATCH, DetailCode::SCHEMA_MISMATCH},
    };
    auto it = ERRNO_DETAIL_MAP.find(errCode);
    return it == ERRNO_DETAIL_MAP.end() ? 0u : static_cast<uint32_t>(it->second);
}

const char *ProcessNotifier::GetDetailMsg(DetailCode code)
{
    static const std::map<DetailCode, const char *> DETAIL_MSG_MAP = {
        {DetailCode::GENERAL_INVALID_ARGS, "Invalid arguments"},
        {DetailCode::GENERAL_INVALID_DB, "Invalid database or connection"},
        {DetailCode::GENERAL_INVALID_CONNECTION, "Invalid database connection"},
        {DetailCode::GENERAL_DB_CLOSED, "The database has been closed, all sync tasks are terminated"},
        {DetailCode::GENERAL_BUSY, "Database is busy, retry later"},
        {DetailCode::GENERAL_INTERNAL_ERROR, "Internal error"},
        {DetailCode::GENERAL_NOT_FOUND, "Resource not found"},
        {DetailCode::GENERAL_NOT_SET, "Sync option not set"},
        {DetailCode::GENERAL_PERMISSION, "Permission denied by the file system or database"},
        {DetailCode::GENERAL_FIRST_PAGE_CORRUPTED, "Database file is corrupted (not a database)"},
        {DetailCode::GENERAL_CORRUPTED_DB, "Database password is invalid or the file is corrupted"},
        {DetailCode::GENERAL_EKEYREVOKED, "Database key has been revoked"},
        {DetailCode::GENERAL_SQLITE_CANT_OPEN, "Failed to open the database file"},
        {DetailCode::GENERAL_CONSTRAINT, "SQLite constraint check failed"},
        {DetailCode::GENERAL_DENIED_SQL, "SQL execution is denied by authorization"},
        {DetailCode::CLOUD_NETWORK_ERROR, "Cloud network error"},
        {DetailCode::CLOUD_ERROR, "Cloud sync error"},
        {DetailCode::CLOUD_FULL_RECORDS, "Cloud records are full"},
        {DetailCode::CLOUD_RECORD_CONFLICT, "Record conflict during upload or download"},
        {DetailCode::CLOUD_GID_MISMATCH, "Cloud gid mismatch with local database"},
        {DetailCode::CLOUD_INVALID_ASSET, "Invalid asset"},
        {DetailCode::CLOUD_ASSET_NOT_FOUND, "Cloud asset not found (404)"},
        {DetailCode::CLOUD_ASSET_NOT_FOUND_DOWN_ONLY, "Asset not found for download-only mode"},
        {DetailCode::CLOUD_REMOVE_ASSETS_FAILED, "Failed to remove local assets"},
        {DetailCode::CLOUD_LOCK_ERROR, "Failed to get cloud sync lock"},
        {DetailCode::CLOUD_VERSION_CONFLICT, "Cloud version conflict, retry limit exceeded"},
        {DetailCode::CLOUD_SYNC_UNSET, "Cloud sync option not set"},
        {DetailCode::CLOUD_DISABLED, "Cloud sync is disabled"},
        {DetailCode::CLOUD_ASSET_SPACE_INSUFFICIENT, "Cloud asset space is insufficient"},
        {DetailCode::CLOUD_LOCAL_ASSET_NOT_FOUND, "Local asset not found when uploading"},
        {DetailCode::CLOUD_SPACE_INSUFFICIENT_SKIPPED, "Records skipped for insufficient cloud space"},
        {DetailCode::CLOUD_EXPIRED_CURSOR, "Cloud cursor expired after retries"},
        {DetailCode::CLOUD_SYNC_TASK_MERGED, "Sync task has been merged into another task"},
        {DetailCode::CLOUD_HEARTBEAT_BLOCKED, "Heartbeat blocked twice, task aborted"},
        {DetailCode::CLOUD_HEARTBEAT_FAILED, "Heartbeat failed too many times"},
        {DetailCode::CLOUD_SYSTEM_EVENT_STOPPED, "Sync tasks have been stopped due to a system event"},
    };
    auto it = DETAIL_MSG_MAP.find(code);
    return it == DETAIL_MSG_MAP.end() ? "" : it->second;
}

std::string ProcessNotifier::GetDetailMessage(DetailCode code, const std::string &tableName)
{
    switch (code) {
        case DetailCode::SCHEMA_NOTEXIST:
            return "Schema does not exist for table: " + tableName;
        case DetailCode::SCHEMA_MISMATCH:
            return "Schema mismatch for table: " + tableName;
        default:
            return GetDetailMsg(code);
    }
}

void ProcessNotifier::ResolveErrorDetail(int errCode, const std::string &tableName,
    uint32_t &detailCode, std::string &errorMessage)
{
    if (detailCode == 0u && errCode != E_OK) {
        uint32_t detailNumber = MapErrnoToDetailNumber(errCode);
        if (detailNumber != 0u) {
            detailCode = MakeDetailCode(SyncStage::GENERAL, static_cast<DetailCode>(detailNumber));
        }
    }
    if (errorMessage.empty() && (detailCode & DETAIL_CODE_INTERNAL_FLAG) != 0u) {
        errorMessage = GetDetailMessage(static_cast<DetailCode>(detailCode & DETAIL_CODE_NUMBER_MASK), tableName);
    }
}
}
