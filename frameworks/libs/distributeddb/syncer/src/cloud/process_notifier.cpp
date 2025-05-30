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
    if (process.downLoadInfo.batchIndex != 0u) {
        LOGD("[ProcessNotifier] update download process index: %" PRIu32, process.downLoadInfo.batchIndex);
        syncProcess.tableProcess[process.tableName].downLoadInfo = process.downLoadInfo;
    }
    if (process.upLoadInfo.batchIndex != 0u) {
        LOGD("[ProcessNotifier] update upload process index: %" PRIu32, process.upLoadInfo.batchIndex);
        syncProcess.tableProcess[process.tableName].upLoadInfo = process.upLoadInfo;
    }
}

void ProcessNotifier::NotifyProcess(const ICloudSyncer::CloudTaskInfo &taskInfo,
    const ICloudSyncer::InnerProcessInfo &process, bool notifyWhenError)
{
    UpdateProcess(process);
    std::map<std::string, SyncProcess> currentProcess;
    {
        std::lock_guard<std::mutex> autoLock(processMutex_);
        if (!notifyWhenError && taskInfo.errCode != E_OK) {
            LOGD("[ProcessNotifier] task has error, do not notify now");
            return;
        }
        syncProcess_.errCode = TransferDBErrno(taskInfo.errCode, true);
        syncProcess_.process = taskInfo.status;
        multiSyncProcess_[user_].errCode = TransferDBErrno(taskInfo.errCode, true);
        multiSyncProcess_[user_].process = taskInfo.status;
        UpdateUploadInfoIfNeeded(process);
        if (user_.empty()) {
            for (const auto &device : devices_) {
                // make sure only one device
                currentProcess[device] = syncProcess_;
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
}
