/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#ifdef RELATIONAL_STORE
#include "sqlite_relational_store.h"

#include <utility>

#include "cloud/cloud_storage_utils.h"
#include "data_donation_utils.h"

namespace DistributedDB {
void SQLiteRelationalStore::StopAllBackgroundTask(TaskType type)
{
#ifdef USE_DISTRIBUTEDDB_CLOUD
    if (type == DistributedDB::TaskType::BACKGROUND_TASK) {
        if (sqliteStorageEngine_ == nullptr) {
            LOGW("[RelationalStore] Storage engine was not initialized when stop all background task");
        } else {
            sqliteStorageEngine_->StopGenLogTask();
        }
    }
    if (cloudSyncer_ == nullptr) {
        LOGW("[RelationalStore] cloudSyncer was not initialized when stop all task, type: %u", type);
    } else {
        (void) cloudSyncer_->StopSyncTask(nullptr, -E_TASK_INTERRUPTED,
            ProcessNotifier::StopSource::STOP_TASK);
    }
#endif
}

#ifdef USE_DISTRIBUTEDDB_CLOUD
int SQLiteRelationalStore::StopGenLogTask(const std::vector<std::string> &tableList)
{
    if (sqliteStorageEngine_ == nullptr) {
        return -E_INVALID_DB;
    }
    return sqliteStorageEngine_->StopGenLogTaskWithTables(tableList);
}

SyncProcess SQLiteRelationalStore::GetCloudTaskStatus(uint64_t taskId) const
{
    return cloudSyncer_->GetCloudTaskStatus(taskId);
}

std::pair<int, DataBaseSchema> SQLiteRelationalStore::FilterCloudDbSchema(const DataBaseSchema &schema)
{
    std::pair<int, DataBaseSchema> res;
    auto &[errCode, databaseSchema] = res;
    if (sqliteStorageEngine_ == nullptr) {
        errCode = -E_INVALID_DB;
        return res;
    }
    for (const auto &item : schema.tables) {
        auto [ret, tableInfo] = sqliteStorageEngine_->AnalyzeTable(item.name);
        if (ret == -E_NOT_FOUND) {
            databaseSchema.tables.emplace_back(item);
            continue;
        }
        if (ret != E_OK) {
            LOGW("[SQLiteRelationalStore] FilterCloudDbSchema analyze table[%s] errCode[%d]",
                DBCommon::StringMiddleMaskingWithLen(item.name).c_str(), ret);
            errCode = ret;
            return res;
        }
        TableSchema tableSchema = item;
        SQLiteRelationalUtils::FilterTableSchema(tableInfo, tableSchema);
        databaseSchema.tables.emplace_back(tableSchema);
    }
    return res;
}
#endif

#ifdef USE_DISTRIBUTEDDB_DEVICE
int SQLiteRelationalStore::RemoveExceptDeviceData(
    const std::map<std::string, std::vector<std::string>> &tableMap, int64_t &changedRows)
{
    auto mode = static_cast<DistributedTableMode>(sqliteStorageEngine_->GetRelationalProperties().GetIntProp(
        RelationalDBProperties::DISTRIBUTED_TABLE_MODE, static_cast<int>(DistributedTableMode::COLLABORATION)));
    if (mode != DistributedTableMode::COLLABORATION) {
        LOGE("[SQLiteRelationalStore]RemoveExceptDeviceData only support collaboration table mode");
        return -E_NOT_SUPPORT;
    }
    auto remoteTableMap = tableMap;
    std::string localDeviceId;
    int errCode = RuntimeContext::GetInstance()->GetLocalIdentity(localDeviceId);
    if (errCode != E_OK) {
        LOGE("[RemoveExceptDeviceData] get local identity failed %d", errCode);
        return errCode;
    }
    if (tableMap.empty()) {
        const auto schema = sqliteStorageEngine_->GetSchema();
        for (const auto &tableInfo : schema.GetTables()) {
            remoteTableMap[tableInfo.first] = {"", localDeviceId};
        }
    }
    for (const auto &tableInfo : remoteTableMap) {
        const std::string &tableName = tableInfo.first;
        errCode = CheckTableSyncType(tableName, TableSyncType::DEVICE_COOPERATION);
        if (errCode != E_OK) {
            return errCode;
        }
        std::vector<std::string> keepDevices = tableInfo.second;
        std::vector<std::string> targetDevices;
        errCode = GetTargetDevices(localDeviceId, keepDevices, targetDevices); // targetDevices is after hash
        if (errCode != E_OK) {
            return errCode;
        }
        if (targetDevices.empty()) {
            continue;
        }
        // erase watermark first
        for (const auto &hashDevice : targetDevices) {
            errCode = syncAbleEngine_->EraseDeviceWaterMark(hashDevice, false, tableName);
            if (errCode != E_OK) {
                LOGE("[SQLiteRelationalStore] erase watermark failed for table, %s, %d",
                    DBCommon::StringMiddleMaskingWithLen(tableName).c_str(), errCode);
                return errCode;
            }
        }
    }
    return RemoveExceptDeviceDataInner(remoteTableMap, changedRows);
}

int SQLiteRelationalStore::RemoveExceptDeviceDataInner(
    const std::map<std::string, std::vector<std::string>> &tableMap, int64_t &changedRows)
{
    SQLiteSingleVerRelationalStorageExecutor *handle = nullptr;
    int errCode = GetHandleAndStartTransaction(handle);
    if (handle == nullptr) {
        return errCode;
    }
    ResFinalizer releaseGuard([this, handle, &errCode] {
        SQLiteSingleVerRelationalStorageExecutor *releaseHandle = handle;
        if (errCode != E_OK) {
            (void)releaseHandle->Rollback();
        } else {
            errCode = releaseHandle->Commit();
        }
        ReleaseHandle(releaseHandle);
    });
    errCode = handle->SetLogTriggerStatus(false);
    if (errCode != E_OK) {
        return errCode;
    };
    bool hasTrackerTable = false;
    for (const auto &iter : tableMap) {
        TrackerTable trackerTable = sqliteStorageEngine_->GetTrackerSchema().GetTrackerTable(iter.first);
        if (!trackerTable.IsEmpty()) {
            hasTrackerTable = true;
            errCode = handle->CreateTempSyncTrigger(trackerTable, true);
            if (errCode != E_OK) {
                return errCode;
            }
        }
        int64_t changedRow = 0;
        errCode = handle->DeleteDistributedExceptDeviceTable(iter.first, iter.second, changedRow);
        if (errCode != E_OK) {
            return errCode;
        }
        changedRows += changedRow;
        errCode = handle->DeleteDistributedExceptDeviceTableLog(iter.first, iter.second, trackerTable);
        if (errCode != E_OK) {
            return errCode;
        }
    }
    if (hasTrackerTable) {
        errCode = handle->ClearAllTempSyncTrigger();
        if (errCode != E_OK) {
            return errCode;
        }
    }
    return handle->SetLogTriggerStatus(true);
}
#endif

int SQLiteRelationalStore::CheckTableSyncType(const std::string &tableName, TableSyncType tableSyncType) const
{
    bool isCreated = false;
    int errCode = sqliteStorageEngine_->CheckTableExists(tableName, isCreated);
    if (errCode != E_OK) {
        LOGE("[SQLiteRelationalStore] check table exist failed, %d", errCode);
        return errCode;
    }
    if (!isCreated) {
        LOGE("[SQLiteRelationalStore] table %s dose not exist in the database",
            DBCommon::StringMiddleMaskingWithLen(tableName).c_str());
        return -E_TABLE_NOT_FOUND;
    }
    TableInfoMap tableInfo = sqliteStorageEngine_->GetSchema().GetTables();
    if (tableInfo.empty()) {
        LOGE("[SQLiteRelationalStore] no distributed table found");
        return -E_NOT_SUPPORT;
    }
    auto iter = tableInfo.find(tableName);
    if (iter == tableInfo.end()) {
        LOGE("[SQLiteRelationalStore] table %s is not a distributed table",
            DBCommon::StringMiddleMaskingWithLen(tableName).c_str());
        return -E_NOT_SUPPORT;
    }
    if (iter->second.GetTableSyncType() != tableSyncType) {
        LOGE("[SQLiteRelationalStore] table with invalid sync type");
        return -E_NOT_SUPPORT;
    }
    return E_OK;
}

int SQLiteRelationalStore::GetTargetDevices(const std::string &localDeviceId,
    const std::vector<std::string> &keepDevices, std::vector<std::string> &targetDevices)
{
    std::set<std::string> hashDevices;
    int errCode = E_OK;
    errCode = GetExistDevices(hashDevices);
    if (errCode != E_OK) {
        return errCode;
    }

    std::unordered_set<std::string> keepHashDeviceSet;
    for (const auto &device : keepDevices) {
        if (device.empty() || device == localDeviceId) {
            continue; // "" mean local device
        }
        std::string hashDeviceId;
        errCode = syncAbleEngine_->GetHashDeviceId(device, hashDeviceId);
        if (errCode != E_OK && errCode != -E_NOT_SUPPORT) {
            return errCode;
        }
        if (errCode == -E_NOT_SUPPORT) {
            errCode = E_OK;
            hashDeviceId = DBCommon::TransferHashString(device);
            LOGI("[SQLiteRelationalStore] device %s not support hashDevicId",
                DBCommon::StringMiddleMaskingWithLen(device).c_str());
            // check device is uuid in meta
            if (hashDevices.find(hashDeviceId) == hashDevices.end()) {
                LOGW("[SQLiteRelationalStore] not match keep device %s",
                    DBCommon::StringMiddleMaskingWithLen(device).c_str());
            }
        }
        keepHashDeviceSet.insert(hashDeviceId);
    }

    for (const auto &device : hashDevices) {
        if (keepHashDeviceSet.find(device) == keepHashDeviceSet.end()) {
            targetDevices.push_back(device);
        }
    }
    return errCode;
}

int SQLiteRelationalStore::SetBinlogEnabled(bool enabled, const std::string &binlogDirPath)
{
    std::lock_guard<std::mutex> lock(initalMutex_);
    if (isBinlogEnabled_ == enabled) {
        if (!enabled || binlogDirPath_ == binlogDirPath) {
            return E_OK;
        }
        LOGW("[RelationalStore][SetBinlogEnabled] binlog dir change while enabled is not supported,"
            " disable binlog first. curDir:%s, newDir:%s",
            DBCommon::StringMiddleMasking(binlogDirPath_).c_str(),
            DBCommon::StringMiddleMasking(binlogDirPath).c_str());
        return -E_NOT_SUPPORT;
    }
    int errCode = ApplyBinlogToAllDatabases(enabled, binlogDirPath);
    if (errCode == E_OK) {
        UpdateBinlogState(enabled, binlogDirPath);
        return E_OK;
    }
    if (!enabled) {
        return errCode;
    }
    // rollback
    if (ApplyBinlogToAllDatabases(false, std::string()) == E_OK) {
        UpdateBinlogState(false, std::string());
    }
    return errCode;
}

int SQLiteRelationalStore::ApplyBinlogToAllDatabases(bool enabled, const std::string &binlogDirPath) const
{
    const std::vector<bool> isExternal = { false, true };
    for (bool external : isExternal) {
        int errCode = SetBinlogEnabled(enabled, external, binlogDirPath);
        if (errCode != E_OK) {
            return errCode;
        }
    }
    return E_OK;
}

void SQLiteRelationalStore::UpdateBinlogState(bool enabled, const std::string &binlogDirPath)
{
    isBinlogEnabled_ = enabled;
    binlogDirPath_ = enabled ? binlogDirPath : std::string();
    if (sqliteStorageEngine_ != nullptr) {
        sqliteStorageEngine_->SetBinlogDirPath(binlogDirPath_);
    }
}

int SQLiteRelationalStore::SetBinlogEnabled(bool enabled, bool isExternal,
    const std::string &binlogDirPath) const
{
    int errCode = E_OK;
    SQLiteSingleVerRelationalStorageExecutor *handle = GetHandle(true, errCode, isExternal);
    if (handle == nullptr) {
        LOGE("[RelationalStore][SetBinlogEnabled] Get write handle failed:%d", errCode);
        return errCode;
    }
    sqlite3 *db = nullptr;
    errCode = handle->GetDbHandle(db);
    if (errCode != E_OK) {
        LOGE("[RelationalStore][SetBinlogEnabled] Get db handle failed:%d", errCode);
        ReleaseHandle(handle, isExternal);
        return errCode;
    }
    errCode = SQLiteUtils::SetBinlogEnabled(db, enabled, binlogDirPath);
    if (errCode != E_OK) {
        LOGE("[RelationalStore][SetBinlogEnabled] Set binlog enabled failed:%d, external:%d, enabled:%d",
            errCode, isExternal, enabled);
    } else {
        DataDonationUtils::SetDataChangedObserver(db);
    }
    ReleaseHandle(handle, isExternal);
    return errCode;
}

int SQLiteRelationalStore::SetSubscribeCursor(const DBSubscribeCursor &cursorIn)
{
    if (sqliteStorageEngine_ == nullptr) {
        LOGE("[RelationalStore][SetSubscribeCursor] sqliteStorageEngine was not initialized");
        return -E_INVALID_DB;
    }
    return sqliteStorageEngine_->SetSubscribeCursor(cursorIn);
}

int SQLiteRelationalStore::SetSubscribeSchema(const SubscribeSchema &schema)
{
    if (!schema.searchSchema.has_value()) {
        LOGE("[RelationalStore][SetSubscribeSchema] searchSchema not set");
        return -E_INVALID_ARGS;
    }
    return sqliteStorageEngine_->SetSubscribeSchema(schema);
}

int SQLiteRelationalStore::SetTrackerMatrixInfo(const MatrixFileInfo &info)
{
    return sqliteStorageEngine_->SetTrackerMatrixInfo(info);
}

int SQLiteRelationalStore::QuerySubscribeOutput(
    const DBSubscribeCursor &cursorIn, DBSubscribeCursor &cursorOut, std::vector<VBucket> &dataOut)
{
    if (sqliteStorageEngine_ == nullptr) {
        return -E_INVALID_DB;
    }
    return sqliteStorageEngine_->QuerySubscribeOutput(cursorIn, cursorOut, dataOut);
}

void SQLiteRelationalStore::CleanDirtyLogIfNeed(const std::string &tableName) const
{
    int errCode = E_OK;
    SQLiteSingleVerRelationalStorageExecutor *handle = GetHandle(true, errCode);
    if (handle == nullptr) {
        LOGW("[RDBStore][ClearDirtyLog] Get handle failed %d", errCode);
        return;
    }
    ResFinalizer finalizer([this, handle]() {
        SQLiteSingleVerRelationalStorageExecutor *releaseHandle = handle;
        ReleaseHandle(releaseHandle);
    });
    sqlite3 *db = nullptr;
    errCode = handle->GetDbHandle(db);
    if (errCode != E_OK) {
        LOGW("[RDBStore][ClearDirtyLog] Get db handle failed %d", errCode);
        return;
    }
    bool isExistDirtyLog = false;
    std::tie(errCode, isExistDirtyLog) = SQLiteRelationalUtils::CheckExistDirtyLog(db, tableName);
    if (errCode != E_OK) {
        LOGW("[RDBStore][ClearDirtyLog] Check dirty log failed %d", errCode);
        return;
    }
    if (!isExistDirtyLog) {
        return;
    }
    auto obj = GetSchemaObj();
    if (!obj.IsSchemaValid()) {
        return;
    }
    errCode = SQLiteRelationalUtils::CleanDirtyLog(db, tableName, obj);
    if (errCode != E_OK) {
        LOGW("[RDBStore][ClearDirtyLog] Clean dirty log failed %d", errCode);
    }
}

RelationalSchemaObject SQLiteRelationalStore::GetSchemaObj() const
{
    if (storageEngine_ == nullptr) {
        return {};
    }
    return storageEngine_->GetSchemaInfo();
}

void SQLiteRelationalStore::TrackerIntegrityRepair(const TrackerSchema &trackerSchema,
    const TableInfo &tableInfo, bool isNoTableInSchema) const
{
    int errCode = E_OK;
    auto *handle = GetHandle(false, errCode);
    if (handle == nullptr) {
        LOGW("[TrackerIntegrityRepair] get read handle failed:%d", errCode);
        return;
    }
    sqlite3 *dbHandle = nullptr;
    if (handle->GetDbHandle(dbHandle) != E_OK) {
        ReleaseHandle(handle);
        return;
    }
    TrackerTable trackerTable = tableInfo.GetTrackerTable();
    trackerTable.CheckMissingTrigger(tableInfo, dbHandle);
    // Check whether cursor exists in meta table, init it later in TrackerRepairImpl if absent.
    trackerTable.CheckMissingCursor(dbHandle, handle->IsMemory());
    // Check whether any log row has a null cursor, refresh it later in TrackerRepairImpl if so.
    trackerTable.CheckNullCursorLog(dbHandle);
    // Try clear historical mismatched log, which usually do not occur and apply to tracker table only.
    if (isNoTableInSchema) {
        trackerTable.CheckMismatchedDataKeys(dbHandle);
    }
    if (!trackerSchema.extendColNames.empty()) {
        trackerTable.CheckNullExtendLog(dbHandle);
    }
    auto obj = GetSchemaObj();
    if (obj.IsSchemaValid()) {
        trackerTable.CheckExistDirtyLog(dbHandle);
    }
    ReleaseHandle(handle);
    LOGI("[TrackerIntegrityRepair] check finish [%s length[%zu]]",
        DBCommon::StringMiddleMasking(trackerSchema.tableName).c_str(), trackerSchema.tableName.length());
    TrackerRepairImpl(trackerTable, obj);
}

void SQLiteRelationalStore::TrackerRepairImpl(TrackerTable &trackerTable, const RelationalSchemaObject &obj) const
{
    trackerTable.Repair([this, &obj] (const TrackerTable::RepairInfo &repairInfo, const std::string &tableName,
        const std::set<std::string> &extendColNames) {
        int errCode = E_OK;
        auto handle = GetHandle(true, errCode);
        if (handle == nullptr) {
            LOGW("[TrackerIntegrityRepair] get write handle failed:%d", errCode);
            return;
        }
        sqlite3 *db = nullptr;
        if (handle->GetDbHandle(db) != E_OK) {
            ReleaseHandle(handle);
            return;
        }
        if (repairInfo.missingCursor) {
            int cursorErr = SQLiteUtils::ExecuteRawSQL(db, CloudStorageUtils::GetCursorUpgradeSql(tableName));
            LOGW("[TrackerIntegrityRepair] recover cursor to meta errCode=%d", cursorErr);
        }
        for (const auto &sql : repairInfo.createTriggerSqls) {
            errCode = SQLiteUtils::ExecuteRawSQL(db, sql);
            if (errCode != E_OK) {
                LOGW("[%s [%zu]] Failed to recreate trigger, errCode=%d",
                    DBCommon::StringMiddleMasking(tableName).c_str(), tableName.size(), errCode);
            }
        }
        if (!repairInfo.misDataKeys.empty()) {
            SQLiteRelationalUtils::DeleteMismatchLog(db, tableName, repairInfo.misDataKeys);
        }
        if (repairInfo.existNullExtend) {
            handle->RecoverNullExtendLog(tableName, extendColNames,
                SQLiteRelationalUtils::GetTempUpdateLogCursorTriggerSql(tableName));
        }
        if (repairInfo.existDirtyLog) {
            (void) SQLiteRelationalUtils::CleanDirtyLog(db, tableName, obj);
        }
        if (repairInfo.existNullCursorLog) {
            (void) SQLiteRelationalUtils::UpdateNullCursor(db, tableName);
        }
        ReleaseHandle(handle);
        LOGI("[TrackerIntegrityRepair] repair finish");
    });
}
} // namespace DistributedDB
#endif