/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#include "sqlite_relational_store_connection.h"
#include "db_errno.h"
#include "log_print.h"
#include "sqlite_relational_utils.h"
#include "res_finalizer.h"

namespace DistributedDB {
SQLiteRelationalStoreConnection::SQLiteRelationalStoreConnection(SQLiteRelationalStore *store)
    : RelationalStoreConnection(store)
{
    OnKill([this]() {
        auto *store = GetDB<SQLiteRelationalStore>();
        if (store == nullptr) {
            return;
        }
        UnlockObj();
        ResFinalizer finalizer([this]() { LockObj(); });
        store->StopSync(GetConnectionId());
    });
}
// Close and release the connection.
int SQLiteRelationalStoreConnection::Close()
{
    if (store_ == nullptr) {
        return -E_INVALID_CONNECTION;
    }

    if (isExclusive_.load()) {
        return -E_BUSY;
    }

    // check if transaction closed
    {
        std::lock_guard<std::mutex> transactionLock(transactionMutex_);
        if (writeHandle_ != nullptr) {
            LOGW("Transaction started, need to rollback before close.");
            int errCode = RollBack();
            if (errCode != E_OK) {
                LOGE("Rollback transaction failed, %d.", errCode);
            }
            ReleaseExecutor(writeHandle_);
        }
    }

    static_cast<SQLiteRelationalStore *>(store_)->ReleaseDBConnection(GetConnectionId(), this);
    return E_OK;
}

std::string SQLiteRelationalStoreConnection::GetIdentifier()
{
    if (store_ == nullptr) {
        return {};
    }
    return store_->GetProperties().GetStringProp(RelationalDBProperties::IDENTIFIER_DATA, "");
}

SQLiteSingleVerRelationalStorageExecutor *SQLiteRelationalStoreConnection::GetExecutor(bool isWrite, int &errCode) const
{
    auto *store = GetDB<SQLiteRelationalStore>();
    if (store == nullptr) { // LCOV_EXCL_BR_LINE
        errCode = -E_NOT_INIT;
        LOGE("[RelationalConnection] store is null, get executor failed! errCode = [%d]", errCode);
        return nullptr;
    }

    return store->GetHandle(isWrite, errCode);
}

void SQLiteRelationalStoreConnection::ReleaseExecutor(SQLiteSingleVerRelationalStorageExecutor *&executor) const
{
    auto *store = GetDB<SQLiteRelationalStore>();
    if (store != nullptr) { // LCOV_EXCL_BR_LINE
        store->ReleaseHandle(executor);
    }
}

int SQLiteRelationalStoreConnection::StartTransaction()
{
    std::lock_guard<std::mutex> lock(transactionMutex_);
    if (writeHandle_ != nullptr) { // LCOV_EXCL_BR_LINE
        LOGD("Transaction started already.");
        return -E_TRANSACT_STATE;
    }

    int errCode = E_OK;
    auto *handle = GetExecutor(true, errCode);
    if (handle == nullptr) { // LCOV_EXCL_BR_LINE
        return errCode;
    }

    errCode = handle->StartTransaction(TransactType::DEFERRED);
    if (errCode != E_OK) { // LCOV_EXCL_BR_LINE
        ReleaseExecutor(handle);
        return errCode;
    }

    writeHandle_ = handle;
    return E_OK;
}

// Commit the transaction
int SQLiteRelationalStoreConnection::Commit()
{
    std::lock_guard<std::mutex> lock(transactionMutex_);
    if (writeHandle_ == nullptr) { // LCOV_EXCL_BR_LINE
        LOGE("single version database is null or the transaction has not been started");
        return -E_INVALID_DB;
    }

    int errCode = writeHandle_->Commit();
    ReleaseExecutor(writeHandle_);
    LOGD("connection commit transaction!");
    return errCode;
}

// Roll back the transaction
int SQLiteRelationalStoreConnection::RollBack()
{
    std::lock_guard<std::mutex> lock(transactionMutex_);
    if (writeHandle_ == nullptr) { // LCOV_EXCL_BR_LINE
        LOGE("Invalid handle for rollback or the transaction has not been started.");
        return -E_INVALID_DB;
    }

    int errCode = writeHandle_->Rollback();
    ReleaseExecutor(writeHandle_);
    LOGI("connection rollback transaction!");
    return errCode;
}

int SQLiteRelationalStoreConnection::CreateDistributedTable(const std::string &tableName, TableSyncType syncType)
{
    auto *store = GetDB<SQLiteRelationalStore>();
    if (store == nullptr) {
        LOGE("[RelationalConnection] store is null, get DB failed!");
        return -E_INVALID_CONNECTION;
    }

    int errCode = store->CreateDistributedTable(tableName, syncType);
    if (errCode != E_OK) {
        LOGE("[RelationalConnection] create distributed table failed. %d", errCode);
    }
    return errCode;
}

int SQLiteRelationalStoreConnection::RemoveDeviceData()
{
    auto *store = GetDB<SQLiteRelationalStore>();
    if (store == nullptr) {
        LOGE("[RelationalConnection] store is null, get DB failed!");
        return -E_INVALID_CONNECTION;
    }

    int errCode = store->RemoveDeviceData();
    if (errCode != E_OK) {
        LOGE("[RelationalConnection] remove device data failed. %d", errCode);
    }
    return errCode;
}

#ifdef USE_DISTRIBUTEDDB_CLOUD
int32_t SQLiteRelationalStoreConnection::GetCloudSyncTaskCount()
{
    auto *store = GetDB<SQLiteRelationalStore>();
    if (store == nullptr) {
        LOGE("[RelationalConnection] store is null, get DB failed!");
        return -1;
    }
    int32_t count = store->GetCloudSyncTaskCount();
    if (count == -1) {
        LOGE("[RelationalConnection] failed to get cloud sync task count");
    }
    return count;
}

int SQLiteRelationalStoreConnection::DoClean(ClearMode mode)
{
    auto *store = GetDB<SQLiteRelationalStore>();
    if (store == nullptr) {
        LOGE("[RelationalConnection] store is null, get DB failed!");
        return -E_INVALID_CONNECTION;
    }

    int errCode = store->CleanCloudData(mode);
    if (errCode != E_OK) {
        LOGE("[RelationalConnection] failed to clean cloud data, %d.", errCode);
    }
    return errCode;
}

int SQLiteRelationalStoreConnection::ClearCloudWatermark(const std::set<std::string> &tableNames)
{
    auto *store = GetDB<SQLiteRelationalStore>();
    if (store == nullptr) {
        LOGE("[RelationalConnection] store is null, get DB failed when clear watermark!");
        return -E_INVALID_CONNECTION;
    }

    int errCode = store->ClearCloudWatermark(tableNames);
    if (errCode != E_OK) {
        LOGE("[RelationalConnection] failed to clear cloud watermark, %d.", errCode);
    }
    return errCode;
}
#endif

int SQLiteRelationalStoreConnection::RemoveDeviceData(const std::string &device)
{
    return RemoveDeviceData(device, {});
}

int SQLiteRelationalStoreConnection::RemoveDeviceData(const std::string &device, const std::string &tableName)
{
    auto *store = GetDB<SQLiteRelationalStore>();
    if (store == nullptr) {
        LOGE("[RelationalConnection] store is null, get DB failed!");
        return -E_INVALID_CONNECTION;
    }

    int errCode = store->RemoveDeviceData(device, tableName);
    if (errCode != E_OK) {
        LOGE("[RelationalConnection] remove device data failed. %d", errCode);
    }
    return errCode;
}

int SQLiteRelationalStoreConnection::Pragma(int cmd, void *parameter) // reserve for interface function fix
{
    (void)cmd;
    (void)parameter;
    return E_OK;
}

int SQLiteRelationalStoreConnection::SyncToDevice(SyncInfo &info)
{
    auto *store = GetDB<SQLiteRelationalStore>();
    if (store == nullptr) {
        LOGE("[RelationalConnection] store is null, get executor failed!");
        return -E_INVALID_CONNECTION;
    }

    ISyncer::SyncParam syncParam;
    syncParam.devices = info.devices;
    syncParam.mode = info.mode;
    syncParam.wait = info.wait;
    syncParam.isQuerySync = true;
    syncParam.relationOnComplete = info.onComplete;
    syncParam.syncQuery = QuerySyncObject(info.query);
    if (syncParam.syncQuery.GetSortType() != SortType::NONE) {
        LOGE("not support order by timestamp, type: %d", static_cast<int>(syncParam.syncQuery.GetSortType()));
        return -E_NOT_SUPPORT;
    }
    if (syncParam.syncQuery.GetValidStatus() != E_OK) {
        LOGE("invalid sync query origin valid status %d", syncParam.syncQuery.GetValidStatus());
        return syncParam.syncQuery.GetValidStatus();
    }
    return store->Sync(syncParam, GetConnectionId());
}

int SQLiteRelationalStoreConnection::RegisterLifeCycleCallback(const DatabaseLifeCycleNotifier &notifier)
{
    auto *store = GetDB<SQLiteRelationalStore>();
    if (store == nullptr) {
        LOGE("[RelationalConnection] store is null, get executor failed!");
        return -E_INVALID_CONNECTION;
    }

    return store->RegisterLifeCycleCallback(notifier);
}

int SQLiteRelationalStoreConnection::RegisterObserverAction(const StoreObserver *observer,
    const RelationalObserverAction &action)
{
    return static_cast<SQLiteRelationalStore *>(store_)->RegisterObserverAction(GetConnectionId(), observer, action);
}

int SQLiteRelationalStoreConnection::UnRegisterObserverAction(const StoreObserver *observer)
{
    return static_cast<SQLiteRelationalStore *>(store_)->UnRegisterObserverAction(GetConnectionId(), observer);
}

int SQLiteRelationalStoreConnection::RemoteQuery(const std::string &device, const RemoteCondition &condition,
    uint64_t timeout, std::shared_ptr<ResultSet> &result)
{
    auto *store = GetDB<SQLiteRelationalStore>();
    if (store == nullptr) {
        LOGE("[RelationalConnection] store is null, get executor failed!");
        return -E_INVALID_CONNECTION;
    }
    return store->RemoteQuery(device, condition, timeout, GetConnectionId(), result);
}

#ifdef USE_DISTRIBUTEDDB_CLOUD
int SQLiteRelationalStoreConnection::SetCloudDB(const std::shared_ptr<ICloudDb> &cloudDb)
{
    auto *store = GetDB<SQLiteRelationalStore>();
    if (store == nullptr) {
        LOGE("[RelationalConnection] store is null, get DB failed!");
        return -E_INVALID_CONNECTION;
    }

    return store->SetCloudDB(cloudDb);
}

int SQLiteRelationalStoreConnection::PrepareAndSetCloudDbSchema(const DataBaseSchema &schema)
{
    auto *store = GetDB<SQLiteRelationalStore>();
    if (store == nullptr) {
        LOGE("[RelationalConnection] store is null, get DB failed!");
        return -E_INVALID_CONNECTION;
    }

    int ret = store->PrepareAndSetCloudDbSchema(schema);
    if (ret != E_OK) {
        LOGE("[RelationalConnection] PrepareAndSetCloudDbSchema failed. %d", ret);
    }
    return ret;
}

int SQLiteRelationalStoreConnection::SetIAssetLoader(const std::shared_ptr<IAssetLoader> &loader)
{
    auto *store = GetDB<SQLiteRelationalStore>();
    if (store == nullptr) {
        LOGE("[RelationalConnection] store is null, get DB failed!");
        return -E_INVALID_CONNECTION;
    }

    int ret = store->SetIAssetLoader(loader);
    if (ret != E_OK) {
        LOGE("[RelationalConnection] Set asset loader failed. %d", ret);
    }
    return ret;
}
#endif

int SQLiteRelationalStoreConnection::GetStoreInfo(std::string &userId, std::string &appId, std::string &storeId)
{
    auto *store = GetDB<SQLiteRelationalStore>();
    if (store == nullptr) {
        LOGE("[RelationalConnection] store is null, get storeInfo failed!");
        return -E_INVALID_CONNECTION;
    }
    auto properties = store->GetProperties();
    userId = properties.GetStringProp(RelationalDBProperties::USER_ID, "");
    appId = properties.GetStringProp(RelationalDBProperties::APP_ID, "");
    storeId = properties.GetStringProp(RelationalDBProperties::STORE_ID, "");
    return E_OK;
}

int SQLiteRelationalStoreConnection::SetTrackerTable(const TrackerSchema &schema)
    {
    auto *store = GetDB<SQLiteRelationalStore>();
    if (store == nullptr) {
        LOGE("[RelationalConnection] store is null, get DB failed!");
        return -E_INVALID_CONNECTION;
    }
    int errCode = store->SetTrackerTable(schema);
    if (errCode != E_OK && errCode != -E_WITH_INVENTORY_DATA) {
        LOGE("[RelationalConnection] set tracker table failed. %d", errCode);
    }
    return errCode;
}

int SQLiteRelationalStoreConnection::ExecuteSql(const SqlCondition &condition, std::vector<VBucket> &records)
{
    auto *store = GetDB<SQLiteRelationalStore>();
    if (store == nullptr) {
        LOGE("[RelationalConnection] store is null, get executor failed!");
        return -E_INVALID_CONNECTION;
    }
    return store->ExecuteSql(condition, records);
}

int SQLiteRelationalStoreConnection::SetReference(const std::vector<TableReferenceProperty> &tableReferenceProperty)
{
    auto *store = GetDB<SQLiteRelationalStore>();
    if (store == nullptr) {
        LOGE("[SetReference] store is null, get DB failed!");
        return -E_INVALID_CONNECTION;
    }
    return store->SetReference(tableReferenceProperty);
}

int SQLiteRelationalStoreConnection::CleanTrackerData(const std::string &tableName, int64_t cursor)
{
    auto *store = GetDB<SQLiteRelationalStore>();
    if (store == nullptr) { // LCOV_EXCL_BR_LINE
        LOGE("[RelationalConnection] store is null, get executor failed!");
        return -E_INVALID_CONNECTION;
    }
    return store->CleanTrackerData(tableName, cursor);
}

int SQLiteRelationalStoreConnection::Pragma(PragmaCmd cmd, PragmaData &pragmaData)
{
    auto *store = GetDB<SQLiteRelationalStore>();
    if (store == nullptr) {
        LOGE("[RelationalConnection] store is null, get executor failed!");
        return -E_INVALID_CONNECTION;
    }
    return store->Pragma(cmd, pragmaData);
}

int SQLiteRelationalStoreConnection::UpsertData(RecordStatus status, const std::string &tableName,
    const std::vector<VBucket> &records)
{
    auto *store = GetDB<SQLiteRelationalStore>();
    if (store == nullptr) {
        LOGE("[RelationalConnection] store is null, upsert dara failed!");
        return -E_INVALID_CONNECTION;
    }
    return store->UpsertData(status, tableName, records);
}

#ifdef USE_DISTRIBUTEDDB_CLOUD
int SQLiteRelationalStoreConnection::SetCloudSyncConfig(const CloudSyncConfig &config)
{
    auto *store = GetDB<SQLiteRelationalStore>();
    if (store == nullptr) { // LCOV_EXCL_BR_LINE
        LOGE("[RelationalConnection] store is null, set cloud sync config failed!");
        return -E_INVALID_CONNECTION;
    }
    return store->SetCloudSyncConfig(config);
}

int SQLiteRelationalStoreConnection::Sync(const CloudSyncOption &option, const SyncProcessCallback &onProcess,
    uint64_t taskId)
{
    auto *store = GetDB<SQLiteRelationalStore>();
    if (store == nullptr) {
        LOGE("[RelationalConnection] store is null, get executor failed!");
        return -E_INVALID_CONNECTION;
    }
    {
        AutoLock lockGuard(this);
        if (IsKilled()) {
            // If this happens, users are using a closed connection.
            LOGE("[RelationalConnection] Sync on a closed connection.");
            return -E_STALE;
        }
        IncObjRef(this);
    }
    int errCode = store->Sync(option, onProcess, taskId);
    DecObjRef(this);
    return errCode;
}

SyncProcess SQLiteRelationalStoreConnection::GetCloudTaskStatus(uint64_t taskId)
{
    auto *store = GetDB<SQLiteRelationalStore>();
    if (store == nullptr) {
        LOGE("[RelationalConnection] store is null, get executor failed!");
        SyncProcess process;
        process.errCode = DB_ERROR;
        return process;
    }
    {
        AutoLock lockGuard(this);
        if (IsKilled()) {
            // If this happens, users are using a closed connection.
            LOGE("[RelationalConnection] Get sync task on a closed connection.");
            SyncProcess process;
            process.errCode = DB_ERROR;
            return process;
        }
        IncObjRef(this);
    }
    SyncProcess process = store->GetCloudTaskStatus(taskId);
    DecObjRef(this);
    return process;
}
#endif

int SQLiteRelationalStoreConnection::SetDistributedDbSchema(const DistributedSchema &schema, bool isForceUpgrade)
{
    auto *store = GetDB<SQLiteRelationalStore>();
    if (store == nullptr) {
        LOGE("[RelationalConnection] store is null when set distributed schema");
        return -E_INVALID_CONNECTION;
    }
    return store->SetDistributedSchema(SQLiteRelationalUtils::FilterRepeatDefine(schema), isForceUpgrade);
}

int SQLiteRelationalStoreConnection::GetDownloadingAssetsCount(int32_t &count)
{
    auto *store = GetDB<SQLiteRelationalStore>();
    if (store == nullptr) {
        LOGE("[RelationalConnection] store is null, get executor failed!");
        return -E_INVALID_CONNECTION;
    }
    return store->GetDownloadingAssetsCount(count);
}

int SQLiteRelationalStoreConnection::SetTableMode(DistributedTableMode tableMode)
{
    auto *store = GetDB<SQLiteRelationalStore>();
    if (store == nullptr) {
        LOGE("[RelationalConnection] store is null when set distributed table mode.");
        return -E_INVALID_CONNECTION;
    }
    return store->SetTableMode(tableMode);
}

int SQLiteRelationalStoreConnection::OperateDataStatus(uint32_t dataOperator)
{
    auto *store = GetDB<SQLiteRelationalStore>();
    if (store == nullptr) {
        LOGE("[RelationalConnection] store is null when operate data status.");
        return -E_INVALID_CONNECTION;
    }
    return store->OperateDataStatus(dataOperator);
}

int32_t SQLiteRelationalStoreConnection::GetDeviceSyncTaskCount()
{
    auto *store = GetDB<SQLiteRelationalStore>();
    if (store == nullptr) {
        LOGE("[RelationalConnection] store is null when get device sync task count.");
        return 0;
    }
    return store->GetDeviceSyncTaskCount();
}
}
#endif