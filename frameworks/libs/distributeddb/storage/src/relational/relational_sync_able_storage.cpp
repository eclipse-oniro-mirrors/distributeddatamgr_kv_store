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
#include "relational_sync_able_storage.h"

#include <utility>

#include "cloud/cloud_db_constant.h"
#include "cloud/cloud_storage_utils.h"
#include "concurrent_adapter.h"
#include "data_compression.h"
#include "db_common.h"
#include "db_dfx_adapter.h"
#include "generic_single_ver_kv_entry.h"
#include "platform_specific.h"
#include "query_utils.h"
#include "relational_remote_query_continue_token.h"
#include "relational_sync_data_inserter.h"
#include "res_finalizer.h"
#include "runtime_context.h"
#include "time_helper.h"

namespace DistributedDB {
namespace {
void TriggerCloseAutoLaunchConn(const RelationalDBProperties &properties)
{
    static constexpr const char *CLOSE_CONN_TASK = "auto launch close relational connection";
    (void)RuntimeContext::GetInstance()->ScheduleQueuedTask(
        std::string(CLOSE_CONN_TASK),
        [properties] { RuntimeContext::GetInstance()->CloseAutoLaunchConnection(DBTypeInner::DB_RELATION, properties); }
    );
}
}

RelationalSyncAbleStorage::RelationalSyncAbleStorage(std::shared_ptr<SQLiteSingleRelationalStorageEngine> engine)
    : storageEngine_(std::move(engine)),
      reusedHandle_(nullptr),
      isCachedOption_(false)
{}

RelationalSyncAbleStorage::~RelationalSyncAbleStorage()
{
    syncAbleEngine_ = nullptr;
}

// Get interface type of this relational db.
int RelationalSyncAbleStorage::GetInterfaceType() const
{
    return SYNC_RELATION;
}

// Get the interface ref-count, in order to access asynchronously.
void RelationalSyncAbleStorage::IncRefCount()
{
    LOGD("RelationalSyncAbleStorage ref +1");
    IncObjRef(this);
}

// Drop the interface ref-count.
void RelationalSyncAbleStorage::DecRefCount()
{
    LOGD("RelationalSyncAbleStorage ref -1");
    DecObjRef(this);
}

// Get the identifier of this rdb.
std::vector<uint8_t> RelationalSyncAbleStorage::GetIdentifier() const
{
    std::string identifier = storageEngine_->GetIdentifier();
    return std::vector<uint8_t>(identifier.begin(), identifier.end());
}

std::vector<uint8_t> RelationalSyncAbleStorage::GetDualTupleIdentifier() const
{
    std::string identifier = storageEngine_->GetProperties().GetStringProp(
        DBProperties::DUAL_TUPLE_IDENTIFIER_DATA, "");
    std::vector<uint8_t> identifierVect(identifier.begin(), identifier.end());
    return identifierVect;
}

// Get the max timestamp of all entries in database.
void RelationalSyncAbleStorage::GetMaxTimestamp(Timestamp &timestamp) const
{
    int errCode = E_OK;
    auto handle = GetHandle(false, errCode, OperatePerm::NORMAL_PERM);
    if (handle == nullptr) {
        return;
    }
    timestamp = 0;
    errCode = handle->GetMaxTimestamp(storageEngine_->GetSchema().GetTableNames(), timestamp);
    if (errCode != E_OK) {
        LOGE("GetMaxTimestamp failed, errCode:%d", errCode);
        TriggerCloseAutoLaunchConn(storageEngine_->GetProperties());
    }
    ReleaseHandle(handle);
}

int RelationalSyncAbleStorage::GetMaxTimestamp(const std::string &tableName, Timestamp &timestamp) const
{
    int errCode = E_OK;
    auto handle = GetHandle(false, errCode, OperatePerm::NORMAL_PERM);
    if (handle == nullptr) {
        return errCode;
    }
    timestamp = 0;
    errCode = handle->GetMaxTimestamp({ tableName }, timestamp);
    if (errCode != E_OK) {
        LOGE("GetMaxTimestamp failed, errCode:%d", errCode);
        TriggerCloseAutoLaunchConn(storageEngine_->GetProperties());
    }
    ReleaseHandle(handle);
    return errCode;
}

SQLiteSingleVerRelationalStorageExecutor *RelationalSyncAbleStorage::GetHandle(bool isWrite, int &errCode,
    OperatePerm perm) const
{
    if (storageEngine_ == nullptr) {
        errCode = -E_INVALID_DB;
        return nullptr;
    }
    auto handle = static_cast<SQLiteSingleVerRelationalStorageExecutor *>(
        storageEngine_->FindExecutor(isWrite, perm, errCode));
    if (handle == nullptr) {
        TriggerCloseAutoLaunchConn(storageEngine_->GetProperties());
    }
    return handle;
}

SQLiteSingleVerRelationalStorageExecutor *RelationalSyncAbleStorage::GetHandleExpectTransaction(bool isWrite,
    int &errCode, OperatePerm perm) const
{
    if (storageEngine_ == nullptr) {
        errCode = -E_INVALID_DB;
        return nullptr;
    }
    if (transactionHandle_ != nullptr) {
        return transactionHandle_;
    }
    auto handle = static_cast<SQLiteSingleVerRelationalStorageExecutor *>(
        storageEngine_->FindExecutor(isWrite, perm, errCode));
    if (errCode != E_OK) {
        ReleaseHandle(handle);
        handle = nullptr;
    }
    return handle;
}

void RelationalSyncAbleStorage::ReleaseHandle(SQLiteSingleVerRelationalStorageExecutor *&handle) const
{
    if (storageEngine_ == nullptr) {
        return;
    }
    StorageExecutor *databaseHandle = handle;
    storageEngine_->Recycle(databaseHandle);
    std::function<void()> listener = nullptr;
    {
        std::lock_guard<std::mutex> autoLock(heartBeatMutex_);
        listener = heartBeatListener_;
    }
    if (listener) {
        listener();
    }
}

// Get meta data associated with the given key.
int RelationalSyncAbleStorage::GetMetaData(const Key &key, Value &value) const
{
    if (key.size() > DBConstant::MAX_KEY_SIZE) {
        return -E_INVALID_ARGS;
    }
    int errCode = E_OK;
    auto handle = GetHandle(false, errCode, OperatePerm::NORMAL_PERM);
    if (handle == nullptr) {
        return errCode;
    }
    errCode = handle->GetKvData(key, value);
    if (errCode != E_OK && errCode != -E_NOT_FOUND) {
        TriggerCloseAutoLaunchConn(storageEngine_->GetProperties());
    }
    ReleaseHandle(handle);
    return errCode;
}

int RelationalSyncAbleStorage::GetMetaDataByPrefixKey(const Key &keyPrefix, std::map<Key, Value> &data) const
{
    if (keyPrefix.size() > DBConstant::MAX_KEY_SIZE) {
        return -E_INVALID_ARGS;
    }
    int errCode = E_OK;
    auto handle = GetHandle(false, errCode, OperatePerm::NORMAL_PERM);
    if (handle == nullptr) {
        return errCode;
    }
    errCode = handle->GetKvDataByPrefixKey(keyPrefix, data);
    if (errCode != E_OK && errCode != -E_NOT_FOUND) {
        TriggerCloseAutoLaunchConn(storageEngine_->GetProperties());
    }
    ReleaseHandle(handle);
    return errCode;
}

// Put meta data as a key-value entry.
int RelationalSyncAbleStorage::PutMetaData(const Key &key, const Value &value)
{
    int errCode = E_OK;
    auto *handle = GetHandle(true, errCode, OperatePerm::NORMAL_PERM);
    if (handle == nullptr) {
        return errCode;
    }

    errCode = handle->PutKvData(key, value); // meta doesn't need time.
    if (errCode != E_OK) {
        LOGE("Put kv data err:%d", errCode);
        TriggerCloseAutoLaunchConn(storageEngine_->GetProperties());
    }
    ReleaseHandle(handle);
    return errCode;
}

int RelationalSyncAbleStorage::PutMetaData(const Key &key, const Value &value, bool isInTransaction)
{
    if (storageEngine_ == nullptr) {
        return -E_INVALID_DB;
    }
    int errCode = E_OK;
    SQLiteSingleVerRelationalStorageExecutor *handle = nullptr;
    std::unique_lock<std::mutex> handLock(reusedHandleMutex_, std::defer_lock);

    // try to recycle using the handle
    if (isInTransaction) {
        handLock.lock();
        if (reusedHandle_ != nullptr) {
            handle = static_cast<SQLiteSingleVerRelationalStorageExecutor *>(reusedHandle_);
        } else {
            isInTransaction = false;
            handLock.unlock();
        }
    }

    if (handle == nullptr) {
        handle = GetHandle(true, errCode, OperatePerm::NORMAL_PERM);
        if (handle == nullptr) {
            return errCode;
        }
    }

    errCode = handle->PutKvData(key, value);
    if (errCode != E_OK) {
        LOGE("Put kv data err:%d", errCode);
        TriggerCloseAutoLaunchConn(storageEngine_->GetProperties());
    }
    if (!isInTransaction) {
        ReleaseHandle(handle);
    }
    return errCode;
}

// Delete multiple meta data records in a transaction.
int RelationalSyncAbleStorage::DeleteMetaData(const std::vector<Key> &keys)
{
    for (const auto &key : keys) {
        if (key.empty() || key.size() > DBConstant::MAX_KEY_SIZE) {
            return -E_INVALID_ARGS;
        }
    }
    int errCode = E_OK;
    auto handle = GetHandle(true, errCode, OperatePerm::NORMAL_PERM);
    if (handle == nullptr) {
        return errCode;
    }

    handle->StartTransaction(TransactType::IMMEDIATE);
    errCode = handle->DeleteMetaData(keys);
    if (errCode != E_OK) {
        handle->Rollback();
        LOGE("[SinStore] DeleteMetaData failed, errCode = %d", errCode);
        TriggerCloseAutoLaunchConn(storageEngine_->GetProperties());
    } else {
        handle->Commit();
    }
    ReleaseHandle(handle);
    return errCode;
}

// Delete multiple meta data records with key prefix in a transaction.
int RelationalSyncAbleStorage::DeleteMetaDataByPrefixKey(const Key &keyPrefix) const
{
    if (keyPrefix.empty() || keyPrefix.size() > DBConstant::MAX_KEY_SIZE) {
        return -E_INVALID_ARGS;
    }

    int errCode = E_OK;
    auto handle = GetHandle(true, errCode, OperatePerm::NORMAL_PERM);
    if (handle == nullptr) {
        return errCode;
    }

    errCode = handle->DeleteMetaDataByPrefixKey(keyPrefix);
    if (errCode != E_OK) {
        LOGE("[SinStore] DeleteMetaData by prefix key failed, errCode = %d", errCode);
        TriggerCloseAutoLaunchConn(storageEngine_->GetProperties());
    }
    ReleaseHandle(handle);
    return errCode;
}

// Get all meta data keys.
int RelationalSyncAbleStorage::GetAllMetaKeys(std::vector<Key> &keys) const
{
    int errCode = E_OK;
    auto *handle = GetHandle(true, errCode, OperatePerm::NORMAL_PERM);
    if (handle == nullptr) {
        return errCode;
    }

    errCode = handle->GetAllMetaKeys(keys);
    if (errCode != E_OK) {
        TriggerCloseAutoLaunchConn(storageEngine_->GetProperties());
    }
    ReleaseHandle(handle);
    return errCode;
}

const RelationalDBProperties &RelationalSyncAbleStorage::GetDbProperties() const
{
    return storageEngine_->GetProperties();
}

static int GetKvEntriesByDataItems(std::vector<SingleVerKvEntry *> &entries, std::vector<DataItem> &dataItems)
{
    int errCode = E_OK;
    for (auto &item : dataItems) {
        auto entry = new (std::nothrow) GenericSingleVerKvEntry();
        if (entry == nullptr) {
            errCode = -E_OUT_OF_MEMORY;
            LOGE("GetKvEntries failed, errCode:%d", errCode);
            SingleVerKvEntry::Release(entries);
            break;
        }
        entry->SetEntryData(std::move(item));
        entries.push_back(entry);
    }
    return errCode;
}

static size_t GetDataItemSerialSize(const DataItem &item, size_t appendLen)
{
    // timestamp and local flag: 3 * uint64_t, version(uint32_t), key, value, origin dev and the padding size.
    // the size would not be very large.
    static const size_t maxOrigDevLength = 40;
    size_t devLength = std::max(maxOrigDevLength, item.origDev.size());
    size_t dataSize = (Parcel::GetUInt64Len() * 3 + Parcel::GetUInt32Len() + Parcel::GetVectorCharLen(item.key) +
                       Parcel::GetVectorCharLen(item.value) + devLength + appendLen);
    return dataSize;
}

static bool CanHoldDeletedData(const std::vector<DataItem> &dataItems, const DataSizeSpecInfo &dataSizeInfo,
    size_t appendLen)
{
    bool reachThreshold = (dataItems.size() >= dataSizeInfo.packetSize);
    for (size_t i = 0, blockSize = 0; !reachThreshold && i < dataItems.size(); i++) {
        blockSize += GetDataItemSerialSize(dataItems[i], appendLen);
        reachThreshold = (blockSize >= dataSizeInfo.blockSize * DBConstant::QUERY_SYNC_THRESHOLD);
    }
    return !reachThreshold;
}

static void ProcessContinueTokenForQuerySync(const std::vector<DataItem> &dataItems, int &errCode,
    SQLiteSingleVerRelationalContinueToken *&token)
{
    if (errCode != -E_UNFINISHED) { // Error happened or get data finished. Token should be cleared.
        delete token;
        token = nullptr;
        return;
    }

    if (dataItems.empty()) {
        errCode = -E_INTERNAL_ERROR;
        LOGE("Get data unfinished but data items is empty.");
        delete token;
        token = nullptr;
        return;
    }
    token->SetNextBeginTime(dataItems.back());
    token->UpdateNextSyncOffset(dataItems.size());
}

/**
 * Caller must ensure that parameter token is valid.
 * If error happened, token will be deleted here.
 */
int RelationalSyncAbleStorage::GetSyncDataForQuerySync(std::vector<DataItem> &dataItems,
    SQLiteSingleVerRelationalContinueToken *&token, const DataSizeSpecInfo &dataSizeInfo,
    RelationalSchemaObject &&filterSchema) const
{
    if (storageEngine_ == nullptr) {
        return -E_INVALID_DB;
    }

    int errCode = E_OK;
    auto handle = static_cast<SQLiteSingleVerRelationalStorageExecutor *>(storageEngine_->FindExecutor(false,
        OperatePerm::NORMAL_PERM, errCode));
    if (handle == nullptr) {
        goto ERROR;
    }
    handle->SetLocalSchema(filterSchema);
    do {
        errCode = handle->GetSyncDataByQuery(dataItems,
            Parcel::GetAppendedLen(),
            dataSizeInfo,
            [token](sqlite3 *db, sqlite3_stmt *&queryStmt, sqlite3_stmt *&fullStmt, bool &isGettingDeletedData) {
                return token->GetStatement(db, queryStmt, fullStmt, isGettingDeletedData);
            }, storageEngine_->GetSchema().GetTable(token->GetQuery().GetTableName()));
        if (errCode == -E_FINISHED) {
            token->FinishGetData();
            errCode = token->IsGetAllDataFinished() ? E_OK : -E_UNFINISHED;
        }
    } while (errCode == -E_UNFINISHED && CanHoldDeletedData(dataItems, dataSizeInfo, Parcel::GetAppendedLen()));

ERROR:
    if (errCode != -E_UNFINISHED && errCode != E_OK) { // Error happened.
        dataItems.clear();
    }
    ProcessContinueTokenForQuerySync(dataItems, errCode, token);
    ReleaseHandle(handle);
    return errCode;
}

// use kv struct data to sync
// Get the data which would be synced with query condition
int RelationalSyncAbleStorage::GetSyncData(QueryObject &query, const SyncTimeRange &timeRange,
    const DataSizeSpecInfo &dataSizeInfo, ContinueToken &continueStmtToken,
    std::vector<SingleVerKvEntry *> &entries) const
{
    if (!timeRange.IsValid()) {
        return -E_INVALID_ARGS;
    }
    query.SetSchema(storageEngine_->GetSchema());
    auto token = new (std::nothrow) SQLiteSingleVerRelationalContinueToken(timeRange, query);
    if (token == nullptr) {
        LOGE("[SingleVerNStore] Allocate continue token failed.");
        return -E_OUT_OF_MEMORY;
    }

    continueStmtToken = static_cast<ContinueToken>(token);
    return GetSyncDataNext(entries, continueStmtToken, dataSizeInfo);
}

int RelationalSyncAbleStorage::GetSyncDataNext(std::vector<SingleVerKvEntry *> &entries,
    ContinueToken &continueStmtToken, const DataSizeSpecInfo &dataSizeInfo) const
{
    auto token = static_cast<SQLiteSingleVerRelationalContinueToken *>(continueStmtToken);
    if (token == nullptr) {
        LOGE("[SingleVerNStore] Allocate continue stmt token failed.");
        return -E_OUT_OF_MEMORY;
    }
    if (!token->CheckValid()) {
        return -E_INVALID_ARGS;
    }
    RelationalSchemaObject schema = storageEngine_->GetSchema();
    RelationalSchemaObject filterSchema;
    if (token->IsUseLocalSchema()) {
        filterSchema = schema;
    } else {
        int errCode = GetRemoteDeviceSchema(token->GetRemoteDev(), filterSchema);
        if (errCode != E_OK) {
            return errCode;
        }
    }
    const auto fieldInfos = schema.GetTable(token->GetQuery().GetTableName()).GetFieldInfos();
    std::vector<std::string> fieldNames;
    fieldNames.reserve(fieldInfos.size());
    for (const auto &fieldInfo : fieldInfos) { // order by cid
        fieldNames.push_back(fieldInfo.GetFieldName());
    }
    token->SetFieldNames(fieldNames);

    std::vector<DataItem> dataItems;
    int errCode = GetSyncDataForQuerySync(dataItems, token, dataSizeInfo, std::move(filterSchema));
    if (errCode != E_OK && errCode != -E_UNFINISHED) { // The code need be sent to outside except new error happened.
        continueStmtToken = static_cast<ContinueToken>(token);
        return errCode;
    }

    int innerCode = GetKvEntriesByDataItems(entries, dataItems);
    if (innerCode != E_OK) {
        errCode = innerCode;
        delete token;
        token = nullptr;
    }
    continueStmtToken = static_cast<ContinueToken>(token);
    return errCode;
}

namespace {
std::vector<DataItem> ConvertEntries(std::vector<SingleVerKvEntry *> entries)
{
    std::vector<DataItem> dataItems;
    for (const auto &itemEntry : entries) {
        GenericSingleVerKvEntry *entry = static_cast<GenericSingleVerKvEntry *>(itemEntry);
        if (entry != nullptr) {
            DataItem item;
            item.origDev = entry->GetOrigDevice();
            item.flag = entry->GetFlag();
            item.timestamp = entry->GetTimestamp();
            item.writeTimestamp = entry->GetWriteTimestamp();
            entry->GetKey(item.key);
            entry->GetValue(item.value);
            entry->GetHashKey(item.hashKey);
            dataItems.push_back(item);
        }
    }
    return dataItems;
}
}

int RelationalSyncAbleStorage::PutSyncDataWithQuery(const QueryObject &object,
    const std::vector<SingleVerKvEntry *> &entries, const DeviceID &deviceName)
{
    std::vector<DataItem> dataItems = ConvertEntries(entries);
    return PutSyncData(object, dataItems, deviceName);
}

int RelationalSyncAbleStorage::SaveSyncDataItems(const QueryObject &object, std::vector<DataItem> &dataItems,
    const std::string &deviceName)
{
    int errCode = E_OK;
    LOGD("[RelationalSyncAbleStorage::SaveSyncDataItems] Get write handle.");
    QueryObject query = object;
    auto localSchema = storageEngine_->GetSchema();
    query.SetSchema(localSchema);

    RelationalSchemaObject filterSchema;
    errCode = GetRemoteDeviceSchema(deviceName, filterSchema);
    if (errCode != E_OK) {
        LOGE("Find remote schema failed. err=%d", errCode);
        return errCode;
    }
    if (!IsSetDistributedSchema(query.GetTableName(), localSchema)) {
        return -E_SCHEMA_MISMATCH;
    }
    if (query.IsUseLocalSchema()) {
        // remote send always with its table col sort
        filterSchema.SetDistributedSchema(localSchema.GetDistributedSchema());
    }

    StoreInfo info = GetStoreInfo();
    SchemaInfo schemaInfo = {storageEngine_->GetSchema(), storageEngine_->GetTrackerSchema()};
    auto inserter = RelationalSyncDataInserter::CreateInserter(
        deviceName, query, schemaInfo, filterSchema.GetSyncFieldInfo(query.GetTableName()), info);
    inserter.SetEntries(dataItems);

    auto *handle = GetHandle(true, errCode, OperatePerm::NORMAL_PERM);
    if (handle == nullptr) {
        return errCode;
    }

    // To prevent certain abnormal scenarios from deleting the table,
    // check if the table exists before each synchronization.
    // If the table does not exist, create it.
    // Because it is a fallback scenario, if the table creation fails, no failure will be returned
    if (localSchema.GetTableMode() == DistributedTableMode::SPLIT_BY_DEVICE) {
        errCode = handle->CreateDistributedDeviceTable(deviceName,
            storageEngine_->GetSchema().GetTable(query.GetTableName()), info);
        if (errCode != E_OK) {
            LOGW("[RelationalSyncAbleStorage::SaveSyncDataItems] Create distributed device table fail %d", errCode);
        }
    }
    DBDfxAdapter::StartTracing();

    handle->SetTableMode(localSchema.GetTableMode());
    errCode = handle->SaveSyncItems(inserter);
    ChangedData data = inserter.GetChangedData();
    data.properties.isP2pSyncDataChange = !dataItems.empty();

    DBDfxAdapter::FinishTracing();
    bool isEmptyChangedData = data.field.empty() && data.primaryData[OP_INSERT].empty() &&
        data.primaryData[OP_UPDATE].empty() && data.primaryData[OP_DELETE].empty();
    if (errCode == E_OK && !isEmptyChangedData) {
        // dataItems size > 0 now because already check before
        // all dataItems will write into db now, so need to observer notify here
        // if some dataItems will not write into db in the future, observer notify here need change
        data.tableName = query.GetTableName();
        // SPLIT_BY_DEVICE trigger observer with device, userId, appId and storeId, so trigger with isChangeData false
        // COLLABORATION   trigger observer with changeData, so trigger with isChangeData true
        TriggerObserverAction(deviceName, std::move(data),
            GetDbProperties().GetDistributedTableMode() == DistributedTableMode::COLLABORATION, Origin::ORIGIN_REMOTE);
    }

    ReleaseHandle(handle);
    return errCode;
}

int RelationalSyncAbleStorage::PutSyncData(const QueryObject &query, std::vector<DataItem> &dataItems,
    const std::string &deviceName)
{
    if (deviceName.length() > DBConstant::MAX_DEV_LENGTH) {
        LOGW("Device length is invalid for sync put");
        return -E_INVALID_ARGS;
    }

    int errCode = SaveSyncDataItems(query, dataItems, deviceName); // Currently true to check value content
    if (errCode != E_OK) {
        LOGE("[Relational] PutSyncData errCode:%d", errCode);
        TriggerCloseAutoLaunchConn(storageEngine_->GetProperties());
    }
    return errCode;
}

int RelationalSyncAbleStorage::RemoveDeviceData(const std::string &deviceName, bool isNeedNotify)
{
    (void) deviceName;
    (void) isNeedNotify;
    return -E_NOT_SUPPORT;
}

RelationalSchemaObject RelationalSyncAbleStorage::GetSchemaInfo() const
{
    return storageEngine_->GetSchema();
}

int RelationalSyncAbleStorage::GetSecurityOption(SecurityOption &option) const
{
    std::lock_guard<std::mutex> autoLock(securityOptionMutex_);
    if (isCachedOption_) {
        option = securityOption_;
        return E_OK;
    }
    std::string dbPath = storageEngine_->GetProperties().GetStringProp(DBProperties::DATA_DIR, "");
    int errCode = RuntimeContext::GetInstance()->GetSecurityOption(dbPath, securityOption_);
    if (errCode == E_OK) {
        option = securityOption_;
        isCachedOption_ = true;
    }
    return errCode;
}

void RelationalSyncAbleStorage::NotifyRemotePushFinished(const std::string &deviceId) const
{
    return;
}

// Get the timestamp when database created or imported
int RelationalSyncAbleStorage::GetDatabaseCreateTimestamp(Timestamp &outTime) const
{
    return OS::GetCurrentSysTimeInMicrosecond(outTime);
}

std::vector<QuerySyncObject> RelationalSyncAbleStorage::GetTablesQuery()
{
    auto tableNames = storageEngine_->GetSchema().GetTableNames();
    std::vector<QuerySyncObject> queries;
    queries.reserve(tableNames.size());
    for (const auto &it : tableNames) {
        queries.emplace_back(Query::Select(it));
    }
    return queries;
}

int RelationalSyncAbleStorage::LocalDataChanged(int notifyEvent, std::vector<QuerySyncObject> &queryObj)
{
    (void) queryObj;
    return -E_NOT_SUPPORT;
}

int RelationalSyncAbleStorage::InterceptData(std::vector<SingleVerKvEntry *> &entries, const std::string &sourceID,
    const std::string &targetID, bool isPush) const
{
    return E_OK;
}

int RelationalSyncAbleStorage::CreateDistributedDeviceTable(const std::string &device,
    const RelationalSyncStrategy &syncStrategy)
{
    auto mode = storageEngine_->GetProperties().GetDistributedTableMode();
    if (mode != DistributedTableMode::SPLIT_BY_DEVICE) {
        LOGD("No need create device table in COLLABORATION mode.");
        return E_OK;
    }

    int errCode = E_OK;
    auto *handle = GetHandle(true, errCode, OperatePerm::NORMAL_PERM);
    if (handle == nullptr) {
        return errCode;
    }

    errCode = handle->StartTransaction(TransactType::IMMEDIATE);
    if (errCode != E_OK) {
        LOGE("Start transaction failed:%d", errCode);
        TriggerCloseAutoLaunchConn(storageEngine_->GetProperties());
        ReleaseHandle(handle);
        return errCode;
    }

    StoreInfo info = GetStoreInfo();
    for (const auto &[table, strategy] : syncStrategy) {
        if (!strategy.permitSync) {
            continue;
        }

        errCode = handle->CreateDistributedDeviceTable(device, storageEngine_->GetSchema().GetTable(table), info);
        if (errCode != E_OK) {
            LOGE("Create distributed device table failed. %d", errCode);
            break;
        }
    }

    if (errCode == E_OK) {
        errCode = handle->Commit();
    } else {
        (void)handle->Rollback();
    }

    ReleaseHandle(handle);
    return errCode;
}

int RelationalSyncAbleStorage::RegisterSchemaChangedCallback(const std::function<void()> &callback)
{
    std::lock_guard lock(onSchemaChangedMutex_);
    onSchemaChanged_ = callback;
    return E_OK;
}

void RelationalSyncAbleStorage::NotifySchemaChanged()
{
    std::lock_guard lock(onSchemaChangedMutex_);
    if (onSchemaChanged_) {
        LOGD("Notify relational schema was changed");
        onSchemaChanged_();
    }
}
int RelationalSyncAbleStorage::GetCompressionAlgo(std::set<CompressAlgorithm> &algorithmSet) const
{
    algorithmSet.clear();
    DataCompression::GetCompressionAlgo(algorithmSet);
    return E_OK;
}

int RelationalSyncAbleStorage::RegisterObserverAction(uint64_t connectionId, const StoreObserver *observer,
    const RelationalObserverAction &action)
{
    ConcurrentAdapter::AdapterAutoLock(dataChangeDeviceMutex_);
    ResFinalizer finalizer([this]() { ConcurrentAdapter::AdapterAutoUnLock(dataChangeDeviceMutex_); });
    auto it = dataChangeCallbackMap_.find(connectionId);
    if (it != dataChangeCallbackMap_.end()) {
        if (it->second.find(observer) != it->second.end()) {
            LOGE("obsever already registered");
            return -E_ALREADY_SET;
        }
        if (it->second.size() >= DBConstant::MAX_OBSERVER_COUNT) {
            LOGE("The number of relational observers has been over limit");
            return -E_MAX_LIMITS;
        }
        it->second[observer] = action;
    } else {
        dataChangeCallbackMap_[connectionId][observer] = action;
    }
    LOGI("register relational observer ok");
    return E_OK;
}

int RelationalSyncAbleStorage::UnRegisterObserverAction(uint64_t connectionId, const StoreObserver *observer)
{
    if (observer == nullptr) {
        EraseDataChangeCallback(connectionId);
        return E_OK;
    }
    ConcurrentAdapter::AdapterAutoLock(dataChangeDeviceMutex_);
    ResFinalizer finalizer([this]() { ConcurrentAdapter::AdapterAutoUnLock(dataChangeDeviceMutex_); });
    auto it = dataChangeCallbackMap_.find(connectionId);
    if (it != dataChangeCallbackMap_.end()) {
        auto action = it->second.find(observer);
        if (action != it->second.end()) {
            it->second.erase(action);
            LOGI("unregister relational observer.");
            if (it->second.empty()) {
                dataChangeCallbackMap_.erase(it);
                LOGI("observer for this delegate is zero now");
            }
            return E_OK;
        }
    }
    return -E_NOT_FOUND;
}

void RelationalSyncAbleStorage::ExecuteDataChangeCallback(
    const std::pair<uint64_t, std::map<const StoreObserver *, RelationalObserverAction>> &item,
    const std::string &deviceName, const ChangedData &changedData, bool isChangedData, Origin origin)
{
    for (auto &action : item.second) {
        if (action.second == nullptr) {
            continue;
        }
        ChangedData observerChangeData = changedData;
        if (action.first != nullptr) {
            FilterChangeDataByDetailsType(observerChangeData, action.first->GetCallbackDetailsType());
        }
        action.second(deviceName, std::move(observerChangeData), isChangedData, origin);
    }
}

void RelationalSyncAbleStorage::TriggerObserverAction(const std::string &deviceName,
    ChangedData &&changedData, bool isChangedData)
{
    TriggerObserverAction(deviceName, std::move(changedData), isChangedData, Origin::ORIGIN_CLOUD);
}

void RelationalSyncAbleStorage::TriggerObserverAction(const std::string &deviceName, ChangedData &&changedData,
    bool isChangedData, Origin origin)
{
    IncObjRef(this);
    int taskErrCode =
        ConcurrentAdapter::ScheduleTask([this, deviceName, changedData, isChangedData, origin] () mutable {
            LOGD("begin to trigger relational observer.");
            ConcurrentAdapter::AdapterAutoLock(dataChangeDeviceMutex_);
            ResFinalizer finalizer([this]() { ConcurrentAdapter::AdapterAutoUnLock(dataChangeDeviceMutex_); });
            for (const auto &item : dataChangeCallbackMap_) {
                ExecuteDataChangeCallback(item, deviceName, changedData, isChangedData, origin);
            }
            DecObjRef(this);
        }, &dataChangeCallbackMap_);
    if (taskErrCode != E_OK) {
        LOGE("TriggerObserverAction scheduletask retCode=%d", taskErrCode);
        DecObjRef(this);
    }
}

void RelationalSyncAbleStorage::RegisterHeartBeatListener(const std::function<void()> &listener)
{
    std::lock_guard<std::mutex> autoLock(heartBeatMutex_);
    heartBeatListener_ = listener;
}

int RelationalSyncAbleStorage::CheckAndInitQueryCondition(QueryObject &query) const
{
    RelationalSchemaObject schema = storageEngine_->GetSchema();
    TableInfo table = schema.GetTable(query.GetTableName());
    if (!table.IsValid()) {
        LOGE("Query table is not a distributed table.");
        return -E_DISTRIBUTED_SCHEMA_NOT_FOUND;
    }
    if (table.GetTableSyncType() == CLOUD_COOPERATION) {
        LOGE("cloud table mode is not support");
        return -E_NOT_SUPPORT;
    }
    query.SetSchema(schema);

    int errCode = E_OK;
    auto *handle = GetHandle(true, errCode);
    if (handle == nullptr) {
        return errCode;
    }

    errCode = handle->CheckQueryObjectLegal(table, query, schema.GetSchemaVersion());
    if (errCode != E_OK) {
        LOGE("Check relational query condition failed. %d", errCode);
        TriggerCloseAutoLaunchConn(storageEngine_->GetProperties());
    }

    ReleaseHandle(handle);
    return errCode;
}

bool RelationalSyncAbleStorage::CheckCompatible(const std::string &schema, uint8_t type) const
{
    // return true if is relational schema.
    return !schema.empty() && ReadSchemaType(type) == SchemaType::RELATIVE;
}

int RelationalSyncAbleStorage::GetRemoteQueryData(const PreparedStmt &prepStmt, size_t packetSize,
    std::vector<std::string> &colNames, std::vector<RelationalRowData *> &data) const
{
    if (!storageEngine_->GetSchema().IsSchemaValid()) {
        return -E_NOT_SUPPORT;
    }
    if (prepStmt.GetOpCode() != PreparedStmt::ExecutorOperation::QUERY || !prepStmt.IsValid()) {
        LOGE("[ExecuteQuery] invalid args");
        return -E_INVALID_ARGS;
    }
    int errCode = E_OK;
    auto handle = GetHandle(false, errCode, OperatePerm::NORMAL_PERM);
    if (handle == nullptr) {
        LOGE("[ExecuteQuery] get handle fail:%d", errCode);
        return errCode;
    }
    errCode = handle->ExecuteQueryBySqlStmt(prepStmt.GetSql(), prepStmt.GetBindArgs(), packetSize, colNames, data);
    if (errCode != E_OK) {
        LOGE("[ExecuteQuery] ExecuteQueryBySqlStmt failed:%d", errCode);
    }
    ReleaseHandle(handle);
    return errCode;
}

int RelationalSyncAbleStorage::ExecuteQuery(const PreparedStmt &prepStmt, size_t packetSize,
    RelationalRowDataSet &dataSet, ContinueToken &token) const
{
    dataSet.Clear();
    if (token == nullptr) {
        // start query
        std::vector<std::string> colNames;
        std::vector<RelationalRowData *> data;
        ResFinalizer finalizer([&data] { RelationalRowData::Release(data); });

        int errCode = GetRemoteQueryData(prepStmt, packetSize, colNames, data);
        if (errCode != E_OK) {
            return errCode;
        }

        // create one token
        token = static_cast<ContinueToken>(
            new (std::nothrow) RelationalRemoteQueryContinueToken(std::move(colNames), std::move(data)));
        if (token == nullptr) {
            LOGE("ExecuteQuery OOM");
            return -E_OUT_OF_MEMORY;
        }
    }

    auto remoteToken = static_cast<RelationalRemoteQueryContinueToken *>(token);
    if (!remoteToken->CheckValid()) {
        LOGE("ExecuteQuery invalid token");
        return -E_INVALID_ARGS;
    }

    int errCode = remoteToken->GetData(packetSize, dataSet);
    if (errCode == -E_UNFINISHED) {
        errCode = E_OK;
    } else {
        if (errCode != E_OK) {
            dataSet.Clear();
        }
        delete remoteToken;
        remoteToken = nullptr;
        token = nullptr;
    }
    LOGI("ExecuteQuery finished, errCode:%d, size:%d", errCode, dataSet.GetSize());
    return errCode;
}

int RelationalSyncAbleStorage::SaveRemoteDeviceSchema(const std::string &deviceId, const std::string &remoteSchema,
    uint8_t type)
{
    if (ReadSchemaType(type) != SchemaType::RELATIVE) {
        return -E_INVALID_ARGS;
    }

    RelationalSchemaObject schemaObj;
    int errCode = schemaObj.ParseFromSchemaString(remoteSchema);
    if (errCode != E_OK) {
        LOGE("Parse remote schema failed. err=%d", errCode);
        return errCode;
    }

    std::string keyStr = DBConstant::REMOTE_DEVICE_SCHEMA_KEY_PREFIX + DBCommon::TransferHashString(deviceId);
    Key remoteSchemaKey(keyStr.begin(), keyStr.end());
    Value remoteSchemaBuff(remoteSchema.begin(), remoteSchema.end());
    errCode = PutMetaData(remoteSchemaKey, remoteSchemaBuff);
    if (errCode != E_OK) {
        LOGE("Save remote schema failed. err=%d", errCode);
        return errCode;
    }

    return remoteDeviceSchema_.Put(deviceId, remoteSchema);
}

int RelationalSyncAbleStorage::GetRemoteDeviceSchema(const std::string &deviceId,
    RelationalSchemaObject &schemaObj) const
{
    if (schemaObj.IsSchemaValid()) {
        LOGE("schema is already valid");
        return -E_INVALID_ARGS;
    }

    std::string remoteSchema;
    int errCode = remoteDeviceSchema_.Get(deviceId, remoteSchema);
    if (errCode == -E_NOT_FOUND) {
        LOGW("Get remote device schema miss cached.");
        std::string keyStr = DBConstant::REMOTE_DEVICE_SCHEMA_KEY_PREFIX + DBCommon::TransferHashString(deviceId);
        Key remoteSchemaKey(keyStr.begin(), keyStr.end());
        Value remoteSchemaBuff;
        errCode = GetMetaData(remoteSchemaKey, remoteSchemaBuff);
        if (errCode != E_OK) {
            LOGE("Get remote device schema from meta failed. err=%d", errCode);
            return errCode;
        }
        remoteSchema = std::string(remoteSchemaBuff.begin(), remoteSchemaBuff.end());
        errCode = remoteDeviceSchema_.Put(deviceId, remoteSchema);
    }

    if (errCode != E_OK) {
        LOGE("Get remote device schema failed. err=%d", errCode);
        return errCode;
    }

    errCode = schemaObj.ParseFromSchemaString(remoteSchema);
    if (errCode != E_OK) {
        LOGE("Parse remote schema failed. err=%d", errCode);
    }
    return errCode;
}

void RelationalSyncAbleStorage::SetReusedHandle(StorageExecutor *handle)
{
    std::lock_guard<std::mutex> autoLock(reusedHandleMutex_);
    reusedHandle_ = handle;
}

void RelationalSyncAbleStorage::ReleaseRemoteQueryContinueToken(ContinueToken &token) const
{
    auto remoteToken = static_cast<RelationalRemoteQueryContinueToken *>(token);
    delete remoteToken;
    remoteToken = nullptr;
    token = nullptr;
}

StoreInfo RelationalSyncAbleStorage::GetStoreInfo() const
{
    StoreInfo info = {
        storageEngine_->GetProperties().GetStringProp(DBProperties::USER_ID, ""),
        storageEngine_->GetProperties().GetStringProp(DBProperties::APP_ID, ""),
        storageEngine_->GetProperties().GetStringProp(DBProperties::STORE_ID, "")
    };
    return info;
}

int RelationalSyncAbleStorage::StartTransaction(TransactType type, bool isAsyncDownload)
{
    if (isAsyncDownload) {
        return StartTransactionForAsyncDownload(type);
    }
    if (storageEngine_ == nullptr) {
        return -E_INVALID_DB;
    }
    std::unique_lock<std::shared_mutex> lock(transactionMutex_);
    if (transactionHandle_ != nullptr) {
        LOGD("Transaction started already.");
        return -E_TRANSACT_STATE;
    }
    int errCode = E_OK;
    auto *handle = static_cast<SQLiteSingleVerRelationalStorageExecutor *>(
        storageEngine_->FindExecutor(type == TransactType::IMMEDIATE, OperatePerm::NORMAL_PERM, errCode));
    if (handle == nullptr) {
        ReleaseHandle(handle);
        return errCode;
    }
    errCode = handle->StartTransaction(type);
    if (errCode != E_OK) {
        ReleaseHandle(handle);
        return errCode;
    }
    transactionHandle_ = handle;
    return errCode;
}

int RelationalSyncAbleStorage::Commit(bool isAsyncDownload)
{
    if (isAsyncDownload) {
        return CommitForAsyncDownload();
    }
    std::unique_lock<std::shared_mutex> lock(transactionMutex_);
    if (transactionHandle_ == nullptr) {
        LOGE("relation database is null or the transaction has not been started");
        return -E_INVALID_DB;
    }
    int errCode = transactionHandle_->Commit();
    ReleaseHandle(transactionHandle_);
    transactionHandle_ = nullptr;
    LOGD("connection commit transaction!");
    return errCode;
}

int RelationalSyncAbleStorage::Rollback(bool isAsyncDownload)
{
    if (isAsyncDownload) {
        return RollbackForAsyncDownload();
    }
    std::unique_lock<std::shared_mutex> lock(transactionMutex_);
    if (transactionHandle_ == nullptr) {
        LOGE("Invalid handle for rollback or the transaction has not been started.");
        return -E_INVALID_DB;
    }

    int errCode = transactionHandle_->Rollback();
    ReleaseHandle(transactionHandle_);
    transactionHandle_ = nullptr;
    LOGI("connection rollback transaction!");
    return errCode;
}

int RelationalSyncAbleStorage::GetAllUploadCount(const QuerySyncObject &query,
    const std::vector<Timestamp> &timestampVec, bool isCloudForcePush, bool isCompensatedTask, int64_t &count)
{
    int errCode = E_OK;
    auto *handle = GetHandleExpectTransaction(false, errCode);
    if (handle == nullptr) {
        return errCode;
    }
    QuerySyncObject queryObj = query;
    queryObj.SetSchema(GetSchemaInfo());
    errCode = handle->GetAllUploadCount(timestampVec, isCloudForcePush, isCompensatedTask, queryObj, count);
    if (transactionHandle_ == nullptr) {
        ReleaseHandle(handle);
    }
    return errCode;
}

int RelationalSyncAbleStorage::GetUploadCount(const QuerySyncObject &query, const Timestamp &timestamp,
    bool isCloudForcePush, bool isCompensatedTask, int64_t &count)
{
    int errCode = E_OK;
    auto *handle = GetHandleExpectTransaction(false, errCode);
    if (handle == nullptr) {
        return errCode;
    }
    QuerySyncObject queryObj = query;
    queryObj.SetSchema(GetSchemaInfo());
    errCode = handle->GetUploadCount(timestamp, isCloudForcePush, isCompensatedTask, queryObj, count);
    if (transactionHandle_ == nullptr) {
        ReleaseHandle(handle);
    }
    return errCode;
}

int RelationalSyncAbleStorage::GetCloudData(const TableSchema &tableSchema, const QuerySyncObject &querySyncObject,
    const Timestamp &beginTime, ContinueToken &continueStmtToken, CloudSyncData &cloudDataResult)
{
    SyncTimeRange syncTimeRange = { .beginTime = beginTime };
    QuerySyncObject query = querySyncObject;
    query.SetSchema(GetSchemaInfo());
    auto token = new (std::nothrow) SQLiteSingleVerRelationalContinueToken(syncTimeRange, query);
    if (token == nullptr) {
        LOGE("[SingleVerNStore] Allocate continue token failed.");
        return -E_OUT_OF_MEMORY;
    }
    token->SetCloudTableSchema(tableSchema);
    continueStmtToken = static_cast<ContinueToken>(token);
    return GetCloudDataNext(continueStmtToken, cloudDataResult);
}

int RelationalSyncAbleStorage::GetCloudDataNext(ContinueToken &continueStmtToken,
    CloudSyncData &cloudDataResult)
{
    if (continueStmtToken == nullptr) {
        return -E_INVALID_ARGS;
    }
    auto token = static_cast<SQLiteSingleVerRelationalContinueToken *>(continueStmtToken);
    if (!token->CheckValid()) {
        return -E_INVALID_ARGS;
    }
    int errCode = E_OK;
    auto *handle = GetHandleExpectTransaction(false, errCode);
    if (handle == nullptr) {
        LOGE("Invalid handle, release the token, %d", errCode);
        ReleaseCloudDataToken(continueStmtToken);
        return -E_INVALID_DB;
    }
    cloudDataResult.isShared = IsSharedTable(cloudDataResult.tableName);
    auto config = GetCloudSyncConfig();
    handle->SetUploadConfig(config.maxUploadCount, config.maxUploadSize);
    errCode = handle->GetSyncCloudData(uploadRecorder_, cloudDataResult, *token);
    LOGI("mode:%d upload data, ins:%zu, upd:%zu, del:%zu, lock:%zu", cloudDataResult.mode,
        cloudDataResult.insData.extend.size(), cloudDataResult.updData.extend.size(),
        cloudDataResult.delData.extend.size(), cloudDataResult.lockData.extend.size());
    if (transactionHandle_ == nullptr) {
        ReleaseHandle(handle);
    }
    if (errCode != -E_UNFINISHED) {
        delete token;
        token = nullptr;
    }
    continueStmtToken = static_cast<ContinueToken>(token);
    if (errCode != E_OK && errCode != -E_UNFINISHED) {
        return errCode;
    }
    int fillRefGidCode = FillReferenceData(cloudDataResult);
    return fillRefGidCode == E_OK ? errCode : fillRefGidCode;
}

int RelationalSyncAbleStorage::GetCloudGid(const TableSchema &tableSchema, const QuerySyncObject &querySyncObject,
    bool isCloudForcePush, bool isCompensatedTask, std::vector<std::string> &cloudGid)
{
    int errCode = E_OK;
    auto *handle = GetHandle(false, errCode);
    if (handle == nullptr) {
        return errCode;
    }
    Timestamp beginTime = 0u;
    SyncTimeRange syncTimeRange = { .beginTime = beginTime };
    QuerySyncObject query = querySyncObject;
    query.SetSchema(GetSchemaInfo());
    handle->SetTableSchema(tableSchema);
    errCode = handle->GetSyncCloudGid(query, syncTimeRange, isCloudForcePush, isCompensatedTask, cloudGid);
    ReleaseHandle(handle);
    if (errCode != E_OK) {
        LOGE("[RelationalSyncAbleStorage] GetCloudGid failed %d", errCode);
    }
    return errCode;
}

int RelationalSyncAbleStorage::ReleaseCloudDataToken(ContinueToken &continueStmtToken)
{
    if (continueStmtToken == nullptr) {
        return E_OK;
    }
    auto token = static_cast<SQLiteSingleVerRelationalContinueToken *>(continueStmtToken);
    if (!token->CheckValid()) {
        return E_OK;
    }
    int errCode = token->ReleaseCloudStatement();
    delete token;
    token = nullptr;
    return errCode;
}

int RelationalSyncAbleStorage::GetSchemaFromDB(RelationalSchemaObject &schema)
{
    Key schemaKey;
    DBCommon::StringToVector(DBConstant::RELATIONAL_SCHEMA_KEY, schemaKey);
    Value schemaVal;
    int errCode = GetMetaData(schemaKey, schemaVal);
    if (errCode != E_OK && errCode != -E_NOT_FOUND) {
        LOGE("Get relational schema from DB failed. %d", errCode);
        return errCode;
    } else if (errCode == -E_NOT_FOUND || schemaVal.empty()) {
        LOGW("No relational schema info was found. error %d size %zu", errCode, schemaVal.size());
        return -E_NOT_FOUND;
    }
    std::string schemaStr;
    DBCommon::VectorToString(schemaVal, schemaStr);
    errCode = schema.ParseFromSchemaString(schemaStr);
    if (errCode != E_OK) {
        LOGE("Parse schema string from DB failed.");
        return errCode;
    }
    storageEngine_->SetSchema(schema);
    return errCode;
}

int RelationalSyncAbleStorage::ChkSchema(const TableName &tableName)
{
    std::shared_lock<std::shared_mutex> readLock(schemaMgrMutex_);
    RelationalSchemaObject localSchema = GetSchemaInfo();
    int errCode = schemaMgr_.ChkSchema(tableName, localSchema);
    if (errCode == -E_SCHEMA_MISMATCH) {
        LOGI("Get schema by tableName %s failed.", DBCommon::STR_MASK(tableName));
        RelationalSchemaObject newSchema;
        errCode = GetSchemaFromDB(newSchema);
        if (errCode != E_OK) {
            LOGE("Get schema from db when check schema. err: %d", errCode);
            return -E_SCHEMA_MISMATCH;
        }
        errCode = schemaMgr_.ChkSchema(tableName, newSchema);
    }
    return errCode;
}

int RelationalSyncAbleStorage::SetCloudDbSchema(const DataBaseSchema &schema)
{
    std::unique_lock<std::shared_mutex> writeLock(schemaMgrMutex_);
    RelationalSchemaObject localSchema = GetSchemaInfo();
    schemaMgr_.SetCloudDbSchema(schema, localSchema);
    return E_OK;
}

int RelationalSyncAbleStorage::GetInfoByPrimaryKeyOrGid(const std::string &tableName, const VBucket &vBucket,
    DataInfoWithLog &dataInfoWithLog, VBucket &assetInfo)
{
    return GetInfoByPrimaryKeyOrGid(tableName, vBucket, true, dataInfoWithLog, assetInfo);
}

int RelationalSyncAbleStorage::GetInfoByPrimaryKeyOrGidInner(SQLiteSingleVerRelationalStorageExecutor *handle,
    const std::string &tableName, const VBucket &vBucket, DataInfoWithLog &dataInfoWithLog, VBucket &assetInfo)
{
    if (handle == nullptr) {
        return -E_INVALID_DB;
    }
    TableSchema tableSchema;
    int errCode = GetCloudTableSchema(tableName, tableSchema);
    if (errCode != E_OK) {
        LOGE("Get cloud schema failed when query log for cloud sync, %d", errCode);
        return errCode;
    }
    RelationalSchemaObject localSchema = GetSchemaInfo();
    handle->SetLocalSchema(localSchema);
    return handle->GetInfoByPrimaryKeyOrGid(tableSchema, vBucket, dataInfoWithLog, assetInfo);
}

int RelationalSyncAbleStorage::PutCloudSyncData(const std::string &tableName, DownloadData &downloadData)
{
    if (transactionHandle_ == nullptr) {
        LOGE(" the transaction has not been started");
        return -E_INVALID_DB;
    }
    return PutCloudSyncDataInner(transactionHandle_, tableName, downloadData);
}

int RelationalSyncAbleStorage::PutCloudSyncDataInner(SQLiteSingleVerRelationalStorageExecutor *handle,
    const std::string &tableName, DownloadData &downloadData)
{
    TableSchema tableSchema;
    int errCode = GetCloudTableSchema(tableName, tableSchema);
    if (errCode != E_OK) {
        LOGE("Get cloud schema failed when save cloud data, %d", errCode);
        return errCode;
    }
    RelationalSchemaObject localSchema = GetSchemaInfo();
    handle->SetLocalSchema(localSchema);
    TrackerTable trackerTable = storageEngine_->GetTrackerSchema().GetTrackerTable(tableName);
    handle->SetLogicDelete(IsCurrentLogicDelete());
    errCode = handle->PutCloudSyncData(tableName, tableSchema, trackerTable, downloadData);
    handle->SetLogicDelete(false);
    return errCode;
}

int RelationalSyncAbleStorage::GetCloudDbSchema(std::shared_ptr<DataBaseSchema> &cloudSchema)
{
    std::shared_lock<std::shared_mutex> readLock(schemaMgrMutex_);
    cloudSchema = schemaMgr_.GetCloudDbSchema();
    return E_OK;
}

int RelationalSyncAbleStorage::CleanCloudData(ClearMode mode, const std::vector<std::string> &tableNameList,
    const RelationalSchemaObject &localSchema, std::vector<Asset> &assets)
{
    if (transactionHandle_ == nullptr) {
        LOGE("the transaction has not been started");
        return -E_INVALID_DB;
    }
    transactionHandle_->SetLogicDelete(logicDelete_);
    std::vector<std::string> notifyTableList;
    int errCode = transactionHandle_->DoCleanInner(mode, tableNameList, localSchema, assets, notifyTableList);
    if (!notifyTableList.empty()) {
        for (auto notifyTableName : notifyTableList) {
            ChangedData changedData;
            changedData.type = ChangedDataType::DATA;
            changedData.tableName = notifyTableName;
            std::vector<DistributedDB::Type> dataVec;
            DistributedDB::Type type;
            if (mode == FLAG_ONLY) {
                type = std::string(CloudDbConstant::FLAG_ONLY_MODE_NOTIFY);
            } else {
                type = std::string(CloudDbConstant::FLAG_AND_DATA_MODE_NOTIFY);
            }
            dataVec.push_back(type);
            changedData.primaryData[ChangeType::OP_DELETE].push_back(dataVec);
            TriggerObserverAction("CLOUD", std::move(changedData), true);
        }
    }
    transactionHandle_->SetLogicDelete(false);
    return errCode;
}

int RelationalSyncAbleStorage::ClearCloudLogVersion(const std::vector<std::string> &tableNameList)
{
    if (transactionHandle_ == nullptr) {
        LOGE("[RelationalSyncAbleStorage][ClearCloudLogVersion] the transaction has not been started");
        return -E_INVALID_DB;
    }
    return transactionHandle_->DoClearCloudLogVersion(tableNameList);
}

int RelationalSyncAbleStorage::GetCloudTableSchema(const TableName &tableName, TableSchema &tableSchema)
{
    std::shared_lock<std::shared_mutex> readLock(schemaMgrMutex_);
    return schemaMgr_.GetCloudTableSchema(tableName, tableSchema);
}

int RelationalSyncAbleStorage::FillCloudAssetForDownload(const std::string &tableName, VBucket &asset,
    bool isDownloadSuccess)
{
    if (storageEngine_ == nullptr) {
        return -E_INVALID_DB;
    }
    if (transactionHandle_ == nullptr) {
        LOGE("the transaction has not been started when fill asset for download.");
        return -E_INVALID_DB;
    }
    TableSchema tableSchema;
    int errCode = GetCloudTableSchema(tableName, tableSchema);
    if (errCode != E_OK) {
        LOGE("Get cloud schema failed when fill cloud asset, %d", errCode);
        return errCode;
    }
    uint64_t currCursor = DBConstant::INVALID_CURSOR;
    errCode = transactionHandle_->FillCloudAssetForDownload(tableSchema, asset, isDownloadSuccess, currCursor);
    if (errCode != E_OK) {
        LOGE("fill cloud asset for download failed.%d", errCode);
    }
    return errCode;
}

int RelationalSyncAbleStorage::SetLogTriggerStatus(bool status)
{
    int errCode = E_OK;
    auto *handle = GetHandleExpectTransaction(false, errCode);
    if (handle == nullptr) {
        return errCode;
    }
    errCode = handle->SetLogTriggerStatus(status);
    if (transactionHandle_ == nullptr) {
        ReleaseHandle(handle);
    }
    return errCode;
}

int RelationalSyncAbleStorage::SetCursorIncFlag(bool flag)
{
    int errCode = E_OK;
    auto *handle = GetHandleExpectTransaction(false, errCode);
    if (handle == nullptr) {
        return errCode;
    }
    errCode = handle->SetCursorIncFlag(flag);
    if (transactionHandle_ == nullptr) {
        ReleaseHandle(handle);
    }
    return errCode;
}

int RelationalSyncAbleStorage::FillCloudLogAndAsset(const OpType opType, const CloudSyncData &data, bool fillAsset,
    bool ignoreEmptyGid)
{
    if (storageEngine_ == nullptr) {
        return -E_INVALID_DB;
    }
    int errCode = E_OK;
    auto writeHandle = static_cast<SQLiteSingleVerRelationalStorageExecutor *>(
        storageEngine_->FindExecutor(true, OperatePerm::NORMAL_PERM, errCode));
    if (writeHandle == nullptr) {
        return errCode;
    }
    errCode = writeHandle->StartTransaction(TransactType::IMMEDIATE);
    if (errCode != E_OK) {
        ReleaseHandle(writeHandle);
        return errCode;
    }
    errCode = FillCloudLogAndAssetInner(writeHandle, opType, data, fillAsset, ignoreEmptyGid);
    if (errCode != E_OK) {
        LOGE("Failed to fill version or cloud asset, opType:%d ret:%d.", opType, errCode);
        writeHandle->Rollback();
        ReleaseHandle(writeHandle);
        return errCode;
    }
    errCode = writeHandle->Commit();
    ReleaseHandle(writeHandle);
    return errCode;
}

void RelationalSyncAbleStorage::SetSyncAbleEngine(std::shared_ptr<SyncAbleEngine> syncAbleEngine)
{
    syncAbleEngine_ = syncAbleEngine;
}

std::string RelationalSyncAbleStorage::GetIdentify() const
{
    if (storageEngine_ == nullptr) {
        LOGW("[RelationalSyncAbleStorage] engine is nullptr return default");
        return "";
    }
    return storageEngine_->GetIdentifier();
}

void RelationalSyncAbleStorage::EraseDataChangeCallback(uint64_t connectionId)
{
    TaskHandle handle = ConcurrentAdapter::ScheduleTaskH([this, connectionId] () mutable {
        ConcurrentAdapter::AdapterAutoLock(dataChangeDeviceMutex_);
        ResFinalizer finalizer([this]() { ConcurrentAdapter::AdapterAutoUnLock(dataChangeDeviceMutex_); });
        auto it = dataChangeCallbackMap_.find(connectionId);
        if (it != dataChangeCallbackMap_.end()) {
            dataChangeCallbackMap_.erase(it);
            LOGI("erase all observer for this delegate.");
        }
    }, nullptr, &dataChangeCallbackMap_);
    ADAPTER_WAIT(handle);
}

void RelationalSyncAbleStorage::ReleaseContinueToken(ContinueToken &continueStmtToken) const
{
    auto token = static_cast<SQLiteSingleVerRelationalContinueToken *>(continueStmtToken);
    if (token == nullptr || !(token->CheckValid())) {
        LOGW("[RelationalSyncAbleStorage][ReleaseContinueToken] Input is not a continue token.");
        return;
    }
    delete token;
    continueStmtToken = nullptr;
}

int RelationalSyncAbleStorage::CheckQueryValid(const QuerySyncObject &query)
{
    int errCode = E_OK;
    auto *handle = GetHandle(false, errCode);
    if (handle == nullptr) {
        return errCode;
    }
    errCode = handle->CheckQueryObjectLegal(query);
    if (errCode != E_OK) {
        ReleaseHandle(handle);
        return errCode;
    }
    QuerySyncObject queryObj = query;
    queryObj.SetSchema(GetSchemaInfo());
    int64_t count = 0;
    errCode = handle->GetUploadCount(UINT64_MAX, false, false, queryObj, count);
    ReleaseHandle(handle);
    if (errCode != E_OK) {
        LOGE("[RelationalSyncAbleStorage] CheckQueryValid failed %d", errCode);
        return -E_INVALID_ARGS;
    }
    return errCode;
}

int RelationalSyncAbleStorage::CreateTempSyncTrigger(const std::string &tableName)
{
    int errCode = E_OK;
    auto *handle = GetHandle(true, errCode);
    if (handle == nullptr) {
        return errCode;
    }
    errCode = CreateTempSyncTriggerInner(handle, tableName, true);
    ReleaseHandle(handle);
    if (errCode != E_OK) {
        LOGE("[RelationalSyncAbleStorage] Create temp sync trigger failed %d", errCode);
    }
    return errCode;
}

int RelationalSyncAbleStorage::GetAndResetServerObserverData(const std::string &tableName,
    ChangeProperties &changeProperties)
{
    int errCode = E_OK;
    auto *handle = GetHandle(false, errCode);
    if (handle == nullptr) {
        return errCode;
    }
    errCode = handle->GetAndResetServerObserverData(tableName, changeProperties);
    ReleaseHandle(handle);
    if (errCode != E_OK) {
        LOGE("[RelationalSyncAbleStorage] get server observer data failed %d", errCode);
    }
    return errCode;
}

void RelationalSyncAbleStorage::FilterChangeDataByDetailsType(ChangedData &changedData, uint32_t type)
{
    if ((type & static_cast<uint32_t>(CallbackDetailsType::DEFAULT)) == 0) {
        changedData.field = {};
        for (size_t i = ChangeType::OP_INSERT; i < ChangeType::OP_BUTT; ++i) {
            changedData.primaryData[i].clear();
        }
    }
    if ((type & static_cast<uint32_t>(CallbackDetailsType::BRIEF)) == 0) {
        changedData.properties = {};
    }
}

int RelationalSyncAbleStorage::ClearAllTempSyncTrigger()
{
    int errCode = E_OK;
    auto *handle = GetHandle(true, errCode);
    if (handle == nullptr) {
        return errCode;
    }
    errCode = handle->ClearAllTempSyncTrigger();
    ReleaseHandle(handle);
    if (errCode != E_OK) {
        LOGE("[RelationalSyncAbleStorage] clear all temp sync trigger failed %d", errCode);
    }
    return errCode;
}

int RelationalSyncAbleStorage::FillReferenceData(CloudSyncData &syncData)
{
    std::map<int64_t, Entries> referenceGid;
    int errCode = GetReferenceGid(syncData.tableName, syncData.insData, referenceGid);
    if (errCode != E_OK) {
        LOGE("[RelationalSyncAbleStorage] get insert reference data failed %d", errCode);
        return errCode;
    }
    errCode = FillReferenceDataIntoExtend(syncData.insData.rowid, referenceGid, syncData.insData.extend);
    if (errCode != E_OK) {
        return errCode;
    }
    referenceGid.clear();
    errCode = GetReferenceGid(syncData.tableName, syncData.updData, referenceGid);
    if (errCode != E_OK) {
        LOGE("[RelationalSyncAbleStorage] get update reference data failed %d", errCode);
        return errCode;
    }
    return FillReferenceDataIntoExtend(syncData.updData.rowid, referenceGid, syncData.updData.extend);
}

int RelationalSyncAbleStorage::FillReferenceDataIntoExtend(const std::vector<int64_t> &rowid,
    const std::map<int64_t, Entries> &referenceGid, std::vector<VBucket> &extend)
{
    if (referenceGid.empty()) {
        return E_OK;
    }
    int ignoredCount = 0;
    for (size_t index = 0u; index < rowid.size(); index++) {
        if (index >= extend.size()) {
            LOGE("[RelationalSyncAbleStorage] index out of range when fill reference gid into extend!");
            return -E_UNEXPECTED_DATA;
        }
        int64_t rowId = rowid[index];
        if (referenceGid.find(rowId) == referenceGid.end()) {
            // current data miss match reference data, we ignored it
            ignoredCount++;
            continue;
        }
        extend[index].insert({ CloudDbConstant::REFERENCE_FIELD, referenceGid.at(rowId) });
    }
    if (ignoredCount != 0) {
        LOGD("[RelationalSyncAbleStorage] ignored %d data when fill reference data", ignoredCount);
    }
    return E_OK;
}

bool RelationalSyncAbleStorage::IsSharedTable(const std::string &tableName)
{
    std::unique_lock<std::shared_mutex> writeLock(schemaMgrMutex_);
    return schemaMgr_.IsSharedTable(tableName);
}

std::map<std::string, std::string> RelationalSyncAbleStorage::GetSharedTableOriginNames()
{
    std::unique_lock<std::shared_mutex> writeLock(schemaMgrMutex_);
    return schemaMgr_.GetSharedTableOriginNames();
}

int RelationalSyncAbleStorage::GetReferenceGid(const std::string &tableName, const CloudSyncBatch &syncBatch,
    std::map<int64_t, Entries> &referenceGid)
{
    std::map<std::string, std::vector<TableReferenceProperty>> tableReference;
    int errCode = GetTableReference(tableName, tableReference);
    if (errCode != E_OK) {
        return errCode;
    }
    if (tableReference.empty()) {
        LOGD("[RelationalSyncAbleStorage] currentTable not exist reference property");
        return E_OK;
    }
    auto *handle = GetHandle(false, errCode);
    if (handle == nullptr) {
        return errCode;
    }
    errCode = handle->GetReferenceGid(tableName, syncBatch, tableReference, referenceGid);
    ReleaseHandle(handle);
    return errCode;
}

int RelationalSyncAbleStorage::GetTableReference(const std::string &tableName,
    std::map<std::string, std::vector<TableReferenceProperty>> &reference)
{
    if (storageEngine_ == nullptr) {
        LOGE("[RelationalSyncAbleStorage] storage is null when get reference gid");
        return -E_INVALID_DB;
    }
    RelationalSchemaObject schema = storageEngine_->GetSchema();
    auto referenceProperty = schema.GetReferenceProperty();
    if (referenceProperty.empty()) {
        return E_OK;
    }
    auto [sourceTableName, errCode] = GetSourceTableName(tableName);
    if (errCode != E_OK) {
        return errCode;
    }
    for (const auto &property : referenceProperty) {
        if (DBCommon::CaseInsensitiveCompare(property.sourceTableName, sourceTableName)) {
            if (!IsSharedTable(tableName)) {
                reference[property.targetTableName].push_back(property);
                continue;
            }
            TableReferenceProperty tableReference;
            tableReference.sourceTableName = tableName;
            tableReference.columns = property.columns;
            tableReference.columns[CloudDbConstant::CLOUD_OWNER] = CloudDbConstant::CLOUD_OWNER;
            auto [sharedTargetTable, ret] = GetSharedTargetTableName(property.targetTableName);
            if (ret != E_OK) {
                return ret;
            }
            tableReference.targetTableName = sharedTargetTable;
            reference[tableReference.targetTableName].push_back(tableReference);
        }
    }
    return E_OK;
}

std::pair<std::string, int> RelationalSyncAbleStorage::GetSourceTableName(const std::string &tableName)
{
    std::pair<std::string, int> res = { "", E_OK };
    std::shared_ptr<DataBaseSchema> cloudSchema;
    (void) GetCloudDbSchema(cloudSchema);
    if (cloudSchema == nullptr) {
        LOGE("[RelationalSyncAbleStorage] cloud schema is null when get source table");
        return { "", -E_INTERNAL_ERROR };
    }
    for (const auto &table : cloudSchema->tables) {
        if (CloudStorageUtils::IsSharedTable(table)) {
            continue;
        }
        if (DBCommon::CaseInsensitiveCompare(table.name, tableName) ||
            DBCommon::CaseInsensitiveCompare(table.sharedTableName, tableName)) {
            res.first = table.name;
            break;
        }
    }
    if (res.first.empty()) {
        LOGE("[RelationalSyncAbleStorage] not found table in cloud schema");
        res.second = -E_SCHEMA_MISMATCH;
    }
    return res;
}

std::pair<std::string, int> RelationalSyncAbleStorage::GetSharedTargetTableName(const std::string &tableName)
{
    std::pair<std::string, int> res = { "", E_OK };
    std::shared_ptr<DataBaseSchema> cloudSchema;
    (void) GetCloudDbSchema(cloudSchema);
    if (cloudSchema == nullptr) {
        LOGE("[RelationalSyncAbleStorage] cloud schema is null when get shared target table");
        return { "", -E_INTERNAL_ERROR };
    }
    for (const auto &table : cloudSchema->tables) {
        if (CloudStorageUtils::IsSharedTable(table)) {
            continue;
        }
        if (DBCommon::CaseInsensitiveCompare(table.name, tableName)) {
            res.first = table.sharedTableName;
            break;
        }
    }
    if (res.first.empty()) {
        LOGE("[RelationalSyncAbleStorage] not found table in cloud schema");
        res.second = -E_SCHEMA_MISMATCH;
    }
    return res;
}

void RelationalSyncAbleStorage::SetLogicDelete(bool logicDelete)
{
    logicDelete_ = logicDelete;
    LOGI("[RelationalSyncAbleStorage] set logic delete %d", static_cast<int>(logicDelete));
}

bool RelationalSyncAbleStorage::IsCurrentLogicDelete() const
{
    return logicDelete_;
}

std::pair<int, uint32_t> RelationalSyncAbleStorage::GetAssetsByGidOrHashKey(const TableSchema &tableSchema,
    const std::string &gid, const Bytes &hashKey, VBucket &assets)
{
    if (gid.empty() && hashKey.empty()) {
        LOGE("both gid and hashKey are empty.");
        return { -E_INVALID_ARGS, static_cast<uint32_t>(LockStatus::UNLOCK) };
    }
    if (transactionHandle_ == nullptr) {
        LOGE("the transaction has not been started");
        return { -E_INVALID_DB, static_cast<uint32_t>(LockStatus::UNLOCK) };
    }
    auto [errCode, status] = transactionHandle_->GetAssetsByGidOrHashKey(tableSchema, gid, hashKey, assets);
    if (errCode != E_OK && errCode != -E_NOT_FOUND && errCode != -E_CLOUD_GID_MISMATCH) {
        LOGE("get assets by gid or hashKey failed. %d", errCode);
    }
    return { errCode, status };
}

int RelationalSyncAbleStorage::SetIAssetLoader(const std::shared_ptr<IAssetLoader> &loader)
{
    int errCode = E_OK;
    auto *wHandle = GetHandle(true, errCode);
    if (wHandle == nullptr) {
        return errCode;
    }
    wHandle->SetIAssetLoader(loader);
    ReleaseHandle(wHandle);
    return errCode;
}

int RelationalSyncAbleStorage::UpsertData(RecordStatus status, const std::string &tableName,
    const std::vector<VBucket> &records)
{
    int errCode = E_OK;
    auto *handle = GetHandle(true, errCode);
    if (handle == nullptr || errCode != E_OK) {
        return errCode;
    }
    handle->SetPutDataMode(SQLiteSingleVerRelationalStorageExecutor::PutDataMode::USER);
    handle->SetMarkFlagOption(SQLiteSingleVerRelationalStorageExecutor::MarkFlagOption::SET_WAIT_COMPENSATED_SYNC);
    errCode = UpsertDataInner(handle, tableName, records);
    handle->SetPutDataMode(SQLiteSingleVerRelationalStorageExecutor::PutDataMode::SYNC);
    handle->SetMarkFlagOption(SQLiteSingleVerRelationalStorageExecutor::MarkFlagOption::DEFAULT);
    ReleaseHandle(handle);
    return errCode;
}

int RelationalSyncAbleStorage::UpsertDataInner(SQLiteSingleVerRelationalStorageExecutor *handle,
    const std::string &tableName, const std::vector<VBucket> &records)
{
    int errCode = E_OK;
    errCode = handle->StartTransaction(TransactType::IMMEDIATE);
    if (errCode != E_OK) {
        LOGE("[RDBStorageEngine] start transaction failed %d when upsert data", errCode);
        return errCode;
    }
    errCode = CreateTempSyncTriggerInner(handle, tableName);
    if (errCode == E_OK) {
        errCode = UpsertDataInTransaction(handle, tableName, records);
        (void) handle->ClearAllTempSyncTrigger();
    }
    if (errCode == E_OK) {
        errCode = handle->Commit();
        if (errCode != E_OK) {
            LOGE("[RDBStorageEngine] commit failed %d when upsert data", errCode);
        }
    } else {
        int ret = handle->Rollback();
        if (ret != E_OK) {
            LOGW("[RDBStorageEngine] rollback failed %d when upsert data", ret);
        }
    }
    return errCode;
}

int RelationalSyncAbleStorage::UpsertDataInTransaction(SQLiteSingleVerRelationalStorageExecutor *handle,
    const std::string &tableName, const std::vector<VBucket> &records)
{
    TableSchema tableSchema;
    int errCode = GetCloudTableSchema(tableName, tableSchema);
    if (errCode != E_OK) {
        LOGE("Get cloud schema failed when save cloud data, %d", errCode);
        return errCode;
    }
    TableInfo localTable = GetSchemaInfo().GetTable(tableName); // for upsert, the table must exist in local
    std::map<std::string, Field> pkMap = CloudStorageUtils::GetCloudPrimaryKeyFieldMap(tableSchema, true);
    std::set<std::vector<uint8_t>> primaryKeys;
    DownloadData downloadData;
    for (const auto &record : records) {
        DataInfoWithLog dataInfoWithLog;
        VBucket assetInfo;
        auto [errorCode, hashValue] = CloudStorageUtils::GetHashValueWithPrimaryKeyMap(record,
            tableSchema, localTable, pkMap, false);
        if (errorCode != E_OK) {
            return errorCode;
        }
        errCode = GetInfoByPrimaryKeyOrGidInner(handle, tableName, record, dataInfoWithLog, assetInfo);
        if (errCode != E_OK && errCode != -E_NOT_FOUND) {
            return errCode;
        }
        VBucket recordCopy = record;
        if ((errCode == -E_NOT_FOUND ||
            (dataInfoWithLog.logInfo.flag & static_cast<uint32_t>(LogInfoFlag::FLAG_DELETE)) != 0) &&
            primaryKeys.find(hashValue) == primaryKeys.end()) {
            downloadData.opType.push_back(OpType::INSERT);
            auto currentTime = TimeHelper::GetSysCurrentTime();
            recordCopy[CloudDbConstant::MODIFY_FIELD] = static_cast<int64_t>(currentTime);
            recordCopy[CloudDbConstant::CREATE_FIELD] = static_cast<int64_t>(currentTime);
            primaryKeys.insert(hashValue);
        } else {
            downloadData.opType.push_back(OpType::UPDATE);
            recordCopy[CloudDbConstant::GID_FIELD] = dataInfoWithLog.logInfo.cloudGid;
            recordCopy[CloudDbConstant::MODIFY_FIELD] = static_cast<int64_t>(dataInfoWithLog.logInfo.timestamp);
            recordCopy[CloudDbConstant::CREATE_FIELD] = static_cast<int64_t>(dataInfoWithLog.logInfo.wTimestamp);
            recordCopy[CloudDbConstant::SHARING_RESOURCE_FIELD] = dataInfoWithLog.logInfo.sharingResource;
            recordCopy[CloudDbConstant::VERSION_FIELD] = dataInfoWithLog.logInfo.version;
        }
        downloadData.existDataKey.push_back(dataInfoWithLog.logInfo.dataKey);
        downloadData.data.push_back(std::move(recordCopy));
    }
    return PutCloudSyncDataInner(handle, tableName, downloadData);
}

int RelationalSyncAbleStorage::UpdateRecordFlag(const std::string &tableName, bool recordConflict,
    const LogInfo &logInfo)
{
    if (transactionHandle_ == nullptr) {
        LOGE("[RelationalSyncAbleStorage] the transaction has not been started");
        return -E_INVALID_DB;
    }
    TableSchema tableSchema;
    GetCloudTableSchema(tableName, tableSchema);
    std::vector<VBucket> assets;
    int errCode = transactionHandle_->GetDownloadAssetRecordsByGid(tableSchema, logInfo.cloudGid, assets);
    if (errCode != E_OK) {
        LOGE("[RelationalSyncAbleStorage] get download asset by gid %s failed %d",
            DBCommon::StringMiddleMasking(logInfo.cloudGid).c_str(), errCode);
        return errCode;
    }
    bool isInconsistency = !assets.empty();
    UpdateRecordFlagStruct updateRecordFlag = {
        .tableName = tableName,
        .isRecordConflict = recordConflict,
        .isInconsistency = isInconsistency
    };
    std::string sql = CloudStorageUtils::GetUpdateRecordFlagSql(updateRecordFlag, logInfo);
    return transactionHandle_->UpdateRecordFlag(tableName, sql, logInfo);
}

int RelationalSyncAbleStorage::FillCloudLogAndAssetInner(SQLiteSingleVerRelationalStorageExecutor *handle,
    OpType opType, const CloudSyncData &data, bool fillAsset, bool ignoreEmptyGid)
{
    TableSchema tableSchema;
    int errCode = GetCloudTableSchema(data.tableName, tableSchema);
    if (errCode != E_OK) {
        LOGE("get table schema failed when fill log and asset. %d", errCode);
        return errCode;
    }
    errCode = handle->FillHandleWithOpType(opType, data, fillAsset, ignoreEmptyGid, tableSchema);
    if (errCode != E_OK) {
        return errCode;
    }
    if (opType == OpType::INSERT) {
        errCode = CloudStorageUtils::UpdateRecordFlagAfterUpload(
            handle, {data.tableName, CloudWaterType::INSERT, tableSchema}, data.insData, uploadRecorder_);
    } else if (opType == OpType::UPDATE) {
        errCode = CloudStorageUtils::UpdateRecordFlagAfterUpload(
            handle, {data.tableName, CloudWaterType::UPDATE, tableSchema}, data.updData, uploadRecorder_);
    } else if (opType == OpType::DELETE) {
        errCode = CloudStorageUtils::UpdateRecordFlagAfterUpload(
            handle, {data.tableName, CloudWaterType::DELETE, tableSchema}, data.delData, uploadRecorder_);
    } else if (opType == OpType::LOCKED_NOT_HANDLE) {
        errCode = CloudStorageUtils::UpdateRecordFlagAfterUpload(
            handle, {data.tableName, CloudWaterType::BUTT, tableSchema}, data.lockData, uploadRecorder_, true);
    }
    return errCode;
}

int RelationalSyncAbleStorage::GetCompensatedSyncQuery(std::vector<QuerySyncObject> &syncQuery,
    std::vector<std::string> &users, bool isQueryDownloadRecords)
{
    std::vector<TableSchema> tables;
    int errCode = GetCloudTableWithoutShared(tables);
    if (errCode != E_OK) {
        return errCode;
    }
    if (tables.empty()) {
        LOGD("[RDBStorage] Table is empty, no need to compensated sync");
        return E_OK;
    }
    auto *handle = GetHandle(true, errCode);
    if (handle == nullptr || errCode != E_OK) {
        return errCode;
    }
    errCode = GetCompensatedSyncQueryInner(handle, tables, syncQuery, isQueryDownloadRecords);
    ReleaseHandle(handle);
    return errCode;
}

int RelationalSyncAbleStorage::ClearUnLockingNoNeedCompensated()
{
    std::vector<TableSchema> tables;
    int errCode = GetCloudTableWithoutShared(tables);
    if (errCode != E_OK) {
        return errCode;
    }
    if (tables.empty()) {
        LOGI("[RDBStorage] Table is empty, no need to clear unlocking status");
        return E_OK;
    }
    auto *handle = GetHandle(true, errCode);
    if (handle == nullptr || errCode != E_OK) {
        return errCode;
    }
    errCode = handle->StartTransaction(TransactType::IMMEDIATE);
    if (errCode != E_OK) {
        ReleaseHandle(handle);
        return errCode;
    }
    for (const auto &table : tables) {
        errCode = handle->ClearUnLockingStatus(table.name);
        if (errCode != E_OK) {
            LOGW("[ClearUnLockingNoNeedCompensated] clear unlocking status failed, continue! errCode=%d", errCode);
        }
    }
    errCode = handle->Commit();
    if (errCode != E_OK) {
        LOGE("[ClearUnLockingNoNeedCompensated] commit failed %d when clear unlocking status", errCode);
    }
    ReleaseHandle(handle);
    return errCode;
}

int RelationalSyncAbleStorage::GetCloudTableWithoutShared(std::vector<TableSchema> &tables)
{
    const auto tableInfos = GetSchemaInfo().GetTables();
    for (const auto &[tableName, info] : tableInfos) {
        if (info.GetSharedTableMark()) {
            continue;
        }
        TableSchema schema;
        int errCode = GetCloudTableSchema(tableName, schema);
        if (errCode == -E_NOT_FOUND) {
            continue;
        }
        if (errCode != E_OK) {
            LOGW("[RDBStorage] Get cloud table failed %d", errCode);
            return errCode;
        }
        tables.push_back(schema);
    }
    return E_OK;
}

int RelationalSyncAbleStorage::GetCompensatedSyncQueryInner(SQLiteSingleVerRelationalStorageExecutor *handle,
    const std::vector<TableSchema> &tables, std::vector<QuerySyncObject> &syncQuery, bool isQueryDownloadRecords)
{
    int errCode = E_OK;
    errCode = handle->StartTransaction(TransactType::IMMEDIATE);
    if (errCode != E_OK) {
        return errCode;
    }
    for (const auto &table : tables) {
        if (!CheckTableSupportCompensatedSync(table)) {
            continue;
        }

        std::vector<VBucket> syncDataPk;
        errCode = handle->GetWaitCompensatedSyncDataPk(table, syncDataPk, isQueryDownloadRecords);
        if (errCode != E_OK) {
            LOGW("[RDBStorageEngine] Get wait compensated sync data failed, continue! errCode=%d", errCode);
            errCode = E_OK;
            continue;
        }
        if (syncDataPk.empty()) {
            // no data need to compensated sync
            continue;
        }
        errCode = CloudStorageUtils::GetSyncQueryByPk(table.name, syncDataPk, false, syncQuery);
        if (errCode != E_OK) {
            LOGW("[RDBStorageEngine] Get compensated sync query happen error, ignore it! errCode = %d", errCode);
            errCode = E_OK;
            continue;
        }
    }
    if (errCode == E_OK) {
        errCode = handle->Commit();
        if (errCode != E_OK) {
            LOGE("[RDBStorageEngine] commit failed %d when get compensated sync query", errCode);
        }
    } else {
        int ret = handle->Rollback();
        if (ret != E_OK) {
            LOGW("[RDBStorageEngine] rollback failed %d when get compensated sync query", ret);
        }
    }
    return errCode;
}

int RelationalSyncAbleStorage::CreateTempSyncTriggerInner(SQLiteSingleVerRelationalStorageExecutor *handle,
    const std::string &tableName, bool flag)
{
    TrackerTable trackerTable = storageEngine_->GetTrackerSchema().GetTrackerTable(tableName);
    if (trackerTable.IsEmpty()) {
        trackerTable.SetTableName(tableName);
    }
    return handle->CreateTempSyncTrigger(trackerTable, flag);
}

bool RelationalSyncAbleStorage::CheckTableSupportCompensatedSync(const TableSchema &table)
{
    auto it = std::find_if(table.fields.begin(), table.fields.end(), [](const auto &field) {
        return field.primary && (field.type == TYPE_INDEX<Asset> || field.type == TYPE_INDEX<Assets> ||
            field.type == TYPE_INDEX<Bytes>);
    });
    if (it != table.fields.end()) {
        LOGI("[RDBStorageEngine] Table contain not support pk field type, ignored");
        return false;
    }
    // check whether reference exist
    std::map<std::string, std::vector<TableReferenceProperty>> tableReference;
    int errCode = RelationalSyncAbleStorage::GetTableReference(table.name, tableReference);
    if (errCode != E_OK) {
        LOGW("[RDBStorageEngine] Get table reference failed! errCode = %d", errCode);
        return false;
    }
    if (!tableReference.empty()) {
        LOGI("[RDBStorageEngine] current table exist reference property");
        return false;
    }
    return true;
}

int RelationalSyncAbleStorage::MarkFlagAsConsistent(const std::string &tableName, const DownloadData &downloadData,
    const std::set<std::string> &gidFilters)
{
    if (transactionHandle_ == nullptr) {
        LOGE("the transaction has not been started");
        return -E_INVALID_DB;
    }
    int errCode = transactionHandle_->MarkFlagAsConsistent(tableName, downloadData, gidFilters);
    if (errCode != E_OK) {
        LOGE("[RelationalSyncAbleStorage] mark flag as consistent failed.%d", errCode);
    }
    return errCode;
}

CloudSyncConfig RelationalSyncAbleStorage::GetCloudSyncConfig() const
{
    std::lock_guard<std::mutex> autoLock(configMutex_);
    return cloudSyncConfig_;
}

void RelationalSyncAbleStorage::SetCloudSyncConfig(const CloudSyncConfig &config)
{
    std::lock_guard<std::mutex> autoLock(configMutex_);
    cloudSyncConfig_ = config;
}

bool RelationalSyncAbleStorage::IsTableExistReference(const std::string &table)
{
    // check whether reference exist
    std::map<std::string, std::vector<TableReferenceProperty>> tableReference;
    int errCode = RelationalSyncAbleStorage::GetTableReference(table, tableReference);
    if (errCode != E_OK) {
        LOGW("[RDBStorageEngine] Get table reference failed! errCode = %d", errCode);
        return false;
    }
    return !tableReference.empty();
}

bool RelationalSyncAbleStorage::IsTableExistReferenceOrReferenceBy(const std::string &table)
{
    // check whether reference or reference by exist
    if (storageEngine_ == nullptr) {
        LOGE("[IsTableExistReferenceOrReferenceBy] storage is null when get reference gid");
        return false;
    }
    RelationalSchemaObject schema = storageEngine_->GetSchema();
    auto referenceProperty = schema.GetReferenceProperty();
    if (referenceProperty.empty()) {
        return false;
    }
    auto [sourceTableName, errCode] = GetSourceTableName(table);
    if (errCode != E_OK) {
        return false;
    }
    for (const auto &property : referenceProperty) {
        if (DBCommon::CaseInsensitiveCompare(property.sourceTableName, sourceTableName) ||
            DBCommon::CaseInsensitiveCompare(property.targetTableName, sourceTableName)) {
            return true;
        }
    }
    return false;
}

void RelationalSyncAbleStorage::ReleaseUploadRecord(const std::string &tableName, const CloudWaterType &type,
    Timestamp localMark)
{
    uploadRecorder_.ReleaseUploadRecord(tableName, type, localMark);
}

int RelationalSyncAbleStorage::ReviseLocalModTime(const std::string &tableName,
    const std::vector<ReviseModTimeInfo> &revisedData)
{
    if (storageEngine_ == nullptr) {
        LOGE("[ReviseLocalModTime] Storage is null");
        return -E_INVALID_DB;
    }
    int errCode = E_OK;
    auto writeHandle = static_cast<SQLiteSingleVerRelationalStorageExecutor *>(
            storageEngine_->FindExecutor(true, OperatePerm::NORMAL_PERM, errCode));
    if (writeHandle == nullptr) {
        LOGE("[ReviseLocalModTime] Get write handle fail: %d", errCode);
        return errCode;
    }
    errCode = writeHandle->StartTransaction(TransactType::IMMEDIATE);
    if (errCode != E_OK) {
        LOGE("[ReviseLocalModTime] Start Transaction fail: %d", errCode);
        ReleaseHandle(writeHandle);
        return errCode;
    }
    errCode = writeHandle->ReviseLocalModTime(tableName, revisedData);
    if (errCode != E_OK) {
        LOGE("[ReviseLocalModTime] Revise local modify time fail: %d", errCode);
        writeHandle->Rollback();
        ReleaseHandle(writeHandle);
        return errCode;
    }
    errCode = writeHandle->Commit();
    ReleaseHandle(writeHandle);
    return errCode;
}

int RelationalSyncAbleStorage::GetCursor(const std::string &tableName, uint64_t &cursor)
{
    if (transactionHandle_ == nullptr) {
        LOGE("[RelationalSyncAbleStorage] the transaction has not been started");
        return -E_INVALID_DB;
    }
    return transactionHandle_->GetCursor(tableName, cursor);
}

int RelationalSyncAbleStorage::GetLocalDataCount(const std::string &tableName, int &dataCount,
    int &logicDeleteDataCount)
{
    int errCode = E_OK;
    auto *handle = GetHandle(false, errCode);
    if (handle == nullptr || errCode != E_OK) {
        LOGE("[RelationalSyncAbleStorage] Get handle failed when get local data count: %d", errCode);
        return errCode;
    }
    errCode = handle->GetLocalDataCount(tableName, dataCount, logicDeleteDataCount);
    ReleaseHandle(handle);
    return errCode;
}
}
#endif
