/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include "sqlite_cloud_kv_store.h"

#include "cloud/cloud_db_constant.h"
#include "cloud/cloud_storage_utils.h"
#include "db_base64_utils.h"
#include "db_common.h"
#include "query_utils.h"
#include "res_finalizer.h"
#include "runtime_context.h"
#include "sqlite_cloud_kv_executor_utils.h"
#include "sqlite_single_ver_continue_token.h"

namespace DistributedDB {
SqliteCloudKvStore::SqliteCloudKvStore(KvStorageHandle *handle)
    : storageHandle_(handle), transactionHandle_(nullptr)
{
}

int SqliteCloudKvStore::GetMetaData(const Key &key, Value &value) const
{
    return storageHandle_->GetMetaData(key, value);
}

int SqliteCloudKvStore::PutMetaData(const Key &key, const Value &value)
{
    return storageHandle_->PutMetaData(key, value, false);
}

int SqliteCloudKvStore::ChkSchema(const TableName &tableName)
{
    return E_OK;
}

int SqliteCloudKvStore::SetCloudDbSchema(const DataBaseSchema &schema)
{
    return E_OK;
}

int SqliteCloudKvStore::SetCloudDbSchema(const std::map<std::string, DataBaseSchema> &schema)
{
    std::lock_guard<std::mutex> autoLock(schemaMutex_);
    if (!CheckSchema(schema)) {
        return -E_INVALID_SCHEMA;
    }
    schema_ = schema;
    return E_OK;
}

int SqliteCloudKvStore::GetCloudDbSchema(std::shared_ptr<DataBaseSchema> &cloudSchema)
{
    std::lock_guard<std::mutex> autoLock(schemaMutex_);
    cloudSchema = std::make_shared<DataBaseSchema>(schema_[user_]);
    return E_OK;
}

int SqliteCloudKvStore::GetCloudTableSchema(const TableName &tableName,
    TableSchema &tableSchema)
{
    std::lock_guard<std::mutex> autoLock(schemaMutex_);
    if (schema_.find(user_) == schema_.end()) {
        LOGE("[SqliteCloudKvStore] not set cloud schema");
        return -E_SCHEMA_MISMATCH;
    }
    auto it = std::find_if(schema_[user_].tables.begin(), schema_[user_].tables.end(), [&](const auto &table) {
        return table.name == tableName;
    });
    if (it != schema_[user_].tables.end()) {
        tableSchema = *it;
        return E_OK;
    }
    LOGW("[SqliteCloudKvStore] not found table schema");
    return -E_NOT_FOUND;
}

int SqliteCloudKvStore::StartTransaction(TransactType type, bool isAsyncDownload)
{
    if (isAsyncDownload) {
        return StartTransactionForAsyncDownload(type);
    }
    {
        std::lock_guard<std::mutex> autoLock(transactionMutex_);
        if (transactionHandle_ != nullptr) {
            LOGW("[SqliteCloudKvStore] transaction has been started");
            return E_OK;
        }
    }
    auto [errCode, handle] = storageHandle_->GetStorageExecutor(type == TransactType::IMMEDIATE);
    if (errCode != E_OK) {
        return errCode;
    }
    if (handle == nullptr) {
        LOGE("[SqliteCloudKvStore] get handle return null");
        return -E_INTERNAL_ERROR;
    }
    errCode = handle->StartTransaction(type);
    std::lock_guard<std::mutex> autoLock(transactionMutex_);
    transactionHandle_ = handle;
    LOGD("[SqliteCloudKvStore] start transaction!");
    return errCode;
}

int SqliteCloudKvStore::Commit(bool isAsyncDownload)
{
    if (isAsyncDownload) {
        return CommitForAsyncDownload();
    }
    SQLiteSingleVerStorageExecutor *handle;
    {
        std::lock_guard<std::mutex> autoLock(transactionMutex_);
        if (transactionHandle_ == nullptr) {
            LOGW("[SqliteCloudKvStore] no need to commit, transaction has not been started");
            return E_OK;
        }
        handle = transactionHandle_;
        transactionHandle_ = nullptr;
    }
    int errCode = handle->Commit();
    storageHandle_->RecycleStorageExecutor(handle);
    LOGD("[SqliteCloudKvStore] commit transaction!");
    return errCode;
}

int SqliteCloudKvStore::Rollback(bool isAsyncDownload)
{
    if (isAsyncDownload) {
        return RollbackForAsyncDownload();
    }
    SQLiteSingleVerStorageExecutor *handle;
    {
        std::lock_guard<std::mutex> autoLock(transactionMutex_);
        if (transactionHandle_ == nullptr) {
            LOGW("[SqliteCloudKvStore] no need to rollback, transaction has not been started");
            return E_OK;
        }
        handle = transactionHandle_;
        transactionHandle_ = nullptr;
    }
    int errCode = handle->Rollback();
    storageHandle_->RecycleStorageExecutor(handle);
    LOGD("[SqliteCloudKvStore] rollback transaction!");
    return errCode;
}

int SqliteCloudKvStore::StartTransactionForAsyncDownload(TransactType type)
{
    {
        std::lock_guard<std::mutex> autoLock(transactionMutex_);
        if (asyncDownloadTransactionHandle_ != nullptr) {
            LOGW("[SqliteCloudKvStore] async download transaction has been started");
            return E_OK;
        }
    }
    auto [errCode, handle] = storageHandle_->GetStorageExecutor(type == TransactType::IMMEDIATE);
    if (errCode != E_OK) {
        return errCode;
    }
    if (handle == nullptr) {
        LOGE("[SqliteCloudKvStore] get handle return null");
        return -E_INTERNAL_ERROR;
    }
    errCode = handle->StartTransaction(type);
    std::lock_guard<std::mutex> autoLock(transactionMutex_);
    asyncDownloadTransactionHandle_ = handle;
    LOGD("[SqliteCloudKvStore] start async download transaction!");
    return errCode;
}

int SqliteCloudKvStore::CommitForAsyncDownload()
{
    SQLiteSingleVerStorageExecutor *handle;
    {
        std::lock_guard<std::mutex> autoLock(transactionMutex_);
        if (asyncDownloadTransactionHandle_ == nullptr) {
            LOGW("[SqliteCloudKvStore] no need to commit, transaction has not been started");
            return E_OK;
        }
        handle = asyncDownloadTransactionHandle_;
        asyncDownloadTransactionHandle_ = nullptr;
    }
    int errCode = handle->Commit();
    storageHandle_->RecycleStorageExecutor(handle);
    LOGD("[SqliteCloudKvStore] commit transaction!");
    return errCode;
}

int SqliteCloudKvStore::RollbackForAsyncDownload()
{
    SQLiteSingleVerStorageExecutor *handle;
    {
        std::lock_guard<std::mutex> autoLock(transactionMutex_);
        if (asyncDownloadTransactionHandle_ == nullptr) {
            LOGW("[SqliteCloudKvStore] no need to rollback, transaction has not been started");
            return E_OK;
        }
        handle = asyncDownloadTransactionHandle_;
        asyncDownloadTransactionHandle_ = nullptr;
    }
    int errCode = handle->Rollback();
    storageHandle_->RecycleStorageExecutor(handle);
    LOGD("[SqliteCloudKvStore] rollback transaction!");
    return errCode;
}

int SqliteCloudKvStore::GetUploadCount([[gnu::unused]] const QuerySyncObject &query,
    const Timestamp &timestamp, bool isCloudForcePush, [[gnu::unused]] bool isCompensatedTask,
    int64_t &count)
{
    auto [db, handle] = GetTransactionDbHandleAndMemoryStatus(false);
    if (db == nullptr || handle == nullptr) {
        LOGE("[SqliteCloudKvStore] get upload count without transaction");
        return -E_INTERNAL_ERROR;
    }
    int errCode = E_OK;
    std::tie(errCode, count) = SqliteCloudKvExecutorUtils::CountCloudData(db, handle->IsMemory(), timestamp, user_,
        isCloudForcePush);
    if (transactionHandle_ == nullptr) {
        storageHandle_->RecycleStorageExecutor(handle);
    }
    return errCode;
}

int SqliteCloudKvStore::GetAllUploadCount(const QuerySyncObject &query,
    const std::vector<Timestamp> &timestampVec, bool isCloudForcePush, [[gnu::unused]] bool isCompensatedTask,
    int64_t &count)
{
    auto [db, handle] = GetTransactionDbHandleAndMemoryStatus(false);
    if (db == nullptr || handle == nullptr) {
        LOGE("[SqliteCloudKvStore] get upload count without transaction");
        return -E_INTERNAL_ERROR;
    }
    int errCode = E_OK;
    QuerySyncObject queryObj = query;
    std::tie(errCode, count) = SqliteCloudKvExecutorUtils::CountAllCloudData(
        {db, handle->IsMemory()}, timestampVec, user_, isCloudForcePush, queryObj);
    if (transactionHandle_ == nullptr) {
        storageHandle_->RecycleStorageExecutor(handle);
    }
    return errCode;
}

int SqliteCloudKvStore::GetCloudData(const TableSchema &tableSchema, const QuerySyncObject &object,
    const Timestamp &beginTime, ContinueToken &continueStmtToken, CloudSyncData &cloudDataResult)
{
    SyncTimeRange timeRange;
    timeRange.beginTime = 0;
    auto token = new (std::nothrow) SQLiteSingleVerContinueToken(timeRange, object);
    if (token == nullptr) {
        LOGE("[SqliteCloudKvStore] create token failed");
        return -E_OUT_OF_MEMORY;
    }
    token->SetUser(user_);
    recorder_.SetUser(user_);
    cloudDataResult.tableName = CloudDbConstant::CLOUD_KV_TABLE_NAME;
    continueStmtToken = static_cast<ContinueToken>(token);
    return GetCloudDataNext(continueStmtToken, cloudDataResult);
}

int SqliteCloudKvStore::GetCloudDataNext(ContinueToken &continueStmtToken, CloudSyncData &cloudDataResult)
{
    if (continueStmtToken == nullptr) {
        LOGE("[SqliteCloudKvStore] token is null");
        return -E_INVALID_ARGS;
    }
    auto token = static_cast<SQLiteSingleVerContinueToken *>(continueStmtToken);
    if (!token->CheckValid()) {
        LOGE("[SqliteCloudKvStore] token is invalid");
        return -E_INVALID_ARGS;
    }
    auto [db, handle] = GetTransactionDbHandleAndMemoryStatus(false);
    if (db == nullptr || handle == nullptr) {
        LOGE("[SqliteCloudKvStore] the transaction has not been started, release the token");
        ReleaseCloudDataToken(continueStmtToken);
        return -E_INTERNAL_ERROR;
    }
    int errCode = SqliteCloudKvExecutorUtils::GetCloudData(
        GetCloudSyncConfig(), {db, handle->IsMemory()}, recorder_, *token, cloudDataResult);
    if (transactionHandle_ == nullptr) {
        storageHandle_->RecycleStorageExecutor(handle);
    }
    if (errCode != -E_UNFINISHED) {
        ReleaseCloudDataToken(continueStmtToken);
    } else {
        continueStmtToken = token;
    }
    return errCode;
}

int SqliteCloudKvStore::ReleaseCloudDataToken(ContinueToken &continueStmtToken)
{
    if (continueStmtToken == nullptr) {
        return E_OK;
    }
    auto token = static_cast<SQLiteSingleVerContinueToken *>(continueStmtToken);
    if (!token->CheckValid()) {
        return E_OK;
    }
    token->ReleaseCloudQueryStmt();
    delete token;
    continueStmtToken = nullptr;
    return E_OK;
}

int SqliteCloudKvStore::GetInfoByPrimaryKeyOrGid([[gnu::unused]] const std::string &tableName, const VBucket &vBucket,
    DataInfoWithLog &dataInfoWithLog, [[gnu::unused]] VBucket &assetInfo)
{
    auto [db, handle] = GetTransactionDbHandleAndMemoryStatus(false);
    if (db == nullptr || handle == nullptr) {
        LOGE("[SqliteCloudKvStore] the transaction has not been started");
        return -E_INTERNAL_ERROR;
    }
    int errCode = E_OK;
    std::tie(errCode, dataInfoWithLog) = SqliteCloudKvExecutorUtils::GetLogInfo(db, handle->IsMemory(), vBucket, user_);
    if (transactionHandle_ == nullptr) {
        storageHandle_->RecycleStorageExecutor(handle);
    }
    return errCode;
}

int SqliteCloudKvStore::PutCloudSyncData([[gnu::unused]] const std::string &tableName, DownloadData &downloadData)
{
    auto [db, handle] = GetTransactionDbHandleAndMemoryStatus(true);
    if (db == nullptr || handle == nullptr) {
        LOGE("[SqliteCloudKvStore] the transaction has not been started");
        return -E_INTERNAL_ERROR;
    }
    downloadData.timeOffset = storageHandle_->GetLocalTimeOffsetForCloud();
    int ret = SqliteCloudKvExecutorUtils::PutCloudData(db, handle->IsMemory(), downloadData);
    if (transactionHandle_ == nullptr) {
        storageHandle_->RecycleStorageExecutor(handle);
    }
    return ret;
}

int SqliteCloudKvStore::UpdateAssetStatusForAssetOnly(const std::string &tableName, VBucket &asset)
{
    return E_OK;
}

int SqliteCloudKvStore::FillCloudLogAndAsset(OpType opType, const CloudSyncData &data, bool fillAsset,
    bool ignoreEmptyGid)
{
    auto [errCode, handle] = storageHandle_->GetStorageExecutor(true);
    if (errCode != E_OK) {
        LOGE("[SqliteCloudKvStore] get handle failed %d when fill log", errCode);
        return errCode;
    }
    sqlite3 *db = nullptr;
    (void)handle->GetDbHandle(db);
    errCode = SqliteCloudKvExecutorUtils::FillCloudLog({db, ignoreEmptyGid}, opType, data, user_, recorder_);
    storageHandle_->RecycleStorageExecutor(handle);
    return errCode;
}

void SqliteCloudKvStore::FilterCloudVersionPrefixKey(std::vector<std::vector<Type>> &changeValList)
{
    changeValList.erase(std::remove_if(changeValList.begin(), changeValList.end(),
        [&](const std::vector<Type> &existPkVal) {
            bool isFilter = false;
            for (auto type : existPkVal) {
                std::string prefixKey;
                int errCode = CloudStorageUtils::GetValueFromOneField(type, prefixKey);
                if (errCode != E_OK) {
                    LOGE("[SqliteCloudKvStore] can not get key from changedData, %d", errCode);
                    break;
                }
                isFilter = !prefixKey.empty() && prefixKey.find(CloudDbConstant::CLOUD_VERSION_RECORD_PREFIX_KEY) == 0;
                if (isFilter) {
                    break;
                }
            }
            return isFilter;
        }), changeValList.end());
}

void SqliteCloudKvStore::TriggerObserverAction(const std::string &deviceName, ChangedData &&changedData,
    bool isChangedData)
{
    {
        std::lock_guard<std::mutex> autoLock(observerMapMutex_);
        if (cloudObserverMap_.empty()) {
            return;
        }
    }
    for (auto &changeValList : changedData.primaryData) {
        FilterCloudVersionPrefixKey(changeValList);
    }
    RefObject::IncObjRef(this);
    int errCode = RuntimeContext::GetInstance()->ScheduleTask([this, deviceName, changedData, isChangedData]() {
        {
            std::lock_guard<std::mutex> autoLock(observerMapMutex_);
            for (const auto &item : cloudObserverMap_) {
                ChangedData observerChangeData = changedData;
                item.second(deviceName, std::move(observerChangeData), isChangedData);
            }
        }
        RefObject::DecObjRef(this);
    });
    if (errCode != E_OK) {
        LOGW("[SqliteCloudKvStore] Trigger observer action failed %d", errCode);
        RefObject::DecObjRef(this);
    }
}

std::string SqliteCloudKvStore::GetIdentify() const
{
    return "";
}

int SqliteCloudKvStore::GetCloudGid(const TableSchema &tableSchema, const QuerySyncObject &querySyncObject,
    bool isCloudForcePush, bool isCompensatedTask, std::vector<std::string> &cloudGid)
{
    auto[errCode, handle] = storageHandle_->GetStorageExecutor(false);
    if (errCode != E_OK) {
        LOGE("[SqliteCloudKvStore] get handle failed %d", errCode);
        return errCode;
    }
    sqlite3 *db = nullptr;
    (void)handle->GetDbHandle(db);
    QuerySyncObject query = querySyncObject;
    errCode = SqliteCloudKvExecutorUtils::QueryCloudGid(db, handle->IsMemory(), user_, query, cloudGid);
    storageHandle_->RecycleStorageExecutor(handle);
    if (errCode != E_OK) {
        LOGE("[SqliteCloudKvStore] Query cloud gid failed %d", errCode);
    }
    return errCode;
}

int SqliteCloudKvStore::FillCloudAssetForDownload(const std::string &tableName, VBucket &asset, bool isDownloadSuccess)
{
    return E_OK;
}

int SqliteCloudKvStore::FillCloudAssetForAsyncDownload(const std::string &tableName, VBucket &asset,
    bool isDownloadSuccess)
{
    return E_OK;
}

int SqliteCloudKvStore::SetLogTriggerStatus(bool status)
{
    return E_OK;
}

int SqliteCloudKvStore::SetLogTriggerStatusForAsyncDownload(bool status)
{
    return E_OK;
}

int SqliteCloudKvStore::SetCursorIncFlag(bool status)
{
    return E_OK;
}

int SqliteCloudKvStore::CheckQueryValid(const QuerySyncObject &query)
{
    return E_OK;
}

std::pair<int, std::vector<std::string>> SqliteCloudKvStore::GetDownloadAssetTable()
{
    return {};
}

std::pair<int, std::vector<std::string>> SqliteCloudKvStore::GetDownloadAssetRecords(
    const std::string &tableName, int64_t beginTime)
{
    return {};
}

bool SqliteCloudKvStore::IsSharedTable(const std::string &tableName)
{
    return false;
}

void SqliteCloudKvStore::SetUser(const std::string &user)
{
    user_ = user;
}

std::pair<sqlite3 *, SQLiteSingleVerStorageExecutor *> SqliteCloudKvStore::GetTransactionDbHandleAndMemoryStatus(
    bool isWrite)
{
    std::lock_guard<std::mutex> autoLock(transactionMutex_);
    if (transactionHandle_ == nullptr) {
        if (storageHandle_ == nullptr) {
            return {nullptr, nullptr};
        }
        auto [errCode, handle] = storageHandle_->GetStorageExecutor(isWrite);
        if (errCode != E_OK) {
            LOGE("[SqliteCloudKvStore] get handle failed %d when fill log", errCode);
            return {nullptr, nullptr};
        }
        sqlite3 *db = nullptr;
        (void)handle->GetDbHandle(db);
        return {db, handle};
    }
    sqlite3 *db = nullptr;
    (void)transactionHandle_->GetDbHandle(db);
    return {db, transactionHandle_};
}

void SqliteCloudKvStore::RegisterObserverAction(const KvStoreObserver *observer, const ObserverAction &action)
{
    std::lock_guard<std::mutex> autoLock(observerMapMutex_);
    cloudObserverMap_[observer] = action;
}

void SqliteCloudKvStore::UnRegisterObserverAction(const KvStoreObserver *observer)
{
    std::lock_guard<std::mutex> autoLock(observerMapMutex_);
    cloudObserverMap_.erase(observer);
}

int SqliteCloudKvStore::GetCloudVersion(const std::string &device, std::map<std::string, std::string> &versionMap)
{
    auto [errCode, handle] = storageHandle_->GetStorageExecutor(false);
    if (errCode != E_OK) {
        LOGE("[SqliteCloudKvStore] get handle failed %d", errCode);
        return errCode;
    }
    sqlite3 *db = nullptr;
    (void)handle->GetDbHandle(db);
    std::vector<VBucket> dataVector = {};
    errCode = SqliteCloudKvExecutorUtils::GetCloudVersionFromCloud(db, handle->IsMemory(), device, dataVector);
    storageHandle_->RecycleStorageExecutor(handle);
    if (errCode != E_OK) {
        LOGE("[SqliteCloudKvStore] get cloud version record failed %d", errCode);
        return errCode;
    }
    for (VBucket &data : dataVector) {
        auto [errCodeNext, dataItem] = CloudStorageUtils::GetDataItemFromCloudVersionData(data);
        if (errCodeNext != E_OK) {
            LOGE("[SqliteCloudKvStore] get data item failed %d", errCodeNext);
            return errCodeNext;
        }
        dataItem.dev = DBBase64Utils::DecodeIfNeed(dataItem.dev);
        std::vector<uint8_t> blob = dataItem.value;
        std::string version = std::string(blob.begin(), blob.end());
        std::pair<std::string, std::string> versionPair = std::pair<std::string, std::string>(dataItem.dev, version);
        versionMap.insert(versionPair);
    }
    return E_OK;
}

std::pair<int, CloudSyncData> SqliteCloudKvStore::GetLocalCloudVersion()
{
    std::pair<int, CloudSyncData> res;
    auto &[errCode, data] = res;
    Timestamp currentTime = storageHandle_->GetCurrentTimestamp();
    TimeOffset timeOffset = storageHandle_->GetLocalTimeOffsetForCloud();
    Timestamp rawSysTime = static_cast<Timestamp>(static_cast<TimeOffset>(currentTime) - timeOffset);
    SQLiteSingleVerStorageExecutor *handle = nullptr;
    std::tie(errCode, handle) = storageHandle_->GetStorageExecutor(false);
    if (errCode != E_OK) {
        LOGE("[SqliteCloudKvStore] get handle failed %d when fill log", errCode);
        return res;
    }
    sqlite3 *db = nullptr;
    (void)handle->GetDbHandle(db);
    std::tie(errCode, data) = SqliteCloudKvExecutorUtils::GetLocalCloudVersion(db, handle->IsMemory(), user_);
    data.isCloudVersionRecord = true;
    storageHandle_->RecycleStorageExecutor(handle);
    FillTimestamp(rawSysTime, currentTime, data.insData);
    FillTimestamp(rawSysTime, currentTime, data.updData);
    data.tableName = CloudDbConstant::CLOUD_KV_TABLE_NAME;
    return res;
}

void SqliteCloudKvStore::FillTimestamp(Timestamp rawSystemTime, Timestamp virtualTime, CloudSyncBatch &syncBatch)
{
    for (auto &item : syncBatch.extend) {
        item[CloudDbConstant::MODIFY_FIELD] = static_cast<int64_t>(rawSystemTime);
        if (item.find(CloudDbConstant::CREATE_FIELD) == item.end()) {
            item[CloudDbConstant::CREATE_FIELD] = static_cast<int64_t>(rawSystemTime);
            item[CloudDbConstant::CLOUD_KV_FIELD_DEVICE_CREATE_TIME] = static_cast<int64_t>(virtualTime);
        }
    }
}

bool SqliteCloudKvStore::CheckSchema(std::map<std::string, DataBaseSchema> schema)
{
    if (schema.size() == 0) {
        LOGE("[SqliteCloudKvStore] empty schema.");
        return false;
    }
    for (auto it = schema.begin(); it != schema.end(); it++) {
        std::vector<TableSchema> tables = it->second.tables;
        if (tables.size() != 1) {
            LOGE("[SqliteCloudKvStore] invalid tables num: %zu", tables.size());
            return false;
        }
        TableSchema actualTable = tables[0];
        std::string expectTableName = CloudDbConstant::CLOUD_KV_TABLE_NAME;
        std::string expectSharedTableName = "";
        std::vector<Field> expectFields = {
            {CloudDbConstant::CLOUD_KV_FIELD_KEY, TYPE_INDEX<std::string>, true, true},
            {CloudDbConstant::CLOUD_KV_FIELD_DEVICE, TYPE_INDEX<std::string>, false, true},
            {CloudDbConstant::CLOUD_KV_FIELD_ORI_DEVICE, TYPE_INDEX<std::string>, false, true},
            {CloudDbConstant::CLOUD_KV_FIELD_VALUE, TYPE_INDEX<std::string>, false, true},
            {CloudDbConstant::CLOUD_KV_FIELD_DEVICE_CREATE_TIME, TYPE_INDEX<int64_t>, false, true}
        };
        if (actualTable.name != expectTableName || actualTable.sharedTableName != expectSharedTableName ||
            actualTable.fields.size() != expectFields.size()) {
            LOGE("[SqliteCloudKvStore] check table failed.");
            return false;
        }
        for (uint32_t i = 0; i < actualTable.fields.size(); i++) {
            Field actualField = actualTable.fields[i];
            if (std::find(expectFields.begin(), expectFields.end(), actualField) == expectFields.end()) {
                LOGE("[SqliteCloudKvStore] check fields failed.");
                return false;
            }
        }
    }
    return true;
}

void SqliteCloudKvStore::SetCloudSyncConfig(const CloudSyncConfig &config)
{
    std::lock_guard<std::mutex> autoLock(configMutex_);
    config_ = config;
    LOGI("[SqliteCloudKvStore] SetCloudSyncConfig value:[%" PRId32 ", %" PRId32 ", %" PRId32 ", %d]",
        config_.maxUploadCount, config_.maxUploadSize, config_.maxRetryConflictTimes, config_.isSupportEncrypt);
}

CloudSyncConfig SqliteCloudKvStore::GetCloudSyncConfig() const
{
    std::lock_guard<std::mutex> autoLock(configMutex_);
    return config_;
}

std::map<std::string, DataBaseSchema> SqliteCloudKvStore::GetDataBaseSchemas()
{
    std::lock_guard<std::mutex> autoLock(schemaMutex_);
    return schema_;
}

void SqliteCloudKvStore::ReleaseUploadRecord(const std::string &tableName, const CloudWaterType &type,
    Timestamp localMark)
{
    recorder_.ReleaseUploadRecord(tableName, type, localMark);
}

bool SqliteCloudKvStore::IsTagCloudUpdateLocal(const LogInfo &localInfo, const LogInfo &cloudInfo,
    SingleVerConflictResolvePolicy policy)
{
    // if local not delete and cloud is different user, insert data to local by timestamp
    if (localInfo.dataKey != -1 && (localInfo.flag & static_cast<uint64_t>(LogInfoFlag::FLAG_LOCAL)) == 0 &&
        (localInfo.cloud_flag & static_cast<uint64_t>(LogInfoFlag::FLAG_LOGIN_USER)) == 0 &&
        (localInfo.flag & static_cast<uint64_t>(LogInfoFlag::FLAG_CLOUD_WRITE)) ==
        static_cast<uint64_t>(LogInfoFlag::FLAG_CLOUD_WRITE) && localInfo.wTimestamp > cloudInfo.wTimestamp) {
        return false;
    }
    std::string cloudInfoDev;
    auto decodeCloudInfoDev = DBBase64Utils::Decode(cloudInfo.device);
    if (!decodeCloudInfoDev.empty()) {
        cloudInfoDev = std::string(decodeCloudInfoDev.begin(), decodeCloudInfoDev.end());
    }
    if (policy == SingleVerConflictResolvePolicy::DENY_OTHER_DEV_AMEND_CUR_DEV_DATA &&
        !localInfo.originDev.empty() && localInfo.originDev == cloudInfoDev) {
        return true;
    }
    std::string device;
    if (RuntimeContext::GetInstance()->GetLocalIdentity(device) != E_OK) {
        LOGE("[SqliteCloudKvStore] GetLocalIdentity device failed.");
        return false;
    }
    device = DBCommon::TransferHashString(device);
    std::string localInfoDev = localInfo.device;
    if (localInfoDev.empty()) {
        return false;
    }
    bool isLocal = (localInfo.flag & static_cast<uint32_t>(LogInfoFlag::FLAG_LOCAL)) ==
        static_cast<uint32_t>(LogInfoFlag::FLAG_LOCAL);
    if (cloudInfoDev.empty()) {
        return !isLocal;
    }
    return localInfoDev == cloudInfoDev && localInfoDev != device;
}

int SqliteCloudKvStore::GetCompensatedSyncQuery(std::vector<QuerySyncObject> &syncQuery,
    std::vector<std::string> &users, bool isQueryDownloadRecords)
{
    std::shared_ptr<DataBaseSchema> cloudSchema;
    (void)GetCloudDbSchema(cloudSchema);
    if (cloudSchema == nullptr) {
        return -E_INVALID_SCHEMA;
    }
    if (cloudSchema->tables.empty()) {
        return E_OK;
    }
    int ret = StartTransaction(TransactType::DEFERRED);
    if (ret != E_OK) {
        return ret;
    }
    sqlite3 *db = nullptr;
    (void)transactionHandle_->GetDbHandle(db);
    for (const auto &table: cloudSchema->tables) {
        std::vector<VBucket> syncDataPk;
        std::vector<VBucket> syncDataUserId;
        int errCode = SqliteCloudKvExecutorUtils::GetWaitCompensatedSyncData(db, transactionHandle_->IsMemory(),
            syncDataPk, syncDataUserId);
        if (errCode != E_OK) {
            LOGW("[SqliteCloudKvStore] Get wait compensated sync date failed, continue! errCode=%d", errCode);
            continue;
        }
        if (syncDataPk.empty()) {
            continue;
        }
        errCode = CloudStorageUtils::GetSyncQueryByPk(table.name, syncDataPk, true, syncQuery);
        if (errCode != E_OK) {
            LOGW("[SqliteCloudKvStore] Get compensated sync query happen error, ignore it! errCode = %d", errCode);
            continue;
        }
        for (auto &oneRow : syncDataUserId) {
            std::string user;
            errCode = CloudStorageUtils::GetStringFromCloudData(CloudDbConstant::CLOUD_KV_FIELD_USERID, oneRow, user);
            if (errCode != E_OK) {
                LOGW("[SqliteCloudKvStore] Get compensated sync query happen error, ignore it! errCode = %d", errCode);
                continue;
            }
            users.push_back(user);
        }
    }
    return Commit();
}

int SqliteCloudKvStore::ReviseOneLocalModTime(sqlite3_stmt *stmt, const ReviseModTimeInfo &data, bool isMemory)
{
    int errCode = SQLiteUtils::BindInt64ToStatement(stmt, 1, data.curTime); // 1st bind modify time
    if (errCode != E_OK) {
        LOGE("[SqliteCloudKvStore][ReviseOneLocalModTime] Bind revise modify time failed: %d", errCode);
        return errCode;
    }
    errCode = SQLiteUtils::BindBlobToStatement(stmt, 2, data.hashKey); // 2nd bind hash key
    if (errCode != E_OK) {
        LOGE("[SqliteCloudKvStore][ReviseOneLocalModTime] Bind hash key failed: %d", errCode);
        return errCode;
    }
    errCode = SQLiteUtils::BindInt64ToStatement(stmt, 3, data.invalidTime); // 3rd bind modify time
    if (errCode != E_OK) {
        LOGE("[SqliteCloudKvStore][ReviseOneLocalModTime] Bind modify time failed: %d", errCode);
        return errCode;
    }
    errCode = SQLiteUtils::StepWithRetry(stmt, isMemory);
    if (errCode != SQLiteUtils::MapSQLiteErrno(SQLITE_DONE)) {
        LOGE("[SqliteCloudKvStore][ReviseOneLocalModTime] Revise failed: %d", errCode);
        return errCode;
    }
    return E_OK;
}

int SqliteCloudKvStore::ReviseLocalModTime(const std::string &tableName,
    const std::vector<ReviseModTimeInfo> &revisedData)
{
    auto [errCode, handle] = storageHandle_->GetStorageExecutor(true);
    if (errCode != E_OK) {
        LOGE("[SqliteCloudKvStore][ReviseLocalModTime] Get handle failed: %d", errCode);
        return errCode;
    }
    sqlite3 *db = nullptr;
    (void)handle->GetDbHandle(db);
    sqlite3_stmt *stmt = nullptr;
    std::string sql = "UPDATE " + tableName + " SET modify_time=? WHERE hash_key=? AND modify_time=?";
    errCode = SQLiteUtils::GetStatement(db, sql, stmt);
    if (errCode != E_OK) {
        LOGE("[SqliteCloudKvStore][ReviseLocalModTime] Get stmt failed: %d", errCode);
        storageHandle_->RecycleStorageExecutor(handle);
        return errCode;
    }
    ResFinalizer finalizer([stmt]() {
        sqlite3_stmt *statement = stmt;
        int ret = E_OK;
        SQLiteUtils::ResetStatement(statement, true, ret);
        if (ret != E_OK) {
            LOGW("[SqliteCloudKvStore][ReviseLocalModTime] Reset stmt failed %d", ret);
        }
    });
    for (auto &data : revisedData) {
        errCode = ReviseOneLocalModTime(stmt, data, handle->IsMemory());
        if (errCode != E_OK) {
            LOGE("[SqliteCloudKvStore][ReviseLocalModTime] Revise one record failed %d", errCode);
            break;
        }
        LOGI("[SqliteCloudKvStore][ReviseLocalModTime] Local data mod time revised from %lld to %lld",
            data.invalidTime, data.curTime);
        int resetCode = E_OK;
        SQLiteUtils::ResetStatement(stmt, false, resetCode);
        if (resetCode != E_OK) {
            LOGE("[SqliteCloudKvStore][ReviseLocalModTime] Reset stmt failed: %d", resetCode);
            break;
        }
    }
    storageHandle_->RecycleStorageExecutor(handle);
    return errCode;
}

int SqliteCloudKvStore::GetLocalDataCount(const std::string &tableName, int &dataCount, int &logicDeleteDataCount)
{
    auto [errCode, handle] = storageHandle_->GetStorageExecutor(true);
    if (errCode != E_OK) {
        LOGE("[SqliteCloudKvStore][GetLocalDataCount] Get handle failed: %d", errCode);
        return errCode;
    }
    sqlite3 *db = nullptr;
    (void)handle->GetDbHandle(db);

    std::string dataCountSql = "select count(*) from " + tableName;
    errCode = SQLiteUtils::GetCountBySql(db, dataCountSql, dataCount);
    if (errCode != E_OK) {
        LOGE("[SqliteCloudKvStore][GetLocalDataCount] Query local data count failed: %d", errCode);
        storageHandle_->RecycleStorageExecutor(handle);
        return errCode;
    }

    std::string logicDeleteDataCountSql = "select count(*) from " + tableName + " where flag&0x01 != 0";
    errCode = SQLiteUtils::GetCountBySql(db, logicDeleteDataCountSql, logicDeleteDataCount);
    if (errCode != E_OK) {
        LOGE("[SqliteCloudKvStore][GetLocalDataCount] Query local logic delete data count failed: %d", errCode);
    }
    storageHandle_->RecycleStorageExecutor(handle);
    return errCode;
}

int SqliteCloudKvStore::OperateDataStatus(uint32_t dataOperator)
{
    LOGI("[SqliteCloudKvStore] OperateDataStatus %" PRIu32, dataOperator);
    if ((dataOperator & static_cast<uint32_t>(DataOperator::UPDATE_TIME)) == 0 &&
        (dataOperator & static_cast<uint32_t>(DataOperator::RESET_UPLOAD_CLOUD)) == 0) {
        return E_OK;
    }

    Timestamp currentRawTime = storageHandle_->GetCurrentTimestamp();
    TimeOffset timeOffset = storageHandle_->GetLocalTimeOffsetForCloud();
    Timestamp currentSysTime = static_cast<Timestamp>(static_cast<TimeOffset>(currentRawTime) - timeOffset);
    auto currentVirtualTime = std::to_string(currentRawTime);
    auto currentTime = std::to_string(currentSysTime);

    auto [errCode, handle] = storageHandle_->GetStorageExecutor(true);
    if (errCode != E_OK) {
        LOGE("[SqliteCloudKvStore][OperateDataStatus] Get handle failed: %d", errCode);
        return errCode;
    }
    errCode = handle->StartTransaction(TransactType::IMMEDIATE);
    if (errCode != E_OK) {
        LOGE("[SqliteCloudKvStore][OperateDataStatus] Start transaction failed %d when operate data status", errCode);
        storageHandle_->RecycleStorageExecutor(handle);
        return errCode;
    }
    errCode = OperateDataStatusInner(handle, currentVirtualTime, currentTime, dataOperator);
    if (errCode == E_OK) {
        errCode = handle->Commit();
        if (errCode != E_OK) {
            LOGE("[SqliteCloudKvStore][OperateDataStatus] Commit failed %d when operate data status", errCode);
        }
    } else {
        int ret = handle->Rollback();
        if (ret != E_OK) {
            LOGE("[SqliteCloudKvStore][OperateDataStatus] Rollback failed %d when operate data status", ret);
        }
    }
    storageHandle_->RecycleStorageExecutor(handle);
    return errCode;
}

int SqliteCloudKvStore::OperateDataStatusInner(SQLiteSingleVerStorageExecutor *handle,
    const std::string &currentVirtualTime, const std::string &currentTime, uint32_t dataOperator)
{
    sqlite3 *db = nullptr;
    int errCode = handle->GetDbHandle(db);
    if (errCode != E_OK) {
        LOGE("[SqliteCloudKvStore][OperateDataStatus] Get db failed %d when operate data status", errCode);
        return errCode;
    }
    if ((dataOperator & static_cast<uint32_t>(DataOperator::UPDATE_TIME)) != 0) {
        errCode = SQLiteUtils::UpdateLocalDataModifyTime(db, currentVirtualTime, currentTime);
        if (errCode != E_OK) {
            LOGE("[SqliteCloudKvStore][OperateDataStatus] Update local data modify time failed: %d", errCode);
            return errCode;
        }
    }
    if ((dataOperator & static_cast<uint32_t>(DataOperator::RESET_UPLOAD_CLOUD)) != 0) {
        errCode = SQLiteUtils::UpdateLocalDataCloudFlag(db);
        if (errCode != E_OK) {
            LOGE("[SqliteCloudKvStore][OperateDataStatus] Update local data cloud flag failed: %d", errCode);
        }
    }
    return errCode;
}
}
