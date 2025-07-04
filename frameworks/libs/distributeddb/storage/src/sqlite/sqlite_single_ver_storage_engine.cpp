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

#include "sqlite_single_ver_storage_engine.h"

#include <memory>

#include "db_common.h"
#include "db_constant.h"
#include "db_errno.h"
#include "kvdb_manager.h"
#include "log_print.h"
#include "param_check_utils.h"
#include "platform_specific.h"
#include "runtime_context.h"
#include "single_ver_utils.h"
#include "sqlite_log_table_manager.h"
#include "sqlite_single_ver_database_upgrader.h"
#include "sqlite_single_ver_natural_store.h"
#include "sqlite_single_ver_schema_database_upgrader.h"

namespace DistributedDB {
SQLiteSingleVerStorageEngine::SQLiteSingleVerStorageEngine()
    : executorState_(ExecutorState::INVALID),
      cacheRecordVersion_(CACHE_RECORD_DEFAULT_VERSION),
      isCorrupted_(false),
      isNeedUpdateSecOpt_(false),
      maxValueSize_(DBConstant::MAX_VALUE_SIZE)
{}

SQLiteSingleVerStorageEngine::~SQLiteSingleVerStorageEngine()
{
}

int SQLiteSingleVerStorageEngine::MigrateLocalData(SQLiteSingleVerStorageExecutor *handle) const
{
    return handle->MigrateLocalData();
}

int SQLiteSingleVerStorageEngine::EraseDeviceWaterMark(const std::set<std::string> &removeDevices, bool isNeedHash)
{
    auto kvdbManager = KvDBManager::GetInstance();
    if (kvdbManager == nullptr) { // LCOV_EXCL_BR_LINE
        return -E_INVALID_DB;
    }
    auto identifier = GetIdentifier();
    auto kvdb = kvdbManager->FindKvDB(identifier);
    if (kvdb == nullptr) { // LCOV_EXCL_BR_LINE
        LOGE("[SingleVerEngine::EraseWaterMark] kvdb is null.");
        return -E_INVALID_DB;
    }

    auto kvStore = static_cast<SQLiteSingleVerNaturalStore *>(kvdb);
    for (const auto &devId : removeDevices) {
        int errCode = kvStore->EraseDeviceWaterMark(devId, isNeedHash);
        if (errCode != E_OK) { // LCOV_EXCL_BR_LINE
            RefObject::DecObjRef(kvdb);
            return errCode;
        }
    }

    RefObject::DecObjRef(kvdb);
    return E_OK;
}

int SQLiteSingleVerStorageEngine::GetRemoveDataDevices(SQLiteSingleVerStorageExecutor *handle, const DataItem &item,
    std::set<std::string> &removeDevices, bool &isNeedHash) const
{
    if (handle == nullptr) { // LCOV_EXCL_BR_LINE
        return -E_INVALID_DB;
    }
    if (item.value.empty()) { // Device ID has been set to value in cache db
        // Empty means remove all device data, get device id from meta key
        // LCOV_EXCL_BR_LINE
        int errCode = handle->GetExistsDevicesFromMeta(removeDevices);
        if (errCode != E_OK) { // LCOV_EXCL_BR_LINE
            LOGE("Get remove devices list from meta failed. err=%d", errCode);
            return errCode;
        }
        isNeedHash = false;
    } else {
        std::string deviceName;
        DBCommon::VectorToString(item.value, deviceName);
        removeDevices.insert(deviceName);
    }
    return E_OK;
}

int SQLiteSingleVerStorageEngine::EraseDeviceWaterMark(SQLiteSingleVerStorageExecutor *&handle,
    const std::vector<DataItem> &dataItems)
{
    int errCode = E_OK;
    for (const auto &dataItem : dataItems) {
        if ((dataItem.flag & DataItem::REMOVE_DEVICE_DATA_FLAG) == DataItem::REMOVE_DEVICE_DATA_FLAG ||
            (dataItem.flag & DataItem::REMOVE_DEVICE_DATA_NOTIFY_FLAG) == DataItem::REMOVE_DEVICE_DATA_NOTIFY_FLAG) {
            bool isNeedHash = true;
            std::set<std::string> removeDevices;
            errCode = GetRemoveDataDevices(handle, dataItem, removeDevices, isNeedHash);
            if (errCode != E_OK) { // LCOV_EXCL_BR_LINE
                LOGE("Get remove device id failed. err=%d", errCode);
                return errCode;
            }

            // sync module will use handle to fix watermark, if fix fail then migrate fail, not need hold write handle
            errCode = ReleaseExecutor(handle);
            if (errCode != E_OK) { // LCOV_EXCL_BR_LINE
                LOGE("release executor for erase water mark! errCode = [%d]", errCode);
                return errCode;
            }

            errCode = EraseDeviceWaterMark(removeDevices, isNeedHash);
            if (errCode != E_OK) { // LCOV_EXCL_BR_LINE
                LOGE("EraseDeviceWaterMark failed when migrating, errCode = [%d]", errCode);
                return errCode;
            }

            handle = static_cast<SQLiteSingleVerStorageExecutor *>(FindExecutor(true, OperatePerm::NORMAL_PERM,
                errCode));
            if (errCode != E_OK) { // LCOV_EXCL_BR_LINE
                LOGE("Migrate sync data fail, Can not get available executor, errCode = [%d]", errCode);
                return errCode;
            }
        }
    }
    return errCode;
}

int SQLiteSingleVerStorageEngine::MigrateSyncDataByVersion(SQLiteSingleVerStorageExecutor *&handle,
    NotifyMigrateSyncData &syncData, uint64_t &curMigrateVer)
{
    if (syncData.committedData == nullptr) {
        syncData.committedData = new (std::nothrow) SingleVerNaturalStoreCommitNotifyData();
        if (syncData.committedData == nullptr) {
            LOGE("[SQLiteSingleVerStorageEngine::MigrateSyncData] committedData is null.");
            return -E_OUT_OF_MEMORY;
        }
    }
    InitConflictNotifiedFlag(syncData.committedData);

    std::vector<DataItem> dataItems;
    uint64_t minVerIncurCacheDb = 0;
    if (handle == nullptr) {
        LOGE("[MigrateSyncDataByVersion] handle is nullptr.");
        return -E_INVALID_DB;
    }
    int errCode = handle->GetMinVersionCacheData(dataItems, minVerIncurCacheDb);
    if (errCode != E_OK) {
        LOGE("[MigrateSyncDataByVersion]Fail to get cur data in cache! err[%d]", errCode);
        return errCode;
    }

    if (minVerIncurCacheDb == 0) { // min version in cache db is 1
        ++curMigrateVer;
        return E_OK;
    }

    if (minVerIncurCacheDb != curMigrateVer) { // double check for latest version is migrated
        curMigrateVer = minVerIncurCacheDb;
    }

    // Call the syncer module to erase the water mark.
    errCode = EraseDeviceWaterMark(handle, dataItems);
    if (errCode != E_OK) {
        LOGE("[MigrateSyncData] Erase water mark failed:%d", errCode);
        return errCode;
    }

    // next version need process
    LOGD("MigrateVer[%" PRIu64 "], minVer[%" PRIu64 "] maxVer[%" PRIu64 "]",
        curMigrateVer, minVerIncurCacheDb, GetCacheRecordVersion());
    errCode = handle->MigrateSyncDataByVersion(curMigrateVer++, syncData, dataItems);
    if (errCode != E_OK) {
        LOGE("Migrate sync data fail and rollback, errCode = [%d]", errCode);
        return errCode;
    }

    errCode = ReleaseHandleTransiently(handle, 2ULL, syncData); // temporary release handle 2ms
    if (errCode != E_OK) {
        return errCode;
    }

    return E_OK;
}

// Temporary release handle for idleTime ms, avoid long-term blocking
int SQLiteSingleVerStorageEngine::ReleaseHandleTransiently(SQLiteSingleVerStorageExecutor *&handle, uint64_t idleTime,
    NotifyMigrateSyncData &syncData)
{
    int errCode = ReleaseExecutor(handle);
    if (errCode != E_OK) {
        LOGE("release executor for reopen database! errCode = [%d]", errCode);
        return errCode;
    }

    CommitNotifyForMigrateCache(syncData); // Trigger sync after release handle

    std::this_thread::sleep_for(std::chrono::milliseconds(idleTime)); // Wait 2 ms to free this handle for put data
    handle = static_cast<SQLiteSingleVerStorageExecutor *>(FindExecutor(true, OperatePerm::NORMAL_PERM, errCode));
    if (errCode != E_OK) {
        LOGE("Migrate sync data fail, Can not get available executor, errCode = [%d]", errCode);
        return errCode;
    }
    return errCode;
}

int SQLiteSingleVerStorageEngine::AddSubscribeToMainDBInMigrate()
{
    LOGD("Add subscribe to mainDB from cache. %d", GetEngineState());
    std::lock_guard<std::mutex> lock(subscribeMutex_);
    if (subscribeQuery_.empty()) { // LCOV_EXCL_BR_LINE
        return E_OK;
    }
    int errCode = E_OK;
    auto handle = static_cast<SQLiteSingleVerStorageExecutor *>(FindExecutor(true, OperatePerm::NORMAL_PERM, errCode));
    if (errCode != E_OK || handle == nullptr) { // LCOV_EXCL_BR_LINE
        LOGE("Get available executor for add subscribe failed. %d", errCode);
        return errCode;
    }
    errCode = handle->StartTransaction(TransactType::IMMEDIATE);
    if (errCode != E_OK) { // LCOV_EXCL_BR_LINE
        goto END;
    }
    for (auto item : subscribeQuery_) {
        errCode = handle->AddSubscribeTrigger(item.second, item.first);
        if (errCode != E_OK) {
            LOGE("Add subscribe trigger failed: %d id: %s", errCode, item.first.c_str());
        }
    }
    subscribeQuery_.clear();
    // Not rollback even if some triggers add failed. Users don’t perceive errors, add triggers as much as possible
    (void)handle->Commit();
END:
    ReleaseExecutor(handle);
    return errCode;
}

int SQLiteSingleVerStorageEngine::MigrateSyncData(SQLiteSingleVerStorageExecutor *&handle, bool &isNeedTriggerSync)
{
    int errCode = E_OK;
    if (handle == nullptr) {
        handle = static_cast<SQLiteSingleVerStorageExecutor *>(FindExecutor(true, OperatePerm::NORMAL_PERM, errCode));
        if (errCode != E_OK) {
            LOGE("Migrate sync data fail, Can not get available executor, errCode = [%d]", errCode);
            return errCode;
        }
    }

    LOGD("Begin migrate sync data, need migrate version[%" PRIu64 "]", GetCacheRecordVersion());
    uint64_t curMigrateVer = 0; // The migration process is asynchronous and continuous
    NotifyMigrateSyncData syncData;
    auto kvdbManager = KvDBManager::GetInstance();
    if (kvdbManager != nullptr) {
        auto identifier = GetIdentifier();
        auto kvdb = kvdbManager->FindKvDB(identifier);
        if (kvdb != nullptr) {
            auto kvStore = static_cast<SQLiteSingleVerNaturalStore *>(kvdb);
            syncData.isPermitForceWrite =
                !(kvStore->GetDbProperties().GetBoolProp(KvDBProperties::SYNC_DUAL_TUPLE_MODE, false));
            RefObject::DecObjRef(kvdb);
        } else {
            LOGE("[SingleVerEngine] kvdb is null.");
        }
    }
    // cache atomic version represents version of cacheDb input next time
    while (curMigrateVer < GetCacheRecordVersion()) {
        errCode = MigrateSyncDataByVersion(handle, syncData, curMigrateVer);
        if (errCode != E_OK) {
            LOGE("Migrate version[%" PRIu64 "] failed! errCode = [%d]", curMigrateVer, errCode);
            break;
        }
        if (!syncData.isRemote) {
            isNeedTriggerSync = true;
        }
    }
    if (syncData.committedData != nullptr) {
        RefObject::DecObjRef(syncData.committedData);
        syncData.committedData = nullptr;
    }
    // When finished Migrating sync data, will fix engine state
    return errCode;
}

int SQLiteSingleVerStorageEngine::AttachMainDbAndCacheDb(SQLiteSingleVerStorageExecutor *handle,
    EngineState stateBeforeMigrate)
{
    LOGD("Begin attach main db and cache db by executor!");
    // Judge the file corresponding to db by the engine status and attach it to another file
    int errCode = E_OK;
    std::string attachAbsPath;
    if (handle == nullptr) {
        LOGE("[AttachMainDbAndCacheDb] handle is nullptr.");
        return -E_INVALID_DB;
    }
    if (stateBeforeMigrate == EngineState::MAINDB) {
        attachAbsPath = GetDbDir(option_.subdir, DbType::CACHE) + "/" + DBConstant::SINGLE_VER_CACHE_STORE +
            DBConstant::DB_EXTENSION;
        errCode = handle->AttachMainDbAndCacheDb(option_.cipherType, option_.passwd, attachAbsPath, stateBeforeMigrate);
    } else if (stateBeforeMigrate == EngineState::CACHEDB) {
        attachAbsPath = GetDbDir(option_.subdir, DbType::MAIN) + "/" + DBConstant::SINGLE_VER_DATA_STORE +
        DBConstant::DB_EXTENSION;
        errCode = handle->AttachMainDbAndCacheDb(option_.cipherType, option_.passwd, attachAbsPath, stateBeforeMigrate);
    } else {
        return -E_NOT_SUPPORT;
    }
    if (errCode != E_OK) {
        LOGE("Attached database failed, errCode = [%d] engine state = [%d]", errCode, stateBeforeMigrate);
        return errCode;
    }

    uint64_t maxVersion = 0;
    errCode = handle->GetMaxVersionInCacheDb(maxVersion);
    if (errCode != E_OK || maxVersion < CACHE_RECORD_DEFAULT_VERSION) {
        maxVersion = CACHE_RECORD_DEFAULT_VERSION;
    }

    (void)cacheRecordVersion_.store(maxVersion + 1, std::memory_order_seq_cst);
    return errCode;
}

int SQLiteSingleVerStorageEngine::AttachMainDbAndCacheDb(sqlite3 *dbHandle, EngineState stateBeforeMigrate) const
{
    LOGD("Begin attach main db and cache db by sqlite handle!");
    // Judge the file corresponding to db by the engine status and attach it to another file
    int errCode = E_OK;
    std::string attachAbsPath;
    if (stateBeforeMigrate == EngineState::MAINDB) { // LCOV_EXCL_BR_LINE
        attachAbsPath = GetDbDir(option_.subdir, DbType::CACHE) + "/" + DBConstant::SINGLE_VER_CACHE_STORE +
            DBConstant::DB_EXTENSION;
        errCode = SQLiteUtils::AttachNewDatabase(dbHandle, option_.cipherType, option_.passwd, attachAbsPath, "cache");
    } else if (stateBeforeMigrate == EngineState::CACHEDB) {
        attachAbsPath = GetDbDir(option_.subdir, DbType::MAIN) + "/" + DBConstant::SINGLE_VER_DATA_STORE +
            DBConstant::DB_EXTENSION;
        errCode = SQLiteUtils::AttachNewDatabase(dbHandle, option_.cipherType, option_.passwd, attachAbsPath, "maindb");
    } else {
        return -E_NOT_SUPPORT;
    }
    if (errCode != E_OK) { // LCOV_EXCL_BR_LINE
        LOGE("Attached database failed, errCode = [%d] engine state = [%d]", errCode, stateBeforeMigrate);
        return errCode;
    }

    return errCode;
}

int SQLiteSingleVerStorageEngine::ReInit()
{
    return Init();
}

int SQLiteSingleVerStorageEngine::ReleaseExecutor(SQLiteSingleVerStorageExecutor *&handle)
{
    if (handle == nullptr) {
        return E_OK;
    }
    StorageExecutor *databaseHandle = handle;
    isCorrupted_ = isCorrupted_ || handle->GetCorruptedStatus();
    Recycle(databaseHandle);
    handle = nullptr;
    if (isCorrupted_) {
        LOGE("Database is corrupted or invalid passwd!");
        return -E_INVALID_PASSWD_OR_CORRUPTED_DB; // Externally imperceptible, used to terminate migration
    }
    return E_OK;
}

int SQLiteSingleVerStorageEngine::FinishMigrateData(SQLiteSingleVerStorageExecutor *&handle,
    EngineState stateBeforeMigrate)
{
    LOGI("Begin to finish migrate and reinit db state!");
    int errCode;
    if (handle == nullptr) { // LCOV_EXCL_BR_LINE
        return -E_INVALID_ARGS;
    }

    if (stateBeforeMigrate == EngineState::MAINDB) { // LCOV_EXCL_BR_LINE
        sqlite3 *dbHandle = nullptr;
        errCode = handle->GetDbHandle(dbHandle); // use executor get sqlite3 handle to operating database
        if (errCode != E_OK) {
            LOGE("Get Db handle failed! errCode = [%d]", errCode);
            return errCode;
        }

        errCode = SQLiteUtils::ExecuteRawSQL(dbHandle, "DETACH 'cache'");
        if (errCode != E_OK) { // LCOV_EXCL_BR_LINE
            LOGE("Execute the SQLite detach failed:%d", errCode);
            return errCode;
        }
        // delete cachedb
        errCode = DBCommon::RemoveAllFilesOfDirectory(GetDbDir(option_.subdir, DbType::CACHE), false);
        if (errCode != E_OK) { // LCOV_EXCL_BR_LINE
            LOGE("Remove files of cache database after detach:%d", errCode);
        }

        SetEngineState(EngineState::MAINDB);
        return errCode;
    }

    errCode = ReleaseExecutor(handle);
    if (errCode != E_OK) { // LCOV_EXCL_BR_LINE
        LOGE("Release executor for reopen database! errCode = [%d]", errCode);
        return errCode;
    }

    // close db for reinit this engine
    Release();

    // delete cache db
    errCode = DBCommon::RemoveAllFilesOfDirectory(GetDbDir(option_.subdir, DbType::CACHE), false);
    if (errCode != E_OK) { // LCOV_EXCL_BR_LINE
        LOGE("Remove files of cache database after release current db:%d", errCode);
        return errCode;
    }

    // reInit, it will reset engine state
    errCode = ReInit();
    if (errCode != E_OK) { // LCOV_EXCL_BR_LINE
        LOGE("Reinit failed when finish migrate data! please try reopen kvstore! errCode = [%d]", errCode);
        return errCode;
    }

    return E_OK;
}

int SQLiteSingleVerStorageEngine::InitExecuteMigrate(SQLiteSingleVerStorageExecutor *handle,
    EngineState preMigrateState)
{
    // after attach main and cache need change operate data sql, changing state forbid operate database
    SetEngineState(EngineState::MIGRATING);

    int errCode = E_OK;
    // check if has been attach and attach cache and main for migrate
    if (executorState_ == ExecutorState::MAINDB || executorState_ == ExecutorState::CACHEDB) {
        errCode = AttachMainDbAndCacheDb(handle, preMigrateState);
        if (errCode != E_OK) {
            LOGE("[ExeMigrate] Attach main db and cache db failed!, errCode = [%d]", errCode);
            // For lock state open db, can not attach main and cache
            return errCode;
        }
    } else if (executorState_ == ExecutorState::MAIN_ATTACH_CACHE ||
        // Has been attach, maybe ever crashed, need update version
        executorState_ == ExecutorState::CACHE_ATTACH_MAIN) {
        uint64_t maxVersion = 0;
        errCode = handle->GetMaxVersionInCacheDb(maxVersion);
        if (errCode != E_OK || maxVersion < CACHE_RECORD_DEFAULT_VERSION) {
            maxVersion = CACHE_RECORD_DEFAULT_VERSION;
        }
        (void)cacheRecordVersion_.store(maxVersion + 1, std::memory_order_seq_cst);
    } else {
        return -E_UNEXPECTED_DATA;
    }

    return errCode;
}

int SQLiteSingleVerStorageEngine::ExecuteMigrate()
{
    EngineState preState = GetEngineState();
    std::lock_guard<std::mutex> lock(migrateLock_);
    if (preState == EngineState::MIGRATING || preState == EngineState::INVALID ||
        !OS::CheckPathExistence(GetDbDir(option_.subdir, DbType::CACHE) + "/" + DBConstant::SINGLE_VER_CACHE_STORE +
        DBConstant::DB_EXTENSION)) {
        LOGD("[SqlSingleVerEngine] Being single ver migrating or never create db! engine state [%u]", preState);
        return E_OK;
    }

    // Get write executor for migrate
    int errCode = E_OK;
    auto handle = static_cast<SQLiteSingleVerStorageExecutor *>(FindExecutor(true, OperatePerm::NORMAL_PERM, errCode));
    if (errCode != E_OK) {
        LOGE("Migrate data fail, Can not get available executor, errCode = [%d]", errCode);
        return errCode;
    }

    isMigrating_.store(true);
    LOGD("Migrate start.");
    bool isNeedTriggerSync = false;
    errCode = InitExecuteMigrate(handle, preState);
    if (errCode != E_OK) {
        LOGE("Init migrate data fail, errCode = [%d]", errCode);
        goto END;
    }

    LOGD("[SqlSingleVerEngine] Current engineState [%u] executorState [%u], begin to executing singleVer db migrate!",
        static_cast<unsigned>(preState), static_cast<unsigned>(executorState_));
    // has been attached, Mark start of migration and it can migrate data
    errCode = MigrateLocalData(handle);
    if (errCode != E_OK) {
        LOGE("Migrate local data fail, errCode = [%d]", errCode);
        goto END;
    }

    errCode = MigrateSyncData(handle, isNeedTriggerSync);
    if (errCode != E_OK) {
        LOGE("Migrate Sync data fail, errCode = [%d]", errCode);
        goto END;
    }

    SetEngineState(EngineState::ENGINE_BUSY); // temp forbid use handle and engine for detach and close executor

    // detach database and delete cachedb
    errCode = FinishMigrateData(handle, preState);
    if (errCode != E_OK) {
        LOGE("Finish migrating data fail, errCode = [%d]", errCode);
        goto END;
    }

END: // after FinishMigrateData, it will reset engine state
    // there is no need cover the errCode
    EndMigrate(handle, preState, errCode, isNeedTriggerSync);
    isMigrating_.store(false);
    LOGD("Migrate stop.");
    return errCode;
}

void SQLiteSingleVerStorageEngine::EndMigrate(SQLiteSingleVerStorageExecutor *&handle, EngineState stateBeforeMigrate,
    int errCode, bool isNeedTriggerSync)
{
    LOGD("Finish migrating data! errCode = [%d]", errCode);
    if (errCode != E_OK) {
        SetEngineState(stateBeforeMigrate);
    }
    if (handle != nullptr) {
        handle->ClearMigrateData();
    }
    errCode = ReleaseExecutor(handle);
    if (errCode != E_OK) {
        LOGE("release executor after migrating! errCode = [%d]", errCode);
    }

    errCode = AddSubscribeToMainDBInMigrate();
    if (errCode != E_OK) {
        LOGE("Add subscribe trigger after migrate sync data failed: %d", errCode);
    }

    // Notify max timestamp offset for SyncEngine.
    // When time change offset equals 0, SyncEngine can adjust local time offset according to max timestamp.
    RuntimeContext::GetInstance()->NotifyTimestampChanged(0);
    if (isNeedTriggerSync) {
        commitNotifyFunc_(static_cast<int>(SQLiteGeneralNSNotificationEventType::SQLITE_GENERAL_FINISH_MIGRATE_EVENT),
            nullptr);
    }
    return;
}

bool SQLiteSingleVerStorageEngine::IsEngineCorrupted() const
{
    return isCorrupted_;
}

StorageExecutor *SQLiteSingleVerStorageEngine::NewSQLiteStorageExecutor(sqlite3 *dbHandle, bool isWrite, bool isMemDb)
{
    auto executor = new (std::nothrow) SQLiteSingleVerStorageExecutor(dbHandle, isWrite, isMemDb, executorState_);
    if (executor == nullptr) {
        return executor;
    }
    executor->SetConflictResolvePolicy(option_.conflictReslovePolicy);
    return executor;
}

int SQLiteSingleVerStorageEngine::TryToOpenMainDatabase(bool isWrite, sqlite3 *&db, OpenDbProperties &option)
{
    // Only could get the main database handle in the uninitialized and the main status.
    if (GetEngineState() != EngineState::INVALID && GetEngineState() != EngineState::MAINDB) {
        LOGE("[SQLiteSinStoreEng][GetMainHandle] Can only create new handle for state[%d]", GetEngineState());
        return -E_EKEYREVOKED;
    }

    if (!option.isMemDb) {
        option.uri = GetDbDir(option_.subdir, DbType::MAIN) + "/" + DBConstant::SINGLE_VER_DATA_STORE +
            DBConstant::DB_EXTENSION;
        SetUri(option.uri);
    }

    if (!isWrite) {
        option.createIfNecessary = false;
        SetCreateIfNecessary(option.createIfNecessary);
    }

    int errCode = SQLiteUtils::OpenDatabase(option, db);
    if (errCode != E_OK) {
        if (errno == EKEYREVOKED) {
            LOGI("Failed to open the main database for key revoked[%d]", errCode);
            errCode = -E_EKEYREVOKED;
        }
        return errCode;
    }

    executorState_ = ExecutorState::MAINDB;
    // Set the engine state to main status for that the main database is valid.
    SetEngineState(EngineState::MAINDB);

    if (OS::CheckPathExistence(GetDbDir(option.subdir, DbType::CACHE) + "/" + DBConstant::SINGLE_VER_CACHE_STORE +
        DBConstant::DB_EXTENSION)) {
        // In status cacheDb crash
        errCode = AttachMainDbAndCacheDb(db, EngineState::MAINDB);
        if (errCode != E_OK) {
            LOGE("[SingleVerEngine][GetMain] Attach main db and cache db failed!, errCode = [%d]", errCode);
            return E_OK; // not care err to return, only use for print log
        }
        executorState_ = ExecutorState::MAIN_ATTACH_CACHE;
        // cache and main existed together, can not read data, must execute migrate first
        SetEngineState(EngineState::ATTACHING);
    }

    return errCode;
}

int SQLiteSingleVerStorageEngine::GetDbHandle(bool isWrite, sqlite3 *&dbHandle, OpenDbProperties &option)
{
    int errCode = TryToOpenMainDatabase(isWrite, dbHandle, option);
    const auto &secOpt = option.securityOpt;
    LOGD("Finish to open the main database, write[%d], label[%d], flag[%d], id[%.6s], errCode[%d]", isWrite,
        secOpt.securityLabel, secOpt.securityFlag, hashIdentifier_.c_str(), errCode);
    if (!(ParamCheckUtils::IsS3SECEOpt(secOpt) && errCode == -E_EKEYREVOKED)) {
        return errCode;
    }
    std::string cacheDbPath = GetDbDir(option.subdir, DbType::CACHE) + "/" + DBConstant::SINGLE_VER_CACHE_STORE +
        DBConstant::DB_EXTENSION;
    if (!isWrite || GetEngineState() != EngineState::INVALID ||
        OS::CheckPathExistence(cacheDbPath)) {
        LOGI("[SQLiteSingleStorageEng][GetDbHandle] Only use for first create cache db! [%d] [%d]",
            isWrite, GetEngineState());
        return -E_EKEYREVOKED;
    }

    errCode = GetCacheDbHandle(dbHandle, option);
    if (errCode != E_OK) {
        LOGE("singleVerStorageEngine::GetDbHandle get cache handle fail! errCode = [%d]", errCode);
        return errCode;
    }
    SetEngineState(EngineState::CACHEDB);
    executorState_ = ExecutorState::CACHEDB;

    ResetCacheRecordVersion();
    // Get handle means maindb file ekeyevoked, not need attach to
    return errCode;
}

namespace CacheDbSqls {
const std::string CREATE_CACHE_LOCAL_TABLE_SQL =
    "CREATE TABLE IF NOT EXISTS local_data(" \
        "key     BLOB   NOT NULL," \
        "value  BLOB," \
        "timestamp  INT," \
        "hash_key   BLOB   PRIMARY KEY   NOT NULL," \
        "flag  INT  NOT NULL);";

const std::string CREATE_CACHE_SYNC_TABLE_SQL =
    "CREATE TABLE IF NOT EXISTS sync_data(" \
        "key         BLOB NOT NULL," \
        "value       BLOB," \
        "timestamp   INT  NOT NULL," \
        "flag        INT  NOT NULL," \
        "device      BLOB," \
        "ori_device  BLOB," \
        "hash_key    BLOB  NOT NULL," \
        "w_timestamp INT," \
        "version     INT  NOT NULL," \
        "PRIMARY Key(version, hash_key));";
}

// Warning: Use error passwd create cache database can not check, it will create error passwd cache db,
// And make migrate data failed! This cache db will not be open correctly.
int SQLiteSingleVerStorageEngine::GetCacheDbHandle(sqlite3 *&db, OpenDbProperties &option)
{
    option.uri = GetDbDir(option.subdir, DbType::CACHE) + "/" + DBConstant::SINGLE_VER_CACHE_STORE +
        DBConstant::DB_EXTENSION;
    SetUri(option.uri);
    // creatTable
    option.sqls = {CacheDbSqls::CREATE_CACHE_LOCAL_TABLE_SQL, CacheDbSqls::CREATE_CACHE_SYNC_TABLE_SQL};
    SetSQL(option.sqls);

    if (!option.createIfNecessary) {
        std::string mainDbPath = GetDbDir(option.subdir, DbType::MAIN) + "/" + DBConstant::SINGLE_VER_DATA_STORE +
            DBConstant::DB_EXTENSION;
        if (!OS::CheckPathExistence(mainDbPath)) { // Whether to create a cacheDb is based on whether the mainDb exists
            return -E_INVALID_DB;
        }
    }

    option.createIfNecessary = true;
    int errCode = SQLiteUtils::OpenDatabase(option, db);
    if (errCode != E_OK) {
        LOGE("Get CacheDb handle failed, errCode = [%d], errno = [%d]", errCode, errno);
        return errCode;
    }
    return errCode;
}

void SQLiteSingleVerStorageEngine::CheckDatabaseSecOpt(const SecurityOption &secOption) const
{
    if (!(secOption == option_.securityOpt) && (secOption.securityLabel > option_.securityOpt.securityLabel) &&
        secOption.securityLabel != SecurityLabel::NOT_SET &&
        option_.securityOpt.securityLabel != SecurityLabel::NOT_SET) {
        LOGW("[SQLiteSingleVerStorageEngine] SecurityOption mismatch, existed:[%d-%d] vs input:[%d-%d]",
            secOption.securityLabel, secOption.securityFlag, option_.securityOpt.securityLabel,
            option_.securityOpt.securityFlag);
    }
}

int SQLiteSingleVerStorageEngine::CreateNewDirsAndSetSecOpt() const
{
    LOGD("[SQLiteSingleVerStorageEngine] Begin to create new dirs and set security option");
    return CreateNewDirsAndSetSecOption(option_);
}

int SQLiteSingleVerStorageEngine::GetExistedSecOption(SecurityOption &secOption) const
{
    LOGD("[SQLiteSingleVerStorageEngine] Try to get existed sec option");
    return GetExistedSecOpt(option_, secOption);
}

void SQLiteSingleVerStorageEngine::ClearCorruptedFlag()
{
    isCorrupted_ = false;
}

int SQLiteSingleVerStorageEngine::PreCreateExecutor(bool isWrite, SecurityOption &existedSecOpt,
    OpenDbProperties &option)
{
    // Assume that create the write executor firstly and the write one we will not be released.
    // If the write one would be released in the future, should take care the pass through.
    if (!isWrite) {
        return E_OK;
    }

    if (option.isMemDb) {
        return E_OK;
    }

    // check sqlite open ok
    int errCode = CheckStoreStatus(option);
    if (errCode != E_OK) {
        return errCode;
    }

    // Get the existed database secure option.
    errCode = GetExistedSecOption(existedSecOpt);
    if (errCode != E_OK) {
        return errCode;
    }

    CheckDatabaseSecOpt(existedSecOpt);

    // Judge whether need update the security option of the engine.
    // Should update the security in the import or rekey scene(inner) or exist is not set.
    if (IsUseExistedSecOption(existedSecOpt, option.securityOpt)) {
        option.securityOpt = existedSecOpt;
        SetSecurityOption(existedSecOpt);
    } else {
        isNeedUpdateSecOpt_ = true;
    }

    errCode = CreateNewDirsAndSetSecOpt();
    if (errCode != E_OK) {
        return errCode;
    }

    if (!isUpdated_) {
        errCode = SQLiteSingleVerDatabaseUpgrader::TransferDatabasePath(option.subdir, option);
        if (errCode != E_OK) {
            LOGE("[PreCreateExecutor] Transfer Db file path failed[%d].", errCode);
            return errCode;
        }
    }

    return E_OK;
}

int SQLiteSingleVerStorageEngine::EndCreateExecutor(sqlite3 *db, SecurityOption existedSecOpt, bool isWrite,
    bool isDetachMeta, OpenDbProperties &option)
{
    if (option.isMemDb || !isWrite) {
        return E_OK;
    }

    int errCode = SQLiteSingleVerDatabaseUpgrader::SetSecOption(option.subdir, option.securityOpt, existedSecOpt,
        isNeedUpdateSecOpt_);
    if (errCode != E_OK) {
        if (errCode == -E_NOT_SUPPORT) {
            option.securityOpt = SecurityOption();
            SetSecurityOption(option.securityOpt);
            errCode = E_OK;
        }
        LOGE("SetSecOption failed:%d", errCode);
        return errCode;
    }

    // after setting secOption, the database file operation ends
    // database create completed, delete the token
    if (OS::CheckPathExistence(option.subdir + DBConstant::PATH_POSTFIX_DB_INCOMPLETE) &&
        OS::RemoveFile(option.subdir + DBConstant::PATH_POSTFIX_DB_INCOMPLETE) != E_OK) {
        LOGE("Finish to create the complete database, but delete token fail! errCode = [E_SYSTEM_API_FAIL]");
        return -E_SYSTEM_API_FAIL;
    }
    if (isDetachMeta) {
        errCode = SQLiteUtils::ExecuteRawSQL(db, "DETACH 'meta'");
        if (errCode != E_OK) {
            LOGE("Detach meta db failed %d", errCode);
            return errCode;
        } else {
            LOGI("Detach meta db success");
        }
    }
    errCode = SqliteLogTableManager::CreateKvSyncLogTable(db);
    if (errCode != E_OK) {
        LOGE("[SqlSinEngine] create cloud log table failed, errCode = [%d]", errCode);
    } else {
        LOGI("[SqlSinEngine] create cloud log table success");
    }
    return errCode;
}

int SQLiteSingleVerStorageEngine::TryAttachMetaDb(const SecurityOption &existedSecOpt, sqlite3 *&dbHandle,
    bool &isAttachMeta, bool &isNeedDetachMeta, OpenDbProperties &option)
{
    bool isCurrentSESECE = ParamCheckUtils::IsS3SECEOpt(existedSecOpt);
    bool isOpenSESECE = ParamCheckUtils::IsS3SECEOpt(option.securityOpt);
    // attach or not depend on its true secOpt, but it's not permit while option_.secOpt different from true secOpt
    if ((!option.isMemDb) && (isOpenSESECE || (isNeedUpdateSecOpt_ && isCurrentSESECE))) {
        int errCode = AttachMetaDatabase(dbHandle, option);
        if (errCode != E_OK) {
            (void)sqlite3_close_v2(dbHandle);
            dbHandle = nullptr;
            return errCode;
        }
        isAttachMeta = isOpenSESECE; // only open with S3 SECE need in attach mode
        isNeedDetachMeta = !isOpenSESECE && isCurrentSESECE; // NOT S3 SECE no need meta.db
    }
    return E_OK;
}

int SQLiteSingleVerStorageEngine::CreateNewExecutor(bool isWrite, StorageExecutor *&handle)
{
    SecurityOption existedSecOpt;
    auto option = GetOption();
    int errCode = PreCreateExecutor(isWrite, existedSecOpt, option);
    if (errCode != E_OK) {
        return errCode;
    }

    sqlite3 *dbHandle = nullptr;
    errCode = GetDbHandle(isWrite, dbHandle, option);
    if (errCode != E_OK) {
        return errCode;
    }

    bool isAttachMeta = false;
    bool isDetachMeta = false;
    errCode = TryAttachMetaDb(existedSecOpt, dbHandle, isAttachMeta, isDetachMeta, option);
    if (errCode != E_OK) {
        return errCode;
    }

    RegisterFunctionIfNeed(dbHandle, option);
    errCode = UpgradeInner(dbHandle, option);
    if (errCode != E_OK) {
        (void)sqlite3_close_v2(dbHandle);
        dbHandle = nullptr;
        return errCode;
    }

    errCode = EndCreateExecutor(dbHandle, existedSecOpt, isWrite, isDetachMeta, option);
    if (errCode != E_OK) {
        LOGE("After create executor, set security option incomplete!");
        (void)sqlite3_close_v2(dbHandle);
        dbHandle = nullptr;
        return errCode;
    }

    handle = NewSQLiteStorageExecutor(dbHandle, isWrite, option.isMemDb);
    if (handle == nullptr) {
        LOGE("New SQLiteStorageExecutor[%d] for the pool failed.", isWrite);
        (void)sqlite3_close_v2(dbHandle);
        dbHandle = nullptr;
        return -E_OUT_OF_MEMORY;
    }
    if (isAttachMeta) {
        SQLiteSingleVerStorageExecutor *singleVerHandle = static_cast<SQLiteSingleVerStorageExecutor *>(handle);
        singleVerHandle->SetAttachMetaMode(isAttachMeta);
    }
    return E_OK;
}

int SQLiteSingleVerStorageEngine::UpgradeInner(sqlite3 *db, const OpenDbProperties &option)
{
    if (isUpdated_ || GetEngineState() == EngineState::CACHEDB) {
        return E_OK;
    }

    std::unique_ptr<SQLiteSingleVerDatabaseUpgrader> upgrader;
    LOGD("[SqlSingleEngine][Upgrade] NewSchemaStrSize=%zu", option.schema.size());
    if (option.schema.empty()) {
        upgrader = std::make_unique<SQLiteSingleVerDatabaseUpgrader>(db, option.securityOpt, option.isMemDb);
    } else {
        SchemaObject schema;
        int errCode = schema.ParseFromSchemaString(option.schema);
        if (errCode != E_OK) {
            LOGE("Upgrader failed while parsing the origin schema:%d", errCode);
            return errCode;
        }
        upgrader = std::make_unique<SQLiteSingleVerSchemaDatabaseUpgrader>(db, schema,
            option.securityOpt, option.isMemDb);
    }

    std::string mainDbDir = GetDbDir(option.subdir, DbType::MAIN);
    std::string mainDbFilePath = mainDbDir + "/" + DBConstant::SINGLE_VER_DATA_STORE + DBConstant::DB_EXTENSION;
    SecurityOption secOpt = option.securityOpt;
    int errCode = E_OK;
    if (isNeedUpdateSecOpt_) {
        errCode = GetPathSecurityOption(mainDbFilePath, secOpt);
        if (errCode != E_OK) {
            LOGI("[SingleVerStorageEngine::Upgrade] Failed to get the path security option, errCode = [%d]", errCode);
            if (errCode != -E_NOT_SUPPORT) {
                return errCode;
            }
            secOpt = SecurityOption();
        }
    }

    upgrader->SetMetaUpgrade(secOpt, option.securityOpt, option.subdir);
    upgrader->SetSubdir(option.subdir);
    errCode = upgrader->Upgrade();
    if (errCode != E_OK) {
        LOGE("Single ver database upgrade failed:%d", errCode);
        return errCode;
    }

    LOGD("Finish upgrade single ver database!");
    isUpdated_ = true; // Identification to avoid repeated upgrades
    std::unique_lock<std::shared_mutex> lock(schemaChangedMutex_);
    isSchemaChanged_ = upgrader->IsValueNeedUpgrade();
    return errCode;
}

// Attention: This function should be called before "Upgrade".
// Attention: This function should be called for each executor on the sqlite3 handle that the executor binds to.
void SQLiteSingleVerStorageEngine::RegisterFunctionIfNeed(sqlite3 *dbHandle, const OpenDbProperties &option) const
{
    // This function should accept a sqlite3 handle with no perception of database classification. That is, if it is
    // not a newly created database, the meta-Table should exist and can be accessed.
    std::string schemaStr = option.schema;
    if (schemaStr.empty()) {
        // If schema from GetKvStore::Option is empty, we have to try to load it from database. ReadOnly mode if exist;
        int errCode = SQLiteUtils::GetSchema(dbHandle, schemaStr);
        if (errCode != E_OK) {
            LOGD("[SqlSinEngine] Can't get schema from db[%d], maybe it is just created or not a schema-db.", errCode);
        }
    }
    if (!schemaStr.empty()) {
        // This must be a Schema-Database, if it is Json-Schema, the Register will do nothing and return E_OK
        int errCode = SQLiteUtils::RegisterFlatBufferFunction(dbHandle, schemaStr);
        if (errCode != E_OK) { // Not very likely
            // Just warning, if no index had been or need to be created, then put or kv-get can still use.
            LOGW("[SqlSinEngine] RegisterFlatBufferExtractFunction fail, errCode = %d", errCode);
        }
    }

    // This function is used to update meta_data in triggers when it's attached to mainDB
    int errCode = SQLiteUtils::RegisterMetaDataUpdateFunction(dbHandle);
    if (errCode != E_OK) {
        LOGW("[SqlSinEngine] RegisterMetaDataUpdateFunction fail, errCode = %d", errCode);
    }
}

int SQLiteSingleVerStorageEngine::AttachMetaDatabase(sqlite3 *dbHandle, const OpenDbProperties &option) const
{
    int errCode;
    LOGD("SQLiteSingleVerStorageEngine begin attach metaDb!");
    std::string metaDbPath = option.subdir + "/" + DBConstant::METADB_DIR + "/" +
        DBConstant::SINGLE_VER_META_STORE + DBConstant::DB_EXTENSION;
    // attach metaDb may failed while createIfNecessary is false, here need to create metaDb first.
    if (!option.createIfNecessary && !OS::CheckPathExistence(metaDbPath)) {
        errCode = SQLiteUtils::CreateMetaDatabase(metaDbPath);
        if (errCode != E_OK) {
            return errCode;
        }
    }
    CipherPassword passwd;
    errCode = SQLiteUtils::AttachNewDatabase(dbHandle, option.cipherType, passwd, metaDbPath, "meta");
    if (errCode != E_OK) {
        LOGE("AttachNewDatabase fail, errCode = %d", errCode);
    }
    return errCode;
}

void SQLiteSingleVerStorageEngine::ResetCacheRecordVersion()
{
    (void)cacheRecordVersion_.store(CACHE_RECORD_DEFAULT_VERSION, std::memory_order_seq_cst);
}

void SQLiteSingleVerStorageEngine::IncreaseCacheRecordVersion()
{
    (void)cacheRecordVersion_.fetch_add(1, std::memory_order_seq_cst);
}

uint64_t SQLiteSingleVerStorageEngine::GetAndIncreaseCacheRecordVersion()
{
    return cacheRecordVersion_.fetch_add(1, std::memory_order_seq_cst);
}

uint64_t SQLiteSingleVerStorageEngine::GetCacheRecordVersion() const
{
    return cacheRecordVersion_.load(std::memory_order_seq_cst);
}

void SQLiteSingleVerStorageEngine::CommitAndReleaseNotifyData(SingleVerNaturalStoreCommitNotifyData *&committedData,
    int eventType) const
{
    std::shared_lock<std::shared_mutex> lock(notifyMutex_);
    if (commitNotifyFunc_ == nullptr) {
        LOGE("commitNotifyFunc_ is nullptr, can't notify now.");
        RefObject::DecObjRef(committedData);
        committedData = nullptr;
        return;
    }
    commitNotifyFunc_(eventType, static_cast<KvDBCommitNotifyFilterAbleData *>(committedData));
    committedData = nullptr;
}

void SQLiteSingleVerStorageEngine::InitConflictNotifiedFlag(SingleVerNaturalStoreCommitNotifyData *&committedData) const
{
    if (committedData == nullptr) {
        LOGI("[SQLiteSingleVerStorageEngine::InitConflictNotifiedFlag] committedData is null.");
        return;
    }
    auto identifier = GetIdentifier();
    auto kvDBManager = KvDBManager::GetInstance();
    if (kvDBManager == nullptr) {
        LOGE("[SQLiteSingleVerStorageEngine::InitConflictNotifiedFlag] kvDBManager is null.");
        return;
    }
    auto kvdb = kvDBManager->FindKvDB(identifier);
    if (kvdb == nullptr) {
        LOGE("[SQLiteSingleVerStorageEngine::InitConflictNotifiedFlag] kvdb is null.");
        return;
    }
    unsigned int conflictFlag = 0;
    if (static_cast<GenericKvDB *>(kvdb)->GetRegisterFunctionCount(
        RegisterFuncType::CONFLICT_SINGLE_VERSION_NS_FOREIGN_KEY_ONLY) != 0) {
        conflictFlag |= static_cast<unsigned>(SQLiteGeneralNSConflictType::SQLITE_GENERAL_NS_FOREIGN_KEY_ONLY);
    }
    if (static_cast<GenericKvDB *>(kvdb)->GetRegisterFunctionCount(
        RegisterFuncType::CONFLICT_SINGLE_VERSION_NS_FOREIGN_KEY_ORIG) != 0) {
        conflictFlag |= static_cast<unsigned>(SQLiteGeneralNSConflictType::SQLITE_GENERAL_NS_FOREIGN_KEY_ORIG);
    }
    if (static_cast<GenericKvDB *>(kvdb)->GetRegisterFunctionCount(
        RegisterFuncType::CONFLICT_SINGLE_VERSION_NS_NATIVE_ALL) != 0) {
        conflictFlag |= static_cast<unsigned>(SQLiteGeneralNSConflictType::SQLITE_GENERAL_NS_NATIVE_ALL);
    }
    RefObject::DecObjRef(kvdb);
    LOGD("[SQLiteSingleVerStorageEngine::InitConflictNotifiedFlag] conflictFlag Flag: %u", conflictFlag);
    committedData->SetConflictedNotifiedFlag(static_cast<int>(conflictFlag));
}

void SQLiteSingleVerStorageEngine::SetMaxValueSize(uint32_t maxValueSize)
{
    if (maxValueSize_ != maxValueSize) {
        LOGI("Set the max value size to %" PRIu32, maxValueSize);
    }
    maxValueSize_ = maxValueSize;
}

uint32_t SQLiteSingleVerStorageEngine::GetMaxValueSize()
{
    return maxValueSize_;
}

void SQLiteSingleVerStorageEngine::CommitNotifyForMigrateCache(NotifyMigrateSyncData &syncData) const
{
    const auto &isRemote = syncData.isRemote;
    const auto &isRemoveDeviceData = syncData.isRemoveDeviceData;
    auto &committedData = syncData.committedData;
    auto &entries = syncData.entries;

    // Put data. Including insert, update and delete.
    if (!isRemoveDeviceData) { // LCOV_EXCL_BR_LINE
        if (committedData != nullptr) { // LCOV_EXCL_BR_LINE
            int eventType = static_cast<int>(isRemote ?
                SQLiteGeneralNSNotificationEventType::SQLITE_GENERAL_NS_SYNC_EVENT :
                SQLiteGeneralNSNotificationEventType::SQLITE_GENERAL_NS_PUT_EVENT);
            CommitAndReleaseNotifyData(committedData, eventType);
        }
        return;
    }

    // Remove device data.
    if (entries.empty() || entries.size() > MAX_TOTAL_NOTIFY_ITEM_SIZE) { // LCOV_EXCL_BR_LINE
        return;
    }
    size_t totalSize = 0;
    for (auto iter = entries.begin(); iter != entries.end();) {
        auto &entry = *iter;
        if (committedData == nullptr) { // LCOV_EXCL_BR_LINE
            committedData = new (std::nothrow) SingleVerNaturalStoreCommitNotifyData();
            if (committedData == nullptr) { // LCOV_EXCL_BR_LINE
                LOGE("Alloc committed notify data failed.");
                return;
            }
        }
        if (entry.key.size() > DBConstant::MAX_KEY_SIZE || entry.value.size() > maxValueSize_) { // LCOV_EXCL_BR_LINE
            iter++;
            continue;
        }
        if (entry.key.size() + entry.value.size() + totalSize > MAX_TOTAL_NOTIFY_DATA_SIZE) { // LCOV_EXCL_BR_LINE
            CommitAndReleaseNotifyData(committedData,
                static_cast<int>(SQLiteGeneralNSNotificationEventType::SQLITE_GENERAL_NS_SYNC_EVENT));
            totalSize = 0;
            continue;
        }
        totalSize += (entry.key.size() + entry.value.size());
        committedData->InsertCommittedData(std::move(entry), DataType::DELETE, false);
        iter++;
    }
    if (committedData != nullptr) { // LCOV_EXCL_BR_LINE
        CommitAndReleaseNotifyData(committedData,
            static_cast<int>(SQLiteGeneralNSNotificationEventType::SQLITE_GENERAL_NS_SYNC_EVENT));
    }
}

// Cache subscribe when engine state is CACHE mode, and its will be applied at the beginning of migrate.
void SQLiteSingleVerStorageEngine::CacheSubscribe(const std::string &subscribeId, const QueryObject &query)
{
    std::lock_guard<std::mutex> lock(subscribeMutex_);
    subscribeQuery_[subscribeId] = query;
}

bool SQLiteSingleVerStorageEngine::IsUseExistedSecOption(const SecurityOption &existedSecOpt,
    const SecurityOption &openSecOpt)
{
    if (isNeedUpdateSecOpt_) {
        return false;
    }
    if (existedSecOpt.securityLabel != openSecOpt.securityLabel) {
        return false;
    }
    return true;
}

int SQLiteSingleVerStorageEngine::UpgradeLocalMetaData()
{
    std::function<int(void)> schemaChangedFunc = nullptr;
    {
        std::unique_lock<std::shared_mutex> lock(schemaChangedMutex_);
        if (isSchemaChanged_) {
            schemaChangedFunc = schemaChangedFunc_;
            isSchemaChanged_ = false;
        }
    }
    if (schemaChangedFunc != nullptr) {
        return schemaChangedFunc();
    }
    return E_OK;
}
}
