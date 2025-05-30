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

#include "sqlite_single_ver_storage_executor.h"

#include <algorithm>

#include "cloud/cloud_store_types.h"
#include "data_transformer.h"
#include "db_constant.h"
#include "db_common.h"
#include "db_errno.h"
#include "parcel.h"
#include "platform_specific.h"
#include "res_finalizer.h"
#include "runtime_context.h"
#include "sqlite_meta_executor.h"
#include "sqlite_single_ver_storage_executor_sql.h"
#include "log_print.h"
#include "log_table_manager_factory.h"

namespace DistributedDB {
namespace {
constexpr const char *HWM_HEAD = "naturalbase_cloud_meta_sync_data_";
}

int SQLiteSingleVerStorageExecutor::BindSyncDataTime(sqlite3_stmt *statement, const DataItem &dataItem, bool isUpdate)
{
    int errCode = SQLiteUtils::BindInt64ToStatement(statement, BIND_SYNC_STAMP_INDEX, dataItem.timestamp);
    if (errCode != E_OK) {
        LOGE("Bind saved sync data stamp failed:%d", errCode);
        return errCode;
    }

    const int writeTimeIndex = isUpdate ? BIND_SYNC_UPDATE_W_TIME_INDEX : BIND_SYNC_W_TIME_INDEX;
    errCode = SQLiteUtils::BindInt64ToStatement(statement, writeTimeIndex, dataItem.writeTimestamp);
    if (errCode != E_OK) {
        LOGE("Bind saved sync data write stamp failed:%d", errCode);
        return errCode;
    }

    const int modifyTimeIndex = isUpdate ? BIND_SYNC_UPDATE_MODIFY_TIME_INDEX : BIND_SYNC_MODIFY_TIME_INDEX;
    errCode = SQLiteUtils::BindInt64ToStatement(statement, modifyTimeIndex, dataItem.modifyTime);
    if (errCode != E_OK) {
        LOGE("Bind saved sync data modify time failed:%d", errCode);
        return errCode;
    }

    const int createTimeIndex = isUpdate ? BIND_SYNC_UPDATE_CREATE_TIME_INDEX : BIND_SYNC_CREATE_TIME_INDEX;
    errCode = SQLiteUtils::BindInt64ToStatement(statement, createTimeIndex, dataItem.createTime);
    if (errCode != E_OK) {
        LOGE("Bind saved sync data create time failed:%d", errCode);
        return errCode;
    }

    if (IsPrintTimestamp()) {
        LOGI("Write timestamp:%" PRIu64 " timestamp:%" PRIu64 ", flag:%" PRIu64 " modifyTime:%" PRIu64 " createTime:%"
            PRIu64 ", key size:%" PRIu32 ", value size:%" PRIu32, dataItem.writeTimestamp, dataItem.timestamp,
            dataItem.flag, dataItem.modifyTime, dataItem.createTime, dataItem.key.size(), dataItem.value.size());
    }
    return errCode;
}

int SQLiteSingleVerStorageExecutor::CreateCloudLogTable()
{
    if (dbHandle_ == nullptr) {
        return -E_INVALID_DB;
    }
    return SqliteLogTableManager::CreateKvSyncLogTable(dbHandle_);
}

int SQLiteSingleVerStorageExecutor::CloudExcuteRemoveOrUpdate(const std::string &sql, const std::string &deviceName,
    const std::string &user, bool isUserBlobType)
{
    int errCode = E_OK;
    sqlite3_stmt *statement = nullptr;
    errCode = SQLiteUtils::GetStatement(dbHandle_, sql, statement);
    if (errCode != E_OK) {
        return errCode;
    }
    // device name always hash string.
    int bindIndex = 1; // 1 is the first index for blob to bind.
    int ret = E_OK;
    if (!user.empty()) {
        if (isUserBlobType) {
            std::vector<uint8_t> useVect(user.begin(), user.end());
            errCode = SQLiteUtils::BindBlobToStatement(statement, bindIndex, useVect, true);
        } else {
            errCode = SQLiteUtils::BindTextToStatement(statement, bindIndex, user);
        }
        if (errCode != E_OK) {
            LOGE("Failed to bind the removed device:%d", errCode);
            SQLiteUtils::ResetStatement(statement, true, ret);
            return errCode;
        }
        bindIndex++;
    }
    if (!deviceName.empty()) {
        std::vector<uint8_t> devVect(deviceName.begin(), deviceName.end());
        errCode = SQLiteUtils::BindBlobToStatement(statement, bindIndex, devVect, true); // only one arg.
        if (errCode != E_OK) {
            LOGE("Failed to bind the removed device:%d", errCode);
            SQLiteUtils::ResetStatement(statement, true, ret);
            return errCode;
        }
    }
    errCode = SQLiteUtils::StepWithRetry(statement, isMemDb_);
    if (errCode != SQLiteUtils::MapSQLiteErrno(SQLITE_DONE)) {
        LOGE("Failed to execute rm the device synced data:%d", errCode);
    } else {
        errCode = E_OK;
    }
    SQLiteUtils::ResetStatement(statement, true, ret);
    return errCode != E_OK ? errCode : ret;
}

int SQLiteSingleVerStorageExecutor::CloudCheckDataExist(const std::string &sql, const std::string &deviceName,
    const std::string &user, bool &isExist)
{
    int errCode = E_OK;
    sqlite3_stmt *statement = nullptr;
    errCode = SQLiteUtils::GetStatement(dbHandle_, sql, statement);
    if (errCode != E_OK) {
        return errCode;
    }
    int bindIndex = 1; // 1 is the first index for blob to bind.
    int ret = E_OK;
    if (!user.empty()) {
        errCode = SQLiteUtils::BindTextToStatement(statement, bindIndex, user); // only one arg.
        if (errCode != E_OK) {
            LOGE("Failed to bind the removed device:%d", errCode);
            SQLiteUtils::ResetStatement(statement, true, ret);
            return errCode;
        }
        bindIndex++;
        if (sql == SELECT_CLOUD_LOG_DATA_BY_USERID_HASHKEY_SQL) { // the second argument is also userid.
            errCode = SQLiteUtils::BindTextToStatement(statement, bindIndex, user); // only one arg.
            if (errCode != E_OK) {
                LOGE("Failed to bind the removed device:%d", errCode);
                SQLiteUtils::ResetStatement(statement, true, ret);
                return errCode;
            }
        }
    }
    if (!deviceName.empty()) {
        std::vector<uint8_t> devVect(deviceName.begin(), deviceName.end());
        errCode = SQLiteUtils::BindBlobToStatement(statement, bindIndex, devVect, true); // only one arg.
        if (errCode != E_OK) {
            LOGE("Failed to bind the removed device:%d", errCode);
            SQLiteUtils::ResetStatement(statement, true, ret);
            return errCode;
        }
    }
    errCode = SQLiteUtils::StepWithRetry(statement, isMemDb_);
    if (errCode != SQLiteUtils::MapSQLiteErrno(SQLITE_DONE) && errCode != SQLiteUtils::MapSQLiteErrno(SQLITE_ROW)) {
        LOGE("Failed to execute find the device synced data:%d", errCode);
    } else {
        if (errCode == SQLiteUtils::MapSQLiteErrno(SQLITE_ROW)) { // means deviceId can be matched in log table
            isExist = true;
        }
        SQLiteUtils::ResetStatement(statement, true, ret);
        return E_OK;
    }
    SQLiteUtils::ResetStatement(statement, true, ret);
    return errCode != E_OK ? errCode : ret;
}

int SQLiteSingleVerStorageExecutor::RemoveDeviceDataInner(ClearMode mode)
{
    if (mode == ClearMode::DEFAULT) {
        return CloudExcuteRemoveOrUpdate(REMOVE_ALL_DEV_SYNC_DATA_SQL, "", "");
    }
    int errCode = CloudExcuteRemoveOrUpdate(REMOVE_CLOUD_ALL_HWM_DATA_SQL, "", "", true);
    if (errCode != E_OK) {
        return errCode;
    }
    errCode = CloudExcuteRemoveOrUpdate(REMOVE_CLOUD_ALL_LOG_DATA_SQL, "", "");
    if (errCode != E_OK) {
        return errCode;
    }
    if (mode == FLAG_AND_DATA) {
        return CloudExcuteRemoveOrUpdate(REMOVE_CLOUD_ALL_DEV_DATA_SQL, "", "");
    } else if (mode == FLAG_ONLY) {
        errCode = CloudExcuteRemoveOrUpdate(REMOVE_CLOUD_ALL_DEV_DATA_VERSION_SQL, "", "");
        if (errCode != E_OK) {
            return errCode;
        }
    }
    return CloudExcuteRemoveOrUpdate(UPDATE_CLOUD_ALL_DEV_DATA_SQL, "", "");
}

int SQLiteSingleVerStorageExecutor::RemoveDeviceDataInner(const std::string &deviceName, ClearMode mode)
{
    if (mode == ClearMode::DEFAULT) {
        return CloudExcuteRemoveOrUpdate(REMOVE_DEV_SYNC_DATA_BY_DEV_ID_SQL, deviceName, "");
    }
    int errCode = CloudExcuteRemoveOrUpdate(REMOVE_CLOUD_ALL_HWM_DATA_SQL, "", "", true);
    if (errCode != E_OK) {
        return errCode;
    }
    errCode = CloudExcuteRemoveOrUpdate(REMOVE_CLOUD_LOG_DATA_BY_DEVID_SQL, deviceName, "");
    if (errCode != E_OK) {
        return errCode;
    }
    if (mode == FLAG_AND_DATA) {
        return CloudExcuteRemoveOrUpdate(REMOVE_CLOUD_DEV_DATA_BY_DEVID_SQL, deviceName, "");
    } else if (mode == FLAG_ONLY) {
        errCode = CloudExcuteRemoveOrUpdate(REMOVE_CLOUD_DEV_DATA_VERSION_BY_DEVID_SQL, deviceName, "");
        if (errCode != E_OK) {
            return errCode;
        }
    }
    return CloudExcuteRemoveOrUpdate(UPDATE_CLOUD_DEV_DATA_BY_DEVID_SQL, deviceName, "");
}

int SQLiteSingleVerStorageExecutor::RemoveDeviceDataWithUserInner(const std::string &user, ClearMode mode)
{
    int errCode = CloudExcuteRemoveOrUpdate(REMOVE_CLOUD_HWM_DATA_BY_USERID_SQL, "",
        std::string(HWM_HEAD) + user, true);
    if (errCode != E_OK) {
        return errCode;
    }
    if (mode == FLAG_AND_DATA) {
        bool isMultiHashExistInLog = false;
        errCode = CloudCheckDataExist(SELECT_CLOUD_LOG_DATA_BY_USERID_HASHKEY_SQL, "", user, isMultiHashExistInLog);
        if (errCode != E_OK) {
            return errCode;
        }
        if (!isMultiHashExistInLog) { // means the hashKey is unique in the log table.
            errCode = CloudExcuteRemoveOrUpdate(REMOVE_CLOUD_DEV_DATA_BY_USERID_SQL, "", user);
            if (errCode != E_OK) {
                return errCode;
            }
        }
    }
    errCode = CloudExcuteRemoveOrUpdate(UPDATE_CLOUD_DEV_DATA_BY_USERID_SQL, "", user); // delete synclog table.
    if (errCode != E_OK) {
        return errCode;
    }
    return CloudExcuteRemoveOrUpdate(REMOVE_CLOUD_LOG_DATA_BY_USERID_SQL, "", user);
}

int SQLiteSingleVerStorageExecutor::RemoveDeviceDataWithUserInner(const std::string &deviceName,
    const std::string &user, ClearMode mode)
{
    int errCode = CloudExcuteRemoveOrUpdate(REMOVE_CLOUD_HWM_DATA_BY_USERID_SQL, "",
        std::string(HWM_HEAD) + user, true);
    if (errCode != E_OK) {
        return errCode;
    }
    bool isMultiHashExistInLog = false;
    int ret = CloudCheckDataExist(SELECT_CLOUD_LOG_DATA_BY_USERID_HASHKEY_SQL, "", user, isMultiHashExistInLog);
    if (ret != E_OK) {
        return ret;
    }
    errCode = CloudExcuteRemoveOrUpdate(REMOVE_CLOUD_LOG_DATA_BY_USERID_DEVID_SQL, deviceName, user);
    if (errCode != E_OK) {
        return errCode;
    }
    if (mode == FLAG_AND_DATA) {
        if (!isMultiHashExistInLog) { // means the hashKey is unique in the log table.
            // If the hashKey does not exist in the syncLog table and type is cloud data, the data should be deleted
            return CloudExcuteRemoveOrUpdate(REMOVE_CLOUD_DEV_DATA_BY_DEVID_HASHKEY_NOTIN_SQL, deviceName, "");
        }
    }
    return CloudExcuteRemoveOrUpdate(UPDATE_CLOUD_DEV_DATA_BY_DEVID_HASHKEY_NOTIN_SQL, deviceName, "");
}

int SQLiteSingleVerStorageExecutor::RemoveDeviceData(const std::string &deviceName, ClearMode mode)
{
    if (deviceName.empty()) {
        return CheckCorruptedStatus(RemoveDeviceDataInner(mode));
    }
    bool isDataExist = false;
    int errCode = CloudCheckDataExist(SELECT_CLOUD_LOG_DATA_BY_DEVID_SQL, deviceName, "", isDataExist);
    // means deviceId can not be matched in log table
    if (mode != ClearMode::DEFAULT && (!isDataExist || errCode != E_OK)) {
        return CheckCorruptedStatus(errCode);
    }
    return CheckCorruptedStatus(RemoveDeviceDataInner(deviceName, mode));
}

int SQLiteSingleVerStorageExecutor::RemoveDeviceData(const std::string &deviceName, const std::string &user,
    ClearMode mode)
{
    if (mode == ClearMode::DEFAULT) {
        return CheckCorruptedStatus(deviceName.empty() ?
            RemoveDeviceDataInner(mode) : RemoveDeviceDataInner(deviceName, mode));
    }
    int errCode = E_OK;
    bool isDataExist = false;
    if (deviceName.empty()) {
        errCode = CloudCheckDataExist(SELECT_CLOUD_DEV_DATA_BY_USERID_SQL, "", user, isDataExist);
        if (errCode != E_OK || !isDataExist) {
            return CheckCorruptedStatus(errCode);
        }
        return CheckCorruptedStatus(RemoveDeviceDataWithUserInner(user, mode));
    }
    errCode = CloudCheckDataExist(SELECT_CLOUD_LOG_DATA_BY_USERID_DEVID_SQL, deviceName, user, isDataExist);
    if (errCode != E_OK || !isDataExist) {
        return CheckCorruptedStatus(errCode);
    }
    return CheckCorruptedStatus(RemoveDeviceDataWithUserInner(deviceName, user, mode));
}

int SQLiteSingleVerStorageExecutor::GetEntries(const std::string &device, std::vector<Entry> &entries) const
{
    const std::string sql = SELECT_SYNC_ENTRIES_BY_DEVICE_SQL;
    sqlite3_stmt *stmt = nullptr;
    int errCode = SQLiteUtils::GetStatement(dbHandle_, sql, stmt);
    if (errCode != E_OK) {
        LOGE("[SQLiteSingleVerStorageExecutor] Get entries by device statement failed:%d", errCode);
        return errCode;
    }
    ResFinalizer finalizer([stmt]() {
        sqlite3_stmt *statement = stmt;
        int ret = E_OK;
        SQLiteUtils::ResetStatement(statement, true, ret);
        if (ret != E_OK) {
            LOGW("[SQLiteSingleVerStorageExecutor] Reset get entries statement failed:%d", ret);
        }
    });
    auto hashDev = DBCommon::TransferHashString(device);
    Value blobDev;
    DBCommon::StringToVector(hashDev, blobDev);
    errCode = SQLiteUtils::BindBlobToStatement(stmt, BIND_GET_ENTRIES_DEVICE_INDEX, blobDev);
    if (errCode != E_OK) {
        LOGE("[SQLiteSingleVerStorageExecutor] Bind hash device[%s] to statement failed:%d",
            DBCommon::TransferStringToHex(hashDev).c_str(), errCode);
        return errCode;
    }
    errCode = StepForResultEntries(true, stmt, entries);
    if (errCode != E_OK) {
        LOGE("[SQLiteSingleVerStorageExecutor] Get device[%s] entries failed:%d",
            DBCommon::TransferStringToHex(hashDev).c_str(), errCode);
        return errCode;
    }
    LOGD("[SQLiteSingleVerStorageExecutor] Get %zu entries by device", entries.size());
    return errCode;
}

int SQLiteSingleVerStorageExecutor::PrepareForUnSyncTotalByTime(Timestamp begin, Timestamp end,
    sqlite3_stmt *&statement, bool getDeletedData) const
{
    if (dbHandle_ == nullptr) {
        return -E_INVALID_DB;
    }

    const std::string sql = (getDeletedData ? COUNT_SYNC_DELETED_ENTRIES_SQL : COUNT_SYNC_ENTRIES_SQL);
    int errCode = SQLiteUtils::GetStatement(dbHandle_, sql, statement);
    if (errCode != E_OK) {
        LOGE("Prepare the sync num entries statement error:%d", errCode);
        return errCode;
    }

    errCode = SQLiteUtils::BindInt64ToStatement(statement, BIND_BEGIN_STAMP_INDEX, begin);
    if (errCode != E_OK) {
        LOGE("Bind the begin timestamp for getting sync num error:%d", errCode);
        int ret = E_OK;
        SQLiteUtils::ResetStatement(statement, true, ret);
        return CheckCorruptedStatus(errCode);
    }

    errCode = SQLiteUtils::BindInt64ToStatement(statement, BIND_END_STAMP_INDEX, end);
    if (errCode != E_OK) {
        LOGE("Bind the end timestamp for getting sync num error:%d", errCode);
        int ret = E_OK;
        SQLiteUtils::ResetStatement(statement, true, ret);
    }
    return CheckCorruptedStatus(errCode);
}

int SQLiteSingleVerStorageExecutor::GetCountValue(sqlite3_stmt *&countStatement, uint32_t &total) const
{
    int errCode = SQLiteUtils::StepWithRetry(countStatement, isMemDb_);
    if (errCode == SQLiteUtils::MapSQLiteErrno(SQLITE_ROW)) {
        uint64_t readCount = static_cast<uint64_t>(sqlite3_column_int64(countStatement, 0));
        if (readCount > UINT32_MAX) {
            LOGW("ReadCount is beyond UINT32_MAX");
            total = 0;
            errCode = -E_UNEXPECTED_DATA;
        } else {
            total = static_cast<uint32_t>(readCount);
            errCode = E_OK;
        }
        LOGD("[GetCountValue]Entry count in this result set is %" PRIu32 "", total);
    } else {
        errCode = -E_UNEXPECTED_DATA;
    }
    int ret = E_OK;
    SQLiteUtils::ResetStatement(countStatement, true, ret);
    return CheckCorruptedStatus(errCode);
}

int SQLiteSingleVerStorageExecutor::GetUnSyncTotalByTimestamp(Timestamp begin, Timestamp end, uint32_t &total) const
{
    sqlite3_stmt *countStatement = nullptr;
    int errCode = PrepareForUnSyncTotalByTime(begin, end, countStatement);
    if (errCode != E_OK) {
        return errCode;
    }
    return GetCountValue(countStatement, total);
}

int SQLiteSingleVerStorageExecutor::GetDeletedSyncTotalByTimestamp(Timestamp begin, Timestamp end,
    uint32_t &total) const
{
    sqlite3_stmt *countStatement = nullptr;
    int errCode = PrepareForUnSyncTotalByTime(begin, end, countStatement, true);
    if (errCode != E_OK) {
        return errCode;
    }
    return GetCountValue(countStatement, total);
}

int SQLiteSingleVerStorageExecutor::GetSyncTotalWithQuery(QueryObject &query,
    const std::pair<Timestamp, Timestamp> &timeRange, uint32_t &total) const
{
    int errCode = E_OK;
    SqliteQueryHelper helper = query.GetQueryHelper(errCode);
    if (errCode != E_OK) {
        return errCode;
    }
    sqlite3_stmt *queryStmt = nullptr;
    errCode = helper.GetQuerySyncStatement(dbHandle_, timeRange.first, timeRange.second, queryStmt, true);
    if (errCode != E_OK) {
        LOGE("Get query sync num statement failed. %d", errCode);
        return errCode;
    }
    return GetCountValue(queryStmt, total);
}

int SQLiteSingleVerStorageExecutor::RemoveCloudUploadFlag(const std::vector<uint8_t> &hashKey)
{
    const std::string tableName = "naturalbase_kv_aux_sync_data_log";
    bool isCreate = false;
    int errCode = SQLiteUtils::CheckTableExists(dbHandle_, tableName, isCreate);
    if (errCode != E_OK) {
        return errCode;
    }
    if (!isCreate) {
        return E_OK;
    }
    std::string removeSql = "UPDATE " + tableName + " SET cloud_flag=0 WHERE hash_key=?";
    sqlite3_stmt *stmt = nullptr;
    errCode = SQLiteUtils::GetStatement(dbHandle_, removeSql, stmt);
    if (errCode != E_OK) {
        LOGE("[SQLiteSingleVerStorageExecutor] Remove cloud flag get stmt failed %d", errCode);
        return errCode;
    }
    errCode = SQLiteUtils::BindBlobToStatement(stmt, BIND_HASH_KEY_INDEX, hashKey);
    if (errCode != E_OK) {
        LOGE("[SQLiteSingleVerStorageExecutor] Remove cloud flag bind hashKey failed %d", errCode);
        return errCode;
    }
    errCode = SQLiteUtils::StepWithRetry(stmt, isMemDb_);
    if (errCode == SQLiteUtils::MapSQLiteErrno(SQLITE_ROW) || errCode == SQLiteUtils::MapSQLiteErrno(SQLITE_DONE)) {
        errCode = E_OK;
    }
    int ret = E_OK;
    SQLiteUtils::ResetStatement(stmt, true, ret);
    if (ret != E_OK) {
        LOGW("[SQLiteSingleVerStorageExecutor] Finalize stmt failed %d", ret);
    }
    return errCode == E_OK ? ret : errCode;
}

bool SQLiteSingleVerStorageExecutor::IsFromDataOwner(const DataItem &itemGet, const std::string &syncDev)
{
    return itemGet.dev == syncDev ||
        (conflictResolvePolicy_ == DENY_OTHER_DEV_AMEND_CUR_DEV_DATA && itemGet.origDev == syncDev);
}

int SQLiteSingleVerStorageExecutor::ClearCloudWatermark()
{
    return CloudExcuteRemoveOrUpdate(REMOVE_CLOUD_ALL_HWM_DATA_SQL, "", "", true);
}

int SQLiteSingleVerStorageExecutor::GetMetaDataByPrefixKey(const Key &keyPrefix, std::map<Key, Value> &data) const
{
    std::string metaTableName = "meta_data";
    return SqliteMetaExecutor::GetMetaDataByPrefixKey(dbHandle_, isMemDb_, metaTableName, keyPrefix, data);
}
} // namespace DistributedDB
