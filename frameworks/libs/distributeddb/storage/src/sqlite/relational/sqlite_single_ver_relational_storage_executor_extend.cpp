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
#ifdef RELATIONAL_STORE
#include "sqlite_single_ver_relational_storage_executor.h"

#include <algorithm>
#include <optional>

#include "cloud/cloud_db_constant.h"
#include "cloud/cloud_storage_utils.h"
#include "data_transformer.h"
#include "db_common.h"
#include "log_table_manager_factory.h"
#include "relational_row_data_impl.h"
#include "res_finalizer.h"
#include "runtime_context.h"
#include "sqlite_meta_executor.h"
#include "sqlite_relational_utils.h"
#include "value_hash_calc.h"

namespace DistributedDB {
int SQLiteSingleVerRelationalStorageExecutor::GetInfoByPrimaryKeyOrGid(const TableSchema &tableSchema,
    const VBucket &vBucket, DataInfoWithLog &dataInfoWithLog, VBucket &assetInfo)
{
    std::string querySql;
    std::set<std::string> pkSet = CloudStorageUtils::GetCloudPrimaryKey(tableSchema);
    std::vector<Field> assetFields = CloudStorageUtils::GetCloudAsset(tableSchema);
    int errCode = GetQueryInfoSql(tableSchema.name, vBucket, pkSet, assetFields, querySql);
    if (errCode != E_OK) {
        LOGE("Get query log sql fail, %d", errCode);
        return errCode;
    }
    if (!pkSet.empty()) {
        errCode = GetPrimaryKeyHashValue(vBucket, tableSchema, dataInfoWithLog.logInfo.hashKey, true);
        if (errCode != E_OK) {
            LOGE("calc hash fail when get query log statement, errCode = %d", errCode);
            return errCode;
        }
    }
    sqlite3_stmt *selectStmt = nullptr;
    errCode = GetQueryLogStatement(tableSchema, vBucket, querySql, dataInfoWithLog.logInfo.hashKey, selectStmt);
    if (errCode != E_OK) {
        LOGE("Get query log statement fail, %d", errCode);
        return errCode;
    }

    bool alreadyFound = false;
    do {
        errCode = SQLiteUtils::StepWithRetry(selectStmt);
        if (errCode == SQLiteUtils::MapSQLiteErrno(SQLITE_ROW)) {
            if (alreadyFound) {
                LOGE("found more than one records in log table for one primary key or gid.");
                errCode = -E_CLOUD_ERROR;
                break;
            }
            alreadyFound = true;
            std::map<std::string, Field> pkMap = CloudStorageUtils::GetCloudPrimaryKeyFieldMap(tableSchema);
            errCode = GetInfoByStatement(selectStmt, assetFields, pkMap, dataInfoWithLog, assetInfo);
            if (errCode != E_OK) {
                LOGE("Get info by statement fail, %d", errCode);
                break;
            }
        } else if (errCode == SQLiteUtils::MapSQLiteErrno(SQLITE_DONE)) {
            errCode = alreadyFound ? E_OK : -E_NOT_FOUND;
            break;
        } else {
            LOGE("SQLite step failed when query log for cloud sync:%d", errCode);
            break;
        }
    } while (errCode == E_OK);

    int ret = E_OK;
    SQLiteUtils::ResetStatement(selectStmt, true, ret);
    return errCode != E_OK ? errCode : ret;
}

int SQLiteSingleVerRelationalStorageExecutor::GetLogInfoByStatement(sqlite3_stmt *statement, LogInfo &logInfo)
{
    int index = 0;
    logInfo.dataKey = sqlite3_column_int64(statement, index++);
    std::vector<uint8_t> device;
    (void)SQLiteUtils::GetColumnBlobValue(statement, index++, device);    // 1 is device
    DBCommon::VectorToString(device, logInfo.device);
    std::vector<uint8_t> originDev;
    (void)SQLiteUtils::GetColumnBlobValue(statement, index++, originDev); // 2 is originDev
    DBCommon::VectorToString(originDev, logInfo.originDev);
    logInfo.timestamp = static_cast<Timestamp>(sqlite3_column_int64(statement, index++)); // 3 is timestamp
    logInfo.wTimestamp = static_cast<Timestamp>(sqlite3_column_int64(statement, index++)); // 4 is wtimestamp
    logInfo.flag = static_cast<uint64_t>(sqlite3_column_int(statement, index++)); // 5 is flag
    (void)SQLiteUtils::GetColumnBlobValue(statement, index++, logInfo.hashKey); // 6 is hash_key
    (void)SQLiteUtils::GetColumnTextValue(statement, index++, logInfo.cloudGid); // 7 is cloud_gid
    (void)SQLiteUtils::GetColumnTextValue(statement, index++, logInfo.sharingResource); // 8 is sharing_resource
    logInfo.status = static_cast<uint64_t>(sqlite3_column_int64(statement, index++)); // 9 is status
    (void)SQLiteUtils::GetColumnTextValue(statement, index++, logInfo.version); // 10 is version
    return index;
}

int SQLiteSingleVerRelationalStorageExecutor::GetInfoByStatement(sqlite3_stmt *statement,
    const std::vector<Field> &assetFields, const std::map<std::string, Field> &pkMap, DataInfoWithLog &dataInfoWithLog,
    VBucket &assetInfo)
{
    int index = GetLogInfoByStatement(statement, dataInfoWithLog.logInfo); // start index of assetInfo or primary key
    int errCode = E_OK;
    for (const auto &field: assetFields) {
        Type cloudValue;
        errCode = SQLiteRelationalUtils::GetCloudValueByType(statement, field.type, index++, cloudValue);
        if (errCode != E_OK) {
            break;
        }
        errCode = PutVBucketByType(assetInfo, field, cloudValue);
        if (errCode != E_OK) {
            break;
        }
    }
    if (errCode != E_OK) {
        LOGE("set asset field failed, errCode = %d", errCode);
        return errCode;
    }

    // fill primary key
    for (const auto &item : pkMap) {
        Type cloudValue;
        errCode = SQLiteRelationalUtils::GetCloudValueByType(statement, item.second.type, index++, cloudValue);
        if (errCode != E_OK) {
            break;
        }
        errCode = PutVBucketByType(dataInfoWithLog.primaryKeys, item.second, cloudValue);
        if (errCode != E_OK) {
            break;
        }
    }
    return errCode;
}

std::string SQLiteSingleVerRelationalStorageExecutor::GetInsertSqlForCloudSync(const TableSchema &tableSchema)
{
    std::string sql = "insert into " + tableSchema.name + "(";
    for (const auto &field : tableSchema.fields) {
        sql += field.colName + ",";
    }
    sql.pop_back();
    sql += ") values(";
    for (size_t i = 0; i < tableSchema.fields.size(); i++) {
        sql += "?,";
    }
    sql.pop_back();
    sql += ");";
    return sql;
}

int SQLiteSingleVerRelationalStorageExecutor::GetPrimaryKeyHashValue(const VBucket &vBucket,
    const TableSchema &tableSchema, std::vector<uint8_t> &hashValue, bool allowEmpty)
{
    int errCode = E_OK;
    TableInfo localTable = localSchema_.GetTable(tableSchema.name);
    // table name in cloud schema is in lower case
    if (!DBCommon::CaseInsensitiveCompare(localTable.GetTableName(), tableSchema.name)) {
        LOGE("localSchema doesn't contain table from cloud");
        return -E_INTERNAL_ERROR;
    }

    std::map<std::string, Field> pkMap = CloudStorageUtils::GetCloudPrimaryKeyFieldMap(tableSchema, true);
    if (pkMap.size() == 0) {
        int64_t rowid = SQLiteUtils::GetLastRowId(dbHandle_);
        std::vector<uint8_t> value;
        DBCommon::StringToVector(std::to_string(rowid), value);
        errCode = DBCommon::CalcValueHash(value, hashValue);
    } else {
        std::tie(errCode, hashValue) = CloudStorageUtils::GetHashValueWithPrimaryKeyMap(vBucket,
            tableSchema, localTable, pkMap, allowEmpty);
    }
    return errCode;
}

int SQLiteSingleVerRelationalStorageExecutor::GetQueryLogStatement(const TableSchema &tableSchema,
    const VBucket &vBucket, const std::string &querySql, const Key &hashKey, sqlite3_stmt *&selectStmt)
{
    int errCode = SQLiteUtils::GetStatement(dbHandle_, querySql, selectStmt);
    if (errCode != E_OK) {
        LOGE("Get select log statement failed, %d", errCode);
        return errCode;
    }

    std::string cloudGid;
    int ret = E_OK;
    errCode = CloudStorageUtils::GetValueFromVBucket(CloudDbConstant::GID_FIELD, vBucket, cloudGid);
    if (putDataMode_ == PutDataMode::SYNC && errCode != E_OK) {
        SQLiteUtils::ResetStatement(selectStmt, true, ret);
        LOGE("Get cloud gid fail when bind query log statement.");
        return errCode;
    }

    int index = 0;
    if (!cloudGid.empty()) {
        index++;
        errCode = SQLiteUtils::BindTextToStatement(selectStmt, index, cloudGid);
        if (errCode != E_OK) {
            LOGE("Bind cloud gid to query log statement failed. %d", errCode);
            SQLiteUtils::ResetStatement(selectStmt, true, errCode);
            return errCode;
        }
    }

    index++;
    errCode = SQLiteUtils::BindBlobToStatement(selectStmt, index, hashKey, true);
    if (errCode != E_OK) {
        LOGE("Bind hash key to query log statement failed. %d", errCode);
        SQLiteUtils::ResetStatement(selectStmt, true, ret);
    }
    return errCode != E_OK ? errCode : ret;
}

int SQLiteSingleVerRelationalStorageExecutor::GetQueryLogSql(const std::string &tableName, const VBucket &vBucket,
    const std::set<std::string> &pkSet, std::string &querySql)
{
    std::string cloudGid;
    int errCode = CloudStorageUtils::GetValueFromVBucket(CloudDbConstant::GID_FIELD, vBucket, cloudGid);
    if (errCode != E_OK) {
        LOGE("Get cloud gid fail when query log table.");
        return errCode;
    }

    if (pkSet.empty() && cloudGid.empty()) {
        LOGE("query log table failed because of both primary key and gid are empty.");
        return -E_CLOUD_ERROR;
    }
    std::string sql = "SELECT data_key, device, ori_device, timestamp, wtimestamp, flag, hash_key, cloud_gid,"
        " sharing_resource, status, version FROM " + std::string(DBConstant::RELATIONAL_PREFIX) + tableName +
        "_log WHERE ";
    if (!cloudGid.empty()) {
        sql += "cloud_gid = ? OR ";
    }
    sql += "hash_key = ?";

    querySql = sql;
    return E_OK;
}

int SQLiteSingleVerRelationalStorageExecutor::ExecutePutCloudData(const std::string &tableName,
    const TableSchema &tableSchema, const TrackerTable &trackerTable, DownloadData &downloadData,
    std::map<int, int> &statisticMap)
{
    int index = 0;
    int errCode = E_OK;
    for (OpType op : downloadData.opType) {
        VBucket &vBucket = downloadData.data[index];
        switch (op) {
            case OpType::INSERT:
                errCode = InsertCloudData(vBucket, tableSchema, trackerTable, GetLocalDataKey(index, downloadData));
                break;
            case OpType::UPDATE:
                errCode = UpdateCloudData(vBucket, tableSchema);
                break;
            case OpType::DELETE:
                errCode = DeleteCloudData(tableName, vBucket, tableSchema, trackerTable);
                break;
            case OpType::ONLY_UPDATE_GID:
            case OpType::SET_CLOUD_FORCE_PUSH_FLAG_ZERO:
            case OpType::SET_CLOUD_FORCE_PUSH_FLAG_ONE:
            case OpType::UPDATE_TIMESTAMP:
            case OpType::CLEAR_GID:
            case OpType::LOCKED_NOT_HANDLE:
                errCode = OnlyUpdateLogTable(vBucket, tableSchema, op);
                [[fallthrough]];
            case OpType::NOT_HANDLE:
                errCode = errCode == E_OK ? OnlyUpdateAssetId(tableName, tableSchema, vBucket,
                    GetLocalDataKey(index, downloadData), op) : errCode;
                break;
            default:
                errCode = -E_CLOUD_ERROR;
                break;
        }
        if (errCode != E_OK) {
            LOGE("put cloud sync data fail: %d", errCode);
            return errCode;
        }
        statisticMap[static_cast<int>(op)]++;
        index++;
    }
    return errCode;
}

int SQLiteSingleVerRelationalStorageExecutor::DoCleanInner(ClearMode mode,
    const std::vector<std::string> &tableNameList, const RelationalSchemaObject &localSchema,
    std::vector<Asset> &assets, std::vector<std::string> &notifyTableList)
{
    int errCode = SetLogTriggerStatus(false);
    if (errCode != E_OK) {
        LOGE("Fail to set log trigger off when clean cloud data, %d", errCode);
        return errCode;
    }
    if (mode == FLAG_ONLY) {
        errCode = DoCleanLogs(tableNameList, localSchema);
        if (errCode != E_OK) {
            LOGE("[Storage Executor] Failed to do clean logs when clean cloud data.");
            return errCode;
        }
        notifyTableList = tableNameList;
    } else if (mode == FLAG_AND_DATA) {
        errCode = DoCleanLogAndData(tableNameList, localSchema, assets);
        if (errCode != E_OK) {
            LOGE("[Storage Executor] Failed to do clean log and data when clean cloud data.");
            return errCode;
        }
        notifyTableList = tableNameList;
    } else if (mode == CLEAR_SHARED_TABLE) {
        errCode = DoCleanShareTableDataAndLog(tableNameList);
        if (errCode != E_OK) {
            LOGE("[Storage Executor] Failed to do clean log and data when clean cloud data.");
            return errCode;
        }
        notifyTableList = tableNameList;
    }
    for (const auto &tableName: tableNameList) {
        errCode = CleanDownloadingFlag(tableName);
        if (errCode != E_OK) {
            LOGE("Fail to clean downloading flag, %d, tableName:%s, length:%zu",
                errCode, DBCommon::StringMiddleMasking(tableName).c_str(), tableName.size());
            return errCode;
        }
    }
    errCode = SetLogTriggerStatus(true);
    if (errCode != E_OK) {
        LOGE("Fail to set log trigger on when clean cloud data, %d", errCode);
    }

    return errCode;
}

int SQLiteSingleVerRelationalStorageExecutor::DoCleanLogs(const std::vector<std::string> &tableNameList,
    const RelationalSchemaObject &localSchema)
{
    int errCode = E_OK;
    int i = 1;
    for (const auto &tableName: tableNameList) {
        std::string logTableName = DBCommon::GetLogTableName(tableName);
        LOGD("[Storage Executor] Start clean cloud data on log table. table index: %d.", i);
        errCode = DoCleanAssetId(tableName, localSchema);
        if (errCode != E_OK) {
            LOGE("[Storage Executor] failed to clean asset id when clean cloud data, %d", errCode);
            return errCode;
        }
        errCode = CleanCloudDataOnLogTable(logTableName, FLAG_ONLY);
        if (errCode != E_OK) {
            LOGE("[Storage Executor] failed to clean cloud data on log table, %d", errCode);
            return errCode;
        }
        i++;
    }

    return errCode;
}

void SQLiteSingleVerRelationalStorageExecutor::UpdateCursor(sqlite3_context *ctx, int argc, sqlite3_value **argv)
{
    if (ctx == nullptr || argc != 0 || argv == nullptr) {
        LOGW("[SqlSinRDBExe][UpdateCursor] invalid param=%d", argc);
        return;
    }
    auto context = static_cast<UpdateCursorContext *>(sqlite3_user_data(ctx));
    if (context == nullptr) {
        LOGW("[SqlSinRDBExe][UpdateCursor] invalid context");
        return;
    }
    context->cursor++;
    sqlite3_result_int64(ctx, static_cast<sqlite3_int64>(context->cursor));
}

int SQLiteSingleVerRelationalStorageExecutor::CreateFuncUpdateCursor(UpdateCursorContext &context,
    void(*updateCursor)(sqlite3_context *ctx, int argc, sqlite3_value **argv)) const
{
    std::string sql = "update_cursor";
    int errCode = sqlite3_create_function_v2(dbHandle_, sql.c_str(), 0, SQLITE_UTF8 | SQLITE_DIRECTONLY,
        &context, updateCursor, nullptr, nullptr, nullptr);
    if (errCode != SQLITE_OK) {
        LOGE("[Storage Executor][UpdateCursor] Create func=updateCursor failed=%d", errCode);
        return SQLiteUtils::MapSQLiteErrno(errCode);
    }
    return E_OK;
}

int SQLiteSingleVerRelationalStorageExecutor::GetCursor(const std::string &tableName, uint64_t &cursor)
{
    return SQLiteRelationalUtils::GetCursor(dbHandle_, tableName, cursor);
}

int SQLiteSingleVerRelationalStorageExecutor::SetCursor(const std::string &tableName, uint64_t cursor)
{
    std::string sql = "UPDATE " + std::string(DBConstant::RELATIONAL_PREFIX) + "metadata SET VALUE = ? where KEY = ?;";
    sqlite3_stmt *stmt = nullptr;
    int errCode = SQLiteUtils::GetStatement(dbHandle_, sql, stmt);
    if (errCode != E_OK) {
        LOGE("Set cursor sql failed=%d", errCode);
        return errCode;
    }
    ResFinalizer finalizer([stmt]() {
        sqlite3_stmt *statement = stmt;
        int ret = E_OK;
        SQLiteUtils::ResetStatement(statement, true, ret);
        if (ret != E_OK) {
            LOGW("Reset stmt failed %d when set cursor", ret);
        }
    });
    int index = 1;
    errCode = SQLiteUtils::BindInt64ToStatement(stmt, index++, cursor);
    if (errCode != E_OK) {
        LOGE("Bind saved cursor failed:%d", errCode);
        return errCode;
    }
    Key key;
    DBCommon::StringToVector(DBCommon::GetCursorKey(tableName), key);
    errCode = SQLiteUtils::BindBlobToStatement(stmt, index, key, false);
    if (errCode != E_OK) {
        return errCode;
    }
    errCode = SQLiteUtils::StepWithRetry(stmt, isMemDb_);
    if (errCode == SQLiteUtils::MapSQLiteErrno(SQLITE_DONE)) {
        errCode = E_OK;
    }
    return errCode;
}

int SQLiteSingleVerRelationalStorageExecutor::DoCleanLogAndData(const std::vector<std::string> &tableNameList,
    const RelationalSchemaObject &localSchema, std::vector<Asset> &assets)
{
    int errCode = E_OK;
    for (size_t i = 0; i < tableNameList.size(); i++) {
        std::string tableName = tableNameList[i];
        std::string logTableName = DBCommon::GetLogTableName(tableName);
        std::vector<int64_t> dataKeys;
        errCode = GetCleanCloudDataKeys(logTableName, dataKeys, true);
        if (errCode != E_OK) {
            LOGE("[Storage Executor] Failed to get clean cloud data keys, %d.", errCode);
            return errCode;
        }

        std::vector<FieldInfo> fieldInfos = localSchema.GetTable(tableName).GetFieldInfos();
        errCode = GetCloudAssets(tableName, fieldInfos, dataKeys, assets);
        if (errCode != E_OK) {
            LOGE("[Storage Executor] failed to get cloud assets when clean cloud data, %d", errCode);
            return errCode;
        }
        if (isLogicDelete_) {
            errCode = SetDataOnUserTableWithLogicDelete(tableName, logTableName);
        } else {
            errCode = CleanCloudDataAndLogOnUserTable(tableName, logTableName, localSchema);
        }
        if (errCode != E_OK) {
            LOGE("[Storage Executor] failed to clean cloud data and log on user table, %d.", errCode);
            return errCode;
        }
    }
    return errCode;
}

int SQLiteSingleVerRelationalStorageExecutor::GetAssetOnTable(const std::string &tableName,
    const std::string &fieldName, const std::vector<int64_t> &dataKeys, std::vector<Asset> &assets)
{
    int errCode = E_OK;
    int ret = E_OK;
    sqlite3_stmt *selectStmt = nullptr;
    for (const auto &rowId : dataKeys) {
        std::string queryAssetSql = "SELECT " + fieldName + " FROM '" + tableName +
            "' WHERE " + std::string(DBConstant::SQLITE_INNER_ROWID) + " = " + std::to_string(rowId) + ";";
        errCode = SQLiteUtils::GetStatement(dbHandle_, queryAssetSql, selectStmt);
        if (errCode != E_OK) { // LCOV_EXCL_BR_LINE
            LOGE("Get select asset statement failed, %d", errCode);
            return errCode;
        }
        errCode = SQLiteUtils::StepWithRetry(selectStmt);
        if (errCode == SQLiteUtils::MapSQLiteErrno(SQLITE_ROW)) { // LCOV_EXCL_BR_LINE
            std::vector<uint8_t> blobValue;
            errCode = SQLiteUtils::GetColumnBlobValue(selectStmt, 0, blobValue);
            if (errCode != E_OK) { // LCOV_EXCL_BR_LINE
                LOGE("Get column blob value failed, %d", errCode);
                goto END;
            }
            if (blobValue.empty()) {
                SQLiteUtils::ResetStatement(selectStmt, true, ret);
                continue;
            }
            Asset asset;
            errCode = RuntimeContext::GetInstance()->BlobToAsset(blobValue, asset);
            if (errCode != E_OK) { // LCOV_EXCL_BR_LINE
                LOGE("Transfer blob to asset failed, %d", errCode);
                goto END;
            }
            assets.push_back(asset);
        } else if (errCode == SQLiteUtils::MapSQLiteErrno(SQLITE_DONE)) {
            errCode = E_OK;
            Asset asset;
            assets.push_back(asset);
        }
        SQLiteUtils::ResetStatement(selectStmt, true, ret);
    }
    return errCode != E_OK ? errCode : ret;
END:
    SQLiteUtils::ResetStatement(selectStmt, true, ret);
    return errCode != E_OK ? errCode : ret;
}

int SQLiteSingleVerRelationalStorageExecutor::GetCloudAssetsOnTable(const std::string &tableName,
    const std::string &fieldName, const std::vector<int64_t> &dataKeys, std::vector<Asset> &assets)
{
    int errCode = E_OK;
    int ret = E_OK;
    sqlite3_stmt *selectStmt = nullptr;
    for (const auto &rowId : dataKeys) {
        std::string queryAssetsSql = "SELECT " + fieldName + " FROM '" + tableName +
            "' WHERE " + std::string(DBConstant::SQLITE_INNER_ROWID) + " = " + std::to_string(rowId) + ";";
        errCode = SQLiteUtils::GetStatement(dbHandle_, queryAssetsSql, selectStmt);
        if (errCode != E_OK) { // LCOV_EXCL_BR_LINE
            LOGE("Get select assets statement failed, %d", errCode);
            goto END;
        }
        errCode = SQLiteUtils::StepWithRetry(selectStmt);
        if (errCode == SQLiteUtils::MapSQLiteErrno(SQLITE_ROW)) { // LCOV_EXCL_BR_LINE
            std::vector<uint8_t> blobValue;
            errCode = SQLiteUtils::GetColumnBlobValue(selectStmt, 0, blobValue);
            if (errCode != E_OK) {
                goto END;
            }
            Assets tmpAssets;
            errCode = RuntimeContext::GetInstance()->BlobToAssets(blobValue, tmpAssets);
            if (errCode != E_OK) { // LCOV_EXCL_BR_LINE
                goto END;
            }
            for (const auto &asset: tmpAssets) {
                assets.push_back(asset);
            }
        } else if (errCode == SQLiteUtils::MapSQLiteErrno(SQLITE_DONE)) {
            errCode = E_OK;
        }
        SQLiteUtils::ResetStatement(selectStmt, true, ret);
    }
    return errCode != E_OK ? errCode : ret;
END:
    SQLiteUtils::ResetStatement(selectStmt, true, ret);
    return errCode != E_OK ? errCode : ret;
}

int SQLiteSingleVerRelationalStorageExecutor::GetCloudAssets(const std::string &tableName,
    const std::vector<FieldInfo> &fieldInfos, const std::vector<int64_t> &dataKeys, std::vector<Asset> &assets)
{
    int errCode = E_OK;
    for (const auto &fieldInfo: fieldInfos) {
        if (fieldInfo.IsAssetType()) {
            errCode = GetAssetOnTable(tableName, fieldInfo.GetFieldName(), dataKeys, assets);
            if (errCode != E_OK) {
                LOGE("[Storage Executor] failed to get cloud asset on table, %d.", errCode);
                return errCode;
            }
        } else if (fieldInfo.IsAssetsType()) {
            errCode = GetCloudAssetsOnTable(tableName, fieldInfo.GetFieldName(), dataKeys, assets);
            if (errCode != E_OK) {
                LOGE("[Storage Executor] failed to get cloud assets on table, %d.", errCode);
                return errCode;
            }
        }
    }
    return errCode;
}

int SQLiteSingleVerRelationalStorageExecutor::SetCursorIncFlag(bool flag)
{
    std::string sql = "INSERT OR REPLACE INTO " + std::string(DBConstant::RELATIONAL_PREFIX) + "metadata" +
        " VALUES ('cursor_inc_flag', ";
    if (flag) {
        sql += "'true'";
    } else {
        sql += "'false'";
    }
    sql += ");";
    int errCode = SQLiteUtils::ExecuteRawSQL(dbHandle_, sql);
    if (errCode != E_OK) {
        LOGE("set cursor inc flag fail, errCode = %d", errCode);
    }
    return errCode;
}

int SQLiteSingleVerRelationalStorageExecutor::PutCloudSyncData(const std::string &tableName,
    const TableSchema &tableSchema, const TrackerTable &trackerTable, DownloadData &downloadData)
{
    if (downloadData.data.size() != downloadData.opType.size()) {
        LOGE("put cloud data, data size = %zu, flag size = %zu.", downloadData.data.size(),
             downloadData.opType.size());
        return -E_CLOUD_ERROR;
    }

    int errCode = SetLogTriggerStatus(false);
    if (errCode != E_OK) {
        LOGE("Fail to set log trigger off, %d", errCode);
        return errCode;
    }

    std::map<int, int> statisticMap = {};
    errCode = ExecutePutCloudData(tableName, tableSchema, trackerTable, downloadData, statisticMap);
    int ret = SetLogTriggerStatus(true);
    if (ret != E_OK) {
        LOGE("Fail to set log trigger on, %d", ret);
    }
    LOGI("save cloud data:%d, ins:%d, upd:%d, del:%d, only gid:%d, flag zero:%d, flag one:%d, upd timestamp:%d,"
         "clear gid:%d, not handle:%d, lock:%d",
         errCode, statisticMap[static_cast<int>(OpType::INSERT)], statisticMap[static_cast<int>(OpType::UPDATE)],
         statisticMap[static_cast<int>(OpType::DELETE)], statisticMap[static_cast<int>(OpType::ONLY_UPDATE_GID)],
         statisticMap[static_cast<int>(OpType::SET_CLOUD_FORCE_PUSH_FLAG_ZERO)],
         statisticMap[static_cast<int>(OpType::SET_CLOUD_FORCE_PUSH_FLAG_ONE)],
         statisticMap[static_cast<int>(OpType::UPDATE_TIMESTAMP)], statisticMap[static_cast<int>(OpType::CLEAR_GID)],
         statisticMap[static_cast<int>(OpType::NOT_HANDLE)], statisticMap[static_cast<int>(OpType::LOCKED_NOT_HANDLE)]);
    return errCode == E_OK ? ret : errCode;
}

int SQLiteSingleVerRelationalStorageExecutor::UpdateAssetStatusForAssetOnly(
    const TableSchema &tableSchema, VBucket &vBucket)
{
    std::string cloudGid;
    int errCode = CloudStorageUtils::GetValueFromVBucket(CloudDbConstant::GID_FIELD, vBucket, cloudGid);
    if (errCode != E_OK) {
        LOGE("Miss gid when fill Asset %d.", errCode);
        return errCode;
    }
    std::vector<Field> assetsField;
    errCode = CloudStorageUtils::GetAssetFieldsFromSchema(tableSchema, vBucket, assetsField);
    if (errCode != E_OK) {
        LOGE("No assets need to be filled when download assets only, err:%d.", errCode);
        return errCode;
    }

    sqlite3_stmt *stmt = nullptr;
    errCode = GetFillDownloadAssetStatement(tableSchema.name, vBucket, assetsField, stmt);
    if (errCode != E_OK) {
        LOGE("can not get assetsField from tableSchema:%s err:%d when download assets only.",
            tableSchema.name.c_str(), errCode);
        return errCode;
    }
    return ExecuteFillDownloadAssetStatement(stmt, assetsField.size() + 1, cloudGid);
}

int SQLiteSingleVerRelationalStorageExecutor::InsertCloudData(VBucket &vBucket, const TableSchema &tableSchema,
    const TrackerTable &trackerTable, int64_t dataKey)
{
    int errCode = E_OK;
    if (dataKey > 0) {
        errCode = RemoveDataAndLog(tableSchema.name, dataKey);
        if (errCode != E_OK) {
            return errCode;
        }
    }
    std::string sql = GetInsertSqlForCloudSync(tableSchema);
    sqlite3_stmt *insertStmt = nullptr;
    errCode = SQLiteUtils::GetStatement(dbHandle_, sql, insertStmt);
    if (errCode != E_OK) {
        LOGE("Get insert statement failed when save cloud data, %d", errCode);
        return errCode;
    }
    if (putDataMode_ == PutDataMode::SYNC) {
        CloudStorageUtils::PrepareToFillAssetFromVBucket(vBucket, CloudStorageUtils::FillAssetBeforeDownload);
    }
    errCode = BindValueToUpsertStatement(vBucket, tableSchema.fields, insertStmt);
    if (errCode != E_OK) {
        SQLiteUtils::ResetStatement(insertStmt, true, errCode);
        return errCode;
    }
    // insert data
    errCode = SQLiteUtils::StepWithRetry(insertStmt, false);
    int ret = E_OK;
    SQLiteUtils::ResetStatement(insertStmt, true, ret);
    if (errCode != SQLiteUtils::MapSQLiteErrno(SQLITE_DONE)) {
        LOGE("insert data failed when save cloud data:%d, reset stmt:%d", errCode, ret);
        return errCode;
    }

    // insert log
    return InsertLogRecord(tableSchema, trackerTable, vBucket);
}

std::string GetInsertLogSql(const std::string &logTableName, const std::set<std::string> &extendColNames)
{
    if (extendColNames.empty()) {
        return "INSERT OR REPLACE INTO " + logTableName + " VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, " +
            "CASE WHEN (SELECT status FROM " + logTableName + " WHERE hash_key=?) IS NULL THEN 0 ELSE " +
            "(SELECT status FROM " + logTableName + " WHERE hash_key=?) " + "END)";
    }
    std::string sql = "INSERT OR REPLACE INTO " + logTableName + " VALUES(?, ?, ?, ?, ?, ?, ?, ?, json_object(";
    for (const auto &extendColName : extendColNames) {
        sql += "'" + extendColName + "',?,";
    }
    sql.pop_back();
    sql += "), 0, ?, ?, CASE WHEN (SELECT status FROM " + logTableName +
        " WHERE hash_key=?) IS NULL THEN 0 ELSE " + "(SELECT status FROM " + logTableName +
        " WHERE hash_key=?) " + "END)";
    return sql;
}

int SQLiteSingleVerRelationalStorageExecutor::InsertLogRecord(const TableSchema &tableSchema,
    const TrackerTable &trackerTable, VBucket &vBucket)
{
    if (putDataMode_ == PutDataMode::SYNC && !CloudStorageUtils::IsContainsPrimaryKey(tableSchema)) {
        // when one data is deleted, "insert or replace" will insert another log record if there is no primary key,
        // so we need to delete the old log record according to the gid first
        std::string gidStr;
        int errCode = CloudStorageUtils::GetValueFromVBucket(CloudDbConstant::GID_FIELD, vBucket, gidStr);
        if (errCode != E_OK || gidStr.empty()) {
            LOGE("Get gid from bucket fail when delete log with no primary key or gid is empty, errCode = %d", errCode);
            return errCode;
        }
        std::string sql = "DELETE FROM " + DBCommon::GetLogTableName(tableSchema.name) + " WHERE cloud_gid = '"
            + gidStr + "';";
        errCode = SQLiteUtils::ExecuteRawSQL(dbHandle_, sql);
        if (errCode != E_OK) {
            LOGE("delete log record according gid fail, errCode = %d", errCode);
            return errCode;
        }
    }

    std::string sql = GetInsertLogSql(DBCommon::GetLogTableName(tableSchema.name), trackerTable.GetExtendNames());
    sqlite3_stmt *insertLogStmt = nullptr;
    int errCode = SQLiteUtils::GetStatement(dbHandle_, sql, insertLogStmt);
    if (errCode != E_OK) {
        LOGE("Get insert log statement failed when save cloud data, %d", errCode);
        return errCode;
    }

    errCode = BindValueToInsertLogStatement(vBucket, tableSchema, trackerTable, insertLogStmt);
    if (errCode != E_OK) {
        SQLiteUtils::ResetStatement(insertLogStmt, true, errCode);
        return errCode;
    }

    errCode = SQLiteUtils::StepWithRetry(insertLogStmt, false);
    int ret = E_OK;
    SQLiteUtils::ResetStatement(insertLogStmt, true, ret);
    if (errCode == SQLiteUtils::MapSQLiteErrno(SQLITE_DONE)) {
        return ret;
    } else {
        LOGE("insert log data failed when save cloud data:%d, reset stmt:%d", errCode, ret);
        return errCode;
    }
}

int SQLiteSingleVerRelationalStorageExecutor::BindOneField(int index, const VBucket &vBucket, const Field &field,
    sqlite3_stmt *updateStmt)
{
    auto it = bindCloudFieldFuncMap_.find(field.type);
    if (it == bindCloudFieldFuncMap_.end()) {
        LOGE("unknown cloud type when bind one field.");
        return -E_CLOUD_ERROR;
    }
    return it->second(index, vBucket, field, updateStmt);
}

int SQLiteSingleVerRelationalStorageExecutor::BindValueToUpsertStatement(const VBucket &vBucket,
    const std::vector<Field> &fields, sqlite3_stmt *upsertStmt)
{
    int errCode = E_OK;
    int index = 0;
    for (const auto &field : fields) {
        index++;
        errCode = BindOneField(index, vBucket, field, upsertStmt);
        if (errCode != E_OK) {
            return errCode;
        }
    }
    return errCode;
}

int SQLiteSingleVerRelationalStorageExecutor::BindStatusSubQueryHashKeyStatement(sqlite3_stmt *insertLogStmt,
    std::vector<uint8_t> &hashKey, int &index)
{
    int errCode = SQLiteUtils::BindBlobToStatement(insertLogStmt, index++, hashKey); // next is hash_key
    if (errCode != E_OK) {
        LOGE("Bind hash_key to status subQuery statement failed, %d", errCode);
        return errCode;
    }

    errCode = SQLiteUtils::BindBlobToStatement(insertLogStmt, index++, hashKey); // next is hash_key
    if (errCode != E_OK) {
        LOGE("Bind hash_key to status subQuery2 statement failed, %d", errCode);
        return errCode;
    }
    return errCode;
}

int BindExtendValue(const VBucket &vBucket, const TrackerTable &trackerTable, sqlite3_stmt *stmt, int &index)
{
    const std::set<std::string> &extendColNames = trackerTable.GetExtendNames();
    int errCode = E_OK;
    int extendValueIndex = index;
    if (extendColNames.empty()) {
        return SQLiteUtils::BindTextToStatement(stmt, index++, "");
    }
    for (const auto &extendColName : extendColNames) {
        if (vBucket.find(extendColName) == vBucket.end()) {
            errCode = SQLiteUtils::BindTextToStatement(stmt, extendValueIndex++, "");
        } else {
            Type extendValue = vBucket.at(extendColName);
            errCode = SQLiteRelationalUtils::BindStatementByType(stmt, extendValueIndex++, extendValue);
        }
        if (errCode != E_OK) {
            const char *tableName = DBCommon::StringMiddleMasking(trackerTable.GetTableName()).c_str();
            size_t nameLength = trackerTable.GetTableName().size();
            LOGE("[%s [%zu]] Bind extend field failed: %d", tableName, nameLength, errCode);
            return errCode;
        }
    }
    index = extendValueIndex;
    return E_OK;
}

int SQLiteSingleVerRelationalStorageExecutor::BindHashKeyAndGidToInsertLogStatement(const VBucket &vBucket,
    const TableSchema &tableSchema, const TrackerTable &trackerTable, sqlite3_stmt *insertLogStmt, int &index)
{
    std::vector<uint8_t> hashKey;
    int errCode = GetPrimaryKeyHashValue(vBucket, tableSchema, hashKey);
    if (errCode != E_OK) {
        return errCode;
    }
    errCode = SQLiteUtils::BindBlobToStatement(insertLogStmt, index++, hashKey); // next is hash_key
    if (errCode != E_OK) {
        LOGE("Bind hash_key to insert log statement failed, %d", errCode);
        return errCode;
    }

    std::string cloudGid;
    if (putDataMode_ == PutDataMode::SYNC) {
        errCode = CloudStorageUtils::GetValueFromVBucket<std::string>(CloudDbConstant::GID_FIELD, vBucket, cloudGid);
        if (errCode != E_OK) {
            LOGE("get gid for insert log statement failed, %d", errCode);
            return -E_CLOUD_ERROR;
        }
    }

    errCode = SQLiteUtils::BindTextToStatement(insertLogStmt, index++, cloudGid); // next is cloud_gid
    if (errCode != E_OK) {
        LOGE("Bind cloud_gid to insert log statement failed, %d", errCode);
        return errCode;
    }

    errCode = BindExtendValue(vBucket, trackerTable, insertLogStmt, index); // next is extend_field
    if (errCode != E_OK) {
        LOGE("Bind extend_field to insert log statement failed, %d", errCode);
        return errCode;
    }

    errCode = BindShareValueToInsertLogStatement(vBucket, tableSchema, insertLogStmt, index);
    if (errCode != E_OK) {
        return errCode;
    }
    return BindStatusSubQueryHashKeyStatement(insertLogStmt, hashKey, index);
}

int SQLiteSingleVerRelationalStorageExecutor::BindValueToInsertLogStatement(VBucket &vBucket,
    const TableSchema &tableSchema, const TrackerTable &trackerTable, sqlite3_stmt *insertLogStmt)
{
    int64_t rowid = SQLiteUtils::GetLastRowId(dbHandle_);
    int bindIndex = 1; // 1 is rowid
    int errCode = SQLiteUtils::BindInt64ToStatement(insertLogStmt, bindIndex++, rowid);
    if (errCode != E_OK) {
        LOGE("Bind rowid to insert log statement failed, %d", errCode);
        return errCode;
    }

    errCode = SQLiteUtils::BindTextToStatement(insertLogStmt, bindIndex++, GetDev()); // next is device
    if (errCode != E_OK) {
        LOGE("Bind device to insert log statement failed, %d", errCode);
        return errCode;
    }

    errCode = SQLiteUtils::BindTextToStatement(insertLogStmt, bindIndex++, GetDev()); // next is ori_device
    if (errCode != E_OK) {
        LOGE("Bind ori_device to insert log statement failed, %d", errCode);
        return errCode;
    }

    int64_t val = 0;
    errCode = CloudStorageUtils::GetValueFromVBucket<int64_t>(CloudDbConstant::MODIFY_FIELD, vBucket, val);
    if (errCode != E_OK) {
        LOGE("get modify time for insert log statement failed, %d", errCode);
        return -E_CLOUD_ERROR;
    }

    errCode = SQLiteUtils::BindInt64ToStatement(insertLogStmt, bindIndex++, val); // next is timestamp
    if (errCode != E_OK) {
        LOGE("Bind timestamp to insert log statement failed, %d", errCode);
        return errCode;
    }

    errCode = CloudStorageUtils::GetValueFromVBucket<int64_t>(CloudDbConstant::CREATE_FIELD, vBucket, val);
    if (errCode != E_OK) {
        LOGE("get create time for insert log statement failed, %d", errCode);
        return -E_CLOUD_ERROR;
    }

    errCode = SQLiteUtils::BindInt64ToStatement(insertLogStmt, bindIndex++, val); // next is wtimestamp
    if (errCode != E_OK) {
        LOGE("Bind wtimestamp to insert log statement failed, %d", errCode);
        return errCode;
    }

    errCode = SQLiteUtils::MapSQLiteErrno(sqlite3_bind_int(insertLogStmt, bindIndex++, GetDataFlag())); // next is flag
    if (errCode != E_OK) {
        LOGE("Bind flag to insert log statement failed, %d", errCode);
        return errCode;
    }

    vBucket[CloudDbConstant::ROW_ID_FIELD_NAME] = rowid; // fill rowid to cloud data to notify user
    return BindHashKeyAndGidToInsertLogStatement(vBucket, tableSchema, trackerTable, insertLogStmt, bindIndex);
}

std::string SQLiteSingleVerRelationalStorageExecutor::GetWhereConditionForDataTable(const std::string &gidStr,
    const std::set<std::string> &pkSet, const std::string &tableName, bool queryByPk)
{
    std::string where = " WHERE";
    if (!gidStr.empty()) { // gid has higher priority, because primary key may be modified
        where += " " + std::string(DBConstant::SQLITE_INNER_ROWID) + " = (SELECT data_key FROM " +
            DBCommon::GetLogTableName(tableName) + " WHERE cloud_gid = '" + gidStr + "')";
    }
    if (!pkSet.empty() && queryByPk) {
        if (!gidStr.empty()) {
            where += " OR";
        }
        where += " (1 = 1";
        for (const auto &pk : pkSet) {
            where += (" AND " + pk + " = ?");
        }
        where += ");";
    }
    return where;
}

int SQLiteSingleVerRelationalStorageExecutor::GetUpdateSqlForCloudSync(const std::vector<Field> &updateFields,
    const TableSchema &tableSchema, const std::string &gidStr, const std::set<std::string> &pkSet,
    std::string &updateSql)
{
    if (pkSet.empty() && gidStr.empty()) {
        LOGE("update data fail because both primary key and gid is empty.");
        return -E_CLOUD_ERROR;
    }
    std::string sql = "UPDATE " + tableSchema.name + " SET";
    for (const auto &field : updateFields) {
        sql +=  " " + field.colName + " = ?,";
    }
    sql.pop_back();
    sql += GetWhereConditionForDataTable(gidStr, pkSet, tableSchema.name);
    updateSql = sql;
    return E_OK;
}

static inline bool IsGidValid(const std::string &gidStr)
{
    if (!gidStr.empty()) {
        return gidStr.find("'") == std::string::npos;
    }
    return true;
}

int SQLiteSingleVerRelationalStorageExecutor::GetUpdateDataTableStatement(const VBucket &vBucket,
    const TableSchema &tableSchema, sqlite3_stmt *&updateStmt)
{
    std::string gidStr;
    int errCode = CloudStorageUtils::GetValueFromVBucket(CloudDbConstant::GID_FIELD, vBucket, gidStr);
    if (errCode != E_OK) {
        LOGE("Get gid from cloud data fail when construct update data sql, errCode = %d", errCode);
        return errCode;
    }
    if (!IsGidValid(gidStr)) {
        LOGE("invalid char in cloud gid");
        return -E_CLOUD_ERROR;
    }

    std::set<std::string> pkSet = CloudStorageUtils::GetCloudPrimaryKey(tableSchema);
    auto updateFields = GetUpdateField(vBucket, tableSchema);
    std::string updateSql;
    errCode = GetUpdateSqlForCloudSync(updateFields, tableSchema, gidStr, pkSet, updateSql);
    if (errCode != E_OK) {
        return errCode;
    }

    errCode = SQLiteUtils::GetStatement(dbHandle_, updateSql, updateStmt);
    if (errCode != E_OK) {
        LOGE("Get update statement failed when update cloud data, %d", errCode);
        return errCode;
    }

    // bind value
    if (!pkSet.empty()) {
        std::vector<Field> pkFields = CloudStorageUtils::GetCloudPrimaryKeyField(tableSchema, true);
        updateFields.insert(updateFields.end(), pkFields.begin(), pkFields.end());
    }
    errCode = BindValueToUpsertStatement(vBucket, updateFields, updateStmt);
    if (errCode != E_OK) {
        LOGE("bind value to update statement failed when update cloud data, %d", errCode);
        SQLiteUtils::ResetStatement(updateStmt, true, errCode);
    }
    return errCode;
}

int SQLiteSingleVerRelationalStorageExecutor::UpdateCloudData(VBucket &vBucket, const TableSchema &tableSchema)
{
    if (putDataMode_ == PutDataMode::SYNC) {
        CloudStorageUtils::PrepareToFillAssetFromVBucket(vBucket, CloudStorageUtils::FillAssetBeforeDownload);
    }
    sqlite3_stmt *updateStmt = nullptr;
    int errCode = GetUpdateDataTableStatement(vBucket, tableSchema, updateStmt);
    if (errCode != E_OK) {
        LOGE("Get update data table statement fail, %d", errCode);
        return errCode;
    }

    // update data
    errCode = SQLiteUtils::StepWithRetry(updateStmt, false);
    if (errCode == SQLiteUtils::MapSQLiteErrno(SQLITE_DONE)) {
        errCode = E_OK;
    } else {
        LOGE("update data failed when save cloud data:%d", errCode);
        SQLiteUtils::ResetStatement(updateStmt, true, errCode);
        return errCode;
    }
    SQLiteUtils::ResetStatement(updateStmt, true, errCode);

    // update log
    errCode = UpdateLogRecord(vBucket, tableSchema, OpType::UPDATE);
    if (errCode != E_OK) {
        LOGE("update log record failed when update cloud data, errCode = %d", errCode);
    }
    return errCode;
}

static inline bool IsAllowWithPrimaryKey(OpType opType)
{
    return (opType == OpType::DELETE || opType == OpType::UPDATE_TIMESTAMP || opType == OpType::CLEAR_GID ||
        opType == OpType::ONLY_UPDATE_GID || opType == OpType::LOCKED_NOT_HANDLE);
}

int SQLiteSingleVerRelationalStorageExecutor::UpdateLogRecord(const VBucket &vBucket, const TableSchema &tableSchema,
    OpType opType)
{
    sqlite3_stmt *updateLogStmt = nullptr;
    std::vector<std::string> updateColName;
    int errCode = GetUpdateLogRecordStatement(tableSchema, vBucket, opType, updateColName, updateLogStmt);
    if (errCode != E_OK) {
        LOGE("Get update log statement failed, errCode = %d", errCode);
        return errCode;
    }

    errCode = BindValueToUpdateLogStatement(vBucket, tableSchema, updateColName, IsAllowWithPrimaryKey(opType),
        updateLogStmt);
    int ret = E_OK;
    if (errCode != E_OK) {
        LOGE("bind value to update log statement failed when update cloud data, %d", errCode);
        SQLiteUtils::ResetStatement(updateLogStmt, true, ret);
        return errCode != E_OK ? errCode : ret;
    }

    errCode = SQLiteUtils::StepWithRetry(updateLogStmt, false);
    if (errCode == SQLiteUtils::MapSQLiteErrno(SQLITE_DONE)) {
        errCode = E_OK;
    } else {
        LOGE("update log record failed when update cloud data:%d", errCode);
    }
    SQLiteUtils::ResetStatement(updateLogStmt, true, ret);
    return errCode != E_OK ? errCode : ret;
}

int SQLiteSingleVerRelationalStorageExecutor::BindValueToUpdateLogStatement(const VBucket &vBucket,
    const TableSchema &tableSchema, const std::vector<std::string> &colNames, bool allowPrimaryKeyEmpty,
    sqlite3_stmt *updateLogStmt)
{
    int errCode = CloudStorageUtils::BindUpdateLogStmtFromVBucket(vBucket, tableSchema, colNames, updateLogStmt);
    if (errCode != E_OK) {
        return errCode;
    }
    std::map<std::string, Field> pkMap = CloudStorageUtils::GetCloudPrimaryKeyFieldMap(tableSchema);
    if (pkMap.empty()) {
        return E_OK;
    }

    std::vector<uint8_t> hashKey;
    errCode = GetPrimaryKeyHashValue(vBucket, tableSchema, hashKey, allowPrimaryKeyEmpty);
    if (errCode != E_OK) {
        return errCode;
    }
    return SQLiteUtils::BindBlobToStatement(updateLogStmt, colNames.size() + 1, hashKey);
}

int SQLiteSingleVerRelationalStorageExecutor::GetDeleteStatementForCloudSync(const TableSchema &tableSchema,
    const std::set<std::string> &pkSet, const VBucket &vBucket, sqlite3_stmt *&deleteStmt)
{
    std::string gidStr;
    int errCode = CloudStorageUtils::GetValueFromVBucket(CloudDbConstant::GID_FIELD, vBucket, gidStr);
    if (errCode != E_OK) {
        LOGE("Get gid from cloud data fail when construct delete sql, errCode = %d", errCode);
        return errCode;
    }
    if (gidStr.empty() || gidStr.find("'") != std::string::npos) {
        LOGE("empty or invalid char in cloud gid");
        return -E_CLOUD_ERROR;
    }

    bool queryByPk = CloudStorageUtils::IsVbucketContainsAllPK(vBucket, pkSet);
    std::string deleteSql = "DELETE FROM " + tableSchema.name;
    deleteSql += GetWhereConditionForDataTable(gidStr, pkSet, tableSchema.name, queryByPk);
    errCode = SQLiteUtils::GetStatement(dbHandle_, deleteSql, deleteStmt);
    if (errCode != E_OK) {
        LOGE("Get delete statement failed when delete data, %d", errCode);
        return errCode;
    }

    int ret = E_OK;
    if (!pkSet.empty() && queryByPk) {
        std::vector<Field> pkFields = CloudStorageUtils::GetCloudPrimaryKeyField(tableSchema, true);
        errCode = BindValueToUpsertStatement(vBucket, pkFields, deleteStmt);
        if (errCode != E_OK) {
            LOGE("bind value to delete statement failed when delete cloud data, %d", errCode);
            SQLiteUtils::ResetStatement(deleteStmt, true, ret);
        }
    }
    return errCode != E_OK ? errCode : ret;
}

int SQLiteSingleVerRelationalStorageExecutor::DeleteCloudData(const std::string &tableName, const VBucket &vBucket,
    const TableSchema &tableSchema, const TrackerTable &trackerTable)
{
    if (isLogicDelete_) {
        return LogicDeleteCloudData(tableName, vBucket, tableSchema, trackerTable);
    }
    std::set<std::string> pkSet = CloudStorageUtils::GetCloudPrimaryKey(tableSchema);
    sqlite3_stmt *deleteStmt = nullptr;
    int errCode = GetDeleteStatementForCloudSync(tableSchema, pkSet, vBucket, deleteStmt);
    if (errCode != E_OK) {
        return errCode;
    }
    errCode = SQLiteUtils::StepWithRetry(deleteStmt, false);
    int ret = E_OK;
    SQLiteUtils::ResetStatement(deleteStmt, true, ret);
    if (errCode != SQLiteUtils::MapSQLiteErrno(SQLITE_DONE)) {
        LOGE("delete data failed when sync with cloud:%d", errCode);
        return errCode;
    }
    if (ret != E_OK) {
        LOGE("reset delete statement failed:%d", ret);
        return ret;
    }

    // update log
    errCode = UpdateLogRecord(vBucket, tableSchema, OpType::DELETE);
    if (errCode != E_OK) {
        LOGE("update log record failed when delete cloud data, errCode = %d", errCode);
    }
    return errCode;
}

int SQLiteSingleVerRelationalStorageExecutor::OnlyUpdateLogTable(const VBucket &vBucket,
    const TableSchema &tableSchema, OpType opType)
{
    return UpdateLogRecord(vBucket, tableSchema, opType);
}

int SQLiteSingleVerRelationalStorageExecutor::DeleteTableTrigger(const std::string &missTable) const
{
    static const char *triggerEndName[] = {
        "_ON_INSERT",
        "_ON_UPDATE",
        "_ON_DELETE"
    };
    std::string logTableName = DBConstant::SYSTEM_TABLE_PREFIX + missTable;
    for (const auto &endName : triggerEndName) {
        std::string deleteSql = "DROP TRIGGER IF EXISTS " + logTableName + endName + ";";
        int errCode = SQLiteUtils::ExecuteRawSQL(dbHandle_, deleteSql);
        if (errCode != E_OK) {
            LOGE("[DeleteTableTrigger] Drop trigger failed. %d", errCode);
            return errCode;
        }
    }
    return E_OK;
}

void SQLiteSingleVerRelationalStorageExecutor::SetLogicDelete(bool isLogicDelete)
{
    isLogicDelete_ = isLogicDelete;
}

int SQLiteSingleVerRelationalStorageExecutor::UpdateRecordStatus(const std::string &tableName,
    const std::string &status, const Key &hashKey)
{
    std::string sql = "UPDATE " + DBCommon::GetLogTableName(tableName) + " SET " + status + " WHERE hash_key = ?;";
    sqlite3_stmt *stmt = nullptr;
    int errCode = SQLiteUtils::GetStatement(dbHandle_, sql, stmt);
    if (errCode != E_OK) {
        LOGE("[Storage Executor] Get stmt failed when update record status, %d", errCode);
        return errCode;
    }
    int ret = E_OK;
    errCode = SQLiteUtils::BindBlobToStatement(stmt, 1, hashKey); // 1 is bind index of hashKey
    if (errCode != E_OK) {
        LOGE("[Storage Executor] Bind hashKey to update record status stmt failed, %d", errCode);
        SQLiteUtils::ResetStatement(stmt, true, ret);
        return errCode;
    }
    errCode = SQLiteUtils::StepWithRetry(stmt);
    if (errCode == SQLiteUtils::MapSQLiteErrno(SQLITE_DONE)) {
        errCode = E_OK;
    } else {
        LOGE("[Storage Executor]Step update record status stmt failed, %d", errCode);
    }
    SQLiteUtils::ResetStatement(stmt, true, ret);
    return errCode == E_OK ? ret : errCode;
}

void SQLiteSingleVerRelationalStorageExecutor::SetUploadConfig(int32_t maxUploadCount, int32_t maxUploadSize)
{
    maxUploadCount_ = maxUploadCount;
    maxUploadSize_ = maxUploadSize;
}

int SQLiteSingleVerRelationalStorageExecutor::LogicDeleteCloudData(const std::string &tableName, const VBucket &vBucket,
    const TableSchema &tableSchema, const TrackerTable &trackerTable)
{
    LOGD("[RDBExecutor] logic delete skip delete data");
    int errCode = SQLiteUtils::ExecuteRawSQL(dbHandle_, CloudStorageUtils::GetCursorIncSql(tableName));
    if (errCode != E_OK) {
        return errCode;
    }
    errCode = UpdateLogRecord(vBucket, tableSchema, OpType::DELETE);
    if (errCode != E_OK) {
        return errCode;
    }
    if (!trackerTable.IsEmpty()) {
        return SQLiteRelationalUtils::SelectServerObserver(dbHandle_, tableName, true);
    }
    return E_OK;
}

int SQLiteSingleVerRelationalStorageExecutor::InitCursorToMeta(const std::string &tableName)
{
    Value key;
    Value cursor;
    DBCommon::StringToVector(DBCommon::GetCursorKey(tableName), key);
    int errCode = GetKvData(key, cursor);
    if (errCode == -E_NOT_FOUND) {
        DBCommon::StringToVector(std::string("0"), cursor);
        errCode = PutKvData(key, cursor);
        if (errCode != E_OK) {
            LOGE("Init cursor to meta table failed. %d", errCode);
        }
        return errCode;
    }
    if (errCode != E_OK) {
        LOGE("Get cursor from meta table failed. %d", errCode);
    }
    return errCode;
}

void SQLiteSingleVerRelationalStorageExecutor::SetTableSchema(const TableSchema &tableSchema)
{
    tableSchema_ = tableSchema;
}

int SQLiteSingleVerRelationalStorageExecutor::ReviseLocalModTime(const std::string &tableName,
    const std::vector<ReviseModTimeInfo> &revisedData)
{
    sqlite3_stmt *stmt = nullptr;
    std::string sql = "UPDATE " + DBCommon::GetLogTableName(tableName) +
        " SET timestamp=? where hash_key=? AND timestamp=?";
    int errCode = SQLiteUtils::GetStatement(dbHandle_, sql, stmt);
    if (errCode != E_OK) {
        LOGE("[RDBExecutor][ReviseLocalModTime] Get stmt failed: %d", errCode);
        return errCode;
    }
    ResFinalizer finalizer([stmt]() {
        sqlite3_stmt *statement = stmt;
        int ret = E_OK;
        SQLiteUtils::ResetStatement(statement, true, ret);
        if (ret != E_OK) {
            LOGW("[RDBExecutor][ReviseLocalModTime] Reset stmt failed %d", ret);
        }
    });
    for (auto &data : revisedData) {
        int resetCode = E_OK;
        errCode = SQLiteUtils::BindInt64ToStatement(stmt, 1, data.curTime); // 1st bind modify time
        if (errCode != E_OK) {
            LOGE("[RDBExecutor][ReviseLocalModTime] Bind revised modify time failed: %d", errCode);
            return errCode;
        }
        errCode = SQLiteUtils::BindBlobToStatement(stmt, 2, data.hashKey); // 2nd bind hash key
        if (errCode != E_OK) {
            LOGE("[RDBExecutor][ReviseLocalModTime] Bind hash key failed: %d", errCode);
            return errCode;
        }
        errCode = SQLiteUtils::BindInt64ToStatement(stmt, 3, data.invalidTime); // 3rd bind modify time
        if (errCode != E_OK) {
            LOGE("[RDBExecutor][ReviseLocalModTime] Bind modify time failed: %d", errCode);
            return errCode;
        }
        errCode = SQLiteUtils::StepWithRetry(stmt);
        if (errCode != SQLiteUtils::MapSQLiteErrno(SQLITE_DONE)) {
            LOGE("[RDBExecutor][ReviseLocalModTime] Revise failed: %d", errCode);
            return errCode;
        }
        LOGI("[RDBExecutor][ReviseLocalModTime] Local data mod time revised from %lld to %lld",
            data.invalidTime, data.curTime);
        SQLiteUtils::ResetStatement(stmt, false, resetCode);
        if (resetCode != E_OK) {
            LOGW("[RDBExecutor][ReviseLocalModTime] Reset stmt failed: %d", resetCode);
            return resetCode;
        }
    }
    return E_OK;
}

bool SQLiteSingleVerRelationalStorageExecutor::IsNeedUpdateAssetIdInner(sqlite3_stmt *selectStmt,
    const VBucket &vBucket, const Field &field, VBucket &assetInfo, bool &isNotIncCursor)
{
    if (field.type == TYPE_INDEX<Asset>) {
        Asset asset;
        UpdateLocalAssetId(vBucket, field.colName, asset);
        Asset *assetDBPtr = std::get_if<Asset>(&assetInfo[field.colName]);
        if (assetDBPtr == nullptr) {
            isNotIncCursor = true;
            return true;
        }
        const Asset &assetDB = *assetDBPtr;
        if (assetDB.assetId != asset.assetId || asset.status != AssetStatus::NORMAL) {
            isNotIncCursor = true;
            return true;
        }
    }
    if (field.type == TYPE_INDEX<Assets>) {
        Assets assets;
        UpdateLocalAssetsId(vBucket, field.colName, assets);
        Assets *assetsDBPtr = std::get_if<Assets>(&assetInfo[field.colName]);
        if (assetsDBPtr == nullptr) {
            isNotIncCursor = true;
            return true;
        }
        Assets &assetsDB = *assetsDBPtr;
        if (assets.size() != assetsDB.size()) {
            isNotIncCursor = true;
            return true;
        }
        for (uint32_t i = 0; i < assets.size(); ++i) {
            if (assets[i].assetId != assetsDB[i].assetId || assets[i].status != AssetStatus::NORMAL) {
                isNotIncCursor = true;
                return true;
            }
        }
    }
    return false;
}

bool SQLiteSingleVerRelationalStorageExecutor::IsNeedUpdateAssetId(const TableSchema &tableSchema, int64_t dataKey,
    const VBucket &vBucket, bool &isNotIncCursor)
{
    std::vector<Field> assetFields;
    for (const auto &field : tableSchema.fields) {
        if (field.type == TYPE_INDEX<Asset>) {
            assetFields.push_back(field);
        }
        if (field.type == TYPE_INDEX<Assets>) {
            assetFields.push_back(field);
        }
    }
    if (assetFields.empty()) {
        return false;
    }
    sqlite3_stmt *selectStmt = nullptr;
    std::string queryAssetsSql = "SELECT ";
    for (const auto &field : assetFields) {
        queryAssetsSql += field.colName + ",";
    }
    queryAssetsSql.pop_back();
    queryAssetsSql += " FROM '" + tableSchema.name + "' WHERE " + std::string(DBConstant::SQLITE_INNER_ROWID) + " = " +
        std::to_string(dataKey) + ";";
    int errCode = SQLiteUtils::GetStatement(dbHandle_, queryAssetsSql, selectStmt);
    if (errCode != E_OK) { // LCOV_EXCL_BR_LINE
        LOGE("Get select assets statement failed, %d.", errCode);
        return true;
    }
    ResFinalizer finalizer([selectStmt]() {
        sqlite3_stmt *statementInner = selectStmt;
        int ret = E_OK;
        SQLiteUtils::ResetStatement(statementInner, true, ret);
        if (ret != E_OK) {
            LOGW("Reset stmt failed %d when get asset", ret);
        }
    });
    VBucket assetInfo;
    errCode = GetAssetInfoOnTable(selectStmt, assetFields, assetInfo);
    if (errCode != E_OK) {
        return true;
    }
    return std::any_of(assetFields.begin(), assetFields.end(), [&](const Field &field) {
        return IsNeedUpdateAssetIdInner(selectStmt, vBucket, field, assetInfo, isNotIncCursor);
    });
}

int SQLiteSingleVerRelationalStorageExecutor::MarkFlagAsConsistent(const std::string &tableName,
    const DownloadData &downloadData, const std::set<std::string> &gidFilters)
{
    if (downloadData.data.size() != downloadData.opType.size()) {
        LOGE("The num of data:%zu an opType:%zu is not equal.", downloadData.data.size(), downloadData.opType.size());
        return -E_CLOUD_ERROR;
    }
    std::string sql = "UPDATE " + DBCommon::GetLogTableName(tableName) +
        " SET flag=flag&(~0x20), " + CloudDbConstant::UNLOCKING_TO_UNLOCK + " WHERE cloud_gid=? and timestamp=?;";
    sqlite3_stmt *stmt = nullptr;
    int errCode = SQLiteUtils::GetStatement(dbHandle_, sql, stmt);
    if (errCode != E_OK) {
        LOGE("Get mark flag as consistent stmt failed, %d.", errCode);
        return errCode;
    }
    int ret = E_OK;
    int index = 0;
    for (const auto &data: downloadData.data) {
        SQLiteUtils::ResetStatement(stmt, false, ret);
        OpType opType = downloadData.opType[index++];
        if (opType == OpType::NOT_HANDLE || opType == OpType::LOCKED_NOT_HANDLE) {
            continue;
        }
        errCode = CloudStorageUtils::BindStepConsistentFlagStmt(stmt, data, gidFilters);
        if (errCode != E_OK) {
            break;
        }
    }
    SQLiteUtils::ResetStatement(stmt, true, ret);
    return errCode == E_OK ? ret : errCode;
}

int SQLiteSingleVerRelationalStorageExecutor::MarkFlagAsAssetAsyncDownload(const std::string &tableName,
    const DownloadData &downloadData, const std::set<std::string> &gidFilters)
{
    if (downloadData.data.empty()) {
        return E_OK;
    }
    if (downloadData.data.size() != downloadData.opType.size()) {
        LOGE("The num of data:%zu an opType:%zu is not equal.", downloadData.data.size(), downloadData.opType.size());
        return -E_CLOUD_ERROR;
    }
    std::string sql = "UPDATE " + DBCommon::GetLogTableName(tableName) + " SET flag=flag|0x1000 WHERE cloud_gid=?;";
    sqlite3_stmt *stmt = nullptr;
    int errCode = SQLiteUtils::GetStatement(dbHandle_, sql, stmt);
    if (errCode != E_OK) {
        LOGE("[Storage Executor]Get mark flag as asset async download stmt failed, %d.", errCode);
        return errCode;
    }
    int ret = E_OK;
    for (const auto &gid : gidFilters) {
        SQLiteUtils::ResetStatement(stmt, false, ret);
        if (ret != E_OK) {
            LOGE("[Storage Executor]Reset stmt failed:%d", ret);
            break;
        }
        errCode = SQLiteUtils::BindTextToStatement(stmt, 1, gid);
        if (errCode != E_OK) {
            break;
        }
        errCode = SQLiteUtils::StepWithRetry(stmt);
        if (errCode == SQLiteUtils::MapSQLiteErrno(SQLITE_DONE)) {
            errCode = E_OK;
        } else {
            LOGW("[Storage Executor]Step mark flag as asset async download stmt failed %d gid %s",
                errCode, gid.c_str());
        }
    }
    SQLiteUtils::ResetStatement(stmt, true, ret);
    return errCode == E_OK ? ret : errCode;
}

int SQLiteSingleVerRelationalStorageExecutor::FillCloudVersionForUpload(const std::string &tableName,
    const CloudSyncBatch &batchData)
{
    if (batchData.extend.empty()) {
        return E_OK;
    }
    if (batchData.hashKey.empty() || batchData.extend.size() != batchData.hashKey.size()) {
        LOGE("invalid sync data for filling version.");
        return -E_INVALID_ARGS;
    }
    std::string sql = "UPDATE '" + DBCommon::GetLogTableName(tableName) +
        "' SET version = ? WHERE hash_key = ? ";
    sqlite3_stmt *stmt = nullptr;
    int errCode = SQLiteUtils::GetStatement(dbHandle_, sql, stmt);
    if (errCode != E_OK) {
        return errCode;
    }
    int ret = E_OK;
    for (size_t i = 0; i < batchData.extend.size(); ++i) {
        errCode = BindUpdateVersionStatement(batchData.extend[i], batchData.hashKey[i], stmt);
        if (errCode != E_OK) {
            LOGE("bind update version stmt failed.");
            SQLiteUtils::ResetStatement(stmt, true, ret);
            return errCode;
        }
    }
    SQLiteUtils::ResetStatement(stmt, true, ret);
    return ret;
}

int SQLiteSingleVerRelationalStorageExecutor::QueryCount(const std::string &tableName, int64_t &count)
{
    return SQLiteRelationalUtils::QueryCount(dbHandle_, tableName, count);
}

int SQLiteSingleVerRelationalStorageExecutor::CheckInventoryData(const std::string &tableName)
{
    int64_t dataCount = 0;
    int errCode = SQLiteRelationalUtils::QueryCount(dbHandle_, tableName, dataCount);
    if (errCode != E_OK) {
        LOGE("Query count failed %d", errCode);
        return errCode;
    }
    return dataCount > 0 ? -E_WITH_INVENTORY_DATA : E_OK;
}

int SQLiteSingleVerRelationalStorageExecutor::GetUploadCountInner(const Timestamp &timestamp,
    SqliteQueryHelper &helper, std::string &sql, int64_t &count)
{
    sqlite3_stmt *stmt = nullptr;
    int errCode = helper.GetCloudQueryStatement(false, dbHandle_, sql, stmt);
    if (errCode != E_OK) {
        LOGE("failed to get count statement %d", errCode);
        return errCode;
    }
    errCode = SQLiteUtils::StepWithRetry(stmt, isMemDb_);
    if (errCode == SQLiteUtils::MapSQLiteErrno(SQLITE_ROW)) {
        count = static_cast<int64_t>(sqlite3_column_int64(stmt, 0));
        errCode = E_OK;
    } else {
        LOGE("Failed to get the count to be uploaded. %d", errCode);
    }
    SQLiteUtils::ResetStatement(stmt, true, errCode);
    return errCode;
}

int SQLiteSingleVerRelationalStorageExecutor::GetUploadCount(const Timestamp &timestamp, bool isCloudForcePush,
    bool isCompensatedTask, QuerySyncObject &query, int64_t &count)
{
    int errCode;
    SqliteQueryHelper helper = query.GetQueryHelper(errCode);
    if (errCode != E_OK) {
        return errCode;
    }
    std::string sql = helper.GetCountRelationalCloudQuerySql(isCloudForcePush, isCompensatedTask,
        CloudWaterType::DELETE);
    return GetUploadCountInner(timestamp, helper, sql, count);
}

int SQLiteSingleVerRelationalStorageExecutor::GetAllUploadCount(const std::vector<Timestamp> &timestampVec,
    bool isCloudForcePush, bool isCompensatedTask, QuerySyncObject &query, int64_t &count)
{
    std::vector<CloudWaterType> typeVec = DBCommon::GetWaterTypeVec();
    if (timestampVec.size() != typeVec.size()) {
        return -E_INVALID_ARGS;
    }
    int errCode;
    SqliteQueryHelper helper = query.GetQueryHelper(errCode);
    if (errCode != E_OK) {
        return errCode;
    }
    count = 0;
    for (size_t i = 0; i < typeVec.size(); i++) {
        std::string sql = helper.GetCountRelationalCloudQuerySql(isCloudForcePush, isCompensatedTask, typeVec[i]);
        int64_t tempCount = 0;
        helper.AppendCloudQueryToGetDiffData(sql, typeVec[i]);
        errCode = GetUploadCountInner(timestampVec[i], helper, sql, tempCount);
        if (errCode != E_OK) {
            return errCode;
        }
        count += tempCount;
    }
    return E_OK;
}

int SQLiteSingleVerRelationalStorageExecutor::UpdateCloudLogGid(const CloudSyncData &cloudDataResult,
    bool ignoreEmptyGid)
{
    if (cloudDataResult.insData.extend.empty() || cloudDataResult.insData.rowid.empty() ||
        cloudDataResult.insData.extend.size() != cloudDataResult.insData.rowid.size()) {
        return -E_INVALID_ARGS;
    }
    std::string sql = "UPDATE '" + DBCommon::GetLogTableName(cloudDataResult.tableName)
        + "' SET cloud_gid = ? WHERE data_key = ? ";
    sqlite3_stmt *stmt = nullptr;
    int errCode = SQLiteUtils::GetStatement(dbHandle_, sql, stmt);
    if (errCode != E_OK) {
        return errCode;
    }
    errCode = BindStmtWithCloudGid(cloudDataResult, ignoreEmptyGid, stmt);
    int resetCode = E_OK;
    SQLiteUtils::ResetStatement(stmt, true, resetCode);
    return errCode == E_OK ? resetCode : errCode;
}

int SQLiteSingleVerRelationalStorageExecutor::GetSyncCloudData(const CloudUploadRecorder &uploadRecorder,
    CloudSyncData &cloudDataResult, SQLiteSingleVerRelationalContinueToken &token)
{
    token.GetCloudTableSchema(tableSchema_);
    sqlite3_stmt *queryStmt = nullptr;
    bool isStepNext = false;
    int errCode = token.GetCloudStatement(dbHandle_, cloudDataResult, queryStmt, isStepNext);
    if (errCode != E_OK) {
        (void)token.ReleaseCloudStatement();
        return errCode;
    }
    uint32_t totalSize = 0;
    uint32_t stepNum = -1;
    do {
        if (isStepNext) {
            errCode = SQLiteUtils::StepNext(queryStmt, isMemDb_);
            if (errCode != E_OK) {
                errCode = (errCode == -E_FINISHED ? E_OK : errCode);
                break;
            }
        }
        isStepNext = true;
        errCode = GetCloudDataForSync(uploadRecorder, queryStmt, cloudDataResult, ++stepNum, totalSize);
    } while (errCode == E_OK);
    if (errCode != -E_UNFINISHED) {
        (void)token.ReleaseCloudStatement();
    }
    return errCode;
}

int SQLiteSingleVerRelationalStorageExecutor::PutVBucketByType(VBucket &vBucket, const Field &field, Type &cloudValue)
{
    if (field.type == TYPE_INDEX<Asset> && cloudValue.index() == TYPE_INDEX<Bytes>) {
        Asset asset;
        int errCode = RuntimeContext::GetInstance()->BlobToAsset(std::get<Bytes>(cloudValue), asset);
        if (errCode != E_OK) {
            return errCode;
        }
        if (!CloudStorageUtils::CheckAssetStatus({asset})) {
            return -E_CLOUD_ERROR;
        }
        vBucket.insert_or_assign(field.colName, asset);
    } else if (field.type == TYPE_INDEX<Assets> && cloudValue.index() == TYPE_INDEX<Bytes>) {
        Assets assets;
        int errCode = RuntimeContext::GetInstance()->BlobToAssets(std::get<Bytes>(cloudValue), assets);
        if (errCode != E_OK) {
            return errCode;
        }
        if (CloudStorageUtils::IsAssetsContainDuplicateAsset(assets) || !CloudStorageUtils::CheckAssetStatus(assets)) {
            return -E_CLOUD_ERROR;
        }
        vBucket.insert_or_assign(field.colName, assets);
    } else {
        vBucket.insert_or_assign(field.colName, cloudValue);
    }
    return E_OK;
}

int SQLiteSingleVerRelationalStorageExecutor::GetDownloadAsset(std::vector<VBucket> &assetsV, const Field &field,
    Type &cloudValue)
{
    if (field.type == TYPE_INDEX<Asset> && cloudValue.index() == TYPE_INDEX<Bytes>) {
        Asset asset;
        VBucket bucket;
        int errCode = RuntimeContext::GetInstance()->BlobToAsset(std::get<Bytes>(cloudValue), asset);
        if (errCode != E_OK) {
            return errCode;
        }
        if (AssetOperationUtils::IsAssetNeedDownload(asset)) {
            bucket.insert_or_assign(field.colName, asset);
            assetsV.push_back(bucket);
        }
    } else if (field.type == TYPE_INDEX<Assets> && cloudValue.index() == TYPE_INDEX<Bytes>) {
        Assets assets;
        int errCode = RuntimeContext::GetInstance()->BlobToAssets(std::get<Bytes>(cloudValue), assets);
        if (errCode != E_OK) {
            return errCode;
        }
        if (CloudStorageUtils::IsAssetsContainDuplicateAsset(assets)) {
            return E_OK;
        }
        for (const auto &asset : assets) {
            if (AssetOperationUtils::IsAssetNeedDownload(asset)) {
                VBucket bucket;
                bucket.insert_or_assign(field.colName, asset);
                assetsV.push_back(bucket);
            }
        }
    }
    return E_OK;
}

int SQLiteSingleVerRelationalStorageExecutor::GetAssetInfoOnTable(sqlite3_stmt *&stmt,
    const std::vector<Field> &assetFields, VBucket &assetInfo)
{
    int errCode = SQLiteUtils::StepWithRetry(stmt);
    if (errCode == SQLiteUtils::MapSQLiteErrno(SQLITE_ROW)) { // LCOV_EXCL_BR_LINE
        int index = 0;
        for (const auto &field : assetFields) {
            Type cloudValue;
            errCode = SQLiteRelationalUtils::GetCloudValueByType(stmt, field.type, index++, cloudValue);
            if (errCode != E_OK) {
                break;
            }
            errCode = PutVBucketByType(assetInfo, field, cloudValue);
            if (errCode != E_OK) {
                break;
            }
        }
    } else if (errCode == SQLiteUtils::MapSQLiteErrno(SQLITE_DONE)) {
        errCode = E_OK;
    } else {
        LOGE("[RDBExecutor] Step failed when get asset from table, errCode = %d.", errCode);
    }
    return errCode;
}

int SQLiteSingleVerRelationalStorageExecutor::GetLocalDataCount(const std::string &tableName, int &dataCount,
    int &logicDeleteDataCount)
{
    std::string dataCountSql = "select count(*) from " + DBCommon::GetLogTableName(tableName) + " where data_key != -1";
    int errCode = SQLiteUtils::GetCountBySql(dbHandle_, dataCountSql, dataCount);
    if (errCode != E_OK) {
        LOGE("[RDBExecutor] Query local data count failed: %d", errCode);
        return errCode;
    }

    std::string logicDeleteDataCountSql = "select count(*) from " + DBCommon::GetLogTableName(tableName) +
        " where flag&0x08!=0 and data_key != -1";
    errCode = SQLiteUtils::GetCountBySql(dbHandle_, logicDeleteDataCountSql, logicDeleteDataCount);
    if (errCode != E_OK) {
        LOGE("[RDBExecutor] Query local logic delete data count failed: %d", errCode);
    }
    return errCode;
}

int SQLiteSingleVerRelationalStorageExecutor::UpdateExtendField(const std::string &tableName,
    const std::set<std::string> &extendColNames)
{
    bool isLogTableExist = false;
    int errCode = SQLiteUtils::CheckTableExists(dbHandle_, DBCommon::GetLogTableName(tableName), isLogTableExist);
    if (errCode == E_OK && !isLogTableExist) {
        LOGW("[RDBExecutor][UpdateExtendField] Log table of [%s [%zu]] not found!",
            DBCommon::StringMiddleMasking(tableName).c_str(), tableName.size());
        return E_OK;
    }
    std::string sql = "update " + DBCommon::GetLogTableName(tableName) + " as log set extend_field = json_object(";
    for (const auto &extendColName : extendColNames) {
        sql += "'" + extendColName + "',data." + extendColName + ",";
    }
    sql.pop_back();
    sql += ") from " + tableName + " as data where log.data_key = data." + std::string(DBConstant::SQLITE_INNER_ROWID);
    sqlite3_stmt *stmt = nullptr;
    errCode = SQLiteUtils::GetStatement(dbHandle_, sql, stmt);
    if (errCode != E_OK) {
        return errCode;
    }

    ResFinalizer finalizer([stmt]() {
        sqlite3_stmt *statement = stmt;
        int ret = E_OK;
        SQLiteUtils::ResetStatement(statement, true, ret);
        if (ret != E_OK) {
            LOGW("[RDBExecutor][UpdateExtendField] Reset stmt failed %d", ret);
        }
    });
    errCode = SQLiteUtils::StepWithRetry(stmt);
    if (errCode != SQLiteUtils::MapSQLiteErrno(SQLITE_DONE)) {
        LOGE("[RDBExecutor][UpdateExtendField] Update [%s [%zu]] extend field failed: %d",
            DBCommon::StringMiddleMasking(tableName).c_str(), tableName.size(), errCode);
        return errCode;
    }
    return E_OK;
}

int BuildJsonExtendField(const std::string &tableName, const std::string &lowVersionExtendColName, sqlite3 *db)
{
    std::string sql = "update " + DBCommon::GetLogTableName(tableName) + " set extend_field = json_object('" +
        lowVersionExtendColName + "',extend_field) where data_key = -1 and (json_valid(extend_field) = 0 or " +
        "json_extract(extend_field, '$." + lowVersionExtendColName +"') is null)";
    sqlite3_stmt *stmt = nullptr;
    int errCode = SQLiteUtils::GetStatement(db, sql, stmt);
    if (errCode != E_OK) {
        return errCode;
    }
    errCode = SQLiteUtils::StepWithRetry(stmt);
    if (errCode != SQLiteUtils::MapSQLiteErrno(SQLITE_DONE)) {
        LOGE("[RDBExecutor][UpdateDeleteDataExtendField] Update [%s [%zu]] extend field non-JSON format failed: %d",
            DBCommon::StringMiddleMasking(tableName).c_str(), tableName.size(), errCode);
    } else {
        errCode = E_OK;
    }
    int ret = E_OK;
    SQLiteUtils::ResetStatement(stmt, true, ret);
    if (ret != E_OK) {
        LOGW("[RDBExecutor][UpdateExtendField] Reset stmt failed %d", ret);
    }
    return errCode;
}

std::string GetUpdateExtendFieldSql(const std::string &tableName, const std::set<std::string> &oldExtendColNames,
    const std::set<std::string> &extendColNames)
{
    std::string sql = "update " + DBCommon::GetLogTableName(tableName) +
        " set extend_field = json_insert(extend_field,";
    bool isContainNewCol = false;
    for (const auto &extendColName : extendColNames) {
        if (oldExtendColNames.find(extendColName) != oldExtendColNames.end()) {
            continue;
        }
        isContainNewCol = true;
        sql += "'$." + extendColName + "',null,";
    }
    if (!isContainNewCol) {
        return "";
    }
    sql.pop_back();
    sql += ") where data_key = -1 and json_valid(extend_field) = 1;";
    return sql;
}

int SQLiteSingleVerRelationalStorageExecutor::UpdateDeleteDataExtendField(const std::string &tableName,
    const std::string &lowVersionExtendColName, const std::set<std::string> &oldExtendColNames,
    const std::set<std::string> &extendColNames)
{
    bool isLogTableExist = false;
    if (SQLiteUtils::CheckTableExists(dbHandle_, DBCommon::GetLogTableName(tableName), isLogTableExist) == E_OK &&
        !isLogTableExist) {
        LOGW("[RDBExecutor][UpdateDeleteDataExtendField] Log table of [%s [%zu]] not found!",
            DBCommon::StringMiddleMasking(tableName).c_str(), tableName.size());
        return E_OK;
    }
    int errCode = E_OK;
    if (!lowVersionExtendColName.empty()) {
        errCode = BuildJsonExtendField(tableName, lowVersionExtendColName, dbHandle_);
        if (errCode != E_OK) {
            LOGE("[UpdateDeleteDataExtendField] Update low version extend field of [%s [%zu]] to json failed: %d",
                DBCommon::StringMiddleMasking(tableName).c_str(), tableName.size(), errCode);
            return errCode;
        }
    }
    std::string sql = GetUpdateExtendFieldSql(tableName, oldExtendColNames, extendColNames);
    if (sql.empty()) {
        return E_OK;
    }

    sqlite3_stmt *stmt = nullptr;
    errCode = SQLiteUtils::GetStatement(dbHandle_, sql, stmt);
    if (errCode != E_OK) {
        return errCode;
    }
    errCode = SQLiteUtils::StepWithRetry(stmt);
    if (errCode != SQLiteUtils::MapSQLiteErrno(SQLITE_DONE)) {
        LOGE("[RDBExecutor][UpdateDeleteDataExtendField] Update extend field of [%s [%zu]] failed: %d",
            DBCommon::StringMiddleMasking(tableName).c_str(), tableName.size(), errCode);
    } else {
        errCode = E_OK;
    }
    int ret = E_OK;
    SQLiteUtils::ResetStatement(stmt, true, ret);
    if (ret != E_OK) {
        LOGW("[RDBExecutor][UpdateDeleteDataExtendField] Reset stmt failed %d", ret);
    }
    return errCode;
}

int SQLiteSingleVerRelationalStorageExecutor::GetDownloadAssetGid(const TableSchema &tableSchema,
    std::vector<std::string> &gids, int64_t beginTime, bool abortWithLimit)
{
    std::string sql = "SELECT cloud_gid FROM " + DBCommon::GetLogTableName(tableSchema.name) +
        " WHERE flag&0x1000=0x1000 AND timestamp >= ?;";
    sqlite3_stmt *stmt = nullptr;
    int errCode = SQLiteUtils::GetStatement(dbHandle_, sql, stmt);
    if (errCode != E_OK) {
        LOGE("[RDBExecutor]Get gid statement failed, %d", errCode);
        return errCode;
    }
    errCode = SQLiteUtils::BindInt64ToStatement(stmt, 1, beginTime);
    if (errCode != E_OK) {
        LOGE("[RDBExecutor] bind time failed %d when get download asset gid", errCode);
        SQLiteUtils::ResetStatement(stmt, true, errCode);
        return errCode;
     }
    uint32_t count = 0;
    do {
        errCode = SQLiteUtils::StepWithRetry(stmt, false);
        if (errCode == SQLiteUtils::MapSQLiteErrno(SQLITE_DONE)) {
            errCode = E_OK;
            break;
        } else if (errCode != SQLiteUtils::MapSQLiteErrno(SQLITE_ROW)) {
            LOGE("[RDBExecutor]Get downloading assets gid failed. %d", errCode);
            break;
        }
        std::string gid;
        errCode = SQLiteUtils::GetColumnTextValue(stmt, 0, gid);
        if (errCode != E_OK) {
            LOGW("[RDBExecutor]Get downloading assets gid failed %d when get col", errCode);
            continue;
        }
        gids.push_back(gid);
        if (AbortGetDownloadAssetGidIfNeed(tableSchema, gid, abortWithLimit, count)) {
            break;
        }
    } while (errCode == E_OK);
    int ret = E_OK;
    SQLiteUtils::ResetStatement(stmt, true, ret);
    return errCode == E_OK ? ret : errCode;
}

int SQLiteSingleVerRelationalStorageExecutor::GetDownloadAssetRecordsByGid(const TableSchema &tableSchema,
    const std::string gid, std::vector<VBucket> &assets)
{
    std::vector<Field> assetFields;
    std::string sql = "SELECT";
    for (const auto &field: tableSchema.fields) {
        if (field.type == TYPE_INDEX<Asset> || field.type == TYPE_INDEX<Assets>) {
            assetFields.emplace_back(field);
            sql += " b." + field.colName + ",";
        }
    }
    if (assetFields.empty()) {
        return E_OK;
    }
    sql.pop_back(); // remove last ,
    sql += CloudStorageUtils::GetLeftJoinLogSql(tableSchema.name) + " WHERE a.cloud_gid = ?;";
    sqlite3_stmt *stmt = nullptr;
    int errCode = SQLiteUtils::GetStatement(dbHandle_, sql, stmt);
    if (errCode != E_OK) {
        LOGE("Get downloading asset records statement failed, %d", errCode);
        return errCode;
    }
    errCode = SQLiteUtils::BindTextToStatement(stmt, 1, gid);
    if (errCode != E_OK) {
        SQLiteUtils::ResetStatement(stmt, true, errCode);
        return errCode;
    }
    errCode = SQLiteUtils::StepWithRetry(stmt);
    if (errCode == SQLiteUtils::MapSQLiteErrno(SQLITE_ROW)) {
        int index = 0;
        for (const auto &field: assetFields) {
            Type value;
            errCode = SQLiteRelationalUtils::GetCloudValueByType(stmt, field.type, index++, value);
            if (errCode != E_OK) {
                break;
            }
            errCode = GetDownloadAsset(assets, field, value);
            if (errCode != E_OK) {
                break;
            }
        }
    } else if (errCode == SQLiteUtils::MapSQLiteErrno(SQLITE_DONE)) {
        errCode = E_OK;
    } else {
        LOGE("step get downloading asset records statement failed %d.", errCode);
    }
    int ret = E_OK;
    SQLiteUtils::ResetStatement(stmt, true, ret);
    return errCode == E_OK ? ret : errCode;
}

int SQLiteSingleVerRelationalStorageExecutor::GetDownloadingCount(const std::string &tableName, int32_t &count)
{
    std::string sql = "SELECT count(*) FROM " + DBCommon::GetLogTableName(tableName) + " WHERE flag&0x1000=0x1000;";
    int errCode = SQLiteUtils::GetCountBySql(dbHandle_, sql, count);
    if (errCode != E_OK) {
        LOGE("[RDBExecutor] Query local data count failed: %d", errCode);
    }
    return errCode;
}

int SQLiteSingleVerRelationalStorageExecutor::GetDownloadingAssetsCount(
    const TableSchema &tableSchema, int32_t &totalCount)
{
    std::vector<std::string> gids;
    int errCode = GetDownloadAssetGid(tableSchema, gids);
    if (errCode != E_OK) {
        LOGE("[RDBExecutor]Get downloading assets gid failed: %d", errCode);
        return errCode;
    }
    for (const auto &gid : gids) {
        std::vector<VBucket> assets;
        errCode = GetDownloadAssetRecordsByGid(tableSchema, gid, assets);
        if (errCode != E_OK) {
            LOGE("[RDBExecutor]Get downloading assets records by gid failed: %d", errCode);
            return errCode;
        }
        totalCount += assets.size();
    }
    return E_OK;
}

int SQLiteSingleVerRelationalStorageExecutor::GetDownloadAssetRecordsInner(
    const TableSchema &tableSchema, int64_t beginTime, std::vector<std::string> &gids)
{
    int errCode = GetDownloadAssetGid(tableSchema, gids, beginTime, true);
    if (errCode != E_OK) {
        LOGE("[RDBExecutor]Get downloading assets gid failed: %d", errCode);
    }
    return errCode;
}

int SQLiteSingleVerRelationalStorageExecutor::CleanDownloadingFlag(const std::string &tableName)
{
    std::string sql;
    sql += "UPDATE " + DBCommon::GetLogTableName(tableName) + " SET flag=flag&(~0x1000);";
    sqlite3_stmt *stmt = nullptr;
    int errCode = SQLiteUtils::GetStatement(dbHandle_, sql, stmt);
    if (errCode != E_OK) {
        LOGE("[RDBExecutor]Get stmt failed clean downloading flag: %d, tableName: %s, length: %zu",
            errCode, DBCommon::StringMiddleMasking(tableName).c_str(), tableName.size());
        return errCode;
    }
    errCode = SQLiteUtils::StepWithRetry(stmt);
    if (errCode == SQLiteUtils::MapSQLiteErrno(SQLITE_DONE)) {
        errCode = E_OK;
    } else {
        LOGE("[RDBExecutor]Clean downloading flag failed: %d, tableName: %s, length: %zu",
            errCode, DBCommon::StringMiddleMasking(tableName).c_str(), tableName.size());
    }
    int ret = E_OK;
    SQLiteUtils::ResetStatement(stmt, true, ret);
    if (ret != E_OK) {
        LOGE("[RDBExecutor]Reset stmt failed clean downloading flag: %d", ret);
    }
    return errCode != E_OK ? errCode : ret;
}

bool SQLiteSingleVerRelationalStorageExecutor::AbortGetDownloadAssetGidIfNeed(
    const DistributedDB::TableSchema &tableSchema, const std::string &gid, bool abortWithLimit,
    uint32_t &count)
{
    if (!abortWithLimit) {
        return false;
    }
    std::vector<VBucket> assets;
    int errCode = GetDownloadAssetRecordsByGid(tableSchema, gid, assets);
    if (errCode != E_OK) {
        LOGW("[RDBExecutor]Get downloading assets failed %d gid %s", errCode, gid.c_str());
        return false;
    }
    count += assets.size();
    return count >= RuntimeContext::GetInstance()->GetAssetsDownloadManager()->GetMaxDownloadAssetsCount();
}
} // namespace DistributedDB
#endif
