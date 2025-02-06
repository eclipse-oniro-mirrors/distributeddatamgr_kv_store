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
#ifndef SQLITE_SINGLE_VER_RELATIONAL_STORAGE_EXECUTOR_H
#define SQLITE_SINGLE_VER_RELATIONAL_STORAGE_EXECUTOR_H
#ifdef RELATIONAL_STORE

#include <atomic>
#include "cloud/asset_operation_utils.h"
#include "cloud/cloud_db_constant.h"
#include "cloud/cloud_store_types.h"
#include "cloud/cloud_upload_recorder.h"
#include "data_transformer.h"
#include "db_types.h"
#include "icloud_sync_storage_interface.h"
#include "macro_utils.h"
#include "query_object.h"
#include "relational_row_data.h"
#include "relational_store_delegate.h"
#include "relational_sync_data_inserter.h"
#include "sqlite_log_table_manager.h"
#include "sqlite_single_ver_relational_continue_token.h"
#include "sqlite_storage_executor.h"
#include "sqlite_utils.h"
#include "tracker_table.h"

namespace DistributedDB {
class SQLiteSingleVerRelationalStorageExecutor : public SQLiteStorageExecutor {
public:
    enum class PutDataMode {
        SYNC,
        USER
    };
    enum class MarkFlagOption {
        DEFAULT,
        SET_WAIT_COMPENSATED_SYNC
    };

    struct UpdateCursorContext {
        int errCode = E_OK;
        uint64_t cursor;
    };

    SQLiteSingleVerRelationalStorageExecutor(sqlite3 *dbHandle, bool writable, DistributedTableMode mode);
    ~SQLiteSingleVerRelationalStorageExecutor() override = default;

    // Delete the copy and assign constructors
    DISABLE_COPY_ASSIGN_MOVE(SQLiteSingleVerRelationalStorageExecutor);

    int ResetLogStatus(std::string &tableName);

    int CreateRelationalLogTable(DistributedTableMode mode, bool isUpgraded, const std::string &identity,
        TableInfo &table);

    // The parameter "identity" is a hash string that identifies a device
    int CreateDistributedTable(DistributedTableMode mode, bool isUpgraded, const std::string &identity,
        TableInfo &table);

    int UpgradeDistributedTable(const std::string &tableName, DistributedTableMode mode, bool &schemaChanged,
        RelationalSchemaObject &schema, TableSyncType syncType);

    int StartTransaction(TransactType type);
    int Commit();
    int Rollback();

    // For Get sync data
    int GetSyncDataByQuery(std::vector<DataItem> &dataItems, size_t appendLength, const DataSizeSpecInfo &sizeInfo,
        std::function<int(sqlite3 *, sqlite3_stmt *&, sqlite3_stmt *&, bool &)> getStmt, const TableInfo &tableInfo);

    // operation of meta data
    int GetKvData(const Key &key, Value &value) const;
    int PutKvData(const Key &key, const Value &value) const;
    int DeleteMetaData(const std::vector<Key> &keys) const;
    int DeleteMetaDataByPrefixKey(const Key &keyPrefix) const;
    int GetAllMetaKeys(std::vector<Key> &keys) const;

    // For Put sync data
    int SaveSyncItems(RelationalSyncDataInserter &inserter, bool useTrans = true);

    int CheckDBModeForRelational();

    int DeleteDistributedDeviceTable(const std::string &device, const std::string &tableName);

    int DeleteDistributedAllDeviceTableLog(const std::string &tableName);

    int DeleteDistributedDeviceTableLog(const std::string &device, const std::string &tableName);

    int DeleteDistributedLogTable(const std::string &tableName);

    int CheckAndCleanDistributedTable(const std::vector<std::string> &tableNames,
        std::vector<std::string> &missingTables);

    int CreateDistributedDeviceTable(const std::string &device, const TableInfo &baseTbl, const StoreInfo &info);

    int CheckQueryObjectLegal(const TableInfo &table, QueryObject &query, const std::string &schemaVersion);

    int CheckQueryObjectLegal(const QuerySyncObject &query);

    int GetMaxTimestamp(const std::vector<std::string> &tablesName, Timestamp &maxTimestamp) const;

    int ExecuteQueryBySqlStmt(const std::string &sql, const std::vector<std::string> &bindArgs, int packetSize,
        std::vector<std::string> &colNames, std::vector<RelationalRowData *> &data);

    int SaveSyncDataItems(RelationalSyncDataInserter &inserter);

    int CheckEncryptedOrCorrupted() const;

    int GetExistsDeviceList(std::set<std::string> &devices) const;

    int GetUploadCount(const Timestamp &timestamp, bool isCloudForcePush, bool isCompensatedTask,
        QuerySyncObject &query, int64_t &count);

    int GetAllUploadCount(const std::vector<Timestamp> &timestampVec, bool isCloudForcePush, bool isCompensatedTask,
        QuerySyncObject &query, int64_t &count);

    int UpdateCloudLogGid(const CloudSyncData &cloudDataResult, bool ignoreEmptyGid);

    int GetSyncCloudData(const CloudUploadRecorder &uploadRecorder, CloudSyncData &cloudDataResult,
        SQLiteSingleVerRelationalContinueToken &token);

    int GetSyncCloudGid(QuerySyncObject &query, const SyncTimeRange &syncTimeRange, bool isCloudForcePushStrategy,
        bool isCompensatedTask, std::vector<std::string> &cloudGid);

    void SetLocalSchema(const RelationalSchemaObject &localSchema);

    int GetInfoByPrimaryKeyOrGid(const TableSchema &tableSchema, const VBucket &vBucket,
        DataInfoWithLog &dataInfoWithLog, VBucket &assetInfo);

    int PutCloudSyncData(const std::string &tableName, const TableSchema &tableSchema,
        const TrackerTable &trackerTable, DownloadData &downloadData);

    int UpdateAssetStatusForAssetOnly(const TableSchema &tableSchema, VBucket &asset);

    int FillCloudAssetForDownload(const TableSchema &tableSchema, VBucket &vBucket, bool isDownloadSuccess,
        uint64_t &currCursor);
    int FillCloudAssetForAsyncDownload(const TableSchema &tableSchema, VBucket &vBucket, bool isDownloadSuccess);
    int DoCleanInner(ClearMode mode, const std::vector<std::string> &tableNameList,
        const RelationalSchemaObject &localSchema, std::vector<Asset> &assets,
        std::vector<std::string> &notifyTableList);

    int FillCloudAssetForUpload(OpType opType, const TableSchema &tableSchema, const CloudSyncBatch &data);
    int FillCloudVersionForUpload(const OpType opType, const CloudSyncData &data);

    int SetLogTriggerStatus(bool status);
    int SetCursorIncFlag(bool flag);

    int GetCursor(const std::string &tableName, uint64_t &cursor);

    int AnalysisTrackerTable(const TrackerTable &trackerTable, TableInfo &tableInfo);
    int CreateTrackerTable(const TrackerTable &trackerTable, const TableInfo &table, bool checkData);
    int GetOrInitTrackerSchemaFromMeta(RelationalSchemaObject &schema);
    int ExecuteSql(const SqlCondition &condition, std::vector<VBucket> &records);

    int GetClearWaterMarkTables(const std::vector<TableReferenceProperty> &tableReferenceProperty,
        const RelationalSchemaObject &schema, std::set<std::string> &clearWaterMarkTables);
    int CreateTempSyncTrigger(const TrackerTable &trackerTable, bool flag);
    int GetAndResetServerObserverData(const std::string &tableName, ChangeProperties &changeProperties);
    int ClearAllTempSyncTrigger();
    int CleanTrackerData(const std::string &tableName, int64_t cursor, bool isOnlyTrackTable);
    int CreateSharedTable(const TableSchema &schema);
    int DeleteTable(const std::vector<std::string> &tableNames);
    int UpdateSharedTable(const std::map<std::string, std::vector<Field>> &updateTableNames);
    int AlterTableName(const std::map<std::string, std::string> &tableNames);
    int DeleteTableTrigger(const std::string &missTable) const;

    int GetReferenceGid(const std::string &tableName, const CloudSyncBatch &syncBatch,
        const std::map<std::string, std::vector<TableReferenceProperty>> &tableReference,
        std::map<int64_t, Entries> &referenceGid);

    int CheckIfExistUserTable(const std::string &tableName);

    void SetLogicDelete(bool isLogicDelete);
    int RenewTableTrigger(DistributedTableMode mode, const TableInfo &tableInfo, TableSyncType syncType);

    std::pair<int, uint32_t> GetAssetsByGidOrHashKey(const TableSchema &tableSchema, const std::string &gid,
        const Bytes &hashKey, VBucket &assets);

    int FillHandleWithOpType(const OpType opType, const CloudSyncData &data, bool fillAsset, bool ignoreEmptyGid,
        const TableSchema &tableSchema);

    void SetIAssetLoader(const std::shared_ptr<IAssetLoader> &loader);

    int CleanResourceForDroppedTable(const std::string &tableName);

    void SetPutDataMode(PutDataMode mode);

    void SetMarkFlagOption(MarkFlagOption option);

    int UpgradedLogForExistedData(TableInfo &tableInfo, bool schemaChanged);

    int UpdateRecordFlag(const std::string &tableName, const std::string &sql, const LogInfo &logInfo);

    void MarkFlagAsUploadFinished(const std::string &tableName, const Key &hashKey, Timestamp timestamp,
        bool isExistAssetsDownload);

    int CleanUploadFinishedFlag(const std::string &tableName);

    int GetWaitCompensatedSyncDataPk(const TableSchema &table, std::vector<VBucket> &data,
        bool isQueryDownloadRecords);

    int ClearUnLockingStatus(const std::string &tableName);

    int MarkFlagAsConsistent(const std::string &tableName, const DownloadData &downloadData,
        const std::set<std::string> &gidFilters);

    int MarkFlagAsAssetAsyncDownload(const std::string &tableName, const DownloadData &downloadData,
        const std::set<std::string> &gidFilters);

    int CheckInventoryData(const std::string &tableName);

    int UpdateRecordStatus(const std::string &tableName, const std::string &status, const Key &hashKey);

    void SetUploadConfig(int32_t maxUploadCount, int32_t maxUploadSize);

    int InitCursorToMeta(const std::string &tableName);

    void SetTableSchema(const TableSchema &tableSchema);

    int ReviseLocalModTime(const std::string &tableName, const std::vector<ReviseModTimeInfo> &revisedData);

    int GetLocalDataCount(const std::string &tableName, int &dataCount, int &logicDeleteDataCount);

    int GetCloudDataCount(const std::string &tableName, DownloadData &downloadData, int64_t &count);

    int UpdateExtendField(const std::string &tableName, const std::set<std::string> &extendColNames);

    int UpdateDeleteDataExtendField(const std::string &tableName, const std::string &lowVersionExtendColName,
        const std::set<std::string> &oldExtendColNames, const std::set<std::string> &extendColNames);

    void CheckAndCreateTrigger(const TrackerTable &trackerTable);

    int GetDownloadingAssetsCount(const TableSchema &tableSchema, int32_t &totalCount);

    int GetDownloadingCount(const std::string &tableName, int32_t &count);

    int GetDownloadAssetGid(const TableSchema &tableSchema, std::vector<std::string> &gids,
        int64_t beginTime = 0, bool abortWithLimit = false);

    int GetDownloadAssetRecordsInner(const TableSchema &tableSchema, int64_t beginTime, std::vector<std::string> &gids);

    int GetDownloadAssetRecordsByGid(const TableSchema &tableSchema, const std::string gid,
        std::vector<VBucket> &assets);

    int CleanDownloadingFlag(const std::string &tableName);

    int CleanDownloadingFlagByGid(const std::string &tableName, const std::string &gid, VBucket dbAssets);

    int CompareSchemaTableColumns(const std::string &tableName);

    void CheckAndCreateTrigger(const TableInfo &table);

    int GetLockStatusByGid(const std::string &tableName, const std::string &gid, LockStatus &status);
private:
    int DoCleanLogs(const std::vector<std::string> &tableNameList, const RelationalSchemaObject &localSchema);

    int DoCleanLogAndData(const std::vector<std::string> &tableNameList,
        const RelationalSchemaObject &localSchema, std::vector<Asset> &assets);

    int CleanCloudDataOnLogTable(const std::string &logTableName, ClearMode mode);

    int CleanCloudDataAndLogOnUserTable(const std::string &tableName, const std::string &logTableName,
        const RelationalSchemaObject &localSchema);

    int ChangeCloudDataFlagOnLogTable(const std::string &logTableName);

    int SetDataOnUserTableWithLogicDelete(const std::string &tableName, const std::string &logTableName);

    static void UpdateCursor(sqlite3_context *ctx, int argc, sqlite3_value **argv);

    int CreateFuncUpdateCursor(UpdateCursorContext &context,
        void(*updateCursorFunc)(sqlite3_context *ctx, int argc, sqlite3_value **argv)) const;

    int SetCursor(const std::string &tableName, uint64_t cursor);

    int IncreaseCursorOnAssetData(const std::string &tableName, const std::string &gid, uint64_t &currCursor);

    int GetCleanCloudDataKeys(const std::string &logTableName, std::vector<int64_t> &dataKeys,
        bool distinguishCloudFlag);

    int GetCloudAssets(const std::string &tableName, const std::vector<FieldInfo> &fieldInfos,
        const std::vector<int64_t> &dataKeys, std::vector<Asset> &assets);

    int GetAssetOnTable(const std::string &tableName, const std::string &fieldName,
        const std::vector<int64_t> &dataKeys, std::vector<Asset> &assets);

    int GetCloudAssetsOnTable(const std::string &tableName, const std::string &fieldName,
        const std::vector<int64_t> &dataKeys, std::vector<Asset> &assets);

    int GetDataItemForSync(sqlite3_stmt *statement, DataItem &dataItem, bool isGettingDeletedData) const;

    int CheckDataConflictDefeated(const DataItem &item, sqlite3_stmt *queryStmt,
        bool &isDefeated, bool &isExist, int64_t &rowId);

    int SaveSyncDataItem(RelationalSyncDataInserter &inserter, SaveSyncDataStmt &saveStmt, DataItem &item);

    int SaveSyncDataItem(const DataItem &dataItem, bool isUpdate, SaveSyncDataStmt &saveStmt,
        RelationalSyncDataInserter &inserter, int64_t &rowid);

    int DeleteSyncDataItem(const DataItem &dataItem, RelationalSyncDataInserter &inserter, sqlite3_stmt *&rmDataStmt);

    int AlterAuxTableForUpgrade(const TableInfo &oldTableInfo, const TableInfo &newTableInfo);

    int DeleteSyncLog(const DataItem &item, RelationalSyncDataInserter &inserter, sqlite3_stmt *&rmLogStmt);
    int ProcessMissQueryData(const DataItem &item, RelationalSyncDataInserter &inserter, sqlite3_stmt *&rmDataStmt,
        sqlite3_stmt *&rmLogStmt);
    int GetMissQueryData(sqlite3_stmt *fullStmt, DataItem &item);
    int GetQueryDataAndStepNext(bool isFirstTime, bool isGettingDeletedData, sqlite3_stmt *queryStmt, DataItem &item,
        Timestamp &queryTime);
    int GetMissQueryDataAndStepNext(sqlite3_stmt *fullStmt, DataItem &item, Timestamp &missQueryTime);

    void SetTableInfo(const TableInfo &tableInfo);  // When put or get sync data, must call the func first.

    int GeneLogInfoForExistedData(sqlite3 *db, const std::string &identity, const TableInfo &tableInfo,
        std::unique_ptr<SqliteLogTableManager> &logMgrPtr);

    int CleanExtendAndCursorForDeleteData(const std::string &tableName);

    int GetCloudDataForSync(const CloudUploadRecorder &uploadRecorder, sqlite3_stmt *statement,
        CloudSyncData &cloudDataResult, uint32_t &stepNum, uint32_t &totalSize);

    int PutVBucketByType(VBucket &vBucket, const Field &field, Type &cloudValue);

    int GetDownloadAsset(std::vector<VBucket> &assetsV, const Field &field, Type &cloudValue);

    int ExecutePutCloudData(const std::string &tableName, const TableSchema &tableSchema,
        const TrackerTable &trackerTable, DownloadData &downloadData, std::map<int, int> &statisticMap);

    std::string GetInsertSqlForCloudSync(const TableSchema &tableSchema);

    int GetPrimaryKeyHashValue(const VBucket &vBucket, const TableSchema &tableSchema, std::vector<uint8_t> &hashValue,
        bool allowEmpty = false);

    int GetQueryLogStatement(const TableSchema &tableSchema, const VBucket &vBucket, const std::string &querySql,
        const Key &hashKey, sqlite3_stmt *&selectStmt);

    int GetQueryLogSql(const std::string &tableName, const VBucket &vBucket, const std::set<std::string> &pkSet,
        std::string &querySql);

    int GetQueryInfoSql(const std::string &tableName, const VBucket &vBucket, std::set<std::string> &pkSet,
        std::vector<Field> &assetFields, std::string &querySql);

    int GetFillDownloadAssetStatement(const std::string &tableName, const VBucket &vBucket,
        const std::vector<Field> &fields, sqlite3_stmt *&statement);

    int InitFillUploadAssetStatement(OpType opType, const TableSchema &tableSchema, const CloudSyncBatch &data,
        const int &index, sqlite3_stmt *&statement);

    int GetLogInfoByStatement(sqlite3_stmt *statement, LogInfo &logInfo);

    int GetInfoByStatement(sqlite3_stmt *statement, const std::vector<Field> &assetFields,
        const std::map<std::string, Field> &pkMap, DataInfoWithLog &dataInfoWithLog, VBucket &assetInfo);

    int InsertCloudData(VBucket &vBucket, const TableSchema &tableSchema, const TrackerTable &trackerTable,
        int64_t dataKey);

    int InsertLogRecord(const TableSchema &tableSchema, const TrackerTable &trackerTable, VBucket &vBucket);

    int BindOneField(int index, const VBucket &vBucket, const Field &field, sqlite3_stmt *updateStmt);

    int BindValueToUpsertStatement(const VBucket &vBucket,  const std::vector<Field> &fields, sqlite3_stmt *upsertStmt);

    int BindStatusSubQueryHashKeyStatement(sqlite3_stmt *insertLogStmt, std::vector<uint8_t> &hashKey, int &index);

    int BindHashKeyAndGidToInsertLogStatement(const VBucket &vBucket, const TableSchema &tableSchema,
        const TrackerTable &trackerTable, sqlite3_stmt *insertLogStmt, int &index);

    int BindShareValueToInsertLogStatement(const VBucket &vBucket, const TableSchema &tableSchema,
        sqlite3_stmt *insertLogStmt, int &index);

    int BindValueToInsertLogStatement(VBucket &vBucket, const TableSchema &tableSchema,
        const TrackerTable &trackerTable, sqlite3_stmt *insertLogStmt);

    std::string GetWhereConditionForDataTable(const std::string &gidStr, const std::set<std::string> &pkSet,
        const std::string &tableName, bool queryByPk = true);

    int GetUpdateSqlForCloudSync(const std::vector<Field> &updateFields, const TableSchema &tableSchema,
        const std::string &gidStr, const std::set<std::string> &pkSet, std::string &updateSql);

    int GetUpdateDataTableStatement(const VBucket &vBucket, const TableSchema &tableSchema, sqlite3_stmt *&updateStmt);

    int UpdateCloudData(VBucket &vBucket, const TableSchema &tableSchema);

    int GetUpdateLogRecordStatement(const TableSchema &tableSchema, const VBucket &vBucket, OpType opType,
        std::vector<std::string> &updateColName, sqlite3_stmt *&updateLogStmt);
    int AppendUpdateLogRecordWhereSqlCondition(const TableSchema &tableSchema, const VBucket &vBucket,
        std::string &sql);

    int UpdateLogRecord(const VBucket &vBucket, const TableSchema &tableSchema, OpType opType);

    int BindValueToUpdateLogStatement(const VBucket &vBucket, const TableSchema &tableSchema,
        const std::vector<std::string> &colNames, bool allowPrimaryKeyEmpty, sqlite3_stmt *updateLogStmt);

    int GetDeleteStatementForCloudSync(const TableSchema &tableSchema, const std::set<std::string> &pkSet,
        const VBucket &vBucket, sqlite3_stmt *&deleteStmt);

    int UpdateTrackerTableTimeStamp(sqlite3 *db, const std::string &identity, const TableInfo &tableInfo,
        std::unique_ptr<SqliteLogTableManager> &logMgrPtr, bool isRowReplace);

    int DeleteCloudData(const std::string &tableName, const VBucket &vBucket, const TableSchema &tableSchema,
        const TrackerTable &trackerTable);

    int IsTableOnceDropped(const std::string &tableName, bool &onceDropped);

    int OnlyUpdateLogTable(const VBucket &vBucket, const TableSchema &tableSchema, OpType opType);

    int BindUpdateVersionStatement(const VBucket &vBucket, const Bytes &hashKey, sqlite3_stmt *&stmt);
    int DoCleanShareTableDataAndLog(const std::vector<std::string> &tableNameList);
    int SetDataOnShareTableWithLogicDelete(const std::string &tableName, const std::string &logTableName);
    int CleanShareTable(const std::string &tableName);

    int GetReferenceGidInner(const std::string &sourceTable, const std::string &targetTable,
        const CloudSyncBatch &syncBatch, const std::vector<TableReferenceProperty> &targetTableReference,
        std::map<int64_t, Entries> &referenceGid);

    int GetReferenceGidByStmt(sqlite3_stmt *statement, const CloudSyncBatch &syncBatch,
        const std::string &targetTable, std::map<int64_t, Entries> &referenceGid);

    static std::string GetReferenceGidSql(const std::string &sourceTable, const std::string &targetTable,
        const std::vector<std::string> &sourceFields, const std::vector<std::string> &targetFields);

    static std::pair<std::vector<std::string>, std::vector<std::string>> SplitReferenceByField(
        const std::vector<TableReferenceProperty> &targetTableReference);

    int BindStmtWithCloudGid(const CloudSyncData &cloudDataResult, bool ignoreEmptyGid, sqlite3_stmt *&stmt);

    int GetCloudDeleteSql(const std::string &table, std::string &sql);

    int RemoveDataAndLog(const std::string &tableName, int64_t dataKey);

    int64_t GetLocalDataKey(size_t index, const DownloadData &downloadData);

    int BindStmtWithCloudGidInner(const std::string &gid, int64_t rowid,
        sqlite3_stmt *&stmt, int &fillGidCount);

    int DoCleanAssetId(const std::string &tableName, const RelationalSchemaObject &localSchema);

    int CleanAssetId(const std::string &tableName, const std::vector<FieldInfo> &fieldInfos,
        const std::vector<int64_t> &dataKeys);

    int UpdateAssetIdOnUserTable(const std::string &tableName, const std::string &fieldName,
        const std::vector<int64_t> &dataKeys, std::vector<Asset> &assets);

    int GetAssetsAndUpdateAssetsId(const std::string &tableName, const std::string &fieldName,
        const std::vector<int64_t> &dataKeys);

    int CleanAssetsIdOnUserTable(const std::string &tableName, const std::string &fieldName, const int64_t rowId,
        const std::vector<uint8_t> &assetsValue);

    int InitGetAssetStmt(const std::string &sql, const std::string &gid, const Bytes &hashKey,
        sqlite3_stmt *&stmt);

    int GetAssetsByRowId(sqlite3_stmt *&selectStmt, Assets &assets);

    int ExecuteFillDownloadAssetStatement(sqlite3_stmt *&stmt, int beginIndex, const std::string &cloudGid);

    int CleanDownloadChangedAssets(const VBucket &vBucket, const AssetOperationUtils::RecordAssetOpType &assetOpType);

    int GetAndBindFillUploadAssetStatement(const std::string &tableName, const VBucket &assets,
        sqlite3_stmt *&statement);

    int OnlyUpdateAssetId(const std::string &tableName, const TableSchema &tableSchema, const VBucket &vBucket,
        int64_t dataKey, OpType opType);

    void UpdateLocalAssetId(const VBucket &vBucket, const std::string &fieldName, Asset &asset);

    void UpdateLocalAssetsId(const VBucket &vBucket, const std::string &fieldName, Assets &assets);

    int BindAssetToBlobStatement(const Asset &asset, int index, sqlite3_stmt *&stmt);

    int BindAssetsToBlobStatement(const Assets &assets, int index, sqlite3_stmt *&stmt);

    int GetAssetInfoOnTable(sqlite3_stmt *&stmt, const std::vector<Field> &assetFields, VBucket &assetInfo);

    int BindAssetFiledToBlobStatement(const TableSchema &tableSchema, const std::vector<Asset> &assetOfOneRecord,
        const std::vector<Assets> &assetsOfOneRecord, sqlite3_stmt *&stmt);

    int UpdateAssetsIdForOneRecord(const TableSchema &tableSchema, const std::string &sql,
        const std::vector<Asset> &assetOfOneRecord, const std::vector<Assets> &assetsOfOneRecord);

    bool IsNeedUpdateAssetIdInner(sqlite3_stmt *selectStmt, const VBucket &vBucket, const Field &field,
        VBucket &assetInfo, bool &isNotIncCursor);

    bool IsNeedUpdateAssetId(const TableSchema &tableSchema, int64_t dataKey, const VBucket &vBucket,
        bool &isNotIncCursor);

    int UpdateAssetId(const TableSchema &tableSchema, int64_t dataKey, const VBucket &vBucket);

    int64_t GetDataFlag();

    std::string GetUpdateDataFlagSql(const VBucket &data);

    std::string GetDev();

    std::vector<Field> GetUpdateField(const VBucket &vBucket, const TableSchema &tableSchema);

    int GetRecordFromStmt(sqlite3_stmt *stmt, const std::vector<Field> &fields, int startIndex, VBucket &record);

    int FillCloudVersionForUpload(const std::string &tableName, const CloudSyncBatch &batchData);

    int QueryCount(const std::string &tableName, int64_t &count);

    int GetUploadCountInner(const Timestamp &timestamp, SqliteQueryHelper &helper, std::string &sql, int64_t &count);

    int LogicDeleteCloudData(const std::string &tableName, const VBucket &vBucket,
        const TableSchema &tableSchema, const TrackerTable &trackerTable);

    bool AbortGetDownloadAssetGidIfNeed(const TableSchema &tableSchema, const std::string &gid, bool abortWithLimit,
        uint32_t &count);

    static constexpr const char *CONSISTENT_FLAG = "0x20";
    static constexpr const char *UPDATE_FLAG_CLOUD = "flag = 0";
    static constexpr const char *UPDATE_FLAG_WAIT_COMPENSATED_SYNC = "flag = flag | 0x10";
    static constexpr const char *FLAG_IS_WAIT_COMPENSATED_SYNC =
        "(a.flag & 0x10 != 0 and a.status = 0) or a.status = 1";
    static constexpr const char *FLAG_IS_WAIT_COMPENSATED_CONTAIN_DOWNLOAD_SYNC =
        "(a.flag & 0x10 != 0 and a.status = 0) or a.status = 1 or (a.flag & 0x1000 != 0 and a.status = 0)";

    std::string baseTblName_;
    TableInfo table_;  // Always operating table, user table when get, device table when put.
    TableSchema tableSchema_; // for cloud table
    RelationalSchemaObject localSchema_;

    DistributedTableMode mode_;

    std::map<int32_t, std::function<int(int, const VBucket &, const Field &, sqlite3_stmt *)>> bindCloudFieldFuncMap_;
    std::map<int32_t, std::function<int(const VBucket &, const Field &, std::vector<uint8_t> &)>> toVectorFuncMap_;

    std::atomic<bool> isLogicDelete_;
    std::shared_ptr<IAssetLoader> assetLoader_;

    PutDataMode putDataMode_;
    MarkFlagOption markFlagOption_;

    std::atomic<int32_t> maxUploadCount_;
    std::atomic<int32_t> maxUploadSize_;
};
} // namespace DistributedDB
#endif
#endif // SQLITE_SINGLE_VER_RELATIONAL_STORAGE_EXECUTOR_H
