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

#ifndef KV_STORE_TYPE_H
#define KV_STORE_TYPE_H

#include <functional>
#include <map>
#include <set>
#include <string>

#include "query.h"
#include "types_export.h"

namespace DistributedDB {
enum DBStatus {
    OK = 0,
    DB_ERROR = 27328512, // DBStatus in [27328512, 27394048)
    BUSY,
    NOT_FOUND,
    INVALID_ARGS,
    TIME_OUT,
    NOT_SUPPORT,
    INVALID_PASSWD_OR_CORRUPTED_DB,
    OVER_MAX_LIMITS,
    INVALID_FILE,
    NO_PERMISSION,
    FILE_ALREADY_EXISTED,
    SCHEMA_MISMATCH,
    INVALID_SCHEMA,
    READ_ONLY,
    INVALID_VALUE_FIELDS, // invalid put value for json schema.
    INVALID_FIELD_TYPE, // invalid put value field type for json schema.
    CONSTRAIN_VIOLATION, // invalid put value constrain for json schema.
    INVALID_FORMAT, // invalid put value format for json schema.
    STALE, // new record is staler compared to the same key existed in db.
    LOCAL_DELETED, // local data is deleted by the unpublish.
    LOCAL_DEFEAT, // local data defeat the sync data while unpublish.
    LOCAL_COVERED, // local data is covered by the sync data while unpublish.
    INVALID_QUERY_FORMAT,
    INVALID_QUERY_FIELD,
    PERMISSION_CHECK_FORBID_SYNC, // permission check result , forbid sync.
    ALREADY_SET, // already set.
    COMM_FAILURE, // communicator may get some error.
    EKEYREVOKED_ERROR, // EKEYREVOKED error when operating db file
    SECURITY_OPTION_CHECK_ERROR, // such as remote device's SecurityOption not equal to local
    SCHEMA_VIOLATE_VALUE, // Values already exist in dbFile do not match new schema
    INTERCEPT_DATA_FAIL, // Interceptor push data failed.
    LOG_OVER_LIMITS, // Log size is over the limits.
    DISTRIBUTED_SCHEMA_NOT_FOUND, // the sync table is not a relational table
    DISTRIBUTED_SCHEMA_CHANGED, // the schema was changed
    MODE_MISMATCH,
    NOT_ACTIVE,
    USER_CHANGED,
    NONEXISTENT,  // for row record, pass invalid column name or invalid column index.
    TYPE_MISMATCH,  // for row record, get value with mismatch func.
    REMOTE_OVER_SIZE, // for remote query, the data is too many, only get part or data.
    RATE_LIMIT,
    DATA_HANDLE_ERROR, // remote handle data failed
    CONSTRAINT, // constraint check failed in sqlite
    CLOUD_ERROR, // cloud error
    QUERY_END, // Indicates that query function has queried last data from cloud
    DB_CLOSED, // db is closed
    UNSET_ERROR, // something should be set not be set
    CLOUD_NETWORK_ERROR, // network error in cloud
    CLOUD_SYNC_UNSET, // not set sync option in cloud
    CLOUD_FULL_RECORDS, // cloud's record is full
    CLOUD_LOCK_ERROR, // cloud failed to get sync lock
    CLOUD_ASSET_SPACE_INSUFFICIENT, // cloud asset space is insufficient
    PROPERTY_CHANGED, // reference property changed
    CLOUD_VERSION_CONFLICT, // cloud failed to update version
    CLOUD_RECORD_EXIST_CONFLICT, // this error happen in Download/BatchInsert/BatchUpdate
    REMOVE_ASSETS_FAIL, // remove local assets failed
    WITH_INVENTORY_DATA, // inventory data exists when setTracker for the first time
    WAIT_COMPENSATED_SYNC, // need to do compensated sync
    CLOUD_SYNC_TASK_MERGED, // sync task is merged
    CLOUD_RECORD_NOT_FOUND, // this error happen in BatchUpdate/BatchDelete
    CLOUD_RECORD_ALREADY_EXISTED, // this error happen in BatchInsert
    SQLITE_CANT_OPEN, // the sqlite cannot open
    LOCAL_ASSET_NOT_FOUND, // file manager miss local assets
    ASSET_NOT_FOUND_FOR_DOWN_ONLY, // assets miss for asset only
    CLOUD_DISABLED, // the cloud switch has been turned off
    DISTRIBUTED_FIELD_DECREASE, // sync fewer specified columns than last time
    SKIP_ASSET, // workaround status for contact app assets download failure, need to ignore these failures
    BUTT_STATUS = 27394048 // end of status
};

struct KvStoreConfig {
    std::string dataDir;
};

enum PragmaCmd {
    AUTO_SYNC = 1,
    SYNC_DEVICES = 2, // this cmd will be removed in the future, don't use it
    RM_DEVICE_DATA = 3, // this cmd will be removed in the future, don't use it
    PERFORMANCE_ANALYSIS_GET_REPORT,
    PERFORMANCE_ANALYSIS_OPEN,
    PERFORMANCE_ANALYSIS_CLOSE,
    PERFORMANCE_ANALYSIS_SET_REPORTFILENAME,
    GET_IDENTIFIER_OF_DEVICE,
    GET_DEVICE_IDENTIFIER_OF_ENTRY,
    GET_QUEUED_SYNC_SIZE,
    SET_QUEUED_SYNC_LIMIT,
    GET_QUEUED_SYNC_LIMIT,
    SET_WIPE_POLICY,  // set the policy of wipe remote stale data
    RESULT_SET_CACHE_MODE, // Accept ResultSetCacheMode Type As PragmaData
    RESULT_SET_CACHE_MAX_SIZE, // Allowed Int Type Range [1,16], Unit MB
    SET_SYNC_RETRY,
    SET_MAX_LOG_LIMIT,
    EXEC_CHECKPOINT,
    LOGIC_DELETE_SYNC_DATA,
    SET_MAX_VALUE_SIZE,
};

enum ResolutionPolicyType {
    AUTO_LAST_WIN = 0,      // resolve conflicts by timestamp(default value)
    CUSTOMER_RESOLUTION = 1 // resolve conflicts by user
};

enum ObserverMode {
    OBSERVER_CHANGES_NATIVE = 1,
    OBSERVER_CHANGES_FOREIGN = 2,
    OBSERVER_CHANGES_LOCAL_ONLY = 4,
    OBSERVER_CHANGES_CLOUD = 8,
    // bit mask
    OBSERVER_CHANGES_BRIEF = 0x100,  // notify only device
    OBSERVER_CHANGES_DETAIL = 0x200, // notify with key
    OBSERVER_CHANGES_DATA = 0x400    // notify with entry
};

enum SyncMode {
    SYNC_MODE_PUSH_ONLY,
    SYNC_MODE_PULL_ONLY,
    SYNC_MODE_PUSH_PULL,
    SYNC_MODE_CLOUD_MERGE = 4,
    SYNC_MODE_CLOUD_FORCE_PUSH,
    SYNC_MODE_CLOUD_FORCE_PULL,
};

enum ConflictResolvePolicy {
    LAST_WIN = 0,
    DEVICE_COLLABORATION,
};

struct TableStatus {
    std::string tableName;
    DBStatus status;
};

enum ProcessStatus {
    PREPARED = 0,
    PROCESSING = 1,
    FINISHED = 2,
};

enum class CollateType : uint32_t {
    COLLATE_NONE = 0,
    COLLATE_NOCASE,
    COLLATE_RTRIM,
    COLLATE_BUTT
};

struct Info {
    uint32_t batchIndex = 0;
    uint32_t total = 0;
    uint32_t successCount = 0; // merge or upload success count
    uint32_t failCount = 0;
    uint32_t insertCount = 0;
    uint32_t updateCount = 0;
    uint32_t deleteCount = 0;
};

struct TableProcessInfo {
    ProcessStatus process = PREPARED;
    Info downLoadInfo;
    Info upLoadInfo;
};

struct SyncProcess {
    ProcessStatus process = PREPARED;
    DBStatus errCode = OK;
    std::map<std::string, TableProcessInfo> tableProcess;
};

struct DeviceSyncOption {
    std::vector<std::string> devices;
    SyncMode mode = SYNC_MODE_PULL_ONLY;
    Query query; // isQuery must be set to true if the query is set
    bool isQuery = false;
    bool isWait = true;
};

struct DeviceSyncInfo {
    uint32_t total = 0;
    uint32_t finishedCount = 0;
};

struct DeviceSyncProcess {
    ProcessStatus process = PREPARED;
    DBStatus errCode = OK;
    uint32_t syncId;
    DeviceSyncInfo pullInfo;
};

using KvStoreCorruptionHandler = std::function<void (const std::string &appId, const std::string &userId,
    const std::string &storeId)>;
using StoreCorruptionHandler = std::function<void (const std::string &appId, const std::string &userId,
    const std::string &storeId)>;
using SyncStatusCallback = std::function<void(const std::map<std::string, std::vector<TableStatus>> &devicesMap)>;

using SyncProcessCallback = std::function<void(const std::map<std::string, SyncProcess> &process)>;

using DeviceSyncProcessCallback = std::function<void(const std::map<std::string, DeviceSyncProcess> &processMap)>;

struct RemoteCondition {
    std::string sql;  // The sql statement;
    std::vector<std::string> bindArgs;  // The bind args.
};

struct DBInfo {
    std::string userId;
    std::string appId;
    std::string storeId;
    bool syncDualTupleMode = false;
    bool isNeedSync = false;
};

using UpdateKeyCallback = std::function<void (const Key &originKey, Key &newKey)>;

struct TrackerSchema {
    std::string tableName;
    std::set<std::string> extendColNames;
    std::set<std::string> trackerColNames;
    bool isForceUpgrade = false;
    bool isTrackAction = false;
};

struct TableReferenceProperty {
    std::string sourceTableName;
    std::string targetTableName;
    std::map<std::string, std::string> columns; // key is sourceTable column, value is targetTable column
};

static constexpr const char *GAUSSDB_RD = "gaussdb_rd";
static constexpr const char *SQLITE = "sqlite";
struct ChangeProperties {
    bool isTrackedDataChange = false;
    bool isP2pSyncDataChange = false;
    bool isKnowledgeDataChange = false;
};

enum IndexType : uint32_t {
    /**
     * use btree index type in database
    */
    BTREE = 0,
    /**
     * use hash index type in database
    */
    HASH,
};

struct Rdconfig {
    bool readOnly = false;
    IndexType type = BTREE;
    uint32_t pageSize = 32u;
    uint32_t cacheSize = 2048u;
};

struct WatermarkInfo {
    uint64_t sendMark = 0; // data will be sent which timestamp greater than sendMark
    uint64_t receiveMark = 0; // data will be sent in remote which timestamp greater than receiveMark
};

struct DbIdParam {
    std::string appId;
    std::string userId;
    std::string storeId;
    std::string subUser = "";
    int32_t instanceId = 0;
};

struct DistributedField {
    std::string colName;
    bool isP2pSync = false; // device p2p sync with this column when it was true
    // default generate by local table pk when none field was specified
    bool isSpecified = false; // local log hashKey will generate by specified field and deal conflict with them
};

struct DistributedTable {
    std::string tableName;
    std::vector<DistributedField> fields;
};

struct DistributedSchema {
    uint32_t version = 0;
    std::vector<DistributedTable> tables;
};

// Table mode of device data for relational store
enum class DistributedTableMode : int {
    COLLABORATION = 0, // Save all devices data in user table
    SPLIT_BY_DEVICE // Save device data in each table split by device
};

enum class DataOperator : uint32_t {
    UPDATE_TIME = 0x01,
    RESET_UPLOAD_CLOUD = 0x02
};

struct DeviceSyncTarget {
    std::string device;
    std::string userId;
    DeviceSyncTarget(std::string device, std::string userId) : device(std::move(device)), userId(std::move(userId)) {}
    bool operator<(const DeviceSyncTarget& other) const
    {
        if (device == other.device) {
            return userId < other.userId;
        }
        return device < other.device;
    }
};
} // namespace DistributedDB
#endif // KV_STORE_TYPE_H
