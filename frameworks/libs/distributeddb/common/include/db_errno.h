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

#ifndef DISTRIBUTEDDB_ERRNO_H
#define DISTRIBUTEDDB_ERRNO_H

namespace DistributedDB {
constexpr const int E_OK = 0;
constexpr const int E_BASE = 1000; // different from the other errno.
constexpr const int E_NOT_SUPPORT = (E_BASE + 1); // not support currently.
constexpr const int E_INVALID_DB = (E_BASE + 2); // invalid db or connection.
constexpr const int E_NOT_FOUND = (E_BASE + 3); // not found the resource.
constexpr const int E_BUSY = (E_BASE + 4); // the db is busy
constexpr const int E_UNEXPECTED_DATA = (E_BASE + 5); // Data does not match expectation.
constexpr const int E_STALE = (E_BASE + 6); // Resource has been stopped, killed or destroyed.
constexpr const int E_INVALID_ARGS = (E_BASE + 7); // the input args is invalid.
constexpr const int E_REGISTER_OBSERVER = (E_BASE + 8); // error in register observer related function.
constexpr const int E_TRANSACT_STATE = (E_BASE + 9); // transaction state error.
constexpr const int E_SECUREC_ERROR = (E_BASE + 10); // security interface returns error
constexpr const int E_OUT_OF_MEMORY = (E_BASE + 11); // out of memory
constexpr const int E_NOT_PERMIT = (E_BASE + 12); // operation is not permitted
// function or handle already registered and not allowed replace
constexpr const int E_ALREADY_REGISTER = (E_BASE + 13);
constexpr const int E_ALREADY_ALLOC = (E_BASE + 14); // Object had already been allocated
constexpr const int E_ALREADY_RELEASE = (E_BASE + 15); // Object had already been released
constexpr const int E_CONTAINER_FULL = (E_BASE + 16); // container full
constexpr const int E_CONTAINER_EMPTY = (E_BASE + 17); // container empty
constexpr const int E_CONTAINER_FULL_TO_NOTFULL = (E_BASE + 18); // container status changed from full to not full
constexpr const int E_CONTAINER_NOTEMPTY_TO_EMPTY = (E_BASE + 19); // container status changed from full to not full
constexpr const int E_WAIT_RETRY = (E_BASE + 20); // wait and retry later
constexpr const int E_PARSE_FAIL = (E_BASE + 21); // parse packet or frame fail
constexpr const int E_TIMEOUT = (E_BASE + 22); // time out
constexpr const int E_SERIALIZE_ERROR = (E_BASE + 23); // serialize error
constexpr const int E_DESERIALIZE_ERROR = (E_BASE + 24); // deserialize error
constexpr const int E_NOT_REGISTER = (E_BASE + 25); // handler or function not registered
constexpr const int E_LENGTH_ERROR = (E_BASE + 26); // error relative to length
constexpr const int E_UNFINISHED = (E_BASE + 27); // get sync data unfinished.
constexpr const int E_FINISHED = (E_BASE + 28); // get sync data finished.
constexpr const int E_INVALID_MESSAGE_ID = (E_BASE + 29); // invalid messageId error
constexpr const int E_MESSAGE_ID_ERROR = (E_BASE + 30); // messageId is not expected
constexpr const int E_MESSAGE_TYPE_ERROR = (E_BASE + 31); // messageType is not expected
constexpr const int E_PERIPHERAL_INTERFACE_FAIL = (E_BASE + 32); // peripheral interface fail
constexpr const int E_NOT_INIT = (E_BASE + 33); // module may not init
constexpr const int E_MAX_LIMITS = (E_BASE + 34); // over max limits.
constexpr const int E_INVALID_CONNECTION = (E_BASE + 35); // invalid db connection.
constexpr const int E_NO_SUCH_ENTRY = (E_BASE + 36); // invalid db connection.
constexpr const int E_INTERNAL_ERROR = (E_BASE + 37); // an error due to code logic that is a bug
constexpr const int E_CONTAINER_ONLY_DELAY_TASK = (E_BASE + 38); // only delay task left in the container
constexpr const int E_SUM_CALCULATE_FAIL = (E_BASE + 39); // only delay task left in the container
constexpr const int E_SUM_MISMATCH = (E_BASE + 40); // check sum mismatch
constexpr const int E_OUT_OF_DATE = (E_BASE + 41); // things is out of date
constexpr const int E_OBJ_IS_KILLED = (E_BASE + 42); // the refObject has been killed.
constexpr const int E_SYSTEM_API_FAIL = (E_BASE + 43); // call the system api failed
constexpr const int E_INVALID_DATA = (E_BASE + 44); // invalid data
constexpr const int E_OUT_OF_IDS = (E_BASE + 45); // out of ids.
constexpr const int E_SEND_DATA = (E_BASE + 46); // need send data
constexpr const int E_NEED_TIMER = (E_BASE + 47); // timer is still need
constexpr const int E_NO_NEED_TIMER = (E_BASE + 48); // timer no longer need
constexpr const int E_COMBINE_FAIL = (E_BASE + 49); // fail in combining a frame
constexpr const int E_END_TIMER = (E_BASE + 50); // timer no longer needed
constexpr const int E_CALC_HASH = (E_BASE + 51); // calc hash error
constexpr const int E_REMOVE_FILE = (E_BASE + 52); // remove file failed
constexpr const int E_STATE_MACHINE_ERROR = (E_BASE + 53); // sync state machine error
constexpr const int E_NO_DATA_SEND = (E_BASE + 54); // no data to send
constexpr const int E_RECV_FINISHED = (E_BASE + 55); // recv finished
constexpr const int E_NEED_PULL_REPONSE = (E_BASE + 56); // need to response pull request
constexpr const int E_NO_SYNC_TASK = (E_BASE + 57); // no sync task to do
constexpr const int E_INVALID_PASSWD_OR_CORRUPTED_DB = (E_BASE + 58); // invalid password or corrupted database.
constexpr const int E_RESULT_SET_STATUS_INVALID = (E_BASE + 59); // status of result set is invalid.
constexpr const int E_RESULT_SET_EMPTY = (E_BASE + 60); // the result set is empty.
constexpr const int E_UPGRADE_FAILED = (E_BASE + 61); // the upgrade failed.
constexpr const int E_INVALID_FILE = (E_BASE + 62); // import invalid file.
constexpr const int E_INVALID_PATH = (E_BASE + 63); // the path is invalid.
constexpr const int E_EMPTY_PATH = (E_BASE + 64); // the path is empty.
constexpr const int E_TASK_BREAK_OFF = (E_BASE + 65); // task quit due to normal break off or error happen
constexpr const int E_INCORRECT_DATA = (E_BASE + 66); // data in the database is incorrect
constexpr const int E_NO_RESOURCE_FOR_USE = (E_BASE + 67); // no resource such as dbhandle for use
constexpr const int E_LAST_SYNC_FRAME = (E_BASE + 68); // this frame is the last frame for this sync
constexpr const int E_VERSION_NOT_SUPPORT = (E_BASE + 69); // version not support in any layer
constexpr const int E_FRAME_TYPE_NOT_SUPPORT = (E_BASE + 70); // frame type not support
constexpr const int E_INVALID_TIME = (E_BASE + 71); // the time is invalid
constexpr const int E_INVALID_VERSION = (E_BASE + 72); // sqlite storage version is invalid
constexpr const int E_SCHEMA_NOTEXIST = (E_BASE + 73); // schema does not exist
constexpr const int E_INVALID_SCHEMA = (E_BASE + 74); // the schema is invalid
constexpr const int E_SCHEMA_MISMATCH = (E_BASE + 75); // the schema is mismatch
constexpr const int E_INVALID_FORMAT = (E_BASE + 76); // the value is invalid json or mismatch with the schema.
constexpr const int E_READ_ONLY = (E_BASE + 77); // only have the read permission.
constexpr const int E_NEED_ABILITY_SYNC = (E_BASE + 78); // ability sync has not done
constexpr const int E_WAIT_NEXT_MESSAGE = (E_BASE + 79); // need remote device send a next message.
constexpr const int E_LOCAL_DELETED = (E_BASE + 80); // local data is deleted by the unpublish.
constexpr const int E_LOCAL_DEFEAT = (E_BASE + 81); // local data defeat the sync data while unpublish.
constexpr const int E_LOCAL_COVERED = (E_BASE + 82); // local data is covered by the sync data while unpublish.
constexpr const int E_INVALID_QUERY_FORMAT = (E_BASE + 83); // query format is not valid.
constexpr const int E_INVALID_QUERY_FIELD = (E_BASE + 84); // query field is not valid.
constexpr const int E_ALREADY_OPENED = (E_BASE + 85); // the database is already opened.
constexpr const int E_ALREADY_SET = (E_BASE + 86); // already set.
constexpr const int E_SAVE_DATA_NOTIFY = (E_BASE + 87); // notify remote device to keep alive, don't timeout
constexpr const int E_RE_SEND_DATA = (E_BASE + 88); // need re send data
constexpr const int E_EKEYREVOKED = (E_BASE + 89); // the EKEYREVOKED error
constexpr const int E_SECURITY_OPTION_CHECK_ERROR = (E_BASE + 90); // remote device's SecurityOption not equal to local
constexpr const int E_SYSTEM_API_ADAPTER_CALL_FAILED = (E_BASE + 91); // Adapter call failed
// not need delete msg, will be delete by sliding window receiver
constexpr const int E_NOT_NEED_DELETE_MSG = (E_BASE + 92);
constexpr const int E_SLIDING_WINDOW_SENDER_ERR = (E_BASE + 93); // sliding window sender err
constexpr const int E_SLIDING_WINDOW_RECEIVER_INVALID_MSG = (E_BASE + 94); // sliding window receiver invalid msg
constexpr const int E_IGNORE_DATA = (E_BASE + 95); // ignore the data changed by other devices and ignore the same data.
constexpr const int E_FORBID_CACHEDB = (E_BASE + 96); // such after rekey can not check passwd due to file control.
constexpr const int E_INTERCEPT_DATA_FAIL = (E_BASE + 97); // Intercept push data failed.
// The algo is defined, but there's no implement for the algo.
constexpr const int E_INVALID_COMPRESS_ALGO = (E_BASE + 98);
constexpr const int E_LOG_OVER_LIMITS = (E_BASE + 99); // The log file size is over the limits.
constexpr const int E_MODE_MISMATCH = (E_BASE + 100); // dual sync mode mismatch
constexpr const int E_NO_NEED_ACTIVE = (E_BASE + 101); // no need to active sync mode
constexpr const int E_REMOTE_OVER_SIZE = (E_BASE + 102); // for remote query, over MAX_REMOTEDATA_SIZE
constexpr const int E_NONEXISTENT = (E_BASE + 103);  // for result set, nonexistent index
constexpr const int E_TYPE_MISMATCH = (E_BASE + 104);  // for result set, mismatch type
constexpr const int E_DENIED_SQL = (E_BASE + 105);  // denied sql, not permit to execute
constexpr const int E_USER_CHANGE = (E_BASE + 106); // user change
constexpr const int E_CONSTRAINT = (E_BASE + 107); // sql failed with constraint
constexpr const int E_CLOUD_ERROR = (E_BASE + 108); // cloud error
constexpr const int E_QUERY_END = (E_BASE + 110); // Indicates that query function has queried last data from cloud
constexpr const int E_DB_CLOSED = (E_BASE + 111); // db is closed
constexpr const int E_NOT_SET = (E_BASE + 112); // asset loader is not set
constexpr const int E_CLOUD_NETWORK_ERROR = (E_BASE + 113); // network error in cloud
constexpr const int E_CLOUD_SYNC_UNSET = (E_BASE + 114); // not set sync option in cloud
constexpr const int E_CLOUD_FULL_RECORDS = (E_BASE + 115); // cloud's record is full
constexpr const int E_CLOUD_LOCK_ERROR = (E_BASE + 116); // cloud failed to get sync lock
constexpr const int E_CLOUD_ASSET_SPACE_INSUFFICIENT = (E_BASE + 117); // cloud asset space is insufficient
constexpr const int E_CLOUD_INVALID_ASSET = (E_BASE + 118); // the asset is invalid
constexpr const int E_TASK_PAUSED = (E_BASE + 119); // the task was paused, don't finished it
constexpr const int E_CLOUD_VERSION_CONFLICT = (E_BASE + 120); // cloud failed to update version
constexpr const int E_CLOUD_RECORD_EXIST_CONFLICT = (E_BASE + 121); // record conflict when upload/download
constexpr const int E_REMOVE_ASSETS_FAILED = (E_BASE + 122); // remove local assets failed
// add at 108 version, use for machine check ability sync finish
constexpr const int E_ABILITY_SYNC_FINISHED = (E_BASE + 123);
constexpr const int E_NEED_TIME_SYNC = (E_BASE + 124); // time sync has not done
constexpr const int E_CLOUD_GID_MISMATCH = (E_BASE + 125); // cloud gid cannot match in db
constexpr const int E_WITH_INVENTORY_DATA = (E_BASE + 126); // inventory data exists when setTracker for the first time
constexpr const int E_WAIT_COMPENSATED_SYNC = (E_BASE + 127); // need to do compensated sync
constexpr const int E_CLOUD_SYNC_TASK_MERGED = (E_BASE + 128); // sync task is merged
constexpr const int E_SQLITE_CANT_OPEN = (E_BASE + 129); // the sqlite cannot open.
constexpr const int E_LOCAL_ASSET_NOT_FOUND = (E_BASE + 130); // local asset not found.
constexpr const int E_ASSET_NOT_FOUND_FOR_DOWN_ONLY = (E_BASE + 131); // asset not found for download asset only.
// Num 150+ is reserved for schema related errno, since it may be added regularly
constexpr const int E_JSON_PARSE_FAIL = (E_BASE + 150); // Parse json fail in grammatical level
constexpr const int E_JSON_INSERT_PATH_EXIST = (E_BASE + 151); // Path already exist before insert
constexpr const int E_JSON_INSERT_PATH_CONFLICT = (E_BASE + 152); // Nearest path ends with type not object
constexpr const int E_JSON_DELETE_PATH_NOT_FOUND = (E_BASE + 153); // Path to delete not found
constexpr const int E_SCHEMA_PARSE_FAIL = (E_BASE + 160); // Parse schema fail in content level
constexpr const int E_SCHEMA_EQUAL_EXACTLY = (E_BASE + 161); // Two schemas are exactly the same
constexpr const int E_SCHEMA_UNEQUAL_COMPATIBLE = (E_BASE + 162); // New schema contain different index
// New schema contain more field(index may differ)
constexpr const int E_SCHEMA_UNEQUAL_COMPATIBLE_UPGRADE = (E_BASE + 163);
constexpr const int E_SCHEMA_UNEQUAL_INCOMPATIBLE = (E_BASE + 164); // New schema contain more field or index
constexpr const int E_SCHEMA_VIOLATE_VALUE = (E_BASE + 165); // New schema violate values already exist in dbFile
constexpr const int E_FLATBUFFER_VERIFY_FAIL = (E_BASE + 170); // Verify flatbuffer content(schema or value) fail.
constexpr const int E_VALUE_MATCH = (E_BASE + 180); // Value match schema(strict or compatible) without amend
constexpr const int E_VALUE_MATCH_AMENDED = (E_BASE + 181); // Value match schema(strict or compatible) with amend
constexpr const int E_VALUE_MISMATCH_FEILD_COUNT = (E_BASE + 182); // Value mismatch schema in field count
constexpr const int E_VALUE_MISMATCH_FEILD_TYPE = (E_BASE + 183); // Value mismatch schema in field type
constexpr const int E_VALUE_MISMATCH_CONSTRAINT = (E_BASE + 184); // Value mismatch schema in constraint
constexpr const int E_VALUE_MISMATCH_OTHER_REASON = (E_BASE + 185); // Value mismatch schema in other reason
constexpr const int E_RELATIONAL_TABLE_EQUAL = (E_BASE + 186); // In table is same
constexpr const int E_RELATIONAL_TABLE_COMPATIBLE = (E_BASE + 187); // In table is compatible
// In table has more fields with default value
constexpr const int E_RELATIONAL_TABLE_COMPATIBLE_UPGRADE = (E_BASE + 188);
constexpr const int E_RELATIONAL_TABLE_INCOMPATIBLE = (E_BASE + 189); // In table is incompatible
constexpr const int E_REBUILD_DATABASE = (E_BASE + 190); // database is rebuilt
// Num 200+ is reserved for fixed value errno, which should not be changed between time
// Message with errorNo of Feedback-type is generated by CommunicatorAggregator without data part(No deserial if exist)
constexpr const int E_FEEDBACK_UNKNOWN_MESSAGE = (E_BASE + 200); // Unknown message feedback from remote device
// Communicator not found feedback from remote device
constexpr const int E_FEEDBACK_COMMUNICATOR_NOT_FOUND = (E_BASE + 201);
// Schema was not found in relational distributed tables
constexpr const int E_DISTRIBUTED_SCHEMA_NOT_FOUND = (E_BASE + 202);
constexpr const int E_DISTRIBUTED_SCHEMA_CHANGED = (E_BASE + 203); // Schema has change when do sync
constexpr const int E_TABLE_REFERENCE_CHANGED = (E_BASE + 204); // table reference is changed
constexpr const int E_CLOUD_DISABLED = (E_BASE + 205); // The cloud switch has been turned off
constexpr const int E_DISTRIBUTED_FIELD_DECREASE = (E_BASE + 206); // Sync fewer specified columns than last time
constexpr const int E_NO_TRUSTED_USER = (E_BASE + 207); // No trusted found before device sync
} // namespace DistributedDB

#endif // DISTRIBUTEDDB_ERRNO_H
