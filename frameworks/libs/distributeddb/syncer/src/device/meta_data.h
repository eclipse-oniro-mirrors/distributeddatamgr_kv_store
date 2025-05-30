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

#ifndef META_DATA_H
#define META_DATA_H

#include <atomic>
#include <map>
#include <mutex>
#include <vector>

#include "db_types.h"
#include "ikvdb_sync_interface.h"
#include "version.h"
#include "query_sync_water_mark_helper.h"

namespace DistributedDB {
struct MetaDataValue {
    TimeOffset timeOffset = 0;
    uint64_t lastUpdateTime = 0;
    uint64_t localWaterMark = 0;
    uint64_t peerWaterMark = 0;
    Timestamp dbCreateTime = 0;
    uint64_t clearDeviceDataMark = 0; // Default 0 for not remove device data.
    uint64_t syncMark = 0; // 0x1 ability sync finish 0x2 time sync finish
    uint64_t remoteSchemaVersion = 0; // reset zero when local schema change
    int64_t systemTimeOffset = 0; // record dev time offset
    uint64_t remoteSoftwareVersion = 0; // record remote version
};

struct LocalMetaData {
    uint32_t version = LOCAL_META_DATA_VERSION_V2; // start at 108
    uint64_t localSchemaVersion = 0;
};

enum class SyncMark : uint32_t {
    SYNC_MARK_ABILITY_SYNC = 0x01,
    SYNC_MARK_TIME_SYNC = 0x02,
    SYNC_MARK_TIME_CHANGE = 0x04,
};

class Metadata {
public:
    class MetaWaterMarkAutoLock final {
    public:
        explicit MetaWaterMarkAutoLock(std::shared_ptr<Metadata> metadata);
        ~MetaWaterMarkAutoLock();
    private:
        DISABLE_COPY_ASSIGN_MOVE(MetaWaterMarkAutoLock);
        const std::shared_ptr<Metadata> metadataPtr_;
    };

    Metadata();
    virtual ~Metadata();

    int Initialize(ISyncInterface *storage);

    int SaveTimeOffset(const DeviceID &deviceId, const DeviceID &userId, TimeOffset inValue);

    void GetTimeOffset(const DeviceID &deviceId, const DeviceID &userId, TimeOffset &outValue);

    virtual void GetLocalWaterMark(const DeviceID &deviceId, const DeviceID &userId, uint64_t &outValue);

    int SaveLocalWaterMark(const DeviceID &deviceId, const DeviceID &userId, uint64_t inValue);

    void GetPeerWaterMark(const DeviceID &deviceId, const DeviceID &userId, uint64_t &outValue, bool isNeedHash = true);

    int SavePeerWaterMark(const DeviceID &deviceId, const DeviceID &userId, uint64_t inValue, bool isNeedHash);

    int SaveLocalTimeOffset(TimeOffset timeOffset, bool saveIntoDb = true);

    TimeOffset GetLocalTimeOffset() const;

    int EraseDeviceWaterMark(const std::string &deviceId, bool isNeedHash);

    int EraseDeviceWaterMark(const std::string &deviceId, const std::string &userId, bool isNeedHash,
        const std::string &tableName);

    void SetLastLocalTime(Timestamp lastLocalTime);

    Timestamp GetLastLocalTime() const;

    int SetSendQueryWaterMark(const std::string &queryIdentify,
        const std::string &deviceId, const std::string &userId, const WaterMark &waterMark);

    // the querySync's sendWatermark will increase by the device watermark
    // if the sendWatermark less than device watermark
    int GetSendQueryWaterMark(const std::string &queryIdentify,
        const std::string &deviceId, const std::string &userId, WaterMark &waterMark, bool isAutoLift = true);

    int SetRecvQueryWaterMark(const std::string &queryIdentify,
        const std::string &deviceId, const std::string &userId, const WaterMark &waterMark);

    // the querySync's recvWatermark will increase by the device watermark
    // if the watermark less than device watermark
    int GetRecvQueryWaterMark(const std::string &queryIdentify,
        const std::string &deviceId, const std::string &userId, WaterMark &waterMark);

    virtual int SetLastQueryTime(const std::string &queryIdentify, const std::string &deviceId,
        const std::string &userId, const Timestamp &timestamp);

    virtual int GetLastQueryTime(const std::string &queryIdentify, const std::string &deviceId,
        const std::string &userId, Timestamp &timestamp);

    int SetSendDeleteSyncWaterMark(const std::string &deviceId, const std::string &userId, const WaterMark &waterMark);

    // the deleteSync's sendWatermark will increase by the device watermark
    // if the sendWatermark less than device watermark
    int GetSendDeleteSyncWaterMark(const std::string &deviceId, const std::string &userId, WaterMark &waterMark,
        bool isAutoLift = true);

    int SetRecvDeleteSyncWaterMark(const std::string &deviceId, const std::string &userId, const WaterMark &waterMark,
        bool isNeedHash = true);

    // the deleteSync's recvWatermark will increase by the device watermark
    // if the recvWatermark less than device watermark
    int GetRecvDeleteSyncWaterMark(const std::string &deviceId, const std::string &userId, WaterMark &waterMark);

    void GetDbCreateTime(const DeviceID &deviceId, const DeviceID &userId, uint64_t &outValue);

    int SetDbCreateTime(const DeviceID &deviceId, const DeviceID &userId, uint64_t inValue, bool isNeedHash);

    int ResetMetaDataAfterRemoveData(const DeviceID &deviceId, const DeviceID &userId);

    void GetRemoveDataMark(const DeviceID &deviceId, const DeviceID &userId, uint64_t &outValue);

    // always get value from db, value updated from storage trigger
    uint64_t GetQueryLastTimestamp(const DeviceID &deviceId, const std::string &queryId) const;

    void RemoveQueryFromRecordSet(const DeviceID &deviceId, const std::string &queryId);

    int SaveClientId(const std::string &deviceId, const std::string &clientId);

    int GetHashDeviceId(const std::string &clientId, std::string &hashDevId) const;

    void LockWaterMark() const;

    void UnlockWaterMark() const;

    int GetWaterMarkInfoFromDB(const std::string &dev, const std::string &userId, bool isNeedHash, WatermarkInfo &info);

    int ClearAllAbilitySyncFinishMark();

    int SetAbilitySyncFinishMark(const std::string &deviceId, const std::string &userId, bool finish);

    bool IsAbilitySyncFinish(const std::string &deviceId, const std::string &userId);

    int ClearAllTimeSyncFinishMark();

    int SetTimeSyncFinishMark(const std::string &deviceId, const std::string &userId, bool finish);

    int SetTimeChangeMark(const std::string &deviceId, const std::string &userId, bool change);

    bool IsTimeSyncFinish(const std::string &deviceId, const std::string &userId);

    bool IsTimeChange(const std::string &deviceId, const std::string &userId);

    int SetRemoteSchemaVersion(const std::string &deviceId, const std::string &userId, uint64_t schemaVersion);

    uint64_t GetRemoteSchemaVersion(const std::string &deviceId, const std::string &userId);

    int SetSystemTimeOffset(const std::string &deviceId, const std::string &userId, int64_t systemTimeOffset);

    int64_t GetSystemTimeOffset(const std::string &deviceId, const std::string &userId);

    std::pair<int, uint64_t> GetLocalSchemaVersion();

    int SetLocalSchemaVersion(uint64_t schemaVersion);

    uint64_t GetRemoteSoftwareVersion(const std::string &deviceId, const std::string &userId);

    int SetRemoteSoftwareVersion(const std::string &deviceId, const std::string &userId, uint64_t version);
private:

    int SaveMetaDataValue(const DeviceID &deviceId, const DeviceID &userId, const MetaDataValue &inValue,
        bool isNeedHash = true);

    // sync module need hash devices id
    int GetMetaDataValue(const DeviceID &deviceId, const DeviceID &userId, MetaDataValue &outValue, bool isNeedHash);

    static int SerializeMetaData(const MetaDataValue &inValue, std::vector<uint8_t> &outValue);

    static int DeSerializeMetaData(const std::vector<uint8_t> &inValue, MetaDataValue &outValue);

    int GetMetadataFromDb(const std::vector<uint8_t> &key, std::vector<uint8_t> &outValue) const;

    int GetMetadataFromDbByPrefixKey(const Key &keyPrefix, std::map<Key, Value> &data) const;

    int SetMetadataToDb(const std::vector<uint8_t> &key, const std::vector<uint8_t> &inValue);

    int64_t StringToLong(const std::vector<uint8_t> &value) const;

    int GetAllMetadataKey(std::vector<std::vector<uint8_t>> &keys);

    int LoadAllMetadata();

    void GetHashDeviceId(const DeviceID &deviceId, const DeviceID &userId, DeviceID &hashDeviceId, bool isNeedHash);

    // reset the waterMark to zero
    int ResetRecvQueryWaterMark(const DeviceID &deviceId, const DeviceID &userId, const std::string &tableName,
        bool isNeedHash);

    int SetSyncMark(const std::string &deviceId, const std::string &userId, SyncMark syncMark, bool finish);

    bool IsContainSyncMark(const std::string &deviceId, const std::string &userId, SyncMark syncMark);

    int SaveLocalMetaData(const LocalMetaData &localMetaData);

    std::pair<int, LocalMetaData> GetLocalMetaData();

    enum class MetaValueAction : uint32_t {
        CLEAR_ABILITY_SYNC_MARK = 0x01,
        CLEAR_TIME_SYNC_MARK = 0x02,
        CLEAR_REMOTE_SCHEMA_VERSION = 0x04,
        CLEAR_SYSTEM_TIME_OFFSET = 0x08,
        CLEAR_TIME_CHANGE_MARK = 0x10,
        SET_TIME_CHANGE_MARK = 0x20,
    };

    int ClearAllMetaDataValue(uint32_t innerClearAction);

    static void ClearMetaDataValue(uint32_t innerClearAction, MetaDataValue &metaDataValue);

    static std::pair<int, Value> SerializeLocalMetaData(const LocalMetaData &localMetaData);

    static std::pair<int, LocalMetaData> DeSerializeLocalMetaData(const Value &value);

    static uint64_t CalculateLocalMetaDataLength();

    int InitLocalMetaData();

    int GetMetaDataValueFromDB(const std::string &deviceId, const std::string &userId, bool isNeedHash,
        MetaDataValue &metaDataValue);

    int GetMetaDataValueFromDB(const Key &key, MetaDataValue &metaDataValue);
    int GetMetaDataFromDBByPrefixKey(const std::string &deviceId, bool isNeedHash,
        std::map<Key, MetaDataValue> &metaData);

    // store localTimeOffset in ram; if change, should add a lock first, change here and metadata,
    // then release lock
    std::atomic<TimeOffset> localTimeOffset_;
    std::mutex localTimeOffsetLock_;
    ISyncInterface *naturalStoragePtr_;

    // if changed, it should be locked from save-to-db to change-in-memory.save to db must be first,
    // if save to db fail, it will not be changed in memory.
    mutable std::mutex metadataLock_;
    std::map<DeviceSyncTarget, DeviceID> deviceIdToHashDeviceIdMap_;

    // store localTimeOffset in ram, used to make timestamp increase
    mutable std::mutex lastLocalTimeLock_;
    Timestamp lastLocalTime_;

    QuerySyncWaterMarkHelper querySyncWaterMarkHelper_;

    // set value: SUBSCRIBE_QUERY_PREFIX + DBCommon::TransferHashString(queryId)
    // queryId is not in set while key is not found from db first time, and return lastTimestamp = INT64_MAX
    // if query is in set return 0 while not found from db, means already sync before, don't trigger again
    mutable std::map<DeviceID, std::set<std::string>> queryIdMap_;

    std::mutex clientIdLock_;
    std::map<DeviceID, std::string> clientIdCache_;

    mutable std::recursive_mutex waterMarkMutex_;
    mutable std::mutex localMetaDataMutex_;
};
}  // namespace DistributedDB
#endif
