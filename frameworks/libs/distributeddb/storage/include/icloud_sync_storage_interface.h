/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef ICLOUD_SYNC_STORAGE_INTERFACE_H
#define ICLOUD_SYNC_STORAGE_INTERFACE_H

#include "cloud/cloud_db_types.h"
#include "cloud/cloud_store_types.h"
#include "cloud/iAssetLoader.h"
#include "data_transformer.h"
#include "query_sync_object.h"
#include "query_utils.h"
#include "sqlite_utils.h"
#include "store_observer.h"

namespace DistributedDB {

enum class OpType : uint8_t {
    INSERT = 1,
    UPDATE, // update data, gid and timestamp at same time
    DELETE,
    ONLY_UPDATE_GID,
    // used in Cloud Force Push strategy, when SET_CLOUD_FORCE_PUSH_FLAG_ONE, upload process won't process this record
    SET_CLOUD_FORCE_PUSH_FLAG_ONE,
    SET_CLOUD_FORCE_PUSH_FLAG_ZERO,
    UPDATE_TIMESTAMP,
    CLEAR_GID,
    UPDATE_VERSION,
    INSERT_VERSION,
    SET_UPLOADING,
    LOCKED_NOT_HANDLE,
    NOT_HANDLE
};

typedef struct DownloadData {
    std::vector<VBucket> data;
    std::vector<OpType> opType;
    std::vector<int64_t> existDataKey;
    std::vector<Key> existDataHashKey;
    std::string user;
    TimeOffset timeOffset = 0;
} DownloadData;

class ICloudSyncStorageHook {
public:
    ICloudSyncStorageHook() = default;
    virtual ~ICloudSyncStorageHook() = default;

    virtual void SetSyncFinishHook(const std::function<void (void)> &func)
    {
        syncFinishFunc_ = func;
    }

    virtual void SyncFinishHook()
    {
        if (syncFinishFunc_) {
            syncFinishFunc_();
        }
    }

    virtual void SetDoUploadHook(const std::function<void (void)> &func)
    {
        uploadStartFunc_ = func;
    }

    virtual void DoUploadHook()
    {
        if (uploadStartFunc_) {
            uploadStartFunc_();
        }
    }

    void SetBeforeUploadTransaction(const std::function<void (void)> &func)
    {
        beforeUploadTransaction_ = func;
    }

    void DoBeforeUploadTransaction()
    {
        if (beforeUploadTransaction_) {
            beforeUploadTransaction_();
        }
    }
protected:
    std::function<void (void)> syncFinishFunc_;
    std::function<void (void)> uploadStartFunc_;
    std::function<void (void)> beforeUploadTransaction_;
};

class ICloudSyncStorageInterface : public ICloudSyncStorageHook {
public:
    ICloudSyncStorageInterface() = default;
    virtual ~ICloudSyncStorageInterface() = default;

    virtual int GetMetaData(const Key &key, Value &value) const = 0;

    virtual int PutMetaData(const Key &key, const Value &value) = 0;

    virtual int ChkSchema(const TableName &tableName) = 0;

    virtual int SetCloudDbSchema(const DataBaseSchema &schema) = 0;

    virtual int GetCloudDbSchema(std::shared_ptr<DataBaseSchema> &cloudSchema) = 0;

    virtual int GetCloudTableSchema(const TableName &tableName, TableSchema &tableSchema) = 0;

    virtual int StartTransaction(TransactType type) = 0;

    virtual int Commit() = 0;

    virtual int Rollback() = 0;

    virtual int GetUploadCount(const QuerySyncObject &query, const Timestamp &timestamp, bool isCloudForcePush,
        bool isCompensatedTask, int64_t &count) = 0;

    virtual int GetAllUploadCount(const QuerySyncObject &query, const std::vector<Timestamp> &timestampVec,
        bool isCloudForcePush, bool isCompensatedTask, int64_t &count) = 0;

    virtual int GetCloudData(const TableSchema &tableSchema, const QuerySyncObject &object, const Timestamp &beginTime,
        ContinueToken &continueStmtToken, CloudSyncData &cloudDataResult) = 0;

    virtual int GetCloudDataNext(ContinueToken &continueStmtToken, CloudSyncData &cloudDataResult) = 0;

    virtual int GetCloudGid(const TableSchema &tableSchema, const QuerySyncObject &querySyncObject,
        bool isCloudForcePush, bool isCompensatedTask, std::vector<std::string> &cloudGid) = 0;

    virtual int ReleaseCloudDataToken(ContinueToken &continueStmtToken) = 0;

    virtual int GetInfoByPrimaryKeyOrGid(const std::string &tableName, const VBucket &vBucket,
        DataInfoWithLog &dataInfoWithLog, VBucket &assetInfo) = 0;

    virtual int PutCloudSyncData(const std::string &tableName, DownloadData &downloadData) = 0;

    virtual int UpdateAssetStatusForAssetOnly(const std::string &tableName, VBucket &asset) = 0;

    virtual int CleanCloudData(ClearMode mode, const std::vector<std::string> &tableNameList,
        const RelationalSchemaObject &localSchema, std::vector<Asset> &assets)
    {
        return E_OK;
    }

    virtual void TriggerObserverAction(const std::string &deviceName, ChangedData &&changedData,
        bool isChangedData) = 0;

    virtual int FillCloudAssetForDownload(const std::string &tableName, VBucket &asset, bool isDownloadSuccess) = 0;

    virtual int FillCloudAssetForAsyncDownload(const std::string &tableName, VBucket &asset,
        bool isDownloadSuccess) = 0;

    virtual int SetLogTriggerStatus(bool status) = 0;

    virtual int SetLogTriggerStatusForAsyncDownload(bool status) = 0;

    virtual int SetCursorIncFlag(bool flag)
    {
        return E_OK;
    };

    virtual int FillCloudLogAndAsset(OpType opType, const CloudSyncData &data, bool fillAsset, bool ignoreEmptyGid) = 0;

    virtual std::string GetIdentify() const = 0;

    virtual int CheckQueryValid(const QuerySyncObject &query) = 0;

    virtual int CreateTempSyncTrigger(const std::string &tableName)
    {
        return E_OK;
    }

    virtual int GetAndResetServerObserverData(const std::string &tableName, ChangeProperties &changeProperties)
    {
        return E_OK;
    }

    virtual int ClearAllTempSyncTrigger()
    {
        return E_OK;
    }

    virtual bool IsSharedTable(const std::string &tableName) = 0;

    virtual std::pair<int, uint32_t> GetAssetsByGidOrHashKey(const TableSchema &tableSchema, const std::string &gid,
        const Bytes &hashKey, VBucket &assets)
    {
        return { E_OK, static_cast<uint32_t>(LockStatus::UNLOCK) };
    }

    virtual std::pair<int, uint32_t> GetAssetsByGidOrHashKeyForAsyncDownload(const TableSchema &tableSchema,
        const std::string &gid, const Bytes &hashKey, VBucket &assets)
    {
        return { E_OK, static_cast<uint32_t>(LockStatus::UNLOCK) };
    }

    virtual int SetIAssetLoader([[gnu::unused]] const std::shared_ptr<IAssetLoader> &loader)
    {
        return E_OK;
    }

    virtual int UpdateRecordFlag([[gnu::unused]] const std::string &tableName,
        [[gnu::unused]] bool recordConflict, [[gnu::unused]] const LogInfo &logInfo)
    {
        return E_OK;
    }

    virtual int UpdateRecordFlagForAsyncDownload([[gnu::unused]] const std::string &tableName,
        [[gnu::unused]] bool recordConflict, [[gnu::unused]] const LogInfo &logInfo)
    {
        return E_OK;
    }

    virtual int GetCompensatedSyncQuery([[gnu::unused]] std::vector<QuerySyncObject> &syncQuery,
        [[gnu::unused]] std::vector<std::string> &users, [[gnu::unused]] bool isQueryDownloadRecords)
    {
        return E_OK;
    }

    virtual int ClearUnLockingNoNeedCompensated()
    {
        return E_OK;
    }

    virtual int MarkFlagAsConsistent([[gnu::unused]] const std::string &tableName,
        [[gnu::unused]] const DownloadData &downloadData, [[gnu::unused]] const std::set<std::string> &gidFilters)
    {
        return E_OK;
    }

    virtual int MarkFlagAsAssetAsyncDownload([[gnu::unused]] const std::string &tableName,
        [[gnu::unused]] const DownloadData &downloadData, [[gnu::unused]] const std::set<std::string> &gidFilters)
    {
        return E_OK;
    }

    virtual void SetUser([[gnu::unused]] const std::string &user)
    {
    }

    virtual std::pair<int, CloudSyncData> GetLocalCloudVersion()
    {
        return {E_OK, {}};
    }

    virtual CloudSyncConfig GetCloudSyncConfig() const = 0;

    virtual bool IsTableExistReference(const std::string &table)
    {
        return false;
    }

    virtual bool IsTableExistReferenceOrReferenceBy(const std::string &table)
    {
        return false;
    }

    virtual void ReleaseUploadRecord([[gnu::unused]] const std::string &tableName,
        [[gnu::unused]] const CloudWaterType &type, Timestamp localMark)
    {
    }

    virtual bool IsTagCloudUpdateLocal(const LogInfo &localInfo, const LogInfo &cloudInfo,
        SingleVerConflictResolvePolicy policy)
    {
        return false;
    }

    virtual int ReviseLocalModTime(const std::string &tableName,
        const std::vector<ReviseModTimeInfo> &revisedData)
    {
        return E_OK;
    }

    virtual int GetCursor(const std::string &tableName, uint64_t &cursor)
    {
        cursor = DBConstant::INVALID_CURSOR;
        return -E_NOT_SUPPORT;
    }

    virtual bool IsCurrentLogicDelete() const
    {
        return false;
    }

    virtual int GetLocalDataCount(const std::string &tableName, int &dataCount, int &logicDeleteDataCount) = 0;

    virtual std::pair<int, std::vector<std::string>> GetDownloadAssetTable() = 0;

    virtual std::pair<int, std::vector<std::string>> GetDownloadAssetRecords(const std::string &tableName,
        int64_t beginTime) = 0;

    virtual int GetInfoByPrimaryKeyOrGid(const std::string &tableName, const VBucket &vBucket,
        [[gnu::unused]] bool useTransaction, DataInfoWithLog &dataInfoWithLog, VBucket &assetInfo)
    {
        return GetInfoByPrimaryKeyOrGid(tableName, vBucket, dataInfoWithLog, assetInfo);
    }
};
}

#endif // ICLOUD_SYNC_STORAGE_INTERFACE_H
