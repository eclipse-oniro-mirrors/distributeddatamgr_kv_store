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

#ifndef PROCESS_NOTIFIER_H
#define PROCESS_NOTIFIER_H
#include <map>
#include <string>
#include "db_errno.h"
#include "icloud_syncer.h"
namespace DistributedDB {

class ProcessNotifier {
public:
    // detailCode layout: internal flag | stage(bits 16-21) | error number(bits 0-15)
    static constexpr const uint32_t DETAIL_CODE_STAGE_SHIFT = 16;
    static constexpr const uint32_t DETAIL_CODE_INTERNAL_FLAG = 0x400000;
    static constexpr const uint32_t DETAIL_CODE_NUMBER_MASK = 0xFFFF;

    // stateless detail code helpers shared by all instances
    static uint32_t MakeDetailCode(SyncStage stage, DetailCode code);

    // the entry that stopped the sync, used to enrich the stopped message so the
    // callback tells which interface terminated the tasks
    enum class StopSource {
        NONE = 0, // default: no marker appended, the message stays byte-identical to the base
        REMOVE_DEVICE_DATA, // KV/RDB RemoveDeviceData family (incl. the cloud clean mode)
        STOP_TASK, // RDB StopTask (StopAllBackgroundTask)
        IMPORT, // KV Import: stops the tasks only, without closing the syncer
        TABLE_REFERENCE_CHANGED, // internal: table reference changed
        USER_CHANGE, // internal: user switch
    };

    // the base stopped message, plus a " (stopped by <entry>)" marker when the source is known
    static std::string GetStoppedMessage(StopSource source);

    // a detail code needs the stage stamp when it is an internal code whose stage bits are
    // still empty; external codes and already stamped codes pass through untouched
    static bool NeedsStageStamp(uint32_t detailCode);

    // external detail codes come straight from the cloud adapter (GetErrorDetail) and never
    // carry the internal flag bit
    static bool IsExternalDetailCode(uint32_t detailCode);

    // errno to DetailCode mapping; unmapped errnos (OK/QUERY_END/SKIP etc.) keep detailCode unset
    static uint32_t MapErrnoToDetailNumber(int errCode);

    static const char *GetDetailMsg(DetailCode code);

    // schema messages are composed with the table name at runtime
    static std::string GetDetailMessage(DetailCode code, const std::string &tableName);

    // map errCode to the internal DetailCode when detailCode is unset, then derive the message
    // from the internal detailCode when the message is empty; the stage bits are left empty and
    // are stamped by ProcessNotifier when the detail is written into a CloudErrorInfo
    static void ResolveErrorDetail(int errCode, const std::string &tableName,
        uint32_t &detailCode, std::string &errorMessage);

    explicit ProcessNotifier(ICloudSyncer *syncer);
    ~ProcessNotifier();

    void Init(const std::vector<std::string> &tableName, const std::vector<std::string> &devices,
        const std::vector<std::string> &users);

    void UpdateProcess(const ICloudSyncer::InnerProcessInfo &process);

    void NotifyProcess(const ICloudSyncer::CloudTaskInfo &taskInfo, const ICloudSyncer::InnerProcessInfo &process,
        bool notifyWhenError = false);

    std::vector<std::string> GetDevices() const;

    uint32_t GetUploadBatchIndex(const std::string &tableName) const;

    void ResetUploadBatchIndex(const std::string &tableName);

    void UpdateUploadRetryInfo(const ICloudSyncer::InnerProcessInfo &process);

    void GetLastUploadInfo(const std::string &tableName, Info &lastUploadInfo,
        ICloudSyncer::UploadRetryInfo &retryInfo) const;

    void GetDownloadInfoByTableName(ICloudSyncer::InnerProcessInfo &process);

    void SetUser(const std::string &user);

    void SetAllTableFinish();

    void UpdateAllTablesFinally();

    std::map<std::string, TableProcessInfo> GetCurrentTableProcess() const;

    // the current sync stage is maintained here and stamped into stage-less internal detail codes
    void SetStage(SyncStage stage);

    SyncStage GetStage() const;

    // stamp the maintained stage into a stage-less internal detail code;
    // external codes and already stamped codes pass through untouched
    uint32_t StampStage(uint32_t detailCode);

protected:
    mutable std::mutex processMutex_;
    SyncProcess syncProcess_;
    std::map<std::string, SyncProcess> multiSyncProcess_;
    std::vector<std::string> devices_;
    ICloudSyncer *syncer_;
    std::string user_;
    std::map<std::string, uint32_t> processRetryInfo_;
    SyncStage stage_ = SyncStage::GENERAL;
private:
    void FillProcessInfo(const ICloudSyncer::CloudTaskInfo &taskInfo, const ICloudSyncer::InnerProcessInfo &process);

    static void InitSyncProcess(const std::vector<std::string> &tableName, SyncProcess &syncProcess);
    bool IsMultiUser() const;

    /* update success count of previous upload batch after download retry. */
    void UpdateUploadInfoIfNeeded(const ICloudSyncer::InnerProcessInfo &process);

    void UpdateTableInfoFinally(std::map<std::string, TableProcessInfo> &processInfo);

    void UpdateErrorInfoIfNeed(CloudErrorInfo source, CloudErrorInfo &target) const;

    // overwrite the accumulated detail with the latest task-level error, keeping the
    // accumulated external detail of the batch failure that ended the task
    void UpdateErrorInfoToLatest(const CloudErrorInfo &source, CloudErrorInfo &target) const;

    // clear accumulated error detail when the final result is OK
    static void ResetErrorDetail(CloudErrorInfo &errorInfo);

    // caller must hold processMutex_
    uint32_t StampStageLocked(uint32_t detailCode) const;
};
}
#endif // PROCESS_NOTIFIER_H
