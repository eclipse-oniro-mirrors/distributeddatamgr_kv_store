/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include "cloud_syncer.h"

#include "cloud/icloud_db.h"
#include "db_errno.h"
#include "log_print.h"
#include "store_types.h"

namespace DistributedDB {

// plain whole-triple setter: callers compose one failure's errCode/detailCode/errorMessage
// together, so the three fields never mix different failures; the report policy also lives in
// the callers: SetTaskFailed keeps the first failure of a task (the guard skips an already
// failed task), while SetCurrentTaskFailedWithoutLock takes the latest event (each machine
// fires it once and the teardown unlock failure is intentionally the final word)
void CloudSyncer::SetTaskErrorInfo(ICloudSyncer::CloudTaskInfo &taskInfo, int errCode,
    const std::string &errorMessage, uint32_t detailCode)
{
    taskInfo.errCode = errCode;
    taskInfo.errorMessage = errorMessage;
    taskInfo.detailCode = detailCode;
}

void CloudSyncer::WarnIfExternalCodeCollides(uint32_t detailCode)
{
    // bit22 marks the internal detail code layout; the cloud side guarantees its codes never use
    // it, log the unexpected so a misattributed internal-style message can be located quickly
    if (detailCode != 0u && (detailCode & ProcessNotifier::DETAIL_CODE_INTERNAL_FLAG) != 0u) {
        LOGW("[CloudSyncer] external detailCode 0x%06" PRIx32 " collides with the internal code layout!",
            detailCode);
    }
}

// map errCode to internal DetailCode when detailCode is unset, then derive the message
// from the internal detailCode when the message is empty (the stage bits are stamped by
// the ProcessNotifier when the detail is written into a CloudErrorInfo)
void CloudSyncer::SetTaskFailed(TaskId taskId, int errCode, const std::string &errorMessage,
    uint32_t detailCode, const std::string &tableName)
{
    std::lock_guard<std::mutex> autoLock(dataLock_);
    auto it = cloudTaskInfos_.find(taskId);
    if (it == cloudTaskInfos_.end() || it->second.errCode != E_OK) {
        return;
    }
    std::string msg = errorMessage;
    ProcessNotifier::ResolveErrorDetail(errCode,
        tableName.empty() ? currentContext_.tableName : tableName, detailCode, msg);
    SetTaskErrorInfo(it->second, errCode, msg, StampStageFromNotifierLocked(detailCode));
}

void CloudSyncer::SetCurrentTaskFailedWithoutLock(int errCode, const std::string &errorMessage,
    uint32_t detailCode, const std::string &tableName)
{
    if (currentContext_.currentTaskId == INVALID_TASK_ID ||
        cloudTaskInfos_.find(currentContext_.currentTaskId) == cloudTaskInfos_.end()) {
        return;
    }
    // an echo of the recorded failure carries no new information: the same errno arriving with
    // no detail is a checkpoint re-reporting the task errno (e.g. the upload preprocess aborting
    // a task already failed by the heartbeat), it must not erase the composed detail of the
    // original failure; a new errno or a detail-carrying failure (e.g. the teardown unlock
    // failure with the adapter detail) still wins as the latest event
    auto &taskInfo = cloudTaskInfos_[currentContext_.currentTaskId];
    if (errCode == taskInfo.errCode && taskInfo.detailCode != 0u && detailCode == 0u &&
        errorMessage.empty()) {
        return;
    }
    std::string msg = errorMessage;
    ProcessNotifier::ResolveErrorDetail(errCode,
        tableName.empty() ? currentContext_.tableName : tableName, detailCode, msg);
    SetTaskErrorInfo(taskInfo, errCode, msg, StampStageFromNotifierLocked(detailCode));
}

void CloudSyncer::HeartBeatFailed(TaskId taskId, int errCode, const ErrorDetail &externalDetail)
{
    WarnIfExternalCodeCollides(externalDetail.detailCode);
    {
        std::lock_guard<std::mutex> autoLock(heartbeatMutex_);
        auto it = failedHeartbeatCount_.find(taskId);
        if (it == failedHeartbeatCount_.end()) {
            // the heartbeat data has been removed for a finished task, ignore the stale task id
            return;
        }
        it->second++;
        if (it->second < MAX_HEARTBEAT_FAILED_LIMIT) {
            return;
        }
    }
    LOGW("[CloudSyncer] heartbeat failed too much times!");
    FinishHeartBeatTimer();
    // external detail first, fall back to internal heartbeat-failure detail
    uint32_t detailCode = externalDetail.detailCode != 0u ? externalDetail.detailCode
        : ProcessNotifier::MakeDetailCode(SyncStage::GENERAL, DetailCode::CLOUD_HEARTBEAT_FAILED);
    SetTaskFailed(taskId, errCode, externalDetail.errorMessage, detailCode);
}

void CloudSyncer::RegisterAssetDownloadFailCallback(const AssetDownloadFailCallback &callback)
{
    std::lock_guard<std::mutex> autoLock(assetDownloadFailCallbackMutex_);
    assetDownloadFailCallback_ = callback;
}

void CloudSyncer::NotifyDownloadAssetsFail(const std::string &tableName, const ErrorDetail &errorDetail)
{
    AssetDownloadFailCallback callback;
    {
        std::lock_guard<std::mutex> autoLock(assetDownloadFailCallbackMutex_);
        callback = assetDownloadFailCallback_;
    }
    if (callback) {
        // invoke the callback outside the lock to avoid deadlock
        callback(tableName, errorDetail);
    }
}

// forward the stage switch to the notifier which owns and stamps the stage
void CloudSyncer::SetCurrentStage(SyncStage stage)
{
    std::shared_ptr<ProcessNotifier> notifier;
    {
        std::lock_guard<std::mutex> autoLock(dataLock_);
        notifier = currentContext_.notifier;
    }
    if (notifier != nullptr) {
        notifier->SetStage(stage);
    }
}

uint32_t CloudSyncer::StampDetailStageFromNotifier(uint32_t detailCode) const
{
    if (!ProcessNotifier::NeedsStageStamp(detailCode)) {
        return detailCode;
    }
    std::shared_ptr<ProcessNotifier> notifier;
    {
        std::lock_guard<std::mutex> autoLock(dataLock_);
        notifier = currentContext_.notifier;
    }
    if (notifier == nullptr) {
        return detailCode;
    }
    return notifier->StampStage(detailCode);
}

uint32_t CloudSyncer::StampStageFromNotifierLocked(uint32_t detailCode) const
{
    // caller must hold dataLock_; the lock order dataLock_ -> processMutex_ follows
    // SetCurrentStage, no reverse path exists
    if (!ProcessNotifier::NeedsStageStamp(detailCode)) {
        return detailCode;
    }
    auto notifier = currentContext_.notifier;
    return notifier == nullptr ? detailCode : notifier->StampStage(detailCode);
}

void CloudSyncer::FillCloudErrorInfoFromProxy(int errCode, const ErrorDetail &externalDetail,
    InnerProcessInfo &info) const
{
    // the batch asset operations report the record level failures via the record status and always
    // return E_OK, and the fetch side is status guarded, so a non-empty detail is the real failure
    // report even when errCode says OK; an empty detail on success keeps the early return.
    if ((errCode == E_OK || errCode == -E_QUERY_END) && externalDetail.detailCode == 0u) {
        return;
    }
    WarnIfExternalCodeCollides(externalDetail.detailCode);
    CloudErrorInfo &errorInfo = info.innerCloudErrorInfo;
    if (externalDetail.detailCode != 0u && errorInfo.detailCode == 0u) {
        errorInfo.detailCode = externalDetail.detailCode;
    }
    if (!externalDetail.errorMessage.empty() && errorInfo.errorMessage.empty()) {
        errorInfo.errorMessage = externalDetail.errorMessage;
    }
    ProcessNotifier::ResolveErrorDetail(errCode, info.tableName, errorInfo.detailCode, errorInfo.errorMessage);
    // the stage is stamped by the notifier when the CloudErrorInfo is filled
    errorInfo.detailCode = StampDetailStageFromNotifier(errorInfo.detailCode);
}

ErrorDetail CloudSyncer::GetDownloadFailErrorDetail(int errCode, const std::string &tableName,
    const InnerProcessInfo &info) const
{
    ErrorDetail errorDetail = { info.innerCloudErrorInfo.detailCode, info.innerCloudErrorInfo.errorMessage };
    ProcessNotifier::ResolveErrorDetail(errCode, tableName, errorDetail.detailCode, errorDetail.errorMessage);
    // asset download failures belong to the download stage whatever the current stage is
    if (ProcessNotifier::NeedsStageStamp(errorDetail.detailCode)) {
        errorDetail.detailCode = ProcessNotifier::MakeDetailCode(SyncStage::DOWNLOAD,
            static_cast<DetailCode>(errorDetail.detailCode & ProcessNotifier::DETAIL_CODE_NUMBER_MASK));
    }
    return errorDetail;
}
} // namespace DistributedDB
