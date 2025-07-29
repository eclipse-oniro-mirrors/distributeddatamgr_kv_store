/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include "single_ver_data_sync_utils.h"

#include <mutex>
#include "db_common.h"
#include "version.h"
#include "log_print.h"
#include "message.h"
namespace DistributedDB {
namespace {
void FillPermissionCheckParam(const SyncGenericInterface* storage, int mode, PermissionCheckParam &param, uint8_t &flag)
{
    param.appId = storage->GetDbProperties().GetStringProp(DBProperties::APP_ID, "");
    param.userId = storage->GetDbProperties().GetStringProp(DBProperties::USER_ID, "");
    param.storeId = storage->GetDbProperties().GetStringProp(DBProperties::STORE_ID, "");
    param.instanceId = storage->GetDbProperties().GetIntProp(DBProperties::INSTANCE_ID, 0);
    switch (mode) {
        case SyncModeType::PUSH:
            flag = CHECK_FLAG_RECEIVE;
            break;
        case SyncModeType::PULL:
            flag = CHECK_FLAG_SEND;
            break;
        case SyncModeType::PUSH_AND_PULL:
            flag = CHECK_FLAG_SEND | CHECK_FLAG_RECEIVE;
            break;
        default:
            flag = CHECK_FLAG_RECEIVE;
            break;
    }
}
}

int SingleVerDataSyncUtils::QuerySyncCheck(const SingleVerSyncTaskContext *context, bool &isCheckStatus)
{
    if (context == nullptr) {
        isCheckStatus = false;
        return -E_INVALID_ARGS;
    }
    if (!context->IsQuerySync()) {
        isCheckStatus = true;
        return E_OK;
    }
    uint32_t version = std::min(context->GetRemoteSoftwareVersion(), SOFTWARE_VERSION_CURRENT);
    // for 101 version, no need to do abilitySync, just send request to remote
    if (version <= SOFTWARE_VERSION_RELEASE_1_0) {
        isCheckStatus = true;
        return E_OK;
    }
    if (version < SOFTWARE_VERSION_RELEASE_4_0) {
        LOGE("[SingleVerDataSync] not support query sync when remote ver lower than 104");
        isCheckStatus = false;
        return E_OK;
    }
    if (version < SOFTWARE_VERSION_RELEASE_5_0 && !(context->GetQuery().IsQueryOnlyByKey())) {
        LOGE("[SingleVerDataSync] remote version only support prefix key");
        isCheckStatus = false;
        return E_OK;
    }
    if (context->GetQuery().HasInKeys() && context->IsNotSupportAbility(SyncConfig::INKEYS_QUERY)) {
        isCheckStatus = false;
        return E_OK;
    }
    isCheckStatus = true;
    return E_OK;
}

int SingleVerDataSyncUtils::AckMsgErrnoCheck(const SingleVerSyncTaskContext *context, const Message *message)
{
    if (context == nullptr || message == nullptr) {
        return -E_INVALID_ARGS;
    }
    if (message->IsFeedbackError()) {
        LOGE("[DataSync][AckMsgErrnoCheck] message errNo=%d", message->GetErrorNo());
        return -static_cast<int>(message->GetErrorNo());
    }
    return E_OK;
}

int SingleVerDataSyncUtils::RequestQueryCheck(const DataRequestPacket *packet, SyncGenericInterface *storage)
{
    if (storage == nullptr || packet == nullptr) {
        return -E_INVALID_ARGS;
    }
    if (SyncOperation::GetSyncType(packet->GetMode()) != SyncType::QUERY_SYNC_TYPE) {
        return E_OK;
    }
    QuerySyncObject syncQuery = packet->GetQuery();
    int errCode = storage->CheckAndInitQueryCondition(syncQuery);
    if (errCode != E_OK) {
        LOGE("[SingleVerDataSync] check sync query failed,errCode=%d", errCode);
        return errCode;
    }
    return E_OK;
}

bool SingleVerDataSyncUtils::IsPermitLocalDeviceRecvData(const std::string &deviceId,
    const SecurityOption &remoteSecOption)
{
    return RuntimeContext::GetInstance()->CheckDeviceSecurityAbility(deviceId, remoteSecOption);
}

bool SingleVerDataSyncUtils::IsPermitRemoteDeviceRecvData(const std::string &deviceId,
    const SecurityOption &remoteSecOption, SyncGenericInterface *storage)
{
    if (storage == nullptr) {
        return false;
    }
    SecurityOption localSecOption;
    if (remoteSecOption.securityLabel == NOT_SUPPORT_SEC_CLASSIFICATION) {
        return true;
    }
    int errCode = storage->GetSecurityOption(localSecOption);
    if (errCode == -E_NOT_SUPPORT) {
        return true;
    }
    if (errCode != E_OK) {
        LOGE("[SingleVerDataSyncUtils] get security option error %d", errCode);
        return false;
    }
    if (localSecOption.securityLabel == NOT_SET) {
        LOGE("[SingleVerDataSyncUtils] local label is not set!");
        return false;
    }
    return RuntimeContext::GetInstance()->CheckDeviceSecurityAbility(deviceId, localSecOption);
}

void SingleVerDataSyncUtils::TransDbDataItemToSendDataItem(const std::string &localHashName,
    std::vector<SendDataItem> &outData)
{
    for (size_t i = 0; i < outData.size(); i++) {
        if (outData[i] == nullptr) {
            continue;
        }
        outData[i]->SetOrigDevice(outData[i]->GetOrigDevice().empty() ? localHashName : outData[i]->GetOrigDevice());
        if (i == 0 || i == (outData.size() - 1)) {
            LOGD("[DataSync][TransToSendItem] printData packet=%zu,timestamp=%" PRIu64 ",flag=%" PRIu64, i,
                outData[i]->GetTimestamp(), outData[i]->GetFlag());
        }
    }
}

std::string SingleVerDataSyncUtils::TransferForeignOrigDevName(const std::string &deviceName,
    const std::string &localHashName)
{
    if (localHashName == deviceName) {
        return "";
    }
    return deviceName;
}

void SingleVerDataSyncUtils::TransSendDataItemToLocal(const SingleVerSyncTaskContext *context,
    const std::string &localHashName, const std::vector<SendDataItem> &data)
{
    TimeOffset offset = context->GetTimeOffset();
    for (auto &item : data) {
        if (item == nullptr) {
            continue;
        }
        item->SetOrigDevice(TransferForeignOrigDevName(item->GetOrigDevice(), localHashName));
        Timestamp tempTimestamp = item->GetTimestamp();
        Timestamp tempWriteTimestamp = item->GetWriteTimestamp();
        item->SetTimestamp(tempTimestamp - static_cast<Timestamp>(offset));
        if (tempWriteTimestamp != 0) {
            item->SetWriteTimestamp(tempWriteTimestamp - static_cast<Timestamp>(offset));
        }

        Timestamp currentLocalTime = context->GetCurrentLocalTime();
        if (item->GetTimestamp() > currentLocalTime) {
            item->SetTimestamp(currentLocalTime);
        }
        if (item->GetWriteTimestamp() > currentLocalTime) {
            item->SetWriteTimestamp(currentLocalTime);
        }
    }
}

void SingleVerDataSyncUtils::TranslateErrCodeIfNeed(int mode, uint32_t version, int &errCode)
{
    // once get data occur E_EKEYREVOKED error, should also send request to remote dev to pull data.
    if (SyncOperation::TransferSyncMode(mode) == SyncModeType::PUSH_AND_PULL &&
        version > SOFTWARE_VERSION_RELEASE_2_0 && errCode == -E_EKEYREVOKED) {
        errCode = E_OK;
    }
}

int SingleVerDataSyncUtils::RunPermissionCheck(SingleVerSyncTaskContext *context, const SyncGenericInterface* storage,
    const std::string &label, const DataRequestPacket *packet)
{
    int mode = SyncOperation::TransferSyncMode(packet->GetMode());
    return RunPermissionCheckInner(context, storage, label, packet, mode);
}

int SingleVerDataSyncUtils::RunPermissionCheck(SingleVerSyncTaskContext *context, const SyncGenericInterface* storage,
    const std::string &label, int mode)
{
    return RunPermissionCheckInner(context, storage, label, nullptr, mode);
}

bool SingleVerDataSyncUtils::CheckPermitReceiveData(const SingleVerSyncTaskContext *context,
    const ICommunicator *communicator, const SyncGenericInterface *storage)
{
    if (storage == nullptr) {
        LOGE("[SingleVerDataSyncUtils] storage is nullptr when check receive data");
        return false;
    }
    // check memory db here because remote maybe low version
    // it will send option with not set rather than not support when remote is memory db
    bool memory = storage->GetDbProperties().GetBoolProp(KvDBProperties::MEMORY_MODE, false);
    if (memory) {
        LOGI("[SingleVerDataSyncUtils] skip check receive data because local is memory db");
        return true;
    }
    SecurityOption remoteSecOption = context->GetRemoteSeccurityOption();
    std::string localDeviceId;
    if (communicator == nullptr || remoteSecOption.securityLabel == NOT_SUPPORT_SEC_CLASSIFICATION) {
        return true;
    }
    communicator->GetLocalIdentity(localDeviceId);
    SecurityOption localOption;
    int errCode = storage->GetSecurityOption(localOption);
    if (errCode == -E_NOT_SUPPORT) {
        LOGD("[SingleVerDataSyncUtils] local not support get security label");
        return true;
    }
    if (errCode == E_OK && localOption.securityLabel == SecurityLabel::NOT_SET) {
        LOGE("[SingleVerDataSyncUtils] local label is not set!");
        return false;
    }
    if (remoteSecOption.securityLabel == SecurityLabel::S0 && localOption.securityLabel == SecurityLabel::S1) {
        remoteSecOption.securityLabel = SecurityLabel::S1;
        LOGI("[SingleVerDataSyncUtils] Transform Remote SecLabel From S0 To S1 When Receive Data");
    }
    if (remoteSecOption.securityLabel == FAILED_GET_SEC_CLASSIFICATION) {
        LOGE("[SingleVerDataSyncUtils] remote label get failed!");
        return false;
    }
    if (remoteSecOption.securityLabel != SecurityLabel::NOT_SET &&
        remoteSecOption.securityLabel != localOption.securityLabel) {
        LOGE("[SingleVerDataSyncUtils] label is not equal remote %d local %d", remoteSecOption.securityLabel,
            localOption.securityLabel);
        return false;
    }
    bool isPermitSync = SingleVerDataSyncUtils::IsPermitLocalDeviceRecvData(localDeviceId, remoteSecOption);
    if (isPermitSync) {
        return isPermitSync;
    }
    LOGE("[SingleVerDataSyncUtils][PermitReceiveData] check failed: permitReceive=%d, localDev=%s, seclabel=%d,"
        " secflag=%d", isPermitSync, STR_MASK(localDeviceId), remoteSecOption.securityLabel,
        remoteSecOption.securityFlag);
    return isPermitSync;
}

void SingleVerDataSyncUtils::SetPacketId(DataRequestPacket *packet, SingleVerSyncTaskContext *context, uint32_t version)
{
    if (version > SOFTWARE_VERSION_RELEASE_2_0) {
        context->IncPacketId(); // begin from 1
        std::vector<uint64_t> reserved {context->GetPacketId()};
        packet->SetReserved(reserved);
    }
}

int SingleVerDataSyncUtils::GetMessageId(SyncType syncType)
{
    if (syncType == SyncType::QUERY_SYNC_TYPE) {
        return QUERY_SYNC_MESSAGE;
    }
    return DATA_SYNC_MESSAGE;
}

void SingleVerDataSyncUtils::PushAndPullKeyRevokHandle(SingleVerSyncTaskContext *context)
{
    // for push_and_pull mode it may be EKEYREVOKED error before receive watermarkexception
    // should clear errCode and restart pushpull request.
    int mode = SyncOperation::TransferSyncMode(context->GetMode());
    if (context->GetRemoteSoftwareVersion() > SOFTWARE_VERSION_RELEASE_2_0 && mode == SyncModeType::PUSH_AND_PULL &&
        context->GetTaskErrCode() == -E_EKEYREVOKED) {
        context->SetTaskErrCode(E_OK);
    }
}

int SingleVerDataSyncUtils::GetReSendMode(int mode, uint32_t sequenceId, SyncType syncType)
{
    int curMode = SyncOperation::TransferSyncMode(mode);
    if (curMode == SyncModeType::PUSH || curMode == SyncModeType::PULL) {
        return mode;
    }
    if (curMode == SyncModeType::RESPONSE_PULL) {
        return (syncType == SyncType::QUERY_SYNC_TYPE) ? SyncModeType::QUERY_PUSH : SyncModeType::PUSH;
    }
    // set push_and_pull mode when resend first sequenceId to inform remote to run RESPONSE_PULL task
    // for sequenceId which is larger than first, only need to send data, means to set push or query_push mode
    if (sequenceId == 1) {
        return (syncType == SyncType::QUERY_SYNC_TYPE) ? SyncModeType::QUERY_PUSH_PULL : SyncModeType::PUSH_AND_PULL;
    }
    return (syncType == SyncType::QUERY_SYNC_TYPE) ? SyncModeType::QUERY_PUSH : SyncModeType::PUSH;
}

void SingleVerDataSyncUtils::FillControlRequestPacket(ControlRequestPacket *packet, SingleVerSyncTaskContext *context)
{
    uint32_t version = std::min(context->GetRemoteSoftwareVersion(), SOFTWARE_VERSION_CURRENT);
    uint32_t flag = 0;
    if (context->GetMode() == SyncModeType::SUBSCRIBE_QUERY && context->IsAutoSubscribe()) {
        flag = SubscribeRequest::IS_AUTO_SUBSCRIBE;
    }
    packet->SetPacketHead(E_OK, version, GetControlCmdType(context->GetMode()), flag);
    packet->SetQuery(context->GetQuery());
}

ControlCmdType SingleVerDataSyncUtils::GetControlCmdType(int mode)
{
    if (mode == SyncModeType::SUBSCRIBE_QUERY) {
        return ControlCmdType::SUBSCRIBE_QUERY_CMD;
    } else if  (mode == SyncModeType::UNSUBSCRIBE_QUERY) {
        return ControlCmdType::UNSUBSCRIBE_QUERY_CMD;
    }
    return ControlCmdType::INVALID_CONTROL_CMD;
}

int SingleVerDataSyncUtils::GetModeByControlCmdType(ControlCmdType controlCmd)
{
    if (controlCmd == ControlCmdType::SUBSCRIBE_QUERY_CMD) {
        return SyncModeType::SUBSCRIBE_QUERY;
    } else if  (controlCmd == ControlCmdType::UNSUBSCRIBE_QUERY_CMD) {
        return SyncModeType::UNSUBSCRIBE_QUERY;
    }
    return SyncModeType::INVALID_MODE;
}

bool SingleVerDataSyncUtils::IsNeedTriggerQueryAutoSync(Message *inMsg, QuerySyncObject &query)
{
    if (inMsg == nullptr) {
        return false;
    }
    if (inMsg->GetMessageId() != CONTROL_SYNC_MESSAGE || inMsg->GetMessageType() != TYPE_REQUEST) {
        return false;
    }
    auto packet = inMsg->GetObject<SubscribeRequest>();
    if (packet == nullptr) {
        return false;
    }
    uint32_t controlCmdType = packet->GetcontrolCmdType();
    if (controlCmdType == ControlCmdType::SUBSCRIBE_QUERY_CMD) {
        query = packet->GetQuery();
        LOGI("[SingleVerDataSync] receive sub scribe query cmd,begin to trigger query auto sync");
        return true;
    }
    return false;
}

void SingleVerDataSyncUtils::ControlAckErrorHandle(const SingleVerSyncTaskContext *context,
    const std::shared_ptr<SubscribeManager> &subManager)
{
    if (context->GetMode() == SyncModeType::SUBSCRIBE_QUERY) {
        // reserve before need clear
        subManager->DeleteLocalSubscribeQuery(context->GetDeviceId(), context->GetQuery());
    }
}

void SingleVerDataSyncUtils::SetMessageHeadInfo(Message &message, uint16_t inMsgType, const std::string &inTarget,
    uint32_t inSequenceId, uint32_t inSessionId)
{
    message.SetMessageType(inMsgType);
    message.SetTarget(inTarget);
    message.SetSequenceId(inSequenceId);
    message.SetSessionId(inSessionId);
}

bool SingleVerDataSyncUtils::IsGetDataSuccessfully(int errCode)
{
    return (errCode == E_OK || errCode == -E_UNFINISHED);
}

Timestamp SingleVerDataSyncUtils::GetMaxSendDataTime(const std::vector<SendDataItem> &inData)
{
    Timestamp stamp = 0;
    for (size_t i = 0; i < inData.size(); i++) {
        if (inData[i] == nullptr) {
            continue;
        }
        Timestamp tempStamp = inData[i]->GetTimestamp();
        if (stamp < tempStamp) {
            stamp = tempStamp;
        }
    }
    return stamp;
}

SyncTimeRange SingleVerDataSyncUtils::GetFullSyncDataTimeRange(const std::vector<SendDataItem> &inData,
    WaterMark localMark, UpdateWaterMark &isUpdate)
{
    Timestamp maxTimestamp = localMark;
    Timestamp minTimestamp = localMark;
    for (size_t i = 0; i < inData.size(); i++) {
        if (inData[i] == nullptr) {
            continue;
        }
        Timestamp tempStamp = inData[i]->GetTimestamp();
        if (maxTimestamp < tempStamp) {
            maxTimestamp = tempStamp;
        }
        if (minTimestamp > tempStamp) {
            minTimestamp = tempStamp;
        }
        isUpdate.normalUpdateMark = true;
    }
    return {minTimestamp, 0, maxTimestamp, 0};
}

SyncTimeRange SingleVerDataSyncUtils::GetQuerySyncDataTimeRange(const std::vector<SendDataItem> &inData,
    WaterMark localMark, WaterMark deleteLocalMark, UpdateWaterMark &isUpdate)
{
    SyncTimeRange dataTimeRange = {localMark, deleteLocalMark, localMark, deleteLocalMark};
    for (size_t i = 0; i < inData.size(); i++) {
        if (inData[i] == nullptr) {
            continue;
        }
        Timestamp tempStamp = inData[i]->GetTimestamp();
        if ((inData[i]->GetFlag() & DataItem::DELETE_FLAG) == 0) { // query data
            if (dataTimeRange.endTime < tempStamp) {
                dataTimeRange.endTime = tempStamp;
            }
            if (dataTimeRange.beginTime > tempStamp) {
                dataTimeRange.beginTime = tempStamp;
            }
            isUpdate.normalUpdateMark = true;
        }
        if ((inData[i]->GetFlag() & DataItem::DELETE_FLAG) != 0) { // delete data
            if (dataTimeRange.deleteEndTime < tempStamp) {
                dataTimeRange.deleteEndTime = tempStamp;
            }
            if (dataTimeRange.deleteBeginTime > tempStamp) {
                dataTimeRange.deleteBeginTime = tempStamp;
            }
            isUpdate.deleteUpdateMark = true;
        }
    }
    return dataTimeRange;
}

SyncTimeRange SingleVerDataSyncUtils::ReviseLocalMark(SyncType syncType, const SyncTimeRange &dataTimeRange,
    UpdateWaterMark updateMark)
{
    SyncTimeRange tmpDataTime = dataTimeRange;
    if (updateMark.deleteUpdateMark && syncType == SyncType::QUERY_SYNC_TYPE) {
        tmpDataTime.deleteEndTime += 1;
    }
    if (updateMark.normalUpdateMark) {
        tmpDataTime.endTime += 1;
    }
    return tmpDataTime;
}

SyncTimeRange SingleVerDataSyncUtils::GetRecvDataTimeRange(SyncType syncType,
    const std::vector<SendDataItem> &data, UpdateWaterMark &isUpdate)
{
    if (syncType != SyncType::QUERY_SYNC_TYPE) {
        return SingleVerDataSyncUtils::GetFullSyncDataTimeRange(data, 0, isUpdate);
    }
    return SingleVerDataSyncUtils::GetQuerySyncDataTimeRange(data, 0, 0, isUpdate);
}

SyncTimeRange SingleVerDataSyncUtils::GetSyncDataTimeRange(SyncType syncType, WaterMark localMark, WaterMark deleteMark,
    const std::vector<SendDataItem> &inData, UpdateWaterMark &isUpdate)
{
    if (syncType != SyncType::QUERY_SYNC_TYPE) {
        return SingleVerDataSyncUtils::GetFullSyncDataTimeRange(inData, localMark, isUpdate);
    }
    return SingleVerDataSyncUtils::GetQuerySyncDataTimeRange(inData, localMark, deleteMark, isUpdate);
}

int SingleVerDataSyncUtils::RunPermissionCheckInner(const SingleVerSyncTaskContext *context,
    const SyncGenericInterface* storage, const std::string &label, const DataRequestPacket *packet, int mode)
{
    PermissionCheckParam param;
    uint8_t flag = 0u;
    FillPermissionCheckParam(storage, mode, param, flag);
    param.deviceId = context->GetDeviceId();
    if (packet != nullptr) {
        param.extraConditions = packet->GetExtraConditions();
    }
    int errCode = RuntimeContext::GetInstance()->RunPermissionCheck(param, flag);
    if (errCode != E_OK) {
        LOGE("[DataSync][RunPermissionCheck] check failed flag=%" PRIu8 ",dev=%s", flag,
            STR_MASK(context->GetDeviceId()));
    }
    return errCode;
}

std::pair<TimeOffset, TimeOffset> SingleVerDataSyncUtils::GetTimeOffsetFromRequestMsg(const Message *message)
{
    std::pair<TimeOffset, TimeOffset> res;
    auto &[systemOffset, senderLocalOffset] = res;
    const DataRequestPacket *packet = message->GetObject<DataRequestPacket>();
    if (packet == nullptr) {
        systemOffset = 0;
        senderLocalOffset = 0;
        return res;
    }
    systemOffset = packet->GetSystemTimeOffset();
    senderLocalOffset = packet->GetSenderTimeOffset();
    return res;
}

void SingleVerDataSyncUtils::RecordClientId(const SingleVerSyncTaskContext &context,
    const SyncGenericInterface &storage, std::shared_ptr<Metadata> &metadata)
{
    StoreInfo info = {
        storage.GetDbProperties().GetStringProp(DBProperties::USER_ID, ""),
        storage.GetDbProperties().GetStringProp(DBProperties::APP_ID, ""),
        storage.GetDbProperties().GetStringProp(DBProperties::STORE_ID, "")
    };
    std::string clientId;
    if (RuntimeContext::GetInstance()->TranslateDeviceId(context.GetDeviceId(), info, clientId) == E_OK) {
        int errCode = metadata->SaveClientId(context.GetDeviceId(), clientId);
        if (errCode != E_OK) {
            LOGW("[DataSync] record clientId failed %d", errCode);
        }
    }
}

void SingleVerDataSyncUtils::SetDataRequestCommonInfo(const SingleVerSyncTaskContext &context,
    const SyncGenericInterface &storage, DataRequestPacket &packet, std::shared_ptr<Metadata> &metadata)
{
    packet.SetSenderTimeOffset(metadata->GetLocalTimeOffset());
    packet.SetSystemTimeOffset(metadata->GetSystemTimeOffset(context.GetDeviceId(), context.GetTargetUserId()));
    if (context.GetRemoteSoftwareVersion() < SOFTWARE_VERSION_RELEASE_9_0) {
        return;
    }
    auto [err, localSchemaVer] = metadata->GetLocalSchemaVersion();
    if (err != E_OK) {
        LOGW("[DataSync] get local schema version failed:%d", err);
        return;
    }
    packet.SetSchemaVersion(localSchemaVer);
    SecurityOption localOption;
    err = storage.GetSecurityOption(localOption);
    if (err == -E_NOT_SUPPORT) {
        LOGW("[DataSync] local not support sec classification");
        localOption.securityLabel = NOT_SUPPORT_SEC_CLASSIFICATION;
    } else if (err != E_OK) {
        LOGE("[DataSync] get local security option errCode:%d", err);
        localOption.securityLabel = FAILED_GET_SEC_CLASSIFICATION;
    }
    packet.SetSecurityOption(localOption);
}

int SingleVerDataSyncUtils::SchemaVersionMatchCheck(const SingleVerSyncTaskContext &context,
    const DataRequestPacket &packet, std::shared_ptr<Metadata> &metadata)
{
    if (context.GetRemoteSoftwareVersion() < SOFTWARE_VERSION_RELEASE_9_0) {
        return E_OK;
    }
    auto remoteSchemaVersion = metadata->GetRemoteSchemaVersion(context.GetDeviceId(), context.GetTargetUserId());
    if (remoteSchemaVersion != packet.GetSchemaVersion()) {
        LOGE("[DataSync] remote schema version misMatch, need ability sync again, packet %" PRIu64 " cache %" PRIu64,
             packet.GetSchemaVersion(), remoteSchemaVersion);
        return -E_NEED_ABILITY_SYNC;
    }
    return E_OK;
}

int SingleVerDataSyncUtils::GetUnsyncTotal(const SingleVerSyncTaskContext *context, const SyncGenericInterface *storage,
    uint32_t &total)
{
    SyncTimeRange waterRange;
    WaterMark startMark = context->GetInitWaterMark();
    if ((waterRange.endTime == 0) || (startMark > waterRange.endTime)) {
        return E_OK;
    }

    waterRange.beginTime = startMark;
    waterRange.deleteBeginTime = context->GetInitDeletedMark();
    return GetUnsyncTotal(context, storage, waterRange, total);
}

int SingleVerDataSyncUtils::GetUnsyncTotal(const SingleVerSyncTaskContext *context, const SyncGenericInterface *storage,
    SyncTimeRange &waterMarkInfo, uint32_t &total)
{
    int errCode = E_OK;
    SyncType curType = (context->IsQuerySync() ? SyncType::QUERY_SYNC_TYPE : SyncType::MANUAL_FULL_SYNC_TYPE);
    if (curType != SyncType::QUERY_SYNC_TYPE) {
        errCode = storage->GetUnSyncTotal(waterMarkInfo.beginTime, waterMarkInfo.endTime, total);
    } else {
        QuerySyncObject queryObj = context->GetQuery();
        errCode = storage->GetUnSyncTotal(queryObj, waterMarkInfo, total);
    }
    if (errCode != E_OK) {
        LOGE("[DataSync][GetUnsyncTotal] Get unsync data num failed, errCode=%d", errCode);
    }
    return errCode;
}

bool SingleVerDataSyncUtils::IsSupportRequestTotal(uint32_t version)
{
    return version >= SOFTWARE_VERSION_RELEASE_10_0;
}

void SingleVerDataSyncUtils::UpdateSyncProcess(SingleVerSyncTaskContext *context, const DataRequestPacket *packet)
{
    const std::vector<SendDataItem> &data = packet->GetData();
    int32_t dataSize = std::count_if(data.begin(), data.end(), [](SendDataItem item) {
        return (item->GetFlag() & DataItem::REMOTE_DEVICE_DATA_MISS_QUERY) == 0;
    });
    if (dataSize < 0) {
        return;
    }

    LOGD("[DataSync][UpdateSyncProcess] mode=%d, total=%" PRIu64 ", size=%d", packet->GetMode(),
        packet->GetTotalDataCount(), dataSize);
    if (packet->GetMode() == SyncModeType::PUSH || packet->GetMode() == SyncModeType::QUERY_PUSH) {
        // save total count to sync process
        if (packet->GetTotalDataCount() > 0) {
            context->SetOperationSyncProcessTotal(context->GetDeviceId(), packet->GetTotalDataCount());
        }
        context->UpdateOperationFinishedCount(context->GetDeviceId(), static_cast<uint32_t>(dataSize));
    }
}

void SingleVerDataSyncUtils::CacheInitWaterMark(SingleVerSyncTaskContext *context, SingleVerDataSync *dataSync)
{
    SyncType curType = (context->IsQuerySync() ? SyncType::QUERY_SYNC_TYPE : SyncType::MANUAL_FULL_SYNC_TYPE);
    WaterMark startMark = 0;
    dataSync->GetLocalWaterMark(curType, context->GetQuerySyncId(), context, startMark);
    context->SetInitWaterMark(startMark);

    WaterMark deletedMark = 0;
    dataSync->GetLocalDeleteSyncWaterMark(context, deletedMark);
    context->SetInitDeletedMark(deletedMark);
    LOGI("[SingleVerDataSync][CacheInitWaterMark] startMark %" PRIu64 " deletedMark %" PRIu64, startMark, deletedMark);
}

QuerySyncObject SingleVerDataSyncUtils::GetQueryFromDataRequest(const DataRequestPacket &packet,
    const SingleVerSyncTaskContext &context, uint32_t sessionId)
{
    auto query = packet.GetQuery();
    query.SetRemoteDev(context.GetDeviceId());
    query.SetUseLocalSchema(sessionId == context.GetRequestSessionId());
    return query;
}
}