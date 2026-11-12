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
#define LOG_TAG "StoreManager"
#include "store_manager.h"

#include <algorithm>

#include "backup_manager.h"
#include "dev_manager.h"
#include "kvdb_service_client.h"
#include "kvstore_service_death_notifier.h"
#include "log_print.h"
#include "runtime_config.h"
#include "security_manager.h"

#include "store_util.h"
#include "task_executor.h"
namespace OHOS::DistributedKv {
namespace {
constexpr int32_t AFTER_CREATE_MAX_RETRY = 3;
constexpr int32_t AFTER_CREATE_RETRY_DELAY_MS = 100;
constexpr uint32_t AFTER_CREATE_WAIT_INTERVAL = 2000;
}

bool IsRetryableStatus(Status status)
{
    return status == IPC_ERROR || status == SERVER_UNAVAILABLE || status == IPC_PARCEL_ERROR;
}

void ClearPassword(std::vector<uint8_t> &password)
{
    std::fill(password.begin(), password.end(), 0);
}
StoreManager &StoreManager::GetInstance()
{
    static StoreManager instance;
    return instance;
}

bool StoreManager::CleanUp()
{
    if (KVDBServiceClient::CleanUp()) {
        DistributedDB::RuntimeConfig::Clean();
        return true;
    }
    return false;
}

std::shared_ptr<SingleKvStore> StoreManager::GetKVStore(const AppId &appId, const StoreId &storeId,
    const Options &options, Status &status)
{
    std::string path = options.GetDatabaseDir();
    ZLOGD("appId:%{public}s, storeId:%{public}s type:%{public}d area:%{public}d dir:%{public}s", appId.appId.c_str(),
        StoreUtil::Anonymous(storeId.storeId).c_str(), options.kvStoreType, options.area,
        StoreUtil::Anonymous(path).c_str());
    status = ILLEGAL_STATE;
    if (!appId.IsValid() || !storeId.IsValid() || !options.IsValidType()) {
        ZLOGE("Params invalid type");
        status = INVALID_ARGUMENT;
        return nullptr;
    }
    WaitAfterCreate(appId, storeId);
    auto service = KVDBServiceClient::GetInstance();
    if (service != nullptr) {
        status = service->BeforeCreate(appId, storeId, options);
    }
    if (status == STORE_META_CHANGED) {
        ReportInfo reportInfo = { .options = options, .errorCode = status, .systemErrorNo = errno,
            .appId = appId.appId, .storeId = storeId.storeId, .functionName = std::string(__FUNCTION__) };
        KVDBFaultHiViewReporter::ReportKVFaultEvent(reportInfo);
        ZLOGE("appId:%{public}s, storeId:%{public}s type:%{public}d encrypt:%{public}d", appId.appId.c_str(),
            StoreUtil::Anonymous(storeId.storeId).c_str(), options.kvStoreType, options.encrypt);
        return nullptr;
    }
    StoreParams storeParams;
    auto kvStore = StoreFactory::GetInstance().GetOrOpenStore(appId, storeId, options, status, storeParams);
    if ((status == DATA_CORRUPTED || status == CRYPT_ERROR) && options.encrypt) {
        kvStore = OpenWithSecretKeyFromService(appId, storeId, options, status, storeParams);
    }
    if (status != SUCCESS) {
        ReportInfo reportInfo = { .options = options, .errorCode = status, .systemErrorNo = errno,
            .appId = appId.appId, .storeId = storeId.storeId, .functionName = std::string(__FUNCTION__) };
        KVDBFaultHiViewReporter::ReportKVFaultEvent(reportInfo);
    } else if (kvStore != nullptr && kvStore->IsRebuild()) {
        ReportInfo reportInfo = { .options = options, .errorCode = status, .systemErrorNo = errno,
            .appId = appId.appId, .storeId = storeId.storeId, .functionName = std::string(__FUNCTION__) };
        ZLOGI("Rebuild store success, storeId:%{public}s", StoreUtil::Anonymous(storeId.storeId).c_str());
        KVDBFaultHiViewReporter::ReportKVRebuildEvent(reportInfo);
    }
    SubmitAfterCreate(appId, storeId, options, service, storeParams);
    return kvStore;
}

std::shared_ptr<SingleKvStore> StoreManager::OpenWithSecretKeyFromService(const AppId &appId, const StoreId &storeId,
    const Options &options, Status &status, StoreParams &storeParams)
{
    std::shared_ptr<SingleKvStore> kvStore;
    std::vector<std::vector<uint8_t>> keys;
    std::string baseDir = options.baseDir;
    BackupInfo info = { .name = storeId.storeId, .baseDir = baseDir, .appId = appId.appId,
        .storeId = storeId.storeId, .subUser = options.subUser, .isCustomDir = options.isCustomDir };
    if (BackupManager::GetInstance().GetSecretKeyFromService(appId, storeId, keys, info) != Status::SUCCESS) {
        for (auto &key : keys) {
            key.assign(key.size(), 0);
        }
        return kvStore;
    }
    std::string path = options.GetDatabaseDir();
    for (auto &key : keys) {
        SecurityManager::DBPassword dbPassword;
        dbPassword.SetValue(key.data(), key.size());
        SecurityManager::GetInstance().SaveDBPassword(storeId.storeId, path, dbPassword.password);
        kvStore = StoreFactory::GetInstance().GetOrOpenStore(appId, storeId, options, status, storeParams);
        if (status == SUCCESS) {
            break;
        }
    }
    for (auto &key : keys) {
        key.assign(key.size(), 0);
    }
    return kvStore;
}

Status StoreManager::CloseKVStore(const AppId &appId, const StoreId &storeId, int32_t subUser)
{
    ZLOGD("appId:%{public}s, storeId:%{public}s", appId.appId.c_str(), StoreUtil::Anonymous(storeId.storeId).c_str());
    if (!appId.IsValid() || !storeId.IsValid()) {
        return INVALID_ARGUMENT;
    }

    return StoreFactory::GetInstance().Close(appId, storeId, subUser);
}

Status StoreManager::CloseKVStore(const AppId &appId, const StoreId &storeId, const std::string &path)
{
    ZLOGD("appId:%{public}s, storeId:%{public}s", appId.appId.c_str(), StoreUtil::Anonymous(storeId.storeId).c_str());
    if (!appId.IsValid() || !storeId.IsValid() || path.empty()) {
        ZLOGE("Invalid appId, storeId or path is empty.");
        return INVALID_ARGUMENT;
    }

    return StoreFactory::GetInstance().Close(appId, storeId, path);
}

Status StoreManager::CloseAllKVStore(const AppId &appId, int32_t subUser)
{
    ZLOGD("appId:%{public}s", appId.appId.c_str());
    if (!appId.IsValid()) {
        return INVALID_ARGUMENT;
    }

    return StoreFactory::GetInstance().Close(appId, { "" }, subUser, true);
}

Status StoreManager::GetStoreIds(const AppId &appId, std::vector<StoreId> &storeIds, int32_t subUser)
{
    ZLOGD("appId:%{public}s", appId.appId.c_str());
    if (!appId.IsValid()) {
        return INVALID_ARGUMENT;
    }
    WaitAllAfterCreate(appId);
    auto service = KVDBServiceClient::GetInstance();
    if (service == nullptr) {
        return SERVER_UNAVAILABLE;
    }
    return service->GetStoreIds(appId, subUser, storeIds);
}

Status StoreManager::Delete(const AppId &appId, const StoreId &storeId, const std::string &path, int32_t subUser)
{
    ZLOGD("appId:%{public}s, storeId:%{public}s dir:%{public}s", appId.appId.c_str(),
        StoreUtil::Anonymous(storeId.storeId).c_str(), StoreUtil::Anonymous(path).c_str());
    if (!appId.IsValid() || !storeId.IsValid()) {
        return INVALID_ARGUMENT;
    }
    WaitAfterCreate(appId, storeId);
    auto service = KVDBServiceClient::GetInstance();
    if (service != nullptr) {
        service->Delete(appId, storeId, subUser);
    }
    auto status = StoreFactory::GetInstance().Delete(appId, storeId, path, subUser);
    ReportInfo reportInfo = { .options = { .baseDir = path }, .errorCode = status, .systemErrorNo = errno,
        .appId = appId.appId, .storeId = storeId.storeId, .functionName = std::string(__FUNCTION__) };
    if (status != SUCCESS) {
        KVDBFaultHiViewReporter::ReportKVFaultEvent(reportInfo);
    } else {
        KVDBFaultHiViewReporter::ReportKVRebuildEvent(reportInfo);
    }
    return status;
}

Status StoreManager::Delete(const AppId &appId, const StoreId &storeId, const Options &options)
{
    ZLOGD("appId:%{public}s, storeId:%{public}s dir:%{public}s", appId.appId.c_str(),
        StoreUtil::Anonymous(storeId.storeId).c_str(), StoreUtil::Anonymous(options.baseDir).c_str());
    if (!appId.IsValid() || !storeId.IsValid()) {
        return INVALID_ARGUMENT;
    }
    WaitAfterCreate(appId, storeId);
    auto service = KVDBServiceClient::GetInstance();
    if (service != nullptr) {
        service->Delete(appId, storeId, options);
    }
    auto status = StoreFactory::GetInstance().Delete(appId, storeId, options.baseDir, options.subUser);
    ReportInfo reportInfo = { .options = { .baseDir = options.baseDir }, .errorCode = status, .systemErrorNo = errno,
        .appId = appId.appId, .storeId = storeId.storeId, .functionName = std::string(__FUNCTION__) };
    if (status != SUCCESS) {
        KVDBFaultHiViewReporter::ReportKVFaultEvent(reportInfo);
    } else {
        KVDBFaultHiViewReporter::ReportKVRebuildEvent(reportInfo);
    }
    return status;
}

Status StoreManager::PutSwitch(const AppId &appId, const SwitchData &data)
{
    ZLOGD("appId:%{public}s, value len:%{public}u", appId.appId.c_str(), data.length);
    if (!appId.IsValid()) {
        return INVALID_ARGUMENT;
    }
    auto service = KVDBServiceClient::GetInstance();
    if (service == nullptr) {
        return SERVER_UNAVAILABLE;
    }
    return service->PutSwitch(appId, data);
}

std::pair<Status, SwitchData> StoreManager::GetSwitch(const AppId &appId, const std::string &networkId)
{
    ZLOGD("appId:%{public}s, networkId:%{public}s", appId.appId.c_str(), StoreUtil::Anonymous(networkId).c_str());
    if (!appId.IsValid() || networkId.empty()) {
        return { INVALID_ARGUMENT, SwitchData() };
    }
    auto service = KVDBServiceClient::GetInstance();
    if (service == nullptr) {
        return { SERVER_UNAVAILABLE, SwitchData() };
    }
    SwitchData data;
    auto status = service->GetSwitch(appId, networkId, data);
    return { status, std::move(data) };
}

Status StoreManager::SubscribeSwitchData(const AppId &appId, std::shared_ptr<KvStoreObserver> observer)
{
    ZLOGD("appId:%{public}s", appId.appId.c_str());
    if (!appId.IsValid() || observer == nullptr) {
        return INVALID_ARGUMENT;
    }
    auto service = KVDBServiceClient::GetInstance();
    if (service == nullptr) {
        return SERVER_UNAVAILABLE;
    }
    auto serviceAgent = service->GetServiceAgent(appId);
    if (serviceAgent == nullptr) {
        return SERVER_UNAVAILABLE;
    }
    auto status = service->SubscribeSwitchData(appId);
    if (status != SUCCESS) {
        return status;
    }
    serviceAgent->AddSwitchCallback(appId.appId, observer);
    switchObservers_.Compute(appId.appId, [appId, observer](auto &, auto &switchBridge) {
        if (switchBridge == nullptr) {
            switchBridge = std::make_shared<SwitchObserverBridge>(appId);
            KvStoreServiceDeathNotifier::AddServiceDeathWatcher(switchBridge);
        }
        switchBridge->AddSwitchCallback(observer);
        return true;
    });
    return SUCCESS;
}

Status StoreManager::UnsubscribeSwitchData(const AppId &appId, std::shared_ptr<KvStoreObserver> observer)
{
    ZLOGD("appId:%{public}s", appId.appId.c_str());
    if (!appId.IsValid() || observer == nullptr) {
        return INVALID_ARGUMENT;
    }
    auto service = KVDBServiceClient::GetInstance();
    if (service == nullptr) {
        return SERVER_UNAVAILABLE;
    }
    auto serviceAgent = service->GetServiceAgent(appId);
    if (serviceAgent == nullptr) {
        return SERVER_UNAVAILABLE;
    }
    auto status = service->UnsubscribeSwitchData(appId);
    if (status != SUCCESS) {
        return status;
    }
    serviceAgent->DeleteSwitchCallback(appId.appId, observer);
    switchObservers_.ComputeIfPresent(appId.appId, [appId, observer](auto &, auto &switchBridge) {
        if (switchBridge != nullptr) {
            switchBridge->DeleteSwitchCallback(observer);
        }
        return true;
    });
    return SUCCESS;
}

void StoreManager::SubmitAfterCreate(const AppId &appId, const StoreId &storeId, const Options &options,
    const std::shared_ptr<KVDBServiceClient> &service, StoreParams &storeParams)
{
    if (!storeParams.isCreate || !options.persistent) {
        return;
    }
    std::vector<uint8_t> pwd(storeParams.password.GetData(), storeParams.password.GetData() +
        storeParams.password.GetSize());
    if (service != nullptr) {
        ScheduleAfterCreate(appId, storeId, options, service, pwd);
    }
    ClearPassword(pwd);
    storeParams.password.Clear();
}

void StoreManager::ScheduleAfterCreate(const AppId &appId, const StoreId &storeId, const Options &options,
    const std::shared_ptr<KVDBServiceClient> &service, std::vector<uint8_t> pwd)
{
    auto pending = std::make_shared<std::promise<void>>();
    pendingAfterCreates_.InsertOrAssign(PendingKey(appId, storeId), pending->get_future().share());
    auto taskId = TaskExecutor::GetInstance().Execute(
        [appId, storeId, options, pwd, pending]() mutable {
        StoreManager::GetInstance().AfterCreateAsync(appId, storeId, options, std::move(pwd), 0, pending);
    });
    if (taskId != TaskExecutor::INVALID_TASK_ID) {
        return;
    }
    Status afterStatus = service->AfterCreate(appId, storeId, options, pwd);
    if (afterStatus == SUCCESS) {
        pending->set_value();
        pendingAfterCreates_.Erase(PendingKey(appId, storeId));
        return;
    }
    ReportInfo reportInfo = { .options = options, .errorCode = afterStatus, .systemErrorNo = errno,
        .appId = appId.appId, .storeId = storeId.storeId, .functionName = "AfterCreate" };
    KVDBFaultHiViewReporter::ReportKVFaultEvent(reportInfo);
    pending->set_value();
    pendingAfterCreates_.Erase(PendingKey(appId, storeId));
}

void StoreManager::AfterCreateAsync(const AppId &appId, const StoreId &storeId, const Options &options,
    std::vector<uint8_t> password, int32_t retryCount, std::shared_ptr<std::promise<void>> pending)
{
    auto service = KVDBServiceClient::GetInstance();
    if (service == nullptr) {
        ClearPassword(password);
        if (pending != nullptr) {
            pending->set_value();
        }
        pendingAfterCreates_.Erase(PendingKey(appId, storeId));
        return;
    }
    Status status = service->AfterCreate(appId, storeId, options, password);
    if (status == SUCCESS) {
        ClearPassword(password);
        if (pending != nullptr) {
            pending->set_value();
        }
        pendingAfterCreates_.Erase(PendingKey(appId, storeId));
        return;
    }
    ReportInfo reportInfo = { .options = options, .errorCode = status, .systemErrorNo = errno,
        .appId = appId.appId, .storeId = storeId.storeId, .functionName = "AfterCreate" };
    KVDBFaultHiViewReporter::ReportKVFaultEvent(reportInfo);
    if (IsRetryableStatus(status) && retryCount < AFTER_CREATE_MAX_RETRY) {
        auto taskId = TaskExecutor::GetInstance().Schedule(std::chrono::milliseconds(AFTER_CREATE_RETRY_DELAY_MS),
            [appId, storeId, options, password = std::move(password), retryCount, pending]() mutable {
                StoreManager::GetInstance().AfterCreateAsync(appId, storeId, options, std::move(password),
                    retryCount + 1, pending);
            });
        if (taskId == TaskExecutor::INVALID_TASK_ID) {
            ClearPassword(password);
            if (pending != nullptr) {
                pending->set_value();
            }
            pendingAfterCreates_.Erase(PendingKey(appId, storeId));
        }
    } else {
        ClearPassword(password);
        if (pending != nullptr) {
            pending->set_value();
        }
        pendingAfterCreates_.Erase(PendingKey(appId, storeId));
    }
}

std::string StoreManager::PendingKey(const AppId &appId, const StoreId &storeId)
{
    return appId.appId + "/" + storeId.storeId;
}

void StoreManager::WaitAfterCreate(const AppId &appId, const StoreId &storeId)
{
    std::shared_future<void> future;
    bool hasPending = false;
    pendingAfterCreates_.ComputeIfPresent(PendingKey(appId, storeId),
        [&future, &hasPending](const auto &, auto &value) {
        future = value;
        hasPending = true;
        return true;
    });
    if (!hasPending) {
        return;
    }
    if (future.wait_for(std::chrono::milliseconds(AFTER_CREATE_WAIT_INTERVAL)) != std::future_status::ready) {
        ZLOGW("appId:%{public}s, storeId:%{public}s wait after create timeout:%{public}ums",
            appId.appId.c_str(), StoreUtil::Anonymous(storeId.storeId).c_str(), AFTER_CREATE_WAIT_INTERVAL);
        ReportInfo reportInfo = { .options = {}, .errorCode = TIME_OUT, .systemErrorNo = errno,
            .appId = appId.appId, .storeId = storeId.storeId, .functionName = "WaitAfterCreate" };
        KVDBFaultHiViewReporter::ReportKVFaultEvent(reportInfo);
    }
}

void StoreManager::WaitAllAfterCreate(const AppId &appId)
{
    std::string prefix = appId.appId + "/";
    std::vector<std::shared_future<void>> futures;
    pendingAfterCreates_.ForEachCopies([&prefix, &futures](const auto &key, auto &value) {
        if (key.compare(0, prefix.size(), prefix) == 0) {
            futures.push_back(value);
        }
        return false;
    });
    for (auto &future : futures) {
        if (future.wait_for(std::chrono::milliseconds(AFTER_CREATE_WAIT_INTERVAL)) != std::future_status::ready) {
            ZLOGW("appId:%{public}s wait all after create timeout:%{public}ums", appId.appId.c_str(),
                AFTER_CREATE_WAIT_INTERVAL);
            ReportInfo reportInfo = { .options = {}, .errorCode = TIME_OUT, .systemErrorNo = errno,
                .appId = appId.appId, .storeId = "", .functionName = "WaitAllAfterCreate" };
            KVDBFaultHiViewReporter::ReportKVFaultEvent(reportInfo);
        }
    }
}
}