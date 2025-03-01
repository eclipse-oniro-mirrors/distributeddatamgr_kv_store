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
#define LOG_TAG "AutoSyncTimerMock"
#include "auto_sync_timer.h"

#include "kvdb_service_client.h"
#include "log_print.h"

namespace OHOS::DistributedKv {
AutoSyncTimer &AutoSyncTimer::GetInstance()
{
    static AutoSyncTimer instance;
    return instance;
}

void AutoSyncTimer::StartTimer()
{
    std::lock_guard<decltype(mutex_)> lockGuard(mutex_);
    if (forceSyncTaskId_ == TaskExecutor::INVALID_TASK_ID) {
        forceSyncTaskId_ =
            TaskExecutor::GetInstance().Schedule(std::chrono::milliseconds(FORCE_SYNC_INTERVAL), ProcessTask());
    }
    if (delaySyncTaskId_ == TaskExecutor::INVALID_TASK_ID) {
        delaySyncTaskId_ =
            TaskExecutor::GetInstance().Schedule(std::chrono::milliseconds(AUTO_SYNC_INTERVAL), ProcessTask());
    } else {
        delaySyncTaskId_ =
            TaskExecutor::GetInstance().Reset(delaySyncTaskId_, std::chrono::milliseconds(AUTO_SYNC_INTERVAL));
    }
}

void AutoSyncTimer::DoAutoSync(const std::string &appId, std::set<StoreId> storeIds)
{
    AddSyncStores(appId, std::move(storeIds));
    StartTimer();
}

void AutoSyncTimer::AddSyncStores(const std::string &appId, std::set<StoreId> storeIds)
{
    stores_.Compute(appId, [&storeIds](const auto &key, std::vector<StoreId> &value) {
        std::set<StoreId> tempStores(value.begin(), value.end());
        for (auto it = storeIds.begin(); it != storeIds.end(); it++) {
            if (tempStores.count(*it) == 0) {
                value.push_back(*it);
            }
        }
        return !value.empty();
    });
}

bool AutoSyncTimer::HasSyncStores()
{
    return !stores_.Empty();
}

std::map<std::string, std::vector<StoreId>> AutoSyncTimer::GetStoreIds()
{
    std::map<std::string, std::vector<StoreId>> stores;
    int count = SYNC_STORE_NUM;
    stores_.EraseIf([&stores, &count](const std::string &key, std::vector<StoreId> &value) {
        int size = value.size();
        if (size <= count) {
            stores.insert({ key, std::move(value) });
            count = count - size;
            return true;
        }
        auto &innerStore = stores[key];
        auto it = value.begin();
        while (it != value.end() && count > 0) {
            innerStore.push_back(*it);
            it++;
            count--;
        }
        value.erase(value.begin(), it);
        return value.empty();
    });
    return stores;
}

std::function<void()> AutoSyncTimer::ProcessTask()
{
    return [this]() {
        StopTimer();
        auto service = KVDBServiceClient::GetInstance();
        if (service == nullptr) {
            StartTimer();
            return;
        }
        auto storeIds = GetStoreIds();
        for (const auto &id : storeIds) {
            auto res = HasCollaboration(id.first);
            if (!res.first) {
                continue;
            }
            ZLOGD("DoSync appId:%{public}s store size:%{public}zu", id.first.c_str(), id.second.size());
            for (const auto &storeId : id.second) {
                KVDBService::SyncInfo syncInfo;
                service->Sync({ id.first }, storeId, DEFAULT_USER_ID, syncInfo);
            }
        }
        if (HasSyncStores()) {
            StartTimer();
        }
    };
}

std::pair<bool, std::string> AutoSyncTimer::HasCollaboration(const std::string &appId)
{
    return { true, "" };
}

void AutoSyncTimer::StopTimer()
{
    std::lock_guard<decltype(mutex_)> lockGuard(mutex_);
    TaskExecutor::GetInstance().Remove(forceSyncTaskId_);
    TaskExecutor::GetInstance().Remove(delaySyncTaskId_);
    forceSyncTaskId_ = TaskExecutor::INVALID_TASK_ID;
    delaySyncTaskId_ = TaskExecutor::INVALID_TASK_ID;
}
} // namespace OHOS::DistributedKv