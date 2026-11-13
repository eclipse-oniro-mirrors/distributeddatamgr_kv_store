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
#ifndef OHOS_DISTRIBUTED_DATA_FRAMEWORKS_KVDB_STORE_MANAGER_H
#define OHOS_DISTRIBUTED_DATA_FRAMEWORKS_KVDB_STORE_MANAGER_H

#include "concurrent_map.h"
#include "single_kvstore.h"
#include "kv_hiview_reporter.h"
#include "store_factory.h"
#include "switch_observer_bridge.h"

#include <future>

namespace OHOS::DistributedKv {
class KVDBServiceClient;
class StoreManager {
public:
    static StoreManager &GetInstance();
    std::shared_ptr<SingleKvStore> GetKVStore(const AppId &appId, const StoreId &storeId, const Options &options,
        Status &status);
    Status CloseKVStore(const AppId &appId, const StoreId &storeId, int32_t subUser = 0);
    Status CloseKVStore(const AppId &appId, const StoreId &storeId, const std::string &path);
    Status CloseAllKVStore(const AppId &appId, int32_t subUser = 0);
    Status GetStoreIds(const AppId &appId, std::vector<StoreId> &storeIds, int32_t subUser = 0);
    Status Delete(const AppId &appId, const StoreId &storeId, const std::string &path, int32_t subUser = 0);
    Status Delete(const AppId &appId, const StoreId &storeId, const Options &options);
    Status PutSwitch(const AppId &appId, const SwitchData &data);
    std::pair<Status, SwitchData> GetSwitch(const AppId &appId, const std::string &networkId);
    Status SubscribeSwitchData(const AppId &appId, std::shared_ptr<KvStoreObserver> observer);
    Status UnsubscribeSwitchData(const AppId &appId, std::shared_ptr<KvStoreObserver> observer);
    bool CleanUp();
    void WaitAfterCreate(const AppId &appId, const StoreId &storeId);

private:
    std::shared_ptr<SingleKvStore> OpenWithSecretKeyFromService(const AppId &appId, const StoreId &storeId,
        const Options &options, Status &status, StoreParams &storeParams);
    void AfterCreateAsync(const AppId &appId, const StoreId &storeId, const Options &options,
        std::vector<uint8_t> password, int32_t retryCount, std::shared_ptr<std::promise<void>> pending);
    void SubmitAfterCreate(const AppId &appId, const StoreId &storeId, const Options &options,
        const std::shared_ptr<KVDBServiceClient> &service, StoreParams &storeParams);
    void ScheduleAfterCreate(const AppId &appId, const StoreId &storeId, const Options &options,
        const std::shared_ptr<KVDBServiceClient> &service, std::vector<uint8_t> pwd);
    void WaitAllAfterCreate(const AppId &appId);
    static std::string PendingKey(const AppId &appId, const StoreId &storeId);
    ConcurrentMap<std::string, std::shared_ptr<SwitchObserverBridge>> switchObservers_;
    ConcurrentMap<std::string, std::shared_future<void>> pendingAfterCreates_;
};
} // namespace OHOS::DistributedKv
#endif // OHOS_DISTRIBUTED_DATA_FRAMEWORKS_KVDB_STORE_MANAGER_H
