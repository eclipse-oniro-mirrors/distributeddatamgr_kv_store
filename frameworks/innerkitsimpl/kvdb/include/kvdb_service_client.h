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
#ifndef OHOS_DISTRIBUTED_DATA_FRAMEWORKS_KVDB_SERVICE_CLIENT_H
#define OHOS_DISTRIBUTED_DATA_FRAMEWORKS_KVDB_SERVICE_CLIENT_H
#include <functional>
#include "concurrent_map.h"
#include "iremote_broker.h"
#include "iremote_proxy.h"
#include "kvdb_service.h"
#include "kvdb_notifier_client.h"
#include "task_executor.h"
namespace OHOS::DistributedKv {
class KVDBServiceProxy : public KVDBService, public IRemoteBroker {
public:
    using KVDBService::KVDBService;
};

class KVDBServiceClient : public IRemoteProxy<KVDBServiceProxy> {
public:
    static std::shared_ptr<KVDBServiceClient> GetInstance();
    Status GetStoreIds(const AppId &appId, int32_t subUser, std::vector<StoreId> &storeIds) override;
    Status BeforeCreate(const AppId &appId, const StoreId &storeId, const Options &options) override;
    Status AfterCreate(const AppId &appId, const StoreId &storeId, const Options &options,
        const std::vector<uint8_t> &password) override;
    Status Delete(const AppId &appId, const StoreId &storeId, int32_t subUser) override;
    Status Close(const AppId &appId, const StoreId &storeId, int32_t subUser) override;
    Status Sync(const AppId &appId, const StoreId &storeId, int32_t subUser, SyncInfo &syncInfo) override;
    Status RegServiceNotifier(const AppId &appId, sptr<IKVDBNotifier> notifier) override;
    Status UnregServiceNotifier(const AppId &appIdd) override;
    Status SetSyncParam(const AppId &appId, const StoreId &storeId, int32_t subUser,
        const KvSyncParam &syncParam) override;
    Status GetSyncParam(const AppId &appId, const StoreId &storeId, int32_t subUser, KvSyncParam &syncParam) override;
    Status EnableCapability(const AppId &appId, const StoreId &storeId, int32_t subUser) override;
    Status DisableCapability(const AppId &appId, const StoreId &storeId, int32_t subUser) override;
    Status SetCapability(const AppId &appId, const StoreId &storeId, int32_t subUser,
        const std::vector<std::string> &local, const std::vector<std::string> &remote) override;
    Status AddSubscribeInfo(const AppId &appId, const StoreId &storeId, int32_t subUser,
        const SyncInfo &syncInfo) override;
    Status RmvSubscribeInfo(const AppId &appId, const StoreId &storeId, int32_t subUser,
        const SyncInfo &syncInfo) override;
    Status Subscribe(const AppId &appId, const StoreId &storeId, int32_t subUser,
        sptr<IKvStoreObserver> observer) override;
    Status Unsubscribe(const AppId &appId, const StoreId &storeId, int32_t subUser,
        sptr<IKvStoreObserver> observer) override;
    Status GetBackupPassword(const AppId &appId, const StoreId &storeId, int32_t subUser,
        std::vector<std::vector<uint8_t>> &passwords, int32_t passwordType) override;
    Status CloudSync(const AppId &appId, const StoreId &storeId, const SyncInfo &syncInfo) override;
    Status NotifyDataChange(const AppId &appId, const StoreId &storeId, uint64_t delay) override;
    Status PutSwitch(const AppId &appId, const SwitchData &data) override;
    Status GetSwitch(const AppId &appId, const std::string &networkId, SwitchData &data) override;
    Status SubscribeSwitchData(const AppId &appId) override;
    Status UnsubscribeSwitchData(const AppId &appId) override;
    Status SetConfig(const AppId &appId, const StoreId &storeId, const StoreConfig &storeConfig) override;
    Status RemoveDeviceData(const AppId &appId, const StoreId &storeId, int32_t subUser,
        const std::string &device) override;

    sptr<KVDBNotifierClient> GetServiceAgent(const AppId &appId);

protected:
    explicit KVDBServiceClient(const sptr<IRemoteObject> &object);
    virtual ~KVDBServiceClient() = default;

private:
    class ServiceDeath : public KvStoreDeathRecipient {
    public:
        ServiceDeath() = default;
        virtual ~ServiceDeath() = default;
        void OnRemoteDied() override;
    };
    static std::mutex mutex_;
    static std::shared_ptr<KVDBServiceClient> instance_;
    static std::atomic_bool isWatched_;
    sptr<IRemoteObject> remote_;
    std::mutex agentMtx_;
    sptr<KVDBNotifierClient> serviceAgent_;
};
} // namespace OHOS::DistributedKv
#endif // OHOS_DISTRIBUTED_DATA_FRAMEWORKS_KVDB_SERVICE_CLIENT_H