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
#include "distributedkvdatamanager_fuzzer.h"

#include <vector>
#include <sys/stat.h>

#include "distributed_kv_data_manager.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "kvstore_death_recipient.h"
#include "kvstore_observer.h"
#include "types.h"

using namespace OHOS;
using namespace OHOS::DistributedKv;

class DistributedKvDataManagerFuzzer {
    /* Keep C++ file names the same as the class name */
};

namespace OHOS {
static std::shared_ptr<SingleKvStore> singleKvStore_ = nullptr;

static DistributedKvDataManager manager;
static Options create;
static Options noCreate;
static UserId userId;
static AppId appId;
static StoreId storeIdTest;

class MyDeathRecipient : public KvStoreDeathRecipient {
public:
    MyDeathRecipient()
    {
    }
    virtual ~MyDeathRecipient()
    {
    }
    void OnRemoteDied() override
    {
    }
};

class SwitchDataObserver : public KvStoreObserver {
public:
    SwitchDataObserver() {}
    ~SwitchDataObserver() {}
    SwitchDataObserver(const SwitchDataObserver &) = delete;
    SwitchDataObserver &operator=(const SwitchDataObserver &) = delete;
    SwitchDataObserver(SwitchDataObserver &&) = delete;
    SwitchDataObserver &operator=(SwitchDataObserver &&) = delete;

    void OnSwitchChange(const SwitchNotification &notification) override
    {
    }
};

void SetUpTestCase(void)
{
    userId.userId = "account";
    appId.appId = "distributedkvdatamanagerfuzzertest";
    create.createIfMissing = true;
    create.encrypt = false;
    create.autoSync = true;
    create.kvStoreType = SINGLE_VERSION;
    create.area = EL1;
    create.baseDir = std::string("/data/service/el1/public/database/") + appId.appId;
    mkdir(create.baseDir.c_str(), (S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH));

    manager.CloseAllKvStore(appId);
    manager.DeleteAllKvStore(appId, create.baseDir);
}

void TearDown(void)
{
    manager.CloseAllKvStore(appId);
    manager.DeleteAllKvStore(appId, create.baseDir);
    (void)remove("/data/service/el1/public/database/distributedkvdatamanagerfuzzertest/key");
    (void)remove("/data/service/el1/public/database/distributedkvdatamanagerfuzzertest/kvdb");
    (void)remove("/data/service/el1/public/database/distributedkvdatamanagerfuzzertest");
}

void GetKvStoreFuzz(FuzzedDataProvider &provider)
{
    StoreId storeId;
    storeId.storeId = provider.ConsumeRandomLengthString();
    std::shared_ptr<SingleKvStore> notExistKvStore;
    manager.GetSingleKvStore(create, appId, storeId, notExistKvStore);
    std::shared_ptr<SingleKvStore> existKvStore;
    manager.GetSingleKvStore(noCreate, appId, storeId, existKvStore);
    manager.CloseKvStore(appId, storeId);
    manager.DeleteKvStore(appId, storeId);
}

void GetAllKvStoreFuzz(FuzzedDataProvider &provider)
{
    std::vector<StoreId> storeIds;
    manager.GetAllKvStoreId(appId, storeIds);

    std::shared_ptr<SingleKvStore> KvStore;
    std::string storeId_base = provider.ConsumeRandomLengthString();
    int sum = 10;
    for (int i = 0; i < sum; i++) {
        StoreId storeId;
        storeId.storeId = storeId_base + "_" + std::to_string(i);
        manager.GetSingleKvStore(create, appId, storeId, KvStore);
    }
    manager.GetAllKvStoreId(appId, storeIds);
    manager.CloseAllKvStore(appId);

    manager.GetAllKvStoreId(appId, storeIds);
}

void CloseKvStoreFuzz(FuzzedDataProvider &provider)
{
    StoreId storeId;
    storeId.storeId = provider.ConsumeRandomLengthString();
    manager.CloseKvStore(appId, storeId);
    std::shared_ptr<SingleKvStore> kvStore;
    manager.GetSingleKvStore(create, appId, storeId, kvStore);
    manager.CloseKvStore(appId, storeId);
    manager.CloseKvStore(appId, storeId);
}

void DeleteKvStoreFuzz(FuzzedDataProvider &provider)
{
    StoreId storeId;
    storeId.storeId = provider.ConsumeRandomLengthString();
    manager.DeleteKvStore(appId, storeId, create.baseDir);

    std::shared_ptr<SingleKvStore> kvStore;
    manager.GetSingleKvStore(create, appId, storeId, kvStore);
    manager.CloseKvStore(appId, storeId);
    manager.DeleteKvStore(appId, storeId, create.baseDir);

    manager.CloseKvStore(appId, storeId);
}

void DeleteAllKvStoreFuzz1(FuzzedDataProvider &provider)
{
    std::vector<StoreId> storeIds;
    manager.GetAllKvStoreId(appId, storeIds);

    manager.DeleteAllKvStore(appId, create.baseDir);
    std::shared_ptr<SingleKvStore> KvStore;
    std::string storeId_base = provider.ConsumeRandomLengthString();
    int sum = 10;
    for (int i = 0; i < sum; i++) {
        StoreId storeId;
        storeId.storeId = storeId_base + "_" + std::to_string(i);
        manager.GetSingleKvStore(create, appId, storeId, KvStore);

        manager.CloseKvStore(appId, storeId);
    }
    manager.DeleteAllKvStore(appId, create.baseDir);
}

void DeleteAllKvStoreFuzz2(FuzzedDataProvider &provider)
{
    std::vector<StoreId> storeIds;
    manager.GetAllKvStoreId(appId, storeIds);

    std::shared_ptr<SingleKvStore> KvStore;
    std::string storeId_base = provider.ConsumeRandomLengthString();
    manager.GetSingleKvStore(create, appId, storeIdTest, KvStore);
    manager.CloseKvStore(appId, storeIdTest);
    int sum = 10;
    for (int i = 0; i < sum; i++) {
        StoreId storeId;
        storeId.storeId = storeId_base + "_" + std::to_string(i);
        manager.GetSingleKvStore(create, appId, storeId, KvStore);
    }
    manager.DeleteAllKvStore(appId, create.baseDir);
}

void DeleteAllKvStoreFuzz3(FuzzedDataProvider &provider)
{
    std::vector<StoreId> storeIds;
    manager.GetAllKvStoreId(appId, storeIds);

    std::shared_ptr<SingleKvStore> KvStore;
    std::string storeId_base = provider.ConsumeRandomLengthString();
    int sum = 10;
    for (int i = 0; i < sum; i++) {
        StoreId storeId;
        storeId.storeId = storeId_base + "_" + std::to_string(i);
        manager.GetSingleKvStore(create, appId, storeId, KvStore);
    }
    manager.DeleteAllKvStore(appId, create.baseDir);
}

void RegisterKvStoreServiceDeathRecipientFuzz()
{
    std::shared_ptr<KvStoreDeathRecipient> kvStoreDeathRecipient = std::make_shared<MyDeathRecipient>();
    manager.RegisterKvStoreServiceDeathRecipient(kvStoreDeathRecipient);
    kvStoreDeathRecipient->OnRemoteDied();
}

void UnRegisterKvStoreServiceDeathRecipientFuzz()
{
    std::shared_ptr<KvStoreDeathRecipient> kvStoreDeathRecipient = std::make_shared<MyDeathRecipient>();
    manager.UnRegisterKvStoreServiceDeathRecipient(kvStoreDeathRecipient);
    kvStoreDeathRecipient->OnRemoteDied();
}

void PutSwitchFuzz(FuzzedDataProvider &provider)
{
    std::string appIds = provider.ConsumeRandomLengthString();
    uint32_t input = provider.ConsumeIntegral<uint32_t>();
    SwitchData switchData;
    switchData.value = input;
    switchData.length = input & 0xFFFF;
    manager.PutSwitch({ appIds }, switchData);
    manager.PutSwitch({ "distributed_device_profile_service" }, switchData);
}

void GetSwitchFuzz(FuzzedDataProvider &provider)
{
    std::string appIds = provider.ConsumeRandomLengthString();
    std::string networkId = provider.ConsumeRandomLengthString();
    manager.GetSwitch({ appIds }, networkId);
    manager.GetSwitch({ "distributed_device_profile_service" }, networkId);
}

void SubscribeSwitchDataFuzz(FuzzedDataProvider &provider)
{
    std::string appIds = provider.ConsumeRandomLengthString();
    std::shared_ptr<SwitchDataObserver> observer = std::make_shared<SwitchDataObserver>();
    manager.SubscribeSwitchData({ appIds }, observer);
}

void UnsubscribeSwitchDataFuzz(FuzzedDataProvider &provider)
{
    std::string appIds = provider.ConsumeRandomLengthString();
    std::shared_ptr<SwitchDataObserver> observer = std::make_shared<SwitchDataObserver>();
    manager.SubscribeSwitchData({ appIds }, observer);
    manager.UnsubscribeSwitchData({ appIds }, observer);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::SetUpTestCase();
    OHOS::GetKvStoreFuzz(provider);
    OHOS::GetAllKvStoreFuzz(provider);
    OHOS::CloseKvStoreFuzz(provider);
    OHOS::DeleteKvStoreFuzz(provider);
    OHOS::DeleteAllKvStoreFuzz1(provider);
    OHOS::DeleteAllKvStoreFuzz2(provider);
    OHOS::DeleteAllKvStoreFuzz3(provider);
    OHOS::RegisterKvStoreServiceDeathRecipientFuzz();
    OHOS::UnRegisterKvStoreServiceDeathRecipientFuzz();
    OHOS::PutSwitchFuzz(provider);
    OHOS::GetSwitchFuzz(provider);
    OHOS::SubscribeSwitchDataFuzz(provider);
    OHOS::UnsubscribeSwitchDataFuzz(provider);
    OHOS::TearDown();
    return 0;
}