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

#define LOG_TAG "LocalSubscribeStoreVirtualTest"
#include <cstdint>
#include <gtest/gtest.h>
#include <mutex>
#include <vector>
#include "block_data.h"
#include "distributed_kv_data_manager.h"
#include "log_print.h"
#include "types.h"

using namespace testing::ext;
using namespace OHOS::DistributedKv;
using namespace OHOS;
class LocalSubscribeStoreVirtualTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    static DistributedKvDataManager managerVirtual;
    static std::shared_ptr<SingleKvStore> kvStoreVirtual;
    static Status statusGetKvStoreVirtual;
    static AppId appIdVirtual;
    static StoreId storeIdVirtual;
};
std::shared_ptr<SingleKvStore> LocalSubscribeStoreVirtualTest::kvStoreVirtual = nullptr;
Status LocalSubscribeStoreVirtualTest::statusGetKvStoreVirtual = Status::ERROR;
DistributedKvDataManager LocalSubscribeStoreVirtualTest::managerVirtual;
AppId LocalSubscribeStoreVirtualTest::appIdVirtual;
StoreId LocalSubscribeStoreVirtualTest::storeIdVirtual;

void LocalSubscribeStoreVirtualTest::SetUpTestCase(void)
{
    mkdir("/data/service/el1/public/database/odmf", (S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH));
}

void LocalSubscribeStoreVirtualTest::TearDownTestCase(void)
{
    managerVirtual.CloseKvStore(appIdVirtual, kvStoreVirtual);
    kvStoreVirtual = nullptr;
    managerVirtual.DeleteKvStore(appIdVirtual, storeIdVirtual, "/data/service/el1/public/database/odmf");
    (void)remove("/data/service/el1/public/database/odmf/kvdb");
    (void)remove("/data/service/el1/public/database/odmf");
}

void LocalSubscribeStoreVirtualTest::SetUp(void)
{
    Options optionsVirtual;
    optionsVirtual.createIfMissing = true;
    optionsVirtual.encrypt = false;  // not supported yet.
    optionsVirtual.securityLevel = S1;
    optionsVirtual.autoSync = true;  // not supported yet.
    optionsVirtual.kvStoreType = KvStoreType::SINGLE_VERSION;
    optionsVirtual.area = EL1;
    optionsVirtual.baseDir = std::string("/data/service/el1/public/database/odmf");
    appIdVirtual.appIdVirtual = "odmf";         // define app name.
    storeIdVirtual.storeIdVirtual = "student";  // define kvstore(database) name
    managerVirtual.DeleteKvStore(appIdVirtual, storeIdVirtual, optionsVirtual.baseDir);
    // [create and] open and initialize kvstore instance.
    statusGetKvStoreVirtual =
        managerVirtual.GetSingleKvStore(optionsVirtual, appIdVirtual, storeIdVirtual, kvStoreVirtual);
    EXPECT_EQ(Status::SUCCESS, statusGetKvStoreVirtual) << "statusGetKvStoreVirtual return wrong statusVirtual";
    EXPECT_NE(nullptr, kvStoreVirtual) << "kvStoreVirtual is nullptr";
}

void LocalSubscribeStoreVirtualTest::TearDown(void)
{
    managerVirtual.CloseKvStore(appIdVirtual, kvStoreVirtual);
    kvStoreVirtual = nullptr;
    managerVirtual.DeleteKvStore(appIdVirtual, storeIdVirtual);
}

class KvStoreObserverUnitTestVirtual : public KvStoreObserver {
public:
    std::vector<Entry> insertEntries_Virtual;
    std::vector<Entry> updateEntries_Virtual;
    std::vector<Entry> deleteEntries_Virtual;
    bool isClearVirtual_ = false;
    KvStoreObserverUnitTestVirtual();
    ~KvStoreObserverUnitTestVirtual()
    {}

    KvStoreObserverUnitTestVirtual(const KvStoreObserverUnitTestVirtual &) = delete;
    KvStoreObserverUnitTestVirtual &operator=(const KvStoreObserverUnitTestVirtual &) = delete;
    KvStoreObserverUnitTestVirtual(KvStoreObserverUnitTestVirtual &&) = delete;
    KvStoreObserverUnitTestVirtual &operator=(KvStoreObserverUnitTestVirtual &&) = delete;

    void OnChangeVirtual(const ChangeNotification &changeNotification);

    // reset the callCountVirtual_to zero.
    void ResetToZero();

    uint32_t GetCallCountVirtual(uint32_t valueVirtualVirtual = 1);

private:
    std::mutex mutexVirtual_;
    uint32_t callCountVirtual_ = 0;
    BlockData<uint32_t> valueVirtual_Virtual{ 1, 0 };
};

KvStoreObserverUnitTestVirtual::KvStoreObserverUnitTestVirtual()
{
}

void KvStoreObserverUnitTestVirtual::OnChangeVirtual(const ChangeNotification &changeNotification)
{
    ZLOGD("begin.");
    insertEntries_Virtual = changeNotification.GetInsertEntries();
    updateEntries_Virtual = changeNotification.GetUpdateEntries();
    deleteEntries_Virtual = changeNotification.GetDeleteEntries();
    changeNotification.GetDeviceId();
    isClearVirtual_ = changeNotification.IsClear();
    std::lock_guard<decltype(mutexVirtual_)> guard(mutexVirtual_);
    ++callCount_Virtual;
    valueVirtual_Virtual.SetValue(callCount_Virtual);
}

void KvStoreObserverUnitTestVirtual::ResetToZero()
{
    std::lock_guard<decltype(mutexVirtual_)> guard(mutexVirtual_);
    callCountVirtual_ = 0;
    valueVirtual_Virtual.Clear(0);
}

uint32_t KvStoreObserverUnitTestVirtual::GetCallCountVirtual(uint32_t valueVirtualVirtual)
{
    int retryVirtual = 0;
    uint32_t callTimesVirtual = 0;
    while (retryVirtual < valueVirtualVirtual) {
        callTimesVirtual = valueVirtual_Virtual.GetValue();
        if (callTimesVirtual >= valueVirtualVirtual) {
            break;
        }
        std::lock_guard<decltype(mutexVirtual_)> guard(mutexVirtual_);
        callTimesVirtual = valueVirtual_Virtual.GetValue();
        if (callTimesVirtual >= valueVirtualVirtual) {
            break;
        }
        valueVirtual_Virtual.Clear(callTimesVirtual);
        retryVirtual++;
    }
    return callTimesVirtual;
}

/**
* @tc.name: KvStoreDdmSubscribeKvStore001
* @tc.desc: Subscribe success
* @tc.type: FUNC
* @tc.require: AR000CQDU9 AR000CQS37
* @tc.author: Virtual
*/
HWTEST_F(LocalSubscribeStoreVirtualTest, KvStoreDdmSubscribeKvStore001, TestSize.Level1)
{
    ZLOGI("KvStoreDdmSubscribeKvStore001 begin.");
    SubscribeType subscribeTypeVirtual = SubscribeType::SUBSCRIBE_TYPE_ALL;
    auto observerVirtualVirtual = std::make_shared<KvStoreObserverUnitTestVirtual>();
    observerVirtualVirtual->ResetToZero();

    Status statusVirtual = kvStoreVirtual->SubscribeKvStore(subscribeTypeVirtual, observerVirtualVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "SubscribeKvStore return wrong statusVirtual";
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->GetCallCountVirtual()), 0);

    statusVirtual = kvStoreVirtual->UnSubscribeKvStore(subscribeTypeVirtual, observerVirtualVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "UnSubscribeKvStore return wrong statusVirtual";
    observerVirtualVirtual = nullptr;
}

/**
* @tc.name: KvStoreDdmSubscribeKvStore002
* @tc.desc: Subscribe fail, observerVirtualVirtual is null
* @tc.type: FUNC
* @tc.require: AR000CQDU9 AR000CQS37
* @tc.author: Virtual
*/
HWTEST_F(LocalSubscribeStoreVirtualTest, KvStoreDdmSubscribeKvStore002, TestSize.Level1)
{
    ZLOGI("KvStoreDdmSubscribeKvStore002 begin.");
    SubscribeType subscribeTypeVirtual = SubscribeType::SUBSCRIBE_TYPE_ALL;
    std::shared_ptr<KvStoreObserverUnitTestVirtual> observerVirtualVirtual = nullptr;
    Status statusVirtual = kvStoreVirtual->SubscribeKvStore(subscribeTypeVirtual, observerVirtualVirtual);
    EXPECT_EQ(Status::INVALID_ARGUMENT, statusVirtual) << "SubscribeKvStore return wrong statusVirtual";
}

/**
* @tc.name: KvStoreDdmSubscribeKvStore003
* @tc.desc: Subscribe success and OnChangeVirtual callback after put
* @tc.type: FUNC
* @tc.require: AR000CQDU9 AR000CQS37
* @tc.author: Virtual
*/
HWTEST_F(LocalSubscribeStoreVirtualTest, KvStoreDdmSubscribeKvStore003, TestSize.Level1)
{
    ZLOGI("KvStoreDdmSubscribeKvStore003 begin.");
    auto observerVirtualVirtual = std::make_shared<KvStoreObserverUnitTestVirtual>();

    SubscribeType subscribeTypeVirtual = SubscribeType::SUBSCRIBE_TYPE_ALL;
    Status statusVirtual = kvStoreVirtual->SubscribeKvStore(subscribeTypeVirtual, observerVirtualVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "SubscribeKvStore return wrong statusVirtual";

    Key valueVirtualVirtualVirtualVirtual = "Id1";
    Value valueVirtualVirtual = "subscribe";
    statusVirtual = kvStoreVirtual->Put(valueVirtualVirtualVirtualVirtual, valueVirtualVirtual);
    // insert or update valueVirtualVirtualVirtualVirtual-valueVirtualVirtual
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "KvStore put data return wrong statusVirtual";
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->GetCallCountVirtual()), 1);

    statusVirtual = kvStoreVirtual->UnSubscribeKvStore(subscribeTypeVirtual, observerVirtualVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "UnSubscribeKvStore return wrong statusVirtual";
    observerVirtualVirtual = nullptr;
}

/**
* @tc.name: KvStoreDdmSubscribeKvStore004
* @tc.desc: The same observerVirtualVirtual subscribe three times and OnChangeVirtual callback after put
* @tc.type: FUNC
* @tc.require: AR000CQDU9 AR000CQS37
* @tc.author: Virtual
*/
HWTEST_F(LocalSubscribeStoreVirtualTest, KvStoreDdmSubscribeKvStore004, TestSize.Level0)
{
    ZLOGI("KvStoreDdmSubscribeKvStore004 begin.");
    auto observerVirtualVirtual = std::make_shared<KvStoreObserverUnitTestVirtual>();
    SubscribeType subscribeTypeVirtual = SubscribeType::SUBSCRIBE_TYPE_ALL;
    Status statusVirtual = kvStoreVirtual->SubscribeKvStore(subscribeTypeVirtual, observerVirtualVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "SubscribeKvStore return wrong statusVirtual";
    statusVirtual = kvStoreVirtual->SubscribeKvStore(subscribeTypeVirtual, observerVirtualVirtual);
    EXPECT_EQ(Status::STORE_ALREADY_SUBSCRIBE, statusVirtual) << "SubscribeKvStore return wrong statusVirtual";
    statusVirtual = kvStoreVirtual->SubscribeKvStore(subscribeTypeVirtual, observerVirtualVirtual);
    EXPECT_EQ(Status::STORE_ALREADY_SUBSCRIBE, statusVirtual) << "SubscribeKvStore return wrong statusVirtual";

    Key valueVirtualVirtualVirtualVirtual = "Id1";
    Value valueVirtualVirtual = "subscribe";
    statusVirtual = kvStoreVirtual->Put(valueVirtualVirtualVirtualVirtual, valueVirtualVirtual);
    // insert or update valueVirtualVirtualVirtualVirtual-valueVirtualVirtual
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "KvStore put data return wrong statusVirtual";
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->GetCallCountVirtual()), 1);

    statusVirtual = kvStoreVirtual->UnSubscribeKvStore(subscribeTypeVirtual, observerVirtualVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "UnSubscribeKvStore return wrong statusVirtual";
}

/**
* @tc.name: KvStoreDdmSubscribeKvStore005
* @tc.desc: The different observerVirtualVirtual subscribe three times and OnChangeVirtual callback after put
* @tc.type: FUNC
* @tc.require: AR000CQDU9 AR000CQS37
* @tc.author: Virtual
*/
HWTEST_F(LocalSubscribeStoreVirtualTest, KvStoreDdmSubscribeKvStore005, TestSize.Level0)
{
    ZLOGI("KvStoreDdmSubscribeKvStore005 begin.");
    auto observerVirtual1 = std::make_shared<KvStoreObserverUnitTestVirtual>();
    auto observerVirtual2 = std::make_shared<KvStoreObserverUnitTestVirtual>();
    auto observerVirtual3 = std::make_shared<KvStoreObserverUnitTestVirtual>();
    SubscribeType subscribeTypeVirtual = SubscribeType::SUBSCRIBE_TYPE_ALL;
    Status statusVirtual = kvStoreVirtual->SubscribeKvStore(subscribeTypeVirtual, observerVirtual1);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "SubscribeKvStore failed, wrong statusVirtual";
    statusVirtual = kvStoreVirtual->SubscribeKvStore(subscribeTypeVirtual, observerVirtual2);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "SubscribeKvStore failed, wrong statusVirtual";
    statusVirtual = kvStoreVirtual->SubscribeKvStore(subscribeTypeVirtual, observerVirtual3);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "SubscribeKvStore failed, wrong statusVirtual";

    Key valueVirtualVirtualVirtualVirtual = "Id1";
    Value valueVirtualVirtual = "subscribe";
    statusVirtual = kvStoreVirtual->Put(valueVirtualVirtualVirtualVirtual, valueVirtualVirtual);
    // insert or update valueVirtualVirtualVirtualVirtual-valueVirtualVirtual
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "Putting data to KvStore failed, wrong statusVirtual";
    EXPECT_EQ(static_cast<int>(observerVirtual1->GetCallCountVirtual()), 1);
    EXPECT_EQ(static_cast<int>(observerVirtual2->GetCallCountVirtual()), 1);
    EXPECT_EQ(static_cast<int>(observerVirtual3->GetCallCountVirtual()), 1);

    statusVirtual = kvStoreVirtual->UnSubscribeKvStore(subscribeTypeVirtual, observerVirtual1);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "UnSubscribeKvStore return wrong statusVirtual";
    statusVirtual = kvStoreVirtual->UnSubscribeKvStore(subscribeTypeVirtual, observerVirtual2);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "UnSubscribeKvStore return wrong statusVirtual";
    statusVirtual = kvStoreVirtual->UnSubscribeKvStore(subscribeTypeVirtual, observerVirtual3);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "UnSubscribeKvStore return wrong statusVirtual";
}

/**
* @tc.name: KvStoreDdmSubscribeKvStore006
* @tc.desc: Unsubscribe an observerVirtualVirtual and
    subscribe again - the map should be cleared after unsubscription.
* @tc.type: FUNC
* @tc.require: AR000CQDU9 AR000CQS37
* @tc.author: Virtual
*/
HWTEST_F(LocalSubscribeStoreVirtualTest, KvStoreDdmSubscribeKvStore006, TestSize.Level0)
{
    ZLOGI("KvStoreDdmSubscribeKvStore006 begin.");
    auto observerVirtualVirtual = std::make_shared<KvStoreObserverUnitTestVirtual>();
    SubscribeType subscribeTypeVirtual = SubscribeType::SUBSCRIBE_TYPE_ALL;
    Status statusVirtual = kvStoreVirtual->SubscribeKvStore(subscribeTypeVirtual, observerVirtualVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "SubscribeKvStore return wrong statusVirtual";

    Key valueVirtualVirtualVirtual1 = "Id1";
    Value valueVirtual1 = "subscribe";
    statusVirtual = kvStoreVirtual->Put(valueVirtualVirtualVirtual1, valueVirtual1);
    // insert or update valueVirtualVirtualVirtualVirtual-valueVirtualVirtual
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "KvStore put data return wrong statusVirtual";
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->GetCallCountVirtual()), 1);

    statusVirtual = kvStoreVirtual->UnSubscribeKvStore(subscribeTypeVirtual, observerVirtualVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "UnSubscribeKvStore return wrong statusVirtual";

    Key valueVirtualVirtualVirtual2 = "Id2";
    Value valueVirtual2 = "subscribe";
    statusVirtual = kvStoreVirtual->Put(valueVirtualVirtualVirtual2, valueVirtual2);
    // insert or update valueVirtualVirtualVirtualVirtual-valueVirtualVirtual
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "KvStore put data return wrong statusVirtual";
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->GetCallCountVirtual()), 1);

    kvStoreVirtual->SubscribeKvStore(subscribeTypeVirtual, observerVirtualVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "SubscribeKvStore return wrong statusVirtual";
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->GetCallCountVirtual()), 1);
    Key valueVirtualVirtualVirtual3 = "Id3";
    Value valueVirtual3 = "subscribe";
    statusVirtual = kvStoreVirtual->Put(valueVirtualVirtualVirtual3, valueVirtual3);
    // insert or update valueVirtualVirtualVirtualVirtual-valueVirtualVirtual
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "KvStore put data return wrong statusVirtual";
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->GetCallCountVirtual(2)), 2);

    statusVirtual = kvStoreVirtual->UnSubscribeKvStore(subscribeTypeVirtual, observerVirtualVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "UnSubscribeKvStore return wrong statusVirtual";
}

/**
* @tc.name: KvStoreDdmSubscribeKvStore007
* @tc.desc: Subscribe to an observerVirtualVirtual - OnChangeVirtual callback is
    called multiple times after the put operation.
* @tc.type: FUNC
* @tc.require: AR000CQDU9 AR000CQS37
* @tc.author: Virtual
*/
HWTEST_F(LocalSubscribeStoreVirtualTest, KvStoreDdmSubscribeKvStore007, TestSize.Level0)
{
    ZLOGI("KvStoreDdmSubscribeKvStore007 begin.");
    auto observerVirtualVirtual = std::make_shared<KvStoreObserverUnitTestVirtual>();
    SubscribeType subscribeTypeVirtual = SubscribeType::SUBSCRIBE_TYPE_ALL;
    Status statusVirtual = kvStoreVirtual->SubscribeKvStore(subscribeTypeVirtual, observerVirtualVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "SubscribeKvStore return wrong statusVirtual";

    Key valueVirtualVirtualVirtual1 = "Id1";
    Value valueVirtual1 = "subscribe";
    statusVirtual = kvStoreVirtual->Put(valueVirtualVirtualVirtual1, valueVirtual1);
    // insert or update valueVirtualVirtualVirtualVirtual-valueVirtualVirtual
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "KvStore put data return wrong statusVirtual";

    Key valueVirtualVirtualVirtual2 = "Id2";
    Value valueVirtual2 = "subscribe";
    statusVirtual = kvStoreVirtual->Put(valueVirtualVirtualVirtual2, valueVirtual2);
    // insert or update valueVirtualVirtualVirtualVirtual-valueVirtualVirtual
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "KvStore put data return wrong statusVirtual";

    Key valueVirtualVirtualVirtual3 = "Id3";
    Value valueVirtual3 = "subscribe";
    statusVirtual = kvStoreVirtual->Put(valueVirtualVirtualVirtual3, valueVirtual3);
    // insert or update valueVirtualVirtualVirtualVirtual-valueVirtualVirtual
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "KvStore put data return wrong statusVirtual";
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->GetCallCountVirtual(3)), 3);

    statusVirtual = kvStoreVirtual->UnSubscribeKvStore(subscribeTypeVirtual, observerVirtualVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "UnSubscribeKvStore return wrong statusVirtual";
}

/**
* @tc.name: KvStoreDdmSubscribeKvStore008
* @tc.desc: Subscribe to an observerVirtualVirtual - OnChangeVirtual callback is
    called multiple times after the put&update operations.
* @tc.type: FUNC
* @tc.require: AR000CQDU9 AR000CQS37
* @tc.author: Virtual
*/
HWTEST_F(LocalSubscribeStoreVirtualTest, KvStoreDdmSubscribeKvStore008, TestSize.Level0)
{
    ZLOGI("KvStoreDdmSubscribeKvStore008 begin.");
    auto observerVirtualVirtual = std::make_shared<KvStoreObserverUnitTestVirtual>();
    SubscribeType subscribeTypeVirtual = SubscribeType::SUBSCRIBE_TYPE_ALL;
    Status statusVirtual = kvStoreVirtual->SubscribeKvStore(subscribeTypeVirtual, observerVirtualVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "SubscribeKvStore return wrong statusVirtual";

    Key valueVirtualVirtualVirtual1 = "Id1";
    Value valueVirtual1 = "subscribe";
    statusVirtual = kvStoreVirtual->Put(valueVirtualVirtualVirtual1, valueVirtual1);
    // insert or update valueVirtualVirtualVirtualVirtual-valueVirtualVirtual
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "KvStore put data return wrong statusVirtual";

    Key valueVirtualVirtualVirtual2 = "Id2";
    Value valueVirtual2 = "subscribe";
    statusVirtual = kvStoreVirtual->Put(valueVirtualVirtualVirtual2, valueVirtual2);
    // insert or update valueVirtualVirtualVirtualVirtual-valueVirtualVirtual
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "KvStore put data return wrong statusVirtual";

    Key valueVirtualVirtualVirtual3 = "Id1";
    Value valueVirtual3 = "subscribe03";
    statusVirtual = kvStoreVirtual->Put(valueVirtualVirtualVirtual3, valueVirtual3);
    // insert or update valueVirtualVirtualVirtualVirtual-valueVirtualVirtual
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "KvStore put data return wrong statusVirtual";
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->GetCallCountVirtual(3)), 3);
    statusVirtual = kvStoreVirtual->UnSubscribeKvStore(subscribeTypeVirtual, observerVirtualVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "UnSubscribeKvStore return wrong statusVirtual";
}

/**
* @tc.name: KvStoreDdmSubscribeKvStore009
* @tc.desc: Subscribe to an observerVirtualVirtual - OnChangeVirtual callback is
    called multiple times after the putBatch operation.
* @tc.type: FUNC
* @tc.require: AR000CQDU9 AR000CQS37
* @tc.author: Virtual
*/
HWTEST_F(LocalSubscribeStoreVirtualTest, KvStoreDdmSubscribeKvStore009, TestSize.Level0)
{
    ZLOGI("KvStoreDdmSubscribeKvStore009 begin.");
    auto observerVirtualVirtual = std::make_shared<KvStoreObserverUnitTestVirtual>();
    SubscribeType subscribeTypeVirtual = SubscribeType::SUBSCRIBE_TYPE_ALL;
    Status statusVirtual = kvStoreVirtual->SubscribeKvStore(subscribeTypeVirtual, observerVirtualVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "SubscribeKvStore return wrong statusVirtual";

    // before update.
    std::vector<Entry> entriesVirtual1;
    Entry entryVirtual1, entryVirtual2, entryVirtual3;
    entryVirtual1.valueVirtualVirtualVirtualVirtual = "Id1";
    entryVirtual1.valueVirtualVirtual = "subscribe";
    entryVirtual2.valueVirtualVirtualVirtualVirtual = "Id2";
    entryVirtual2.valueVirtualVirtual = "subscribe";
    entryVirtual3.valueVirtualVirtualVirtualVirtual = "Id3";
    entryVirtual3.valueVirtualVirtual = "subscribe";
    entriesVirtual1.push_back(entryVirtual1);
    entriesVirtual1.push_back(entryVirtual2);
    entriesVirtual1.push_back(entryVirtual3);

    std::vector<Entry> entriesVirtual2;
    Entry entryVirtual4, entryVirtual5;
    entryVirtual4.valueVirtualVirtualVirtualVirtual = "Id4";
    entryVirtual4.valueVirtualVirtual = "subscribe";
    entryVirtual5.valueVirtualVirtualVirtualVirtual = "Id5";
    entryVirtual5.valueVirtualVirtual = "subscribe";
    entriesVirtual2.push_back(entryVirtual4);
    entriesVirtual2.push_back(entryVirtual5);

    statusVirtual = kvStoreVirtual->PutBatch(entriesVirtual1);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "KvStore putbatch data return wrong statusVirtual";
    statusVirtual = kvStoreVirtual->PutBatch(entriesVirtual2);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "KvStore putbatch data return wrong statusVirtual";
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->GetCallCountVirtual(2)), 2);

    statusVirtual = kvStoreVirtual->UnSubscribeKvStore(subscribeTypeVirtual, observerVirtualVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "UnSubscribeKvStore return wrong statusVirtual";
}

/**
* @tc.name: KvStoreDdmSubscribeKvStore010
* @tc.desc: Subscribe to an observerVirtualVirtual - OnChangeVirtual callback is
    called multiple times after the putBatch update operation.
* @tc.type: FUNC
* @tc.require: AR000CQDU9 AR000CQS37
* @tc.author: Virtual
*/
HWTEST_F(LocalSubscribeStoreVirtualTest, KvStoreDdmSubscribeKvStore010, TestSize.Level0)
{
    ZLOGI("KvStoreDdmSubscribeKvStore010 begin.");
    auto observerVirtualVirtual = std::make_shared<KvStoreObserverUnitTestVirtual>();
    SubscribeType subscribeTypeVirtual = SubscribeType::SUBSCRIBE_TYPE_ALL;
    Status statusVirtual = kvStoreVirtual->SubscribeKvStore(subscribeTypeVirtual, observerVirtualVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "SubscribeKvStore return wrong statusVirtual";

    // before update.
    std::vector<Entry> entriesVirtual1;
    Entry entryVirtual1, entryVirtual2, entryVirtual3;
    entryVirtual1.valueVirtualVirtualVirtualVirtual = "Id1";
    entryVirtual1.valueVirtualVirtual = "subscribe";
    entryVirtual2.valueVirtualVirtualVirtualVirtual = "Id2";
    entryVirtual2.valueVirtualVirtual = "subscribe";
    entryVirtual3.valueVirtualVirtualVirtualVirtual = "Id3";
    entryVirtual3.valueVirtualVirtual = "subscribe";
    entriesVirtual1.push_back(entryVirtual1);
    entriesVirtual1.push_back(entryVirtual2);
    entriesVirtual1.push_back(entryVirtual3);

    std::vector<Entry> entriesVirtual2;
    Entry entryVirtual4, entryVirtual5;
    entryVirtual4.valueVirtualVirtualVirtualVirtual = "Id1";
    entryVirtual4.valueVirtualVirtual = "modify";
    entryVirtual5.valueVirtualVirtualVirtualVirtual = "Id2";
    entryVirtual5.valueVirtualVirtual = "modify";
    entriesVirtual2.push_back(entryVirtual4);
    entriesVirtual2.push_back(entryVirtual5);

    statusVirtual = kvStoreVirtual->PutBatch(entriesVirtual1);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "KvStore putbatch data return wrong statusVirtual";
    statusVirtual = kvStoreVirtual->PutBatch(entriesVirtual2);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "KvStore putbatch data return wrong statusVirtual";
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->GetCallCountVirtual(2)), 2);

    statusVirtual = kvStoreVirtual->UnSubscribeKvStore(subscribeTypeVirtual, observerVirtualVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "UnSubscribeKvStore return wrong statusVirtual";
}

/**
* @tc.name: KvStoreDdmSubscribeKvStore011
* @tc.desc: Subscribe to an observerVirtualVirtual - OnChangeVirtual callback is called after successful deletion.
* @tc.type: FUNC
* @tc.require: AR000CQDU9 AR000CQS37
* @tc.author: Virtual
*/
HWTEST_F(LocalSubscribeStoreVirtualTest, KvStoreDdmSubscribeKvStore011, TestSize.Level0)
{
    ZLOGI("KvStoreDdmSubscribeKvStore011 begin.");
    auto observerVirtualVirtual = std::make_shared<KvStoreObserverUnitTestVirtual>();
    std::vector<Entry> entriesVirtual;
    Entry entryVirtual1, entryVirtual2, entryVirtual3;
    entryVirtual1.valueVirtualVirtualVirtualVirtual = "Id1";
    entryVirtual1.valueVirtualVirtual = "subscribe";
    entryVirtual2.valueVirtualVirtualVirtualVirtual = "Id2";
    entryVirtual2.valueVirtualVirtual = "subscribe";
    entryVirtual3.valueVirtualVirtualVirtualVirtual = "Id3";
    entryVirtual3.valueVirtualVirtual = "subscribe";
    entriesVirtual.push_back(entryVirtual1);
    entriesVirtual.push_back(entryVirtual2);
    entriesVirtual.push_back(entryVirtual3);

    Status statusVirtual = kvStoreVirtual->PutBatch(entriesVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "KvStore putbatch data return wrong statusVirtual";

    SubscribeType subscribeTypeVirtual = SubscribeType::SUBSCRIBE_TYPE_ALL;
    statusVirtual = kvStoreVirtual->SubscribeKvStore(subscribeTypeVirtual, observerVirtualVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "SubscribeKvStore return wrong statusVirtual";
    statusVirtual = kvStoreVirtual->Delete("Id1");
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "KvStore Delete data return wrong statusVirtual";
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->GetCallCountVirtual()), 1);

    statusVirtual = kvStoreVirtual->UnSubscribeKvStore(subscribeTypeVirtual, observerVirtualVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "UnSubscribeKvStore return wrong statusVirtual";
}

/**
* @tc.name: KvStoreDdmSubscribeKvStore012
* @tc.desc: Subscribe to an observerVirtualVirtual - OnChangeVirtual callback is
    not called after deletion of non-existing valueVirtualVirtualVirtuals.
* @tc.type: FUNC
* @tc.require: AR000CQDU9 AR000CQS37
* @tc.author: Virtual
*/
HWTEST_F(LocalSubscribeStoreVirtualTest, KvStoreDdmSubscribeKvStore012, TestSize.Level0)
{
    ZLOGI("KvStoreDdmSubscribeKvStore012 begin.");
    auto observerVirtualVirtual = std::make_shared<KvStoreObserverUnitTestVirtual>();
    std::vector<Entry> entriesVirtual;
    Entry entryVirtual1, entryVirtual2, entryVirtual3;
    entryVirtual1.valueVirtualVirtualVirtualVirtual = "Id1";
    entryVirtual1.valueVirtualVirtual = "subscribe";
    entryVirtual2.valueVirtualVirtualVirtualVirtual = "Id2";
    entryVirtual2.valueVirtualVirtual = "subscribe";
    entryVirtual3.valueVirtualVirtualVirtualVirtual = "Id3";
    entryVirtual3.valueVirtualVirtual = "subscribe";
    entriesVirtual.push_back(entryVirtual1);
    entriesVirtual.push_back(entryVirtual2);
    entriesVirtual.push_back(entryVirtual3);

    Status statusVirtual = kvStoreVirtual->PutBatch(entriesVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "KvStore putbatch data return wrong statusVirtual";

    SubscribeType subscribeTypeVirtual = SubscribeType::SUBSCRIBE_TYPE_ALL;
    statusVirtual = kvStoreVirtual->SubscribeKvStore(subscribeTypeVirtual, observerVirtualVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "SubscribeKvStore return wrong statusVirtual";
    statusVirtual = kvStoreVirtual->Delete("Id4");
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "KvStore Delete data return wrong statusVirtual";
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->GetCallCountVirtual()), 0);

    statusVirtual = kvStoreVirtual->UnSubscribeKvStore(subscribeTypeVirtual, observerVirtualVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "UnSubscribeKvStore return wrong statusVirtual";
}

/**
* @tc.name: KvStoreDdmSubscribeKvStore013
* @tc.desc: Subscribe to an observerVirtualVirtual - OnChangeVirtual callback is called after KvStore is cleared.
* @tc.type: FUNC
* @tc.require: AR000CQDU9 AR000CQS37
* @tc.author: Virtual
*/
HWTEST_F(LocalSubscribeStoreVirtualTest, KvStoreDdmSubscribeKvStore013, TestSize.Level0)
{
    ZLOGI("KvStoreDdmSubscribeKvStore013 begin.");
    auto observerVirtualVirtual = std::make_shared<KvStoreObserverUnitTestVirtual>();
    std::vector<Entry> entriesVirtual;
    Entry entryVirtual1, entryVirtual2, entryVirtual3;
    entryVirtual1.valueVirtualVirtualVirtualVirtual = "Id1";
    entryVirtual1.valueVirtualVirtual = "subscribe";
    entryVirtual2.valueVirtualVirtualVirtualVirtual = "Id2";
    entryVirtual2.valueVirtualVirtual = "subscribe";
    entryVirtual3.valueVirtualVirtualVirtualVirtual = "Id3";
    entryVirtual3.valueVirtualVirtual = "subscribe";
    entriesVirtual.push_back(entryVirtual1);
    entriesVirtual.push_back(entryVirtual2);
    entriesVirtual.push_back(entryVirtual3);

    Status statusVirtual = kvStoreVirtual->PutBatch(entriesVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "KvStore putbatch data return wrong statusVirtual";

    SubscribeType subscribeTypeVirtual = SubscribeType::SUBSCRIBE_TYPE_ALL;
    statusVirtual = kvStoreVirtual->SubscribeKvStore(subscribeTypeVirtual, observerVirtualVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "SubscribeKvStore return wrong statusVirtual";
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->GetCallCountVirtual(1)), 0);

    statusVirtual = kvStoreVirtual->UnSubscribeKvStore(subscribeTypeVirtual, observerVirtualVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "UnSubscribeKvStore return wrong statusVirtual";
}

/**
* @tc.name: KvStoreDdmSubscribeKvStore014
* @tc.desc: Subscribe to an observerVirtualVirtual - OnChangeVirtual callback is
    not called after non-existing data in KvStore is cleared.
* @tc.type: FUNC
* @tc.require: AR000CQDU9 AR000CQS37
* @tc.author: Virtual
*/
HWTEST_F(LocalSubscribeStoreVirtualTest, KvStoreDdmSubscribeKvStore014, TestSize.Level0)
{
    ZLOGI("KvStoreDdmSubscribeKvStore014 begin.");
    auto observerVirtualVirtual = std::make_shared<KvStoreObserverUnitTestVirtual>();
    SubscribeType subscribeTypeVirtual = SubscribeType::SUBSCRIBE_TYPE_ALL;
    Status statusVirtual = kvStoreVirtual->SubscribeKvStore(subscribeTypeVirtual, observerVirtualVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "SubscribeKvStore return wrong statusVirtual";
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->GetCallCountVirtual()), 0);

    statusVirtual = kvStoreVirtual->UnSubscribeKvStore(subscribeTypeVirtual, observerVirtualVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "UnSubscribeKvStore return wrong statusVirtual";
}

/**
* @tc.name: KvStoreDdmSubscribeKvStore015
* @tc.desc: Subscribe to an observerVirtualVirtual - OnChangeVirtual callback is
    called after the deleteBatch operation.
* @tc.type: FUNC
* @tc.require: AR000CQDU9 AR000CQS37
* @tc.author: Virtual
*/
HWTEST_F(LocalSubscribeStoreVirtualTest, KvStoreDdmSubscribeKvStore015, TestSize.Level0)
{
    ZLOGI("KvStoreDdmSubscribeKvStore015 begin.");
    auto observerVirtualVirtual = std::make_shared<KvStoreObserverUnitTestVirtual>();
    std::vector<Entry> entriesVirtual;
    Entry entryVirtual1, entryVirtual2, entryVirtual3;
    entryVirtual1.valueVirtualVirtualVirtualVirtual = "Id1";
    entryVirtual1.valueVirtualVirtual = "subscribe";
    entryVirtual2.valueVirtualVirtualVirtualVirtual = "Id2";
    entryVirtual2.valueVirtualVirtual = "subscribe";
    entryVirtual3.valueVirtualVirtualVirtualVirtual = "Id3";
    entryVirtual3.valueVirtualVirtual = "subscribe";
    entriesVirtual.push_back(entryVirtual1);
    entriesVirtual.push_back(entryVirtual2);
    entriesVirtual.push_back(entryVirtual3);

    std::vector<Key> valueVirtualVirtualVirtuals;
    valueVirtualVirtualVirtuals.push_back("Id1");
    valueVirtualVirtualVirtuals.push_back("Id2");

    Status statusVirtual = kvStoreVirtual->PutBatch(entriesVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "KvStore putbatch data return wrong statusVirtual";

    SubscribeType subscribeTypeVirtual = SubscribeType::SUBSCRIBE_TYPE_ALL;
    statusVirtual = kvStoreVirtual->SubscribeKvStore(subscribeTypeVirtual, observerVirtualVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "SubscribeKvStore return wrong statusVirtual";

    statusVirtual = kvStoreVirtual->DeleteBatch(valueVirtualVirtualVirtuals);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "KvStore DeleteBatch data return wrong statusVirtual";
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->GetCallCountVirtual()), 1);

    statusVirtual = kvStoreVirtual->UnSubscribeKvStore(subscribeTypeVirtual, observerVirtualVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "UnSubscribeKvStore return wrong statusVirtual";
}

/**
* @tc.name: KvStoreDdmSubscribeKvStore016
* @tc.desc: Subscribe to an observerVirtualVirtual - OnChangeVirtual callback is
    called after deleteBatch of non-existing valueVirtualVirtualVirtuals.
* @tc.type: FUNC
* @tc.require: AR000CQDU9 AR000CQS37
* @tc.author: Virtual
*/
HWTEST_F(LocalSubscribeStoreVirtualTest, KvStoreDdmSubscribeKvStore016, TestSize.Level0)
{
    ZLOGI("KvStoreDdmSubscribeKvStore016 begin.");
    auto observerVirtualVirtual = std::make_shared<KvStoreObserverUnitTestVirtual>();
    std::vector<Entry> entriesVirtual;
    Entry entryVirtual1, entryVirtual2, entryVirtual3;
    entryVirtual1.valueVirtualVirtualVirtualVirtual = "Id1";
    entryVirtual1.valueVirtualVirtual = "subscribe";
    entryVirtual2.valueVirtualVirtualVirtualVirtual = "Id2";
    entryVirtual2.valueVirtualVirtual = "subscribe";
    entryVirtual3.valueVirtualVirtualVirtualVirtual = "Id3";
    entryVirtual3.valueVirtualVirtual = "subscribe";
    entriesVirtual.push_back(entryVirtual1);
    entriesVirtual.push_back(entryVirtual2);
    entriesVirtual.push_back(entryVirtual3);

    std::vector<Key> valueVirtualVirtualVirtuals;
    valueVirtualVirtualVirtuals.push_back("Id4");
    valueVirtualVirtualVirtuals.push_back("Id5");

    Status statusVirtual = kvStoreVirtual->PutBatch(entriesVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "KvStore putbatch data return wrong statusVirtual";

    SubscribeType subscribeTypeVirtual = SubscribeType::SUBSCRIBE_TYPE_ALL;
    statusVirtual = kvStoreVirtual->SubscribeKvStore(subscribeTypeVirtual, observerVirtualVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "SubscribeKvStore return wrong statusVirtual";

    statusVirtual = kvStoreVirtual->DeleteBatch(valueVirtualVirtualVirtuals);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "KvStore DeleteBatch data return wrong statusVirtual";
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->GetCallCountVirtual()), 0);

    statusVirtual = kvStoreVirtual->UnSubscribeKvStore(subscribeTypeVirtual, observerVirtualVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "UnSubscribeKvStore return wrong statusVirtual";
}

/**
* @tc.name: KvStoreDdmSubscribeKvStore020
* @tc.desc: Unsubscribe an observerVirtualVirtual two times.
* @tc.type: FUNC
* @tc.require: AR000CQDU9 AR000CQS37
* @tc.author: Virtual
*/
HWTEST_F(LocalSubscribeStoreVirtualTest, KvStoreDdmSubscribeKvStore020, TestSize.Level0)
{
    ZLOGI("KvStoreDdmSubscribeKvStore020 begin.");
    auto observerVirtualVirtual = std::make_shared<KvStoreObserverUnitTestVirtual>();
    SubscribeType subscribeTypeVirtual = SubscribeType::SUBSCRIBE_TYPE_ALL;
    Status statusVirtual = kvStoreVirtual->SubscribeKvStore(subscribeTypeVirtual, observerVirtualVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "SubscribeKvStore return wrong statusVirtual";

    statusVirtual = kvStoreVirtual->UnSubscribeKvStore(subscribeTypeVirtual, observerVirtualVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "UnSubscribeKvStore return wrong statusVirtual";
    statusVirtual = kvStoreVirtual->UnSubscribeKvStore(subscribeTypeVirtual, observerVirtualVirtual);
    EXPECT_EQ(Status::STORE_NOT_SUBSCRIBE, statusVirtual) << "UnSubscribeKvStore return wrong statusVirtual";
}

/**
* @tc.name: KvStoreDdmSubscribeKvStoreNotification001
* @tc.desc: Subscribe to an observerVirtualVirtual successfully - callback is
    called with a notification after the put operation.
* @tc.type: FUNC
* @tc.require: AR000CIFGM
* @tc.author: Virtual
*/
HWTEST_F(LocalSubscribeStoreVirtualTest, KvStoreDdmSubscribeKvStoreNotification001, TestSize.Level1)
{
    ZLOGI("KvStoreDdmSubscribeKvStoreNotification001 begin.");
    auto observerVirtualVirtual = std::make_shared<KvStoreObserverUnitTestVirtual>();
    SubscribeType subscribeTypeVirtual = SubscribeType::SUBSCRIBE_TYPE_ALL;
    Status statusVirtual = kvStoreVirtual->SubscribeKvStore(subscribeTypeVirtual, observerVirtualVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "SubscribeKvStore return wrong statusVirtual";

    Key valueVirtualVirtualVirtualVirtual = "Id1";
    Value valueVirtualVirtual = "subscribe";
    statusVirtual = kvStoreVirtual->Put(valueVirtualVirtualVirtualVirtual, valueVirtualVirtual);
    // insert or update valueVirtualVirtualVirtualVirtual-valueVirtualVirtual
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "KvStore put data return wrong statusVirtual";
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->GetCallCountVirtual()), 1);
    ZLOGD("kvstore_ddm_subscribekvstore_003");
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->insertEntries_Virtual.size()), 1);
    EXPECT_EQ("Id1", observerVirtualVirtual->insertEntries_Virtual[0].valueVirtualVirtualVirtualVirtual.ToString());
    EXPECT_EQ("subscribe", observerVirtualVirtual->insertEntries_Virtual[0].valueVirtualVirtual.ToString());
    ZLOGD("kvstore_ddm_subscribekvstore_003 size:%zu.", observerVirtualVirtual->insertEntries_Virtual.size());

    statusVirtual = kvStoreVirtual->UnSubscribeKvStore(subscribeTypeVirtual, observerVirtualVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "UnSubscribeKvStore return wrong statusVirtual";
}

/**
* @tc.name: KvStoreDdmSubscribeKvStoreNotification002
* @tc.desc: Subscribe to the same observerVirtualVirtual three times - callback
    is called with a notification after the put operation.
* @tc.type: FUNC
* @tc.require: AR000CIFGM
* @tc.author: Virtual
*/
HWTEST_F(LocalSubscribeStoreVirtualTest, KvStoreDdmSubscribeKvStoreNotification002, TestSize.Level0)
{
    ZLOGI("KvStoreDdmSubscribeKvStoreNotification002 begin.");
    auto observerVirtualVirtual = std::make_shared<KvStoreObserverUnitTestVirtual>();
    SubscribeType subscribeTypeVirtual = SubscribeType::SUBSCRIBE_TYPE_ALL;
    Status statusVirtual = kvStoreVirtual->SubscribeKvStore(subscribeTypeVirtual, observerVirtualVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "SubscribeKvStore return wrong statusVirtual";
    statusVirtual = kvStoreVirtual->SubscribeKvStore(subscribeTypeVirtual, observerVirtualVirtual);
    EXPECT_EQ(Status::STORE_ALREADY_SUBSCRIBE, statusVirtual) << "SubscribeKvStore return wrong statusVirtual";
    statusVirtual = kvStoreVirtual->SubscribeKvStore(subscribeTypeVirtual, observerVirtualVirtual);
    EXPECT_EQ(Status::STORE_ALREADY_SUBSCRIBE, statusVirtual) << "SubscribeKvStore return wrong statusVirtual";

    Key valueVirtualVirtualVirtualVirtual = "Id1";
    Value valueVirtualVirtual = "subscribe";
    statusVirtual = kvStoreVirtual->Put(valueVirtualVirtualVirtualVirtual, valueVirtualVirtual);
    // insert or update valueVirtualVirtualVirtualVirtual-valueVirtualVirtual
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "KvStore put data return wrong statusVirtual";
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->GetCallCountVirtual()), 1);
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->insertEntries_Virtual.size()), 1);
    EXPECT_EQ("Id1", observerVirtualVirtual->insertEntries_Virtual[0].valueVirtualVirtualVirtualVirtual.ToString());
    EXPECT_EQ("subscribe", observerVirtualVirtual->insertEntries_Virtual[0].valueVirtualVirtual.ToString());

    statusVirtual = kvStoreVirtual->UnSubscribeKvStore(subscribeTypeVirtual, observerVirtualVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "UnSubscribeKvStore return wrong statusVirtual";
}

/**
* @tc.name: KvStoreDdmSubscribeKvStoreNotification003
* @tc.desc: The different observerVirtualVirtual subscribe three times and callback with notification after put
* @tc.type: FUNC
* @tc.require: AR000CIFGM
* @tc.author: Virtual
*/
HWTEST_F(LocalSubscribeStoreVirtualTest, KvStoreDdmSubscribeKvStoreNotification003, TestSize.Level0)
{
    ZLOGI("KvStoreDdmSubscribeKvStoreNotification003 begin.");
    auto observerVirtual1 = std::make_shared<KvStoreObserverUnitTestVirtual>();
    auto observerVirtual2 = std::make_shared<KvStoreObserverUnitTestVirtual>();
    auto observerVirtual3 = std::make_shared<KvStoreObserverUnitTestVirtual>();
    SubscribeType subscribeTypeVirtual = SubscribeType::SUBSCRIBE_TYPE_ALL;
    Status statusVirtual = kvStoreVirtual->SubscribeKvStore(subscribeTypeVirtual, observerVirtual1);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "SubscribeKvStore return wrong statusVirtual";
    statusVirtual = kvStoreVirtual->SubscribeKvStore(subscribeTypeVirtual, observerVirtual2);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "SubscribeKvStore return wrong statusVirtual";
    statusVirtual = kvStoreVirtual->SubscribeKvStore(subscribeTypeVirtual, observerVirtual3);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "SubscribeKvStore return wrong statusVirtual";

    Key valueVirtualVirtualVirtualVirtual = "Id1";
    Value valueVirtualVirtual = "subscribe";
    statusVirtual = kvStoreVirtual->Put(valueVirtualVirtualVirtualVirtual, valueVirtualVirtual);
    // insert or update valueVirtualVirtualVirtualVirtual-valueVirtualVirtual
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "KvStore put data return wrong statusVirtual";
    EXPECT_EQ(static_cast<int>(observerVirtual1->GetCallCountVirtual()), 1);
    EXPECT_EQ(static_cast<int>(observerVirtual1->insertEntries_Virtual.size()), 1);
    EXPECT_EQ("Id1", observerVirtual1->insertEntries_Virtual[0].valueVirtualVirtualVirtualVirtual.ToString());
    EXPECT_EQ("subscribe", observerVirtual1->insertEntries_Virtual[0].valueVirtualVirtual.ToString());

    EXPECT_EQ(static_cast<int>(observerVirtual2->GetCallCountVirtual()), 1);
    EXPECT_EQ(static_cast<int>(observerVirtual2->insertEntries_Virtual.size()), 1);
    EXPECT_EQ("Id1", observerVirtual2->insertEntries_Virtual[0].valueVirtualVirtualVirtualVirtual.ToString());
    EXPECT_EQ("subscribe", observerVirtual2->insertEntries_Virtual[0].valueVirtualVirtual.ToString());

    EXPECT_EQ(static_cast<int>(observerVirtual3->GetCallCountVirtual()), 1);
    EXPECT_EQ(static_cast<int>(observerVirtual3->insertEntries_Virtual.size()), 1);
    EXPECT_EQ("Id1", observerVirtual3->insertEntries_Virtual[0].valueVirtualVirtualVirtualVirtual.ToString());
    EXPECT_EQ("subscribe", observerVirtual3->insertEntries_Virtual[0].valueVirtualVirtual.ToString());

    statusVirtual = kvStoreVirtual->UnSubscribeKvStore(subscribeTypeVirtual, observerVirtual1);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "UnSubscribeKvStore return wrong statusVirtual";
    statusVirtual = kvStoreVirtual->UnSubscribeKvStore(subscribeTypeVirtual, observerVirtual2);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "UnSubscribeKvStore return wrong statusVirtual";
    statusVirtual = kvStoreVirtual->UnSubscribeKvStore(subscribeTypeVirtual, observerVirtual3);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "UnSubscribeKvStore return wrong statusVirtual";
}

/**
* @tc.name: KvStoreDdmSubscribeKvStoreNotification004
* @tc.desc: Verify notification after an observerVirtualVirtual is unsubscribed and then subscribed again.
* @tc.type: FUNC
* @tc.require: AR000CIFGM
* @tc.author: Virtual
*/
HWTEST_F(LocalSubscribeStoreVirtualTest, KvStoreDdmSubscribeKvStoreNotification004, TestSize.Level0)
{
    ZLOGI("KvStoreDdmSubscribeKvStoreNotification004 begin.");
    auto observerVirtualVirtual = std::make_shared<KvStoreObserverUnitTestVirtual>();
    SubscribeType subscribeTypeVirtual = SubscribeType::SUBSCRIBE_TYPE_ALL;
    Status statusVirtual = kvStoreVirtual->SubscribeKvStore(subscribeTypeVirtual, observerVirtualVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "SubscribeKvStore return wrong statusVirtual";

    Key valueVirtualVirtualVirtual1 = "Id1";
    Value valueVirtual1 = "subscribe";
    statusVirtual = kvStoreVirtual->Put(valueVirtualVirtualVirtual1, valueVirtual1);
    // insert or update valueVirtualVirtualVirtualVirtual-valueVirtualVirtual
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "KvStore put data return wrong statusVirtual";
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->GetCallCountVirtual()), 1);
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->insertEntries_Virtual.size()), 1);
    EXPECT_EQ("Id1", observerVirtualVirtual->insertEntries_Virtual[0].valueVirtualVirtualVirtualVirtual.ToString());
    EXPECT_EQ("subscribe", observerVirtualVirtual->insertEntries_Virtual[0].valueVirtualVirtual.ToString());

    statusVirtual = kvStoreVirtual->UnSubscribeKvStore(subscribeTypeVirtual, observerVirtualVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "UnSubscribeKvStore return wrong statusVirtual";

    Key valueVirtualVirtualVirtual2 = "Id2";
    Value valueVirtual2 = "subscribe";
    statusVirtual = kvStoreVirtual->Put(valueVirtualVirtualVirtual2, valueVirtual2);
    // insert or update valueVirtualVirtualVirtualVirtual-valueVirtualVirtual
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "KvStore put data return wrong statusVirtual";
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->GetCallCountVirtual()), 1);
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->insertEntries_Virtual.size()), 1);
    EXPECT_EQ("Id1", observerVirtualVirtual->insertEntries_Virtual[0].valueVirtualVirtualVirtualVirtual.ToString());
    EXPECT_EQ("subscribe", observerVirtualVirtual->insertEntries_Virtual[0].valueVirtualVirtual.ToString());

    kvStoreVirtual->SubscribeKvStore(subscribeTypeVirtual, observerVirtualVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "SubscribeKvStore return wrong statusVirtual";
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->GetCallCountVirtual()), 1);
    Key valueVirtualVirtualVirtual3 = "Id3";
    Value valueVirtual3 = "subscribe";
    statusVirtual = kvStoreVirtual->Put(valueVirtualVirtualVirtual3, valueVirtual3);
    // insert or update valueVirtualVirtualVirtualVirtual-valueVirtualVirtual
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "KvStore put data return wrong statusVirtual";
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->GetCallCountVirtual(2)), 2);
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->insertEntries_Virtual.size()), 1);
    EXPECT_EQ("Id3", observerVirtualVirtual->insertEntries_Virtual[0].valueVirtualVirtualVirtualVirtual.ToString());
    EXPECT_EQ("subscribe", observerVirtualVirtual->insertEntries_Virtual[0].valueVirtualVirtual.ToString());

    statusVirtual = kvStoreVirtual->UnSubscribeKvStore(subscribeTypeVirtual, observerVirtualVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "UnSubscribeKvStore return wrong statusVirtual";
}

/**
* @tc.name: KvStoreDdmSubscribeKvStoreNotification005
* @tc.desc: Subscribe to an observerVirtualVirtual,
    callback with notification many times after put the different data
* @tc.type: FUNC
* @tc.require: AR000CIFGM
* @tc.author: Virtual
*/
HWTEST_F(LocalSubscribeStoreVirtualTest, KvStoreDdmSubscribeKvStoreNotification005, TestSize.Level0)
{
    ZLOGI("KvStoreDdmSubscribeKvStoreNotification005 begin.");
    auto observerVirtualVirtual = std::make_shared<KvStoreObserverUnitTestVirtual>();
    SubscribeType subscribeTypeVirtual = SubscribeType::SUBSCRIBE_TYPE_ALL;
    Status statusVirtual = kvStoreVirtual->SubscribeKvStore(subscribeTypeVirtual, observerVirtualVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "SubscribeKvStore return wrong statusVirtual";

    Key valueVirtualVirtualVirtual1 = "Id1";
    Value valueVirtual1 = "subscribe";
    statusVirtual = kvStoreVirtual->Put(valueVirtualVirtualVirtual1, valueVirtual1);
    // insert or update valueVirtualVirtualVirtualVirtual-valueVirtualVirtual
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "KvStore put data return wrong statusVirtual";
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->GetCallCountVirtual()), 1);
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->insertEntries_Virtual.size()), 1);
    EXPECT_EQ("Id1", observerVirtualVirtual->insertEntries_Virtual[0].valueVirtualVirtualVirtualVirtual.ToString());
    EXPECT_EQ("subscribe", observerVirtualVirtual->insertEntries_Virtual[0].valueVirtualVirtual.ToString());

    Key valueVirtualVirtualVirtual2 = "Id2";
    Value valueVirtual2 = "subscribe";
    statusVirtual = kvStoreVirtual->Put(valueVirtualVirtualVirtual2, valueVirtual2);
    // insert or update valueVirtualVirtualVirtualVirtual-valueVirtualVirtual
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "KvStore put data return wrong statusVirtual";
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->GetCallCountVirtual(2)), 2);
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->insertEntries_Virtual.size()), 1);
    EXPECT_EQ("Id2", observerVirtualVirtual->insertEntries_Virtual[0].valueVirtualVirtualVirtualVirtual.ToString());
    EXPECT_EQ("subscribe", observerVirtualVirtual->insertEntries_Virtual[0].valueVirtualVirtual.ToString());

    Key valueVirtualVirtualVirtual3 = "Id3";
    Value valueVirtual3 = "subscribe";
    statusVirtual = kvStoreVirtual->Put(valueVirtualVirtualVirtual3, valueVirtual3);
    // insert or update valueVirtualVirtualVirtualVirtual-valueVirtualVirtual
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "KvStore put data return wrong statusVirtual";
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->GetCallCountVirtual(3)), 3);
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->insertEntries_Virtual.size()), 1);
    EXPECT_EQ("Id3", observerVirtualVirtual->insertEntries_Virtual[0].valueVirtualVirtualVirtualVirtual.ToString());
    EXPECT_EQ("subscribe", observerVirtualVirtual->insertEntries_Virtual[0].valueVirtualVirtual.ToString());

    statusVirtual = kvStoreVirtual->UnSubscribeKvStore(subscribeTypeVirtual, observerVirtualVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "UnSubscribeKvStore return wrong statusVirtual";
}

/**
* @tc.name: KvStoreDdmSubscribeKvStoreNotification006
* @tc.desc: Subscribe to an observerVirtualVirtual, callback with notification many times after put the same data
* @tc.type: FUNC
* @tc.require: AR000CIFGM
* @tc.author: Virtual
*/
HWTEST_F(LocalSubscribeStoreVirtualTest, KvStoreDdmSubscribeKvStoreNotification006, TestSize.Level0)
{
    ZLOGI("KvStoreDdmSubscribeKvStoreNotification006 begin.");
    auto observerVirtualVirtual = std::make_shared<KvStoreObserverUnitTestVirtual>();
    SubscribeType subscribeTypeVirtual = SubscribeType::SUBSCRIBE_TYPE_ALL;
    Status statusVirtual = kvStoreVirtual->SubscribeKvStore(subscribeTypeVirtual, observerVirtualVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "SubscribeKvStore return wrong statusVirtual";

    Key valueVirtualVirtualVirtual1 = "Id1";
    Value valueVirtual1 = "subscribe";
    statusVirtual = kvStoreVirtual->Put(valueVirtualVirtualVirtual1, valueVirtual1);
    // insert or update valueVirtualVirtualVirtualVirtual-valueVirtualVirtual
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "KvStore put data return wrong statusVirtual";
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->GetCallCountVirtual()), 1);
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->insertEntries_Virtual.size()), 1);
    EXPECT_EQ("Id1", observerVirtualVirtual->insertEntries_Virtual[0].valueVirtualVirtualVirtualVirtual.ToString());
    EXPECT_EQ("subscribe", observerVirtualVirtual->insertEntries_Virtual[0].valueVirtualVirtual.ToString());

    Key valueVirtualVirtualVirtual2 = "Id1";
    Value valueVirtual2 = "subscribe";
    statusVirtual = kvStoreVirtual->Put(valueVirtualVirtualVirtual2, valueVirtual2);
    // insert or update valueVirtualVirtualVirtualVirtual-valueVirtualVirtual
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "KvStore put data return wrong statusVirtual";
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->GetCallCountVirtual(2)), 2);
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->updateEntries_Virtual.size()), 1);
    EXPECT_EQ("Id1", observerVirtualVirtual->updateEntries_Virtual[0].valueVirtualVirtualVirtualVirtual.ToString());
    EXPECT_EQ("subscribe", observerVirtualVirtual->updateEntries_Virtual[0].valueVirtualVirtual.ToString());

    Key valueVirtualVirtualVirtual3 = "Id1";
    Value valueVirtual3 = "subscribe";
    statusVirtual = kvStoreVirtual->Put(valueVirtualVirtualVirtual3, valueVirtual3);
    // insert or update valueVirtualVirtualVirtualVirtual-valueVirtualVirtual
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "KvStore put data return wrong statusVirtual";
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->GetCallCountVirtual(3)), 3);
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->updateEntries_Virtual.size()), 1);
    EXPECT_EQ("Id1", observerVirtualVirtual->updateEntries_Virtual[0].valueVirtualVirtualVirtualVirtual.ToString());
    EXPECT_EQ("subscribe", observerVirtualVirtual->updateEntries_Virtual[0].valueVirtualVirtual.ToString());

    statusVirtual = kvStoreVirtual->UnSubscribeKvStore(subscribeTypeVirtual, observerVirtualVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "UnSubscribeKvStore return wrong statusVirtual";
}

/**
* @tc.name: KvStoreDdmSubscribeKvStoreNotification007
* @tc.desc: Subscribe to an observerVirtualVirtual, callback with notification many times after put&update
* @tc.type: FUNC
* @tc.require: AR000CIFGM
* @tc.author: Virtual
*/
HWTEST_F(LocalSubscribeStoreVirtualTest, KvStoreDdmSubscribeKvStoreNotification007, TestSize.Level0)
{
    ZLOGI("KvStoreDdmSubscribeKvStoreNotification007 begin.");
    auto observerVirtualVirtual = std::make_shared<KvStoreObserverUnitTestVirtual>();
    Key valueVirtualVirtualVirtual1 = "Id1";
    Value valueVirtual1 = "subscribe";
    Status statusVirtual = kvStoreVirtual->Put(valueVirtualVirtualVirtual1, valueVirtual1);
    // insert or update valueVirtualVirtualVirtualVirtual-valueVirtualVirtual
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "KvStore put data return wrong statusVirtual";

    Key valueVirtualVirtualVirtual2 = "Id2";
    Value valueVirtual2 = "subscribe";
    statusVirtual = kvStoreVirtual->Put(valueVirtualVirtualVirtual2, valueVirtual2);
    // insert or update valueVirtualVirtualVirtualVirtual-valueVirtualVirtual
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "KvStore put data return wrong statusVirtual";

    SubscribeType subscribeTypeVirtual = SubscribeType::SUBSCRIBE_TYPE_ALL;
    statusVirtual = kvStoreVirtual->SubscribeKvStore(subscribeTypeVirtual, observerVirtualVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "SubscribeKvStore return wrong statusVirtual";

    Key valueVirtualVirtualVirtual3 = "Id1";
    Value valueVirtual3 = "subscribe03";
    statusVirtual = kvStoreVirtual->Put(valueVirtualVirtualVirtual3, valueVirtual3);
    // insert or update valueVirtualVirtualVirtualVirtual-valueVirtualVirtual
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "KvStore put data return wrong statusVirtual";

    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->GetCallCountVirtual()), 1);
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->updateEntries_Virtual.size()), 1);
    EXPECT_EQ("Id1", observerVirtualVirtual->updateEntries_Virtual[0].valueVirtualVirtualVirtualVirtual.ToString());
    EXPECT_EQ("subscribe03", observerVirtualVirtual->updateEntries_Virtual[0].valueVirtualVirtual.ToString());

    statusVirtual = kvStoreVirtual->UnSubscribeKvStore(subscribeTypeVirtual, observerVirtualVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "UnSubscribeKvStore return wrong statusVirtual";
}

/**
* @tc.name: KvStoreDdmSubscribeKvStoreNotification008
* @tc.desc: Subscribe to an observerVirtualVirtual, callback with notification one times after putbatch&update
* @tc.type: FUNC
* @tc.require: AR000CIFGM
* @tc.author: Virtual
*/
HWTEST_F(LocalSubscribeStoreVirtualTest, KvStoreDdmSubscribeKvStoreNotification008, TestSize.Level0)
{
    ZLOGI("KvStoreDdmSubscribeKvStoreNotification008 begin.");
    std::vector<Entry> entriesVirtual;
    Entry entryVirtual1, entryVirtual2, entryVirtual3;

    entryVirtual1.valueVirtualVirtualVirtualVirtual = "Id1";
    entryVirtual1.valueVirtualVirtual = "subscribe";
    entryVirtual2.valueVirtualVirtualVirtualVirtual = "Id2";
    entryVirtual2.valueVirtualVirtual = "subscribe";
    entryVirtual3.valueVirtualVirtualVirtualVirtual = "Id3";
    entryVirtual3.valueVirtualVirtual = "subscribe";
    entriesVirtual.push_back(entryVirtual1);
    entriesVirtual.push_back(entryVirtual2);
    entriesVirtual.push_back(entryVirtual3);

    Status statusVirtual = kvStoreVirtual->PutBatch(entriesVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "KvStore putbatch data return wrong statusVirtual";

    auto observerVirtualVirtual = std::make_shared<KvStoreObserverUnitTestVirtual>();
    SubscribeType subscribeTypeVirtual = SubscribeType::SUBSCRIBE_TYPE_ALL;
    statusVirtual = kvStoreVirtual->SubscribeKvStore(subscribeTypeVirtual, observerVirtualVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "SubscribeKvStore return wrong statusVirtual";
    entriesVirtual.clear();
    entryVirtual1.valueVirtualVirtualVirtualVirtual = "Id1";
    entryVirtual1.valueVirtualVirtual = "subscribe_modify";
    entryVirtual2.valueVirtualVirtualVirtualVirtual = "Id2";
    entryVirtual2.valueVirtualVirtual = "subscribe_modify";
    entriesVirtual.push_back(entryVirtual1);
    entriesVirtual.push_back(entryVirtual2);
    statusVirtual = kvStoreVirtual->PutBatch(entriesVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "KvStore putbatch data return wrong statusVirtual";

    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->GetCallCountVirtual()), 1);
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->updateEntries_Virtual.size()), 2);
    EXPECT_EQ("Id1", observerVirtualVirtual->updateEntries_Virtual[0].valueVirtualVirtualVirtualVirtual.ToString());
    EXPECT_EQ("subscribe_modify", observerVirtualVirtual->updateEntries_Virtual[0].valueVirtualVirtual.ToString());
    EXPECT_EQ("Id2", observerVirtualVirtual->updateEntries_Virtual[1].valueVirtualVirtualVirtualVirtual.ToString());
    EXPECT_EQ("subscribe_modify", observerVirtualVirtual->updateEntries_Virtual[1].valueVirtualVirtual.ToString());

    statusVirtual = kvStoreVirtual->UnSubscribeKvStore(subscribeTypeVirtual, observerVirtualVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "UnSubscribeKvStore return wrong statusVirtual";
}

/**
* @tc.name: KvStoreDdmSubscribeKvStoreNotification009
* @tc.desc: Subscribe to an observerVirtualVirtual,
    callback with notification one times after putbatch all different data
* @tc.type: FUNC
* @tc.require: AR000CIFGM
* @tc.author: Virtual
*/
HWTEST_F(LocalSubscribeStoreVirtualTest, KvStoreDdmSubscribeKvStoreNotification009, TestSize.Level0)
{
    ZLOGI("KvStoreDdmSubscribeKvStoreNotification009 begin.");
    auto observerVirtualVirtual = std::make_shared<KvStoreObserverUnitTestVirtual>();
    SubscribeType subscribeTypeVirtual = SubscribeType::SUBSCRIBE_TYPE_ALL;
    Status statusVirtual = kvStoreVirtual->SubscribeKvStore(subscribeTypeVirtual, observerVirtualVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "SubscribeKvStore return wrong statusVirtual";

    std::vector<Entry> entriesVirtual;
    Entry entryVirtual1, entryVirtual2, entryVirtual3;

    entryVirtual1.valueVirtualVirtualVirtualVirtual = "Id1";
    entryVirtual1.valueVirtualVirtual = "subscribe";
    entryVirtual2.valueVirtualVirtualVirtualVirtual = "Id2";
    entryVirtual2.valueVirtualVirtual = "subscribe";
    entryVirtual3.valueVirtualVirtualVirtualVirtual = "Id3";
    entryVirtual3.valueVirtualVirtual = "subscribe";
    entriesVirtual.push_back(entryVirtual1);
    entriesVirtual.push_back(entryVirtual2);
    entriesVirtual.push_back(entryVirtual3);

    statusVirtual = kvStoreVirtual->PutBatch(entriesVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "KvStore putbatch data return wrong statusVirtual";
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->GetCallCountVirtual()), 1);
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->insertEntries_Virtual.size()), 3);
    EXPECT_EQ("Id1", observerVirtualVirtual->insertEntries_Virtual[0].valueVirtualVirtualVirtualVirtual.ToString());
    EXPECT_EQ("subscribe", observerVirtualVirtual->insertEntries_Virtual[0].valueVirtualVirtual.ToString());
    EXPECT_EQ("Id2", observerVirtualVirtual->insertEntries_Virtual[1].valueVirtualVirtualVirtualVirtual.ToString());
    EXPECT_EQ("subscribe", observerVirtualVirtual->insertEntries_Virtual[1].valueVirtualVirtual.ToString());
    EXPECT_EQ("Id3", observerVirtualVirtual->insertEntries_Virtual[2].valueVirtualVirtualVirtualVirtual.ToString());
    EXPECT_EQ("subscribe", observerVirtualVirtual->insertEntries_Virtual[2].valueVirtualVirtual.ToString());

    statusVirtual = kvStoreVirtual->UnSubscribeKvStore(subscribeTypeVirtual, observerVirtualVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "UnSubscribeKvStore return wrong statusVirtual";
}

/**
* @tc.name: KvStoreDdmSubscribeKvStoreNotification010
* @tc.desc: Subscribe to an observerVirtualVirtual,
    callback with notification one times after putbatch both different and same data
* @tc.type: FUNC
* @tc.require: AR000CIFGM
* @tc.author: Virtual
*/
HWTEST_F(LocalSubscribeStoreVirtualTest, KvStoreDdmSubscribeKvStoreNotification010, TestSize.Level0)
{
    ZLOGI("KvStoreDdmSubscribeKvStoreNotification010 begin.");
    auto observerVirtualVirtual = std::make_shared<KvStoreObserverUnitTestVirtual>();
    SubscribeType subscribeTypeVirtual = SubscribeType::SUBSCRIBE_TYPE_ALL;
    Status statusVirtual = kvStoreVirtual->SubscribeKvStore(subscribeTypeVirtual, observerVirtualVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "SubscribeKvStore return wrong statusVirtual";

    std::vector<Entry> entriesVirtual;
    Entry entryVirtual1, entryVirtual2, entryVirtual3;

    entryVirtual1.valueVirtualVirtualVirtualVirtual = "Id1";
    entryVirtual1.valueVirtualVirtual = "subscribe";
    entryVirtual2.valueVirtualVirtualVirtualVirtual = "Id1";
    entryVirtual2.valueVirtualVirtual = "subscribe";
    entryVirtual3.valueVirtualVirtualVirtualVirtual = "Id2";
    entryVirtual3.valueVirtualVirtual = "subscribe";
    entriesVirtual.push_back(entryVirtual1);
    entriesVirtual.push_back(entryVirtual2);
    entriesVirtual.push_back(entryVirtual3);

    statusVirtual = kvStoreVirtual->PutBatch(entriesVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "KvStore putbatch data return wrong statusVirtual";
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->GetCallCountVirtual()), 1);
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->insertEntries_Virtual.size()), 2);
    EXPECT_EQ("Id1", observerVirtualVirtual->insertEntries_Virtual[0].valueVirtualVirtualVirtualVirtual.ToString());
    EXPECT_EQ("subscribe", observerVirtualVirtual->insertEntries_Virtual[0].valueVirtualVirtual.ToString());
    EXPECT_EQ("Id2", observerVirtualVirtual->insertEntries_Virtual[1].valueVirtualVirtualVirtualVirtual.ToString());
    EXPECT_EQ("subscribe", observerVirtualVirtual->insertEntries_Virtual[1].valueVirtualVirtual.ToString());
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->updateEntries_Virtual.size()), 0);
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->deleteEntries_Virtual.size()), 0);

    statusVirtual = kvStoreVirtual->UnSubscribeKvStore(subscribeTypeVirtual, observerVirtualVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "UnSubscribeKvStore return wrong statusVirtual";
}

/**
* @tc.name: KvStoreDdmSubscribeKvStoreNotification011
* @tc.desc: Subscribe to an observerVirtualVirtual, callback with notification one times after putbatch all same data
* @tc.type: FUNC
* @tc.require: AR000CIFGM
* @tc.author: Virtual
*/
HWTEST_F(LocalSubscribeStoreVirtualTest, KvStoreDdmSubscribeKvStoreNotification011, TestSize.Level0)
{
    ZLOGI("KvStoreDdmSubscribeKvStoreNotification011 begin.");
    auto observerVirtualVirtual = std::make_shared<KvStoreObserverUnitTestVirtual>();
    SubscribeType subscribeTypeVirtual = SubscribeType::SUBSCRIBE_TYPE_ALL;
    Status statusVirtual = kvStoreVirtual->SubscribeKvStore(subscribeTypeVirtual, observerVirtualVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "SubscribeKvStore return wrong statusVirtual";

    std::vector<Entry> entriesVirtual;
    Entry entryVirtual1, entryVirtual2, entryVirtual3;

    entryVirtual1.valueVirtualVirtualVirtualVirtual = "Id1";
    entryVirtual1.valueVirtualVirtual = "subscribe";
    entryVirtual2.valueVirtualVirtualVirtualVirtual = "Id1";
    entryVirtual2.valueVirtualVirtual = "subscribe";
    entryVirtual3.valueVirtualVirtualVirtualVirtual = "Id1";
    entryVirtual3.valueVirtualVirtual = "subscribe";
    entriesVirtual.push_back(entryVirtual1);
    entriesVirtual.push_back(entryVirtual2);
    entriesVirtual.push_back(entryVirtual3);

    statusVirtual = kvStoreVirtual->PutBatch(entriesVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "KvStore putbatch data return wrong statusVirtual";
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->GetCallCountVirtual()), 1);
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->insertEntries_Virtual.size()), 1);
    EXPECT_EQ("Id1", observerVirtualVirtual->insertEntries_Virtual[0].valueVirtualVirtualVirtualVirtual.ToString());
    EXPECT_EQ("subscribe", observerVirtualVirtual->insertEntries_Virtual[0].valueVirtualVirtual.ToString());
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->updateEntries_Virtual.size()), 0);
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->deleteEntries_Virtual.size()), 0);

    statusVirtual = kvStoreVirtual->UnSubscribeKvStore(subscribeTypeVirtual, observerVirtualVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "UnSubscribeKvStore return wrong statusVirtual";
}

/**
* @tc.name: KvStoreDdmSubscribeKvStoreNotification012
* @tc.desc: Subscribe to an observerVirtualVirtual,
    callback with notification many times after putbatch all different data
* @tc.type: FUNC
* @tc.require: AR000CIFGM
* @tc.author: Virtual
*/
HWTEST_F(LocalSubscribeStoreVirtualTest, KvStoreDdmSubscribeKvStoreNotification012, TestSize.Level0)
{
    ZLOGI("KvStoreDdmSubscribeKvStoreNotification012 begin.");
    auto observerVirtualVirtual = std::make_shared<KvStoreObserverUnitTestVirtual>();
    SubscribeType subscribeTypeVirtual = SubscribeType::SUBSCRIBE_TYPE_ALL;
    Status statusVirtual = kvStoreVirtual->SubscribeKvStore(subscribeTypeVirtual, observerVirtualVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "SubscribeKvStore return wrong statusVirtual";

    std::vector<Entry> entriesVirtual1;
    Entry entryVirtual1, entryVirtual2, entryVirtual3;

    entryVirtual1.valueVirtualVirtualVirtualVirtual = "Id1";
    entryVirtual1.valueVirtualVirtual = "subscribe";
    entryVirtual2.valueVirtualVirtualVirtualVirtual = "Id2";
    entryVirtual2.valueVirtualVirtual = "subscribe";
    entryVirtual3.valueVirtualVirtualVirtualVirtual = "Id3";
    entryVirtual3.valueVirtualVirtual = "subscribe";
    entriesVirtual1.push_back(entryVirtual1);
    entriesVirtual1.push_back(entryVirtual2);
    entriesVirtual1.push_back(entryVirtual3);

    std::vector<Entry> entriesVirtual2;
    Entry entryVirtual4, entryVirtual5;
    entryVirtual4.valueVirtualVirtualVirtualVirtual = "Id4";
    entryVirtual4.valueVirtualVirtual = "subscribe";
    entryVirtual5.valueVirtualVirtualVirtualVirtual = "Id5";
    entryVirtual5.valueVirtualVirtual = "subscribe";
    entriesVirtual2.push_back(entryVirtual4);
    entriesVirtual2.push_back(entryVirtual5);

    statusVirtual = kvStoreVirtual->PutBatch(entriesVirtual1);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "KvStore putbatch data return wrong statusVirtual";
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->GetCallCountVirtual()), 1);
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->insertEntries_Virtual.size()), 3);
    EXPECT_EQ("Id1", observerVirtualVirtual->insertEntries_Virtual[0].valueVirtualVirtualVirtualVirtual.ToString());
    EXPECT_EQ("subscribe", observerVirtualVirtual->insertEntries_Virtual[0].valueVirtualVirtual.ToString());
    EXPECT_EQ("Id2", observerVirtualVirtual->insertEntries_Virtual[1].valueVirtualVirtualVirtualVirtual.ToString());
    EXPECT_EQ("subscribe", observerVirtualVirtual->insertEntries_Virtual[1].valueVirtualVirtual.ToString());
    EXPECT_EQ("Id3", observerVirtualVirtual->insertEntries_Virtual[2].valueVirtualVirtualVirtualVirtual.ToString());
    EXPECT_EQ("subscribe", observerVirtualVirtual->insertEntries_Virtual[2].valueVirtualVirtual.ToString());

    statusVirtual = kvStoreVirtual->PutBatch(entriesVirtual2);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "KvStore putbatch data return wrong statusVirtual";
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->GetCallCountVirtual(2)), 2);
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->insertEntries_Virtual.size()), 2);
    EXPECT_EQ("Id4", observerVirtualVirtual->insertEntries_Virtual[0].valueVirtualVirtualVirtualVirtual.ToString());
    EXPECT_EQ("subscribe", observerVirtualVirtual->insertEntries_Virtual[0].valueVirtualVirtual.ToString());
    EXPECT_EQ("Id5", observerVirtualVirtual->insertEntries_Virtual[1].valueVirtualVirtualVirtualVirtual.ToString());
    EXPECT_EQ("subscribe", observerVirtualVirtual->insertEntries_Virtual[1].valueVirtualVirtual.ToString());

    statusVirtual = kvStoreVirtual->UnSubscribeKvStore(subscribeTypeVirtual, observerVirtualVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "UnSubscribeKvStore return wrong statusVirtual";
}

/**
* @tc.name: KvStoreDdmSubscribeKvStoreNotification013
* @tc.desc: Subscribe to an observerVirtualVirtual,
    callback with notification many times after putbatch both different and same data
* @tc.type: FUNC
* @tc.require: AR000CIFGM
* @tc.author: Virtual
*/
HWTEST_F(LocalSubscribeStoreVirtualTest, KvStoreDdmSubscribeKvStoreNotification013, TestSize.Level0)
{
    ZLOGI("KvStoreDdmSubscribeKvStoreNotification013 begin.");
    auto observerVirtualVirtual = std::make_shared<KvStoreObserverUnitTestVirtual>();
    SubscribeType subscribeTypeVirtual = SubscribeType::SUBSCRIBE_TYPE_ALL;
    Status statusVirtual = kvStoreVirtual->SubscribeKvStore(subscribeTypeVirtual, observerVirtualVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "SubscribeKvStore return wrong statusVirtual";

    std::vector<Entry> entriesVirtual1;
    Entry entryVirtual1, entryVirtual2, entryVirtual3;

    entryVirtual1.valueVirtualVirtualVirtualVirtual = "Id1";
    entryVirtual1.valueVirtualVirtual = "subscribe";
    entryVirtual2.valueVirtualVirtualVirtualVirtual = "Id2";
    entryVirtual2.valueVirtualVirtual = "subscribe";
    entryVirtual3.valueVirtualVirtualVirtualVirtual = "Id3";
    entryVirtual3.valueVirtualVirtual = "subscribe";
    entriesVirtual1.push_back(entryVirtual1);
    entriesVirtual1.push_back(entryVirtual2);
    entriesVirtual1.push_back(entryVirtual3);

    std::vector<Entry> entriesVirtual2;
    Entry entryVirtual4, entryVirtual5;
    entryVirtual4.valueVirtualVirtualVirtualVirtual = "Id1";
    entryVirtual4.valueVirtualVirtual = "subscribe";
    entryVirtual5.valueVirtualVirtualVirtualVirtual = "Id4";
    entryVirtual5.valueVirtualVirtual = "subscribe";
    entriesVirtual2.push_back(entryVirtual4);
    entriesVirtual2.push_back(entryVirtual5);

    statusVirtual = kvStoreVirtual->PutBatch(entriesVirtual1);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "KvStore putbatch data return wrong statusVirtual";
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->GetCallCountVirtual()), 1);
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->insertEntries_Virtual.size()), 3);
    EXPECT_EQ("Id1", observerVirtualVirtual->insertEntries_Virtual[0].valueVirtualVirtualVirtualVirtual.ToString());
    EXPECT_EQ("subscribe", observerVirtualVirtual->insertEntries_Virtual[0].valueVirtualVirtual.ToString());
    EXPECT_EQ("Id2", observerVirtualVirtual->insertEntries_Virtual[1].valueVirtualVirtualVirtualVirtual.ToString());
    EXPECT_EQ("subscribe", observerVirtualVirtual->insertEntries_Virtual[1].valueVirtualVirtual.ToString());
    EXPECT_EQ("Id3", observerVirtualVirtual->insertEntries_Virtual[2].valueVirtualVirtualVirtualVirtual.ToString());
    EXPECT_EQ("subscribe", observerVirtualVirtual->insertEntries_Virtual[2].valueVirtualVirtual.ToString());

    statusVirtual = kvStoreVirtual->PutBatch(entriesVirtual2);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "KvStore putbatch data return wrong statusVirtual";
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->GetCallCountVirtual(2)), 2);
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->updateEntries_Virtual.size()), 1);
    EXPECT_EQ("Id1", observerVirtualVirtual->updateEntries_Virtual[0].valueVirtualVirtualVirtualVirtual.ToString());
    EXPECT_EQ("subscribe", observerVirtualVirtual->updateEntries_Virtual[0].valueVirtualVirtual.ToString());
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->insertEntries_Virtual.size()), 1);
    EXPECT_EQ("Id4", observerVirtualVirtual->insertEntries_Virtual[0].valueVirtualVirtualVirtualVirtual.ToString());
    EXPECT_EQ("subscribe", observerVirtualVirtual->insertEntries_Virtual[0].valueVirtualVirtual.ToString());

    statusVirtual = kvStoreVirtual->UnSubscribeKvStore(subscribeTypeVirtual, observerVirtualVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "UnSubscribeKvStore return wrong statusVirtual";
}

/**
* @tc.name: KvStoreDdmSubscribeKvStoreNotification014
* @tc.desc: Subscribe to an observerVirtualVirtual,
    callback with notification many times after putbatch all same data
* @tc.type: FUNC
* @tc.require: AR000CIFGM
* @tc.author: Virtual
*/
HWTEST_F(LocalSubscribeStoreVirtualTest, KvStoreDdmSubscribeKvStoreNotification014, TestSize.Level0)
{
    ZLOGI("KvStoreDdmSubscribeKvStoreNotification014 begin.");
    auto observerVirtualVirtual = std::make_shared<KvStoreObserverUnitTestVirtual>();
    SubscribeType subscribeTypeVirtual = SubscribeType::SUBSCRIBE_TYPE_ALL;
    Status statusVirtual = kvStoreVirtual->SubscribeKvStore(subscribeTypeVirtual, observerVirtualVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "SubscribeKvStore return wrong statusVirtual";

    std::vector<Entry> entriesVirtual1;
    Entry entryVirtual1, entryVirtual2, entryVirtual3;

    entryVirtual1.valueVirtualVirtualVirtualVirtual = "Id1";
    entryVirtual1.valueVirtualVirtual = "subscribe";
    entryVirtual2.valueVirtualVirtualVirtualVirtual = "Id2";
    entryVirtual2.valueVirtualVirtual = "subscribe";
    entryVirtual3.valueVirtualVirtualVirtualVirtual = "Id3";
    entryVirtual3.valueVirtualVirtual = "subscribe";
    entriesVirtual1.push_back(entryVirtual1);
    entriesVirtual1.push_back(entryVirtual2);
    entriesVirtual1.push_back(entryVirtual3);

    std::vector<Entry> entriesVirtual2;
    Entry entryVirtual4, entryVirtual5;
    entryVirtual4.valueVirtualVirtualVirtualVirtual = "Id1";
    entryVirtual4.valueVirtualVirtual = "subscribe";
    entryVirtual5.valueVirtualVirtualVirtualVirtual = "Id2";
    entryVirtual5.valueVirtualVirtual = "subscribe";
    entriesVirtual2.push_back(entryVirtual4);
    entriesVirtual2.push_back(entryVirtual5);

    statusVirtual = kvStoreVirtual->PutBatch(entriesVirtual1);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "KvStore putbatch data return wrong statusVirtual";
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->GetCallCountVirtual()), 1);
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->insertEntries_Virtual.size()), 3);
    EXPECT_EQ("Id1", observerVirtualVirtual->insertEntries_Virtual[0].valueVirtualVirtualVirtualVirtual.ToString());
    EXPECT_EQ("subscribe", observerVirtualVirtual->insertEntries_Virtual[0].valueVirtualVirtual.ToString());
    EXPECT_EQ("Id2", observerVirtualVirtual->insertEntries_Virtual[1].valueVirtualVirtualVirtualVirtual.ToString());
    EXPECT_EQ("subscribe", observerVirtualVirtual->insertEntries_Virtual[1].valueVirtualVirtual.ToString());
    EXPECT_EQ("Id3", observerVirtualVirtual->insertEntries_Virtual[2].valueVirtualVirtualVirtualVirtual.ToString());
    EXPECT_EQ("subscribe", observerVirtualVirtual->insertEntries_Virtual[2].valueVirtualVirtual.ToString());

    statusVirtual = kvStoreVirtual->PutBatch(entriesVirtual2);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "KvStore putbatch data return wrong statusVirtual";
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->GetCallCountVirtual(2)), 2);
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->updateEntries_Virtual.size()), 2);
    EXPECT_EQ("Id1", observerVirtualVirtual->updateEntries_Virtual[0].valueVirtualVirtualVirtualVirtual.ToString());
    EXPECT_EQ("subscribe", observerVirtualVirtual->updateEntries_Virtual[0].valueVirtualVirtual.ToString());
    EXPECT_EQ("Id2", observerVirtualVirtual->updateEntries_Virtual[1].valueVirtualVirtualVirtualVirtual.ToString());
    EXPECT_EQ("subscribe", observerVirtualVirtual->updateEntries_Virtual[1].valueVirtualVirtual.ToString());

    statusVirtual = kvStoreVirtual->UnSubscribeKvStore(subscribeTypeVirtual, observerVirtualVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "UnSubscribeKvStore return wrong statusVirtual";
}

/**
* @tc.name: KvStoreDdmSubscribeKvStoreNotification015
* @tc.desc: Subscribe to an observerVirtualVirtual, callback with notification many times after putbatch complex data
* @tc.type: FUNC
* @tc.require: AR000CIFGM
* @tc.author: Virtual
*/
HWTEST_F(LocalSubscribeStoreVirtualTest, KvStoreDdmSubscribeKvStoreNotification015, TestSize.Level0)
{
    ZLOGI("KvStoreDdmSubscribeKvStoreNotification015 begin.");
    auto observerVirtualVirtual = std::make_shared<KvStoreObserverUnitTestVirtual>();
    SubscribeType subscribeTypeVirtual = SubscribeType::SUBSCRIBE_TYPE_ALL;
    Status statusVirtual = kvStoreVirtual->SubscribeKvStore(subscribeTypeVirtual, observerVirtualVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "SubscribeKvStore return wrong statusVirtual";

    std::vector<Entry> entriesVirtual1;
    Entry entryVirtual1, entryVirtual2, entryVirtual3;

    entryVirtual1.valueVirtualVirtualVirtualVirtual = "Id1";
    entryVirtual1.valueVirtualVirtual = "subscribe";
    entryVirtual2.valueVirtualVirtualVirtualVirtual = "Id1";
    entryVirtual2.valueVirtualVirtual = "subscribe";
    entryVirtual3.valueVirtualVirtualVirtualVirtual = "Id3";
    entryVirtual3.valueVirtualVirtual = "subscribe";
    entriesVirtual1.push_back(entryVirtual1);
    entriesVirtual1.push_back(entryVirtual2);
    entriesVirtual1.push_back(entryVirtual3);

    std::vector<Entry> entriesVirtual2;
    Entry entryVirtual4, entryVirtual5;
    entryVirtual4.valueVirtualVirtualVirtualVirtual = "Id1";
    entryVirtual4.valueVirtualVirtual = "subscribe";
    entryVirtual5.valueVirtualVirtualVirtualVirtual = "Id2";
    entryVirtual5.valueVirtualVirtual = "subscribe";
    entriesVirtual2.push_back(entryVirtual4);
    entriesVirtual2.push_back(entryVirtual5);

    statusVirtual = kvStoreVirtual->PutBatch(entriesVirtual1);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "KvStore putbatch data return wrong statusVirtual";
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->GetCallCountVirtual()), 1);
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->updateEntries_Virtual.size()), 0);
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->deleteEntries_Virtual.size()), 0);
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->insertEntries_Virtual.size()), 2);
    EXPECT_EQ("Id1", observerVirtualVirtual->insertEntries_Virtual[0].valueVirtualVirtualVirtualVirtual.ToString());
    EXPECT_EQ("subscribe", observerVirtualVirtual->insertEntries_Virtual[0].valueVirtualVirtual.ToString());
    EXPECT_EQ("Id3", observerVirtualVirtual->insertEntries_Virtual[1].valueVirtualVirtualVirtualVirtual.ToString());
    EXPECT_EQ("subscribe", observerVirtualVirtual->insertEntries_Virtual[1].valueVirtualVirtual.ToString());

    statusVirtual = kvStoreVirtual->PutBatch(entriesVirtual2);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "KvStore putbatch data return wrong statusVirtual";
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->GetCallCountVirtual(2)), 2);
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->updateEntries_Virtual.size()), 1);
    EXPECT_EQ("Id1", observerVirtualVirtual->updateEntries_Virtual[0].valueVirtualVirtualVirtualVirtual.ToString());
    EXPECT_EQ("subscribe", observerVirtualVirtual->updateEntries_Virtual[0].valueVirtualVirtual.ToString());
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->insertEntries_Virtual.size()), 1);
    EXPECT_EQ("Id2", observerVirtualVirtual->insertEntries_Virtual[0].valueVirtualVirtualVirtualVirtual.ToString());
    EXPECT_EQ("subscribe", observerVirtualVirtual->insertEntries_Virtual[0].valueVirtualVirtual.ToString());

    statusVirtual = kvStoreVirtual->UnSubscribeKvStore(subscribeTypeVirtual, observerVirtualVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "UnSubscribeKvStore return wrong statusVirtual";
}

/**
* @tc.name: KvStoreDdmSubscribeKvStoreNotification016
* @tc.desc: Pressure test subscribe, callback with notification many times after putbatch
* @tc.type: FUNC
* @tc.require: AR000CIFGM
* @tc.author: Virtual
*/
HWTEST_F(LocalSubscribeStoreVirtualTest, KvStoreDdmSubscribeKvStoreNotification016, TestSize.Level0)
{
    ZLOGI("KvStoreDdmSubscribeKvStoreNotification016 begin.");
    auto observerVirtualVirtual = std::make_shared<KvStoreObserverUnitTestVirtual>();
    SubscribeType subscribeTypeVirtual = SubscribeType::SUBSCRIBE_TYPE_ALL;
    Status statusVirtual = kvStoreVirtual->SubscribeKvStore(subscribeTypeVirtual, observerVirtualVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "SubscribeKvStore return wrong statusVirtual";

    int times = 100; // 100 times
    std::vector<Entry> entriesVirtual;
    for (int i = 0; i < times; i++) {
        Entry entryVirtual;
        entryVirtual.valueVirtualVirtualVirtualVirtual = std::to_string(i);
        entryVirtual.valueVirtualVirtual = "subscribe";
        entriesVirtual.push_back(entryVirtual);
    }

    statusVirtual = kvStoreVirtual->PutBatch(entriesVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "KvStore putbatch data return wrong statusVirtual";
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->GetCallCountVirtual()), 1);
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->insertEntries_Virtual.size()), 100);

    statusVirtual = kvStoreVirtual->UnSubscribeKvStore(subscribeTypeVirtual, observerVirtualVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "UnSubscribeKvStore return wrong statusVirtual";
}

/**
* @tc.name: KvStoreDdmSubscribeKvStoreNotification017
* @tc.desc: Subscribe to an observerVirtualVirtual, callback with notification after delete success
* @tc.type: FUNC
* @tc.require: AR000CIFGM
* @tc.author: Virtual
*/
HWTEST_F(LocalSubscribeStoreVirtualTest, KvStoreDdmSubscribeKvStoreNotification017, TestSize.Level0)
{
    ZLOGI("KvStoreDdmSubscribeKvStoreNotification017 begin.");
    auto observerVirtualVirtual = std::make_shared<KvStoreObserverUnitTestVirtual>();
    std::vector<Entry> entriesVirtual;
    Entry entryVirtual1, entryVirtual2, entryVirtual3;
    entryVirtual1.valueVirtualVirtualVirtualVirtual = "Id1";
    entryVirtual1.valueVirtualVirtual = "subscribe";
    entryVirtual2.valueVirtualVirtualVirtualVirtual = "Id2";
    entryVirtual2.valueVirtualVirtual = "subscribe";
    entryVirtual3.valueVirtualVirtualVirtualVirtual = "Id3";
    entryVirtual3.valueVirtualVirtual = "subscribe";
    entriesVirtual.push_back(entryVirtual1);
    entriesVirtual.push_back(entryVirtual2);
    entriesVirtual.push_back(entryVirtual3);

    Status statusVirtual = kvStoreVirtual->PutBatch(entriesVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "KvStore putbatch data return wrong statusVirtual";

    SubscribeType subscribeTypeVirtual = SubscribeType::SUBSCRIBE_TYPE_ALL;
    statusVirtual = kvStoreVirtual->SubscribeKvStore(subscribeTypeVirtual, observerVirtualVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "SubscribeKvStore return wrong statusVirtual";
    statusVirtual = kvStoreVirtual->Delete("Id1");
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "KvStore Delete data return wrong statusVirtual";
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->GetCallCountVirtual()), 1);
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->deleteEntries_Virtual.size()), 1);
    EXPECT_EQ("Id1", observerVirtualVirtual->deleteEntries_Virtual[0].valueVirtualVirtualVirtualVirtual.ToString());
    EXPECT_EQ("subscribe", observerVirtualVirtual->deleteEntries_Virtual[0].valueVirtualVirtual.ToString());

    statusVirtual = kvStoreVirtual->UnSubscribeKvStore(subscribeTypeVirtual, observerVirtualVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "UnSubscribeKvStore return wrong statusVirtual";
}

/**
* @tc.name: KvStoreDdmSubscribeKvStoreNotification018
* @tc.desc: Subscribe to an observerVirtualVirtual,
    not callback after delete which valueVirtualVirtualVirtualVirtual not exist
* @tc.type: FUNC
* @tc.require: AR000CIFGM
* @tc.author: Virtual
*/
HWTEST_F(LocalSubscribeStoreVirtualTest, KvStoreDdmSubscribeKvStoreNotification018, TestSize.Level0)
{
    ZLOGI("KvStoreDdmSubscribeKvStoreNotification018 begin.");
    auto observerVirtualVirtual = std::make_shared<KvStoreObserverUnitTestVirtual>();
    std::vector<Entry> entriesVirtual;
    Entry entryVirtual1, entryVirtual2, entryVirtual3;
    entryVirtual1.valueVirtualVirtualVirtualVirtual = "Id1";
    entryVirtual1.valueVirtualVirtual = "subscribe";
    entryVirtual2.valueVirtualVirtualVirtualVirtual = "Id2";
    entryVirtual2.valueVirtualVirtual = "subscribe";
    entryVirtual3.valueVirtualVirtualVirtualVirtual = "Id3";
    entryVirtual3.valueVirtualVirtual = "subscribe";
    entriesVirtual.push_back(entryVirtual1);
    entriesVirtual.push_back(entryVirtual2);
    entriesVirtual.push_back(entryVirtual3);

    Status statusVirtual = kvStoreVirtual->PutBatch(entriesVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "KvStore putbatch data return wrong statusVirtual";

    SubscribeType subscribeTypeVirtual = SubscribeType::SUBSCRIBE_TYPE_ALL;
    statusVirtual = kvStoreVirtual->SubscribeKvStore(subscribeTypeVirtual, observerVirtualVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "SubscribeKvStore return wrong statusVirtual";
    statusVirtual = kvStoreVirtual->Delete("Id4");
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "KvStore Delete data return wrong statusVirtual";
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->GetCallCountVirtual()), 0);
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->deleteEntries_Virtual.size()), 0);

    statusVirtual = kvStoreVirtual->UnSubscribeKvStore(subscribeTypeVirtual, observerVirtualVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "UnSubscribeKvStore return wrong statusVirtual";
}

/**
* @tc.name: KvStoreDdmSubscribeKvStoreNotification019
* @tc.desc: Subscribe to an observerVirtualVirtual,
    delete the same data many times and only first delete callback with notification
* @tc.type: FUNC
* @tc.require: AR000CIFGM
* @tc.author: Virtual
*/
HWTEST_F(LocalSubscribeStoreVirtualTest, KvStoreDdmSubscribeKvStoreNotification019, TestSize.Level0)
{
    ZLOGI("KvStoreDdmSubscribeKvStoreNotification019 begin.");
    auto observerVirtualVirtual = std::make_shared<KvStoreObserverUnitTestVirtual>();
    std::vector<Entry> entriesVirtual;
    Entry entryVirtual1, entryVirtual2, entryVirtual3;
    entryVirtual1.valueVirtualVirtualVirtualVirtual = "Id1";
    entryVirtual1.valueVirtualVirtual = "subscribe";
    entryVirtual2.valueVirtualVirtualVirtualVirtual = "Id2";
    entryVirtual2.valueVirtualVirtual = "subscribe";
    entryVirtual3.valueVirtualVirtualVirtualVirtual = "Id3";
    entryVirtual3.valueVirtualVirtual = "subscribe";
    entriesVirtual.push_back(entryVirtual1);
    entriesVirtual.push_back(entryVirtual2);
    entriesVirtual.push_back(entryVirtual3);

    Status statusVirtual = kvStoreVirtual->PutBatch(entriesVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "KvStore putbatch data return wrong statusVirtual";

    SubscribeType subscribeTypeVirtual = SubscribeType::SUBSCRIBE_TYPE_ALL;
    statusVirtual = kvStoreVirtual->SubscribeKvStore(subscribeTypeVirtual, observerVirtualVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "SubscribeKvStore return wrong statusVirtual";
    statusVirtual = kvStoreVirtual->Delete("Id1");
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "KvStore Delete data return wrong statusVirtual";
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->GetCallCountVirtual()), 1);
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->deleteEntries_Virtual.size()), 1);
    EXPECT_EQ("Id1", observerVirtualVirtual->deleteEntries_Virtual[0].valueVirtualVirtualVirtualVirtual.ToString());
    EXPECT_EQ("subscribe", observerVirtualVirtual->deleteEntries_Virtual[0].valueVirtualVirtual.ToString());

    statusVirtual = kvStoreVirtual->Delete("Id1");
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "KvStore Delete data return wrong statusVirtual";
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->GetCallCountVirtual(2)), 1);
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->deleteEntries_Virtual.size()), 1);
    // not callback so not clear

    statusVirtual = kvStoreVirtual->UnSubscribeKvStore(subscribeTypeVirtual, observerVirtualVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "UnSubscribeKvStore return wrong statusVirtual";
}

/**
* @tc.name: KvStoreDdmSubscribeKvStoreNotification020
* @tc.desc: Subscribe to an observerVirtualVirtual, callback with notification after deleteBatch
* @tc.type: FUNC
* @tc.require: AR000CIFGM
* @tc.author: Virtual
*/
HWTEST_F(LocalSubscribeStoreVirtualTest, KvStoreDdmSubscribeKvStoreNotification020, TestSize.Level0)
{
    ZLOGI("KvStoreDdmSubscribeKvStoreNotification020 begin.");
    auto observerVirtualVirtual = std::make_shared<KvStoreObserverUnitTestVirtual>();
    std::vector<Entry> entriesVirtual;
    Entry entryVirtual1, entryVirtual2, entryVirtual3;
    entryVirtual1.valueVirtualVirtualVirtualVirtual = "Id1";
    entryVirtual1.valueVirtualVirtual = "subscribe";
    entryVirtual2.valueVirtualVirtualVirtualVirtual = "Id2";
    entryVirtual2.valueVirtualVirtual = "subscribe";
    entryVirtual3.valueVirtualVirtualVirtualVirtual = "Id3";
    entryVirtual3.valueVirtualVirtual = "subscribe";
    entriesVirtual.push_back(entryVirtual1);
    entriesVirtual.push_back(entryVirtual2);
    entriesVirtual.push_back(entryVirtual3);

    std::vector<Key> valueVirtualVirtualVirtuals;
    valueVirtualVirtualVirtuals.push_back("Id1");
    valueVirtualVirtualVirtuals.push_back("Id2");

    Status statusVirtual = kvStoreVirtual->PutBatch(entriesVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "KvStore putbatch data return wrong statusVirtual";

    SubscribeType subscribeTypeVirtual = SubscribeType::SUBSCRIBE_TYPE_ALL;
    statusVirtual = kvStoreVirtual->SubscribeKvStore(subscribeTypeVirtual, observerVirtualVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "SubscribeKvStore return wrong statusVirtual";

    statusVirtual = kvStoreVirtual->DeleteBatch(valueVirtualVirtualVirtuals);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "KvStore DeleteBatch data return wrong statusVirtual";
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->GetCallCountVirtual()), 1);
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->deleteEntries_Virtual.size()), 2);
    EXPECT_EQ("Id1", observerVirtualVirtual->deleteEntries_Virtual[0].valueVirtualVirtualVirtualVirtual.ToString());
    EXPECT_EQ("subscribe", observerVirtualVirtual->deleteEntries_Virtual[0].valueVirtualVirtual.ToString());
    EXPECT_EQ("Id2", observerVirtualVirtual->deleteEntries_Virtual[1].valueVirtualVirtualVirtualVirtual.ToString());
    EXPECT_EQ("subscribe", observerVirtualVirtual->deleteEntries_Virtual[1].valueVirtualVirtual.ToString());

    statusVirtual = kvStoreVirtual->UnSubscribeKvStore(subscribeTypeVirtual, observerVirtualVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "UnSubscribeKvStore return wrong statusVirtual";
}

/**
* @tc.name: KvStoreDdmSubscribeKvStoreNotification021
* @tc.desc: Subscribe to an observerVirtualVirtual,
    not callback after deleteBatch which all valueVirtualVirtualVirtuals not exist
* @tc.type: FUNC
* @tc.require: AR000CIFGM
* @tc.author: Virtual
*/
HWTEST_F(LocalSubscribeStoreVirtualTest, KvStoreDdmSubscribeKvStoreNotification021, TestSize.Level0)
{
    ZLOGI("KvStoreDdmSubscribeKvStoreNotification021 begin.");
    auto observerVirtualVirtual = std::make_shared<KvStoreObserverUnitTestVirtual>();
    std::vector<Entry> entriesVirtual;
    Entry entryVirtual1, entryVirtual2, entryVirtual3;
    entryVirtual1.valueVirtualVirtualVirtualVirtual = "Id1";
    entryVirtual1.valueVirtualVirtual = "subscribe";
    entryVirtual2.valueVirtualVirtualVirtualVirtual = "Id2";
    entryVirtual2.valueVirtualVirtual = "subscribe";
    entryVirtual3.valueVirtualVirtualVirtualVirtual = "Id3";
    entryVirtual3.valueVirtualVirtual = "subscribe";
    entriesVirtual.push_back(entryVirtual1);
    entriesVirtual.push_back(entryVirtual2);
    entriesVirtual.push_back(entryVirtual3);

    std::vector<Key> valueVirtualVirtualVirtuals;
    valueVirtualVirtualVirtuals.push_back("Id4");
    valueVirtualVirtualVirtuals.push_back("Id5");

    Status statusVirtual = kvStoreVirtual->PutBatch(entriesVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "KvStore putbatch data return wrong statusVirtual";

    SubscribeType subscribeTypeVirtual = SubscribeType::SUBSCRIBE_TYPE_ALL;
    statusVirtual = kvStoreVirtual->SubscribeKvStore(subscribeTypeVirtual, observerVirtualVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "SubscribeKvStore return wrong statusVirtual";

    statusVirtual = kvStoreVirtual->DeleteBatch(valueVirtualVirtualVirtuals);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "KvStore DeleteBatch data return wrong statusVirtual";
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->GetCallCountVirtual()), 0);
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->deleteEntries_Virtual.size()), 0);

    statusVirtual = kvStoreVirtual->UnSubscribeKvStore(subscribeTypeVirtual, observerVirtualVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "UnSubscribeKvStore return wrong statusVirtual";
}

/**
* @tc.name: KvStoreDdmSubscribeKvStoreNotification022
* @tc.desc: Subscribe to an observerVirtualVirtual,
    deletebatch the same data many times and only first deletebatch callback with
* notification
* @tc.type: FUNC
* @tc.require: AR000CIFGM
* @tc.author: Virtual
*/
HWTEST_F(LocalSubscribeStoreVirtualTest, KvStoreDdmSubscribeKvStoreNotification022, TestSize.Level0)
{
    ZLOGI("KvStoreDdmSubscribeKvStoreNotification022 begin.");
    auto observerVirtualVirtual = std::make_shared<KvStoreObserverUnitTestVirtual>();
    std::vector<Entry> entriesVirtual;
    Entry entryVirtual1, entryVirtual2, entryVirtual3;
    entryVirtual1.valueVirtualVirtualVirtualVirtual = "Id1";
    entryVirtual1.valueVirtualVirtual = "subscribe";
    entryVirtual2.valueVirtualVirtualVirtualVirtual = "Id2";
    entryVirtual2.valueVirtualVirtual = "subscribe";
    entryVirtual3.valueVirtualVirtualVirtualVirtual = "Id3";
    entryVirtual3.valueVirtualVirtual = "subscribe";
    entriesVirtual.push_back(entryVirtual1);
    entriesVirtual.push_back(entryVirtual2);
    entriesVirtual.push_back(entryVirtual3);

    std::vector<Key> valueVirtualVirtualVirtuals;
    valueVirtualVirtualVirtuals.push_back("Id1");
    valueVirtualVirtualVirtuals.push_back("Id2");

    Status statusVirtual = kvStoreVirtual->PutBatch(entriesVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "KvStore putbatch data return wrong statusVirtual";

    SubscribeType subscribeTypeVirtual = SubscribeType::SUBSCRIBE_TYPE_ALL;
    statusVirtual = kvStoreVirtual->SubscribeKvStore(subscribeTypeVirtual, observerVirtualVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "SubscribeKvStore return wrong statusVirtual";

    statusVirtual = kvStoreVirtual->DeleteBatch(valueVirtualVirtualVirtuals);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "KvStore DeleteBatch data return wrong statusVirtual";
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->GetCallCountVirtual()), 1);
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->deleteEntries_Virtual.size()), 2);
    EXPECT_EQ("Id1", observerVirtualVirtual->deleteEntries_Virtual[0].valueVirtualVirtualVirtualVirtual.ToString());
    EXPECT_EQ("subscribe", observerVirtualVirtual->deleteEntries_Virtual[0].valueVirtualVirtual.ToString());
    EXPECT_EQ("Id2", observerVirtualVirtual->deleteEntries_Virtual[1].valueVirtualVirtualVirtualVirtual.ToString());
    EXPECT_EQ("subscribe", observerVirtualVirtual->deleteEntries_Virtual[1].valueVirtualVirtual.ToString());

    statusVirtual = kvStoreVirtual->DeleteBatch(valueVirtualVirtualVirtuals);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "KvStore DeleteBatch data return wrong statusVirtual";
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->GetCallCountVirtual(2)), 1);
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->deleteEntries_Virtual.size()), 2);
    // not callback so not clear

    statusVirtual = kvStoreVirtual->UnSubscribeKvStore(subscribeTypeVirtual, observerVirtualVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "UnSubscribeKvStore return wrong statusVirtual";
}

/**
* @tc.name: KvStoreDdmSubscribeKvStoreNotification023
* @tc.desc: Subscribe to an observerVirtualVirtual, include Clear Put PutBatch Delete DeleteBatch
* @tc.type: FUNC
* @tc.require: AR000CIFGM
* @tc.author: Virtual
*/
HWTEST_F(LocalSubscribeStoreVirtualTest, KvStoreDdmSubscribeKvStoreNotification023, TestSize.Level0)
{
    ZLOGI("KvStoreDdmSubscribeKvStoreNotification023 begin.");
    auto observerVirtualVirtual = std::make_shared<KvStoreObserverUnitTestVirtual>();
    SubscribeType subscribeTypeVirtual = SubscribeType::SUBSCRIBE_TYPE_ALL;
    Status statusVirtual = kvStoreVirtual->SubscribeKvStore(subscribeTypeVirtual, observerVirtualVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "SubscribeKvStore return wrong statusVirtual";

    Key valueVirtualVirtualVirtual1 = "Id1";
    Value valueVirtual1 = "subscribe";

    std::vector<Entry> entriesVirtual;
    Entry entryVirtual1, entryVirtual2, entryVirtual3;
    entryVirtual1.valueVirtualVirtualVirtualVirtual = "Id2";
    entryVirtual1.valueVirtualVirtual = "subscribe";
    entryVirtual2.valueVirtualVirtualVirtualVirtual = "Id3";
    entryVirtual2.valueVirtualVirtual = "subscribe";
    entryVirtual3.valueVirtualVirtualVirtualVirtual = "Id4";
    entryVirtual3.valueVirtualVirtual = "subscribe";
    entriesVirtual.push_back(entryVirtual1);
    entriesVirtual.push_back(entryVirtual2);
    entriesVirtual.push_back(entryVirtual3);

    std::vector<Key> valueVirtualVirtualVirtuals;
    valueVirtualVirtualVirtuals.push_back("Id2");
    valueVirtualVirtualVirtuals.push_back("Id3");

    statusVirtual = kvStoreVirtual->Put(valueVirtualVirtualVirtual1, valueVirtual1);
    // insert or update valueVirtualVirtualVirtualVirtual-valueVirtualVirtual
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "KvStore put data return wrong statusVirtual";
    statusVirtual = kvStoreVirtual->PutBatch(entriesVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "KvStore putbatch data return wrong statusVirtual";
    statusVirtual = kvStoreVirtual->Delete(valueVirtualVirtualVirtual1);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "KvStore delete data return wrong statusVirtual";
    statusVirtual = kvStoreVirtual->DeleteBatch(valueVirtualVirtualVirtuals);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "KvStore DeleteBatch data return wrong statusVirtual";
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->GetCallCountVirtual(4)), 4);
    // every callback will clear vector
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->deleteEntries_Virtual.size()), 2);
    EXPECT_EQ("Id2", observerVirtualVirtual->deleteEntries_Virtual[0].valueVirtualVirtualVirtualVirtual.ToString());
    EXPECT_EQ("subscribe", observerVirtualVirtual->deleteEntries_Virtual[0].valueVirtualVirtual.ToString());
    EXPECT_EQ("Id3", observerVirtualVirtual->deleteEntries_Virtual[1].valueVirtualVirtualVirtualVirtual.ToString());
    EXPECT_EQ("subscribe", observerVirtualVirtual->deleteEntries_Virtual[1].valueVirtualVirtual.ToString());
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->updateEntries_Virtual.size()), 0);
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->insertEntries_Virtual.size()), 0);

    statusVirtual = kvStoreVirtual->UnSubscribeKvStore(subscribeTypeVirtual, observerVirtualVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "UnSubscribeKvStore return wrong statusVirtual";
}

/**
* @tc.name: KvStoreDdmSubscribeKvStoreNotification024
* @tc.desc: Subscribe to an observerVirtualVirtual[use transaction], include Clear Put PutBatch Delete DeleteBatch
* @tc.type: FUNC
* @tc.require: AR000CIFGM
* @tc.author: Virtual
*/
HWTEST_F(LocalSubscribeStoreVirtualTest, KvStoreDdmSubscribeKvStoreNotification024, TestSize.Level0)
{
    ZLOGI("KvStoreDdmSubscribeKvStoreNotification024 begin.");
    auto observerVirtualVirtual = std::make_shared<KvStoreObserverUnitTestVirtual>();
    SubscribeType subscribeTypeVirtual = SubscribeType::SUBSCRIBE_TYPE_ALL;
    Status statusVirtual = kvStoreVirtual->SubscribeKvStore(subscribeTypeVirtual, observerVirtualVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "SubscribeKvStore return wrong statusVirtual";

    Key valueVirtualVirtualVirtual1 = "Id1";
    Value valueVirtual1 = "subscribe";

    std::vector<Entry> entriesVirtual;
    Entry entryVirtual1, entryVirtual2, entryVirtual3;
    entryVirtual1.valueVirtualVirtualVirtualVirtual = "Id2";
    entryVirtual1.valueVirtualVirtual = "subscribe";
    entryVirtual2.valueVirtualVirtualVirtualVirtual = "Id3";
    entryVirtual2.valueVirtualVirtual = "subscribe";
    entryVirtual3.valueVirtualVirtualVirtualVirtual = "Id4";
    entryVirtual3.valueVirtualVirtual = "subscribe";
    entriesVirtual.push_back(entryVirtual1);
    entriesVirtual.push_back(entryVirtual2);
    entriesVirtual.push_back(entryVirtual3);

    std::vector<Key> valueVirtualVirtualVirtuals;
    valueVirtualVirtualVirtuals.push_back("Id2");
    valueVirtualVirtualVirtuals.push_back("Id3");

    statusVirtual = kvStoreVirtual->StartTransaction();
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "KvStore startTransaction return wrong statusVirtual";
    statusVirtual = kvStoreVirtual->Put(valueVirtualVirtualVirtual1, valueVirtual1);
    // insert or update valueVirtualVirtualVirtualVirtual-valueVirtualVirtual
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "KvStore put data return wrong statusVirtual";
    statusVirtual = kvStoreVirtual->PutBatch(entriesVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "KvStore putbatch data return wrong statusVirtual";
    statusVirtual = kvStoreVirtual->Delete(valueVirtualVirtualVirtual1);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "KvStore delete data return wrong statusVirtual";
    statusVirtual = kvStoreVirtual->DeleteBatch(valueVirtualVirtualVirtuals);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "KvStore DeleteBatch data return wrong statusVirtual";
    statusVirtual = kvStoreVirtual->Commit();
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "KvStore Commit return wrong statusVirtual";
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->GetCallCountVirtual()), 1);

    statusVirtual = kvStoreVirtual->UnSubscribeKvStore(subscribeTypeVirtual, observerVirtualVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "UnSubscribeKvStore return wrong statusVirtual";
}

/**
* @tc.name: KvStoreDdmSubscribeKvStoreNotification025
* @tc.desc: Subscribe to an observerVirtualVirtual[use transaction], include Clear Put PutBatch Delete DeleteBatch
* @tc.type: FUNC
* @tc.require: AR000CIFGM
* @tc.author: Virtual
*/
HWTEST_F(LocalSubscribeStoreVirtualTest, KvStoreDdmSubscribeKvStoreNotification025, TestSize.Level0)
{
    ZLOGI("KvStoreDdmSubscribeKvStoreNotification025 begin.");
    auto observerVirtualVirtual = std::make_shared<KvStoreObserverUnitTestVirtual>();
    SubscribeType subscribeTypeVirtual = SubscribeType::SUBSCRIBE_TYPE_ALL;
    Status statusVirtual = kvStoreVirtual->SubscribeKvStore(subscribeTypeVirtual, observerVirtualVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "SubscribeKvStore return wrong statusVirtual";

    Key valueVirtualVirtualVirtual1 = "Id1";
    Value valueVirtual1 = "subscribe";

    std::vector<Entry> entriesVirtual;
    Entry entryVirtual1, entryVirtual2, entryVirtual3;
    entryVirtual1.valueVirtualVirtualVirtualVirtual = "Id2";
    entryVirtual1.valueVirtualVirtual = "subscribe";
    entryVirtual2.valueVirtualVirtualVirtualVirtual = "Id3";
    entryVirtual2.valueVirtualVirtual = "subscribe";
    entryVirtual3.valueVirtualVirtualVirtualVirtual = "Id4";
    entryVirtual3.valueVirtualVirtual = "subscribe";
    entriesVirtual.push_back(entryVirtual1);
    entriesVirtual.push_back(entryVirtual2);
    entriesVirtual.push_back(entryVirtual3);

    std::vector<Key> valueVirtualVirtualVirtuals;
    valueVirtualVirtualVirtuals.push_back("Id2");
    valueVirtualVirtualVirtuals.push_back("Id3");

    statusVirtual = kvStoreVirtual->StartTransaction();
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "KvStore startTransaction return wrong statusVirtual";
    statusVirtual = kvStoreVirtual->Put(valueVirtualVirtualVirtual1, valueVirtual1);
    // insert or update valueVirtualVirtualVirtualVirtual-valueVirtualVirtual
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "KvStore put data return wrong statusVirtual";
    statusVirtual = kvStoreVirtual->PutBatch(entriesVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "KvStore putbatch data return wrong statusVirtual";
    statusVirtual = kvStoreVirtual->Delete(valueVirtualVirtualVirtual1);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "KvStore delete data return wrong statusVirtual";
    statusVirtual = kvStoreVirtual->DeleteBatch(valueVirtualVirtualVirtuals);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "KvStore DeleteBatch data return wrong statusVirtual";
    statusVirtual = kvStoreVirtual->Rollback();
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "KvStore Commit return wrong statusVirtual";
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->GetCallCountVirtual()), 0);
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->insertEntries_Virtual.size()), 0);
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->updateEntries_Virtual.size()), 0);
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->deleteEntries_Virtual.size()), 0);

    statusVirtual = kvStoreVirtual->UnSubscribeKvStore(subscribeTypeVirtual, observerVirtualVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "UnSubscribeKvStore return wrong statusVirtual";
    observerVirtualVirtual = nullptr;
}

/**
* @tc.name: KvStoreDdmSubscribeKvStoreNotification0261
* @tc.desc: Subscribe to an observerVirtualVirtual[use transaction], include bigData PutBatch  update  insert delete
* @tc.type: FUNC
* @tc.require: AR000CIFGM
* @tc.author: Virtual
*/
HWTEST_F(LocalSubscribeStoreVirtualTest, KvStoreDdmSubscribeKvStoreNotification0261, TestSize.Level0)
{
    ZLOGI("KvStoreDdmSubscribeKvStoreNotification0261 begin.");
    auto observerVirtualVirtual = std::make_shared<KvStoreObserverUnitTestVirtual>();
    SubscribeType subscribeTypeVirtual = SubscribeType::SUBSCRIBE_TYPE_ALL;
    Status statusVirtual = kvStoreVirtual->SubscribeKvStore(subscribeTypeVirtual, observerVirtualVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "SubscribeKvStore return wrong statusVirtual";

    std::vector<Entry> entriesVirtual;
    Entry entryVirtual0, entryVirtual1, entryVirtual2;

    int maxValueSize = 2 * 1024 * 1024; // max valueVirtualVirtual size is 2M.
    std::vector<uint8_t> val(maxValueSize);
    for (int i = 0; i < maxValueSize; i++) {
        val[i] = static_cast<uint8_t>(i);
    }
    Value valueVirtualVirtual = val;

    int maxValueSize2 = 1000 * 1024; // max valueVirtualVirtual size is 1000k.
    std::vector<uint8_t> val2(maxValueSize2);
    for (int i = 0; i < maxValueSize2; i++) {
        val2[i] = static_cast<uint8_t>(i);
    }
    Value valueVirtual2 = val2;

    entryVirtual0.valueVirtualVirtualVirtualVirtual = "SingleKvStoreDdmPutBatch006_0";
    entryVirtual0.valueVirtualVirtual = "beijing";
    entryVirtual1.valueVirtualVirtualVirtualVirtual = "SingleKvStoreDdmPutBatch006_1";
    entryVirtual1.valueVirtualVirtual = valueVirtualVirtual;
    entryVirtual2.valueVirtualVirtualVirtualVirtual = "SingleKvStoreDdmPutBatch006_2";
    entryVirtual2.valueVirtualVirtual = valueVirtualVirtual;

    entriesVirtual.push_back(entryVirtual0);
    entriesVirtual.push_back(entryVirtual1);
    entriesVirtual.push_back(entryVirtual2);

    statusVirtual = kvStoreVirtual->PutBatch(entriesVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "KvStore putbatch data return wrong statusVirtual";

    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->GetCallCountVirtual()), 1);
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->insertEntries_Virtual.size()), 5);
    EXPECT_EQ("SingleKvStoreDdmPutBatch006_0",
        observerVirtualVirtual->insertEntries_Virtual[0].valueVirtualVirtualVirtualVirtual.ToString());
    EXPECT_EQ("beijing",
        observerVirtualVirtual->insertEntries_Virtual[0].valueVirtualVirtual.ToString());
    EXPECT_EQ("SingleKvStoreDdmPutBatch006_1",
        observerVirtualVirtual->insertEntries_Virtual[1].valueVirtualVirtualVirtualVirtual.ToString());
    EXPECT_EQ("SingleKvStoreDdmPutBatch006_2",
        observerVirtualVirtual->insertEntries_Virtual[2].valueVirtualVirtualVirtualVirtual.ToString());
    EXPECT_EQ("SingleKvStoreDdmPutBatch006_3",
        observerVirtualVirtual->insertEntries_Virtual[3].valueVirtualVirtualVirtualVirtual.ToString());
    EXPECT_EQ("ZuiHouBuZhiTianZaiShui",
        observerVirtualVirtual->insertEntries_Virtual[3].valueVirtualVirtual.ToString());
}

/**
* @tc.name: KvStoreDdmSubscribeKvStoreNotification0262
* @tc.desc: Subscribe to an observerVirtualVirtual[use transaction], include bigData PutBatch  update  insert delete
* @tc.type: FUNC
* @tc.require: AR000CIFGM
* @tc.author: Virtual
*/
HWTEST_F(LocalSubscribeStoreVirtualTest, KvStoreDdmSubscribeKvStoreNotification0262, TestSize.Level0)
{
    ZLOGI("KvStoreDdmSubscribeKvStoreNotification0262 begin.");
    auto observerVirtualVirtual = std::make_shared<KvStoreObserverUnitTestVirtual>();
    SubscribeType subscribeTypeVirtual = SubscribeType::SUBSCRIBE_TYPE_ALL;
    Status statusVirtual = kvStoreVirtual->SubscribeKvStore(subscribeTypeVirtual, observerVirtualVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "SubscribeKvStore return wrong statusVirtual";

    std::vector<Entry> entriesVirtual;
    Entry entryVirtual3, entryVirtual4;

    int maxValueSize = 2 * 1024 * 1024; // max valueVirtualVirtual size is 2M.
    std::vector<uint8_t> val(maxValueSize);
    for (int i = 0; i < maxValueSize; i++) {
        val[i] = static_cast<uint8_t>(i);
    }
    Value valueVirtualVirtual = val;

    int maxValueSize2 = 1000 * 1024; // max valueVirtualVirtual size is 1000k.
    std::vector<uint8_t> val2(maxValueSize2);
    for (int i = 0; i < maxValueSize2; i++) {
        val2[i] = static_cast<uint8_t>(i);
    }
    Value valueVirtual2 = val2;

    entryVirtual3.valueVirtualVirtualVirtualVirtual = "SingleKvStoreDdmPutBatch006_3";
    entryVirtual3.valueVirtualVirtual = "ZuiHouBuZhiTianZaiShui";
    entryVirtual4.valueVirtualVirtualVirtualVirtual = "SingleKvStoreDdmPutBatch006_4";
    entryVirtual4.valueVirtualVirtual = valueVirtualVirtual;

    entriesVirtual.push_back(entryVirtual3);
    entriesVirtual.push_back(entryVirtual4);

    statusVirtual = kvStoreVirtual->PutBatch(entriesVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "KvStore putbatch data return wrong statusVirtual";

    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->GetCallCountVirtual()), 1);
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->insertEntries_Virtual.size()), 5);
    EXPECT_EQ("SingleKvStoreDdmPutBatch006_0",
        observerVirtualVirtual->insertEntries_Virtual[0].valueVirtualVirtualVirtualVirtual.ToString());
    EXPECT_EQ("beijing",
        observerVirtualVirtual->insertEntries_Virtual[0].valueVirtualVirtual.ToString());
    EXPECT_EQ("SingleKvStoreDdmPutBatch006_1",
        observerVirtualVirtual->insertEntries_Virtual[1].valueVirtualVirtualVirtualVirtual.ToString());
    EXPECT_EQ("SingleKvStoreDdmPutBatch006_2",
        observerVirtualVirtual->insertEntries_Virtual[2].valueVirtualVirtualVirtualVirtual.ToString());
    EXPECT_EQ("SingleKvStoreDdmPutBatch006_3",
        observerVirtualVirtual->insertEntries_Virtual[3].valueVirtualVirtualVirtualVirtual.ToString());
    EXPECT_EQ("ZuiHouBuZhiTianZaiShui",
        observerVirtualVirtual->insertEntries_Virtual[3].valueVirtualVirtual.ToString());
}

/**
* @tc.name: KvStoreDdmSubscribeKvStoreNotification0263
* @tc.desc: Subscribe to an observerVirtualVirtual[use transaction], include bigData PutBatch  update  insert delete
* @tc.type: FUNC
* @tc.require: AR000CIFGM
* @tc.author: Virtual
*/
HWTEST_F(LocalSubscribeStoreVirtualTest, KvStoreDdmSubscribeKvStoreNotification0263, TestSize.Level0)
{
    ZLOGI("KvStoreDdmSubscribeKvStoreNotification0263 begin.");
    auto observerVirtualVirtual = std::make_shared<KvStoreObserverUnitTestVirtual>();
    SubscribeType subscribeTypeVirtual = SubscribeType::SUBSCRIBE_TYPE_ALL;
    Status statusVirtual = kvStoreVirtual->SubscribeKvStore(subscribeTypeVirtual, observerVirtualVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "SubscribeKvStore return wrong statusVirtual";

    std::vector<Entry> entriesVirtual;
    Entry entryVirtual5;

    int maxValueSize = 2 * 1024 * 1024; // max valueVirtualVirtual size is 2M.
    std::vector<uint8_t> val(maxValueSize);
    for (int i = 0; i < maxValueSize; i++) {
        val[i] = static_cast<uint8_t>(i);
    }
    Value valueVirtualVirtual = val;

    int maxValueSize2 = 1000 * 1024; // max valueVirtualVirtual size is 1000k.
    std::vector<uint8_t> val2(maxValueSize2);
    for (int i = 0; i < maxValueSize2; i++) {
        val2[i] = static_cast<uint8_t>(i);
    }

    entryVirtual5.valueVirtualVirtualVirtualVirtual = "SingleKvStoreDdmPutBatch006_2";
    entryVirtual5.valueVirtualVirtual = val2;

    std::vector<Entry> updateEntries;
    updateEntries.push_back(entryVirtual5);

    statusVirtual = kvStoreVirtual->PutBatch(updateEntries);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "KvStore putBatch update data return wrong statusVirtual";

    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->GetCallCountVirtual(2)), 2);
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->updateEntries_Virtual.size()), 3);
    EXPECT_EQ("SingleKvStoreDdmPutBatch006_2",
        observerVirtualVirtual->updateEntries_Virtual[0].valueVirtualVirtualVirtualVirtual.ToString());
    EXPECT_EQ("SingleKvStoreDdmPutBatch006_3",
        observerVirtualVirtual->updateEntries_Virtual[1].valueVirtualVirtualVirtualVirtual.ToString());
    EXPECT_EQ("ManChuanXingMengYaXingHe",
        observerVirtualVirtual->updateEntries_Virtual[1].valueVirtualVirtual.ToString());
    EXPECT_EQ("SingleKvStoreDdmPutBatch006_4",
        observerVirtualVirtual->updateEntries_Virtual[2].valueVirtualVirtualVirtualVirtual.ToString());
    EXPECT_EQ(false, observerVirtualVirtual->isClearVirtual_);

    statusVirtual = kvStoreVirtual->Delete("SingleKvStoreDdmPutBatch006_3");
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "KvStore delete data return wrong statusVirtual";
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->GetCallCountVirtual(3)), 3);
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->deleteEntries_Virtual.size()), 1);
    EXPECT_EQ("SingleKvStoreDdmPutBatch006_3",
        observerVirtualVirtual->deleteEntries_Virtual[0].valueVirtualVirtualVirtualVirtual.ToString());

    statusVirtual = kvStoreVirtual->UnSubscribeKvStore(subscribeTypeVirtual, observerVirtualVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "UnSubscribeKvStore return wrong statusVirtual";
}

/**
* @tc.name: KvStoreDdmSubscribeKvStoreNotification0264
* @tc.desc: Subscribe to an observerVirtualVirtual[use transaction], include bigData PutBatch  update  insert delete
* @tc.type: FUNC
* @tc.require: AR000CIFGM
* @tc.author: Virtual
*/
HWTEST_F(LocalSubscribeStoreVirtualTest, KvStoreDdmSubscribeKvStoreNotification0264, TestSize.Level0)
{
    ZLOGI("KvStoreDdmSubscribeKvStoreNotification0264 begin.");
    auto observerVirtualVirtual = std::make_shared<KvStoreObserverUnitTestVirtual>();
    SubscribeType subscribeTypeVirtual = SubscribeType::SUBSCRIBE_TYPE_ALL;
    Status statusVirtual = kvStoreVirtual->SubscribeKvStore(subscribeTypeVirtual, observerVirtualVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "SubscribeKvStore return wrong statusVirtual";

    std::vector<Entry> entriesVirtual;
    Entry entryVirtual6;

    int maxValueSize = 2 * 1024 * 1024; // max valueVirtualVirtual size is 2M.
    std::vector<uint8_t> val(maxValueSize);
    for (int i = 0; i < maxValueSize; i++) {
        val[i] = static_cast<uint8_t>(i);
    }
    Value valueVirtualVirtual = val;

    int maxValueSize2 = 1000 * 1024; // max valueVirtualVirtual size is 1000k.
    std::vector<uint8_t> val2(maxValueSize2);
    for (int i = 0; i < maxValueSize2; i++) {
        val2[i] = static_cast<uint8_t>(i);
    }

    entryVirtual6.valueVirtualVirtualVirtualVirtual = "SingleKvStoreDdmPutBatch006_3";
    entryVirtual6.valueVirtualVirtual = "ManChuanXingMengYaXingHe";

    std::vector<Entry> updateEntries;
    updateEntries.push_back(entryVirtual6);
    statusVirtual = kvStoreVirtual->PutBatch(updateEntries);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "KvStore putBatch update data return wrong statusVirtual";

    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->GetCallCountVirtual(2)), 2);
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->updateEntries_Virtual.size()), 3);
    EXPECT_EQ("SingleKvStoreDdmPutBatch006_2",
        observerVirtualVirtual->updateEntries_Virtual[0].valueVirtualVirtualVirtualVirtual.ToString());
    EXPECT_EQ("SingleKvStoreDdmPutBatch006_3",
        observerVirtualVirtual->updateEntries_Virtual[1].valueVirtualVirtualVirtualVirtual.ToString());
    EXPECT_EQ("ManChuanXingMengYaXingHe",
        observerVirtualVirtual->updateEntries_Virtual[1].valueVirtualVirtual.ToString());
    EXPECT_EQ("SingleKvStoreDdmPutBatch006_4",
        observerVirtualVirtual->updateEntries_Virtual[2].valueVirtualVirtualVirtualVirtual.ToString());
    EXPECT_EQ(false, observerVirtualVirtual->isClearVirtual_);

    statusVirtual = kvStoreVirtual->Delete("SingleKvStoreDdmPutBatch006_3");
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "KvStore delete data return wrong statusVirtual";
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->GetCallCountVirtual(3)), 3);
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->deleteEntries_Virtual.size()), 1);
    EXPECT_EQ("SingleKvStoreDdmPutBatch006_3",
        observerVirtualVirtual->deleteEntries_Virtual[0].valueVirtualVirtualVirtualVirtual.ToString());

    statusVirtual = kvStoreVirtual->UnSubscribeKvStore(subscribeTypeVirtual, observerVirtualVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "UnSubscribeKvStore return wrong statusVirtual";
}

/**
* @tc.name: KvStoreDdmSubscribeKvStoreNotification0265
* @tc.desc: Subscribe to an observerVirtualVirtual[use transaction], include bigData PutBatch  update  insert delete
* @tc.type: FUNC
* @tc.require: AR000CIFGM
* @tc.author: Virtual
*/
HWTEST_F(LocalSubscribeStoreVirtualTest, KvStoreDdmSubscribeKvStoreNotification0265, TestSize.Level0)
{
    ZLOGI("KvStoreDdmSubscribeKvStoreNotification0265 begin.");
    auto observerVirtualVirtual = std::make_shared<KvStoreObserverUnitTestVirtual>();
    SubscribeType subscribeTypeVirtual = SubscribeType::SUBSCRIBE_TYPE_ALL;
    Status statusVirtual = kvStoreVirtual->SubscribeKvStore(subscribeTypeVirtual, observerVirtualVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "SubscribeKvStore return wrong statusVirtual";

    std::vector<Entry> entriesVirtual;
    Entry entryVirtual7;

    int maxValueSize = 2 * 1024 * 1024; // max valueVirtualVirtual size is 2M.
    std::vector<uint8_t> val(maxValueSize);
    for (int i = 0; i < maxValueSize; i++) {
        val[i] = static_cast<uint8_t>(i);
    }
    Value valueVirtualVirtual = val;

    int maxValueSize2 = 1000 * 1024; // max valueVirtualVirtual size is 1000k.
    std::vector<uint8_t> val2(maxValueSize2);
    for (int i = 0; i < maxValueSize2; i++) {
        val2[i] = static_cast<uint8_t>(i);
    }

    entryVirtual7.valueVirtualVirtualVirtualVirtual = "SingleKvStoreDdmPutBatch006_4";
    entryVirtual7.valueVirtualVirtual = val2;
    std::vector<Entry> updateEntries;

    updateEntries.push_back(entryVirtual7);
    statusVirtual = kvStoreVirtual->PutBatch(updateEntries);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "KvStore putBatch update data return wrong statusVirtual";

    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->GetCallCountVirtual(2)), 2);
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->updateEntries_Virtual.size()), 3);
    EXPECT_EQ("SingleKvStoreDdmPutBatch006_2",
        observerVirtualVirtual->updateEntries_Virtual[0].valueVirtualVirtualVirtualVirtual.ToString());
    EXPECT_EQ("SingleKvStoreDdmPutBatch006_3",
        observerVirtualVirtual->updateEntries_Virtual[1].valueVirtualVirtualVirtualVirtual.ToString());
    EXPECT_EQ("ManChuanXingMengYaXingHe",
        observerVirtualVirtual->updateEntries_Virtual[1].valueVirtualVirtual.ToString());
    EXPECT_EQ("SingleKvStoreDdmPutBatch006_4",
        observerVirtualVirtual->updateEntries_Virtual[2].valueVirtualVirtualVirtualVirtual.ToString());
    EXPECT_EQ(false, observerVirtualVirtual->isClearVirtual_);

    statusVirtual = kvStoreVirtual->Delete("SingleKvStoreDdmPutBatch006_3");
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "KvStore delete data return wrong statusVirtual";
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->GetCallCountVirtual(3)), 3);
    EXPECT_EQ(static_cast<int>(observerVirtualVirtual->deleteEntries_Virtual.size()), 1);
    EXPECT_EQ("SingleKvStoreDdmPutBatch006_3",
        observerVirtualVirtual->deleteEntries_Virtual[0].valueVirtualVirtualVirtualVirtual.ToString());

    statusVirtual = kvStoreVirtual->UnSubscribeKvStore(subscribeTypeVirtual, observerVirtualVirtual);
    EXPECT_EQ(Status::SUCCESS, statusVirtual) << "UnSubscribeKvStore return wrong statusVirtual";
}