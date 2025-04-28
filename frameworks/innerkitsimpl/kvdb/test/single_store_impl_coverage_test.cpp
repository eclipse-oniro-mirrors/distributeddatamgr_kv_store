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
#include <condition_variable>
#include <gtest/gtest.h>
#include <vector>

#include "block_data.h"
#include "dev_manager.h"
#include "device_manager.h"
#include "distributed_kv_data_manager.h"
#include "dm_device_info.h"
#include "file_ex.h"
#include "kv_store_nb_delegate.h"
#include "single_store_impl.h"
#include "store_factory.h"
#include "store_manager.h"
#include "sys/stat.h"
#include "types.h"

using namespace testing::ext;
using namespace OHOS::DistributedKv;
using DBStatus = DistributedDB::DBStatus;
using DBStore = DistributedDB::KvStoreNbDelegate;
using SyncCallback = KvStoreSyncCallback;
using DevInfo = OHOS::DistributedHardware::DmDeviceInfo;
namespace OHOS::Test {

std::vector<uint8_t> Random(int32_t len)
{
    return std::vector<uint8_t>(len, 'a');
}

class SingleStoreImplTest : public testing::Test {
public:
    class TestObserver : public KvStoreObserver {
    public:
        TestObserver()
        {
            // The time interval parameter is 5.
            data_ = std::make_shared<OHOS::BlockData<bool>>(5, false);
        }
        void OnChange(const ChangeNotification &notification) override
        {
            insert_ = notification.GetInsertEntries();
            update_ = notification.GetUpdateEntries();
            delete_ = notification.GetDeleteEntries();
            deviceId_ = notification.GetDeviceId();
            bool value = true;
            data_->SetValue(value);
        }
        std::vector<Entry> insert_;
        std::vector<Entry> update_;
        std::vector<Entry> delete_;
        std::string deviceId_;

        std::shared_ptr<OHOS::BlockData<bool>> data_;
    };

    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    std::shared_ptr<SingleKvStore> CreateKVStore(std::string storeIdTest, KvStoreType type, bool encrypt, bool backup);
    std::shared_ptr<SingleStoreImpl> CreateKVStore(bool autosync = false);
    std::shared_ptr<SingleKvStore> kvStore_;
    static constexpr int MAX_RESULTSET_SIZE = 8;
};

void SingleStoreImplTest::SetUpTestCase(void)
{
    std::string baseDir = "/data/service/el1/public/database/SingleStoreImplTest";
    mkdir(baseDir.c_str(), (S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH));
}

void SingleStoreImplTest::TearDownTestCase(void)
{
    std::string baseDir = "/data/service/el1/public/database/SingleStoreImplTest";
    StoreManager::GetInstance().Delete({ "SingleStoreImplTest" }, { "SingleKVStore" }, baseDir);

    (void)remove("/data/service/el1/public/database/SingleStoreImplTest/key");
    (void)remove("/data/service/el1/public/database/SingleStoreImplTest/kvdb");
    (void)remove("/data/service/el1/public/database/SingleStoreImplTest");
}

void SingleStoreImplTest::SetUp(void)
{
    kvStore_ = CreateKVStore("SingleKVStore", SINGLE_VERSION, false, true);
    if (kvStore_ == nullptr) {
        kvStore_ = CreateKVStore("SingleKVStore", SINGLE_VERSION, false, true);
    }
    ASSERT_NE(kvStore_, nullptr);
}

void SingleStoreImplTest::TearDown(void)
{
    AppId appId = { "SingleStoreImplTest" };
    StoreId storeId = { "SingleKVStore" };
    kvStore_ = nullptr;
    auto status = StoreManager::GetInstance().CloseKVStore(appId, storeId);
    ASSERT_EQ(status, SUCCESS);
    auto baseDir = "/data/service/el1/public/database/SingleStoreImplTest";
    status = StoreManager::GetInstance().Delete(appId, storeId, baseDir);
    ASSERT_EQ(status, SUCCESS);
}

std::shared_ptr<SingleKvStore> SingleStoreImplTest::CreateKVStore(
    std::string storeIdTest, KvStoreType type, bool encrypt, bool backup)
{
    Options options;
    options.kvStoreType = type;
    options.securityLevel = S1;
    options.encrypt = encrypt;
    options.area = EL1;
    options.backup = backup;
    options.baseDir = "/data/service/el1/public/database/SingleStoreImplTest";

    AppId appId = { "SingleStoreImplTest" };
    StoreId storeId = { storeIdTest };
    Status status = StoreManager::GetInstance().Delete(appId, storeId, options.baseDir);
    return StoreManager::GetInstance().GetKVStore(appId, storeId, options, status);
}

std::shared_ptr<SingleStoreImpl> SingleStoreImplTest::CreateKVStore(bool autosync)
{
    AppId appId = { "SingleStoreImplTest" };
    StoreId storeId = { "DestructorTest" };
    std::shared_ptr<SingleStoreImpl> kvStore;
    Options options;
    options.kvStoreType = SINGLE_VERSION;
    options.securityLevel = S2;
    options.area = EL1;
    options.autoSync = autosync;
    options.baseDir = "/data/service/el1/public/database/SingleStoreImplTest";
    StoreFactory storeFactory;
    auto dbManager = storeFactory.GetDBManager(options.baseDir, appId);
    auto dbPassword = SecurityManager::GetInstance().GetDBPassword(storeId.storeId, options.baseDir, options.encrypt);
    DBStatus dbStatus = DBStatus::DB_ERROR;
    dbManager->GetKvStore(storeId, storeFactory.GetDBOption(options, dbPassword),
        [&dbManager, &kvStore, &appId, &dbStatus, &options, &storeFactory](auto status, auto *store) {
            dbStatus = status;
            if (store == nullptr) {
                return;
            }
            auto release = [dbManager](auto *store) {
                dbManager->CloseKvStore(store);
            };
            auto dbStore = std::shared_ptr<DBStore>(store, release);
            storeFactory.SetDbConfig(dbStore);
            const Convertor &convertor = *(storeFactory.convertors_[options.kvStoreType]);
            kvStore = std::make_shared<SingleStoreImpl>(dbStore, appId, options, convertor);
        });
    return kvStore;
}

/**
 * @tc.name: GetStoreId
 * @tc.desc: get the store id of the kv store
 * @tc.type: FUNC
 * @tc.require: I4XVQQ
 * @tc.author: Sven Wang
 */
HWTEST_F(SingleStoreImplTest, GetStoreId, TestSize.Level0)
{
    ASSERT_NE(kvStore_, nullptr);
    auto storeId = kvStore_->GetStoreId();
    ASSERT_EQ(storeId.storeId, "SingleKVStore");
}

/**
 * @tc.name: GetSubUser
 * @tc.desc: get the subUser of the kv store
 * @tc.type: FUNC
 */
HWTEST_F(SingleStoreImplTest, GetSubUser, TestSize.Level0)
{
    ASSERT_NE(kvStore_, nullptr);
    auto subUser = kvStore_->GetSubUser();
    ASSERT_EQ(subUser, 0);
}

/**
 * @tc.name: Put
 * @tc.desc: put key-value data to the kv store
 * @tc.type: FUNC
 * @tc.require: I4XVQQ
 * @tc.author: Sven Wang
 */
HWTEST_F(SingleStoreImplTest, Put, TestSize.Level0)
{
    ASSERT_NE(kvStore_, nullptr);
    auto status = kvStore_->Put({ "Put Test" }, { "Put Value" });
    ASSERT_EQ(status, SUCCESS);
    status = kvStore_->Put({ "   Put Test" }, { "Put2 Value" });
    ASSERT_EQ(status, SUCCESS);
    Value value;
    status = kvStore_->Get({ "Put Test" }, value);
    ASSERT_EQ(status, SUCCESS);
    ASSERT_EQ(value.ToString(), "Put2 Value");
}

/**
 * @tc.name: Put_Invalid_Key
 * @tc.desc: put invalid key-value data to the device kv store and single kv store
 * @tc.type: FUNC
 * @tc.require: I4XVQQ
 * @tc.author: wu fengshan
 */
HWTEST_F(SingleStoreImplTest, Put_Invalid_Key, TestSize.Level0)
{
    std::shared_ptr<SingleKvStore> kvStore;
    AppId appId = { "SingleStoreImplTest" };
    StoreId storeId = { "DeviceKVStore" };
    kvStore = CreateKVStore(storeId.storeId, DEVICE_COLLABORATION, false, true);
    ASSERT_NE(kvStore, nullptr);

    size_t maxDevKeyLen = 897;
    std::string str(maxDevKeyLen, 'a');
    Blob key(str);
    Blob value("test_value");
    Status status = kvStore->Put(key, value);
    EXPECT_EQ(status, INVALID_ARGUMENT);

    Blob key1("");
    Blob value1("test_value1");
    status = kvStore->Put(key1, value1);
    EXPECT_EQ(status, INVALID_ARGUMENT);

    kvStore = nullptr;
    status = StoreManager::GetInstance().CloseKVStore(appId, storeId);
    ASSERT_EQ(status, SUCCESS);
    std::string baseDir = "/data/service/el1/public/database/SingleStoreImplTest";
    status = StoreManager::GetInstance().Delete(appId, storeId, baseDir);
    ASSERT_EQ(status, SUCCESS);

    size_t maxSingleKeyLen = 1025;
    std::string str1(maxSingleKeyLen, 'b');
    Blob key2(str1);
    Blob value2("test_value2");
    status = kvStore_->Put(key2, value2);
    EXPECT_EQ(status, INVALID_ARGUMENT);

    status = kvStore_->Put(key1, value1);
    EXPECT_EQ(status, INVALID_ARGUMENT);
}

/**
 * @tc.name: PutBatch
 * @tc.desc: put some key-value data to the kv store
 * @tc.type: FUNC
 * @tc.require: I4XVQQ
 * @tc.author: Sven Wang
 */
HWTEST_F(SingleStoreImplTest, PutBatch, TestSize.Level0)
{
    ASSERT_NE(kvStore_, nullptr);
    std::vector<Entry> entries;
    for (int i = 0; i < 10; ++i) {
        Entry entry;
        entry.key = std::to_string(i).append("_k");
        entry.value = std::to_string(i).append("_v");
        entries.push_back(entry);
    }
    auto status = kvStore_->PutBatch(entries);
    ASSERT_EQ(status, SUCCESS);
}

/**
 * @tc.name: GetStoreId
 * @tc.desc: test IsRebuild
 * @tc.type: FUNC
 */
HWTEST_F(SingleStoreImplTest, IsRebuild, TestSize.Level0)
{
    ASSERT_NE(kvStore_, nullptr);
    auto status = kvStore_->IsRebuild();
    ASSERT_EQ(status, false);
}

/**
 * @tc.name: PutBatch001
 * @tc.desc: entry.value.Size() > MAX_VALUE_LENGTH
 * @tc.type: FUNC
 */
HWTEST_F(SingleStoreImplTest, PutBatch001, TestSize.Level1)
{
    ASSERT_NE(kvStore_, nullptr);
    size_t totalLength = SingleStoreImpl::MAX_VALUE_LENGTH + 1; // create an out-of-limit large number
    char fillChar = 'a';
    std::string longString(totalLength, fillChar);
    std::vector<Entry> entries;
    Entry entry;
    entry.key = "PutBatch001_test";
    entry.value = longString;
    entries.push_back(entry);
    auto status = kvStore_->PutBatch(entries);
    ASSERT_EQ(status, INVALID_ARGUMENT);
    entries.clear();
    Entry entrys;
    entrys.key = "";
    entrys.value = "PutBatch001_test_value";
    entries.push_back(entrys);
    status = kvStore_->PutBatch(entries);
    ASSERT_EQ(status, INVALID_ARGUMENT);
}

/**
 * @tc.name: Delete
 * @tc.desc: delete the value of the key
 * @tc.type: FUNC
 * @tc.require: I4XVQQ
 * @tc.author: Sven Wang
 */
HWTEST_F(SingleStoreImplTest, Delete, TestSize.Level0)
{
    ASSERT_NE(kvStore_, nullptr);
    auto status = kvStore_->Put({ "Put Test" }, { "Put Value" });
    ASSERT_EQ(status, SUCCESS);
    Value value;
    status = kvStore_->Get({ "Put Test" }, value);
    ASSERT_EQ(status, SUCCESS);
    ASSERT_EQ(std::string("Put Value"), value.ToString());
    status = kvStore_->Delete({ "Put Test" });
    ASSERT_EQ(status, SUCCESS);
    value = {};
    status = kvStore_->Get({ "Put Test" }, value);
    ASSERT_EQ(status, KEY_NOT_FOUND);
    ASSERT_EQ(std::string(""), value.ToString());
}

/**
 * @tc.name: DeleteBatch
 * @tc.desc: delete the values of the keys
 * @tc.type: FUNC
 * @tc.require: I4XVQQ
 * @tc.author: Sven Wang
 */
HWTEST_F(SingleStoreImplTest, DeleteBatch, TestSize.Level0)
{
    ASSERT_NE(kvStore_, nullptr);
    std::vector<Entry> entries;
    for (int i = 0; i < 10; ++i) {
        Entry entry;
        entry.key = std::to_string(i).append("_k");
        entry.value = std::to_string(i).append("_v");
        entries.push_back(entry);
    }
    auto status = kvStore_->PutBatch(entries);
    ASSERT_EQ(status, SUCCESS);
    std::vector<Key> keys;
    for (int i = 0; i < 10; ++i) {
        Key key = std::to_string(i).append("_k");
        keys.push_back(key);
    }
    status = kvStore_->DeleteBatch(keys);
    ASSERT_EQ(status, SUCCESS);
    for (int i = 0; i < 10; ++i) {
        Value value;
        status = kvStore_->Get(keys[i], value);
        ASSERT_EQ(status, KEY_NOT_FOUND);
        ASSERT_EQ(value.ToString(), std::string(""));
    }
}

/**
 * @tc.name: Transaction
 * @tc.desc: do transaction
 * @tc.type: FUNC
 * @tc.require: I4XVQQ
 * @tc.author: Sven Wang
 */
HWTEST_F(SingleStoreImplTest, Transaction, TestSize.Level0)
{
    ASSERT_NE(kvStore_, nullptr);
    auto status = kvStore_->StartTransaction();
    ASSERT_EQ(status, SUCCESS);
    status = kvStore_->Commit();
    ASSERT_EQ(status, SUCCESS);

    status = kvStore_->StartTransaction();
    ASSERT_EQ(status, SUCCESS);
    status = kvStore_->Rollback();
    ASSERT_EQ(status, SUCCESS);
}

/**
 * @tc.name: SubscribeKvStore
 * @tc.desc: subscribe local
 * @tc.type: FUNC
 * @tc.require: I4XVQQ
 * @tc.author: Sven Wang
 */
HWTEST_F(SingleStoreImplTest, SubscribeKvStore, TestSize.Level0)
{
    ASSERT_NE(kvStore_, nullptr);
    auto observer = std::make_shared<TestObserver>();
    auto status = kvStore_->SubscribeKvStore(SUBSCRIBE_TYPE_LOCAL, observer);
    ASSERT_EQ(status, SUCCESS);
    status = kvStore_->SubscribeKvStore(SUBSCRIBE_TYPE_REMOTE, observer);
    ASSERT_EQ(status, SUCCESS);
    status = kvStore_->SubscribeKvStore(SUBSCRIBE_TYPE_CLOUD, observer);
    ASSERT_EQ(status, SUCCESS);
    status = kvStore_->SubscribeKvStore(SUBSCRIBE_TYPE_LOCAL, observer);
    ASSERT_EQ(status, STORE_ALREADY_SUBSCRIBE);
    status = kvStore_->SubscribeKvStore(SUBSCRIBE_TYPE_REMOTE, observer);
    ASSERT_EQ(status, STORE_ALREADY_SUBSCRIBE);
    status = kvStore_->SubscribeKvStore(SUBSCRIBE_TYPE_CLOUD, observer);
    ASSERT_EQ(status, STORE_ALREADY_SUBSCRIBE);
    status = kvStore_->SubscribeKvStore(SUBSCRIBE_TYPE_ALL, observer);
    ASSERT_EQ(status, STORE_ALREADY_SUBSCRIBE);
    bool invalidValue = false;
    observer->data_->Clear(invalidValue);
    status = kvStore_->Put({ "Put Test" }, { "Put Value" });
    ASSERT_EQ(status, SUCCESS);
    ASSERT_TRUE(observer->data_->GetValue());
    ASSERT_EQ(observer->insert_.size(), 1);
    ASSERT_EQ(observer->update_.size(), 0);
    ASSERT_EQ(observer->delete_.size(), 0);
    observer->data_->Clear(invalidValue);
    status = kvStore_->Put({ "Put Test" }, { "Put Value1" });
    ASSERT_EQ(status, SUCCESS);
    ASSERT_TRUE(observer->data_->GetValue());
    ASSERT_EQ(observer->insert_.size(), 0);
    ASSERT_EQ(observer->update_.size(), 1);
    ASSERT_EQ(observer->delete_.size(), 0);
    observer->data_->Clear(invalidValue);
    status = kvStore_->Delete({ "Put Test" });
    ASSERT_EQ(status, SUCCESS);
    ASSERT_TRUE(observer->data_->GetValue());
    ASSERT_EQ(observer->insert_.size(), 0);
    ASSERT_EQ(observer->update_.size(), 0);
    ASSERT_EQ(observer->delete_.size(), 1);
}

/**
 * @tc.name: SubscribeKvStore002
 * @tc.desc: subscribe local
 * @tc.type: FUNC
 * @tc.require: I4XVQQ
 * @tc.author: Hollokin
 */
HWTEST_F(SingleStoreImplTest, SubscribeKvStore002, TestSize.Level0)
{
    ASSERT_NE(kvStore_, nullptr);
    std::shared_ptr<TestObserver> subscribedObserver;
    std::shared_ptr<TestObserver> unSubscribedObserver;
    for (int i = 0; i < 15; ++i) {
        auto observer = std::make_shared<TestObserver>();
        auto status1 = kvStore_->SubscribeKvStore(SUBSCRIBE_TYPE_LOCAL, observer);
        auto status2 = kvStore_->SubscribeKvStore(SUBSCRIBE_TYPE_REMOTE, observer);
        if (i < 8) {
            ASSERT_EQ(status1, SUCCESS);
            ASSERT_EQ(status2, SUCCESS);
            subscribedObserver = observer;
        } else {
            ASSERT_EQ(status1, OVER_MAX_LIMITS);
            ASSERT_EQ(status2, OVER_MAX_LIMITS);
            unSubscribedObserver = observer;
        }
    }

    auto status = kvStore_->SubscribeKvStore(SUBSCRIBE_TYPE_LOCAL, subscribedObserver);
    ASSERT_EQ(status, STORE_ALREADY_SUBSCRIBE);

    status = kvStore_->SubscribeKvStore(SUBSCRIBE_TYPE_LOCAL, {});
    ASSERT_EQ(status, INVALID_ARGUMENT);

    status = kvStore_->SubscribeKvStore(SUBSCRIBE_TYPE_REMOTE, subscribedObserver);
    ASSERT_EQ(status, STORE_ALREADY_SUBSCRIBE);

    status = kvStore_->SubscribeKvStore(SUBSCRIBE_TYPE_ALL, subscribedObserver);
    ASSERT_EQ(status, SUCCESS);

    status = kvStore_->UnSubscribeKvStore(SUBSCRIBE_TYPE_LOCAL, subscribedObserver);
    ASSERT_EQ(status, SUCCESS);
    status = kvStore_->SubscribeKvStore(SUBSCRIBE_TYPE_LOCAL, subscribedObserver);
    ASSERT_EQ(status, SUCCESS);

    status = kvStore_->UnSubscribeKvStore(SUBSCRIBE_TYPE_ALL, subscribedObserver);
    ASSERT_EQ(status, SUCCESS);
    status = kvStore_->SubscribeKvStore(SUBSCRIBE_TYPE_LOCAL, unSubscribedObserver);
    ASSERT_EQ(status, SUCCESS);
    subscribedObserver = unSubscribedObserver;
    status = kvStore_->UnSubscribeKvStore(SUBSCRIBE_TYPE_LOCAL, subscribedObserver);
    ASSERT_EQ(status, SUCCESS);
    auto observer = std::make_shared<TestObserver>();
    status = kvStore_->SubscribeKvStore(SUBSCRIBE_TYPE_LOCAL, observer);
    ASSERT_EQ(status, SUCCESS);
    status = kvStore_->SubscribeKvStore(SUBSCRIBE_TYPE_ALL, observer);
    ASSERT_EQ(status, SUCCESS);
    observer = std::make_shared<TestObserver>();
    status = kvStore_->SubscribeKvStore(SUBSCRIBE_TYPE_ALL, observer);
    ASSERT_EQ(status, OVER_MAX_LIMITS);
}

/**
 * @tc.name: SubscribeKvStore003
 * @tc.desc: isClientSync_
 * @tc.type: FUNC
 */
HWTEST_F(SingleStoreImplTest, SubscribeKvStore003, TestSize.Level0)
{
    auto observer = std::make_shared<TestObserver>();
    std::shared_ptr<SingleStoreImpl> kvStore;
    kvStore = CreateKVStore();
    ASSERT_NE(kvStore, nullptr);
    kvStore->isClientSync_ = true;
    auto status = kvStore->SubscribeKvStore(SUBSCRIBE_TYPE_LOCAL, observer);
    ASSERT_EQ(status, SUCCESS);
}

/**
 * @tc.name: UnsubscribeKvStore
 * @tc.desc: unsubscribe
 * @tc.type: FUNC
 * @tc.require: I4XVQQ
 * @tc.author: Sven Wang
 */
HWTEST_F(SingleStoreImplTest, UnsubscribeKvStore, TestSize.Level0)
{
    ASSERT_NE(kvStore_, nullptr);
    auto observer = std::make_shared<TestObserver>();
    auto status = kvStore_->SubscribeKvStore(SUBSCRIBE_TYPE_ALL, observer);
    ASSERT_EQ(status, SUCCESS);
    status = kvStore_->UnSubscribeKvStore(SUBSCRIBE_TYPE_REMOTE, observer);
    ASSERT_EQ(status, SUCCESS);
    status = kvStore_->UnSubscribeKvStore(SUBSCRIBE_TYPE_CLOUD, observer);
    ASSERT_EQ(status, SUCCESS);
    status = kvStore_->UnSubscribeKvStore(SUBSCRIBE_TYPE_REMOTE, observer);
    ASSERT_EQ(status, STORE_NOT_SUBSCRIBE);
    status = kvStore_->UnSubscribeKvStore(SUBSCRIBE_TYPE_LOCAL, observer);
    ASSERT_EQ(status, SUCCESS);
    status = kvStore_->UnSubscribeKvStore(SUBSCRIBE_TYPE_LOCAL, observer);
    ASSERT_EQ(status, STORE_NOT_SUBSCRIBE);
    status = kvStore_->UnSubscribeKvStore(SUBSCRIBE_TYPE_ALL, observer);
    ASSERT_EQ(status, STORE_NOT_SUBSCRIBE);
    status = kvStore_->SubscribeKvStore(SUBSCRIBE_TYPE_LOCAL, observer);
    ASSERT_EQ(status, SUCCESS);
    status = kvStore_->UnSubscribeKvStore(SUBSCRIBE_TYPE_ALL, observer);
    ASSERT_EQ(status, SUCCESS);
}

/**
 * @tc.name: GetEntries
 * @tc.desc: get entries by prefix
 * @tc.type: FUNC
 * @tc.require: I4XVQQ
 * @tc.author: Sven Wang
 */
HWTEST_F(SingleStoreImplTest, GetEntries_Prefix, TestSize.Level0)
{
    ASSERT_NE(kvStore_, nullptr);
    std::vector<Entry> input;
    for (int i = 0; i < 10; ++i) {
        Entry entry;
        entry.key = std::to_string(i).append("_k");
        entry.value = std::to_string(i).append("_v");
        input.push_back(entry);
    }
    auto status = kvStore_->PutBatch(input);
    ASSERT_EQ(status, SUCCESS);
    std::vector<Entry> output;
    status = kvStore_->GetEntries({ "" }, output);
    ASSERT_EQ(status, SUCCESS);
    std::sort(output.begin(), output.end(), [](const Entry &entry, const Entry &sentry) {
        return entry.key.Data() < sentry.key.Data();
    });
    for (int i = 0; i < 10; ++i) {
        ASSERT_TRUE(input[i].key == output[i].key);
        ASSERT_TRUE(input[i].value == output[i].value);
    }
}

/**
 * @tc.name: GetEntries_Less_Prefix
 * @tc.desc: get entries by prefix and the key size less than sizeof(uint32_t)
 * @tc.type: FUNC
 * @tc.require: I4XVQQ
 * @tc.author: wu fengshan
 */
HWTEST_F(SingleStoreImplTest, GetEntries_Less_Prefix, TestSize.Level0)
{
    std::shared_ptr<SingleKvStore> kvStore;
    AppId appId = { "SingleStoreImplTest" };
    StoreId storeId = { "DeviceKVStore" };
    kvStore = CreateKVStore(storeId.storeId, DEVICE_COLLABORATION, false, true);
    ASSERT_NE(kvStore, nullptr);

    std::vector<Entry> input;
    for (int i = 0; i < 10; ++i) {
        Entry entry;
        entry.key = std::to_string(i).append("_k");
        entry.value = std::to_string(i).append("_v");
        input.push_back(entry);
    }
    auto status = kvStore->PutBatch(input);
    ASSERT_EQ(status, SUCCESS);
    std::vector<Entry> output;
    status = kvStore->GetEntries({ "1" }, output);
    ASSERT_NE(output.empty(), true);
    ASSERT_EQ(status, SUCCESS);

    kvStore = nullptr;
    status = StoreManager::GetInstance().CloseKVStore(appId, storeId);
    ASSERT_EQ(status, SUCCESS);
    std::string baseDir = "/data/service/el1/public/database/SingleStoreImplTest";
    status = StoreManager::GetInstance().Delete(appId, storeId, baseDir);
    ASSERT_EQ(status, SUCCESS);

    status = kvStore_->PutBatch(input);
    ASSERT_EQ(status, SUCCESS);
    std::vector<Entry> output1;
    status = kvStore_->GetEntries({ "1" }, output1);
    ASSERT_NE(output1.empty(), true);
    ASSERT_EQ(status, SUCCESS);
}

/**
 * @tc.name: GetEntries_Greater_Prefix
 * @tc.desc: get entries by prefix and the key size is greater than  sizeof(uint32_t)
 * @tc.type: FUNC
 * @tc.require: I4XVQQ
 * @tc.author: wu fengshan
 */
HWTEST_F(SingleStoreImplTest, GetEntries_Greater_Prefix, TestSize.Level0)
{
    std::shared_ptr<SingleKvStore> kvStore;
    AppId appId = { "SingleStoreImplTest" };
    StoreId storeId = { "DeviceKVStore" };
    kvStore = CreateKVStore(storeId.storeId, DEVICE_COLLABORATION, false, true);
    ASSERT_NE(kvStore, nullptr);

    size_t keyLen = sizeof(uint32_t);
    std::vector<Entry> input;
    for (int i = 1; i < 10; ++i) {
        Entry entry;
        std::string str(keyLen, i + '0');
        entry.key = str;
        entry.value = std::to_string(i).append("_v");
        input.push_back(entry);
    }
    auto status = kvStore->PutBatch(input);
    ASSERT_EQ(status, SUCCESS);
    std::vector<Entry> output;
    std::string str1(keyLen, '1');
    status = kvStore->GetEntries(str1, output);
    ASSERT_NE(output.empty(), true);
    ASSERT_EQ(status, SUCCESS);

    kvStore = nullptr;
    status = StoreManager::GetInstance().CloseKVStore(appId, storeId);
    ASSERT_EQ(status, SUCCESS);
    std::string baseDir = "/data/service/el1/public/database/SingleStoreImplTest";
    status = StoreManager::GetInstance().Delete(appId, storeId, baseDir);
    ASSERT_EQ(status, SUCCESS);

    status = kvStore_->PutBatch(input);
    ASSERT_EQ(status, SUCCESS);
    std::vector<Entry> output1;
    status = kvStore_->GetEntries(str1, output1);
    ASSERT_NE(output1.empty(), true);
    ASSERT_EQ(status, SUCCESS);
}

/**
 * @tc.name: GetEntries
 * @tc.desc: get entries by query
 * @tc.type: FUNC
 * @tc.require: I4XVQQ
 * @tc.author: Sven Wang
 */
HWTEST_F(SingleStoreImplTest, GetEntries_DataQuery, TestSize.Level0)
{
    ASSERT_NE(kvStore_, nullptr);
    std::vector<Entry> input;
    for (int i = 0; i < 10; ++i) {
        Entry entry;
        entry.key = std::to_string(i).append("_k");
        entry.value = std::to_string(i).append("_v");
        input.push_back(entry);
    }
    auto status = kvStore_->PutBatch(input);
    ASSERT_EQ(status, SUCCESS);
    DataQuery query;
    query.InKeys({ "0_k", "1_k" });
    std::vector<Entry> output;
    status = kvStore_->GetEntries(query, output);
    ASSERT_EQ(status, SUCCESS);
    std::sort(output.begin(), output.end(), [](const Entry &entry, const Entry &sentry) {
        return entry.key.Data() < sentry.key.Data();
    });
    ASSERT_LE(output.size(), 2);
    for (size_t i = 0; i < output.size(); ++i) {
        ASSERT_TRUE(input[i].key == output[i].key);
        ASSERT_TRUE(input[i].value == output[i].value);
    }
}

/**
 * @tc.name: GetResultSet
 * @tc.desc: get result set by prefix
 * @tc.type: FUNC
 * @tc.require: I4XVQQ
 * @tc.author: Sven Wang
 */
HWTEST_F(SingleStoreImplTest, GetResultSet_Prefix, TestSize.Level0)
{
    ASSERT_NE(kvStore_, nullptr);
    std::vector<Entry> input;
    auto cmp = [](const Key &entry, const Key &sentry) {
        return entry.Data() < sentry.Data();
    };
    std::map<Key, Value, decltype(cmp)> dictionary(cmp);
    for (int i = 0; i < 10; ++i) {
        Entry entry;
        entry.key = std::to_string(i).append("_k");
        entry.value = std::to_string(i).append("_v");
        dictionary[entry.key] = entry.value;
        input.push_back(entry);
    }
    auto status = kvStore_->PutBatch(input);
    ASSERT_EQ(status, SUCCESS);
    std::shared_ptr<KvStoreResultSet> output;
    status = kvStore_->GetResultSet({ "" }, output);
    ASSERT_EQ(status, SUCCESS);
    ASSERT_NE(output, nullptr);
    ASSERT_EQ(output->GetCount(), 10);
    int count = 0;
    while (output->MoveToNext()) {
        count++;
        Entry entry;
        output->GetEntry(entry);
        ASSERT_EQ(entry.value.Data(), dictionary[entry.key].Data());
    }
    ASSERT_EQ(count, output->GetCount());
}

/**
 * @tc.name: GetResultSet
 * @tc.desc: get result set by query
 * @tc.type: FUNC
 * @tc.require: I4XVQQ
 * @tc.author: Sven Wang
 */
HWTEST_F(SingleStoreImplTest, GetResultSet_Query, TestSize.Level0)
{
    ASSERT_NE(kvStore_, nullptr);
    std::vector<Entry> input;
    auto cmp = [](const Key &entry, const Key &sentry) {
        return entry.Data() < sentry.Data();
    };
    std::map<Key, Value, decltype(cmp)> dictionary(cmp);
    for (int i = 0; i < 10; ++i) {
        Entry entry;
        entry.key = std::to_string(i).append("_k");
        entry.value = std::to_string(i).append("_v");
        dictionary[entry.key] = entry.value;
        input.push_back(entry);
    }
    auto status = kvStore_->PutBatch(input);
    ASSERT_EQ(status, SUCCESS);
    DataQuery query;
    query.InKeys({ "0_k", "1_k" });
    std::shared_ptr<KvStoreResultSet> output;
    status = kvStore_->GetResultSet(query, output);
    ASSERT_EQ(status, SUCCESS);
    ASSERT_NE(output, nullptr);
    ASSERT_LE(output->GetCount(), 2);
    int count = 0;
    while (output->MoveToNext()) {
        count++;
        Entry entry;
        output->GetEntry(entry);
        ASSERT_EQ(entry.value.Data(), dictionary[entry.key].Data());
    }
    ASSERT_EQ(count, output->GetCount());
}

/**
 * @tc.name: CloseResultSet
 * @tc.desc: close the result set
 * @tc.type: FUNC
 * @tc.require: I4XVQQ
 * @tc.author: Sven Wang
 */
HWTEST_F(SingleStoreImplTest, CloseResultSet, TestSize.Level0)
{
    ASSERT_NE(kvStore_, nullptr);
    std::vector<Entry> input;
    auto cmp = [](const Key &entry, const Key &sentry) {
        return entry.Data() < sentry.Data();
    };
    std::map<Key, Value, decltype(cmp)> dictionary(cmp);
    for (int i = 0; i < 10; ++i) {
        Entry entry;
        entry.key = std::to_string(i).append("_k");
        entry.value = std::to_string(i).append("_v");
        dictionary[entry.key] = entry.value;
        input.push_back(entry);
    }
    auto status = kvStore_->PutBatch(input);
    ASSERT_EQ(status, SUCCESS);
    DataQuery query;
    query.InKeys({ "0_k", "1_k" });
    std::shared_ptr<KvStoreResultSet> output;
    status = kvStore_->GetResultSet(query, output);
    ASSERT_EQ(status, SUCCESS);
    ASSERT_NE(output, nullptr);
    ASSERT_LE(output->GetCount(), 2);
    auto outputTmp = output;
    status = kvStore_->CloseResultSet(output);
    ASSERT_EQ(status, SUCCESS);
    ASSERT_EQ(output, nullptr);
    ASSERT_EQ(outputTmp->GetCount(), KvStoreResultSet::INVALID_COUNT);
    ASSERT_EQ(outputTmp->GetPosition(), KvStoreResultSet::INVALID_POSITION);
    ASSERT_EQ(outputTmp->MoveToFirst(), false);
    ASSERT_EQ(outputTmp->MoveToLast(), false);
    ASSERT_EQ(outputTmp->MoveToNext(), false);
    ASSERT_EQ(outputTmp->MoveToPrevious(), false);
    ASSERT_EQ(outputTmp->Move(1), false);
    ASSERT_EQ(outputTmp->MoveToPosition(1), false);
    ASSERT_EQ(outputTmp->IsFirst(), false);
    ASSERT_EQ(outputTmp->IsLast(), false);
    ASSERT_EQ(outputTmp->IsBeforeFirst(), false);
    ASSERT_EQ(outputTmp->IsAfterLast(), false);
    Entry entry;
    ASSERT_EQ(outputTmp->GetEntry(entry), ALREADY_CLOSED);
}

/**
 * @tc.name: CloseResultSet001
 * @tc.desc: output = nullptr;
 * @tc.type: FUNC
 */
HWTEST_F(SingleStoreImplTest, CloseResultSet001, TestSize.Level0)
{
    ASSERT_NE(kvStore_, nullptr);
    std::shared_ptr<KvStoreResultSet> output;
    output = nullptr;
    auto status = kvStore_->CloseResultSet(output);
    ASSERT_EQ(status, INVALID_ARGUMENT);
}

/**
 * @tc.name: ResultSetMaxSizeTest
 * @tc.desc: test if kv supports 8 resultSets at the same time
 * @tc.type: FUNC
 * @tc.require: I4XVQQ
 * @tc.author: Yang Qing
 */
HWTEST_F(SingleStoreImplTest, ResultSetMaxSizeTest_Query, TestSize.Level0)
{
    ASSERT_NE(kvStore_, nullptr);
    /**
     * @tc.steps:step1. Put the entry into the database.
     * @tc.expected: step1. Returns SUCCESS.
     */
    std::vector<Entry> input;
    for (int i = 0; i < 10; ++i) {
        Entry entry;
        entry.key = "k_" + std::to_string(i);
        entry.value = "v_" + std::to_string(i);
        input.push_back(entry);
    }
    auto status = kvStore_->PutBatch(input);
    ASSERT_EQ(status, SUCCESS);
    /**
     * @tc.steps:step2. Get the resultset.
     * @tc.expected: step2. Returns SUCCESS.
     */
    DataQuery query;
    query.KeyPrefix("k_");
    std::vector<std::shared_ptr<KvStoreResultSet>> outputs(MAX_RESULTSET_SIZE + 1);
    for (int i = 0; i < MAX_RESULTSET_SIZE; i++) {
        std::shared_ptr<KvStoreResultSet> output;
        status = kvStore_->GetResultSet(query, outputs[i]);
        ASSERT_EQ(status, SUCCESS);
    }
    /**
     * @tc.steps:step3. Get the resultset while resultset size is over the limit.
     * @tc.expected: step3. Returns OVER_MAX_LIMITS.
     */
    status = kvStore_->GetResultSet(query, outputs[MAX_RESULTSET_SIZE]);
    ASSERT_EQ(status, OVER_MAX_LIMITS);
    /**
     * @tc.steps:step4. Close the resultset and getting the resultset is retried
     * @tc.expected: step4. Returns SUCCESS.
     */
    status = kvStore_->CloseResultSet(outputs[0]);
    ASSERT_EQ(status, SUCCESS);
    status = kvStore_->GetResultSet(query, outputs[MAX_RESULTSET_SIZE]);
    ASSERT_EQ(status, SUCCESS);

    for (int i = 1; i <= MAX_RESULTSET_SIZE; i++) {
        status = kvStore_->CloseResultSet(outputs[i]);
        ASSERT_EQ(status, SUCCESS);
    }
}

/**
 * @tc.name: ResultSetMaxSizeTest
 * @tc.desc: test if kv supports 8 resultSets at the same time
 * @tc.type: FUNC
 * @tc.require: I4XVQQ
 * @tc.author: Yang Qing
 */
HWTEST_F(SingleStoreImplTest, ResultSetMaxSizeTest_Prefix, TestSize.Level0)
{
    ASSERT_NE(kvStore_, nullptr);
    /**
     * @tc.steps:step1. Put the entry into the database.
     * @tc.expected: step1. Returns SUCCESS.
     */
    std::vector<Entry> input;
    for (int i = 0; i < 10; ++i) {
        Entry entry;
        entry.key = "k_" + std::to_string(i);
        entry.value = "v_" + std::to_string(i);
        input.push_back(entry);
    }
    auto status = kvStore_->PutBatch(input);
    ASSERT_EQ(status, SUCCESS);
    /**
     * @tc.steps:step2. Get the resultset.
     * @tc.expected: step2. Returns SUCCESS.
     */
    std::vector<std::shared_ptr<KvStoreResultSet>> outputs(MAX_RESULTSET_SIZE + 1);
    for (int i = 0; i < MAX_RESULTSET_SIZE; i++) {
        std::shared_ptr<KvStoreResultSet> output;
        status = kvStore_->GetResultSet({ "k_i" }, outputs[i]);
        ASSERT_EQ(status, SUCCESS);
    }
    /**
     * @tc.steps:step3. Get the resultset while resultset size is over the limit.
     * @tc.expected: step3. Returns OVER_MAX_LIMITS.
     */
    status = kvStore_->GetResultSet({ "" }, outputs[MAX_RESULTSET_SIZE]);
    ASSERT_EQ(status, OVER_MAX_LIMITS);
    /**
     * @tc.steps:step4. Close the resultset and getting the resultset is retried
     * @tc.expected: step4. Returns SUCCESS.
     */
    status = kvStore_->CloseResultSet(outputs[0]);
    ASSERT_EQ(status, SUCCESS);
    status = kvStore_->GetResultSet({ "" }, outputs[MAX_RESULTSET_SIZE]);
    ASSERT_EQ(status, SUCCESS);

    for (int i = 1; i <= MAX_RESULTSET_SIZE; i++) {
        status = kvStore_->CloseResultSet(outputs[i]);
        ASSERT_EQ(status, SUCCESS);
    }
}

/**
 * @tc.name: MaxLogSizeTest
 * @tc.desc: test if the default max limit of wal is 200MB
 * @tc.type: FUNC
 * @tc.require: I4XVQQ
 * @tc.author: Yang Qing
 */
HWTEST_F(SingleStoreImplTest, MaxLogSizeTest, TestSize.Level0)
{
    ASSERT_NE(kvStore_, nullptr);
    /**
     * @tc.steps:step1. Put the random entry into the database.
     * @tc.expected: step1. Returns SUCCESS.
     */
    std::string key;
    std::vector<uint8_t> value = Random(4 * 1024 * 1024);
    key = "test0";
    EXPECT_EQ(kvStore_->Put(key, value), SUCCESS);
    key = "test1";
    EXPECT_EQ(kvStore_->Put(key, value), SUCCESS);
    key = "test2";
    EXPECT_EQ(kvStore_->Put(key, value), SUCCESS);
    /**
     * @tc.steps:step2. Get the resultset.
     * @tc.expected: step2. Returns SUCCESS.
     */
    std::shared_ptr<KvStoreResultSet> output;
    auto status = kvStore_->GetResultSet({ "" }, output);
    ASSERT_EQ(status, SUCCESS);
    ASSERT_NE(output, nullptr);
    ASSERT_EQ(output->GetCount(), 3);
    EXPECT_EQ(output->MoveToFirst(), true);
    /**
     * @tc.steps:step3. Put more data into the database.
     * @tc.expected: step3. Returns SUCCESS.
     */
    for (int i = 0; i < 50; i++) {
        key = "test_" + std::to_string(i);
        EXPECT_EQ(kvStore_->Put(key, value), SUCCESS);
    }
    /**
     * @tc.steps:step4. Put more data into the database while the log size is over the limit.
     * @tc.expected: step4. Returns LOG_LIMITS_ERROR.
     */
    key = "test3";
    EXPECT_EQ(kvStore_->Put(key, value), WAL_OVER_LIMITS);
    EXPECT_EQ(kvStore_->Delete(key), WAL_OVER_LIMITS);
    EXPECT_EQ(kvStore_->StartTransaction(), WAL_OVER_LIMITS);
    /**
     * @tc.steps:step5. Close the resultset and put again.
     * @tc.expected: step4. Return SUCCESS.
     */

    status = kvStore_->CloseResultSet(output);
    ASSERT_EQ(status, SUCCESS);
    EXPECT_EQ(kvStore_->Put(key, value), SUCCESS);
}

/**
 * @tc.name: MaxTest002
 * @tc.desc: test if the default max limit of wal is 200MB
 * @tc.type: FUNC
 * @tc.require: I4XVQQ
 * @tc.author: Yang Qing
 */
HWTEST_F(SingleStoreImplTest, MaxLogSizeTest002, TestSize.Level0)
{
    ASSERT_NE(kvStore_, nullptr);
    /**
     * @tc.steps:step1. Put the random entry into the database.
     * @tc.expected: step1. Returns SUCCESS.
     */
    std::string key;
    std::vector<uint8_t> value = Random(4 * 1024 * 1024);
    key = "test0";
    EXPECT_EQ(kvStore_->Put(key, value), SUCCESS);
    key = "test1";
    EXPECT_EQ(kvStore_->Put(key, value), SUCCESS);
    key = "test2";
    EXPECT_EQ(kvStore_->Put(key, value), SUCCESS);
    /**
     * @tc.steps:step2. Get the resultset.
     * @tc.expected: step2. Returns SUCCESS.
     */
    std::shared_ptr<KvStoreResultSet> output;
    auto status = kvStore_->GetResultSet({ "" }, output);
    ASSERT_EQ(status, SUCCESS);
    ASSERT_NE(output, nullptr);
    ASSERT_EQ(output->GetCount(), 3);
    EXPECT_EQ(output->MoveToFirst(), true);
    /**
     * @tc.steps:step3. Put more data into the database.
     * @tc.expected: step3. Returns SUCCESS.
     */
    for (int i = 0; i < 50; i++) {
        key = "test_" + std::to_string(i);
        EXPECT_EQ(kvStore_->Put(key, value), SUCCESS);
    }
    /**
     * @tc.steps:step4. Put more data into the database while the log size is over the limit.
     * @tc.expected: step4. Returns LOG_LIMITS_ERROR.
     */
    key = "test3";
    EXPECT_EQ(kvStore_->Put(key, value), WAL_OVER_LIMITS);
    EXPECT_EQ(kvStore_->Delete(key), WAL_OVER_LIMITS);
    EXPECT_EQ(kvStore_->StartTransaction(), WAL_OVER_LIMITS);
    status = kvStore_->CloseResultSet(output);
    ASSERT_EQ(status, SUCCESS);
    /**
     * @tc.steps:step5. Close the database and then open the database,put again.
     * @tc.expected: step4. Return SUCCESS.
     */
    AppId appId = { "SingleStoreImplTest" };
    StoreId storeId = { "SingleKVStore" };
    Options options;
    options.kvStoreType = SINGLE_VERSION;
    options.securityLevel = S1;
    options.encrypt = false;
    options.area = EL1;
    options.backup = true;
    options.baseDir = "/data/service/el1/public/database/SingleStoreImplTest";

    status = StoreManager::GetInstance().CloseKVStore(appId, storeId);
    ASSERT_EQ(status, SUCCESS);
    kvStore_ = nullptr;
    kvStore_ = StoreManager::GetInstance().GetKVStore(appId, storeId, options, status);
    ASSERT_EQ(status, SUCCESS);

    status = kvStore_->GetResultSet({ "" }, output);
    ASSERT_EQ(status, SUCCESS);
    ASSERT_NE(output, nullptr);
    EXPECT_EQ(output->MoveToFirst(), true);

    EXPECT_EQ(kvStore_->Put(key, value), SUCCESS);
    status = kvStore_->CloseResultSet(output);
    ASSERT_EQ(status, SUCCESS);
}

/**
 * @tc.name: Move_Offset
 * @tc.desc: Move the ResultSet Relative Distance
 * @tc.type: FUNC
 * @tc.require: I4XVQQ
 * @tc.author: wu fengshan
 */
HWTEST_F(SingleStoreImplTest, Move_Offset, TestSize.Level0)
{
    std::vector<Entry> input;
    for (int i = 0; i < 10; ++i) {
        Entry entry;
        entry.key = std::to_string(i).append("_k");
        entry.value = std::to_string(i).append("_v");
        input.push_back(entry);
    }
    auto status = kvStore_->PutBatch(input);
    ASSERT_EQ(status, SUCCESS);

    Key prefix = "2";
    std::shared_ptr<KvStoreResultSet> output;
    status = kvStore_->GetResultSet(prefix, output);
    ASSERT_EQ(status, SUCCESS);
    ASSERT_NE(output, nullptr);

    auto outputTmp = output;
    ASSERT_EQ(outputTmp->Move(1), true);
    status = kvStore_->CloseResultSet(output);
    ASSERT_EQ(status, SUCCESS);
    ASSERT_EQ(output, nullptr);

    std::shared_ptr<SingleKvStore> kvStore;
    AppId appId = { "SingleStoreImplTest" };
    StoreId storeId = { "DeviceKVStore" };
    kvStore = CreateKVStore(storeId.storeId, DEVICE_COLLABORATION, false, true);
    ASSERT_NE(kvStore, nullptr);

    status = kvStore->PutBatch(input);
    ASSERT_EQ(status, SUCCESS);
    std::shared_ptr<KvStoreResultSet> output1;
    status = kvStore->GetResultSet(prefix, output1);
    ASSERT_EQ(status, SUCCESS);
    ASSERT_NE(output1, nullptr);
    auto outputTmp1 = output1;
    ASSERT_EQ(outputTmp1->Move(1), true);
    status = kvStore->CloseResultSet(output1);
    ASSERT_EQ(status, SUCCESS);
    ASSERT_EQ(output1, nullptr);

    kvStore = nullptr;
    status = StoreManager::GetInstance().CloseKVStore(appId, storeId);
    ASSERT_EQ(status, SUCCESS);
    std::string baseDir = "/data/service/el1/public/database/SingleStoreImplTest";
    status = StoreManager::GetInstance().Delete(appId, storeId, baseDir);
    ASSERT_EQ(status, SUCCESS);
}

/**
 * @tc.name: GetCount
 * @tc.desc: close the result set
 * @tc.type: FUNC
 * @tc.require: I4XVQQ
 * @tc.author: Sven Wang
 */
HWTEST_F(SingleStoreImplTest, GetCount, TestSize.Level0)
{
    ASSERT_NE(kvStore_, nullptr);
    std::vector<Entry> input;
    auto cmp = [](const Key &entry, const Key &sentry) {
        return entry.Data() < sentry.Data();
    };
    std::map<Key, Value, decltype(cmp)> dictionary(cmp);
    for (int i = 0; i < 10; ++i) {
        Entry entry;
        entry.key = std::to_string(i).append("_k");
        entry.value = std::to_string(i).append("_v");
        dictionary[entry.key] = entry.value;
        input.push_back(entry);
    }
    auto status = kvStore_->PutBatch(input);
    ASSERT_EQ(status, SUCCESS);
    DataQuery query;
    query.InKeys({ "0_k", "1_k" });
    int count = 0;
    status = kvStore_->GetCount(query, count);
    ASSERT_EQ(status, SUCCESS);
    ASSERT_EQ(count, 2);
    query.Reset();
    status = kvStore_->GetCount(query, count);
    ASSERT_EQ(status, SUCCESS);
    ASSERT_EQ(count, 10);
}

void ChangeOwnerToService(std::string baseDir, std::string hashId)
{
    static constexpr int ddmsId = 3012;
    std::string path = baseDir;
    chown(path.c_str(), ddmsId, ddmsId);
    path = path + "/kvdb";
    chown(path.c_str(), ddmsId, ddmsId);
    path = path + "/" + hashId;
    chown(path.c_str(), ddmsId, ddmsId);
    path = path + "/single_ver";
    chown(path.c_str(), ddmsId, ddmsId);
    chown((path + "/meta").c_str(), ddmsId, ddmsId);
    chown((path + "/cache").c_str(), ddmsId, ddmsId);
    path = path + "/main";
    chown(path.c_str(), ddmsId, ddmsId);
    chown((path + "/gen_natural_store.db").c_str(), ddmsId, ddmsId);
    chown((path + "/gen_natural_store.db-shm").c_str(), ddmsId, ddmsId);
    chown((path + "/gen_natural_store.db-wal").c_str(), ddmsId, ddmsId);
}

/**
 * @tc.name: RemoveDeviceData
 * @tc.desc: remove local device data
 * @tc.type: FUNC
 * @tc.require: I4XVQQ
 * @tc.author: Sven Wang
 */
HWTEST_F(SingleStoreImplTest, RemoveDeviceData, TestSize.Level0)
{
    auto store = CreateKVStore("DeviceKVStore", DEVICE_COLLABORATION, false, true);
    ASSERT_NE(store, nullptr);
    std::vector<Entry> input;
    auto cmp = [](const Key &entry, const Key &sentry) {
        return entry.Data() < sentry.Data();
    };
    std::map<Key, Value, decltype(cmp)> dictionary(cmp);
    for (int i = 0; i < 10; ++i) {
        Entry entry;
        entry.key = std::to_string(i).append("_k");
        entry.value = std::to_string(i).append("_v");
        dictionary[entry.key] = entry.value;
        input.push_back(entry);
    }
    auto status = store->PutBatch(input);
    ASSERT_EQ(status, SUCCESS);
    int count = 0;
    status = store->GetCount({}, count);
    ASSERT_EQ(status, SUCCESS);
    ASSERT_EQ(count, 10);
    ChangeOwnerToService("/data/service/el1/public/database/SingleStoreImplTest",
        "703c6ec99aa7226bb9f6194cdd60e1873ea9ee52faebd55657ade9f5a5cc3cbd");
    status = store->RemoveDeviceData(DevManager::GetInstance().GetLocalDevice().networkId);
    ASSERT_EQ(status, SUCCESS);
    status = store->GetCount({}, count);
    ASSERT_EQ(status, SUCCESS);
    ASSERT_EQ(count, 10);
    std::string baseDir = "/data/service/el1/public/database/SingleStoreImplTest";
    status = StoreManager::GetInstance().Delete({ "SingleStoreImplTest" }, { "DeviceKVStore" }, baseDir);
    ASSERT_EQ(status, SUCCESS);
}

/**
 * @tc.name: GetSecurityLevel
 * @tc.desc: get security level
 * @tc.type: FUNC
 * @tc.require: I4XVQQ
 * @tc.author: Sven Wang
 */
HWTEST_F(SingleStoreImplTest, GetSecurityLevel, TestSize.Level0)
{
    ASSERT_NE(kvStore_, nullptr);
    SecurityLevel securityLevel = NO_LABEL;
    auto status = kvStore_->GetSecurityLevel(securityLevel);
    ASSERT_EQ(status, SUCCESS);
    ASSERT_EQ(securityLevel, S1);
}

/**
 * @tc.name: RegisterSyncCallback
 * @tc.desc: register the data sync callback
 * @tc.type: FUNC
 * @tc.require: I4XVQQ
 * @tc.author: Sven Wang
 */
HWTEST_F(SingleStoreImplTest, RegisterSyncCallback, TestSize.Level0)
{
    ASSERT_NE(kvStore_, nullptr);
    class TestSyncCallback : public KvStoreSyncCallback {
    public:
        void SyncCompleted(const map<std::string, Status> &results) override { }
        void SyncCompleted(const std::map<std::string, Status> &results, uint64_t sequenceId) override { }
    };
    auto callback = std::make_shared<TestSyncCallback>();
    auto status = kvStore_->RegisterSyncCallback(callback);
    ASSERT_EQ(status, SUCCESS);
}

/**
 * @tc.name: UnRegisterSyncCallback
 * @tc.desc: unregister the data sync callback
 * @tc.type: FUNC
 * @tc.require: I4XVQQ
 * @tc.author: Sven Wang
 */
HWTEST_F(SingleStoreImplTest, UnRegisterSyncCallback, TestSize.Level0)
{
    ASSERT_NE(kvStore_, nullptr);
    class TestSyncCallback : public KvStoreSyncCallback {
    public:
        void SyncCompleted(const map<std::string, Status> &results) override { }
        void SyncCompleted(const std::map<std::string, Status> &results, uint64_t sequenceId) override { }
    };
    auto callback = std::make_shared<TestSyncCallback>();
    auto status = kvStore_->RegisterSyncCallback(callback);
    ASSERT_EQ(status, SUCCESS);
    status = kvStore_->UnRegisterSyncCallback();
    ASSERT_EQ(status, SUCCESS);
}

/**
 * @tc.name: disableBackup
 * @tc.desc: Disable backup
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: Wang Kai
 */
HWTEST_F(SingleStoreImplTest, disableBackup, TestSize.Level0)
{
    AppId appId = { "SingleStoreImplTest" };
    StoreId storeId = { "SingleKVStoreNoBackup" };
    std::shared_ptr<SingleKvStore> kvStoreNoBackup;
    kvStoreNoBackup = CreateKVStore(storeId, SINGLE_VERSION, true, false);
    ASSERT_NE(kvStoreNoBackup, nullptr);
    auto baseDir = "/data/service/el1/public/database/SingleStoreImplTest";
    auto status = StoreManager::GetInstance().CloseKVStore(appId, storeId);
    ASSERT_EQ(status, SUCCESS);
    status = StoreManager::GetInstance().Delete(appId, storeId, baseDir);
    ASSERT_EQ(status, SUCCESS);
}

/**
 * @tc.name: PutOverMaxValue
 * @tc.desc: put key-value data to the kv store and the value size  over the limits
 * @tc.type: FUNC
 * @tc.require: I605H3
 * @tc.author: Wang Kai
 */
HWTEST_F(SingleStoreImplTest, PutOverMaxValue, TestSize.Level0)
{
    ASSERT_NE(kvStore_, nullptr);
    std::string value;
    int maxsize = 1024 * 1024;
    for (int i = 0; i <= maxsize; i++) {
        value += "test";
    }
    Value valuePut(value);
    auto status = kvStore_->Put({ "Put Test" }, valuePut);
    ASSERT_EQ(status, INVALID_ARGUMENT);
}
/**
 * @tc.name: DeleteOverMaxKey
 * @tc.desc: delete the values of the keys and the key size  over the limits
 * @tc.type: FUNC
 * @tc.require: I605H3
 * @tc.author: Wang Kai
 */
HWTEST_F(SingleStoreImplTest, DeleteOverMaxKey, TestSize.Level0)
{
    ASSERT_NE(kvStore_, nullptr);
    std::string str;
    int maxsize = 1024;
    for (int i = 0; i <= maxsize; i++) {
        str += "key";
    }
    Key key(str);
    auto status = kvStore_->Put(key, "Put Test");
    ASSERT_EQ(status, INVALID_ARGUMENT);
    Value value;
    status = kvStore_->Get(key, value);
    ASSERT_EQ(status, INVALID_ARGUMENT);
    status = kvStore_->Delete(key);
    ASSERT_EQ(status, INVALID_ARGUMENT);
}

/**
 * @tc.name: GetEntriesOverMaxKey
 * @tc.desc: get entries the by prefix and the prefix size  over the limits
 * @tc.type: FUNC
 * @tc.require: I605H3
 * @tc.author: Wang Kai
 */
HWTEST_F(SingleStoreImplTest, GetEntriesOverMaxPrefix, TestSize.Level0)
{
    ASSERT_NE(kvStore_, nullptr);
    std::string str;
    int maxsize = 1024;
    for (int i = 0; i <= maxsize; i++) {
        str += "key";
    }
    const Key prefix(str);
    std::vector<Entry> output;
    auto status = kvStore_->GetEntries(prefix, output);
    ASSERT_EQ(status, INVALID_ARGUMENT);
}

/**
 * @tc.name: GetResultSetOverMaxPrefix
 * @tc.desc: get result set the by prefix and the prefix size  over the limits
 * @tc.type: FUNC
 * @tc.require: I605H3
 * @tc.author: Wang Kai
 */
HWTEST_F(SingleStoreImplTest, GetResultSetOverMaxPrefix, TestSize.Level0)
{
    ASSERT_NE(kvStore_, nullptr);
    std::string str;
    int maxsize = 1024;
    for (int i = 0; i <= maxsize; i++) {
        str += "key";
    }
    const Key prefix(str);
    std::shared_ptr<KvStoreResultSet> output;
    auto status = kvStore_->GetResultSet(prefix, output);
    ASSERT_EQ(status, INVALID_ARGUMENT);
}

/**
 * @tc.name: RemoveNullDeviceData
 * @tc.desc: remove local device data and the device is null
 * @tc.type: FUNC
 * @tc.require: I605H3
 * @tc.author: Wang Kai
 */
HWTEST_F(SingleStoreImplTest, RemoveNullDeviceData, TestSize.Level0)
{
    auto store = CreateKVStore("DeviceKVStore", DEVICE_COLLABORATION, false, true);
    ASSERT_NE(store, nullptr);
    std::vector<Entry> input;
    auto cmp = [](const Key &entry, const Key &sentry) {
        return entry.Data() < sentry.Data();
    };
    std::map<Key, Value, decltype(cmp)> dictionary(cmp);
    for (int i = 0; i < 10; ++i) {
        Entry entry;
        entry.key = std::to_string(i).append("_k");
        entry.value = std::to_string(i).append("_v");
        dictionary[entry.key] = entry.value;
        input.push_back(entry);
    }
    auto status = store->PutBatch(input);
    ASSERT_EQ(status, SUCCESS);
    int count = 0;
    status = store->GetCount({}, count);
    ASSERT_EQ(status, SUCCESS);
    ASSERT_EQ(count, 10);
    const string device = { "" };
    ChangeOwnerToService("/data/service/el1/public/database/SingleStoreImplTest",
        "703c6ec99aa7226bb9f6194cdd60e1873ea9ee52faebd55657ade9f5a5cc3cbd");
    status = store->RemoveDeviceData(device);
    ASSERT_EQ(status, SUCCESS);
}

/**
 * @tc.name: CloseKVStoreWithInvalidAppId
 * @tc.desc: close the kv store with invalid appid
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: Yang Qing
 */
HWTEST_F(SingleStoreImplTest, CloseKVStoreWithInvalidAppId, TestSize.Level0)
{
    AppId appId = { "" };
    StoreId storeId = { "SingleKVStore" };
    Status status = StoreManager::GetInstance().CloseKVStore(appId, storeId);
    ASSERT_EQ(status, INVALID_ARGUMENT);
}

/**
 * @tc.name: CloseKVStoreWithInvalidStoreId
 * @tc.desc: close the kv store with invalid store id
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: Yang Qing
 */
HWTEST_F(SingleStoreImplTest, CloseKVStoreWithInvalidStoreId, TestSize.Level0)
{
    AppId appId = { "SingleStoreImplTest" };
    StoreId storeId = { "" };
    Status status = StoreManager::GetInstance().CloseKVStore(appId, storeId);
    ASSERT_EQ(status, INVALID_ARGUMENT);
}

/**
 * @tc.name: CloseAllKVStore
 * @tc.desc: close all kv store
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: Yang Qing
 */
HWTEST_F(SingleStoreImplTest, CloseAllKVStore, TestSize.Level0)
{
    AppId appId = { "SingleStoreImplTestCloseAll" };
    std::vector<std::shared_ptr<SingleKvStore>> kvStores;
    for (int i = 0; i < 5; i++) {
        std::shared_ptr<SingleKvStore> kvStore;
        Options options;
        options.kvStoreType = SINGLE_VERSION;
        options.securityLevel = S1;
        options.area = EL1;
        options.baseDir = "/data/service/el1/public/database/SingleStoreImplTest";
        std::string sId = "SingleStoreImplTestCloseAll" + std::to_string(i);
        StoreId storeId = { sId };
        Status status;
        kvStore = StoreManager::GetInstance().GetKVStore(appId, storeId, options, status);
        ASSERT_NE(kvStore, nullptr);
        kvStores.push_back(kvStore);
        ASSERT_EQ(status, SUCCESS);
        kvStore = nullptr;
    }
    Status status = StoreManager::GetInstance().CloseAllKVStore(appId);
    ASSERT_EQ(status, SUCCESS);
}

/**
 * @tc.name: CloseAllKVStoreWithInvalidAppId
 * @tc.desc: close the kv store with invalid appid
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: Yang Qing
 */
HWTEST_F(SingleStoreImplTest, CloseAllKVStoreWithInvalidAppId, TestSize.Level0)
{
    AppId appId = { "" };
    Status status = StoreManager::GetInstance().CloseAllKVStore(appId);
    ASSERT_EQ(status, INVALID_ARGUMENT);
}

/**
 * @tc.name: DeleteWithInvalidAppId
 * @tc.desc: delete the kv store with invalid appid
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: Yang Qing
 */
HWTEST_F(SingleStoreImplTest, DeleteWithInvalidAppId, TestSize.Level0)
{
    std::string baseDir = "/data/service/el1/public/database/SingleStoreImplTest";
    AppId appId = { "" };
    StoreId storeId = { "SingleKVStore" };
    Status status = StoreManager::GetInstance().Delete(appId, storeId, baseDir);
    ASSERT_EQ(status, INVALID_ARGUMENT);
}

/**
 * @tc.name: DeleteWithInvalidStoreId
 * @tc.desc: delete the kv store with invalid storeid
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: Yang Qing
 */
HWTEST_F(SingleStoreImplTest, DeleteWithInvalidStoreId, TestSize.Level0)
{
    std::string baseDir = "/data/service/el1/public/database/SingleStoreImplTest";
    AppId appId = { "SingleStoreImplTest" };
    StoreId storeId = { "" };
    Status status = StoreManager::GetInstance().Delete(appId, storeId, baseDir);
    ASSERT_EQ(status, INVALID_ARGUMENT);
}

/**
 * @tc.name: GetKVStoreWithPersistentFalse
 * @tc.desc: delete the kv store with the persistent is false
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: Wang Kai
 */
HWTEST_F(SingleStoreImplTest, GetKVStoreWithPersistentFalse, TestSize.Level0)
{
    std::string baseDir = "/data/service/el1/public/database/SingleStoreImplTest";
    AppId appId = { "SingleStoreImplTest" };
    StoreId storeId = { "SingleKVStorePersistentFalse" };
    std::shared_ptr<SingleKvStore> kvStore;
    Options options;
    options.kvStoreType = SINGLE_VERSION;
    options.securityLevel = S1;
    options.area = EL1;
    options.persistent = false;
    options.baseDir = "/data/service/el1/public/database/SingleStoreImplTest";
    Status status;
    kvStore = StoreManager::GetInstance().GetKVStore(appId, storeId, options, status);
    ASSERT_EQ(kvStore, nullptr);
}

/**
 * @tc.name: GetKVStoreWithInvalidType
 * @tc.desc: delete the kv store with the KvStoreType is InvalidType
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: Wang Kai
 */
HWTEST_F(SingleStoreImplTest, GetKVStoreWithInvalidType, TestSize.Level0)
{
    std::string baseDir = "/data/service/el1/public/database/SingleStoreImpStore";
    AppId appId = { "SingleStoreImplTest" };
    StoreId storeId = { "SingleKVStoreInvalidType" };
    std::shared_ptr<SingleKvStore> kvStore;
    Options options;
    options.kvStoreType = INVALID_TYPE;
    options.securityLevel = S1;
    options.area = EL1;
    options.baseDir = "/data/service/el1/public/database/SingleStoreImplTest";
    Status status;
    kvStore = StoreManager::GetInstance().GetKVStore(appId, storeId, options, status);
    ASSERT_EQ(kvStore, nullptr);
}

/**
 * @tc.name: GetKVStoreWithCreateIfMissingFalse
 * @tc.desc: delete the kv store with the createIfMissing is false
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: Wang Kai
 */
HWTEST_F(SingleStoreImplTest, GetKVStoreWithCreateIfMissingFalse, TestSize.Level0)
{
    std::string baseDir = "/data/service/el1/public/database/SingleStoreImplTest";
    AppId appId = { "SingleStoreImplTest" };
    StoreId storeId = { "SingleKVStoreCreateIfMissingFalse" };
    std::shared_ptr<SingleKvStore> kvStore;
    Options options;
    options.kvStoreType = SINGLE_VERSION;
    options.securityLevel = S1;
    options.area = EL1;
    options.createIfMissing = false;
    options.baseDir = "/data/service/el1/public/database/SingleStoreImplTest";
    Status status;
    kvStore = StoreManager::GetInstance().GetKVStore(appId, storeId, options, status);
    ASSERT_EQ(kvStore, nullptr);
}

/**
 * @tc.name: GetKVStoreWithAutoSync
 * @tc.desc: delete the kv store with the autoSync is false
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: Wang Kai
 */
HWTEST_F(SingleStoreImplTest, GetKVStoreWithAutoSync, TestSize.Level0)
{
    std::string baseDir = "/data/service/el1/public/database/SingleStoreImplTest";
    AppId appId = { "SingleStoreImplTest" };
    StoreId storeId = { "SingleKVStoreAutoSync" };
    std::shared_ptr<SingleKvStore> kvStore;
    Options options;
    options.kvStoreType = SINGLE_VERSION;
    options.securityLevel = S1;
    options.area = EL1;
    options.autoSync = false;
    options.baseDir = "/data/service/el1/public/database/SingleStoreImplTest";
    Status status;
    kvStore = StoreManager::GetInstance().GetKVStore(appId, storeId, options, status);
    ASSERT_NE(kvStore, nullptr);
    status = StoreManager::GetInstance().CloseKVStore(appId, storeId);
    ASSERT_EQ(status, SUCCESS);
}

/**
 * @tc.name: GetKVStoreWithAreaEL2
 * @tc.desc: delete the kv store with the area is EL2
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: Wang Kai
 */
HWTEST_F(SingleStoreImplTest, GetKVStoreWithAreaEL2, TestSize.Level0)
{
    std::string baseDir = "/data/service/el2/100/SingleStoreImplTest";
    mkdir(baseDir.c_str(), (S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH));

    AppId appId = { "SingleStoreImplTest" };
    StoreId storeId = { "SingleKVStoreAreaEL2" };
    std::shared_ptr<SingleKvStore> kvStore;
    Options options;
    options.kvStoreType = SINGLE_VERSION;
    options.securityLevel = S2;
    options.area = EL2;
    options.baseDir = "/data/service/el2/100/SingleStoreImplTest";
    Status status;
    kvStore = StoreManager::GetInstance().GetKVStore(appId, storeId, options, status);
    ASSERT_NE(kvStore, nullptr);
    status = StoreManager::GetInstance().CloseKVStore(appId, storeId);
    ASSERT_EQ(status, SUCCESS);
}

/**
 * @tc.name: GetKVStoreWithRebuildTrue
 * @tc.desc: delete the kv store with the rebuild is true
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: Wang Kai
 */
HWTEST_F(SingleStoreImplTest, GetKVStoreWithRebuildTrue, TestSize.Level0)
{
    std::string baseDir = "/data/service/el1/public/database/SingleStoreImplTest";
    AppId appId = { "SingleStoreImplTest" };
    StoreId storeId = { "SingleKVStoreRebuildFalse" };
    std::shared_ptr<SingleKvStore> kvStore;
    Options options;
    options.kvStoreType = SINGLE_VERSION;
    options.securityLevel = S1;
    options.area = EL1;
    options.rebuild = true;
    options.baseDir = "/data/service/el1/public/database/SingleStoreImplTest";
    Status status;
    kvStore = StoreManager::GetInstance().GetKVStore(appId, storeId, options, status);
    ASSERT_NE(kvStore, nullptr);
    status = StoreManager::GetInstance().CloseKVStore(appId, storeId);
    ASSERT_EQ(status, SUCCESS);
}

/**
 * @tc.name: GetStaticStore
 * @tc.desc: get static store
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: zuojiangijang
 */
HWTEST_F(SingleStoreImplTest, GetStaticStore, TestSize.Level0)
{
    std::string baseDir = "/data/service/el1/public/database/SingleStoreImplTest";
    AppId appId = { "SingleStoreImplTest" };
    StoreId storeId = { "StaticStoreTest" };
    std::shared_ptr<SingleKvStore> kvStore;
    Options options;
    options.kvStoreType = SINGLE_VERSION;
    options.securityLevel = S1;
    options.area = EL1;
    options.rebuild = true;
    options.baseDir = "/data/service/el1/public/database/SingleStoreImplTest";
    options.dataType = DataType::TYPE_STATICS;
    Status status;
    kvStore = StoreManager::GetInstance().GetKVStore(appId, storeId, options, status);
    ASSERT_NE(kvStore, nullptr);
    status = StoreManager::GetInstance().CloseKVStore(appId, storeId);
    ASSERT_EQ(status, SUCCESS);
}

/**
 * @tc.name: StaticStoreAsyncGet
 * @tc.desc: static store async get
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: zuojiangijang
 */
HWTEST_F(SingleStoreImplTest, StaticStoreAsyncGet, TestSize.Level0)
{
    std::string baseDir = "/data/service/el1/public/database/SingleStoreImplTest";
    AppId appId = { "SingleStoreImplTest" };
    StoreId storeId = { "StaticStoreAsyncGetTest" };
    std::shared_ptr<SingleKvStore> kvStore;
    Options options;
    options.kvStoreType = SINGLE_VERSION;
    options.securityLevel = S1;
    options.area = EL1;
    options.rebuild = true;
    options.baseDir = "/data/service/el1/public/database/SingleStoreImplTest";
    options.dataType = DataType::TYPE_STATICS;
    Status status;
    kvStore = StoreManager::GetInstance().GetKVStore(appId, storeId, options, status);
    ASSERT_NE(kvStore, nullptr);
    BlockData<bool> blockData { 1, false };
    std::function<void(Status, Value &&)> result = [&blockData](Status status, Value &&value) {
        ASSERT_EQ(status, Status::NOT_FOUND);
        blockData.SetValue(true);
    };
    auto networkId = DevManager::GetInstance().GetLocalDevice().networkId;
    kvStore->Get({ "key" }, networkId, result);
    blockData.GetValue();
    status = StoreManager::GetInstance().CloseKVStore(appId, storeId);
    ASSERT_EQ(status, SUCCESS);
}

/**
 * @tc.name: StaticStoreAsyncGetEntries
 * @tc.desc: static store async get entries
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: zuojiangijang
 */
HWTEST_F(SingleStoreImplTest, StaticStoreAsyncGetEntries, TestSize.Level0)
{
    std::string baseDir = "/data/service/el1/public/database/SingleStoreImplTest";
    AppId appId = { "SingleStoreImplTest" };
    StoreId storeId = { "StaticStoreAsyncGetEntriesTest" };
    std::shared_ptr<SingleKvStore> kvStore;
    Options options;
    options.kvStoreType = SINGLE_VERSION;
    options.securityLevel = S1;
    options.area = EL1;
    options.rebuild = true;
    options.baseDir = "/data/service/el1/public/database/SingleStoreImplTest";
    options.dataType = DataType::TYPE_STATICS;
    Status status;
    kvStore = StoreManager::GetInstance().GetKVStore(appId, storeId, options, status);
    ASSERT_NE(kvStore, nullptr);
    BlockData<bool> blockData { 1, false };
    std::function<void(Status, std::vector<Entry> &&)> result = [&blockData](
                                                                    Status status, std::vector<Entry> &&value) {
        ASSERT_EQ(status, Status::SUCCESS);
        blockData.SetValue(true);
    };
    auto networkId = DevManager::GetInstance().GetLocalDevice().networkId;
    kvStore->GetEntries({ "key" }, networkId, result);
    blockData.GetValue();
    status = StoreManager::GetInstance().CloseKVStore(appId, storeId);
    ASSERT_EQ(status, SUCCESS);
}

/**
 * @tc.name: DynamicStoreAsyncGet
 * @tc.desc: dynamic store async get
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: zuojiangijang
 */
HWTEST_F(SingleStoreImplTest, DynamicStoreAsyncGet, TestSize.Level0)
{
    std::string baseDir = "/data/service/el1/public/database/SingleStoreImplTest";
    AppId appId = { "SingleStoreImplTest" };
    StoreId storeId = { "DynamicStoreAsyncGetTest" };
    std::shared_ptr<SingleKvStore> kvStore;
    Options options;
    options.kvStoreType = SINGLE_VERSION;
    options.securityLevel = S1;
    options.area = EL1;
    options.rebuild = true;
    options.baseDir = "/data/service/el1/public/database/SingleStoreImplTest";
    options.dataType = DataType::TYPE_DYNAMICAL;
    Status status;
    kvStore = StoreManager::GetInstance().GetKVStore(appId, storeId, options, status);
    ASSERT_NE(kvStore, nullptr);
    status = kvStore->Put({ "Put Test" }, { "Put Value" });
    auto networkId = DevManager::GetInstance().GetLocalDevice().networkId;
    BlockData<bool> blockData { 1, false };
    std::function<void(Status, Value &&)> result = [&blockData](Status status, Value &&value) {
        ASSERT_EQ(status, Status::SUCCESS);
        ASSERT_EQ(value.ToString(), "Put Value");
        blockData.SetValue(true);
    };
    kvStore->Get({ "Put Test" }, networkId, result);
    blockData.GetValue();
    status = StoreManager::GetInstance().CloseKVStore(appId, storeId);
    ASSERT_EQ(status, SUCCESS);
}

/**
 * @tc.name: DynamicStoreAsyncGetEntries
 * @tc.desc: dynamic store async get entries
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: zuojiangijang
 */
HWTEST_F(SingleStoreImplTest, DynamicStoreAsyncGetEntries, TestSize.Level0)
{
    std::string baseDir = "/data/service/el1/public/database/SingleStoreImplTest";
    AppId appId = { "SingleStoreImplTest" };
    StoreId storeId = { "DynamicStoreAsyncGetEntriesTest" };
    std::shared_ptr<SingleKvStore> kvStore;
    Options options;
    options.kvStoreType = SINGLE_VERSION;
    options.securityLevel = S1;
    options.area = EL1;
    options.rebuild = true;
    options.baseDir = "/data/service/el1/public/database/SingleStoreImplTest";
    options.dataType = DataType::TYPE_DYNAMICAL;
    Status status;
    kvStore = StoreManager::GetInstance().GetKVStore(appId, storeId, options, status);
    ASSERT_NE(kvStore, nullptr);
    std::vector<Entry> entries;
    for (int i = 0; i < 10; ++i) {
        Entry entry;
        entry.key = "key_" + std::to_string(i);
        entry.value = std::to_string(i);
        entries.push_back(entry);
    }
    status = kvStore->PutBatch(entries);
    ASSERT_EQ(status, SUCCESS);
    auto networkId = DevManager::GetInstance().GetLocalDevice().networkId;
    BlockData<bool> blockData { 1, false };
    std::function<void(Status, std::vector<Entry> &&)> result = [entries, &blockData](
                                                                    Status status, std::vector<Entry> &&value) {
        ASSERT_EQ(status, Status::SUCCESS);
        ASSERT_EQ(value.size(), entries.size());
        blockData.SetValue(true);
    };
    kvStore->GetEntries({ "key_" }, networkId, result);
    blockData.GetValue();
    status = StoreManager::GetInstance().CloseKVStore(appId, storeId);
    ASSERT_EQ(status, SUCCESS);
}

/**
 * @tc.name: SetConfig
 * @tc.desc: SetConfig
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: ht
 */
HWTEST_F(SingleStoreImplTest, SetConfig, TestSize.Level0)
{
    std::string baseDir = "/data/service/el1/public/database/SingleStoreImplTest";
    AppId appId = { "SingleStoreImplTest" };
    StoreId storeId = { "SetConfigTest" };
    std::shared_ptr<SingleKvStore> kvStore;
    Options options;
    options.kvStoreType = SINGLE_VERSION;
    options.securityLevel = S1;
    options.area = EL1;
    options.rebuild = true;
    options.baseDir = "/data/service/el1/public/database/SingleStoreImplTest";
    options.dataType = DataType::TYPE_DYNAMICAL;
    options.cloudConfig.enableCloud = false;
    Status status;
    kvStore = StoreManager::GetInstance().GetKVStore(appId, storeId, options, status);
    ASSERT_NE(kvStore, nullptr);
    StoreConfig storeConfig;
    storeConfig.cloudConfig.enableCloud = true;
    ASSERT_EQ(kvStore->SetConfig(storeConfig), Status::SUCCESS);
}

/**
 * @tc.name: GetDeviceEntries001
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(SingleStoreImplTest, GetDeviceEntries001, TestSize.Level1)
{
    std::string pkgNameEx = "_distributed_data";
    std::shared_ptr<SingleStoreImpl> kvStore;
    kvStore = CreateKVStore();
    ASSERT_NE(kvStore, nullptr);
    std::vector<Entry> output;
    std::string device = DevManager::GetInstance().GetUnEncryptedUuid();
    std::string devices = "GetDeviceEntriestest";
    auto status = kvStore->GetDeviceEntries("", output);
    ASSERT_EQ(status, INVALID_ARGUMENT);
    status = kvStore->GetDeviceEntries(device, output);
    ASSERT_EQ(status, SUCCESS);
    DevInfo devinfo;
    std::string pkgName = std::to_string(getpid()) + pkgNameEx;
    DistributedHardware::DeviceManager::GetInstance().GetLocalDeviceInfo(pkgName, devinfo);
    ASSERT_NE(std::string(devinfo.deviceId), "");
    status = kvStore->GetDeviceEntries(std::string(devinfo.deviceId), output);
    ASSERT_EQ(status, SUCCESS);
}

/**
 * @tc.name: DoSync001
 * @tc.desc: observer = nullptr
 * @tc.type: FUNC
 */
HWTEST_F(SingleStoreImplTest, DoSync001, TestSize.Level1)
{
    std::shared_ptr<SingleStoreImpl> kvStore;
    kvStore = CreateKVStore();
    EXPECT_NE(kvStore, nullptr) << "kvStorePtr is null.";
    std::string deviceId = "no_exist_device_id";
    std::vector<std::string> deviceIds = { deviceId };
    uint32_t allowedDelayMs = 200;
    kvStore->isClientSync_ = false;
    auto syncStatus = kvStore->Sync(deviceIds, SyncMode::PUSH, allowedDelayMs);
    EXPECT_EQ(syncStatus, Status::SUCCESS) << "sync device should return success";
    kvStore->isClientSync_ = true;
    kvStore->syncObserver_ = nullptr;
    syncStatus = kvStore->Sync(deviceIds, SyncMode::PUSH, allowedDelayMs);
    EXPECT_NE(syncStatus, Status::SUCCESS) << "sync device should return error";
}

/**
 * @tc.name: SetCapabilityEnabled001
 * @tc.desc: enabled
 * @tc.type: FUNC
 */
HWTEST_F(SingleStoreImplTest, SetCapabilityEnabled001, TestSize.Level1)
{
    ASSERT_NE(kvStore_, nullptr);
    auto status = kvStore_->SetCapabilityEnabled(true);
    ASSERT_EQ(status, SUCCESS);
    status = kvStore_->SetCapabilityEnabled(false);
    ASSERT_EQ(status, SUCCESS);
}
} // namespace OHOS::Test