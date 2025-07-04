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
#define LOG_TAG "DistributedKvDataManagerEncryptTest"
#include <gtest/gtest.h>

#include "distributed_kv_data_manager.h"
#include "file_ex.h"
#include "kvstore_death_recipient.h"
#include "log_print.h"
#include "types.h"

using namespace testing::ext;
using namespace OHOS::DistributedKv;

class DistributedKvDataManagerEncryptTest : public testing::Test {
public:
    static DistributedKvDataManager manager;
    static Options createEnc;

    static UserId userId;

    static AppId appId;
    static StoreId storeId;

    static void SetUpTestCase(void);
    static void TearDownTestCase(void);

    static void RemoveAllStore(DistributedKvDataManager &manager);

    void SetUp();
    void TearDown();
    DistributedKvDataManagerEncryptTest();
    virtual ~DistributedKvDataManagerEncryptTest();
};

class MyDeathRecipient : public KvStoreDeathRecipient {
public:
    MyDeathRecipient() { }
    virtual ~MyDeathRecipient() { }
    void OnRemoteDied() override { }
};

DistributedKvDataManager DistributedKvDataManagerEncryptTest::manager;
Options DistributedKvDataManagerEncryptTest::createEnc;

UserId DistributedKvDataManagerEncryptTest::userId;

AppId DistributedKvDataManagerEncryptTest::appId;
StoreId DistributedKvDataManagerEncryptTest::storeId;

void DistributedKvDataManagerEncryptTest::RemoveAllStore(DistributedKvDataManager &manager)
{
    manager.CloseAllKvStore(appId);
    manager.DeleteKvStore(appId, storeId, createEnc.baseDir);
    manager.DeleteAllKvStore(appId, createEnc.baseDir);
}
void DistributedKvDataManagerEncryptTest::SetUpTestCase(void)
{
    createEnc.createIfMissing = true;
    createEnc.encrypt = true;
    createEnc.securityLevel = S1;
    createEnc.autoSync = true;
    createEnc.kvStoreType = SINGLE_VERSION;

    userId.userId = "account0";
    appId.appId = "com.ohos.nb.service";

    storeId.storeId = "EncryptStoreId";

    createEnc.area = EL1;
    createEnc.baseDir = std::string("/data/service/el1/public/database/") + appId.appId;
    mkdir(createEnc.baseDir.c_str(), (S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH));
}

void DistributedKvDataManagerEncryptTest::TearDownTestCase(void)
{
    RemoveAllStore(manager);
    (void)remove((createEnc.baseDir + "/kvdb").c_str());
    (void)remove(createEnc.baseDir.c_str());
}

void DistributedKvDataManagerEncryptTest::SetUp(void)
{}

DistributedKvDataManagerEncryptTest::DistributedKvDataManagerEncryptTest(void)
{}

DistributedKvDataManagerEncryptTest::~DistributedKvDataManagerEncryptTest(void)
{}

void DistributedKvDataManagerEncryptTest::TearDown(void)
{
    RemoveAllStore(manager);
}

/**
 * @tc.name: kvstore_ddm_createEncryptedStore_001
 * @tc.desc: Create an encrypted KvStore.
 * @tc.type: FUNC
 */
HWTEST_F(DistributedKvDataManagerEncryptTest, kvstore_ddm_createEncryptedStore_001, TestSize.Level1)
{
    ZLOGI("kvstore_ddm_createEncryptedStore_001 begin.");
    std::shared_ptr<SingleKvStore> kvStore;
    Status status = manager.GetSingleKvStore(createEnc, appId, storeId, kvStore);
    ASSERT_EQ(status, Status::SUCCESS);
    ASSERT_NE(kvStore, nullptr);

    Key key = "age";
    Value value = "18";
    status = kvStore->Put(key, value);
    EXPECT_EQ(Status::SUCCESS, status) << "KvStore put data return wrong status";

    // get value from kvstore.
    Value valueRet;
    Status statusRet = kvStore->Get(key, valueRet);
    EXPECT_EQ(Status::SUCCESS, statusRet) << "get data return wrong status";

    EXPECT_EQ(value, valueRet) << "value and valueRet are not equal";
}

/**
 * @tc.name: GetEncryptStoreWithKeyFromService
 * @tc.desc: Get encrypt store, delete key, get store again.
 * @tc.type: FUNC
 */
HWTEST_F(DistributedKvDataManagerEncryptTest, GetEncryptStoreWithKeyFromService, TestSize.Level1)
{
    ZLOGI("GetEncryptStoreWithKeyFromService begin.");
    std::shared_ptr<SingleKvStore> kvStore;
    Status status = manager.GetSingleKvStore(createEnc, appId, storeId, kvStore);
    ASSERT_EQ(status, Status::SUCCESS);
    ASSERT_NE(kvStore, nullptr);

    manager.CloseAllKvStore(appId);
    std::string keyPath = createEnc.baseDir + "/key/" + storeId.storeId + ".key_v1";
    auto ret = remove(keyPath.c_str());
    ASSERT_EQ(ret, 0);

    kvStore = nullptr;
    status = manager.GetSingleKvStore(createEnc, appId, storeId, kvStore);
    ASSERT_EQ(status, Status::SUCCESS);
    ASSERT_NE(kvStore, nullptr);
}

/**
 * @tc.name: DeleteEncryptedStore_001
 * @tc.desc: Failed to delete encrypted store, then open again.
 * @tc.type: FUNC
 */
HWTEST_F(DistributedKvDataManagerEncryptTest, DeleteEncryptedStore_001, TestSize.Level1)
{
    ZLOGI("DeleteEncryptedStore_001 begin.");
    std::shared_ptr<SingleKvStore> kvStore;
    Status status = manager.GetSingleKvStore(createEnc, appId, storeId, kvStore);
    ASSERT_EQ(status, Status::SUCCESS);
    ASSERT_NE(kvStore, nullptr);

    Key key = "age";
    Value value = "18";
    status = kvStore->Put(key, value);
    EXPECT_EQ(Status::SUCCESS, status);
    std::shared_ptr<KvStoreResultSet> resultSet = nullptr;
    kvStore->GetResultSet("", resultSet);
    ASSERT_NE(resultSet, nullptr);
    ASSERT_TRUE(resultSet->GetCount() == 1);

    // Database busy, delete failed
    status = manager.DeleteKvStore(appId, storeId, createEnc.baseDir);
    ASSERT_NE(status, Status::SUCCESS);

    kvStore->CloseResultSet(resultSet);
    resultSet = nullptr;
    manager.CloseAllKvStore(appId);
    kvStore = nullptr;
    // GetSingleKvStore successful, data still available
    status = manager.GetSingleKvStore(createEnc, appId, storeId, kvStore);
    ASSERT_EQ(status, Status::SUCCESS);
    ASSERT_NE(kvStore, nullptr);
    Value valueRet;
    status = kvStore->Get(key, valueRet);
    ASSERT_EQ(valueRet, value);

    status = manager.DeleteKvStore(appId, storeId, createEnc.baseDir);
    ASSERT_EQ(status, Status::SUCCESS);
}