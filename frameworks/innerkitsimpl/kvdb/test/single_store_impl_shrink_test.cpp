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
#include <sys/stat.h>
#include <unistd.h>

#include <gtest/gtest.h>

#include <chrono>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "single_store_impl.h"
#include "store_manager.h"
#include "types.h"

using namespace testing::ext;
using namespace OHOS::DistributedKv;

namespace OHOS::Test {
namespace {
constexpr const char *BASE_DIR = "/data/service/el1/public/database/SingleStoreImplTest";
constexpr const char *APP_ID = "SingleStoreImplTest";

struct ShrinkManagerSnapshot {
    bool desiredEnabled = false;
    bool shrinkScheduled = false;
};

// The manager fields are guarded by ShrinkManager::stateMutex_; the asynchronous switch task can
// call Finish concurrently, so tests take a locked snapshot instead of reading the fields directly.
ShrinkManagerSnapshot TakeShrinkManagerSnapshot(SingleStoreImpl &store)
{
    ShrinkManager &manager = store.shrinkManager_;
    std::lock_guard<std::mutex> lock(manager.stateMutex_);
    return { manager.desiredEnabled_, manager.shrinkScheduled_ };
}

// Waits until the manager has the expected desired value and no scheduled task. The store engine
// is never queried here: the switch task only reports acceptance, and the manager state is the
// observable contract of the store wrapper.
bool WaitShrinkManagerIdle(SingleStoreImpl &store, bool desiredEnabled,
    std::chrono::milliseconds timeout = std::chrono::seconds(5))
{
    auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        auto snapshot = TakeShrinkManagerSnapshot(store);
        if (snapshot.desiredEnabled == desiredEnabled && !snapshot.shrinkScheduled) {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    auto snapshot = TakeShrinkManagerSnapshot(store);
    return snapshot.desiredEnabled == desiredEnabled && !snapshot.shrinkScheduled;
}
} // namespace

class SingleStoreImplShrinkTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void);
    void TearDown(void);

    std::shared_ptr<SingleKvStore> CreateStore(const std::string &storeId, KvStoreType type);
    void CloseStore(const std::string &storeId, std::shared_ptr<SingleKvStore> &store);
    static std::shared_ptr<SingleStoreImpl> AsImpl(const std::shared_ptr<SingleKvStore> &store);

    std::shared_ptr<SingleKvStore> kvStore_;
};

void SingleStoreImplShrinkTest::SetUpTestCase(void)
{
    mkdir(BASE_DIR, (S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH));
}

void SingleStoreImplShrinkTest::TearDownTestCase(void)
{
    (void)rmdir(BASE_DIR);
}

void SingleStoreImplShrinkTest::SetUp(void)
{
    kvStore_ = CreateStore("ShrinkApiMatrixStore", KvStoreType::SINGLE_VERSION);
    ASSERT_NE(kvStore_, nullptr);
}

void SingleStoreImplShrinkTest::TearDown(void)
{
    CloseStore("ShrinkApiMatrixStore", kvStore_);
}

std::shared_ptr<SingleKvStore> SingleStoreImplShrinkTest::CreateStore(
    const std::string &storeId, KvStoreType type)
{
    Options options;
    options.kvStoreType = type;
    options.securityLevel = S1;
    options.area = EL1;
    options.backup = true;
    options.baseDir = BASE_DIR;
    AppId appId = { APP_ID };
    StoreId id = { storeId };
    Status status = STORE_NOT_FOUND;
    (void)StoreManager::GetInstance().Delete(appId, id, BASE_DIR);
    return StoreManager::GetInstance().GetKVStore(appId, id, options, status);
}

void SingleStoreImplShrinkTest::CloseStore(const std::string &storeId,
    std::shared_ptr<SingleKvStore> &store)
{
    store = nullptr;
    AppId appId = { APP_ID };
    StoreId id = { storeId };
    (void)StoreManager::GetInstance().CloseKVStore(appId, id);
    (void)StoreManager::GetInstance().Delete(appId, id, BASE_DIR);
}

std::shared_ptr<SingleStoreImpl> SingleStoreImplShrinkTest::AsImpl(
    const std::shared_ptr<SingleKvStore> &store)
{
    return std::static_pointer_cast<SingleStoreImpl>(store);
}

/**
 * @tc.name: SetShrinkEnableSQLiteNotSupported
 * @tc.desc: A store without the GaussDB RD shrink capability rejects enable and accepts disable.
 * @tc.type: FUNC
 */
HWTEST_F(SingleStoreImplShrinkTest, SetShrinkEnableSQLiteNotSupported, TestSize.Level1)
{
    ASSERT_NE(kvStore_, nullptr);
    EXPECT_EQ(kvStore_->SetShrinkEnable(true), NOT_SUPPORT);
    EXPECT_EQ(kvStore_->SetShrinkEnable(false), SUCCESS);
}

/**
 * @tc.name: SetShrinkEnableDeviceNotSupported
 * @tc.desc: DEVICE_COLLABORATION stores are outside the LOCAL_ONLY support matrix.
 * @tc.type: FUNC
 */
HWTEST_F(SingleStoreImplShrinkTest, SetShrinkEnableDeviceNotSupported, TestSize.Level1)
{
    auto store = CreateStore("DeviceShrinkStore", KvStoreType::DEVICE_COLLABORATION);
    ASSERT_NE(store, nullptr);
    EXPECT_EQ(store->SetShrinkEnable(true), NOT_SUPPORT);
    EXPECT_EQ(store->SetShrinkEnable(false), SUCCESS);
    CloseStore("DeviceShrinkStore", store);
}

/**
 * @tc.name: SetShrinkEnableClosed
 * @tc.desc: ALREADY_CLOSED takes precedence over the support matrix for both store types.
 * @tc.type: FUNC
 */
HWTEST_F(SingleStoreImplShrinkTest, SetShrinkEnableClosed, TestSize.Level1)
{
    auto localOnly = CreateStore("ClosedLocalOnlyShrinkStore", KvStoreType::LOCAL_ONLY);
    ASSERT_NE(localOnly, nullptr);
    AppId appId = { APP_ID };
    StoreId localOnlyId = { "ClosedLocalOnlyShrinkStore" };
    ASSERT_EQ(StoreManager::GetInstance().CloseKVStore(appId, localOnlyId), SUCCESS);
    EXPECT_EQ(localOnly->SetShrinkEnable(true), ALREADY_CLOSED);
    EXPECT_EQ(localOnly->SetShrinkEnable(false), ALREADY_CLOSED);
    localOnly = nullptr;
    ASSERT_EQ(StoreManager::GetInstance().Delete(appId, localOnlyId, BASE_DIR), SUCCESS);

    auto sqlite = CreateStore("ClosedSqliteShrinkStore", KvStoreType::SINGLE_VERSION);
    ASSERT_NE(sqlite, nullptr);
    StoreId sqliteId = { "ClosedSqliteShrinkStore" };
    ASSERT_EQ(StoreManager::GetInstance().CloseKVStore(appId, sqliteId), SUCCESS);
    EXPECT_EQ(sqlite->SetShrinkEnable(true), ALREADY_CLOSED);
    EXPECT_EQ(sqlite->SetShrinkEnable(false), ALREADY_CLOSED);
    sqlite = nullptr;
    ASSERT_EQ(StoreManager::GetInstance().Delete(appId, sqliteId, BASE_DIR), SUCCESS);
}

/**
 * @tc.name: SetShrinkEnableLocalOnlyAccepted
 * @tc.desc: A LOCAL_ONLY store accepts both values and repeated identical requests; SUCCESS only
 *           means the asynchronous request was accepted.
 * @tc.type: FUNC
 */
HWTEST_F(SingleStoreImplShrinkTest, SetShrinkEnableLocalOnlyAccepted, TestSize.Level1)
{
    auto store = CreateStore("LocalOnlyShrinkStore", KvStoreType::LOCAL_ONLY);
    ASSERT_NE(store, nullptr);
    EXPECT_EQ(store->SetShrinkEnable(true), SUCCESS);
    EXPECT_EQ(store->SetShrinkEnable(true), SUCCESS);
    EXPECT_EQ(store->SetShrinkEnable(false), SUCCESS);
    EXPECT_EQ(store->SetShrinkEnable(false), SUCCESS);
    CloseStore("LocalOnlyShrinkStore", store);
}

/**
 * @tc.name: DeleteDoesNotDriveShrinkManager
 * @tc.desc: Delete/DeleteBatch never read or update the desired switch state; the wrapper stays
 *           responsive for later requests.
 * @tc.type: FUNC
 */
HWTEST_F(SingleStoreImplShrinkTest, DeleteDoesNotDriveShrinkManager, TestSize.Level1)
{
    auto store = CreateStore("DeleteShrinkStore", KvStoreType::LOCAL_ONLY);
    ASSERT_NE(store, nullptr);
    auto impl = AsImpl(store);
    ASSERT_NE(impl, nullptr);
    for (int i = 0; i < 3; ++i) {
        ASSERT_EQ(store->Put(Key("shrink_delete_" + std::to_string(i)), Value("value")), SUCCESS);
    }

    ASSERT_EQ(store->SetShrinkEnable(true), SUCCESS);
    auto before = TakeShrinkManagerSnapshot(*impl);
    EXPECT_TRUE(before.desiredEnabled);
    ASSERT_EQ(store->Delete(Key("shrink_delete_0")), SUCCESS);
    std::vector<Key> keys = { Key("shrink_delete_1"), Key("shrink_delete_2") };
    ASSERT_EQ(store->DeleteBatch(keys), SUCCESS);
    // Delete/DeleteBatch never read or update the switch state. The asynchronous task may clear
    // shrinkScheduled_ concurrently, so only the stable desired value is compared.
    auto after = TakeShrinkManagerSnapshot(*impl);
    EXPECT_EQ(after.desiredEnabled, before.desiredEnabled);
    EXPECT_EQ(store->SetShrinkEnable(true), SUCCESS);
    CloseStore("DeleteShrinkStore", store);
}

/**
 * @tc.name: SetShrinkEnableDisableBeforeTaskStarts
 * @tc.desc: A back-to-back disable replaces the queued enable request; the final desired state is
 *           disabled and the scheduled state converges to idle without querying the engine.
 * @tc.type: FUNC
 */
HWTEST_F(SingleStoreImplShrinkTest, SetShrinkEnableDisableBeforeTaskStarts, TestSize.Level1)
{
    auto store = CreateStore("ToggleShrinkStore", KvStoreType::LOCAL_ONLY);
    ASSERT_NE(store, nullptr);
    auto impl = AsImpl(store);
    ASSERT_NE(impl, nullptr);
    EXPECT_EQ(store->SetShrinkEnable(true), SUCCESS);
    EXPECT_EQ(store->SetShrinkEnable(false), SUCCESS);
    EXPECT_TRUE(WaitShrinkManagerIdle(*impl, false));
    auto snapshot = TakeShrinkManagerSnapshot(*impl);
    EXPECT_FALSE(snapshot.desiredEnabled);
    EXPECT_FALSE(snapshot.shrinkScheduled);
    EXPECT_EQ(store->SetShrinkEnable(false), SUCCESS);
    CloseStore("ToggleShrinkStore", store);
}
} // namespace OHOS::Test
