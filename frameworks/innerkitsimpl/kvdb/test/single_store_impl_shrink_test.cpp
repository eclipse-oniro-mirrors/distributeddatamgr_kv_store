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
#include <cstdint>
#include <memory>
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
constexpr int64_t WAIT_POLL_INTERVAL_MS = 10;

struct ShrinkState {
    bool desiredEnabled = false;
    uint32_t pendingTasks = 0;
};

// SingleStoreImpl::GetShrinkStateForTest returns a locked snapshot of the ShrinkManager state; the
// asynchronous switch task can call Finish concurrently, so tests take that snapshot instead of
// reading the manager fields directly. pendingTasks == 0 means no switch task is queued or running.
ShrinkState TakeShrinkState(const SingleStoreImpl &store)
{
    ShrinkState state;
    store.GetShrinkStateForTest(state.desiredEnabled, state.pendingTasks);
    return state;
}

// Bounded wait until the wrapper has the expected desired value and no unfinished switch task. The
// engine is never queried here: the switch task only reports acceptance, and the wrapper state is
// the observable contract. The polling interval only keeps the loop cheap; it is not used as the
// sole synchronization.
bool WaitShrinkSettled(const SingleStoreImpl &store, bool desiredEnabled,
    std::chrono::milliseconds timeout = std::chrono::seconds(5))
{
    auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        auto state = TakeShrinkState(store);
        if (state.desiredEnabled == desiredEnabled && state.pendingTasks == 0) {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_POLL_INTERVAL_MS));
    }
    auto state = TakeShrinkState(store);
    return state.desiredEnabled == desiredEnabled && state.pendingTasks == 0;
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
    auto impl = AsImpl(kvStore_);
    ASSERT_NE(impl, nullptr);
    // A store without shrink capability creates no task: the state stays disabled and idle (S2).
    auto state = TakeShrinkState(*impl);
    EXPECT_FALSE(state.desiredEnabled);
    EXPECT_EQ(state.pendingTasks, 0u);
}

/**
 * @tc.name: SetShrinkEnableCapabilityBit
 * @tc.desc: When the open path reports no shrink capable engine (for example LOCAL_ONLY opened on
 *           the SQLite fallback), enable is denied with NOT_SUPPORT and creates no task, while
 *           disable stays an idempotent SUCCESS no-op (S2/C1).
 * @tc.type: FUNC
 */
HWTEST_F(SingleStoreImplShrinkTest, SetShrinkEnableCapabilityBit, TestSize.Level1)
{
    auto store = CreateStore("CapabilityShrinkStore", KvStoreType::LOCAL_ONLY);
    ASSERT_NE(store, nullptr);
    auto impl = AsImpl(store);
    ASSERT_NE(impl, nullptr);
    // SetShrinkSupported is the internal hook the open path uses to publish the probed engine
    // capability; overriding it models the SQLite fallback deterministically on any image.
    impl->SetShrinkSupported(false);
    EXPECT_EQ(store->SetShrinkEnable(true), NOT_SUPPORT);
    EXPECT_EQ(store->SetShrinkEnable(false), SUCCESS);
    auto state = TakeShrinkState(*impl);
    EXPECT_FALSE(state.desiredEnabled);
    EXPECT_EQ(state.pendingTasks, 0u);

    // The refusal is stable and never leaves a pending record behind that could swallow a retry.
    EXPECT_EQ(store->SetShrinkEnable(true), NOT_SUPPORT);
    auto retryState = TakeShrinkState(*impl);
    EXPECT_FALSE(retryState.desiredEnabled);
    EXPECT_EQ(retryState.pendingTasks, 0u);
    CloseStore("CapabilityShrinkStore", store);
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
    auto impl = AsImpl(store);
    ASSERT_NE(impl, nullptr);
    auto state = TakeShrinkState(*impl);
    EXPECT_FALSE(state.desiredEnabled);
    EXPECT_EQ(state.pendingTasks, 0u);
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
    auto impl = AsImpl(store);
    ASSERT_NE(impl, nullptr);
    EXPECT_EQ(store->SetShrinkEnable(true), SUCCESS);
    // Repeated identical requests stay SUCCESS: they are deduplicated while a task with the same
    // value is pending, or accepted as an explicit re-request once it finished (S5/C2).
    EXPECT_EQ(store->SetShrinkEnable(true), SUCCESS);
    EXPECT_EQ(store->SetShrinkEnable(false), SUCCESS);
    EXPECT_EQ(store->SetShrinkEnable(false), SUCCESS);
    // Only convergence is asserted; the exact number of executed SET calls depends on scheduling.
    EXPECT_TRUE(WaitShrinkSettled(*impl, false));
    auto state = TakeShrinkState(*impl);
    EXPECT_FALSE(state.desiredEnabled);
    EXPECT_EQ(state.pendingTasks, 0u);
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
    auto before = TakeShrinkState(*impl);
    EXPECT_TRUE(before.desiredEnabled);
    ASSERT_EQ(store->Delete(Key("shrink_delete_0")), SUCCESS);
    std::vector<Key> keys = { Key("shrink_delete_1"), Key("shrink_delete_2") };
    ASSERT_EQ(store->DeleteBatch(keys), SUCCESS);
    // Delete/DeleteBatch never read or update the switch state. The asynchronous task may call
    // Finish concurrently and decrease pendingTasks, so only the stable desired value and a
    // non-increasing count are compared.
    auto after = TakeShrinkState(*impl);
    EXPECT_EQ(after.desiredEnabled, before.desiredEnabled);
    EXPECT_LE(after.pendingTasks, before.pendingTasks);
    EXPECT_EQ(store->SetShrinkEnable(true), SUCCESS);
    EXPECT_TRUE(WaitShrinkSettled(*impl, true));
    CloseStore("DeleteShrinkStore", store);
}

/**
 * @tc.name: SetShrinkEnableDisableBeforeTaskStarts
 * @tc.desc: A back-to-back disable supersedes the queued enable request; the final desired state is
 *           disabled and the wrapper converges to idle without any pending switch task.
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
    EXPECT_TRUE(WaitShrinkSettled(*impl, false));
    auto snapshot = TakeShrinkState(*impl);
    EXPECT_FALSE(snapshot.desiredEnabled);
    EXPECT_EQ(snapshot.pendingTasks, 0u);
    // A same-value disable after the toggle settled is an explicit re-request (C2): it may enqueue
    // one deduplicated SET(false) task, so wait for the wrapper to settle again before closing.
    EXPECT_EQ(store->SetShrinkEnable(false), SUCCESS);
    EXPECT_TRUE(WaitShrinkSettled(*impl, false));
    CloseStore("ToggleShrinkStore", store);
}
} // namespace OHOS::Test
