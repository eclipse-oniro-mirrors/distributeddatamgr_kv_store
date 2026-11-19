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

ShrinkState TakeShrinkState(const SingleStoreImpl &store)
{
    ShrinkState state;
    store.GetShrinkStateForTest(state.desiredEnabled, state.pendingTasks);
    return state;
}

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

bool EnsureShrinkEngineReadyForTest(const std::shared_ptr<SingleStoreImpl> &impl, std::string &reason)
{
    if (impl == nullptr || impl->dbStore_ == nullptr) {
        reason = "shrink capability probe failed: store or delegate is null";
        return false;
    }

    DistributedDB::ShrinkParam setParam;
    setParam.operation = DistributedDB::ShrinkOperation::SET;
    setParam.enable = false;
    DistributedDB::PragmaData setData = static_cast<DistributedDB::PragmaData>(&setParam);
    auto setStatus = impl->dbStore_->Pragma(DistributedDB::SHRINK, setData);
    if (setStatus != DistributedDB::DBStatus::OK) {
        reason = "shrink capability SET probe failed, status=" +
            std::to_string(static_cast<int>(setStatus)) +
            "; RD library may be missing, the store may have fallen back to SQLite, or shrink symbols are unavailable";
        return false;
    }

    DistributedDB::ShrinkParam getParam;
    getParam.operation = DistributedDB::ShrinkOperation::GET;
    DistributedDB::PragmaData getData = static_cast<DistributedDB::PragmaData>(&getParam);
    auto getStatus = impl->dbStore_->Pragma(DistributedDB::SHRINK, getData);
    if (getStatus != DistributedDB::DBStatus::OK) {
        reason = "shrink capability GET probe failed, status=" +
            std::to_string(static_cast<int>(getStatus)) +
            "; RD library may be missing, the store may have fallen back to SQLite, or shrink symbols are unavailable";
        return false;
    }
    return true;
}
}

class SingleStoreImplShrinkTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void);
    void TearDown(void);

    std::shared_ptr<SingleKvStore> CreateStore(const std::string &storeId, KvStoreType type,
        bool isPublic = false);
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
    const std::string &storeId, KvStoreType type, bool isPublic)
{
    Options options;
    options.kvStoreType = type;
    options.isPublic = isPublic;
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

HWTEST_F(SingleStoreImplShrinkTest, SetShrinkEnableSQLiteNotSupported, TestSize.Level1)
{
    ASSERT_NE(kvStore_, nullptr);
    EXPECT_EQ(kvStore_->SetShrinkEnable(true), NOT_SUPPORT);
    EXPECT_EQ(kvStore_->SetShrinkEnable(false), SUCCESS);
    auto impl = AsImpl(kvStore_);
    ASSERT_NE(impl, nullptr);

    auto state = TakeShrinkState(*impl);
    EXPECT_FALSE(state.desiredEnabled);
    EXPECT_EQ(state.pendingTasks, 0u);
}

HWTEST_F(SingleStoreImplShrinkTest, SetShrinkEnableIsPublicNotSupported, TestSize.Level1)
{
    auto store = CreateStore("PublicLocalOnlyShrinkStore", KvStoreType::LOCAL_ONLY, true);
    ASSERT_NE(store, nullptr);
    EXPECT_EQ(store->SetShrinkEnable(true), NOT_SUPPORT);
    EXPECT_EQ(store->SetShrinkEnable(false), SUCCESS);
    auto impl = AsImpl(store);
    ASSERT_NE(impl, nullptr);

    auto state = TakeShrinkState(*impl);
    EXPECT_FALSE(state.desiredEnabled);
    EXPECT_EQ(state.pendingTasks, 0u);
    CloseStore("PublicLocalOnlyShrinkStore", store);
}

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

HWTEST_F(SingleStoreImplShrinkTest, SetShrinkEnableDisableBeforeTaskStarts, TestSize.Level1)
{
    auto store = CreateStore("ToggleShrinkStore", KvStoreType::LOCAL_ONLY);
    ASSERT_NE(store, nullptr);
    auto impl = AsImpl(store);
    ASSERT_NE(impl, nullptr);
    std::string probeReason;
    if (!EnsureShrinkEngineReadyForTest(impl, probeReason)) {
        CloseStore("ToggleShrinkStore", store);
        GTEST_SKIP() << probeReason;
    }
    EXPECT_EQ(store->SetShrinkEnable(true), SUCCESS);
    EXPECT_EQ(store->SetShrinkEnable(false), SUCCESS);
    EXPECT_TRUE(WaitShrinkSettled(*impl, false));
    auto snapshot = TakeShrinkState(*impl);
    EXPECT_FALSE(snapshot.desiredEnabled);
    EXPECT_EQ(snapshot.pendingTasks, 0u);

    EXPECT_EQ(store->SetShrinkEnable(false), SUCCESS);
    EXPECT_TRUE(WaitShrinkSettled(*impl, false));
    CloseStore("ToggleShrinkStore", store);
}
}
