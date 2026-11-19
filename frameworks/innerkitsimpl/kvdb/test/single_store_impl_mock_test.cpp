/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <queue>
#include <sys/types.h>
#include <thread>
#include <unistd.h>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "include/convertor_mock.h"
#include "include/dev_manager_mock.h"
#include "include/kv_store_nb_delegate_mock.h"
#include "include/kvdb_notifier_client_mock.h"
#include "include/kvdb_service_client_mock.h"
#include "include/observer_bridge_mock.h"
#include "include/task_executor_mock.h"
#include "kv_store_nb_delegate.h"
#include "kvstore_observer.h"
#include "single_store_impl.h"
#include "store_factory.h"
#include "store_manager.h"

namespace OHOS::DistributedKv {
using namespace std;
using namespace testing;
using namespace DistributedDB;

static StoreId storeId = { "single_test" };
static AppId appId = { "rekey" };

namespace {
constexpr int WAIT_POLL_INTERVAL_MS = 10;
constexpr int SHRINK_WAIT_TIMEOUT_MS = 5000;
constexpr int32_t MOCK_PAGE_SIZE = 4;

struct ShrinkState {
    bool desired = true;
    uint32_t pending = 0;
};

ShrinkState GetShrinkState(const std::shared_ptr<SingleStoreImpl> &store)
{
    ShrinkState state{};
    store->GetShrinkStateForTest(state.desired, state.pending);
    return state;
}

bool WaitShrinkState(const std::shared_ptr<SingleStoreImpl> &store, bool desired, uint32_t pending,
    std::chrono::milliseconds timeout = std::chrono::milliseconds(SHRINK_WAIT_TIMEOUT_MS))
{
    auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        auto state = GetShrinkState(store);
        if (state.desired == desired && state.pending == pending) {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_POLL_INTERVAL_MS));
    }
    auto state = GetShrinkState(store);
    return state.desired == desired && state.pending == pending;
}
} // namespace

class ShrinkMockDelegate : public DistributedDB::KvStoreNbDelegate {
public:
    using DBKey = DistributedDB::Key;
    using DBValue = DistributedDB::Value;
    using DBEntry = DistributedDB::Entry;
    using DBQuery = DistributedDB::Query;
    using DBResultSet = DistributedDB::KvStoreResultSet;
    using DBStatus = DistributedDB::DBStatus;

    DBStatus Pragma(PragmaCmd cmd, PragmaData &paramData) override
    {
        if (cmd == GET_PAGE_SIZE) {
            // Test guard: production code must not probe the engine on the open path anymore.
            // Count the calls so tests can assert zero; keep filling the page size so this mock
            // remains usable by a future GetPageSize case.
            auto pageSize = static_cast<int32_t *>(paramData);
            if (pageSize != nullptr) {
                *pageSize = MOCK_PAGE_SIZE;
            }
            pageSizeCalls_++;
            return DBStatus::OK;
        }
        if (cmd != SHRINK) {
            return DBStatus::NOT_SUPPORT;
        }
        auto param = static_cast<ShrinkParam *>(paramData);
        if (param == nullptr || param->operation != ShrinkOperation::SET) {
            return DBStatus::INVALID_ARGS;
        }
        setCalls_++;
        {
            std::unique_lock<std::mutex> lock(gateMutex_);
            gateCondition_.wait(lock, [this]() { return !blocked_; });
        }
        DBStatus status = DBStatus::OK;
        {
            std::lock_guard<std::mutex> lock(gateMutex_);
            if (!statusQueue_.empty()) {
                status = statusQueue_.front();
                statusQueue_.pop();
            }
        }
        if (status != DBStatus::OK) {
            return status;
        }
        actual_.store(param->enable);
        return DBStatus::OK;
    }

    DBStatus Get(const DBKey &, DBValue &) const override { return DBStatus::NOT_SUPPORT; }
    DBStatus GetEntries(const DBKey &, std::vector<DBEntry> &) const override { return DBStatus::NOT_SUPPORT; }
    DBStatus GetEntries(const DBKey &, DBResultSet *&) const override { return DBStatus::NOT_SUPPORT; }
    DBStatus GetEntries(const DBQuery &, std::vector<DBEntry> &) const override { return DBStatus::NOT_SUPPORT; }
    DBStatus GetEntries(const DBQuery &, DBResultSet *&) const override { return DBStatus::NOT_SUPPORT; }
    DBStatus GetCount(const DBQuery &, int &) const override { return DBStatus::NOT_SUPPORT; }
    DBStatus CloseResultSet(DBResultSet *&) override { return DBStatus::NOT_SUPPORT; }
    DBStatus Put(const DBKey &, const DBValue &) override { return DBStatus::OK; }
    DBStatus PutBatch(const std::vector<DBEntry> &) override { return DBStatus::NOT_SUPPORT; }
    DBStatus DeleteBatch(const std::vector<DBKey> &) override { return DBStatus::OK; }
    DBStatus Delete(const DBKey &) override { return DBStatus::OK; }
    DBStatus GetLocal(const DBKey &, DBValue &) const override { return DBStatus::NOT_SUPPORT; }
    DBStatus GetLocalEntries(const DBKey &, std::vector<DBEntry> &) const override { return DBStatus::NOT_SUPPORT; }
    DBStatus PutLocal(const DBKey &, const DBValue &) override { return DBStatus::NOT_SUPPORT; }
    DBStatus DeleteLocal(const DBKey &) override { return DBStatus::NOT_SUPPORT; }
    DBStatus PublishLocal(const DBKey &, bool, bool, const DistributedDB::KvStoreNbPublishOnConflict &) override
    {
        return DBStatus::NOT_SUPPORT;
    }
    DBStatus UnpublishToLocal(const DBKey &, bool, bool) override { return DBStatus::NOT_SUPPORT; }
    std::string GetStoreId() const override { return "shrink_mock"; }
    DBStatus SetConflictNotifier(int, const DistributedDB::KvStoreNbConflictNotifier &) override
    {
        return DBStatus::OK;
    }
    DBStatus Rekey(const DistributedDB::CipherPassword &) override { return DBStatus::NOT_SUPPORT; }
    DBStatus Export(const std::string &, const DistributedDB::CipherPassword &, bool) override
    {
        return DBStatus::NOT_SUPPORT;
    }
    DBStatus Import(const std::string &, const DistributedDB::CipherPassword &, bool) override
    {
        return DBStatus::NOT_SUPPORT;
    }
    DBStatus StartTransaction() override { return DBStatus::NOT_SUPPORT; }
    DBStatus Commit() override { return DBStatus::NOT_SUPPORT; }
    DBStatus Rollback() override { return DBStatus::NOT_SUPPORT; }
    DBStatus PutLocalBatch(const std::vector<DBEntry> &) override { return DBStatus::NOT_SUPPORT; }
    DBStatus DeleteLocalBatch(const std::vector<DBKey> &) override { return DBStatus::NOT_SUPPORT; }
    DBStatus GetSecurityOption(DistributedDB::SecurityOption &) const override { return DBStatus::OK; }
    DBStatus CheckIntegrity() const override { return DBStatus::NOT_SUPPORT; }
    DBStatus GetKeys(const DBKey &, std::vector<DBKey> &) const override { return DBStatus::NOT_SUPPORT; }
    DBStatus UpdateKey(const DistributedDB::UpdateKeyCallback &) override { return DBStatus::NOT_SUPPORT; }
    DBStatus GetDeviceEntries(const std::string &, std::vector<DBEntry> &) const override
    {
        return DBStatus::NOT_SUPPORT;
    }

    void BlockSet()
    {
        std::lock_guard<std::mutex> lock(gateMutex_);
        blocked_ = true;
    }

    void ReleaseSet()
    {
        {
            std::lock_guard<std::mutex> lock(gateMutex_);
            blocked_ = false;
        }
        gateCondition_.notify_all();
    }

    void SetNextStatus(DBStatus status)
    {
        std::lock_guard<std::mutex> lock(gateMutex_);
        statusQueue_.push(status);
    }

    bool WaitSetCalls(int expected)
    {
        auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        while (std::chrono::steady_clock::now() < deadline) {
            if (setCalls_.load() >= expected) {
                return true;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_POLL_INTERVAL_MS));
        }
        return setCalls_.load() >= expected;
    }

    bool WaitActual(bool expected)
    {
        auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        while (std::chrono::steady_clock::now() < deadline) {
            if (actual_.load() == expected) {
                return true;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_POLL_INTERVAL_MS));
        }
        return actual_.load() == expected;
    }

    std::atomic<int> setCalls_ { 0 };
    std::atomic<int> pageSizeCalls_ { 0 };
    std::atomic<bool> actual_ { false };

private:
    bool blocked_ = false;
    std::mutex gateMutex_;
    std::condition_variable gateCondition_;
    std::queue<DBStatus> statusQueue_;
};

std::shared_ptr<SingleStoreImpl> CreateShrinkStore(const std::shared_ptr<ShrinkMockDelegate> &delegate,
    Convertor &convertor, KvStoreType type = KvStoreType::LOCAL_ONLY, bool isPublic = false)
{
    Options options;
    options.kvStoreType = type;
    options.isPublic = isPublic;
    options.securityLevel = S2;
    options.area = EL1;
    options.baseDir = "/data/service/el1/public/database/SingleStoreImplTest";
    options.backup = false;
    options.syncable = false;
    AppId appId = { "SingleStoreImplTest" };
    return std::make_shared<SingleStoreImpl>(delegate, appId, options, convertor);
}

// Minimal concrete SingleKvStore used only to exercise the base-class default
// SetShrinkEnable implementation (F2: enable -> NOT_SUPPORT, disable -> SUCCESS).
class DefaultShrinkKvStoreFake : public SingleKvStore {
public:
    Status Get(const Key &, Value &) override { return Status::NOT_SUPPORT; }
    Status GetEntries(const Key &, std::vector<Entry> &) const override { return Status::NOT_SUPPORT; }
    Status GetEntries(const DataQuery &, std::vector<Entry> &) const override { return Status::NOT_SUPPORT; }
    Status GetResultSet(const Key &, std::shared_ptr<KvStoreResultSet> &) const override
    {
        return Status::NOT_SUPPORT;
    }
    Status GetResultSet(const DataQuery &, std::shared_ptr<KvStoreResultSet> &) const override
    {
        return Status::NOT_SUPPORT;
    }
    Status CloseResultSet(std::shared_ptr<KvStoreResultSet> &) override { return Status::NOT_SUPPORT; }
    Status GetCount(const DataQuery &, int &) const override { return Status::NOT_SUPPORT; }
    Status RemoveDeviceData(const std::string &) override { return Status::NOT_SUPPORT; }
    Status GetSecurityLevel(SecurityLevel &) const override { return Status::NOT_SUPPORT; }
    Status Sync(const std::vector<std::string> &, SyncMode, uint32_t) override { return Status::NOT_SUPPORT; }
    Status RegisterSyncCallback(std::shared_ptr<KvStoreSyncCallback>) override { return Status::NOT_SUPPORT; }
    Status UnRegisterSyncCallback() override { return Status::NOT_SUPPORT; }
    Status SetSyncParam(const KvSyncParam &) override { return Status::NOT_SUPPORT; }
    Status GetSyncParam(KvSyncParam &) override { return Status::NOT_SUPPORT; }
    Status SetCapabilityEnabled(bool) const override { return Status::NOT_SUPPORT; }
    Status SetCapabilityRange(const std::vector<std::string> &, const std::vector<std::string> &) const override
    {
        return Status::NOT_SUPPORT;
    }
    Status SubscribeWithQuery(const std::vector<std::string> &, const DataQuery &) override
    {
        return Status::NOT_SUPPORT;
    }
    Status UnsubscribeWithQuery(const std::vector<std::string> &, const DataQuery &) override
    {
        return Status::NOT_SUPPORT;
    }
};

class SingleStoreImplMockTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;

public:
    using DBStatus = DistributedDB::DBStatus;
    using DBStore = DistributedDB::KvStoreNbDelegate;
    using Observer = DistributedKv::KvStoreObserver;
    static inline shared_ptr<DevManagerMock> devManagerMock = nullptr;
    static inline shared_ptr<KVDBServiceClientMock> kVDBServiceClientMock = nullptr;
    static inline shared_ptr<KVDBNotifierClientMock> kVDBNotifierClientMock = nullptr;
    static inline shared_ptr<ObserverBridgeMock> observerBridgeMock = nullptr;
    static inline shared_ptr<TaskExecutorMock> taskExecutorMock = nullptr;
    static inline shared_ptr<ConvertorMock> convertorMock = nullptr;
    static inline shared_ptr<StoreFactory> storeFactory = nullptr;
    std::shared_ptr<SingleStoreImpl> CreateKVStore(bool autosync = false, bool backup = true, bool isSyncable = false);
};

void SingleStoreImplMockTest::SetUp() { }

void SingleStoreImplMockTest::TearDown() { }

void SingleStoreImplMockTest::SetUpTestCase()
{
    GTEST_LOG_(INFO) << "SetUpTestCase enter";
    std::string baseDir = "/data/service/el1/public/database/SingleStoreImplTest";
    mkdir(baseDir.c_str(), (S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH));
    devManagerMock = make_shared<DevManagerMock>();
    BDevManager::devManager = devManagerMock;
    kVDBServiceClientMock = make_shared<KVDBServiceClientMock>();
    BKVDBServiceClient::kVDBServiceClient = kVDBServiceClientMock;
    kVDBNotifierClientMock = make_shared<KVDBNotifierClientMock>();
    BKVDBNotifierClient::kVDBNotifierClient = kVDBNotifierClientMock;
    observerBridgeMock = make_shared<ObserverBridgeMock>();
    BObserverBridge::observerBridge = observerBridgeMock;
    taskExecutorMock = make_shared<TaskExecutorMock>();
    BTaskExecutor::taskExecutor = taskExecutorMock;
    ON_CALL(*taskExecutorMock, Execute(_)).WillByDefault(Return(TaskExecutor::INVALID_TASK_ID));
    convertorMock = make_shared<ConvertorMock>();
    BConvertor::convertor = convertorMock;
    storeFactory = make_shared<StoreFactory>();
}

void SingleStoreImplMockTest::TearDownTestCase()
{
    GTEST_LOG_(INFO) << "TearDownTestCase enter";
    BDevManager::devManager = nullptr;
    devManagerMock = nullptr;
    BKVDBServiceClient::kVDBServiceClient = nullptr;
    kVDBServiceClientMock = nullptr;
    BKVDBNotifierClient::kVDBNotifierClient = nullptr;
    kVDBNotifierClientMock = nullptr;
    BObserverBridge::observerBridge = nullptr;
    observerBridgeMock = nullptr;
    BTaskExecutor::taskExecutor = nullptr;
    taskExecutorMock = nullptr;
    BConvertor::convertor = nullptr;
    convertorMock = nullptr;
    std::string baseDir = "/data/service/el1/public/database/SingleStoreImplTest";
    (void)remove("/data/service/el1/public/database/SingleStoreImplTest");
}

std::shared_ptr<SingleStoreImpl> SingleStoreImplMockTest::CreateKVStore(bool autosync, bool backup, bool isSyncable)
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
    options.backup = backup;
    options.syncable = isSyncable;
    auto dbManager = storeFactory->GetDBManager(options.baseDir, appId);
    auto dbPassword = SecurityManager::GetInstance().GetDBPassword(storeId.storeId, options.baseDir, options.encrypt);
    DBStatus dbStatus = DBStatus::DB_ERROR;
    dbManager->GetKvStore(storeId, storeFactory->GetDBOption(options, dbPassword),
        [&dbManager, &kvStore, &appId, &dbStatus, &options](auto status, auto *store) {
            dbStatus = status;
            if (store == nullptr) {
                return;
            }
            auto release = [dbManager](auto *store) {
                dbManager->CloseKvStore(store);
            };
            auto dbStore = std::shared_ptr<DBStore>(store, release);
            storeFactory->SetDbConfig(dbStore, options.walStartCheckpointSize);
            const Convertor &convertor = *(storeFactory->convertors_[options.kvStoreType]);
            kvStore = std::make_shared<SingleStoreImpl>(dbStore, appId, options, convertor);
        });
    return kvStore;
}

/**
 * @tc.name: OnRemoteDied
 * @tc.desc: remote died.
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: cao zhijun
 */
HWTEST_F(SingleStoreImplMockTest, OnRemoteDied, testing::ext::TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SingleStoreImplMockTest-begin OnRemoteDied";
    try {
        std::shared_ptr<SingleStoreImpl> kvStore;
        kvStore = CreateKVStore(false, false);
        ASSERT_NE(kvStore, nullptr);
        EXPECT_NE(kvStore->dbStore_, nullptr);

        kvStore->taskId_ = 1;
        kvStore->OnRemoteDied();

        kvStore->taskId_ = 0;
        shared_ptr<Observer> observer = make_shared<Observer>();
        shared_ptr<Observer> observer1 = make_shared<Observer>();
        Convertor cvt;
        Convertor cvt1;
        shared_ptr<ObserverBridge> obsBridge = make_shared<ObserverBridge>(appId, storeId, 0, observer, cvt);
        shared_ptr<ObserverBridge> obsBridge1 = make_shared<ObserverBridge>(appId, storeId, 0, observer1, cvt1);

        uint32_t firs = 0;
        firs |= SUBSCRIBE_TYPE_REMOTE;
        pair<uint32_t, std::shared_ptr<ObserverBridge>> one(0, obsBridge);
        pair<uint32_t, std::shared_ptr<ObserverBridge>> two(firs, obsBridge1);

        kvStore->observers_.Insert(uintptr_t(observer.get()), one);
        kvStore->observers_.Insert(uintptr_t(observer1.get()), two);
        EXPECT_CALL(*observerBridgeMock, OnServiceDeath()).Times(1);
        EXPECT_CALL(*taskExecutorMock, Schedule(_, _, _, _)).WillOnce(Return(1));
        kvStore->OnRemoteDied();
        kvStore->observers_.Erase(uintptr_t(observer.get()));
        kvStore->observers_.Erase(uintptr_t(observer1.get()));
        EXPECT_TRUE(kvStore->taskId_ == 1);
    } catch (...) {
        EXPECT_TRUE(false);
        GTEST_LOG_(INFO) << "SingleStoreImplMockTest-an exception occurred by OnRemoteDied.";
    }
    GTEST_LOG_(INFO) << "SingleStoreImplMockTest-end OnRemoteDied";
}

/**
 * @tc.name: Register
 * @tc.desc: register.
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: cao zhijun
 */
HWTEST_F(SingleStoreImplMockTest, Register, testing::ext::TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SingleStoreImplMockTest-begin Register";
    try {
        std::shared_ptr<SingleStoreImpl> kvStore;
        kvStore = CreateKVStore(false, false);
        ASSERT_NE(kvStore, nullptr);
        EXPECT_NE(kvStore->dbStore_, nullptr);

        shared_ptr<Observer> observer = make_shared<Observer>();
        shared_ptr<Observer> observer1 = make_shared<Observer>();
        Convertor cvt;
        Convertor cvt1;
        shared_ptr<ObserverBridge> obsBridge = make_shared<ObserverBridge>(appId, storeId, 0, observer, cvt);
        shared_ptr<ObserverBridge> obsBridge1 = make_shared<ObserverBridge>(appId, storeId, 0, observer1, cvt1);

        uint32_t firs = 0;
        firs |= SUBSCRIBE_TYPE_CLOUD;
        pair<uint32_t, std::shared_ptr<ObserverBridge>> one(0, obsBridge);
        pair<uint32_t, std::shared_ptr<ObserverBridge>> two(firs, obsBridge1);

        kvStore->observers_.Insert(uintptr_t(observer.get()), one);
        kvStore->observers_.Insert(uintptr_t(observer1.get()), two);
        EXPECT_CALL(*observerBridgeMock, RegisterRemoteObserver(_)).WillOnce(Return(ERROR));
        EXPECT_CALL(*taskExecutorMock, Schedule(_, _, _, _)).WillOnce(Return(1));
        kvStore->Register();
        EXPECT_TRUE(kvStore->taskId_ == 1);

        EXPECT_CALL(*observerBridgeMock, RegisterRemoteObserver(_)).WillOnce(Return(SUCCESS));
        kvStore->Register();
        kvStore->observers_.Erase(uintptr_t(observer.get()));
        kvStore->observers_.Erase(uintptr_t(observer1.get()));
        EXPECT_TRUE(kvStore->taskId_ == 0);
    } catch (...) {
        EXPECT_TRUE(false);
        GTEST_LOG_(INFO) << "SingleStoreImplMockTest-an exception occurred by Register.";
    }
    GTEST_LOG_(INFO) << "SingleStoreImplMockTest-end Register";
}

/**
* @tc.name: Put_001
* @tc.desc: Put.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SingleStoreImplMockTest, Put_001, testing::ext::TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SingleStoreImplMockTest-begin Put_001";
    try {
        std::shared_ptr<SingleStoreImpl> kvStore = CreateKVStore(false, false, true);
        ASSERT_NE(kvStore, nullptr);
        EXPECT_NE(kvStore->dbStore_, nullptr);
        std::vector<uint8_t> vect;
        EXPECT_CALL(*convertorMock, ToLocalDBKey(_)).WillOnce(Return(vect));
        size_t maxTestKeyLen = 10;
        std::string str(maxTestKeyLen, 'a');
        Blob key(str);
        Blob value("test_value");
        Status status = kvStore->Put(key, value);
        EXPECT_TRUE(status == INVALID_ARGUMENT);
    } catch (...) {
        EXPECT_TRUE(false);
        GTEST_LOG_(INFO) << "SingleStoreImplMockTest-an exception occurred by Put_001.";
    }
    GTEST_LOG_(INFO) << "SingleStoreImplMockTest-end Put_001";
}


/**
* @tc.name: Put_002
* @tc.desc: Put.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SingleStoreImplMockTest, Put_002, testing::ext::TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SingleStoreImplMockTest-begin Put_002";
    try {
        EXPECT_CALL(*taskExecutorMock, Schedule(_, _, _, _)).Times(AnyNumber());
        std::shared_ptr<SingleStoreImpl> kvStore = CreateKVStore(false, false);
        ASSERT_NE(kvStore, nullptr);
        EXPECT_NE(kvStore->dbStore_, nullptr);
        std::vector<uint8_t> vect{3, 8};
        EXPECT_CALL(*convertorMock, ToLocalDBKey(_)).WillOnce(Return(vect));
        size_t overlongTestKeyLen = 4 * 1024 * 1024 + 1;
        std::string str(overlongTestKeyLen, 'b');
        Blob key1("key1");
        Blob value1(str);
        Status status = kvStore->Put(key1, value1);
        EXPECT_TRUE(status == INVALID_ARGUMENT);
    } catch (...) {
        EXPECT_TRUE(false);
        GTEST_LOG_(INFO) << "SingleStoreImplMockTest-an exception occurred by Put_002.";
    }
    GTEST_LOG_(INFO) << "SingleStoreImplMockTest-end Put_002";
}

/**
* @tc.name: PutBatch_001
* @tc.desc: PutBatch.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SingleStoreImplMockTest, PutBatch_001, testing::ext::TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SingleStoreImplMockTest-begin PutBatch_001";
    try {
        std::shared_ptr<SingleStoreImpl> kvStore = CreateKVStore(false, false);
        ASSERT_NE(kvStore, nullptr);
        EXPECT_NE(kvStore->dbStore_, nullptr);
        kvStore->dbStore_ = nullptr;
        EXPECT_TRUE(kvStore->dbStore_ == nullptr);
        std::vector<Entry> in;
        for (int i = 0; i < 2; ++i) {
            Entry entry;
            entry.key = std::to_string(i).append("_k");
            entry.value = std::to_string(i).append("_v");
            in.emplace_back(entry);
        }
        Status status = kvStore->PutBatch(in);
        EXPECT_TRUE(status == ALREADY_CLOSED);
    } catch (...) {
        EXPECT_TRUE(false);
        GTEST_LOG_(INFO) << "SingleStoreImplMockTest-an exception occurred by PutBatch_001.";
    }
    GTEST_LOG_(INFO) << "SingleStoreImplMockTest-end PutBatch_001";
}

/**
* @tc.name: PutBatch_002
* @tc.desc: PutBatch.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SingleStoreImplMockTest, PutBatch_002, testing::ext::TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SingleStoreImplMockTest-begin PutBatch_002";
    try {
        std::shared_ptr<SingleStoreImpl> kvStore = CreateKVStore(false, false);
        ASSERT_NE(kvStore, nullptr);
        EXPECT_NE(kvStore->dbStore_, nullptr);
        std::vector<Entry> in;
        for (int i = 0; i < 2; ++i) {
            Entry entry;
            entry.key = std::to_string(i).append("_key");
            entry.value = std::to_string(i).append("_val");
            in.emplace_back(entry);
        }
        std::vector<uint8_t> vect;
        EXPECT_CALL(*convertorMock, ToLocalDBKey(_)).WillOnce(Return(vect));
        Status status = kvStore->PutBatch(in);
        EXPECT_TRUE(status == INVALID_ARGUMENT);
    } catch (...) {
        EXPECT_TRUE(false);
        GTEST_LOG_(INFO) << "SingleStoreImplMockTest-an exception occurred by PutBatch_002.";
    }
    GTEST_LOG_(INFO) << "SingleStoreImplMockTest-end PutBatch_002";
}

/**
* @tc.name: PutBatch_003
* @tc.desc: PutBatch.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SingleStoreImplMockTest, PutBatch_003, testing::ext::TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SingleStoreImplMockTest-begin PutBatch_003";
    try {
        std::shared_ptr<SingleStoreImpl> kvStore = CreateKVStore(false, false);
        ASSERT_NE(kvStore, nullptr);
        EXPECT_NE(kvStore->dbStore_, nullptr);
        std::vector<Entry> in;
        for (int i = 0; i < 2; ++i) {
            Entry entry;
            entry.key = std::to_string(i).append("_key");
            entry.value = std::to_string(i).append("_val");
            in.emplace_back(entry);
        }
        std::vector<uint8_t> vect;
        EXPECT_CALL(*convertorMock, ToLocalDBKey(_)).WillOnce(Return(vect));
        Status status = kvStore->PutBatch(in);
        EXPECT_TRUE(status == INVALID_ARGUMENT);
    } catch (...) {
        EXPECT_TRUE(false);
        GTEST_LOG_(INFO) << "SingleStoreImplMockTest-an exception occurred by PutBatch_003.";
    }
    GTEST_LOG_(INFO) << "SingleStoreImplMockTest-end PutBatch_003";
}

/**
* @tc.name: Delete
* @tc.desc: Delete Key.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SingleStoreImplMockTest, Delete, testing::ext::TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SingleStoreImplMockTest-begin Delete";
    try {
        std::shared_ptr<SingleStoreImpl> kvStore = CreateKVStore(false, false);
        ASSERT_NE(kvStore, nullptr);
        EXPECT_NE(kvStore->dbStore_, nullptr);
        kvStore->dbStore_= nullptr;
        EXPECT_TRUE(kvStore->dbStore_ == nullptr);
        Blob key1("key1");
        Status status = kvStore->Delete(key1);
        EXPECT_TRUE(status == ALREADY_CLOSED);
    } catch (...) {
        EXPECT_TRUE(false);
        GTEST_LOG_(INFO) << "SingleStoreImplMockTest-an exception occurred by Delete.";
    }
    GTEST_LOG_(INFO) << "SingleStoreImplMockTest-end Delete";
}

/**
* @tc.name: DeleteBatch
* @tc.desc: DeleteBatch Keys.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SingleStoreImplMockTest, DeleteBatch, testing::ext::TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SingleStoreImplMockTest-begin DeleteBatch";
    try {
        std::shared_ptr<SingleStoreImpl> kvStore = CreateKVStore(false, false);
        ASSERT_NE(kvStore, nullptr);
        EXPECT_NE(kvStore->dbStore_, nullptr);
        kvStore->dbStore_= nullptr;
        EXPECT_TRUE(kvStore->dbStore_ == nullptr);
        std::vector<Key> keys;
        for (int i = 0; i < 2; ++i) {
            Key key = std::to_string(i).append("_k");
            keys.emplace_back(key);
        }
        Status status = kvStore->DeleteBatch(keys);
        EXPECT_TRUE(status == ALREADY_CLOSED);
    } catch (...) {
        EXPECT_TRUE(false);
        GTEST_LOG_(INFO) << "SingleStoreImplMockTest-an exception occurred by DeleteBatch.";
    }
    GTEST_LOG_(INFO) << "SingleStoreImplMockTest-end DeleteBatch";
}

/**
* @tc.name: StartTransaction
* @tc.desc: Start Transaction.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SingleStoreImplMockTest, StartTransaction, testing::ext::TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SingleStoreImplMockTest-begin StartTransaction";
    try {
        std::shared_ptr<SingleStoreImpl> kvStore = CreateKVStore(false, false);
        ASSERT_NE(kvStore, nullptr);
        EXPECT_NE(kvStore->dbStore_, nullptr);
        kvStore->dbStore_= nullptr;
        EXPECT_TRUE(kvStore->dbStore_ == nullptr);
        Status status = kvStore->StartTransaction();
        EXPECT_TRUE(status == ALREADY_CLOSED);
    } catch (...) {
        EXPECT_TRUE(false);
        GTEST_LOG_(INFO) << "SingleStoreImplMockTest-an exception occurred by StartTransaction.";
    }
    GTEST_LOG_(INFO) << "SingleStoreImplMockTest-end StartTransaction";
}

/**
* @tc.name: Commit
* @tc.desc: Commit.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SingleStoreImplMockTest, Commit, testing::ext::TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SingleStoreImplMockTest-begin Commit";
    try {
        std::shared_ptr<SingleStoreImpl> kvStore = CreateKVStore(false, false);
        ASSERT_NE(kvStore, nullptr);
        EXPECT_NE(kvStore->dbStore_, nullptr);
        kvStore->dbStore_= nullptr;
        EXPECT_TRUE(kvStore->dbStore_ == nullptr);
        Status status = kvStore->Commit();
        EXPECT_TRUE(status == ALREADY_CLOSED);
    } catch (...) {
        EXPECT_TRUE(false);
        GTEST_LOG_(INFO) << "SingleStoreImplMockTest-an exception occurred by Commit.";
    }
    GTEST_LOG_(INFO) << "SingleStoreImplMockTest-end Commit";
}

/**
* @tc.name: Rollback
* @tc.desc: Rollback kvstore.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SingleStoreImplMockTest, Rollback, testing::ext::TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SingleStoreImplMockTest-begin Rollback";
    try {
        std::shared_ptr<SingleStoreImpl> kvStore = CreateKVStore(false, false);
        ASSERT_NE(kvStore, nullptr);
        EXPECT_NE(kvStore->dbStore_, nullptr);
        kvStore->dbStore_= nullptr;
        EXPECT_TRUE(kvStore->dbStore_ == nullptr);
        Status status = kvStore->Rollback();
        EXPECT_TRUE(status == ALREADY_CLOSED);
    } catch (...) {
        EXPECT_TRUE(false);
        GTEST_LOG_(INFO) << "SingleStoreImplMockTest-an exception occurred by Rollback.";
    }
    GTEST_LOG_(INFO) << "SingleStoreImplMockTest-end Rollback";
}

/**
* @tc.name: Get
* @tc.desc: Get.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SingleStoreImplMockTest, Get, testing::ext::TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SingleStoreImplMockTest-begin Get";
    try {
        std::shared_ptr<SingleStoreImpl> kvStore = CreateKVStore(false, false);
        ASSERT_NE(kvStore, nullptr);
        EXPECT_NE(kvStore->dbStore_, nullptr);
        kvStore->dbStore_= nullptr;
        EXPECT_TRUE(kvStore->dbStore_ == nullptr);
        size_t testKeyLen = 10;
        std::string str(testKeyLen, 'a');
        Blob key(str);
        Blob value("test_value");
        Status status = kvStore->Get(key, value);
        EXPECT_TRUE(status == ALREADY_CLOSED);
    } catch (...) {
        EXPECT_TRUE(false);
        GTEST_LOG_(INFO) << "SingleStoreImplMockTest-an exception occurred by Get.";
    }
    GTEST_LOG_(INFO) << "SingleStoreImplMockTest-end Get";
}

/**
* @tc.name: GetEntries_001
* @tc.desc: Get Entries.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SingleStoreImplMockTest, GetEntries_001, testing::ext::TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SingleStoreImplMockTest-begin GetEntries_001";
    try {
        std::vector<uint8_t> vct;
        std::shared_ptr<SingleStoreImpl> kvStore = CreateKVStore(false, false);
        ASSERT_NE(kvStore, nullptr);
        EXPECT_NE(kvStore->dbStore_, nullptr);
        EXPECT_CALL(*convertorMock, GetPrefix(An<const Key&>())).WillOnce(Return(vct));
        Blob key("test");
        std::vector<Entry> vecs;
        for (int i = 0; i < 2; ++i) {
            Entry entry;
            entry.key = std::to_string(i).append("_key");
            entry.value = std::to_string(i).append("_val");
            vecs.emplace_back(entry);
        }
        Status status = kvStore->GetEntries(key, vecs);
        EXPECT_TRUE(status == INVALID_ARGUMENT);
    } catch (...) {
        EXPECT_TRUE(false);
        GTEST_LOG_(INFO) << "SingleStoreImplMockTest-an exception occurred by GetEntries_001.";
    }
    GTEST_LOG_(INFO) << "SingleStoreImplMockTest-end GetEntries_001";
}

/**
* @tc.name: GetDeviceEntries
* @tc.desc: Get device entries.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SingleStoreImplMockTest, GetDeviceEntries, testing::ext::TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SingleStoreImplMockTest-begin GetDeviceEntries";
    try {
        std::shared_ptr<SingleStoreImpl> kvStore = CreateKVStore(false, false);
        ASSERT_NE(kvStore, nullptr);
        EXPECT_NE(kvStore->dbStore_, nullptr);
        kvStore->dbStore_= nullptr;
        EXPECT_TRUE(kvStore->dbStore_ == nullptr);
        std::vector<Entry> vcs;
        for (int i = 0; i < 2; ++i) {
            Entry entry;
            entry.key = std::to_string(i).append("_key");
            entry.value = std::to_string(i).append("_val");
            vcs.emplace_back(entry);
        }
        std::string device = "test device";
        Status status = kvStore->GetDeviceEntries(device, vcs);
        EXPECT_TRUE(status == ALREADY_CLOSED);
    } catch (...) {
        EXPECT_TRUE(false);
        GTEST_LOG_(INFO) << "SingleStoreImplMockTest-an exception occurred by GetDeviceEntries.";
    }
    GTEST_LOG_(INFO) << "SingleStoreImplMockTest-end GetDeviceEntries";
}

/**
* @tc.name: GetCount
* @tc.desc: Get count.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SingleStoreImplMockTest, GetCount, testing::ext::TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SingleStoreImplMockTest-begin GetCount";
    try {
        std::shared_ptr<SingleStoreImpl> kvStore = CreateKVStore(false, false);
        ASSERT_NE(kvStore, nullptr);
        EXPECT_NE(kvStore->dbStore_, nullptr);
        kvStore->dbStore_= nullptr;
        EXPECT_TRUE(kvStore->dbStore_ == nullptr);
        DataQuery query;
        int cnt = 0;
        Status status = kvStore->GetCount(query, cnt);
        EXPECT_TRUE(status == ALREADY_CLOSED);
    } catch (...) {
        EXPECT_TRUE(false);
        GTEST_LOG_(INFO) << "SingleStoreImplMockTest-an exception occurred by GetCount.";
    }
    GTEST_LOG_(INFO) << "SingleStoreImplMockTest-end GetCount";
}

/**
* @tc.name: GetCount
* @tc.desc: Get count.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SingleStoreImplMockTest, GetSecurityLevel, testing::ext::TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SingleStoreImplMockTest-begin GetSecurityLevel";
    try {
        std::shared_ptr<SingleStoreImpl> kvStore = CreateKVStore(false, false);
        ASSERT_NE(kvStore, nullptr);
        EXPECT_NE(kvStore->dbStore_, nullptr);
        kvStore->dbStore_= nullptr;
        EXPECT_TRUE(kvStore->dbStore_ == nullptr);
        SecurityLevel securityLevel = NO_LABEL;
        Status status = kvStore->GetSecurityLevel(securityLevel);
        EXPECT_TRUE(status == ALREADY_CLOSED);
    } catch (...) {
        EXPECT_TRUE(false);
        GTEST_LOG_(INFO) << "SingleStoreImplMockTest-an exception occurred by GetSecurityLevel.";
    }
    GTEST_LOG_(INFO) << "SingleStoreImplMockTest-end GetSecurityLevel";
}

/**
* @tc.name: RemoveDeviceData_001
* @tc.desc: Remove device data.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SingleStoreImplMockTest, RemoveDeviceData_001, testing::ext::TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SingleStoreImplMockTest-begin RemoveDeviceData_001";
    try {
        std::shared_ptr<SingleStoreImpl> kvStore = CreateKVStore(false, false);
        ASSERT_NE(kvStore, nullptr);
        EXPECT_NE(kvStore->dbStore_, nullptr);
        kvStore->dbStore_= nullptr;
        EXPECT_TRUE(kvStore->dbStore_ == nullptr);
        Status status = kvStore->RemoveDeviceData("testdevice");
        EXPECT_TRUE(status == ALREADY_CLOSED);
    } catch (...) {
        EXPECT_TRUE(false);
        GTEST_LOG_(INFO) << "SingleStoreImplMockTest-an exception occurred by RemoveDeviceData_001.";
    }
    GTEST_LOG_(INFO) << "SingleStoreImplMockTest-end RemoveDeviceData_001";
}

/**
* @tc.name: RemoveDeviceData_002
* @tc.desc: Remove device data.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SingleStoreImplMockTest, RemoveDeviceData_002, testing::ext::TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SingleStoreImplMockTest-begin RemoveDeviceData_002";
    try {
        std::shared_ptr<SingleStoreImpl> kvStore = CreateKVStore(false, false);
        ASSERT_NE(kvStore, nullptr);
        EXPECT_NE(kvStore->dbStore_, nullptr);
        EXPECT_CALL(*kVDBServiceClientMock, GetInstance()).WillOnce(Return(nullptr));
        Status status = kvStore->RemoveDeviceData("testdevice");
        EXPECT_TRUE(status == SERVER_UNAVAILABLE);
    } catch (...) {
        EXPECT_TRUE(false);
        GTEST_LOG_(INFO) << "SingleStoreImplMockTest-an exception occurred by RemoveDeviceData_002.";
    }
    GTEST_LOG_(INFO) << "SingleStoreImplMockTest-end RemoveDeviceData_002";
}

/**
* @tc.name: CloudSync_001
* @tc.desc: Cloud sync.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SingleStoreImplMockTest, CloudSync_001, testing::ext::TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SingleStoreImplMockTest-begin CloudSync_001";
    try {
        std::shared_ptr<SingleStoreImpl> kvStore = CreateKVStore(false, false);
        ASSERT_NE(kvStore, nullptr);
        EXPECT_NE(kvStore->dbStore_, nullptr);
        EXPECT_CALL(*kVDBServiceClientMock, GetInstance()).WillOnce(Return(nullptr));
        AsyncDetail asyncDetail;
        Status status = kvStore->CloudSync(asyncDetail);
        EXPECT_TRUE(status == SERVER_UNAVAILABLE);
    } catch (...) {
        EXPECT_TRUE(false);
        GTEST_LOG_(INFO) << "SingleStoreImplMockTest-an exception occurred by CloudSync_001.";
    }
    GTEST_LOG_(INFO) << "SingleStoreImplMockTest-end CloudSync_001";
}

/**
* @tc.name: CloudSync_002
* @tc.desc: Cloud sync.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SingleStoreImplMockTest, CloudSync_002, testing::ext::TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SingleStoreImplMockTest-begin CloudSync_002";
    try {
        std::shared_ptr<SingleStoreImpl> kvStore = CreateKVStore(false, false);
        ASSERT_NE(kvStore, nullptr);
        EXPECT_NE(kvStore->dbStore_, nullptr);
        std::shared_ptr<KVDBServiceClient> ser = make_shared<KVDBServiceClient>(nullptr);
        ASSERT_NE(ser, nullptr);
        EXPECT_CALL(*kVDBServiceClientMock, GetInstance()).WillOnce(Return(ser));
        EXPECT_CALL(*kVDBServiceClientMock, GetServiceAgent(_)).WillOnce(Return(nullptr));
        AsyncDetail asyncDetail;
        Status status = kvStore->CloudSync(asyncDetail);
        EXPECT_TRUE(status == ILLEGAL_STATE);
    } catch (...) {
        EXPECT_TRUE(false);
        GTEST_LOG_(INFO) << "SingleStoreImplMockTest-an exception occurred by CloudSync_002.";
    }
    GTEST_LOG_(INFO) << "SingleStoreImplMockTest-end CloudSync_002";
}

/**
* @tc.name: SetSyncParam
* @tc.desc: Set sync param.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SingleStoreImplMockTest, SetSyncParam, testing::ext::TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SingleStoreImplMockTest-begin SetSyncParam";
    try {
        std::shared_ptr<SingleStoreImpl> kvStore = CreateKVStore(false, false);
        ASSERT_NE(kvStore, nullptr);
        EXPECT_NE(kvStore->dbStore_, nullptr);
        EXPECT_CALL(*kVDBServiceClientMock, GetInstance()).WillOnce(Return(nullptr));
        KvSyncParam syncParam{ 500 };
        Status status = kvStore->SetSyncParam(syncParam);
        EXPECT_TRUE(status == SERVER_UNAVAILABLE);
    } catch (...) {
        EXPECT_TRUE(false);
        GTEST_LOG_(INFO) << "SingleStoreImplMockTest-an exception occurred by SetSyncParam.";
    }
    GTEST_LOG_(INFO) << "SingleStoreImplMockTest-end SetSyncParam";
}

/**
* @tc.name: GetSyncParam
* @tc.desc: Get sync param.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SingleStoreImplMockTest, GetSyncParam, testing::ext::TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SingleStoreImplMockTest-begin GetSyncParam";
    try {
        std::shared_ptr<SingleStoreImpl> kvStore = CreateKVStore(false, false);
        ASSERT_NE(kvStore, nullptr);
        EXPECT_NE(kvStore->dbStore_, nullptr);
        EXPECT_CALL(*kVDBServiceClientMock, GetInstance()).WillOnce(Return(nullptr));
        KvSyncParam syncParam;
        Status status = kvStore->GetSyncParam(syncParam);
        EXPECT_TRUE(status == SERVER_UNAVAILABLE);
    } catch (...) {
        EXPECT_TRUE(false);
        GTEST_LOG_(INFO) << "SingleStoreImplMockTest-an exception occurred by GetSyncParam.";
    }
    GTEST_LOG_(INFO) << "SingleStoreImplMockTest-end GetSyncParam";
}

/**
* @tc.name: SetCapabilityEnabled_001
* @tc.desc: Set capability enabled.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SingleStoreImplMockTest, SetCapabilityEnabled_001, testing::ext::TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SingleStoreImplMockTest-begin SetCapabilityEnabled_001";
    try {
        std::shared_ptr<SingleStoreImpl> kvStore = CreateKVStore(false, false);
        ASSERT_NE(kvStore, nullptr);
        EXPECT_NE(kvStore->dbStore_, nullptr);
        EXPECT_CALL(*kVDBServiceClientMock, GetInstance()).WillOnce(Return(nullptr));
        Status status = kvStore->SetCapabilityEnabled(false);
        EXPECT_TRUE(status == SERVER_UNAVAILABLE);
    } catch (...) {
        EXPECT_TRUE(false);
        GTEST_LOG_(INFO) << "SingleStoreImplMockTest-an exception occurred by SetCapabilityEnabled_001.";
    }
    GTEST_LOG_(INFO) << "SingleStoreImplMockTest-end SetCapabilityEnabled_001";
}

/**
* @tc.name: SetCapabilityEnabled_002
* @tc.desc: Set capability enabled.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SingleStoreImplMockTest, SetCapabilityEnabled_002, testing::ext::TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SingleStoreImplMockTest-begin SetCapabilityEnabled_002";
    try {
        std::shared_ptr<SingleStoreImpl> kvStore = CreateKVStore(false, false);
        ASSERT_NE(kvStore, nullptr);
        EXPECT_NE(kvStore->dbStore_, nullptr);
        std::shared_ptr<KVDBServiceClient> service = make_shared<KVDBServiceClient>(nullptr);
        ASSERT_NE(service, nullptr);
        EXPECT_CALL(*kVDBServiceClientMock, GetInstance()).WillOnce(Return(service));
        Status status = kvStore->SetCapabilityEnabled(true);
        EXPECT_TRUE(status == ERROR);
    } catch (...) {
        EXPECT_TRUE(false);
        GTEST_LOG_(INFO) << "SingleStoreImplMockTest-an exception occurred by SetCapabilityEnabled_002.";
    }
    GTEST_LOG_(INFO) << "SingleStoreImplMockTest-end SetCapabilityEnabled_002";
}

/**
* @tc.name: SetCapabilityRange
* @tc.desc: Set capability range.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SingleStoreImplMockTest, SetCapabilityRange, testing::ext::TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SingleStoreImplMockTest-begin SetCapabilityRange";
    try {
        std::shared_ptr<SingleStoreImpl> kvStore = CreateKVStore(false, false);
        ASSERT_NE(kvStore, nullptr);
        EXPECT_NE(kvStore->dbStore_, nullptr);
        EXPECT_CALL(*kVDBServiceClientMock, GetInstance()).WillOnce(Return(nullptr));
        std::vector<std::string> localLabels{"local", "near"};
        std::vector<std::string> remoteLabels{"remote", "far"};
        Status status = kvStore->SetCapabilityRange(localLabels, remoteLabels);
        EXPECT_TRUE(status == SERVER_UNAVAILABLE);
    } catch (...) {
        EXPECT_TRUE(false);
        GTEST_LOG_(INFO) << "SingleStoreImplMockTest-an exception occurred by SetCapabilityRange.";
    }
    GTEST_LOG_(INFO) << "SingleStoreImplMockTest-end SetCapabilityRange";
}

/**
* @tc.name: SubscribeWithQuery_001
* @tc.desc: Subscribe with query.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SingleStoreImplMockTest, SubscribeWithQuery_001, testing::ext::TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SingleStoreImplMockTest-begin SubscribeWithQuery_001";
    try {
        std::shared_ptr<SingleStoreImpl> kvStore = CreateKVStore(false, false);
        ASSERT_NE(kvStore, nullptr);
        EXPECT_NE(kvStore->dbStore_, nullptr);
        EXPECT_CALL(*kVDBServiceClientMock, GetInstance()).WillOnce(Return(nullptr));
        std::vector<std::string> devices{"dev1", "dev2"};
        DataQuery query;
        Status status = kvStore->SubscribeWithQuery(devices, query);
        EXPECT_TRUE(status == SERVER_UNAVAILABLE);
    } catch (...) {
        EXPECT_TRUE(false);
        GTEST_LOG_(INFO) << "SingleStoreImplMockTest-an exception occurred by SubscribeWithQuery_001";
    }
    GTEST_LOG_(INFO) << "SingleStoreImplMockTest-end SubscribeWithQuery_001";
}

/**
* @tc.name: SubscribeWithQuery_002
* @tc.desc: Subscribe with query.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SingleStoreImplMockTest, SubscribeWithQuery_002, testing::ext::TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SingleStoreImplMockTest-begin SubscribeWithQuery_002";
    try {
        std::shared_ptr<SingleStoreImpl> kvStore = CreateKVStore(false, false);
        ASSERT_NE(kvStore, nullptr);
        EXPECT_NE(kvStore->dbStore_, nullptr);
        std::shared_ptr<KVDBServiceClient> serv = make_shared<KVDBServiceClient>(nullptr);
        ASSERT_NE(serv, nullptr);
        EXPECT_CALL(*kVDBServiceClientMock, GetInstance()).WillOnce(Return(serv));
        EXPECT_CALL(*kVDBServiceClientMock, GetServiceAgent(_)).WillOnce(Return(nullptr));
        std::vector<std::string> devices{"dev0", "dev1"};
        DataQuery query;
        Status status = kvStore->SubscribeWithQuery(devices, query);
        EXPECT_TRUE(status == ILLEGAL_STATE);
    } catch (...) {
        EXPECT_TRUE(false);
        GTEST_LOG_(INFO) << "SingleStoreImplMockTest-an exception occurred by SubscribeWithQuery_002";
    }
    GTEST_LOG_(INFO) << "SingleStoreImplMockTest-end SubscribeWithQuery_002";
}

/**
* @tc.name: UnsubscribeWithQuery_001
* @tc.desc: Unsubscribe with query.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SingleStoreImplMockTest, UnsubscribeWithQuery_001, testing::ext::TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SingleStoreImplMockTest-begin UnsubscribeWithQuery_001";
    try {
        std::shared_ptr<SingleStoreImpl> kvStore = CreateKVStore(false, false);
        ASSERT_NE(kvStore, nullptr);
        EXPECT_NE(kvStore->dbStore_, nullptr);
        EXPECT_CALL(*kVDBServiceClientMock, GetInstance()).WillOnce(Return(nullptr));
        std::vector<std::string> devs{"dev0", "dev1"};
        DataQuery quer;
        Status status = kvStore->UnsubscribeWithQuery(devs, quer);
        EXPECT_TRUE(status == SERVER_UNAVAILABLE);
    } catch (...) {
        EXPECT_TRUE(false);
        GTEST_LOG_(INFO) << "SingleStoreImplMockTest-an exception occurred by UnsubscribeWithQuery_001";
    }
    GTEST_LOG_(INFO) << "SingleStoreImplMockTest-end UnsubscribeWithQuery_001";
}

/**
* @tc.name: UnsubscribeWithQuery_002
* @tc.desc: Unsubscribe with query.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SingleStoreImplMockTest, UnsubscribeWithQuery_002, testing::ext::TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SingleStoreImplMockTest-begin UnsubscribeWithQuery_002";
    try {
        std::shared_ptr<SingleStoreImpl> kv = CreateKVStore(false, false);
        ASSERT_NE(kv, nullptr);
        EXPECT_NE(kv->dbStore_, nullptr);
        std::shared_ptr<KVDBServiceClient> serv = make_shared<KVDBServiceClient>(nullptr);
        ASSERT_NE(serv, nullptr);
        EXPECT_CALL(*kVDBServiceClientMock, GetInstance()).WillOnce(Return(serv));
        EXPECT_CALL(*kVDBServiceClientMock, GetServiceAgent(_)).WillOnce(Return(nullptr));
        std::vector<std::string> devs{"dev3", "dev4"};
        DataQuery quer;
        Status status = kv->UnsubscribeWithQuery(devs, quer);
        EXPECT_TRUE(status == ILLEGAL_STATE);
    } catch (...) {
        EXPECT_TRUE(false);
        GTEST_LOG_(INFO) << "SingleStoreImplMockTest-an exception occurred by UnsubscribeWithQuery_002";
    }
    GTEST_LOG_(INFO) << "SingleStoreImplMockTest-end UnsubscribeWithQuery_002";
}

/**
* @tc.name: Restore_001
* @tc.desc: restore kv.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SingleStoreImplMockTest, Restore_001, testing::ext::TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SingleStoreImplMockTest-begin Restore_001";
    try {
        std::shared_ptr<SingleStoreImpl> kv = CreateKVStore(false, false);
        ASSERT_NE(kv, nullptr);
        EXPECT_CALL(*kVDBServiceClientMock, GetInstance()).WillOnce(Return(nullptr));
        std::string baseDirect = "/data/service/el1/public/database/SingleStoreImplTest";
        std::string file = "test.txt";
        kv->isApplication_ = false;
        Status status = kv->Restore(file, baseDirect);
        EXPECT_TRUE(status != SUCCESS);
    } catch (...) {
        EXPECT_TRUE(false);
        GTEST_LOG_(INFO) << "SingleStoreImplMockTest-an exception occurred by Restore_001";
    }
    GTEST_LOG_(INFO) << "SingleStoreImplMockTest-end Restore_001";
}

/**
* @tc.name: Restore_002
* @tc.desc: restore kv.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SingleStoreImplMockTest, Restore_002, testing::ext::TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SingleStoreImplMockTest-begin Restore_002";
    try {
        std::shared_ptr<SingleStoreImpl> kv = CreateKVStore(false, false);
        ASSERT_NE(kv, nullptr);
        std::shared_ptr<KVDBServiceClient> serv = make_shared<KVDBServiceClient>(nullptr);
        ASSERT_NE(serv, nullptr);
        EXPECT_CALL(*kVDBServiceClientMock, GetInstance()).WillOnce(Return(serv));
        std::string baseDirect = "/data/service/el1/public/database/SingleStoreImplTest";
        std::string file = "test1.txt";
        kv->isApplication_ = true;
        kv->apiVersion_ = 15; // version
        Status status = kv->Restore(file, baseDirect);
        EXPECT_TRUE(status != SUCCESS);
    } catch (...) {
        EXPECT_TRUE(false);
        GTEST_LOG_(INFO) << "SingleStoreImplMockTest-an exception occurred by Restore_002";
    }
    GTEST_LOG_(INFO) << "SingleStoreImplMockTest-end Restore_002";
}

/**
* @tc.name: GetResultSet
* @tc.desc: Get result Set.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SingleStoreImplMockTest, GetResultSet, testing::ext::TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SingleStoreImplMockTest-begin GetResultSet";
    try {
        std::shared_ptr<SingleStoreImpl> kv = CreateKVStore(false, false);
        ASSERT_NE(kv, nullptr);
        kv->dbStore_= nullptr;
        EXPECT_TRUE(kv->dbStore_ == nullptr);
        SingleStoreImpl::DBQuery dbQuer;
        std::shared_ptr<KvStoreResultSet> output;
        Status status = kv->GetResultSet(dbQuer, output);
        EXPECT_TRUE(status == ALREADY_CLOSED);
    } catch (...) {
        EXPECT_TRUE(false);
        GTEST_LOG_(INFO) << "SingleStoreImplMockTest-an exception occurred by GetResultSet";
    }
    GTEST_LOG_(INFO) << "SingleStoreImplMockTest-end GetResultSet";
}

/**
* @tc.name: GetEntries
* @tc.desc: Get entries.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SingleStoreImplMockTest, GetEntries, testing::ext::TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SingleStoreImplMockTest-begin GetEntries";
    try {
        std::shared_ptr<SingleStoreImpl> kv = CreateKVStore(false, false);
        ASSERT_NE(kv, nullptr);
        kv->dbStore_= nullptr;
        EXPECT_TRUE(kv->dbStore_ == nullptr);
        std::vector<Entry> vects;
        SingleStoreImpl::DBQuery dbQuer;
        Status status = kv->GetEntries(dbQuer, vects);
        EXPECT_TRUE(status == ALREADY_CLOSED);
    } catch (...) {
        EXPECT_TRUE(false);
        GTEST_LOG_(INFO) << "SingleStoreImplMockTest-an exception occurred by GetEntries";
    }
    GTEST_LOG_(INFO) << "SingleStoreImplMockTest-end GetEntries";
}

/**
* @tc.name: DoSync_001
* @tc.desc: do sync.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SingleStoreImplMockTest, DoSync_001, testing::ext::TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SingleStoreImplMockTest-begin DoSync_001";
    try {
        std::shared_ptr<SingleStoreImpl> kv = CreateKVStore(false, false);
        ASSERT_NE(kv, nullptr);
        kv->isClientSync_ = false;
        ASSERT_FALSE(kv->isClientSync_);
        EXPECT_CALL(*kVDBServiceClientMock, GetInstance()).WillOnce(Return(nullptr));
        SingleStoreImpl::SyncInfo syInfo;
        std::shared_ptr<SingleStoreImpl::SyncCallback> obser;
        auto res = kv->DoSync(syInfo, obser);
        EXPECT_TRUE(res == SERVER_UNAVAILABLE);
    } catch (...) {
        EXPECT_TRUE(false);
        GTEST_LOG_(INFO) << "SingleStoreImplMockTest-an exception occurred by DoSync_001";
    }
    GTEST_LOG_(INFO) << "SingleStoreImplMockTest-end DoSync_001";
}

/**
* @tc.name: DoSync_002
* @tc.desc: do sync.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SingleStoreImplMockTest, DoSync_002, testing::ext::TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SingleStoreImplMockTest-begin DoSync_002";
    try {
        std::shared_ptr<SingleStoreImpl> kv = CreateKVStore(false, false);
        ASSERT_NE(kv, nullptr);
        kv->isClientSync_ = false;
        std::shared_ptr<KVDBServiceClient> servic = make_shared<KVDBServiceClient>(nullptr);
        ASSERT_NE(servic, nullptr);
        EXPECT_CALL(*kVDBServiceClientMock, GetInstance()).WillOnce(Return(servic));
        EXPECT_CALL(*kVDBServiceClientMock, GetServiceAgent(_)).WillOnce(Return(nullptr));
        SingleStoreImpl::SyncInfo syInfo;
        std::shared_ptr<SingleStoreImpl::SyncCallback> observer;
        auto res = kv->DoSync(syInfo, observer);
        EXPECT_TRUE(res == ILLEGAL_STATE);
    } catch (...) {
        EXPECT_TRUE(false);
        GTEST_LOG_(INFO) << "SingleStoreImplMockTest-an exception occurred by DoSync_002";
    }
    GTEST_LOG_(INFO) << "SingleStoreImplMockTest-end DoSync_002";
}

/**
* @tc.name: SetConfig
* @tc.desc: set config.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SingleStoreImplMockTest, SetConfig, testing::ext::TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SingleStoreImplMockTest-begin SetConfig";
    try {
        std::shared_ptr<SingleStoreImpl> kv = CreateKVStore(false, false);
        ASSERT_NE(kv, nullptr);
        EXPECT_CALL(*kVDBServiceClientMock, GetInstance()).WillOnce(Return(nullptr));
        StoreConfig storeConfig;
        auto res = kv->SetConfig(storeConfig);
        EXPECT_TRUE(res == SERVER_UNAVAILABLE);
    } catch (...) {
        EXPECT_TRUE(false);
        GTEST_LOG_(INFO) << "SingleStoreImplMockTest-an exception occurred by SetConfig";
    }
    GTEST_LOG_(INFO) << "SingleStoreImplMockTest-end SetConfig";
}

/**
* @tc.name: DoNotifyChange
* @tc.desc: Do notify change.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SingleStoreImplMockTest, DoNotifyChange, testing::ext::TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SingleStoreImplMockTest-begin DoNotifyChange";
    try {
        std::shared_ptr<SingleStoreImpl> kv = CreateKVStore(false, false);
        ASSERT_NE(kv, nullptr);
        kv->cloudAutoSync_ = false;
        kv->DoNotifyChange();
        EXPECT_TRUE(!kv->cloudAutoSync_);
    } catch (...) {
        EXPECT_TRUE(false);
        GTEST_LOG_(INFO) << "SingleStoreImplMockTest-an exception occurred by DoNotifyChange";
    }
    GTEST_LOG_(INFO) << "SingleStoreImplMockTest-end DoNotifyChange";
}

/**
* @tc.name: IsRebuild
* @tc.desc: is rebuild.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SingleStoreImplMockTest, IsRebuild, testing::ext::TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SingleStoreImplMockTest-begin IsRebuild";
    try {
        std::shared_ptr<SingleStoreImpl> kv = CreateKVStore(false, false);
        ASSERT_NE(kv, nullptr);
        kv->dbStore_= nullptr;
        EXPECT_TRUE(kv->dbStore_ == nullptr);
        auto res = kv->IsRebuild();
        EXPECT_FALSE(res);
    } catch (...) {
        EXPECT_TRUE(false);
        GTEST_LOG_(INFO) << "SingleStoreImplMockTest-an exception occurred by IsRebuild";
    }
    GTEST_LOG_(INFO) << "SingleStoreImplMockTest-end IsRebuild";
}

/**
* @tc.name: WalCheckpointFieldDefault
* @tc.desc: Options.walStartCheckpointSize default value is 204800; field is assignable.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SingleStoreImplMockTest, WalCheckpointFieldDefault, testing::ext::TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SingleStoreImplMockTest-begin WalCheckpointFieldDefault";
    try {
        Options options;
        // Default value must be CHECKPOINT_THRESHOLD_DEFAULT_KB
        EXPECT_EQ(options.walStartCheckpointSize, CHECKPOINT_THRESHOLD_DEFAULT_KB);
        // Field is assignable
        options.walStartCheckpointSize = 8192;
        EXPECT_EQ(options.walStartCheckpointSize, 8192);
    } catch (...) {
        EXPECT_TRUE(false);
        GTEST_LOG_(INFO) << "SingleStoreImplMockTest-an exception occurred by WalCheckpointFieldDefault";
    }
    GTEST_LOG_(INFO) << "SingleStoreImplMockTest-end WalCheckpointFieldDefault";
}

/**
* @tc.name: WalCheckpointFallbackTooSmall
* @tc.desc: GetOrOpenStore with walStartCheckpointSize below MIN_KB (16) falls back to default; store created.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SingleStoreImplMockTest, WalCheckpointFallbackTooSmall, testing::ext::TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SingleStoreImplMockTest-begin WalCheckpointFallbackTooSmall";
    try {
        AppId testAppId = { "WalStartCheckpointSizeTest" };
        StoreId testStoreId = { "TooSmall" };
        Options options;
        options.kvStoreType = SINGLE_VERSION;
        options.securityLevel = S2;
        options.area = EL1;
        options.baseDir = "/data/service/el1/public/database/SingleStoreImplTest";
        options.walStartCheckpointSize = CHECKPOINT_THRESHOLD_MIN_KB - 1; // below MIN_KB
        Status status = SUCCESS;
        StoreParams storeParams;
        auto kvStore = storeFactory->GetOrOpenStore(testAppId, testStoreId, options, status, storeParams);
        EXPECT_EQ(status, SUCCESS);
        EXPECT_NE(kvStore, nullptr);
    } catch (...) {
        EXPECT_TRUE(false);
        GTEST_LOG_(INFO) << "SingleStoreImplMockTest-an exception occurred by WalCheckpointFallbackTooSmall";
    }
    GTEST_LOG_(INFO) << "SingleStoreImplMockTest-end WalCheckpointFallbackTooSmall";
}

/**
* @tc.name: WalCheckpointFallbackTooLarge
* @tc.desc: GetOrOpenStore with walStartCheckpointSize above MAX_KB (524288) falls back to default; store created.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SingleStoreImplMockTest, WalCheckpointFallbackTooLarge, testing::ext::TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SingleStoreImplMockTest-begin WalCheckpointFallbackTooLarge";
    try {
        AppId testAppId = { "WalStartCheckpointSizeTest" };
        StoreId testStoreId = { "TooLarge" };
        Options options;
        options.kvStoreType = SINGLE_VERSION;
        options.securityLevel = S2;
        options.area = EL1;
        options.baseDir = "/data/service/el1/public/database/SingleStoreImplTest";
        options.walStartCheckpointSize = CHECKPOINT_THRESHOLD_MAX_KB + 1; // above MAX_KB
        Status status = SUCCESS;
        StoreParams storeParams;
        auto kvStore = storeFactory->GetOrOpenStore(testAppId, testStoreId, options, status, storeParams);
        EXPECT_EQ(status, SUCCESS);
        EXPECT_NE(kvStore, nullptr);
    } catch (...) {
        EXPECT_TRUE(false);
        GTEST_LOG_(INFO) << "SingleStoreImplMockTest-an exception occurred by WalCheckpointFallbackTooLarge";
    }
    GTEST_LOG_(INFO) << "SingleStoreImplMockTest-end WalCheckpointFallbackTooLarge";
}

/**
* @tc.name: SetDbConfigAppliesConfiguredThreshold
* @tc.desc: GetOrOpenStore with valid walStartCheckpointSize returns SUCCESS
*           (SetDbConfig applies configured value via Pragma).
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SingleStoreImplMockTest, SetDbConfigAppliesConfiguredThreshold, testing::ext::TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SingleStoreImplMockTest-begin SetDbConfigAppliesConfiguredThreshold";
    try {
        AppId testAppId = { "WalStartCheckpointSizeTest" };
        StoreId testStoreId = { "ValidThreshold" };
        Options options;
        options.kvStoreType = SINGLE_VERSION;
        options.securityLevel = S2;
        options.area = EL1;
        options.baseDir = "/data/service/el1/public/database/SingleStoreImplTest";
        options.walStartCheckpointSize = 8192; // 8192 KB, within [16, 524288]
        Status status = INVALID_ARGUMENT;
        StoreParams storeParams;
        auto kvStore = storeFactory->GetOrOpenStore(testAppId, testStoreId, options, status, storeParams);
        EXPECT_EQ(status, SUCCESS);
        EXPECT_NE(kvStore, nullptr);
    } catch (...) {
        EXPECT_TRUE(false);
        GTEST_LOG_(INFO) << "SingleStoreImplMockTest-an exception occurred by SetDbConfigAppliesConfiguredThreshold";
    }
    GTEST_LOG_(INFO) << "SingleStoreImplMockTest-end SetDbConfigAppliesConfiguredThreshold";
}

/**
* @tc.name: WalCheckpointDefaultWhenNotSet
* @tc.desc: GetOrOpenStore with default walStartCheckpointSize (204800 KB) returns SUCCESS.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SingleStoreImplMockTest, WalCheckpointDefaultWhenNotSet, testing::ext::TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SingleStoreImplMockTest-begin WalCheckpointDefaultWhenNotSet";
    try {
        AppId testAppId = { "WalStartCheckpointSizeTest" };
        StoreId testStoreId = { "DefaultThreshold" };
        Options options;
        options.kvStoreType = SINGLE_VERSION;
        options.securityLevel = S2;
        options.area = EL1;
        options.baseDir = "/data/service/el1/public/database/SingleStoreImplTest";
        // walStartCheckpointSize not set; uses default CHECKPOINT_THRESHOLD_DEFAULT_KB
        EXPECT_EQ(options.walStartCheckpointSize, CHECKPOINT_THRESHOLD_DEFAULT_KB);
        Status status = INVALID_ARGUMENT;
        StoreParams storeParams;
        auto kvStore = storeFactory->GetOrOpenStore(testAppId, testStoreId, options, status, storeParams);
        EXPECT_EQ(status, SUCCESS);
        EXPECT_NE(kvStore, nullptr);
    } catch (...) {
        EXPECT_TRUE(false);
        GTEST_LOG_(INFO) << "SingleStoreImplMockTest-an exception occurred by WalCheckpointDefaultWhenNotSet";
    }
    GTEST_LOG_(INFO) << "SingleStoreImplMockTest-end WalCheckpointDefaultWhenNotSet";
}

/**
* @tc.name: GetOrOpenStoreAcceptsMinBoundary
* @tc.desc: GetOrOpenStore accepts walStartCheckpointSize == MIN_KB (16) boundary; returns SUCCESS.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SingleStoreImplMockTest, GetOrOpenStoreAcceptsMinBoundary, testing::ext::TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SingleStoreImplMockTest-begin GetOrOpenStoreAcceptsMinBoundary";
    try {
        AppId testAppId = { "WalStartCheckpointSizeTest" };
        StoreId testStoreId = { "MinBoundary" };
        Options options;
        options.kvStoreType = SINGLE_VERSION;
        options.securityLevel = S2;
        options.area = EL1;
        options.baseDir = "/data/service/el1/public/database/SingleStoreImplTest";
        options.walStartCheckpointSize = CHECKPOINT_THRESHOLD_MIN_KB; // MIN_KB boundary
        Status status = INVALID_ARGUMENT;
        StoreParams storeParams;
        auto kvStore = storeFactory->GetOrOpenStore(testAppId, testStoreId, options, status, storeParams);
        EXPECT_EQ(status, SUCCESS);
        EXPECT_NE(kvStore, nullptr);
    } catch (...) {
        EXPECT_TRUE(false);
        GTEST_LOG_(INFO) << "SingleStoreImplMockTest-an exception occurred by GetOrOpenStoreAcceptsMinBoundary";
    }
    GTEST_LOG_(INFO) << "SingleStoreImplMockTest-end GetOrOpenStoreAcceptsMinBoundary";
}

/**
* @tc.name: GetOrOpenStoreAcceptsMaxBoundary
* @tc.desc: GetOrOpenStore accepts walStartCheckpointSize == MAX_KB (524288) boundary; returns SUCCESS.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SingleStoreImplMockTest, GetOrOpenStoreAcceptsMaxBoundary, testing::ext::TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SingleStoreImplMockTest-begin GetOrOpenStoreAcceptsMaxBoundary";
    try {
        AppId testAppId = { "WalStartCheckpointSizeTest" };
        StoreId testStoreId = { "MaxBoundary" };
        Options options;
        options.kvStoreType = SINGLE_VERSION;
        options.securityLevel = S2;
        options.area = EL1;
        options.baseDir = "/data/service/el1/public/database/SingleStoreImplTest";
        options.walStartCheckpointSize = CHECKPOINT_THRESHOLD_MAX_KB; // MAX_KB boundary
        Status status = INVALID_ARGUMENT;
        StoreParams storeParams;
        auto kvStore = storeFactory->GetOrOpenStore(testAppId, testStoreId, options, status, storeParams);
        EXPECT_EQ(status, SUCCESS);
        EXPECT_NE(kvStore, nullptr);
    } catch (...) {
        EXPECT_TRUE(false);
        GTEST_LOG_(INFO) << "SingleStoreImplMockTest-an exception occurred by GetOrOpenStoreAcceptsMaxBoundary";
    }
    GTEST_LOG_(INFO) << "SingleStoreImplMockTest-end GetOrOpenStoreAcceptsMaxBoundary";
}

/**
* @tc.name: SetDbConfigReturnsErrorWhenPragmaFails
* @tc.desc: SetDbConfig returns non-SUCCESS when Pragma(SET_MAX_LOG_LIMIT) fails (B4 branch coverage).
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SingleStoreImplMockTest, SetDbConfigReturnsErrorWhenPragmaFails, testing::ext::TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SingleStoreImplMockTest-begin SetDbConfigReturnsErrorWhenPragmaFails";
    try {
        // FakeKvStoreNbDelegate: Pragma returns NOT_SUPPORT to trigger B4 (ZLOGE error path).
        auto fakeStore = std::make_shared<FakeKvStoreNbDelegate>();
        fakeStore->pragmaResult_ = DBStatus::NOT_SUPPORT;

        Options options;
        options.kvStoreType = SINGLE_VERSION;
        options.securityLevel = S2;
        options.area = EL1;
        options.baseDir = "/data/service/el1/public/database/SingleStoreImplTest";
        options.walStartCheckpointSize = 8192; // SetDbConfig calls Pragma(SET_MAX_LOG_LIMIT)

        // SetDbConfig is private; tests access it via the same mechanism as CreateKVStore (line 131).
        auto status = storeFactory->SetDbConfig(fakeStore, options.walStartCheckpointSize);
        EXPECT_NE(status, SUCCESS); // B4: Pragma failed → ZLOGE + ConvertStatus returns error
    } catch (...) {
        EXPECT_TRUE(false);
        GTEST_LOG_(INFO) << "SingleStoreImplMockTest-an exception occurred by SetDbConfigReturnsErrorWhenPragmaFails";
    }
    GTEST_LOG_(INFO) << "SingleStoreImplMockTest-end SetDbConfigReturnsErrorWhenPragmaFails";
}

HWTEST_F(SingleStoreImplMockTest, SetShrinkEnableAsyncAndDedupe, testing::ext::TestSize.Level1)
{
    auto delegate = std::make_shared<ShrinkMockDelegate>();
    Convertor convertor;
    auto store = CreateShrinkStore(delegate, convertor);
    ASSERT_NE(store, nullptr);
    delegate->BlockSet();
    ASSERT_EQ(store->SetShrinkEnable(true), SUCCESS);
    ASSERT_TRUE(delegate->WaitSetCalls(1));
    ASSERT_EQ(store->SetShrinkEnable(true), SUCCESS);
    auto dedupeState = GetShrinkState(store);
    EXPECT_EQ(dedupeState.pending, 1u);
    EXPECT_EQ(delegate->setCalls_.load(), 1);
    delegate->ReleaseSet();
    ASSERT_TRUE(delegate->WaitActual(true));
    ASSERT_TRUE(WaitShrinkState(store, true, 0));
    EXPECT_EQ(delegate->setCalls_.load(), 1);
    ASSERT_EQ(store->SetShrinkEnable(false), SUCCESS);
    ASSERT_TRUE(delegate->WaitSetCalls(2));
    ASSERT_TRUE(delegate->WaitActual(false));
    ASSERT_TRUE(WaitShrinkState(store, false, 0));
    ASSERT_EQ(store->SetShrinkEnable(false), SUCCESS);
    ASSERT_TRUE(delegate->WaitSetCalls(3));
    ASSERT_TRUE(WaitShrinkState(store, false, 0));
    EXPECT_EQ(store->Close(true), 0);
}

HWTEST_F(SingleStoreImplMockTest, ShrinkFailureStatuses, testing::ext::TestSize.Level1)
{
    auto delegate = std::make_shared<ShrinkMockDelegate>();
    Convertor convertor;
    auto store = CreateShrinkStore(delegate, convertor);
    ASSERT_NE(store, nullptr);
    const std::vector<DBStatus> statuses = { DBStatus::BUSY, DBStatus::TIME_OUT, DBStatus::NOT_SUPPORT,
        DBStatus::DB_ERROR };
    for (size_t index = 0; index < statuses.size(); ++index) {
        delegate->SetNextStatus(statuses[index]);
        ASSERT_EQ(store->SetShrinkEnable(true), SUCCESS);
        ASSERT_TRUE(delegate->WaitSetCalls(static_cast<int>(index) + 1));
        ASSERT_TRUE(WaitShrinkState(store, true, 0));
        EXPECT_FALSE(delegate->actual_.load());
    }
    EXPECT_EQ(store->Close(true), 0);
}

HWTEST_F(SingleStoreImplMockTest, DisableSkipsNotStartedTask, testing::ext::TestSize.Level1)
{
    auto blockerDelegate = std::make_shared<ShrinkMockDelegate>();
    auto targetDelegate = std::make_shared<ShrinkMockDelegate>();
    Convertor convertor;
    auto blocker = CreateShrinkStore(blockerDelegate, convertor);
    auto target = CreateShrinkStore(targetDelegate, convertor);
    ASSERT_NE(blocker, nullptr);
    ASSERT_NE(target, nullptr);
    struct UnblockGuard {
        explicit UnblockGuard(ShrinkMockDelegate &setDelegate) : delegate(setDelegate) {}
        ~UnblockGuard() { delegate.ReleaseSet(); }
        ShrinkMockDelegate &delegate;
    } guard(*blockerDelegate);
    blockerDelegate->BlockSet();
    ASSERT_EQ(blocker->SetShrinkEnable(true), SUCCESS);
    ASSERT_TRUE(blockerDelegate->WaitSetCalls(1));
    ASSERT_EQ(target->SetShrinkEnable(true), SUCCESS);
    ASSERT_EQ(target->SetShrinkEnable(false), SUCCESS);
    blockerDelegate->ReleaseSet();
    ASSERT_TRUE(blockerDelegate->WaitActual(true));
    ASSERT_TRUE(WaitShrinkState(target, false, 0));
    EXPECT_EQ(targetDelegate->setCalls_.load(), 1);
    EXPECT_FALSE(targetDelegate->actual_.load());
    EXPECT_EQ(blocker->Close(true), 0);
    EXPECT_EQ(target->Close(true), 0);
}

HWTEST_F(SingleStoreImplMockTest, NoEngineProbeOnOpen, testing::ext::TestSize.Level1)
{
    auto delegate = std::make_shared<ShrinkMockDelegate>();
    Convertor convertor;
    auto store = CreateShrinkStore(delegate, convertor);
    ASSERT_NE(store, nullptr);
    EXPECT_EQ(delegate->pageSizeCalls_.load(), 0);
    EXPECT_EQ(store->SetShrinkEnable(true), SUCCESS);
    ASSERT_TRUE(delegate->WaitSetCalls(1));
    ASSERT_TRUE(WaitShrinkState(store, true, 0));
    EXPECT_EQ(delegate->pageSizeCalls_.load(), 0);
    EXPECT_EQ(store->Close(true), 0);
}

HWTEST_F(SingleStoreImplMockTest, IsPublicLocalOnlyNotSupported, testing::ext::TestSize.Level1)
{
    auto delegate = std::make_shared<ShrinkMockDelegate>();
    Convertor convertor;
    auto store = CreateShrinkStore(delegate, convertor, KvStoreType::LOCAL_ONLY, true);
    ASSERT_NE(store, nullptr);
    EXPECT_EQ(store->SetShrinkEnable(true), NOT_SUPPORT);
    EXPECT_EQ(store->SetShrinkEnable(false), SUCCESS);
    EXPECT_EQ(delegate->setCalls_.load(), 0);
    EXPECT_EQ(delegate->pageSizeCalls_.load(), 0);
    auto state = GetShrinkState(store);
    EXPECT_FALSE(state.desired);
    EXPECT_EQ(state.pending, 0u);
    EXPECT_EQ(store->Close(true), 0);
}

HWTEST_F(SingleStoreImplMockTest, LocalOnlyFallbackAccepted, testing::ext::TestSize.Level1)
{
    auto delegate = std::make_shared<ShrinkMockDelegate>();
    delegate->SetNextStatus(DBStatus::NOT_SUPPORT);
    Convertor convertor;
    auto store = CreateShrinkStore(delegate, convertor);
    ASSERT_NE(store, nullptr);
    EXPECT_EQ(store->SetShrinkEnable(true), SUCCESS);
    ASSERT_TRUE(delegate->WaitSetCalls(1));
    ASSERT_TRUE(WaitShrinkState(store, true, 0));
    EXPECT_FALSE(delegate->actual_.load());
    EXPECT_EQ(store->Close(true), 0);
}

HWTEST_F(SingleStoreImplMockTest, NonLocalOnlyTypesNotSupported, testing::ext::TestSize.Level1)
{
    const std::vector<KvStoreType> types = { KvStoreType::SINGLE_VERSION, KvStoreType::DEVICE_COLLABORATION };
    for (auto type : types) {
        auto delegate = std::make_shared<ShrinkMockDelegate>();
        Convertor convertor;
        auto store = CreateShrinkStore(delegate, convertor, type);
        ASSERT_NE(store, nullptr);
        EXPECT_EQ(store->SetShrinkEnable(true), NOT_SUPPORT);
        EXPECT_EQ(store->SetShrinkEnable(false), SUCCESS);
        EXPECT_EQ(delegate->setCalls_.load(), 0);
        EXPECT_EQ(delegate->pageSizeCalls_.load(), 0);
        auto state = GetShrinkState(store);
        EXPECT_FALSE(state.desired);
        EXPECT_EQ(state.pending, 0u);
        EXPECT_EQ(store->Close(true), 0);
    }
}

HWTEST_F(SingleStoreImplMockTest, DefaultSetShrinkEnableContract, testing::ext::TestSize.Level1)
{
    DefaultShrinkKvStoreFake store;
    EXPECT_EQ(store.SetShrinkEnable(true), NOT_SUPPORT);
    EXPECT_EQ(store.SetShrinkEnable(false), SUCCESS);
}
} // namespace OHOS::DistributedKv
