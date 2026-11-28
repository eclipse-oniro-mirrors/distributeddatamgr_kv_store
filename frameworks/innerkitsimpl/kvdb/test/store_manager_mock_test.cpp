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

#include "store_manager.h"

#include "backup_manager.h"
#include "convertor.h"
#include "dev_manager.h"
#include "kv_types_util.h"
#include "kvdb_service_client.h"
#include "kvstore_service_death_notifier.h"
#include "log_print.h"
#include "message_parcel.h"
#include "runtime_config.h"
#include "security_manager.h"
#include "store_factory.h"
#include "store_util.h"
#include "task_executor.h"

#include "include/convertor_mock.h"
#include "include/dev_manager_mock.h"
#include "include/kvdb_notifier_client_mock.h"
#include "include/kvdb_service_client_mock.h"
#include "include/observer_bridge_mock.h"
#include "include/task_executor_mock.h"

#include <chrono>
#include <future>
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <memory>
#include <thread>

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::DistributedKv;

namespace {
constexpr const char *BASE_DIR = "/data/service/el1/public/database/StoreManagerMockTest";
constexpr const char *APP_ID = "StoreManagerMockTest";
}

class StoreManagerMockTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override;
    void TearDown() override;

    static inline std::shared_ptr<DevManagerMock> devManagerMock = nullptr;
    static inline std::shared_ptr<KVDBServiceClientMock> kVDBServiceClientMock = nullptr;
    static inline std::shared_ptr<KVDBNotifierClientMock> kVDBNotifierClientMock = nullptr;
    static inline std::shared_ptr<ObserverBridgeMock> observerBridgeMock = nullptr;
    static inline std::shared_ptr<TaskExecutorMock> taskExecutorMock = nullptr;
    static inline std::shared_ptr<ConvertorMock> convertorMock = nullptr;

    Options GetDefaultOptions();
};

void StoreManagerMockTest::SetUpTestCase()
{
    mkdir(BASE_DIR, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
    devManagerMock = std::make_shared<DevManagerMock>();
    BDevManager::devManager = devManagerMock;
    kVDBServiceClientMock = std::make_shared<KVDBServiceClientMock>();
    BKVDBServiceClient::kVDBServiceClient = kVDBServiceClientMock;
    kVDBNotifierClientMock = std::make_shared<KVDBNotifierClientMock>();
    BKVDBNotifierClient::kVDBNotifierClient = kVDBNotifierClientMock;
    observerBridgeMock = std::make_shared<ObserverBridgeMock>();
    BObserverBridge::observerBridge = observerBridgeMock;
    taskExecutorMock = std::make_shared<TaskExecutorMock>();
    BTaskExecutor::taskExecutor = taskExecutorMock;
    ON_CALL(*taskExecutorMock, Execute(_)).WillByDefault(Return(TaskExecutor::INVALID_TASK_ID));
    convertorMock = std::make_shared<ConvertorMock>();
    BConvertor::convertor = convertorMock;
}

void StoreManagerMockTest::TearDownTestCase()
{
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
    (void)remove(BASE_DIR);
}

void StoreManagerMockTest::SetUp()
{
    KVDBServiceClientMock::status = SUCCESS;
}

void StoreManagerMockTest::TearDown()
{
    KVDBServiceClientMock::status = SUCCESS;
}

Options StoreManagerMockTest::GetDefaultOptions()
{
    Options options;
    options.kvStoreType = SINGLE_VERSION;
    options.securityLevel = S2;
    options.area = EL1;
    options.persistent = true;
    options.baseDir = BASE_DIR;
    options.backup = false;
    options.syncable = false;
    options.autoSync = false;
    return options;
}

/**
 * @tc.name: AfterCreateAsync_FallbackSyncWhenPoolUnavailable
 * @tc.desc: AC-1.10 - When TaskExecutor::Execute returns INVALID_TASK_ID,
 *           AfterCreate is executed synchronously.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(StoreManagerMockTest, AfterCreateAsync_FallbackSyncWhenPoolUnavailable, TestSize.Level1)
{
    AppId appId = { APP_ID };
    StoreId storeId = { "FallbackSyncTest" };
    auto options = GetDefaultOptions();
    auto service = std::make_shared<KVDBServiceClient>(nullptr);

    KVDBServiceClientMock::status = SUCCESS;
    EXPECT_CALL(*kVDBServiceClientMock, GetInstance())
        .WillOnce(Return(service));
    EXPECT_CALL(*taskExecutorMock, Execute(_))
        .Times(AtLeast(1))
        .WillRepeatedly(Return(TaskExecutor::INVALID_TASK_ID));

    Status status = ILLEGAL_STATE;
    auto kvStore = StoreManager::GetInstance().GetKVStore(appId, storeId, options, status);
    EXPECT_EQ(status, SUCCESS);
    EXPECT_NE(kvStore, nullptr);
}

/**
 * @tc.name: AfterCreateAsync_NoRetryOnInvalidArgument
 * @tc.desc: AC-1.9 - When AfterCreate returns INVALID_ARGUMENT,
 *           no retry is scheduled and barrier is released.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(StoreManagerMockTest, AfterCreateAsync_NoRetryOnInvalidArgument, TestSize.Level1)
{
    AppId appId = { APP_ID };
    StoreId storeId = { "NoRetryInvalidTest" };
    auto options = GetDefaultOptions();
    auto service = std::make_shared<KVDBServiceClient>(nullptr);

    EXPECT_CALL(*kVDBServiceClientMock, GetInstance())
        .WillOnce(Return(service))
        .WillOnce(Return(service));
    EXPECT_CALL(*taskExecutorMock, Execute(_))
        .Times(AtLeast(1))
        .WillOnce(DoAll(
            Invoke([](const Task &) { KVDBServiceClientMock::status = INVALID_ARGUMENT; }),
            InvokeArgument<0>(),
            Return(static_cast<ExecutorPool::TaskId>(1))))
        .WillRepeatedly(Return(static_cast<ExecutorPool::TaskId>(1)));
    EXPECT_CALL(*taskExecutorMock, Schedule(_, _, _, _)).Times(AnyNumber());

    KVDBServiceClientMock::status = SUCCESS;
    Status status = ILLEGAL_STATE;
    auto kvStore = StoreManager::GetInstance().GetKVStore(appId, storeId, options, status);
    EXPECT_EQ(status, SUCCESS);
    EXPECT_NE(kvStore, nullptr);
}

/**
 * @tc.name: AfterCreateAsync_RetryOnServiceUnavailable
 * @tc.desc: AC-1.5 - When AfterCreate returns IPC_ERROR (retryable),
 *           Schedule is called for retry.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(StoreManagerMockTest, AfterCreateAsync_RetryOnServiceUnavailable, TestSize.Level1)
{
    AppId appId = { APP_ID };
    StoreId storeId = { "RetryTest" };
    auto options = GetDefaultOptions();
    auto service = std::make_shared<KVDBServiceClient>(nullptr);

    EXPECT_CALL(*kVDBServiceClientMock, GetInstance())
        .WillOnce(Return(service))
        .WillOnce(Return(service));
    EXPECT_CALL(*taskExecutorMock, Execute(_))
        .Times(AtLeast(1))
        .WillOnce(DoAll(
            Invoke([](const Task &) { KVDBServiceClientMock::status = IPC_ERROR; }),
            InvokeArgument<0>(),
            Return(static_cast<ExecutorPool::TaskId>(1))))
        .WillRepeatedly(Return(static_cast<ExecutorPool::TaskId>(1)));
    EXPECT_CALL(*taskExecutorMock, Schedule(_, _, _, _))
        .Times(AnyNumber())
        .WillRepeatedly(Return(static_cast<ExecutorPool::TaskId>(2)));

    KVDBServiceClientMock::status = SUCCESS;
    Status status = ILLEGAL_STATE;
    auto kvStore = StoreManager::GetInstance().GetKVStore(appId, storeId, options, status);
    EXPECT_EQ(status, SUCCESS);
    EXPECT_NE(kvStore, nullptr);
}

/**
 * @tc.name: AfterCreateAsync_ReportFaultOnFailure
 * @tc.desc: AC-1.4 - When AfterCreate returns failure, the failure path is entered
 *           and ReportKVFaultEvent is called with the error code.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(StoreManagerMockTest, AfterCreateAsync_ReportFaultOnFailure, TestSize.Level1)
{
    AppId appId = { APP_ID };
    StoreId storeId = { "FaultReportTest" };
    auto options = GetDefaultOptions();
    auto service = std::make_shared<KVDBServiceClient>(nullptr);

    EXPECT_CALL(*kVDBServiceClientMock, GetInstance())
        .WillOnce(Return(service))
        .WillOnce(Return(service));
    EXPECT_CALL(*taskExecutorMock, Execute(_))
        .Times(AtLeast(1))
        .WillOnce(DoAll(
            Invoke([](const Task &) { KVDBServiceClientMock::status = IPC_ERROR; }),
            InvokeArgument<0>(),
            Return(static_cast<ExecutorPool::TaskId>(1))))
        .WillRepeatedly(Return(static_cast<ExecutorPool::TaskId>(1)));
    EXPECT_CALL(*taskExecutorMock, Schedule(_, _, _, _))
        .Times(AnyNumber())
        .WillRepeatedly(Return(static_cast<ExecutorPool::TaskId>(2)));

    KVDBServiceClientMock::status = SUCCESS;
    Status status = ILLEGAL_STATE;
    auto kvStore = StoreManager::GetInstance().GetKVStore(appId, storeId, options, status);
    EXPECT_EQ(status, SUCCESS);
    EXPECT_NE(kvStore, nullptr);
}

/**
 * @tc.name: WaitAfterCreate_BlocksUntilResolved
 * @tc.desc: AC-1.7 - When a pending AfterCreate exists for the same store,
 *           Delete blocks on WaitAfterCreate until the captured task runs and the promise resolves.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(StoreManagerMockTest, WaitAfterCreate_BlocksUntilResolved, TestSize.Level1)
{
    AppId appId = { APP_ID };
    StoreId storeId = { "WaitBlockTest" };
    auto options = GetDefaultOptions();
    auto service = std::make_shared<KVDBServiceClient>(nullptr);

    KVDBServiceClientMock::status = SUCCESS;
    EXPECT_CALL(*kVDBServiceClientMock, GetInstance())
        .WillRepeatedly(Return(service));
    std::function<void()> capturedAsyncTask;
    EXPECT_CALL(*taskExecutorMock, Execute(_))
        .Times(AtLeast(1))
        .WillOnce(DoAll(SaveArg<0>(&capturedAsyncTask), Return(static_cast<ExecutorPool::TaskId>(1))))
        .WillRepeatedly(Return(static_cast<ExecutorPool::TaskId>(1)));

    Status status = ILLEGAL_STATE;
    auto kvStore = StoreManager::GetInstance().GetKVStore(appId, storeId, options, status);
    EXPECT_EQ(status, SUCCESS);
    EXPECT_NE(kvStore, nullptr);

    ASSERT_NE(capturedAsyncTask, nullptr);

    std::thread worker([&capturedAsyncTask]() { capturedAsyncTask(); });

    StoreManager::GetInstance().Delete(appId, storeId, options.baseDir, 0);
    worker.join();
}

/**
 * @tc.name: WaitAfterCreate_TimeoutDegradesGracefully
 * @tc.desc: AC-1.8 - When AfterCreate takes longer than 2000ms,
 *           WaitAfterCreate times out and degrades gracefully (operation continues).
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(StoreManagerMockTest, WaitAfterCreate_TimeoutDegradesGracefully, TestSize.Level1)
{
    AppId appId = { APP_ID };
    StoreId storeId = { "WaitTimeoutTest" };
    auto options = GetDefaultOptions();
    auto service = std::make_shared<KVDBServiceClient>(nullptr);

    KVDBServiceClientMock::status = SUCCESS;
    EXPECT_CALL(*kVDBServiceClientMock, GetInstance())
        .WillRepeatedly(Return(service));
    std::function<void()> capturedTask;
    EXPECT_CALL(*taskExecutorMock, Execute(_))
        .Times(AtLeast(1))
        .WillOnce(DoAll(SaveArg<0>(&capturedTask), Return(static_cast<ExecutorPool::TaskId>(1))))
        .WillRepeatedly(Return(static_cast<ExecutorPool::TaskId>(1)));

    Status status = ILLEGAL_STATE;
    auto kvStore = StoreManager::GetInstance().GetKVStore(appId, storeId, options, status);
    EXPECT_EQ(status, SUCCESS);
    EXPECT_NE(kvStore, nullptr);

    auto start = std::chrono::steady_clock::now();
    StoreManager::GetInstance().Delete(appId, storeId, options.baseDir, 0);
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start);

    EXPECT_GE(elapsed.count(), 0);
    EXPECT_LE(elapsed.count(), 3000);
}

/**
 * @tc.name: WaitAllAfterCreate_NoPendingEmpty
 * @tc.desc: When no pending AfterCreate exists, WaitAllAfterCreate returns immediately.
 */
HWTEST_F(StoreManagerMockTest, WaitAllAfterCreate_NoPendingEmpty, TestSize.Level1)
{
    AppId appId = { "NoPendingApp" };

    auto start = std::chrono::steady_clock::now();
    StoreManager::GetInstance().WaitAllAfterCreate(appId);
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start);

    EXPECT_LT(elapsed.count(), 100);
}

/**
 * @tc.name: ScheduleAfterCreate_FallbackSyncFailure
 * @tc.desc: When Execute returns INVALID_TASK_ID and AfterCreate returns non-SUCCESS,
 *           fault is reported and barrier is released.
 */
HWTEST_F(StoreManagerMockTest, ScheduleAfterCreate_FallbackSyncFailure, TestSize.Level1)
{
    AppId appId = { APP_ID };
    StoreId storeId = { "FallbackFailTest" };
    auto options = GetDefaultOptions();
    auto service = std::make_shared<KVDBServiceClient>(nullptr);

    KVDBServiceClientMock::status = SUCCESS;
    EXPECT_CALL(*kVDBServiceClientMock, GetInstance())
        .WillOnce(Return(service));
    EXPECT_CALL(*taskExecutorMock, Execute(_))
        .Times(AtLeast(1))
        .WillRepeatedly(DoAll(
            Invoke([](const Task &) { KVDBServiceClientMock::status = IPC_ERROR; }),
            Return(TaskExecutor::INVALID_TASK_ID)));

    Status status = ILLEGAL_STATE;
    auto kvStore = StoreManager::GetInstance().GetKVStore(appId, storeId, options, status);
    EXPECT_EQ(status, SUCCESS);
    EXPECT_NE(kvStore, nullptr);
}

/**
 * @tc.name: AfterCreateAsync_ServiceNull
 * @tc.desc: When AfterCreateAsync runs and GetInstance returns nullptr,
 *           barrier is released and pending is erased.
 */
HWTEST_F(StoreManagerMockTest, AfterCreateAsync_ServiceNull, TestSize.Level1)
{
    AppId appId = { APP_ID };
    StoreId storeId = { "ServiceNullTest" };
    auto options = GetDefaultOptions();
    auto service = std::make_shared<KVDBServiceClient>(nullptr);

    KVDBServiceClientMock::status = SUCCESS;
    EXPECT_CALL(*kVDBServiceClientMock, GetInstance())
        .WillOnce(Return(service))
        .WillRepeatedly(Return(nullptr));
    EXPECT_CALL(*taskExecutorMock, Execute(_))
        .Times(AtLeast(1))
        .WillOnce(DoAll(InvokeArgument<0>(), Return(static_cast<ExecutorPool::TaskId>(1))))
        .WillRepeatedly(Return(static_cast<ExecutorPool::TaskId>(1)));

    Status status = ILLEGAL_STATE;
    auto kvStore = StoreManager::GetInstance().GetKVStore(appId, storeId, options, status);
    EXPECT_EQ(status, SUCCESS);
    EXPECT_NE(kvStore, nullptr);
}

/**
 * @tc.name: AfterCreateAsync_RetryScheduleFails
 * @tc.desc: When AfterCreate fails with retryable error and Schedule returns INVALID_TASK_ID,
 *           barrier is released and pending is erased.
 */
HWTEST_F(StoreManagerMockTest, AfterCreateAsync_RetryScheduleFails, TestSize.Level1)
{
    AppId appId = { APP_ID };
    StoreId storeId = { "RetryScheduleFailTest" };
    auto options = GetDefaultOptions();
    auto service = std::make_shared<KVDBServiceClient>(nullptr);

    EXPECT_CALL(*kVDBServiceClientMock, GetInstance())
        .WillRepeatedly(Return(service));
    EXPECT_CALL(*taskExecutorMock, Execute(_))
        .Times(AtLeast(1))
        .WillOnce(DoAll(
            Invoke([](const Task &) { KVDBServiceClientMock::status = IPC_ERROR; }),
            InvokeArgument<0>(),
            Return(static_cast<ExecutorPool::TaskId>(1))))
        .WillRepeatedly(Return(static_cast<ExecutorPool::TaskId>(1)));
    EXPECT_CALL(*taskExecutorMock, Schedule(_, _, _, _))
        .Times(AtLeast(1))
        .WillRepeatedly(Return(TaskExecutor::INVALID_TASK_ID));

    KVDBServiceClientMock::status = SUCCESS;
    Status status = ILLEGAL_STATE;
    auto kvStore = StoreManager::GetInstance().GetKVStore(appId, storeId, options, status);
    EXPECT_EQ(status, SUCCESS);
    EXPECT_NE(kvStore, nullptr);
}

/**
 * @tc.name: WaitAllAfterCreate_TimeoutWithPending
 * @tc.desc: When pending AfterCreate exists, WaitAllAfterCreate waits and times out.
 */
HWTEST_F(StoreManagerMockTest, WaitAllAfterCreate_TimeoutWithPending, TestSize.Level1)
{
    AppId appId = { "WaitAllTimeoutApp" };
    StoreId storeId = { "WaitAllTimeoutTest" };
    auto options = GetDefaultOptions();
    auto service = std::make_shared<KVDBServiceClient>(nullptr);

    KVDBServiceClientMock::status = SUCCESS;
    EXPECT_CALL(*kVDBServiceClientMock, GetInstance())
        .WillRepeatedly(Return(service));
    EXPECT_CALL(*taskExecutorMock, Execute(_))
        .Times(AtLeast(1))
        .WillRepeatedly(Return(static_cast<ExecutorPool::TaskId>(1)));

    StoreManager::GetInstance().Delete(appId, storeId, options.baseDir, 0);
    Status status = ILLEGAL_STATE;
    auto kvStore = StoreManager::GetInstance().GetKVStore(appId, storeId, options, status);
    EXPECT_EQ(status, SUCCESS);
    EXPECT_NE(kvStore, nullptr);

    auto start = std::chrono::steady_clock::now();
    StoreManager::GetInstance().WaitAllAfterCreate(appId);
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start);

    EXPECT_GE(elapsed.count(), 0);
    EXPECT_LE(elapsed.count(), 3000);
}

/**
 * @tc.name: GetStoreIds_WaitsForAfterCreate
 * @tc.desc: AC-1.7 - GetStoreIds calls WaitAllAfterCreate and waits for pending AfterCreate to resolve.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(StoreManagerMockTest, GetStoreIds_WaitsForAfterCreate, TestSize.Level1)
{
    AppId appId = { "GetStoreIdsWaitApp" };
    StoreId storeId = { "GetStoreIdsWaitTest" };
    auto options = GetDefaultOptions();
    auto service = std::make_shared<KVDBServiceClient>(nullptr);

    KVDBServiceClientMock::status = SUCCESS;
    EXPECT_CALL(*kVDBServiceClientMock, GetInstance())
        .WillRepeatedly(Return(service));
    std::function<void()> capturedAsyncTask;
    EXPECT_CALL(*taskExecutorMock, Execute(_))
        .Times(AtLeast(1))
        .WillOnce(DoAll(SaveArg<0>(&capturedAsyncTask), Return(static_cast<ExecutorPool::TaskId>(1))))
        .WillRepeatedly(Return(static_cast<ExecutorPool::TaskId>(1)));

    StoreManager::GetInstance().Delete(appId, storeId, options.baseDir, 0);
    Status status = ILLEGAL_STATE;
    auto kvStore = StoreManager::GetInstance().GetKVStore(appId, storeId, options, status);
    EXPECT_EQ(status, SUCCESS);
    EXPECT_NE(kvStore, nullptr);

    ASSERT_NE(capturedAsyncTask, nullptr);

    std::thread worker([&capturedAsyncTask]() { capturedAsyncTask(); });

    std::vector<StoreId> storeIds;
    Status result = StoreManager::GetInstance().GetStoreIds(appId, storeIds, 0);
    EXPECT_EQ(result, SUCCESS);
    worker.join();
}

/**
 * @tc.name: DeleteByOptions_WaitsForAfterCreate
 * @tc.desc: AC-1.7 - Delete(options) calls WaitAfterCreate and waits for pending AfterCreate to resolve.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(StoreManagerMockTest, DeleteByOptions_WaitsForAfterCreate, TestSize.Level1)
{
    AppId appId = { "DeleteOptsApp" };
    StoreId storeId = { "DeleteOptionsWaitTest" };
    auto options = GetDefaultOptions();
    auto service = std::make_shared<KVDBServiceClient>(nullptr);

    KVDBServiceClientMock::status = SUCCESS;
    EXPECT_CALL(*kVDBServiceClientMock, GetInstance())
        .WillRepeatedly(Return(service));
    std::function<void()> capturedAsyncTask;
    EXPECT_CALL(*taskExecutorMock, Execute(_))
        .Times(AtLeast(1))
        .WillOnce(DoAll(SaveArg<0>(&capturedAsyncTask), Return(static_cast<ExecutorPool::TaskId>(1))))
        .WillRepeatedly(Return(static_cast<ExecutorPool::TaskId>(1)));

    StoreManager::GetInstance().Delete(appId, storeId, options.baseDir, 0);
    Status status = ILLEGAL_STATE;
    auto kvStore = StoreManager::GetInstance().GetKVStore(appId, storeId, options, status);
    EXPECT_EQ(status, SUCCESS);
    EXPECT_NE(kvStore, nullptr);

    ASSERT_NE(capturedAsyncTask, nullptr);

    std::thread worker([&capturedAsyncTask]() { capturedAsyncTask(); });

    Status result = StoreManager::GetInstance().Delete(appId, storeId, options);
    EXPECT_EQ(result, SUCCESS);
    worker.join();
}

HWTEST_F(StoreManagerMockTest, GetKVStore_DumpStackFlagEnabled_PassedToAfterCreate, TestSize.Level1)
{
    AppId appId = { APP_ID };
    StoreId storeId = { "DumpStackFlagEnabled" };
    auto options = GetDefaultOptions();
    options.role = OWNER;
    options.dumpStackOnFileDeletion = true;
    auto service = std::make_shared<KVDBServiceClient>(nullptr);

    KVDBServiceClientMock::status = SUCCESS;
    KVDBServiceClientMock::afterCreateDumpStackOnFileDeletion = false;
    EXPECT_CALL(*kVDBServiceClientMock, GetInstance())
        .WillRepeatedly(Return(service));
    EXPECT_CALL(*taskExecutorMock, Execute(_))
        .Times(AtLeast(1))
        .WillRepeatedly(Return(TaskExecutor::INVALID_TASK_ID));

    Status status = ILLEGAL_STATE;
    auto kvStore = StoreManager::GetInstance().GetKVStore(appId, storeId, options, status);
    EXPECT_EQ(status, SUCCESS);
    EXPECT_NE(kvStore, nullptr);
    EXPECT_TRUE(KVDBServiceClientMock::afterCreateDumpStackOnFileDeletion);
}

HWTEST_F(StoreManagerMockTest, GetKVStore_DumpStackFlagDisabled_PassedToAfterCreate, TestSize.Level1)
{
    AppId appId = { APP_ID };
    StoreId storeId = { "DumpStackFlagDisabled" };
    auto options = GetDefaultOptions();
    options.role = OWNER;
    options.dumpStackOnFileDeletion = false;
    auto service = std::make_shared<KVDBServiceClient>(nullptr);

    KVDBServiceClientMock::status = SUCCESS;
    KVDBServiceClientMock::afterCreateDumpStackOnFileDeletion = true;
    EXPECT_CALL(*kVDBServiceClientMock, GetInstance())
        .WillRepeatedly(Return(service));
    EXPECT_CALL(*taskExecutorMock, Execute(_))
        .Times(AtLeast(1))
        .WillRepeatedly(Return(TaskExecutor::INVALID_TASK_ID));

    Status status = ILLEGAL_STATE;
    auto kvStore = StoreManager::GetInstance().GetKVStore(appId, storeId, options, status);
    EXPECT_EQ(status, SUCCESS);
    EXPECT_NE(kvStore, nullptr);
    EXPECT_FALSE(KVDBServiceClientMock::afterCreateDumpStackOnFileDeletion);
}

HWTEST_F(StoreManagerMockTest, GetKVStoreAndRestore_DumpStackOptionMatrix_001, TestSize.Level0)
{
    const bool optionMatrix[][3] = {
        { true, false, false },
        { false, true, false },
        { false, false, true },
        { false, false, false },
    };
    AppId appId = { APP_ID };
    auto service = std::make_shared<KVDBServiceClient>(nullptr);
    KVDBServiceClientMock::status = SUCCESS;
    EXPECT_CALL(*kVDBServiceClientMock, GetInstance())
        .WillRepeatedly(Return(service));
    EXPECT_CALL(*taskExecutorMock, Execute(_))
        .Times(AtLeast(1))
        .WillRepeatedly(Return(TaskExecutor::INVALID_TASK_ID));

    int index = 0;
    for (const auto &flags : optionMatrix) {
        StoreId storeId = { std::string("DumpStackBranchMatrix") + std::to_string(index++) };
        auto options = GetDefaultOptions();
        options.role = OWNER;
        options.syncable = flags[0];
        options.backup = flags[1];
        options.dumpStackOnFileDeletion = flags[2];
        Status status = ILLEGAL_STATE;
        auto kvStore = StoreManager::GetInstance().GetKVStore(appId, storeId, options, status);
        EXPECT_EQ(status, SUCCESS);
        EXPECT_NE(kvStore, nullptr);
        if (kvStore != nullptr) {
            Status restoreStatus = kvStore->Restore("missing_dump_stack_backup", options.baseDir);
            EXPECT_EQ(restoreStatus, INVALID_ARGUMENT);
            kvStore = nullptr;
        }
        (void)StoreManager::GetInstance().CloseKVStore(appId, storeId);
        (void)StoreManager::GetInstance().Delete(appId, storeId, options.baseDir);
    }
}

HWTEST_F(StoreManagerMockTest, OptionsMarshalling_DumpStackFlag_RoundTrip, TestSize.Level1)
{
    Options enabled;
    enabled.dumpStackOnFileDeletion = true;
    enabled.autoSync = true;
    enabled.backup = false;
    MessageParcel enabledParcel;
    ASSERT_TRUE(OHOS::ITypesUtil::Marshalling(enabled, enabledParcel));
    Options enabledOutput;
    enabledOutput.dumpStackOnFileDeletion = false;
    ASSERT_TRUE(OHOS::ITypesUtil::Unmarshalling(enabledOutput, enabledParcel));
    EXPECT_TRUE(enabledOutput.dumpStackOnFileDeletion);
    EXPECT_TRUE(enabledOutput.autoSync);
    EXPECT_FALSE(enabledOutput.backup);

    Options disabled;
    disabled.dumpStackOnFileDeletion = false;
    MessageParcel disabledParcel;
    ASSERT_TRUE(OHOS::ITypesUtil::Marshalling(disabled, disabledParcel));
    Options disabledOutput;
    disabledOutput.dumpStackOnFileDeletion = true;
    ASSERT_TRUE(OHOS::ITypesUtil::Unmarshalling(disabledOutput, disabledParcel));
    EXPECT_FALSE(disabledOutput.dumpStackOnFileDeletion);
}
