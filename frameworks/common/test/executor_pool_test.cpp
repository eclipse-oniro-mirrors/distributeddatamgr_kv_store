/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include <gtest/gtest.h>

#include "block_data.h"
#include "executor_pool.h"

namespace OHOS::Test {
using namespace testing::ext;
using namespace OHOS;
using duration = std::chrono::steady_clock::duration;
class ExecutorPoolTest : public testing::Test {
public:
    struct Data {
        std::mutex mutex_;
        int data = 0;
        void Add()
        {
            std::lock_guard<std::mutex> lockGuard(mutex_);
            data++;
        }
    };
    static constexpr uint32_t SHORT_INTERVAL = 100; // ms
    static constexpr uint32_t LONG_INTERVAL = 1;    // s
    static std::shared_ptr<ExecutorPool> executorPool_;
    static void SetUpTestCase(void) {};
    static void TearDownTestCase(void)
    {
        executorPool_ = nullptr;
    };
    void SetUp() {};
    void TearDown() { }
};
std::shared_ptr<ExecutorPool> ExecutorPoolTest::executorPool_ = std::make_shared<ExecutorPool>(12, 5);

/**
 * @tc.name: Execute
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: CRJ
 */
HWTEST_F(ExecutorPoolTest, Execute, TestSize.Level0)
{
    auto expiredTime = std::chrono::milliseconds(SHORT_INTERVAL);
    int testData = 10;
    auto blockData = std::make_shared<BlockData<int>>(LONG_INTERVAL, testData);
    auto atTaskId1 = executorPool_->Schedule(expiredTime, [blockData]() {
        int testData = 11;
        blockData->SetValue(testData);
    });
    ASSERT_EQ(blockData->GetValue(), 11);
    blockData->Clear();
    auto atTaskId2 = executorPool_->Schedule(expiredTime, [blockData]() {
        int testData = 12;
        blockData->SetValue(testData);
    });
    ASSERT_EQ(blockData->GetValue(), 12);
    ASSERT_NE(atTaskId1, atTaskId2);
}

/**
 * @tc.name: Schedule
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: CRJ
 */
HWTEST_F(ExecutorPoolTest, Schedule, TestSize.Level0)
{
    auto expiredTime = std::chrono::milliseconds(SHORT_INTERVAL);
    auto testData = std::make_shared<Data>();
    auto taskId = executorPool_->Schedule(
        [testData] {
            testData->Add();
        },
        expiredTime);
    ASSERT_NE(taskId, ExecutorPool::INVALID_TASK_ID);
    std::this_thread::sleep_for(std::chrono::milliseconds(SHORT_INTERVAL * 12));
    ASSERT_GT(testData->data, 10);
    executorPool_->Remove(taskId);
}

/**
 * @tc.name: MultiSchedule
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: CRJ
 */
HWTEST_F(ExecutorPoolTest, MultiSchedule, TestSize.Level0)
{
    auto data = std::make_shared<Data>();
    auto task = [data] {
        data->Add();
    };
    std::set<ExecutorPool::TaskId> ids;
    for (int i = 0; i < 10; ++i) {
        auto id = executorPool_->Schedule(task, std::chrono::seconds(0), std::chrono::seconds(LONG_INTERVAL), 10);
        ASSERT_EQ(ids.count(id), 0);
        ids.insert(id);
    }
    std::this_thread::sleep_for(std::chrono::seconds(LONG_INTERVAL * 10));
    ASSERT_EQ(data->data, 100);
    for (auto id : ids) {
        executorPool_->Remove(id);
    }
}
/**
 * @tc.name: Remove
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: CRJ
 */
HWTEST_F(ExecutorPoolTest, Remove, TestSize.Level0)
{
    auto expiredTime = std::chrono::milliseconds(SHORT_INTERVAL);
    auto data = std::make_shared<Data>();
    auto task = [data] {
        data->Add();
    };
    auto temp = executorPool_->Schedule(task, expiredTime * 2);
    std::this_thread::sleep_for(std::chrono::milliseconds(SHORT_INTERVAL));
    ASSERT_EQ(data->data, 1);
    ASSERT_TRUE(executorPool_->Remove(temp));
    std::this_thread::sleep_for(expiredTime * 4);
    ASSERT_EQ(data->data, 1);
}
/**
 * @tc.name: Reset
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: CRJ
 */
HWTEST_F(ExecutorPoolTest, Reset, TestSize.Level0)
{
    auto expiredTime = std::chrono::milliseconds(SHORT_INTERVAL);
    auto data = std::make_shared<Data>();
    auto task = [data] {
        data->Add();
    };
    auto temp = executorPool_->Schedule(task, expiredTime * 2);
    std::this_thread::sleep_for(std::chrono::milliseconds(SHORT_INTERVAL));
    ASSERT_EQ(data->data, 1);
    ASSERT_EQ(executorPool_->Reset(temp, std::chrono::milliseconds(expiredTime * 2)), temp);
    std::this_thread::sleep_for(std::chrono::milliseconds(expiredTime * 5));
    ASSERT_EQ(data->data, 3);
    executorPool_->Remove(temp);
}

/**
 * @tc.name: MaxEqualsOne
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: CRJ
 */
HWTEST_F(ExecutorPoolTest, MaxEqualsOne, TestSize.Level0)
{
    auto executors = std::make_shared<ExecutorPool>(1, 0);
    std::atomic<int> testNum = 1;
    auto delayTask = [&testNum] {
        testNum++;
    };
    auto task = [&testNum] {
        testNum += 2;
    };
    executors->Schedule(std::chrono::milliseconds(SHORT_INTERVAL * 2), delayTask);
    ASSERT_EQ(testNum, 1);
    executors->Execute(task);
    std::this_thread::sleep_for(std::chrono::milliseconds(SHORT_INTERVAL));
    ASSERT_EQ(testNum, 3);
    std::this_thread::sleep_for(std::chrono::milliseconds(SHORT_INTERVAL * 2));
    ASSERT_EQ(testNum, 4);
}

/**
 * @tc.name: RemoveInExcuteTask
 * @tc.desc: test remove task when the task is running.
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: ht
 */
HWTEST_F(ExecutorPoolTest, RemoveWhenExcute, TestSize.Level0)
{
    auto executors = std::make_shared<ExecutorPool>(1, 1);
    auto taskId = ExecutorPool::INVALID_TASK_ID;
    std::atomic<int> flag = 0;
    taskId = executors->Schedule(
        [executors, &taskId, &flag]() {
            flag++;
            executors->Remove(taskId, false);
            taskId = ExecutorPool::INVALID_TASK_ID;
        },
        std::chrono::seconds(0), std::chrono::milliseconds(SHORT_INTERVAL), 10);
    std::this_thread::sleep_for(std::chrono::seconds(LONG_INTERVAL));
    ASSERT_EQ(taskId, ExecutorPool::INVALID_TASK_ID);
    ASSERT_EQ(flag, 1);
}
namespace {
// Releases the worker gate and waits (bounded by the BlockData interval) for the worker to leave, both on
// the normal path and when an ASSERT returns early. Every state shared with the worker is a shared_ptr,
// so a worker can never touch a destroyed stack object (ASan stack-use-after-scope) and ExecutorPool
// destruction cannot block on a forever-blocked worker.
class UnblockOnExitGuard {
public:
    UnblockOnExitGuard(std::shared_ptr<BlockData<int>> unblock, std::shared_ptr<BlockData<int>> finished)
        : unblock_(std::move(unblock)), finished_(std::move(finished)) {}
    ~UnblockOnExitGuard()
    {
        if (unblock_ != nullptr) {
            unblock_->SetValue(1);
        }
        if (finished_ != nullptr) {
            (void)finished_->GetValue();
        }
    }
    UnblockOnExitGuard(const UnblockOnExitGuard &) = delete;
    UnblockOnExitGuard &operator=(const UnblockOnExitGuard &) = delete;

private:
    std::shared_ptr<BlockData<int>> unblock_;
    std::shared_ptr<BlockData<int>> finished_;
};
} // namespace

/**
 * @tc.name: RemovePendingQueuedTask
 * @tc.desc: test RemovePending removes a still-queued task and reports that it can no longer execute.
 * @tc.type: FUNC
 */
HWTEST_F(ExecutorPoolTest, RemovePendingQueuedTask, TestSize.Level0)
{
    // One worker: while it is blocked, every other task stays in the waiting queue deterministically.
    auto executors = std::make_shared<ExecutorPool>(1, 1);
    auto started = std::make_shared<BlockData<int>>(5, 0);
    auto unblock = std::make_shared<BlockData<int>>(5, 0);
    auto finished = std::make_shared<BlockData<int>>(5, 0);
    // Declared after executors and before any assertion: an early return still releases the blocked worker
    // and waits for it, so no assertion failure can turn into stack-use-after-scope or a hung process.
    UnblockOnExitGuard gateGuard(unblock, finished);
    auto blockerId = executors->Schedule(std::chrono::seconds(0), [started, unblock, finished]() {
        started->SetValue(1);
        unblock->GetValue();
        finished->SetValue(1);
    });
    ASSERT_NE(blockerId, ExecutorPool::INVALID_TASK_ID);
    ASSERT_EQ(started->GetValue(), 1);

    auto queuedRuns = std::make_shared<std::atomic<int>>(0);
    auto queuedId = executors->Schedule(std::chrono::seconds(0), [queuedRuns]() {
        (*queuedRuns)++;
    });
    ASSERT_NE(queuedId, ExecutorPool::INVALID_TASK_ID);

    // The queued task is really removed, so it is guaranteed not to run.
    ASSERT_TRUE(executors->RemovePending(queuedId));
    // A running task must never be reported as removed.
    ASSERT_FALSE(executors->RemovePending(blockerId));

    unblock->SetValue(1);
    ASSERT_EQ(finished->GetValue(), 1);
    std::this_thread::sleep_for(std::chrono::milliseconds(SHORT_INTERVAL));
    ASSERT_EQ(queuedRuns->load(), 0);
    // Removing an already removed or never scheduled task reports false.
    ASSERT_FALSE(executors->RemovePending(queuedId));
    ASSERT_FALSE(executors->RemovePending(ExecutorPool::INVALID_TASK_ID));
}

/**
 * @tc.name: RemovePendingRunningTask
 * @tc.desc: test RemovePending reports false for a running task; the task keeps running to completion.
 * @tc.type: FUNC
 */
HWTEST_F(ExecutorPoolTest, RemovePendingRunningTask, TestSize.Level0)
{
    auto executors = std::make_shared<ExecutorPool>(1, 1);
    auto started = std::make_shared<BlockData<int>>(5, 0);
    auto unblock = std::make_shared<BlockData<int>>(5, 0);
    auto finished = std::make_shared<BlockData<int>>(5, 0);
    UnblockOnExitGuard gateGuard(unblock, finished);
    auto runs = std::make_shared<std::atomic<int>>(0);
    auto taskId = executors->Schedule(std::chrono::seconds(0), [started, unblock, finished, runs]() {
        (*runs)++;
        started->SetValue(1);
        unblock->GetValue();
        finished->SetValue(1);
    });
    ASSERT_NE(taskId, ExecutorPool::INVALID_TASK_ID);
    ASSERT_EQ(started->GetValue(), 1);

    // The task already started: it cannot be cancelled, its owner must release the record itself.
    ASSERT_FALSE(executors->RemovePending(taskId));
    unblock->SetValue(1);
    std::this_thread::sleep_for(std::chrono::milliseconds(SHORT_INTERVAL));
    ASSERT_EQ(runs->load(), 1);
}
} // namespace OHOS::Test
