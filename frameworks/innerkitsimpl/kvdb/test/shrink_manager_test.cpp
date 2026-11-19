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

#include <atomic>
#include <chrono>
#include <cstdint>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

#include "shrink_manager.h"

using namespace testing::ext;
using namespace OHOS::DistributedKv;

namespace OHOS::Test {
namespace {
struct ShrinkState {
    bool desired = true;
    uint32_t pending = 0;
};

ShrinkState GetState(const ShrinkManager &manager)
{
    ShrinkState state{};
    manager.GetState(state.desired, state.pending);
    return state;
}

bool WaitPending(const ShrinkManager &manager, uint32_t expected, std::chrono::milliseconds timeout)
{
    auto deadline = std::chrono::steady_clock::now() + timeout;
    while (true) {
        if (GetState(manager).pending == expected) {
            return true;
        }
        if (std::chrono::steady_clock::now() >= deadline) {
            return false;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}
} // namespace

class ShrinkManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp(void) {}
    void TearDown(void) {}
};

/**
 * @tc.name: InitialDisableEnqueuesSafetySync
 * @tc.desc: A store starts disabled (desired=false, pending=0), but the first disable still queues one
 *           idempotent SET(false) as a safety sync (A1): it can heal an engine instance left enabled
 *           by an earlier wrapper lifetime. The task carries exactly one pending record, may begin
 *           with the matching desired value, and the first enable still asks for one task.
 * @tc.type: FUNC
 */
HWTEST_F(ShrinkManagerTest, InitialDisableEnqueuesSafetySync, TestSize.Level0)
{
    ShrinkManager manager;
    auto state = GetState(manager);
    EXPECT_FALSE(state.desired);
    EXPECT_EQ(state.pending, 0U);

    // First disable of a never-enabled store: accepted and one safety task is recorded.
    EXPECT_TRUE(manager.SetDesired(false));
    state = GetState(manager);
    EXPECT_FALSE(state.desired);
    EXPECT_EQ(state.pending, 1U);

    // The safety task matches the desired value and must begin; its owner releases the record.
    EXPECT_TRUE(manager.TryBegin(false));
    manager.Finish();
    EXPECT_EQ(GetState(manager).pending, 0U);

    // The first enable is a changed value, so exactly one separate task is recorded.
    EXPECT_TRUE(manager.SetDesired(true));
    EXPECT_TRUE(GetState(manager).desired);
    EXPECT_EQ(GetState(manager).pending, 1U);

    EXPECT_TRUE(manager.TryBegin(true));
    manager.Finish();
    EXPECT_EQ(GetState(manager).pending, 0U);
}

/**
 * @tc.name: SetDesiredReturnsNeedEnqueue
 * @tc.desc: A changed desired value always adds one pending task. A repeated request for the same
 *           value is deduplicated only while a task carrying that value is still pending (S5); with
 *           nothing pending, the same-value request is accepted and queued again.
 * @tc.type: FUNC
 */
HWTEST_F(ShrinkManagerTest, SetDesiredReturnsNeedEnqueue, TestSize.Level0)
{
    ShrinkManager manager;
    // First enable: changed value, exactly one pending task.
    EXPECT_TRUE(manager.SetDesired(true));
    EXPECT_EQ(GetState(manager).pending, 1U);

    // Same value while a task is pending: not enqueued again.
    EXPECT_FALSE(manager.SetDesired(true));
    EXPECT_EQ(GetState(manager).pending, 1U);

    // A changed value always adds exactly one pending task, even while others are pending.
    EXPECT_TRUE(manager.SetDesired(false));
    EXPECT_EQ(GetState(manager).pending, 2U);
    EXPECT_TRUE(manager.SetDesired(true));
    EXPECT_EQ(GetState(manager).pending, 3U);

    // Each pending record is released exactly once by its own task owner.
    manager.Finish();
    manager.Finish();
    manager.Finish();
    EXPECT_EQ(GetState(manager).pending, 0U);

    // Nothing is pending now, so the same-value enable is accepted and queued again.
    EXPECT_TRUE(manager.SetDesired(true));
    EXPECT_EQ(GetState(manager).pending, 1U);
    manager.Finish();
    EXPECT_EQ(GetState(manager).pending, 0U);
}

/**
 * @tc.name: TryBeginOnlyChecksDesired
 * @tc.desc: TryBegin only compares the current desired value; it does not consume the pending
 *           record and does not depend on finishing the previous task first.
 * @tc.type: FUNC
 */
HWTEST_F(ShrinkManagerTest, TryBeginOnlyChecksDesired, TestSize.Level0)
{
    ShrinkManager manager;
    EXPECT_TRUE(manager.SetDesired(true));
    // Only the matching value may begin, regardless of how many tasks are pending.
    EXPECT_TRUE(manager.TryBegin(true));
    EXPECT_FALSE(manager.TryBegin(false));
    manager.Finish();

    EXPECT_TRUE(manager.SetDesired(false));
    EXPECT_TRUE(manager.TryBegin(false));
    EXPECT_FALSE(manager.TryBegin(true));
    // TryBegin neither changes the desired value nor releases the pending record.
    auto state = GetState(manager);
    EXPECT_FALSE(state.desired);
    EXPECT_EQ(state.pending, 1U);

    manager.Finish();
    EXPECT_EQ(GetState(manager).pending, 0U);
}

/**
 * @tc.name: FinishDoesNotDropNewerQueuedRequest
 * @tc.desc: A newer request queued while an older opposite task is running is still allowed to
 *           begin after the older task finishes.
 * @tc.type: FUNC
 */
HWTEST_F(ShrinkManagerTest, FinishDoesNotDropNewerQueuedRequest, TestSize.Level0)
{
    ShrinkManager manager;
    // Task A (enable) is running.
    EXPECT_TRUE(manager.SetDesired(true));
    EXPECT_TRUE(manager.TryBegin(true));

    // Task B (disable) is queued while task A is still running.
    EXPECT_TRUE(manager.SetDesired(false));
    EXPECT_EQ(GetState(manager).pending, 2U);

    // Task A finishes; the queued task B must not be dropped.
    manager.Finish();
    EXPECT_EQ(GetState(manager).pending, 1U);
    EXPECT_TRUE(manager.TryBegin(false));

    manager.Finish();
    EXPECT_EQ(GetState(manager).pending, 0U);
    EXPECT_FALSE(manager.TryBegin(true));
}

/**
 * @tc.name: StaleSkipStillReleasesItsTask
 * @tc.desc: A task is stale when the desired value changed again before it began. It must not call
 *           the engine, but it still owns one pending record and must release it with Finish(), so
 *           later tasks can settle the manager.
 * @tc.type: FUNC
 */
HWTEST_F(ShrinkManagerTest, StaleSkipStillReleasesItsTask, TestSize.Level0)
{
    ShrinkManager manager;
    EXPECT_TRUE(manager.SetDesired(true));  // task A (true)
    EXPECT_TRUE(manager.SetDesired(false)); // task B (false), stale after the next line
    EXPECT_TRUE(manager.SetDesired(true));  // task C (true)
    EXPECT_EQ(GetState(manager).pending, 3U);

    // Task B sees a desired value of true: it is stale and must not issue the engine call.
    EXPECT_FALSE(manager.TryBegin(false));
    // The stale task still finishes and releases its own pending record.
    manager.Finish();
    EXPECT_EQ(GetState(manager).pending, 2U);

    // The tasks carrying the current desired value may begin and finish normally.
    EXPECT_TRUE(manager.TryBegin(true));
    manager.Finish();
    manager.Finish();
    EXPECT_EQ(GetState(manager).pending, 0U);
    EXPECT_TRUE(GetState(manager).desired);
}

/**
 * @tc.name: FinishDecrementsWithoutUnderflow
 * @tc.desc: Finish() decrements the pending task count and never underflows, even when it is called
 *           on a fresh manager or more than once for the same task.
 * @tc.type: FUNC
 */
HWTEST_F(ShrinkManagerTest, FinishDecrementsWithoutUnderflow, TestSize.Level0)
{
    ShrinkManager manager;
    manager.Finish();
    EXPECT_EQ(GetState(manager).pending, 0U);

    EXPECT_TRUE(manager.SetDesired(true));
    EXPECT_EQ(GetState(manager).pending, 1U);
    manager.Finish();
    // A repeated Finish of the same task must stay at zero.
    manager.Finish();
    EXPECT_EQ(GetState(manager).pending, 0U);
    // Finish only releases the task record; it never changes the desired value.
    EXPECT_TRUE(GetState(manager).desired);
}

/**
 * @tc.name: InvalidateResetsState
 * @tc.desc: Invalidate() resets the desired value and the pending count. A running engine call is not
 *           interrupted; its later Finish is harmless. After the reset the first disable queues the
 *           safety SET(false) again, exactly like on a fresh wrapper (A1).
 * @tc.type: FUNC
 */
HWTEST_F(ShrinkManagerTest, InvalidateResetsState, TestSize.Level0)
{
    ShrinkManager manager;
    EXPECT_TRUE(manager.SetDesired(true));
    EXPECT_TRUE(manager.SetDesired(false));
    EXPECT_EQ(GetState(manager).pending, 2U);

    manager.Invalidate();
    auto state = GetState(manager);
    EXPECT_FALSE(state.desired);
    EXPECT_EQ(state.pending, 0U);

    // A running engine call is not interrupted; its later Finish is harmless.
    manager.Finish();
    state = GetState(manager);
    EXPECT_FALSE(state.desired);
    EXPECT_EQ(state.pending, 0U);

    // The first disable after Close is not suppressed: it queues one safety task again.
    EXPECT_TRUE(manager.SetDesired(false));
    state = GetState(manager);
    EXPECT_FALSE(state.desired);
    EXPECT_EQ(state.pending, 1U);
    EXPECT_TRUE(manager.TryBegin(false));
    manager.Finish();
    EXPECT_EQ(GetState(manager).pending, 0U);

    // A later enable starts a brand-new task as usual.
    EXPECT_TRUE(manager.SetDesired(true));
    EXPECT_EQ(GetState(manager).pending, 1U);
    manager.Finish();
    EXPECT_EQ(GetState(manager).pending, 0U);
}

/**
 * @tc.name: ExecuteFailureRollbackAllowsRetry
 * @tc.desc: ScheduleShrink() rolls a failed Execute back with Finish(). The rollback must allow the
 *           same desired value to be scheduled again instead of being deduplicated forever.
 * @tc.type: FUNC
 */
HWTEST_F(ShrinkManagerTest, ExecuteFailureRollbackAllowsRetry, TestSize.Level0)
{
    ShrinkManager manager;
    EXPECT_TRUE(manager.SetDesired(true));
    // Simulates ScheduleShrink() observing INVALID_TASK_ID and rolling the pending record back.
    manager.Finish();
    EXPECT_EQ(GetState(manager).pending, 0U);
    EXPECT_TRUE(GetState(manager).desired);

    // Without the rollback this same-value request would be deduplicated forever.
    EXPECT_TRUE(manager.SetDesired(true));
    EXPECT_EQ(GetState(manager).pending, 1U);
    manager.Finish();
    EXPECT_EQ(GetState(manager).pending, 0U);
}

/**
 * @tc.name: ConcurrentTogglesConverge
 * @tc.desc: Concurrent toggles from several threads keep the pending count balanced and converge to
 *           the last desired value; no request is lost and no record is leaked.
 * @tc.type: FUNC
 */
HWTEST_F(ShrinkManagerTest, ConcurrentTogglesConverge, TestSize.Level0)
{
    constexpr int THREAD_COUNT = 8;
    constexpr int TOGGLES_PER_THREAD = 1000;
    ShrinkManager manager;
    std::atomic<int> requested { 0 };
    std::vector<std::thread> threads;
    threads.reserve(THREAD_COUNT);
    for (int index = 0; index < THREAD_COUNT; ++index) {
        threads.emplace_back([&manager, &requested, index]() {
            bool enable = (index % 2) == 0;
            for (int round = 0; round < TOGGLES_PER_THREAD; ++round) {
                enable = !enable;
                if (manager.SetDesired(enable)) {
                    requested.fetch_add(1);
                    // Model the owner of that task finishing it; the count must stay balanced.
                    manager.Finish();
                }
            }
        });
    }
    for (auto &thread : threads) {
        thread.join();
    }

    // Every SetDesired(true) return owns exactly one Finish(); the state is balanced after join.
    EXPECT_GT(requested.load(), 0);
    EXPECT_TRUE(WaitPending(manager, 0U, std::chrono::milliseconds(500)));
    EXPECT_EQ(GetState(manager).pending, 0U);

    // A final explicit enable deterministically converges to the last requested value.
    EXPECT_TRUE(manager.SetDesired(true));
    manager.Finish();
    auto state = GetState(manager);
    EXPECT_TRUE(state.desired);
    EXPECT_EQ(state.pending, 0U);
    EXPECT_TRUE(manager.TryBegin(true));
}
} // namespace OHOS::Test
