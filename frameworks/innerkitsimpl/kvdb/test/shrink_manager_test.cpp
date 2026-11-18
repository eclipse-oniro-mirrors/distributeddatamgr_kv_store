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

#include <gtest/gtest.h>

#include "shrink_manager.h"

using namespace testing::ext;
using namespace OHOS::DistributedKv;

namespace OHOS::Test {
class ShrinkManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp(void) {}
    void TearDown(void) {}
};

/**
 * @tc.name: SetDesiredReturnsNeedEnqueue
 * @tc.desc: SetDesired asks for a new task when the desired value changes or nothing is scheduled;
 *           the same desired value while a task is scheduled is not enqueued again.
 * @tc.type: FUNC
 */
HWTEST_F(ShrinkManagerTest, SetDesiredReturnsNeedEnqueue, TestSize.Level0)
{
    ShrinkManager manager;
    // The first request always needs a task.
    EXPECT_TRUE(manager.SetDesired(true));
    // A task whose value matches the current desired state may begin.
    EXPECT_TRUE(manager.TryBegin(true));
    manager.Finish();

    // Flipping the desired value needs one new task.
    EXPECT_TRUE(manager.SetDesired(false));
    // The opposite value must not begin.
    EXPECT_FALSE(manager.TryBegin(true));
    // The matching value may begin.
    EXPECT_TRUE(manager.TryBegin(false));
    // A repeated request for the same value while the task is scheduled is not enqueued twice.
    EXPECT_FALSE(manager.SetDesired(false));

    // Close cancels the pending request and rejects the cancelled enable value.
    manager.Invalidate();
    EXPECT_FALSE(manager.TryBegin(true));
}

/**
 * @tc.name: TryBeginOnlyChecksDesired
 * @tc.desc: TryBegin only checks the current desired value; it does not depend on the scheduled
 *           flag or on finishing the previous task first.
 * @tc.type: FUNC
 */
HWTEST_F(ShrinkManagerTest, TryBeginOnlyChecksDesired, TestSize.Level0)
{
    ShrinkManager manager;
    EXPECT_TRUE(manager.SetDesired(true));
    EXPECT_TRUE(manager.TryBegin(true));
    manager.Finish();

    EXPECT_TRUE(manager.SetDesired(false));
    EXPECT_TRUE(manager.TryBegin(false));
    EXPECT_FALSE(manager.TryBegin(true));
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
    ASSERT_TRUE(manager.TryBegin(true));

    // Task B (disable) is queued while task A is still running.
    EXPECT_TRUE(manager.SetDesired(false));

    // Task A finishes and clears the scheduled flag; the queued task B must not be dropped.
    manager.Finish();
    EXPECT_TRUE(manager.TryBegin(false));

    manager.Finish();
    EXPECT_FALSE(manager.TryBegin(true));
}

/**
 * @tc.name: InvalidateCancels
 * @tc.desc: Close invalidates the pending request; a later Finish of a running engine call is
 *           harmless and must not restart the cancelled request.
 * @tc.type: FUNC
 */
HWTEST_F(ShrinkManagerTest, InvalidateCancels, TestSize.Level0)
{
    ShrinkManager manager;
    EXPECT_TRUE(manager.SetDesired(true));
    ASSERT_TRUE(manager.TryBegin(true));

    manager.Invalidate();
    EXPECT_FALSE(manager.TryBegin(true));

    // A running engine call is not interrupted; its later Finish is harmless.
    manager.Finish();
    EXPECT_FALSE(manager.TryBegin(true));
}
} // namespace OHOS::Test
