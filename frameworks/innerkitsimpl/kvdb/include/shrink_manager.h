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

#ifndef OHOS_DISTRIBUTED_DATA_FRAMEWORKS_KVDB_SHRINK_MANAGER_H
#define OHOS_DISTRIBUTED_DATA_FRAMEWORKS_KVDB_SHRINK_MANAGER_H

#include <cstdint>
#include <mutex>

namespace OHOS::DistributedKv {
// ShrinkManager coordinates the asynchronous enable/disable requests of one store wrapper.
// The real switch is owned by the GRD_DB instance; the manager never inspects Delete/DeleteBatch
// and does not keep the engine state as an authority.
//
// A store always starts with desired=false, and the first disable is not special: it still queues one
// idempotent SET(false) as a safety sync. That SET can heal an engine instance that is still enabled
// from an earlier wrapper lifetime (a delegate/engine instance may outlive its wrapper when closing
// the delegate returns busy), so the redundant request is accepted noise on purpose. P3-2 is no
// longer suppressed by the manager.
class ShrinkManager {
public:
    ShrinkManager() = default;
    ~ShrinkManager() = default;

    ShrinkManager(const ShrinkManager &) = delete;
    ShrinkManager &operator=(const ShrinkManager &) = delete;

    // Records the desired switch state and returns true when the caller must enqueue a new task.
    // A changed desired value always asks for one task; a request for the same value asks for one
    // task as well once nothing is pending, so the first disable after opening the store still
    // reaches the engine once (idempotent safety sync, see the class comment). Only a request for
    // the same value while a matching task is still pending is dropped.
    // Every true return adds exactly one pending task; its owner must call Finish() exactly once,
    // whether the task is applied, fails, is superseded (stale skip) or is removed before it starts.
    // A queued task is cancelled with a manual Finish() only after ExecutorPool::RemovePending()
    // confirms it can no longer run; a task that already started releases its own record in the
    // RunShrink finish guard, so the one-Finish-per-task invariant does not depend on Remove().
    bool SetDesired(bool enable);

    // A task may begin only while the current desired value still matches the task request.
    // It intentionally does not depend on the pending task count: a task finishes before a later
    // opposite request starts, and Finish must not discard that later request.
    bool TryBegin(bool enable);

    // Marks one pending task as finished (success, failure, stale skip or cancellation).
    // Extra calls are ignored, so the count never underflows.
    void Finish();

    // Cancels pending requests and resets the desired state when the store is closed.
    // A running engine call is not interrupted; its later Finish is harmless.
    void Invalidate();

    // Test/diagnostics only: snapshot of the desired state and the number of unfinished tasks.
    void GetState(bool &desiredEnabled, uint32_t &pendingTasks) const;

private:
    mutable std::mutex stateMutex_;
    bool desiredEnabled_ = false;
    uint32_t pendingTasks_ = 0;
};
} // namespace OHOS::DistributedKv

#endif // OHOS_DISTRIBUTED_DATA_FRAMEWORKS_KVDB_SHRINK_MANAGER_H
