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

#include <mutex>

namespace OHOS::DistributedKv {
// ShrinkManager coordinates the asynchronous enable/disable requests of one store wrapper.
// The real switch is owned by the GRD_DB instance; the manager never inspects Delete/DeleteBatch
// and does not keep the engine state as an authority.
class ShrinkManager {
public:
    ShrinkManager() = default;
    ~ShrinkManager() = default;

    ShrinkManager(const ShrinkManager &) = delete;
    ShrinkManager &operator=(const ShrinkManager &) = delete;

    // Records the desired switch state. Returns true when the caller should enqueue a new task:
    // the desired value changed, or no task is currently scheduled. Repeated requests for the
    // same desired value while a task is scheduled return false and do not enqueue duplicates.
    bool SetDesired(bool enable);

    // A task may begin only while the current desired value still matches the task request.
    // It intentionally does not depend on shrinkScheduled_: a task finishes before a later
    // opposite request starts, and Finish must not discard that later request.
    bool TryBegin(bool enable);

    // Clears the scheduled flag after a task finishes (success, failure or stale skip).
    void Finish();

    // Cancels pending requests and resets the desired state when the store is closed.
    // A running engine call is not interrupted; its later Finish is harmless.
    void Invalidate();

private:
    mutable std::mutex stateMutex_;
    bool desiredEnabled_ = false;
    bool shrinkScheduled_ = false;
};
} // namespace OHOS::DistributedKv

#endif // OHOS_DISTRIBUTED_DATA_FRAMEWORKS_KVDB_SHRINK_MANAGER_H
