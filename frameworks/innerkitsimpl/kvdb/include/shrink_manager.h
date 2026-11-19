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
// SetDesired returns true when the caller must enqueue exactly one task; that task must call Finish once.
class ShrinkManager {
public:
    bool SetDesired(bool enable);
    bool TryBegin(bool enable);
    void Finish();
    void GetState(bool &desiredEnabled, uint32_t &pendingTasks) const;

private:
    mutable std::mutex stateMutex_;
    bool desiredEnabled_ = false;
    uint32_t pendingTasks_ = 0;
};
} // namespace OHOS::DistributedKv

#endif // OHOS_DISTRIBUTED_DATA_FRAMEWORKS_KVDB_SHRINK_MANAGER_H
