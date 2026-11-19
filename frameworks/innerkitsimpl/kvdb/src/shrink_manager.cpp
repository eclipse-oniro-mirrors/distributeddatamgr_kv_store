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

#include "shrink_manager.h"

namespace OHOS::DistributedKv {
bool ShrinkManager::SetDesired(bool enable)
{
    std::lock_guard<std::mutex> lock(stateMutex_);
    if (desiredEnabled_ == enable && pendingTasks_ > 0) {
        return false;
    }
    desiredEnabled_ = enable;
    ++pendingTasks_;
    return true;
}

bool ShrinkManager::TryBegin(bool enable)
{
    std::lock_guard<std::mutex> lock(stateMutex_);
    return desiredEnabled_ == enable;
}

void ShrinkManager::Finish()
{
    std::lock_guard<std::mutex> lock(stateMutex_);
    --pendingTasks_;
}

void ShrinkManager::GetState(bool &desiredEnabled, uint32_t &pendingTasks) const
{
    std::lock_guard<std::mutex> lock(stateMutex_);
    desiredEnabled = desiredEnabled_;
    pendingTasks = pendingTasks_;
}
} // namespace OHOS::DistributedKv
