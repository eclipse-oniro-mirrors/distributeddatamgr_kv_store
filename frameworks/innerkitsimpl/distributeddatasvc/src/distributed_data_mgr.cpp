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
#define LOG_TAG "DistributedDataMgr"
#include "kvstore_data_service_mgr.h"
#include "distributed_data_mgr.h"

namespace OHOS::DistributedKv {
DistributedDataMgr::DistributedDataMgr() = default;
DistributedDataMgr::~DistributedDataMgr() = default;
int32_t DistributedKv::DistributedDataMgr::ClearAppStorage(const std::string &bundleName, int32_t userId,
    int32_t appIndex, int32_t tokenId)
{
    return KvStoreDataServiceMgr::ClearAppStorage(bundleName, userId, appIndex, tokenId);
}
} // namespace OHOS::DistributedKv
