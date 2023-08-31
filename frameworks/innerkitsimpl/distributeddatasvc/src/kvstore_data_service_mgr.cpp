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
#define LOG_TAG "KvStoreDataServiceMgr"
#include "kvstore_data_service_mgr.h"
#include "log_print.h"
#include "system_ability_definition.h"
#include "iservice_registry.h"
namespace OHOS::DistributedKv {
int32_t KvStoreDataServiceMgr::ClearAppStorage(const std::string &bundleName, int32_t userId, int32_t appIndex, int32_t tokenId)
{
    sptr<IKvStoreDataService> ability = GetDistributedKvDataService();
    if (ability == nullptr) {
        return ERROR;
    }
    return ability->ClearAppStorage(bundleName, userId, appIndex, tokenId);
}

sptr<IKvStoreDataService> KvStoreDataServiceMgr::GetDistributedKvDataService()
{
    ZLOGI("create remote proxy.");
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        ZLOGE("get samgr fail.");
        return nullptr;
    }

    auto remote = samgr->CheckSystemAbility(DISTRIBUTED_KV_DATA_SERVICE_ABILITY_ID);
    auto proxy = iface_cast<IKvStoreDataService>(remote);
    if (proxy == nullptr) {
        ZLOGE("initialize proxy failed.");
        return nullptr;
    }
    return proxy;
}
}
