/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#define LOG_TAG "KvStoreObserverClient"

#include "kvstore_observer_client.h"
#include "log_print.h"

namespace OHOS {
namespace DistributedKv {
KvStoreObserverClient::KvStoreObserverClient(std::shared_ptr<KvStoreObserver> kvStoreObserver)
    : kvStoreObserver_(kvStoreObserver)
{
    ZLOGI("Start");
}

KvStoreObserverClient::~KvStoreObserverClient()
{
    ZLOGI("End");
}

void KvStoreObserverClient::OnChange(const ChangeNotification &changeNotification)
{
    ZLOGI("Start");
    if (kvStoreObserver_ != nullptr) {
        ZLOGI("SINGLE_VERSION start");
        kvStoreObserver_->OnChange(changeNotification);
    }
}

void KvStoreObserverClient::OnChange(const DataOrigin &origin, IKvStoreObserver::Keys &&keys)
{
    ZLOGI("Start");
    if (kvStoreObserver_ != nullptr) {
        kvStoreObserver_->OnChange(origin, std::move(keys));
    }
}
} // namespace DistributedKv
} // namespace OHOS
