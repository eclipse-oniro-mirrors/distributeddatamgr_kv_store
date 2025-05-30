/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#define LOG_TAG "ObserverBridge"
#include "observer_bridge.h"
#include "kvdb_service_client.h"
#include "kvstore_observer_client.h"
#include "log_print.h"
namespace OHOS::DistributedKv {
constexpr uint32_t INVALID_SUBSCRIBE_TYPE = 0;
ObserverBridge::ObserverBridge(AppId appId, StoreId storeId, int32_t subUser, std::shared_ptr<Observer> observer,
    const Convertor &cvt) : appId_(std::move(appId)), storeId_(std::move(storeId)), subUser_(subUser),
    observer_(std::move(observer)), convert_(cvt)
{
}

ObserverBridge::~ObserverBridge()
{
    if (remote_ == nullptr) {
        return;
    }
    auto service = KVDBServiceClient::GetInstance();
    if (service == nullptr) {
        return;
    }
    service->Unsubscribe(appId_, storeId_, subUser_, remote_);
}

Status ObserverBridge::RegisterRemoteObserver(uint32_t realType)
{
    std::lock_guard<decltype(mutex_)> lockGuard(mutex_);
    if (remote_ != nullptr) {
        remote_->realType_ |= realType;
        return SUCCESS;
    }

    auto service = KVDBServiceClient::GetInstance();
    if (service == nullptr) {
        return SERVER_UNAVAILABLE;
    }

    remote_ = new (std::nothrow) ObserverClient(observer_, convert_);
    if (remote_ == nullptr) {
        ZLOGE("New ObserverClient failed, appId:%{public}s", appId_.appId.c_str());
        return ERROR;
    }
    auto status = service->Subscribe(appId_, storeId_, subUser_, remote_);
    if (status != SUCCESS) {
        remote_ = nullptr;
    } else {
        remote_->realType_ = realType;
    }
    return status;
}

Status ObserverBridge::UnregisterRemoteObserver(uint32_t realType)
{
    std::lock_guard<decltype(mutex_)> lockGuard(mutex_);
    if (remote_ == nullptr) {
        return SUCCESS;
    }

    auto service = KVDBServiceClient::GetInstance();
    if (service == nullptr) {
        return SERVER_UNAVAILABLE;
    }

    Status status = Status::SUCCESS;
    remote_->realType_ &= ~SUBSCRIBE_TYPE_LOCAL;
    remote_->realType_ &= ~realType;
    if (remote_->realType_ == 0) {
        status = service->Unsubscribe(appId_, storeId_, subUser_, remote_);
        remote_ = nullptr;
    }
    return status;
}

void ObserverBridge::OnChange(const DBChangedData &data)
{
    std::string deviceId;
    auto inserted = ConvertDB(data.GetEntriesInserted(), deviceId, convert_);
    auto updated = ConvertDB(data.GetEntriesUpdated(), deviceId, convert_);
    auto deleted = ConvertDB(data.GetEntriesDeleted(), deviceId, convert_);
    ChangeNotification notice(std::move(inserted), std::move(updated), std::move(deleted), deviceId, false);
    observer_->OnChange(notice);
}

ObserverBridge::ObserverClient::ObserverClient(std::shared_ptr<Observer> observer, const Convertor &cvt)
    : KvStoreObserverClient(observer), convert_(cvt), realType_(INVALID_SUBSCRIBE_TYPE)
{
}

void ObserverBridge::ObserverClient::OnChange(const ChangeNotification &data)
{
    if ((realType_ & SUBSCRIBE_TYPE_REMOTE) != SUBSCRIBE_TYPE_REMOTE) {
        return;
    }
    std::string deviceId;
    auto inserted = ObserverBridge::ConvertDB(data.GetInsertEntries(), deviceId, convert_);
    auto updated = ObserverBridge::ConvertDB(data.GetUpdateEntries(), deviceId, convert_);
    auto deleted = ObserverBridge::ConvertDB(data.GetDeleteEntries(), deviceId, convert_);
    ChangeNotification notice(std::move(inserted), std::move(updated), std::move(deleted), deviceId, false);
    KvStoreObserverClient::OnChange(notice);
}

void ObserverBridge::ObserverClient::OnChange(const DataOrigin &origin, Keys &&keys)
{
    if ((realType_ & SUBSCRIBE_TYPE_CLOUD) != SUBSCRIBE_TYPE_CLOUD) {
        return;
    }
    KvStoreObserverClient::OnChange(origin, std::move(keys));
}

template<class T>
std::vector<Entry> ObserverBridge::ConvertDB(const T &dbEntries, std::string &deviceId, const Convertor &convert)
{
    std::vector<Entry> entries(dbEntries.size());
    auto it = entries.begin();
    for (const auto &dbEntry : dbEntries) {
        Entry &entry = *it;
        entry.key = convert.ToKey(DBKey(dbEntry.key), deviceId);
        entry.value = dbEntry.value;
        ++it;
    }
    return entries;
}

void ObserverBridge::OnServiceDeath()
{
    std::lock_guard<decltype(mutex_)> lockGuard(mutex_);
    if (remote_ == nullptr) {
        return;
    }
    remote_ = nullptr;
}
} // namespace OHOS::DistributedKv
