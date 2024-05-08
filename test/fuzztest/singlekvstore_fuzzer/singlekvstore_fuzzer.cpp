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

#include "singlekvstore_fuzzer.h"

#include <string>
#include <sys/stat.h>
#include <vector>

#include "distributed_kv_data_manager.h"
#include "store_errno.h"

using namespace OHOS;
using namespace OHOS::DistributedKv;

namespace OHOS {
static std::shared_ptr<SingleKvStore> singleKvStore_ = nullptr;

class DeviceObserverTestImpl : public KvStoreObserver {
public:
    DeviceObserverTestImpl();
    ~DeviceObserverTestImpl()
    {
    }
    DeviceObserverTestImpl(const DeviceObserverTestImpl &) = delete;
    DeviceObserverTestImpl &operator=(const DeviceObserverTestImpl &) = delete;
    DeviceObserverTestImpl(DeviceObserverTestImpl &&) = delete;
    DeviceObserverTestImpl &operator=(DeviceObserverTestImpl &&) = delete;

    void OnChange(const ChangeNotification &changeNotification);
};

void DeviceObserverTestImpl::OnChange(const ChangeNotification &changeNotification)
{
}

DeviceObserverTestImpl::DeviceObserverTestImpl()
{
}

class DeviceSyncCallbackTestImpl : public KvStoreSyncCallback {
public:
    void SyncCompleted(const std::map<std::string, Status> &results);
};

void DeviceSyncCallbackTestImpl::SyncCompleted(const std::map<std::string, Status> &results)
{
}

void SetUpTestCase(void)
{
    DistributedKvDataManager manager;
    Options options = {
        .createIfMissing = true,
        .encrypt = false,
        .autoSync = true,
        .securityLevel = S1,
        .kvStoreType = KvStoreType::SINGLE_VERSION
    };
    options.area = EL1;
    AppId appId = { "kvstorefuzzertest" };
    options.baseDir = std::string("/data/service/el1/public/database/") + appId.appId;
    /* define kvstore(database) name. */
    StoreId storeId = { "fuzzer_single" };
    mkdir(options.baseDir.c_str(), (S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH));
    /* [create and] open and initialize kvstore instance. */
    manager.GetSingleKvStore(options, appId, storeId, singleKvStore_);
}

void TearDown(void)
{
    (void)remove("/data/service/el1/public/database/singlekvstorefuzzertest/key");
    (void)remove("/data/service/el1/public/database/singlekvstorefuzzertest/kvdb");
    (void)remove("/data/service/el1/public/database/singlekvstorefuzzertest");
}

void PutFuzz(const uint8_t *data, size_t size)
{
    std::string skey(data, data + size);
    std::string svalue(data, data + size);
    Key key = { skey };
    Value val = { svalue };
    singleKvStore_->Put(key, val);
    singleKvStore_->Delete(key);
}

void PutBatchFuzz(const uint8_t *data, size_t size)
{
    std::string skey(data, data + size);
    std::string svalue(data, data + size);
    std::vector<Entry> entries;
    std::vector<Key> keys;
    Entry entry1;
    Entry entry2;
    Entry entry3;
    entry1.key = { skey + "test_key1" };
    entry1.value = { svalue + "test_val1" };
    entry2.key = { skey + "test_key2" };
    entry2.value = { svalue + "test_val2" };
    entry3.key = { skey + "test_key3" };
    entry3.value = { svalue + "test_val3" };
    entries.push_back(entry1);
    entries.push_back(entry2);
    entries.push_back(entry3);
    keys.push_back(entry1.key);
    keys.push_back(entry2.key);
    keys.push_back(entry3.key);
    singleKvStore_->PutBatch(entries);
    singleKvStore_->DeleteBatch(keys);
}

void GetFuzz(const uint8_t *data, size_t size)
{
    std::string skey(data, data + size);
    std::string svalue(data, data + size);
    Key key = { skey };
    Value val = { svalue };
    Value val1;
    singleKvStore_->Put(key, val);
    singleKvStore_->Get(key, val1);
    singleKvStore_->Delete(key);
}

void GetEntriesFuzz1(const uint8_t *data, size_t size)
{
    std::string prefix(data, data + size);
    std::string keys = "test_";
    size_t sum = 10;
    std::vector<Entry> results;
    for (size_t i = 0; i < sum; i++) {
        singleKvStore_->Put(prefix + keys + std::to_string(i), { keys + std::to_string(i) });
    }
    singleKvStore_->GetEntries(prefix, results);
    for (size_t i = 0; i < sum; i++) {
        singleKvStore_->Delete(prefix + keys + std::to_string(i));
    }
}

void GetEntriesFuzz2(const uint8_t *data, size_t size)
{
    std::string prefix(data, data + size);
    DataQuery dataQuery;
    dataQuery.KeyPrefix(prefix);
    std::string keys = "test_";
    std::vector<Entry> entries;
    size_t sum = 10;
    for (size_t i = 0; i < sum; i++) {
        singleKvStore_->Put(prefix + keys + std::to_string(i), keys + std::to_string(i));
    }
    singleKvStore_->GetEntries(dataQuery, entries);
    for (size_t i = 0; i < sum; i++) {
        singleKvStore_->Delete(prefix + keys + std::to_string(i));
    }
}

void SubscribeKvStoreFuzz(const uint8_t *data, size_t size)
{
    std::string prefix(data, data + size);
    DataQuery dataQuery;
    dataQuery.KeyPrefix(prefix);
    std::string keys = "test_";
    size_t sum = 10;
    for (size_t i = 0; i < sum; i++) {
        singleKvStore_->Put(prefix + keys + std::to_string(i), keys + std::to_string(i));
    }
    auto observer = std::make_shared<DeviceObserverTestImpl>();
    singleKvStore_->SubscribeKvStore(SubscribeType::SUBSCRIBE_TYPE_ALL, observer);
    singleKvStore_->UnSubscribeKvStore(SubscribeType::SUBSCRIBE_TYPE_ALL, observer);
    for (size_t i = 0; i < sum; i++) {
        singleKvStore_->Delete(prefix + keys + std::to_string(i));
    }
}

void SyncCallbackFuzz(const uint8_t *data, size_t size)
{
    auto syncCallback = std::make_shared<DeviceSyncCallbackTestImpl>();
    singleKvStore_->RegisterSyncCallback(syncCallback);

    std::string prefix(data, data + size);
    DataQuery dataQuery;
    dataQuery.KeyPrefix(prefix);
    std::string keys = "test_";
    size_t sum = 10;
    for (size_t i = 0; i < sum; i++) {
        singleKvStore_->Put(prefix + keys + std::to_string(i), keys + std::to_string(i));
    }

    std::map<std::string, Status> results;
    syncCallback->SyncCompleted(results);

    for (size_t i = 0; i < sum; i++) {
        singleKvStore_->Delete(prefix + keys + std::to_string(i));
    }
    singleKvStore_->UnRegisterSyncCallback();
}

void GetResultSetFuzz1(const uint8_t *data, size_t size)
{
    std::string prefix(data, data + size);
    std::string keys = "test_";
    int position = static_cast<int>(size);
    std::shared_ptr<KvStoreResultSet> resultSet;
    size_t sum = 10;
    for (size_t i = 0; i < sum; i++) {
        singleKvStore_->Put(prefix + keys + std::to_string(i), keys + std::to_string(i));
    }
    auto status = singleKvStore_->GetResultSet(prefix, resultSet);
    if (status != Status::SUCCESS || resultSet == nullptr) {
        return;
    }
    resultSet->Move(position);
    resultSet->MoveToPosition(position);
    Entry entry;
    resultSet->GetEntry(entry);
    for (size_t i = 0; i < sum; i++) {
        singleKvStore_->Delete(prefix + keys + std::to_string(i));
    }
}

void GetResultSetFuzz2(const uint8_t *data, size_t size)
{
    std::string prefix(data, data + size);
    DataQuery dataQuery;
    dataQuery.KeyPrefix(prefix);
    std::string keys = "test_";
    std::shared_ptr<KvStoreResultSet> resultSet;
    size_t sum = 10;
    for (size_t i = 0; i < sum; i++) {
        singleKvStore_->Put(prefix + keys + std::to_string(i), keys + std::to_string(i));
    }
    singleKvStore_->GetResultSet(dataQuery, resultSet);
    singleKvStore_->CloseResultSet(resultSet);
    for (size_t i = 0; i < sum; i++) {
        singleKvStore_->Delete(prefix + keys + std::to_string(i));
    }
}

void GetResultSetFuzz3(const uint8_t *data, size_t size)
{
    std::string prefix(data, data + size);
    DataQuery dataQuery;
    dataQuery.KeyPrefix(prefix);
    std::string keys = "test_";
    std::shared_ptr<KvStoreResultSet> resultSet;
    size_t sum = 10;
    for (size_t i = 0; i < sum; i++) {
        singleKvStore_->Put(prefix + keys + std::to_string(i), keys + std::to_string(i));
    }
    singleKvStore_->GetResultSet(dataQuery, resultSet);
    auto status = singleKvStore_->GetResultSet(prefix, resultSet);
    if (status != Status::SUCCESS || resultSet == nullptr) {
        return;
    }
    int cnt = resultSet->GetCount();
    if (static_cast<int>(size) != cnt) {
        return;
    }
    resultSet->GetPosition();
    resultSet->IsBeforeFirst();
    resultSet->IsFirst();
    resultSet->MoveToPrevious();
    resultSet->IsBeforeFirst();
    resultSet->IsFirst();
    while (resultSet->MoveToNext()) {
        Entry entry;
        resultSet->GetEntry(entry);
    }
    Entry entry;
    resultSet->GetEntry(entry);
    resultSet->IsLast();
    resultSet->IsAfterLast();
    resultSet->MoveToNext();
    resultSet->IsLast();
    resultSet->IsAfterLast();
    resultSet->Move(1);
    resultSet->IsLast();
    resultSet->IsAfterLast();
    resultSet->MoveToFirst();
    resultSet->GetEntry(entry);
    resultSet->MoveToLast();
    resultSet->GetEntry(entry);
    for (size_t i = 0; i < sum; i++) {
        singleKvStore_->Delete(prefix + keys + std::to_string(i));
    }
}

void GetCountFuzz1(const uint8_t *data, size_t size)
{
    int count;
    std::string prefix(data, data + size);
    DataQuery query;
    query.KeyPrefix(prefix);
    std::string keys = "test_";
    size_t sum = 10;
    for (size_t i = 0; i < sum; i++) {
        singleKvStore_->Put(prefix + keys + std::to_string(i), keys + std::to_string(i));
    }
    singleKvStore_->GetCount(query, count);
    for (size_t i = 0; i < sum; i++) {
        singleKvStore_->Delete(prefix + keys + std::to_string(i));
    }
}

void GetCountFuzz2(const uint8_t *data, size_t size)
{
    int count;
    size_t sum = 10;
    std::vector<std::string> keys;
    std::string prefix(data, data + size);
    for (size_t i = 0; i < sum; i++) {
        keys.push_back(prefix);
    }
    DataQuery query;
    query.InKeys(keys);
    std::string skey = "test_";
    for (size_t i = 0; i < sum; i++) {
        singleKvStore_->Put(prefix + skey + std::to_string(i), skey + std::to_string(i));
    }
    singleKvStore_->GetCount(query, count);
    for (size_t i = 0; i < sum; i++) {
        singleKvStore_->Delete(prefix + skey + std::to_string(i));
    }
}

void RemoveDeviceDataFuzz(const uint8_t *data, size_t size)
{
    size_t sum = 10;
    std::string deviceId(data, data + size);
    std::vector<Entry> input;
    auto cmp = [](const Key &entry, const Key &sentry) { return entry.Data() < sentry.Data(); };
    std::map<Key, Value, decltype(cmp)> dictionary(cmp);
    for (size_t i = 0; i < sum; ++i) {
        Entry entry;
        entry.key = std::to_string(i).append("_k");
        entry.value = std::to_string(i).append("_v");
        dictionary[entry.key] = entry.value;
        input.push_back(entry);
    }
    singleKvStore_->PutBatch(input);
    singleKvStore_->RemoveDeviceData(deviceId);
    singleKvStore_->RemoveDeviceData("");

    for (size_t i = 0; i < sum; i++) {
        singleKvStore_->Delete(std::to_string(i).append("_k"));
    }
}

void GetSecurityLevelFuzz(const uint8_t *data, size_t size)
{
    size_t sum = 10;
    std::vector<std::string> keys;
    std::string prefix(data, data + size);
    for (size_t i = 0; i < sum; i++) {
        keys.push_back(prefix);
    }
    std::string skey = "test_";
    for (size_t i = 0; i < sum; i++) {
        singleKvStore_->Put(prefix + skey + std::to_string(i), skey + std::to_string(i));
    }
    SecurityLevel securityLevel;
    singleKvStore_->GetSecurityLevel(securityLevel);
    for (size_t i = 0; i < sum; i++) {
        singleKvStore_->Delete(prefix + skey + std::to_string(i));
    }
}

void SyncFuzz1(const uint8_t *data, size_t size)
{
    size_t sum = 10;
    std::string skey = "test_";
    for (size_t i = 0; i < sum; i++) {
        singleKvStore_->Put(skey + std::to_string(i), skey + std::to_string(i));
    }
    std::string deviceId(data, data + size);
    std::vector<std::string> deviceIds = { deviceId };
    uint32_t allowedDelayMs = 200;
    singleKvStore_->Sync(deviceIds, SyncMode::PUSH, allowedDelayMs);
    for (size_t i = 0; i < sum; i++) {
        singleKvStore_->Delete(skey + std::to_string(i));
    }
}

void SyncFuzz2(const uint8_t *data, size_t size)
{
    size_t sum = 10;
    std::string skey = "test_";
    for (size_t i = 0; i < sum; i++) {
        singleKvStore_->Put(skey + std::to_string(i), skey + std::to_string(i));
    }
    std::string deviceId(data, data + size);
    std::vector<std::string> deviceIds = { deviceId };
    DataQuery dataQuery;
    dataQuery.KeyPrefix("name");
    singleKvStore_->Sync(deviceIds, SyncMode::PULL, dataQuery, nullptr);
    for (size_t i = 0; i < sum; i++) {
        singleKvStore_->Delete(skey + std::to_string(i));
    }
}

void SyncParamFuzz(const uint8_t *data, size_t size)
{
    size_t sum = 10;
    std::vector<std::string> keys;
    std::string prefix(data, data + size);
    for (size_t i = 0; i < sum; i++) {
        keys.push_back(prefix);
    }
    std::string skey = "test_";
    for (size_t i = 0; i < sum; i++) {
        singleKvStore_->Put(prefix + skey + std::to_string(i), skey + std::to_string(i));
    }

    KvSyncParam syncParam { 500 };
    singleKvStore_->SetSyncParam(syncParam);

    KvSyncParam syncParamRet;
    singleKvStore_->GetSyncParam(syncParamRet);

    for (size_t i = 0; i < sum; i++) {
        singleKvStore_->Delete(prefix + skey + std::to_string(i));
    }
}

void SetCapabilityEnabledFuzz(const uint8_t *data, size_t size)
{
    size_t sum = 10;
    std::vector<std::string> keys;
    std::string prefix(data, data + size);
    for (size_t i = 0; i < sum; i++) {
        keys.push_back(prefix);
    }
    std::string skey = "test_";
    for (size_t i = 0; i < sum; i++) {
        singleKvStore_->Put(prefix + skey + std::to_string(i), skey + std::to_string(i));
    }

    singleKvStore_->SetCapabilityEnabled(true);
    singleKvStore_->SetCapabilityEnabled(false);

    for (size_t i = 0; i < sum; i++) {
        singleKvStore_->Delete(prefix + skey + std::to_string(i));
    }
}

void SetCapabilityRangeFuzz(const uint8_t *data, size_t size)
{
    std::string label(data, data + size);
    std::vector<std::string> local = { label + "_local1", label + "_local2" };
    std::vector<std::string> remote = { label + "_remote1", label + "_remote2" };
    singleKvStore_->SetCapabilityRange(local, remote);
}

void SubscribeWithQueryFuzz(const uint8_t *data, size_t size)
{
    std::string deviceId(data, data + size);
    std::vector<std::string> deviceIds = { deviceId + "_1", deviceId + "_2" };
    DataQuery dataQuery;
    dataQuery.KeyPrefix("name");
    singleKvStore_->SubscribeWithQuery(deviceIds, dataQuery);
    singleKvStore_->UnsubscribeWithQuery(deviceIds, dataQuery);
}

void UnSubscribeWithQueryFuzz(const uint8_t *data, size_t size)
{
    std::string deviceId(data, data + size);
    std::vector<std::string> deviceIds = { deviceId + "_1", deviceId + "_2" };
    DataQuery dataQuery;
    dataQuery.KeyPrefix("name");
    singleKvStore_->UnsubscribeWithQuery(deviceIds, dataQuery);
}

void AsyncGetFuzz(data, size)
{
    std::string strKey(data, data + size);
    std::string strValue(data, data + size);
    Key key = { strKey };
    Value val = { strValue };
    singleKvStore_->Put(key, val);
    Value out;
    std::function<void(Status, Value &&)> call = [](Status status, Value &&value) {};
    std::string networkId(data, data + size);
    singleKvStore_->Get(key, networkId, call);
    singleKvStore_->Delete(key);
}

void AsyncGetEntriesFuzz(data, size)
{
    std::string prefix(data, data + size);
    std::string keys = "test_";
    size_t sum = 10;
    std::vector<Entry> results;
    for (size_t i = 0; i < sum; i++) {
        singleKvStore_->Put(prefix + keys + std::to_string(i), { keys + std::to_string(i) });
    }
    std::function<void(Status, std::vector<Entry> &&)> call = [](Status status, std::vector<Entry> &&entry) {};
    std::string networkId(data, data + size);
    singleKvStore_->GetEntries(prefix, networkId, call);
    for (size_t i = 0; i < sum; i++) {
        singleKvStore_->Delete(prefix + keys + std::to_string(i));
    }
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::SetUpTestCase();
    OHOS::PutFuzz(data, size);
    OHOS::PutBatchFuzz(data, size);
    OHOS::GetFuzz(data, size);
    OHOS::GetEntriesFuzz1(data, size);
    OHOS::GetEntriesFuzz2(data, size);
    OHOS::GetResultSetFuzz1(data, size);
    OHOS::GetResultSetFuzz2(data, size);
    OHOS::GetResultSetFuzz3(data, size);
    OHOS::GetCountFuzz1(data, size);
    OHOS::GetCountFuzz2(data, size);
    OHOS::SyncFuzz1(data, size);
    OHOS::SyncFuzz2(data, size);
    OHOS::SubscribeKvStoreFuzz(data, size);
    OHOS::RemoveDeviceDataFuzz(data, size);
    OHOS::GetSecurityLevelFuzz(data, size);
    OHOS::SyncCallbackFuzz(data, size);
    OHOS::SyncParamFuzz(data, size);
    OHOS::SetCapabilityEnabledFuzz(data, size);
    OHOS::SetCapabilityRangeFuzz(data, size);
    OHOS::SubscribeWithQueryFuzz(data, size);
    OHOS::UnSubscribeWithQueryFuzz(data, size);
    OHOS::AsyncGetFuzz(data, size);
    OHOS::AsyncGetEntriesFuzz(data, size);
    OHOS::TearDown();
    return 0;
}