/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "kv_general_ut.h"
#include "virtual_cloud_db.h"

namespace DistributedDB {
void KVGeneralUt::SetUp()
{
    virtualCloudDb_ = std::make_shared<VirtualCloudDb>();
    BasicUnitTest::SetUp();
}

void KVGeneralUt::TearDown()
{
    CloseAllDelegate();
    virtualCloudDb_ = nullptr;
    BasicUnitTest::TearDown();
}

int KVGeneralUt::InitDelegate(const StoreInfo &info)
{
    KvStoreDelegateManager manager(info.appId, info.userId);
    manager.SetKvStoreConfig(GetKvStoreConfig());
    KvStoreNbDelegate::Option option;
    std::lock_guard<std::mutex> autoLock(storeMutex_);
    if (option_.has_value()) {
        option = option_.value();
    }
    KvStoreNbDelegate *store = nullptr;
    DBStatus status = DBStatus::OK;
    manager.GetKvStore(info.storeId, option, [&status, &store](DBStatus ret, KvStoreNbDelegate *delegate) {
        status = ret;
        store = delegate;
    });
    if (status != DBStatus::OK) {
        LOGE("[KVGeneralUt] Init delegate failed %d", static_cast<int>(status));
        return -E_INTERNAL_ERROR;
    }
    stores_[info] = store;
    LOGI("[KVGeneralUt] Init delegate app %s store %s user %s success", info.appId.c_str(),
         info.storeId.c_str(), info.userId.c_str());
    return E_OK;
}

int KVGeneralUt::CloseDelegate(const StoreInfo &info)
{
    std::lock_guard<std::mutex> autoLock(storeMutex_);
    auto iter = stores_.find(info);
    if (iter == stores_.end()) {
        LOGW("[KVGeneralUt] Close not exist delegate app %s store %s user %s", info.appId.c_str(),
            info.storeId.c_str(), info.userId.c_str());
        return E_OK;
    }
    KvStoreDelegateManager manager(info.appId, info.userId);
    manager.SetKvStoreConfig(GetKvStoreConfig());
    auto ret = manager.CloseKvStore(iter->second);
    if (ret != DBStatus::OK) {
        LOGI("[KVGeneralUt] Close delegate app %s store %s user %s failed %d", info.appId.c_str(),
             info.storeId.c_str(), info.userId.c_str(), static_cast<int>(ret));
        return -E_INTERNAL_ERROR;
    }
    LOGI("[KVGeneralUt] Close delegate app %s store %s user %s success", info.appId.c_str(),
         info.storeId.c_str(), info.userId.c_str());
    stores_.erase(iter);
    return E_OK;
}

void KVGeneralUt::CloseAllDelegate()
{
    std::vector<StoreInfo> infoList;
    {
        std::lock_guard<std::mutex> autoLock(storeMutex_);
        for (const auto &item : stores_) {
            infoList.push_back(item.first);
        }
    }
    for (const auto &info : infoList) {
        (void)CloseDelegate(info);
    }
}

void KVGeneralUt::SetOption(const KvStoreNbDelegate::Option &option)
{
    std::lock_guard<std::mutex> autoLock(storeMutex_);
    option_ = option;
}

KvStoreConfig KVGeneralUt::GetKvStoreConfig()
{
    KvStoreConfig config;
    config.dataDir = GetTestDir();
    return config;
}

StoreInfo KVGeneralUt::GetStoreInfo1()
{
    StoreInfo info;
    info.userId = DistributedDBUnitTest::USER_ID;
    info.storeId = DistributedDBUnitTest::STORE_ID_1;
    info.appId = DistributedDBUnitTest::APP_ID;
    return info;
}

StoreInfo KVGeneralUt::GetStoreInfo2()
{
    StoreInfo info;
    info.userId = DistributedDBUnitTest::USER_ID;
    info.storeId = DistributedDBUnitTest::STORE_ID_2;
    info.appId = DistributedDBUnitTest::APP_ID;
    return info;
}

KvStoreNbDelegate *KVGeneralUt::GetDelegate(const DistributedDB::StoreInfo &info) const
{
    std::lock_guard<std::mutex> autoLock(storeMutex_);
    auto iter = stores_.find(info);
    if (iter == stores_.end()) {
        LOGW("[KVGeneralUt] Not exist delegate app %s store %s user %s", info.appId.c_str(),
            info.storeId.c_str(), info.userId.c_str());
        return nullptr;
    }
    return iter->second;
}

void KVGeneralUt::BlockPush(const StoreInfo &from, const StoreInfo &to, DBStatus expectRet)
{
    auto fromStore = GetDelegate(from);
    ASSERT_NE(fromStore, nullptr);
    auto toDevice  = GetDevice(to);
    ASSERT_FALSE(toDevice.empty());
    std::map<std::string, DBStatus> syncRet;
    tool_.SyncTest(fromStore, {toDevice}, SyncMode::SYNC_MODE_PUSH_ONLY, syncRet);
    for (const auto &item : syncRet) {
        EXPECT_EQ(item.second, expectRet);
    }
}

DataBaseSchema KVGeneralUt::GetDataBaseSchema(bool invalidSchema)
{
    DataBaseSchema schema;
    TableSchema tableSchema;
    tableSchema.name = invalidSchema ? "invalid_schema_name" : CloudDbConstant::CLOUD_KV_TABLE_NAME;
    Field field;
    field.colName = CloudDbConstant::CLOUD_KV_FIELD_KEY;
    field.type = TYPE_INDEX<std::string>;
    field.primary = true;
    tableSchema.fields.push_back(field);
    field.colName = CloudDbConstant::CLOUD_KV_FIELD_DEVICE;
    field.primary = false;
    tableSchema.fields.push_back(field);
    field.colName = CloudDbConstant::CLOUD_KV_FIELD_ORI_DEVICE;
    tableSchema.fields.push_back(field);
    field.colName = CloudDbConstant::CLOUD_KV_FIELD_VALUE;
    tableSchema.fields.push_back(field);
    field.colName = CloudDbConstant::CLOUD_KV_FIELD_DEVICE_CREATE_TIME;
    field.type = TYPE_INDEX<int64_t>;
    tableSchema.fields.push_back(field);
    schema.tables.push_back(tableSchema);
    return schema;
}

DBStatus KVGeneralUt::SetCloud(KvStoreNbDelegate *&delegate, bool invalidSchema)
{
    std::lock_guard<std::mutex> autoLock(storeMutex_);
    std::map<std::string, std::shared_ptr<ICloudDb>> cloudDbs;
    cloudDbs[DistributedDBUnitTest::USER_ID] = virtualCloudDb_;
    delegate->SetCloudDB(cloudDbs);
    std::map<std::string, DataBaseSchema> schemas;
    schemas[DistributedDBUnitTest::USER_ID] = GetDataBaseSchema(invalidSchema);
    return delegate->SetCloudDbSchema(schemas);
}

DBStatus KVGeneralUt::GetDeviceEntries(KvStoreNbDelegate *delegate, const std::string &deviceId, bool isSelfDevice,
    std::vector<Entry> &entries)
{
    if (isSelfDevice) {
        communicatorAggregator_->SetLocalDeviceId(deviceId);
    } else {
        communicatorAggregator_->SetLocalDeviceId(deviceId + "_");
    }
    return delegate->GetDeviceEntries(deviceId, entries);
}

void KVGeneralUt::BlockCloudSync(const StoreInfo &from, const std::string &deviceId, DBStatus expectRet)
{
    auto fromStore = GetDelegate(from);
    ASSERT_NE(fromStore, nullptr);

    communicatorAggregator_->SetLocalDeviceId(deviceId);
    CloudSyncOption syncOption;
    syncOption.mode = SyncMode::SYNC_MODE_CLOUD_MERGE;
    syncOption.users.push_back(DistributedDBUnitTest::USER_ID);
    syncOption.devices.push_back("cloud");
    tool_.BlockSync(fromStore, DBStatus::OK, syncOption, expectRet);
}
}