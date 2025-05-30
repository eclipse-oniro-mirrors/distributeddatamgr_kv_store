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
#include <gtest/gtest.h>

#include <utility>
#include "cloud/cloud_db_constant.h"
#include "cloud/cloud_db_data_utils.h"
#include "cloud/cloud_db_proxy.h"
#include "cloud/cloud_db_types.h"
#include "cloud/cloud_sync_utils.h"
#include "distributeddb_tools_unit_test.h"
#include "kv_store_errno.h"
#include "mock_icloud_sync_storage_interface.h"
#include "virtual_asset_loader.h"
#include "virtual_cloud_db.h"
#include "virtual_cloud_syncer.h"
#include "virtual_communicator_aggregator.h"

using namespace std;
using namespace testing::ext;
using namespace DistributedDB;

namespace {
constexpr const char *TABLE_NAME = "Table";
std::vector<Field> GetFields()
{
    return {
        {
            .colName = "col1",
            .type = TYPE_INDEX<int64_t>,
            .primary = true,
            .nullable = false
        },
        {
            .colName = "col2",
            .type = TYPE_INDEX<std::string>,
            .primary = false
        },
        {
            .colName = "col3",
            .type = TYPE_INDEX<Bytes>,
            .primary = false
        }
    };
}

void ModifyRecords(std::vector<VBucket> &expectRecord)
{
    std::vector<VBucket> tempRecord;
    for (const auto &record: expectRecord) {
        VBucket bucket;
        for (auto &[field, val] : record) {
            LOGD("modify field %s", field.c_str());
            if (val.index() == TYPE_INDEX<int64_t>) {
                int64_t v = std::get<int64_t>(val);
                bucket.insert({ field, static_cast<int64_t>(v + 1) });
            } else {
                bucket.insert({ field, val });
            }
        }
        tempRecord.push_back(bucket);
    }
    expectRecord = tempRecord;
}

DBStatus Sync(CloudSyncer *cloudSyncer, int &callCount)
{
    std::mutex processMutex;
    std::condition_variable cv;
    SyncProcess syncProcess;
    const auto callback = [&callCount, &syncProcess, &processMutex, &cv](
        const std::map<std::string, SyncProcess> &process) {
        {
            std::lock_guard<std::mutex> autoLock(processMutex);
            syncProcess = process.begin()->second;
            if (!process.empty()) {
                syncProcess = process.begin()->second;
            } else {
                SyncProcess tmpProcess;
                syncProcess = tmpProcess;
            }
            callCount++;
        }
        cv.notify_all();
    };
    EXPECT_EQ(cloudSyncer->Sync({ "cloud" }, SyncMode::SYNC_MODE_CLOUD_MERGE, { TABLE_NAME }, callback, 0), E_OK);
    {
        LOGI("begin to wait sync");
        std::unique_lock<std::mutex> uniqueLock(processMutex);
        cv.wait(uniqueLock, [&syncProcess]() {
            return syncProcess.process == ProcessStatus::FINISHED;
        });
        LOGI("end to wait sync");
    }
    return syncProcess.errCode;
}

class DistributedDBCloudDBProxyTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;

protected:
    std::shared_ptr<VirtualCloudDb> virtualCloudDb_ = nullptr;
    VirtualCommunicatorAggregator *communicatorAggregator_ = nullptr;
};

void DistributedDBCloudDBProxyTest::SetUpTestCase()
{
}

void DistributedDBCloudDBProxyTest::TearDownTestCase()
{
}

void DistributedDBCloudDBProxyTest::SetUp()
{
    DistributedDBUnitTest::DistributedDBToolsUnitTest::PrintTestCaseInfo();
    virtualCloudDb_ = std::make_shared<VirtualCloudDb>();
    communicatorAggregator_ = new (std::nothrow) VirtualCommunicatorAggregator();
    ASSERT_TRUE(communicatorAggregator_ != nullptr);
    RuntimeContext::GetInstance()->SetCommunicatorAggregator(communicatorAggregator_);
}

void DistributedDBCloudDBProxyTest::TearDown()
{
    virtualCloudDb_ = nullptr;
    RuntimeContext::GetInstance()->SetCommunicatorAggregator(nullptr);
    communicatorAggregator_ = nullptr;
    RuntimeContext::GetInstance()->SetProcessSystemApiAdapter(nullptr);
}

/**
 * @tc.name: CloudDBProxyTest001
 * @tc.desc: Verify cloud db init and close function.
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: zhangqiquan
 */
HWTEST_F(DistributedDBCloudDBProxyTest, CloudDBProxyTest001, TestSize.Level0)
{
    /**
     * @tc.steps: step1. set cloud db to proxy
     * @tc.expected: step1. E_OK
     */
    CloudDBProxy proxy;
    proxy.SetCloudDB(virtualCloudDb_);
    /**
     * @tc.steps: step2. proxy close cloud db with cloud error
     * @tc.expected: step2. -E_CLOUD_ERROR
     */
    virtualCloudDb_->SetCloudError(true);
    EXPECT_EQ(proxy.Close(), -E_CLOUD_ERROR);
    /**
     * @tc.steps: step3. proxy close cloud db again
     * @tc.expected: step3. E_OK because cloud db has been set nullptr
     */
    EXPECT_EQ(proxy.Close(), E_OK);
    virtualCloudDb_->SetCloudError(false);
    EXPECT_EQ(proxy.Close(), E_OK);
}

/**
 * @tc.name: CloudDBProxyTest002
 * @tc.desc: Verify cloud db insert function.
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: zhangqiquan
 */
HWTEST_F(DistributedDBCloudDBProxyTest, CloudDBProxyTest002, TestSize.Level0)
{
    /**
     * @tc.steps: step1. set cloud db to proxy
     * @tc.expected: step1. E_OK
     */
    CloudDBProxy proxy;
    proxy.SetCloudDB(virtualCloudDb_);
    /**
     * @tc.steps: step2. insert data to cloud db
     * @tc.expected: step2. OK
     */
    TableSchema schema = {
        .name = TABLE_NAME,
        .sharedTableName = "",
        .fields = GetFields()
    };
    std::vector<VBucket> expectRecords = CloudDBDataUtils::GenerateRecords(10, schema); // generate 10 records
    std::vector<VBucket> expectExtends = CloudDBDataUtils::GenerateExtends(10); // generate 10 extends
    Info uploadInfo;
    std::vector<VBucket> insert = expectRecords;
    uint32_t retryCount = 0;
    EXPECT_EQ(proxy.BatchInsert(TABLE_NAME, insert, expectExtends, uploadInfo, retryCount), E_OK);

    VBucket extend;
    extend[CloudDbConstant::CURSOR_FIELD] = std::string("");
    std::vector<VBucket> actualRecords;
    EXPECT_EQ(proxy.Query(TABLE_NAME, extend, actualRecords), -E_QUERY_END);
    /**
     * @tc.steps: step3. proxy query data
     * @tc.expected: step3. data is equal to expect
     */
    ASSERT_EQ(actualRecords.size(), expectRecords.size());
    for (size_t i = 0; i < actualRecords.size(); ++i) {
        for (const auto &field: schema.fields) {
            Type expect = expectRecords[i][field.colName];
            Type actual = actualRecords[i][field.colName];
            EXPECT_EQ(expect.index(), actual.index());
        }
    }
    /**
     * @tc.steps: step4. proxy close cloud db
     * @tc.expected: step4. E_OK
     */
    EXPECT_EQ(proxy.Close(), E_OK);
}

/**
 * @tc.name: CloudDBProxyTest003
 * @tc.desc: Verify cloud db update function.
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: zhangqiquan
 */
HWTEST_F(DistributedDBCloudDBProxyTest, CloudDBProxyTest003, TestSize.Level0)
{
    TableSchema schema = {
        .name = TABLE_NAME,
        .sharedTableName = "",
        .fields = GetFields()
    };
    /**
     * @tc.steps: step1. set cloud db to proxy
     * @tc.expected: step1. E_OK
     */
    CloudDBProxy proxy;
    proxy.SetCloudDB(virtualCloudDb_);
    /**
     * @tc.steps: step2. insert data to cloud db
     * @tc.expected: step2. OK
     */
    std::vector<VBucket> expectRecords = CloudDBDataUtils::GenerateRecords(10, schema); // generate 10 records
    std::vector<VBucket> expectExtends = CloudDBDataUtils::GenerateExtends(10); // generate 10 extends
    Info uploadInfo;
    std::vector<VBucket> insert = expectRecords;
    uint32_t retryCount = 0;
    EXPECT_EQ(proxy.BatchInsert(TABLE_NAME, insert, expectExtends, uploadInfo, retryCount), E_OK);
    /**
     * @tc.steps: step3. update data to cloud db
     * @tc.expected: step3. E_OK
     */
    ModifyRecords(expectRecords);
    std::vector<VBucket> update = expectRecords;
    EXPECT_EQ(proxy.BatchUpdate(TABLE_NAME, update, expectExtends, uploadInfo, retryCount), E_OK);
    /**
     * @tc.steps: step3. proxy close cloud db
     * @tc.expected: step3. E_OK
     */
    VBucket extend;
    extend[CloudDbConstant::CURSOR_FIELD] = std::string("");
    std::vector<VBucket> actualRecords;
    EXPECT_EQ(proxy.Query(TABLE_NAME, extend, actualRecords), -E_QUERY_END);
    ASSERT_EQ(actualRecords.size(), expectRecords.size());
    for (size_t i = 0; i < actualRecords.size(); ++i) {
        for (const auto &field: schema.fields) {
            Type expect = expectRecords[i][field.colName];
            Type actual = actualRecords[i][field.colName];
            EXPECT_EQ(expect.index(), actual.index());
        }
    }
    /**
     * @tc.steps: step4. proxy close cloud db
     * @tc.expected: step4. E_OK
     */
    EXPECT_EQ(proxy.Close(), E_OK);
}

/**
 * @tc.name: CloudDBProxyTest004
 * @tc.desc: Verify cloud db init and close function with multiple CloudDbs.
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: zhangtao
 */
HWTEST_F(DistributedDBCloudDBProxyTest, CloudDBProxyTest004, TestSize.Level0)
{
    /**
     * @tc.steps: step1. set cloud db to proxy
     * @tc.expected: step1. E_OK
     */
    CloudDBProxy proxy;
    std::string syncUserA = "SyncUserA";
    std::string syncUserB = "SyncUserB";
    std::string syncUserC = "SyncUserC";
    std::shared_ptr<VirtualCloudDb> virtualCloudDbB = std::make_shared<VirtualCloudDb>();
    std::shared_ptr<VirtualCloudDb> virtualCloudDbC = std::make_shared<VirtualCloudDb>();
    std::map<std::string, std::shared_ptr<ICloudDb>> cloudDBs = {
        {syncUserA, virtualCloudDb_}, {syncUserB, virtualCloudDbB}, {syncUserC, virtualCloudDbC}
    };
    proxy.SetCloudDB(cloudDBs);
    /**
     * @tc.steps: step2. proxy close cloud db with cloud error
     * @tc.expected: step2. -E_CLOUD_ERROR
     */
    for (const auto &pair : cloudDBs) {
        std::shared_ptr<ICloudDb> basePtr = pair.second;
        auto vtrPtr = static_cast<VirtualCloudDb*>(basePtr.get());
        vtrPtr->SetCloudError(true);
    }
    EXPECT_EQ(proxy.Close(), -E_CLOUD_ERROR);
    /**
     * @tc.steps: step3. proxy close cloud db again
     * @tc.expected: step3. E_OK because cloud db has been set nullptr
     */
    EXPECT_EQ(proxy.Close(), E_OK);
    for (const auto &pair : cloudDBs) {
        std::shared_ptr<ICloudDb> basePtr = pair.second;
        auto vtrPtr = static_cast<VirtualCloudDb*>(basePtr.get());
        vtrPtr->SetCloudError(false);
    }
    EXPECT_EQ(proxy.Close(), E_OK);
}

/**
 * @tc.name: CloudDBProxyTest005
 * @tc.desc: Verify sync failed after cloud error.
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: zhangqiquan
 */
HWTEST_F(DistributedDBCloudDBProxyTest, CloudDBProxyTest005, TestSize.Level0)
{
    /**
     * @tc.steps: step1. set cloud db to proxy and sleep 5s when download
     * @tc.expected: step1. E_OK
     */
    auto iCloud = std::make_shared<MockICloudSyncStorageInterface>();
    auto cloudSyncer = new(std::nothrow) VirtualCloudSyncer(StorageProxy::GetCloudDb(iCloud.get()));
    EXPECT_CALL(*iCloud, StartTransaction).WillRepeatedly(testing::Return(E_OK));
    EXPECT_CALL(*iCloud, Commit).WillRepeatedly(testing::Return(E_OK));
    ASSERT_NE(cloudSyncer, nullptr);
    cloudSyncer->SetCloudDB(virtualCloudDb_);
    cloudSyncer->SetSyncAction(true, false);
    virtualCloudDb_->SetCloudError(true);
    /**
     * @tc.steps: step2. call sync and wait sync finish
     * @tc.expected: step2. CLOUD_ERROR by lock error
     */
    int callCount = 0;
    EXPECT_EQ(Sync(cloudSyncer, callCount), CLOUD_ERROR);
    /**
     * @tc.steps: step3. get cloud lock status and heartbeat count
     * @tc.expected: step3. cloud is unlock and no heartbeat
     */
    EXPECT_FALSE(virtualCloudDb_->GetLockStatus());
    EXPECT_GE(virtualCloudDb_->GetHeartbeatCount(), 0);
    virtualCloudDb_->ClearHeartbeatCount();
    cloudSyncer->Close();
    RefObject::KillAndDecObjRef(cloudSyncer);
}

/**
 * @tc.name: CloudDBProxyTest008
 * @tc.desc: Verify cloud db heartbeat with diff status.
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: zhangqiquan
 */
HWTEST_F(DistributedDBCloudDBProxyTest, CloudDBProxyTest008, TestSize.Level0)
{
    /**
     * @tc.steps: step1. set cloud db to proxy
     * @tc.expected: step1. E_OK
     */
    CloudDBProxy proxy;
    proxy.SetCloudDB(virtualCloudDb_);
    /**
     * @tc.steps: step2. proxy heartbeat with diff status
     */
    virtualCloudDb_->SetActionStatus(CLOUD_NETWORK_ERROR);
    int errCode = proxy.HeartBeat();
    EXPECT_EQ(errCode, -E_CLOUD_NETWORK_ERROR);
    EXPECT_EQ(TransferDBErrno(errCode), CLOUD_NETWORK_ERROR);

    virtualCloudDb_->SetActionStatus(CLOUD_SYNC_UNSET);
    errCode = proxy.HeartBeat();
    EXPECT_EQ(errCode, -E_CLOUD_SYNC_UNSET);
    EXPECT_EQ(TransferDBErrno(errCode), CLOUD_SYNC_UNSET);

    virtualCloudDb_->SetActionStatus(CLOUD_FULL_RECORDS);
    errCode = proxy.HeartBeat();
    EXPECT_EQ(errCode, -E_CLOUD_FULL_RECORDS);
    EXPECT_EQ(TransferDBErrno(errCode), CLOUD_FULL_RECORDS);

    virtualCloudDb_->SetActionStatus(CLOUD_LOCK_ERROR);
    errCode = proxy.HeartBeat();
    EXPECT_EQ(errCode, -E_CLOUD_LOCK_ERROR);
    EXPECT_EQ(TransferDBErrno(errCode), CLOUD_LOCK_ERROR);

    virtualCloudDb_->SetActionStatus(DB_ERROR);
    errCode = proxy.HeartBeat();
    EXPECT_EQ(errCode, -E_CLOUD_ERROR);
    EXPECT_EQ(TransferDBErrno(errCode), CLOUD_ERROR);

    /**
     * @tc.steps: step3. proxy close cloud db
     * @tc.expected: step3. E_OK
     */
    EXPECT_EQ(proxy.Close(), E_OK);
}

/**
 * @tc.name: CloudDBProxyTest009
 * @tc.desc: Verify cloud db closed and current task exit .
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: zhangqiquan
 */
HWTEST_F(DistributedDBCloudDBProxyTest, CloudDBProxyTest009, TestSize.Level3)
{
    /**
     * @tc.steps: step1. set cloud db to proxy and sleep 5s when download
     * @tc.expected: step1. E_OK
     */
    auto iCloud = std::make_shared<MockICloudSyncStorageInterface>();
    ASSERT_NE(iCloud, nullptr);
    EXPECT_CALL(*iCloud, Commit).WillRepeatedly(testing::Return(E_OK));
    EXPECT_CALL(*iCloud, StartTransaction).WillRepeatedly(testing::Return(E_OK));
    EXPECT_CALL(*iCloud, Rollback).WillRepeatedly(testing::Return(E_OK));
    auto cloudSyncer = new(std::nothrow) VirtualCloudSyncer(StorageProxy::GetCloudDb(iCloud.get()));
    ASSERT_NE(cloudSyncer, nullptr);
    cloudSyncer->SetCloudDB(virtualCloudDb_);
    cloudSyncer->SetSyncAction(true, false);
    cloudSyncer->SetDownloadFunc([]() {
        std::this_thread::sleep_for(std::chrono::seconds(5)); // sleep 5s
        return -E_CLOUD_ERROR;
    });
    /**
     * @tc.steps: step2. call sync and wait sync finish
     * @tc.expected: step2. E_OK
     */
    std::mutex processMutex;
    bool finished = false;
    std::condition_variable cv;
    LOGI("[CloudDBProxyTest009] Call cloud sync");
    const auto callback = [&finished, &processMutex, &cv](const std::map<std::string, SyncProcess> &process) {
        {
            std::lock_guard<std::mutex> autoLock(processMutex);
            for (const auto &item: process) {
                if (item.second.process == DistributedDB::FINISHED) {
                    finished = true;
                    EXPECT_EQ(item.second.errCode, DB_CLOSED);
                }
            }
        }
        cv.notify_all();
    };
    EXPECT_EQ(cloudSyncer->Sync({ "cloud" }, SyncMode::SYNC_MODE_CLOUD_MERGE, { TABLE_NAME }, callback, 0), E_OK);
    std::this_thread::sleep_for(std::chrono::seconds(1));
    cloudSyncer->Close();
    {
        LOGI("[CloudDBProxyTest009] begin to wait sync");
        std::unique_lock<std::mutex> uniqueLock(processMutex);
        cv.wait_for(uniqueLock, std::chrono::milliseconds(DBConstant::MIN_TIMEOUT), [&finished]() {
            return finished;
        });
        LOGI("[CloudDBProxyTest009] end to wait sync");
    }
    RefObject::KillAndDecObjRef(cloudSyncer);
}

/**
 * @tc.name: CloudDBProxyTest010
 * @tc.desc: Verify cloud db lock with diff status.
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: zhangqiquan
 */
HWTEST_F(DistributedDBCloudDBProxyTest, CloudDBProxyTest010, TestSize.Level0)
{
    /**
     * @tc.steps: step1. set cloud db to proxy
     * @tc.expected: step1. E_OK
     */
    CloudDBProxy proxy;
    proxy.SetCloudDB(virtualCloudDb_);
    /**
     * @tc.steps: step2. proxy lock with diff status
     */
    virtualCloudDb_->SetActionStatus(CLOUD_NETWORK_ERROR);
    auto ret = proxy.Lock();
    EXPECT_EQ(ret.first, -E_CLOUD_NETWORK_ERROR);
    EXPECT_EQ(TransferDBErrno(ret.first), CLOUD_NETWORK_ERROR);

    virtualCloudDb_->SetActionStatus(CLOUD_LOCK_ERROR);
    ret = proxy.Lock();
    EXPECT_EQ(ret.first, -E_CLOUD_LOCK_ERROR);
    EXPECT_EQ(TransferDBErrno(ret.first), CLOUD_LOCK_ERROR);
    /**
     * @tc.steps: step3. proxy close cloud db
     * @tc.expected: step3. E_OK
     */
    EXPECT_EQ(proxy.Close(), E_OK);
}

/**
 * @tc.name: CloudDBProxyTest008
 * @tc.desc: Verify cloud db heartbeat with diff status.
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: zhangqiquan
 */
HWTEST_F(DistributedDBCloudDBProxyTest, CloudDBProxyTest011, TestSize.Level2)
{
    /**
     * @tc.steps: step1. set cloud db to proxy
     * @tc.expected: step1. E_OK
     */
    CloudDBProxy proxy;
    proxy.SetCloudDB(virtualCloudDb_);
    virtualCloudDb_->SetHeartbeatBlockTime(100); // block 100 ms
    std::mutex waitMutex;
    std::condition_variable waitCv;
    const int scheduleCount = 12;
    int currentCount = 0;
    for (int i = 0; i < scheduleCount; ++i) {
        RuntimeContext::GetInstance()->ScheduleTask([&proxy, &waitMutex, &waitCv, &currentCount]() {
            proxy.HeartBeat();
            {
                std::lock_guard<std::mutex> autoLock(waitMutex);
                currentCount++;
                LOGI("[CloudDBProxyTest011] CurrentCount %d", currentCount);
            }
            waitCv.notify_all();
        });
    }
    LOGI("[CloudDBProxyTest011] Begin wait all task finish");
    std::unique_lock<std::mutex> uniqueLock(waitMutex);
    waitCv.wait_for(uniqueLock, std::chrono::milliseconds(DBConstant::MAX_TIMEOUT), [&currentCount, scheduleCount]() {
        return currentCount >= scheduleCount;
    });
    LOGI("[CloudDBProxyTest011] End wait all task finish");
    EXPECT_EQ(currentCount, scheduleCount);
}

/**
 * @tc.name: CloudDBProxyTest012
 * @tc.desc: Asset data deduplication.
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: tankaisheng
 */
HWTEST_F(DistributedDBCloudDBProxyTest, CloudDBProxyTest012, TestSize.Level2)
{
    /**
     * @tc.steps: step1. construct data
     * @tc.expected: step1. E_OK
     */
    Assets assets;
    Asset asset1;
    asset1.name = "assetName1";
    asset1.assetId = "";
    asset1.modifyTime = "20240730";
    assets.push_back(asset1);

    Asset asset2;
    asset2.name = "assetName1";
    asset2.assetId = "1";
    asset2.modifyTime = "20240730";
    assets.push_back(asset2);

    Asset asset3;
    asset3.name = "assetName2";
    asset3.assetId = "2";
    asset3.modifyTime = "20240730";
    assets.push_back(asset3);

    Asset asset4;
    asset4.name = "assetName2";
    asset4.assetId = "3";
    asset4.modifyTime = "20240731";
    assets.push_back(asset4);

    Asset asset5;
    asset5.name = "assetName3";
    asset5.assetId = "4";
    asset5.modifyTime = "20240730";
    assets.push_back(asset5);

    Asset asset6;
    asset6.name = "assetName3";
    asset6.assetId = "5";
    asset6.modifyTime = "20240730";
    assets.push_back(asset6);

    Asset asset7;
    asset7.name = "assetName1";
    asset7.assetId = "6";
    asset7.modifyTime = "20240731";
    assets.push_back(asset7);

    DBCommon::RemoveDuplicateAssetsData(assets);

    /**
     * @tc.steps: step2. check data
     * @tc.expected: step2. E_OK
     */
    std::string assetNameArr[] = {"assetName2", "assetName3", "assetName1"};
    std::string assetIdArr[] = {"3", "5", "6"};
    EXPECT_EQ(assets.size(), 3u);
    for (std::vector<DistributedDB::Asset>::size_type i = 0; i < assets.size(); ++i) {
        EXPECT_EQ(assets.at(i).name, assetNameArr[i]);
        EXPECT_EQ(assets.at(i).assetId, assetIdArr[i]);
    }
}

/**
 * @tc.name: CloudDBProxyTest014
 * @tc.desc: Test asset deduplication with empty assetId.
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: liaoyonghuang
 */
HWTEST_F(DistributedDBCloudDBProxyTest, CloudDBProxyTest014, TestSize.Level0)
{
    /**
     * @tc.steps: step1. set cloud db to proxy
     * @tc.expected: step1. E_OK
     */
    Assets assets;
    Asset asset1;
    asset1.name = "assetName";
    asset1.assetId = "";
    asset1.modifyTime = "1";
    assets.push_back(asset1);

    Asset asset2;
    asset2.name = "assetName";
    asset2.assetId = "";
    asset2.modifyTime = "3";
    assets.push_back(asset2);

    Asset asset3;
    asset3.name = "assetName";
    asset3.assetId = "";
    asset3.modifyTime = "2";
    assets.push_back(asset3);

    /**
     * @tc.steps: step2. Remove duplicate assets and check data
     * @tc.expected: step2. E_OK
     */
    DBCommon::RemoveDuplicateAssetsData(assets);
    ASSERT_EQ(assets.size(), 1u);
    EXPECT_EQ(assets[0].modifyTime, "3");
}

/**
 * @tc.name: CloudSyncQueue001
 * @tc.desc: Verify sync task count decrease after sync finished.
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: zhangqiquan
 */
HWTEST_F(DistributedDBCloudDBProxyTest, CloudSyncQueue001, TestSize.Level2)
{
    /**
     * @tc.steps: step1. set cloud db to proxy and sleep 5s when download
     * @tc.expected: step1. E_OK
     */
    auto iCloud = std::make_shared<MockICloudSyncStorageInterface>();
    ASSERT_NE(iCloud, nullptr);
    auto cloudSyncer = new(std::nothrow) VirtualCloudSyncer(StorageProxy::GetCloudDb(iCloud.get()));
    ASSERT_NE(cloudSyncer, nullptr);
    EXPECT_CALL(*iCloud, Rollback).WillRepeatedly(testing::Return(E_OK));
    EXPECT_CALL(*iCloud, Commit).WillRepeatedly(testing::Return(E_OK));
    EXPECT_CALL(*iCloud, StartTransaction).WillRepeatedly(testing::Return(E_OK));
    cloudSyncer->SetCloudDB(virtualCloudDb_);
    cloudSyncer->SetSyncAction(true, false);
    cloudSyncer->SetDownloadFunc([cloudSyncer]() {
        EXPECT_EQ(cloudSyncer->GetQueueCount(), 1u);
        std::this_thread::sleep_for(std::chrono::seconds(2)); // sleep 2s
        return E_OK;
    });
    /**
     * @tc.steps: step2. call sync and wait sync finish
     */
    int callCount = 0;
    EXPECT_EQ(Sync(cloudSyncer, callCount), OK);
    RuntimeContext::GetInstance()->StopTaskPool();
    EXPECT_EQ(callCount, 1);
    RefObject::KillAndDecObjRef(cloudSyncer);
}

/**
 * @tc.name: CloudSyncQueue002
 * @tc.desc: Verify sync task abort after close.
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: zhangqiquan
 */
HWTEST_F(DistributedDBCloudDBProxyTest, CloudSyncQueue002, TestSize.Level2)
{
    /**
     * @tc.steps: step1. set cloud db to proxy and sleep 2s when download
     * @tc.expected: step1. E_OK
     */
    auto iCloud = std::make_shared<MockICloudSyncStorageInterface>();
    ASSERT_NE(iCloud, nullptr);
    EXPECT_CALL(*iCloud, Rollback).WillRepeatedly(testing::Return(E_OK));
    EXPECT_CALL(*iCloud, Commit).WillRepeatedly(testing::Return(E_OK));
    EXPECT_CALL(*iCloud, StartTransaction).WillRepeatedly(testing::Return(E_OK));
    auto cloudSyncer = new(std::nothrow) VirtualCloudSyncer(StorageProxy::GetCloudDb(iCloud.get()));
    ASSERT_NE(cloudSyncer, nullptr);
    cloudSyncer->SetCloudDB(virtualCloudDb_);
    cloudSyncer->SetSyncAction(true, false);
    std::atomic<bool> close = false;
    cloudSyncer->SetDownloadFunc([cloudSyncer, &close]() {
        std::this_thread::sleep_for(std::chrono::seconds(2)); // sleep 2s
        cloudSyncer->PauseCurrentTask();
        EXPECT_TRUE(close);
        return -E_TASK_PAUSED;
    });
    /**
     * @tc.steps: step2. call sync and wait sync finish
     */
    EXPECT_EQ(cloudSyncer->Sync({ "cloud" }, SyncMode::SYNC_MODE_CLOUD_MERGE, { TABLE_NAME }, nullptr, 0), E_OK);
    std::this_thread::sleep_for(std::chrono::seconds(1));
    close = true;
    cloudSyncer->Close();
    RuntimeContext::GetInstance()->StopTaskPool();
    RefObject::KillAndDecObjRef(cloudSyncer);
}

/**
 * @tc.name: CloudSyncerTest001
 * @tc.desc: Verify syncer notify by queue schedule.
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: zhangqiquan
 */
HWTEST_F(DistributedDBCloudDBProxyTest, CloudSyncerTest001, TestSize.Level2)
{
    /**
     * @tc.steps: step1. set cloud db to proxy
     * @tc.expected: step1. E_OK
     */
    auto iCloud = std::make_shared<MockICloudSyncStorageInterface>();
    EXPECT_CALL(*iCloud, StartTransaction).WillRepeatedly(testing::Return(E_OK));
    EXPECT_CALL(*iCloud, Commit).WillRepeatedly(testing::Return(E_OK));
    EXPECT_CALL(*iCloud, GetIdentify).WillRepeatedly(testing::Return("CloudSyncerTest001"));
    auto cloudSyncer = new(std::nothrow) VirtualCloudSyncer(StorageProxy::GetCloudDb(iCloud.get()));
    std::atomic<int> callCount = 0;
    std::condition_variable cv;
    cloudSyncer->SetCurrentTaskInfo([&callCount, &cv](const std::map<std::string, SyncProcess> &) {
        callCount++;
        int before = callCount;
        LOGD("on callback %d", before);
        std::this_thread::sleep_for(std::chrono::seconds(1));
        EXPECT_EQ(before, callCount);
        cv.notify_all();
    }, 1u);
    const int notifyCount = 2;
    for (int i = 0; i < notifyCount; ++i) {
        cloudSyncer->Notify();
    }
    cloudSyncer->SetCurrentTaskInfo(nullptr, 0); // 0 is invalid task id
    std::mutex processMutex;
    std::unique_lock<std::mutex> uniqueLock(processMutex);
    cv.wait_for(uniqueLock, std::chrono::milliseconds(DBConstant::MIN_TIMEOUT), [&callCount]() {
        return callCount == notifyCount;
    });
    cloudSyncer->Close();
    RefObject::KillAndDecObjRef(cloudSyncer);
}

/**
 * @tc.name: SameBatchTest001
 * @tc.desc: Verify update cache in same batch.
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: zhangqiquan
 */
HWTEST_F(DistributedDBCloudDBProxyTest, SameBatchTest001, TestSize.Level0)
{
    std::map<std::string, LogInfo> localLogInfoCache;
    LogInfo cloudInfo;
    LogInfo localInfo;
    localInfo.hashKey = {'k'};
    cloudInfo.cloudGid = "gid";
    /**
     * @tc.steps: step1. insert cloud into local
     * @tc.expected: step1. local cache has gid
     */
    CloudSyncUtils::UpdateLocalCache(OpType::INSERT, cloudInfo, localInfo, localLogInfoCache);
    std::string hashKey(localInfo.hashKey.begin(), localInfo.hashKey.end());
    EXPECT_EQ(localLogInfoCache[hashKey].cloudGid, cloudInfo.cloudGid);
    /**
     * @tc.steps: step2. delete local
     * @tc.expected: step2. local flag is delete
     */
    CloudSyncUtils::UpdateLocalCache(OpType::DELETE, cloudInfo, localInfo, localLogInfoCache);
    EXPECT_EQ(localLogInfoCache[hashKey].flag, static_cast<uint64_t>(LogInfoFlag::FLAG_DELETE));
}

/**
 * @tc.name: SameBatchTest002
 * @tc.desc: Verify cal opType in same batch.
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: zhangqiquan
 */
HWTEST_F(DistributedDBCloudDBProxyTest, SameBatchTest002, TestSize.Level0)
{
    /**
     * @tc.steps: step1. prepare two data with same pk
     */
    ICloudSyncer::SyncParam param;
    param.downloadData.opType.push_back(OpType::INSERT);
    param.downloadData.opType.push_back(OpType::UPDATE);
    const std::string pkField = "pk";
    param.changedData.field.push_back(pkField);
    VBucket oneRow;
    oneRow[pkField] = static_cast<int64_t>(1); // 1 is pk
    param.downloadData.data.push_back(oneRow);
    param.downloadData.data.push_back(oneRow);
    /**
     * @tc.steps: step2. cal opType by utils
     * @tc.expected: step2. all type should be INSERT
     */
    for (size_t i = 0; i < param.downloadData.data.size(); ++i) {
        EXPECT_EQ(CloudSyncUtils::CalOpType(param, i), OpType::INSERT);
    }
    /**
     * @tc.steps: step3. cal opType by utils
     * @tc.expected: step3. should be UPDATE because diff pk
     */
    oneRow[pkField] = static_cast<int64_t>(2); // 2 is pk
    param.downloadData.data.push_back(oneRow);
    param.downloadData.opType.push_back(OpType::UPDATE);
    // index start with zero
    EXPECT_EQ(CloudSyncUtils::CalOpType(param, param.downloadData.data.size() - 1), OpType::UPDATE);
}

/**
 * @tc.name: CloudDBProxyTest013
 * @tc.desc: Verify CloudDBProxy interfaces.
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: suyue
 */
HWTEST_F(DistributedDBCloudDBProxyTest, CloudDBProxyTest013, TestSize.Level0)
{
    /**
     * @tc.steps: step1. call CloudDBProxy interfaces when ICloudDb is nullptr.
     * @tc.expected: step1. return -E_CLOUD_ERROR.
     */
    CloudDBProxy proxy;
    int ret = proxy.UnLock();
    EXPECT_EQ(ret, -E_CLOUD_ERROR);
    ret = proxy.HeartBeat();
    EXPECT_EQ(ret, -E_CLOUD_ERROR);
    VBucket extend;
    const std::string tableName = "test";
    std::vector<VBucket> record;
    ret = proxy.Query(tableName, extend, record);
    EXPECT_EQ(ret, -E_CLOUD_ERROR);
    Info info;
    uint32_t retryCount = 0;
    ret = proxy.BatchInsert(tableName, record, record, info, retryCount);
    EXPECT_EQ(ret, -E_CLOUD_ERROR);
    ret = proxy.BatchUpdate(tableName, record, record, info, retryCount);
    EXPECT_EQ(ret, -E_CLOUD_ERROR);
    ret = proxy.BatchDelete(tableName, record, record, info, retryCount);
    EXPECT_EQ(ret, -E_CLOUD_ERROR);
    std::pair<int, uint64_t> res = proxy.Lock();
    EXPECT_EQ(res.first, -E_CLOUD_ERROR);
    std::pair<int, std::string> cursor = proxy.GetEmptyCursor(tableName);
    EXPECT_EQ(cursor.first, -E_CLOUD_ERROR);

    /**
     * @tc.steps: step2. call CloudDBProxy interfaces when para is err.
     * @tc.expected: step2. return fail.
     */
    std::pair<int, std::string> ver = proxy.GetCloudVersion("test");
    EXPECT_EQ(ver.first, -E_NOT_SUPPORT);
    std::vector<Asset> assets;
    ret = proxy.RemoveLocalAssets(assets);
    EXPECT_EQ(ret, -E_OK);
    assets = {{}};
    ret = proxy.RemoveLocalAssets(assets);
    EXPECT_EQ(ret, -E_OK);
}

/**
 * @tc.name: CloudDBProxyTest015
 * @tc.desc: Verify CloudDBProxy BatchDownload interfaces.
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: liuhongyang
 */
HWTEST_F(DistributedDBCloudDBProxyTest, CloudDBProxyTest015, TestSize.Level0)
{
    CloudDBProxy proxy;
    
    const Asset a1 = {
    .version = 1, .name = "Phone", .assetId = "0", .subpath = "/local/sync", .uri = "/local/sync",
    .modifyTime = "123456", .createTime = "", .size = "256", .hash = "ASE"
    };
    const Asset a2 = {
        .version = 2, .name = "Phone", .assetId = "0", .subpath = "/local/sync", .uri = "/cloud/sync",
        .modifyTime = "123456", .createTime = "0", .size = "1024", .hash = "DEC"
    };
    Assets assets1;
    Assets assets2;
    assets1.push_back(a1);
    assets2.push_back(a2);

    IAssetLoader::AssetRecord emptyR1 = {"r1", "pre"};
    IAssetLoader::AssetRecord nonEmptyR2 = {"r2", "pre", {{"a1", assets1}}};
    IAssetLoader::AssetRecord emptyR3 = {"r3", "pre"};
    IAssetLoader::AssetRecord nonEmptyR4 = {"r4", "pre", {{"a2", assets2}}};
    size_t uintExpected = 0;
    /**
     * @tc.steps: step1. call CloudDBProxy BatchDownload when iAssetLoader_ is nullptr and no records has assets
     * @tc.expected: step1. return E_OK.
     */
    std::vector<IAssetLoader::AssetRecord> downloadAssets;
    int ret = proxy.BatchDownload(TABLE_NAME, downloadAssets);
    EXPECT_EQ(downloadAssets.size(), uintExpected);
    EXPECT_EQ(ret, E_OK);
    
    downloadAssets.push_back(emptyR1);
    ret = proxy.BatchDownload(TABLE_NAME, downloadAssets);
    uintExpected = 1;
    EXPECT_EQ(downloadAssets.size(), uintExpected);
    EXPECT_EQ(ret, E_OK);

    /**
     * @tc.steps: step2. call CloudDBProxy BatchDownload when iAssetLoader_ is nullptr and some records has assets
     * @tc.expected: step2. return -E_NOT_SET.
     */
    downloadAssets.push_back(nonEmptyR2);
    ret = proxy.BatchDownload(TABLE_NAME, downloadAssets);
    uintExpected = 2;
    EXPECT_EQ(downloadAssets.size(), uintExpected);
    EXPECT_EQ(ret, -E_NOT_SET);

    /**
     * @tc.steps: step3. call CloudDBProxy BatchDownload and make iAssetLoader_ change the assets and status
     * @tc.expected: step3. return E_OK, and status are changed in original vectors
     */
    int totalRecordsUsed = 0; // number of records passed to loader
    std::shared_ptr<VirtualAssetLoader> virtialAssetLoader = make_shared<VirtualAssetLoader>();
    virtialAssetLoader->ForkBatchDownload([&totalRecordsUsed](int rowIndex, std::map<std::string, Assets> &assets) {
        totalRecordsUsed++;
        for (auto &asset : assets) {
            if (asset.first == "a1") {
                return DB_ERROR;
            }
            if (asset.first == "a2") {
                asset.second[0].version = 3;
                return NOT_FOUND;
            }
        }
        return OK;
    });
    proxy.SetIAssetLoader(virtialAssetLoader);
    downloadAssets.push_back(emptyR3);
    downloadAssets.push_back(nonEmptyR4);
    uintExpected = 4;
    EXPECT_EQ(downloadAssets.size(), uintExpected);

    ret = proxy.BatchDownload(TABLE_NAME, downloadAssets);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(virtialAssetLoader->GetBatchDownloadCount(), 1u);
    EXPECT_EQ(totalRecordsUsed, 2);
    EXPECT_EQ(downloadAssets[0].status, OK);
    EXPECT_EQ(downloadAssets[1].status, DB_ERROR);
    EXPECT_EQ(downloadAssets[2].status, OK);
    EXPECT_EQ(downloadAssets[3].status, NOT_FOUND);
    uintExpected = 3;
    EXPECT_EQ(downloadAssets[3].assets["a2"][0].version, uintExpected);
}

/**
 * @tc.name: CloudDBProxyTest016
 * @tc.desc: Verify cancel download
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: zqq
 */
HWTEST_F(DistributedDBCloudDBProxyTest, CloudDBProxyTest016, TestSize.Level0)
{
    auto proxy = std::make_shared<CloudDBProxy>();
    auto loader = make_shared<VirtualAssetLoader>();
    proxy->SetIAssetLoader(loader);
    proxy->CancelDownload();
    EXPECT_EQ(loader->GetCancelCount(), 0u);
}

/**
 * @tc.name: CloudSyncUtilsTest
 * @tc.desc: Verify CloudSyncUtils interfaces
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: suyue
 */
HWTEST_F(DistributedDBCloudDBProxyTest, CloudSyncUtilsTest, TestSize.Level0)
{
    /**
     * @tc.steps: step1. Test type translation interfaces.
     * @tc.expected: step1. success.
     */
    CloudSyncUtils utilsObj;
    EXPECT_EQ(utilsObj.StatusToFlag(AssetStatus::INSERT), AssetOpType::INSERT);
    EXPECT_EQ(utilsObj.StatusToFlag(AssetStatus::DELETE), AssetOpType::DELETE);
    EXPECT_EQ(utilsObj.StatusToFlag(AssetStatus::UPDATE), AssetOpType::UPDATE);
    EXPECT_EQ(utilsObj.StatusToFlag(AssetStatus::NORMAL), AssetOpType::NO_CHANGE);
    EXPECT_EQ(utilsObj.StatusToFlag(AssetStatus::DOWNLOADING), AssetOpType::NO_CHANGE);
    EXPECT_EQ(utilsObj.OpTypeToChangeType(OpType::ONLY_UPDATE_GID), ChangeType::OP_BUTT);

    /**
     * @tc.steps: step2. call CloudSyncUtils interfaces when para is err.
     * @tc.expected: step2. return false.
     */
    const std::vector<DeviceID> devices = {"test"};
    int mode = 10; // set metaMode to 10 not in enum class MetaMode
    int ret = utilsObj.CheckParamValid(devices, static_cast<SyncMode>(mode));
    EXPECT_EQ(ret, -E_INVALID_ARGS);
    VBucket record;
    const std::vector<std::string> pkColNames;
    std::vector<Type> cloudPkVals = {{}};
    ret = utilsObj.GetCloudPkVals(record, pkColNames, 0, cloudPkVals);
    EXPECT_EQ(ret, -E_INVALID_ARGS);
    Assets assets = {{}};
    utilsObj.StatusToFlagForAssets(assets);
    std::vector<Field> fields = {{"test", TYPE_INDEX<Assets>, true, true}};
    utilsObj.StatusToFlagForAssetsInRecord(fields, record);
    Timestamp timestamp;
    CloudSyncData uploadData;
    const int64_t count = 0;
    ret = utilsObj.UpdateExtendTime(uploadData, count, 0, timestamp);
    EXPECT_EQ(ret, -E_INTERNAL_ERROR);
    CloudSyncBatch data;
    data.assets = {{}};
    ret = utilsObj.FillAssetIdToAssets(data, 0, CloudWaterType::UPDATE);
    EXPECT_EQ(ret, -E_CLOUD_ERROR);

    /**
     * @tc.steps: step3. call IsChangeDataEmpty interface when para is different.
     * @tc.expected: step3. success.
     */
    ChangedData changedData;
    EXPECT_EQ(utilsObj.IsChangeDataEmpty(changedData), true);
    changedData.primaryData[OP_INSERT] = {{}};
    EXPECT_EQ(utilsObj.IsChangeDataEmpty(changedData), true);
    changedData.primaryData[OP_UPDATE] = {{}};
    EXPECT_EQ(utilsObj.IsChangeDataEmpty(changedData), true);
    changedData.primaryData[OP_DELETE] = {{}};
    EXPECT_EQ(utilsObj.IsChangeDataEmpty(changedData), false);
}
}