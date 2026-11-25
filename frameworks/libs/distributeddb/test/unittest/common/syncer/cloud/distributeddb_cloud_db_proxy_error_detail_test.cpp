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

#include <gtest/gtest.h>

#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "cloud/cloud_db_constant.h"
#include "cloud/cloud_db_proxy.h"
#include "cloud/iAssetLoader.h"
#include "cloud/icloud_db.h"
#include "db_constant.h"
#include "db_errno.h"
#include "distributeddb_tools_unit_test.h"
#include "store_types.h"
#include "virtual_asset_loader.h"
#include "virtual_cloud_db.h"

using namespace testing::ext;
using namespace DistributedDBUnitTest;
using namespace DistributedDB;

namespace {
constexpr const char *TABLE_NAME = "TestTable";

const Asset ASSET_FOR_DETAIL = { .version = 1,
    .name = "Phone",
    .assetId = "1",
    .subpath = "/local/sync",
    .uri = "/local/sync",
    .modifyTime = "123456",
    .createTime = "",
    .size = "256",
    .hash = "ASE" };

// virtual cloud db which returns a controllable external error detail and action statuses
class ErrorDetailCloudDb : public VirtualCloudDb {
public:
    ErrorDetailCloudDb() = default;
    ~ErrorDetailCloudDb() override = default;

    void SetErrorDetailToReturn(const ErrorDetail &errorDetail)
    {
        errorDetail_ = errorDetail;
    }

    ErrorDetail GetErrorDetail() const override
    {
        return errorDetail_;
    }

    void SetCursorStatus(const std::pair<DBStatus, std::string> &cursorStatus)
    {
        cursorStatus_ = cursorStatus;
    }

    std::pair<DBStatus, std::string> GetEmptyCursor(const std::string &tableName) override
    {
        (void)tableName;
        return cursorStatus_;
    }

    void SetStopStatus(DBStatus status)
    {
        stopStatus_ = status;
    }

    DBStatus StopCloudSync() override
    {
        return stopStatus_;
    }

    void SetQueryAllGidStatus(DBStatus status)
    {
        queryAllGidStatus_ = status;
    }

    DBStatus QueryAllGid(const std::string &tableName, VBucket &extend, std::vector<VBucket> &data) override
    {
        (void)tableName;
        (void)extend;
        (void)data;
        return queryAllGidStatus_;
    }

private:
    ErrorDetail errorDetail_;
    std::pair<DBStatus, std::string> cursorStatus_ = { OK, "0" };
    DBStatus stopStatus_ = OK;
    DBStatus queryAllGidStatus_ = OK;
};

// virtual asset loader which returns a controllable external error detail
class ErrorDetailAssetLoader : public VirtualAssetLoader {
public:
    ErrorDetailAssetLoader() = default;
    ~ErrorDetailAssetLoader() override = default;

    void SetErrorDetailToReturn(const ErrorDetail &errorDetail)
    {
        errorDetail_ = errorDetail;
    }

    ErrorDetail GetErrorDetail() const override
    {
        return errorDetail_;
    }

private:
    ErrorDetail errorDetail_;
};

// derived proxy to expose the protected fetch helpers and the action context
class TestCloudDBProxy : public CloudDBProxy {
public:
    TestCloudDBProxy() = default;
    ~TestCloudDBProxy() = default;

    static void CallFetchErrorDetailFromCloudDb(const std::shared_ptr<ICloudDb> &cloudDb, DBStatus status,
        ErrorDetail &errorDetail)
    {
        CloudDBProxy::FetchErrorDetailFromCloudDb(cloudDb, status, errorDetail);
    }

    static void CallFetchErrorDetailFromAssetLoader(const std::shared_ptr<IAssetLoader> &loader, DBStatus status,
        ErrorDetail &errorDetail)
    {
        CloudDBProxy::FetchErrorDetailFromAssetLoader(loader, status, errorDetail);
    }

    static void CallFetchErrorDetailFromAssetRecords(const std::shared_ptr<IAssetLoader> &loader,
        const std::vector<IAssetLoader::AssetRecord> &records, ErrorDetail &errorDetail)
    {
        CloudDBProxy::FetchErrorDetailFromAssetRecords(loader, records, errorDetail);
    }

    // set the error detail into the action context then move it out twice to check move semantics
    static std::pair<ErrorDetail, ErrorDetail> CloudActionContextDetailMoveCheck(const ErrorDetail &errorDetail)
    {
        CloudDBProxy::CloudActionContext context;
        context.SetErrorDetail(errorDetail);
        ErrorDetail firstDetail;
        context.MoveOutErrorDetail(firstDetail);
        ErrorDetail secondDetail;
        context.MoveOutErrorDetail(secondDetail);
        return { firstDetail, secondDetail };
    }

    // set the error detail twice without move out, the last one should be kept
    static ErrorDetail CloudActionContextDetailOverwriteCheck(const ErrorDetail &firstDetail,
        const ErrorDetail &secondDetail)
    {
        CloudDBProxy::CloudActionContext context;
        context.SetErrorDetail(firstDetail);
        context.SetErrorDetail(secondDetail);
        ErrorDetail movedDetail;
        context.MoveOutErrorDetail(movedDetail);
        return movedDetail;
    }
};

CloudSyncBatch BuildOneRecordBatch()
{
    CloudSyncBatch batch;
    VBucket record;
    record[CloudDbConstant::GID_FIELD] = std::string("0");
    record[CloudDbConstant::MODIFY_FIELD] = static_cast<int64_t>(1);
    batch.record.push_back(record);
    VBucket extend;
    extend[CloudDbConstant::DELETE_FIELD] = false; // insert extends must not carry a gid
    batch.extend.push_back(extend);
    return batch;
}

// assert the error detail keeps the not-set default: detailCode 0 and empty message, shared by
// the proxy interfaces that must keep the detail unset when the cloud db or loader is absent
void ExpectDetailNotSet(const ErrorDetail &detail)
{
    EXPECT_EQ(detail.detailCode, 0u);
    EXPECT_TRUE(detail.errorMessage.empty());
}
}

class DistributedDBCloudDBProxyErrorDetailTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void DistributedDBCloudDBProxyErrorDetailTest::SetUpTestCase()
{
}

void DistributedDBCloudDBProxyErrorDetailTest::TearDownTestCase()
{
}

void DistributedDBCloudDBProxyErrorDetailTest::SetUp()
{
    DistributedDBToolsUnitTest::PrintTestCaseInfo();
}

void DistributedDBCloudDBProxyErrorDetailTest::TearDown()
{
}

/**
 * @tc.name: CloudDBProxyErrorDetail001
 * @tc.desc: Verify proxy batch insert fetches error detail from cloud db on failure.
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: ztx
 */
HWTEST_F(DistributedDBCloudDBProxyErrorDetailTest, CloudDBProxyErrorDetail001, TestSize.Level1)
{
    /**
     * @tc.steps: step1. cloud db returns cloud error with an external error detail
     * @tc.expected: step1. proxy returns -E_CLOUD_ERROR and moves out the external detail
     */
    CloudDBProxy proxy;
    auto cloudDb = std::make_shared<ErrorDetailCloudDb>();
    cloudDb->SetCloudError(true);
    cloudDb->SetErrorDetailToReturn({ 0x400101u, "cloud insert failed" });
    proxy.SetCloudDB(cloudDb);
    CloudSyncBatch batch = BuildOneRecordBatch();
    Info uploadInfo;
    uint32_t retryCount = 0;
    ErrorDetail errorDetail;
    EXPECT_EQ(proxy.BatchInsert(TABLE_NAME, batch, uploadInfo, retryCount, errorDetail), -E_CLOUD_ERROR);
    EXPECT_EQ(errorDetail.detailCode, 0x400101u);
    EXPECT_EQ(errorDetail.errorMessage, "cloud insert failed");
    /**
     * @tc.steps: step2. cloud db returns ok without touching the detail
     * @tc.expected: step2. proxy returns E_OK and the detail keeps not set
     */
    cloudDb->SetCloudError(false);
    batch = BuildOneRecordBatch(); // the failed insert consumed the records, rebuild the batch
    ErrorDetail successDetail;
    EXPECT_EQ(proxy.BatchInsert(TABLE_NAME, batch, uploadInfo, retryCount, successDetail), E_OK);
    EXPECT_EQ(successDetail.detailCode, 0u);
    EXPECT_TRUE(successDetail.errorMessage.empty());
}

/**
 * @tc.name: CloudDBProxyErrorDetail002
 * @tc.desc: Verify proxy batch update and batch delete fetch error detail on failure.
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: ztx
 */
HWTEST_F(DistributedDBCloudDBProxyErrorDetailTest, CloudDBProxyErrorDetail002, TestSize.Level1)
{
    /**
     * @tc.steps: step1. batch update fails with cloud error
     * @tc.expected: step1. proxy returns -E_CLOUD_ERROR with the external detail
     */
    CloudDBProxy proxy;
    auto cloudDb = std::make_shared<ErrorDetailCloudDb>();
    cloudDb->SetCloudError(true);
    cloudDb->SetErrorDetailToReturn({ 0x400102u, "cloud update failed" });
    proxy.SetCloudDB(cloudDb);
    CloudSyncBatch batch = BuildOneRecordBatch();
    Info uploadInfo;
    uint32_t retryCount = 0;
    ErrorDetail updateDetail;
    EXPECT_EQ(proxy.BatchUpdate(TABLE_NAME, batch, uploadInfo, retryCount, updateDetail), -E_CLOUD_ERROR);
    EXPECT_EQ(updateDetail.detailCode, 0x400102u);
    EXPECT_EQ(updateDetail.errorMessage, "cloud update failed");
    /**
     * @tc.steps: step2. batch delete fails with cloud error
     * @tc.expected: step2. proxy returns -E_CLOUD_ERROR with the external detail
     */
    cloudDb->SetErrorDetailToReturn({ 0x400103u, "cloud delete failed" });
    ErrorDetail deleteDetail;
    EXPECT_EQ(proxy.BatchDelete(TABLE_NAME, batch, uploadInfo, retryCount, deleteDetail), -E_CLOUD_ERROR);
    EXPECT_EQ(deleteDetail.detailCode, 0x400103u);
    EXPECT_EQ(deleteDetail.errorMessage, "cloud delete failed");
}

/**
 * @tc.name: CloudDBProxyErrorDetail003
 * @tc.desc: Verify proxy query fetches error detail on failure but not on query end.
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: ztx
 */
HWTEST_F(DistributedDBCloudDBProxyErrorDetailTest, CloudDBProxyErrorDetail003, TestSize.Level1)
{
    /**
     * @tc.steps: step1. query fails with cloud error
     * @tc.expected: step1. proxy returns -E_CLOUD_ERROR with the external detail
     */
    CloudDBProxy proxy;
    auto cloudDb = std::make_shared<ErrorDetailCloudDb>();
    cloudDb->SetCloudError(true);
    cloudDb->SetErrorDetailToReturn({ 0x400104u, "cloud query failed" });
    proxy.SetCloudDB(cloudDb);
    VBucket extend;
    extend[CloudDbConstant::CURSOR_FIELD] = std::string("");
    std::vector<VBucket> data;
    ErrorDetail errorDetail;
    EXPECT_EQ(proxy.Query(TABLE_NAME, extend, data, errorDetail), -E_CLOUD_ERROR);
    EXPECT_EQ(errorDetail.detailCode, 0x400104u);
    EXPECT_EQ(errorDetail.errorMessage, "cloud query failed");
    /**
     * @tc.steps: step2. query reaches the end of the cloud data
     * @tc.expected: step2. proxy returns -E_QUERY_END and does not fetch the error detail
     */
    cloudDb->SetCloudError(false);
    cloudDb->SetErrorDetailToReturn({ 0x400104u, "should not be fetched" });
    VBucket queryExtend;
    queryExtend[CloudDbConstant::CURSOR_FIELD] = std::string("");
    std::vector<VBucket> queryData;
    ErrorDetail queryEndDetail;
    EXPECT_EQ(proxy.Query(TABLE_NAME, queryExtend, queryData, queryEndDetail), -E_QUERY_END);
    EXPECT_EQ(queryEndDetail.detailCode, 0u);
    EXPECT_TRUE(queryEndDetail.errorMessage.empty());
}

/**
 * @tc.name: CloudDBProxyErrorDetail004
 * @tc.desc: Verify proxy get empty cursor fetches error detail on failure.
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: ztx
 */
HWTEST_F(DistributedDBCloudDBProxyErrorDetailTest, CloudDBProxyErrorDetail004, TestSize.Level1)
{
    /**
     * @tc.steps: step1. get empty cursor fails with cloud error
     * @tc.expected: step1. proxy returns -E_CLOUD_ERROR with the external detail
     */
    CloudDBProxy proxy;
    auto cloudDb = std::make_shared<ErrorDetailCloudDb>();
    cloudDb->SetCursorStatus({ CLOUD_ERROR, "" });
    cloudDb->SetErrorDetailToReturn({ 0x400105u, "get cursor failed" });
    proxy.SetCloudDB(cloudDb);
    ErrorDetail errorDetail;
    auto res = proxy.GetEmptyCursor(TABLE_NAME, errorDetail);
    EXPECT_EQ(res.first, -E_CLOUD_ERROR);
    EXPECT_TRUE(res.second.empty());
    EXPECT_EQ(errorDetail.detailCode, 0x400105u);
    EXPECT_EQ(errorDetail.errorMessage, "get cursor failed");
    /**
     * @tc.steps: step2. get empty cursor succeeds
     * @tc.expected: step2. proxy returns E_OK with the cursor and the detail keeps not set
     */
    cloudDb->SetCursorStatus({ OK, "123" });
    ErrorDetail successDetail;
    res = proxy.GetEmptyCursor(TABLE_NAME, successDetail);
    EXPECT_EQ(res.first, E_OK);
    EXPECT_EQ(res.second, "123");
    EXPECT_EQ(successDetail.detailCode, 0u);
    EXPECT_TRUE(successDetail.errorMessage.empty());
}

/**
 * @tc.name: CloudDBProxyErrorDetail005
 * @tc.desc: Verify proxy lock, unlock and heartbeat fetch error detail on failure.
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: ztx
 */
HWTEST_F(DistributedDBCloudDBProxyErrorDetailTest, CloudDBProxyErrorDetail005, TestSize.Level1)
{
    /**
     * @tc.steps: step1. lock fails with cloud error
     * @tc.expected: step1. proxy returns -E_CLOUD_ERROR with the external detail
     */
    CloudDBProxy proxy;
    auto cloudDb = std::make_shared<ErrorDetailCloudDb>();
    cloudDb->SetCloudError(true);
    cloudDb->SetErrorDetailToReturn({ 0x400106u, "cloud lock failed" });
    proxy.SetCloudDB(cloudDb);
    ErrorDetail lockDetail;
    auto lockRes = proxy.Lock(lockDetail);
    EXPECT_EQ(lockRes.first, -E_CLOUD_ERROR);
    EXPECT_EQ(lockRes.second, DBConstant::MIN_TIMEOUT); // the cloud period is passed through even on failure
    EXPECT_EQ(lockDetail.detailCode, 0x400106u);
    EXPECT_EQ(lockDetail.errorMessage, "cloud lock failed");
    /**
     * @tc.steps: step2. unlock fails with cloud error
     * @tc.expected: step2. proxy returns -E_CLOUD_ERROR with the external detail
     */
    cloudDb->SetErrorDetailToReturn({ 0x400107u, "cloud unlock failed" });
    ErrorDetail unlockDetail;
    EXPECT_EQ(proxy.UnLock(unlockDetail), -E_CLOUD_ERROR);
    EXPECT_EQ(unlockDetail.detailCode, 0x400107u);
    EXPECT_EQ(unlockDetail.errorMessage, "cloud unlock failed");
    /**
     * @tc.steps: step3. heartbeat fails
     * @tc.expected: step3. proxy returns -E_CLOUD_ERROR with the external detail
     */
    cloudDb->SetHeartbeatError(true);
    cloudDb->SetErrorDetailToReturn({ 0x400108u, "cloud heartbeat failed" });
    ErrorDetail heartbeatDetail;
    EXPECT_EQ(proxy.HeartBeat(heartbeatDetail), -E_CLOUD_ERROR);
    EXPECT_EQ(heartbeatDetail.detailCode, 0x400108u);
    EXPECT_EQ(heartbeatDetail.errorMessage, "cloud heartbeat failed");
    /**
     * @tc.steps: step4. lock, unlock and heartbeat succeed
     * @tc.expected: step4. proxy returns E_OK and the details keep not set
     */
    cloudDb->SetCloudError(false);
    cloudDb->SetHeartbeatError(false);
    ErrorDetail lockSuccessDetail;
    auto lockSuccessRes = proxy.Lock(lockSuccessDetail);
    EXPECT_EQ(lockSuccessRes.first, E_OK);
    EXPECT_NE(lockSuccessRes.second, 0u);
    EXPECT_EQ(lockSuccessDetail.detailCode, 0u);
    ErrorDetail unlockSuccessDetail;
    EXPECT_EQ(proxy.UnLock(unlockSuccessDetail), E_OK);
    EXPECT_EQ(unlockSuccessDetail.detailCode, 0u);
    ErrorDetail heartbeatSuccessDetail;
    EXPECT_EQ(proxy.HeartBeat(heartbeatSuccessDetail), E_OK);
    EXPECT_EQ(heartbeatSuccessDetail.detailCode, 0u);
}

/**
 * @tc.name: CloudDBProxyErrorDetail006
 * @tc.desc: Verify proxy stop cloud sync and query all gid fetch error detail on failure.
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: ztx
 */
HWTEST_F(DistributedDBCloudDBProxyErrorDetailTest, CloudDBProxyErrorDetail006, TestSize.Level1)
{
    /**
     * @tc.steps: step1. stop cloud sync fails
     * @tc.expected: step1. proxy returns -E_CLOUD_ERROR with the external detail
     */
    CloudDBProxy proxy;
    auto cloudDb = std::make_shared<ErrorDetailCloudDb>();
    cloudDb->SetStopStatus(CLOUD_ERROR);
    cloudDb->SetErrorDetailToReturn({ 0x400109u, "stop cloud sync failed" });
    proxy.SetCloudDB(cloudDb);
    ErrorDetail stopDetail;
    EXPECT_EQ(proxy.StopCloudSync(stopDetail), -E_CLOUD_ERROR);
    EXPECT_EQ(stopDetail.detailCode, 0x400109u);
    EXPECT_EQ(stopDetail.errorMessage, "stop cloud sync failed");
    /**
     * @tc.steps: step2. stop cloud sync succeeds
     * @tc.expected: step2. proxy returns E_OK and the detail keeps not set
     */
    cloudDb->SetStopStatus(OK);
    ErrorDetail stopSuccessDetail;
    EXPECT_EQ(proxy.StopCloudSync(stopSuccessDetail), E_OK);
    EXPECT_EQ(stopSuccessDetail.detailCode, 0u);
    /**
     * @tc.steps: step3. query all gid fails
     * @tc.expected: step3. proxy returns -E_CLOUD_ERROR with the external detail
     */
    cloudDb->SetQueryAllGidStatus(CLOUD_ERROR);
    cloudDb->SetErrorDetailToReturn({ 0x40010Au, "query all gid failed" });
    VBucket extend;
    std::vector<VBucket> data;
    ErrorDetail gidDetail;
    EXPECT_EQ(proxy.QueryAllGid(TABLE_NAME, extend, data, gidDetail), -E_CLOUD_ERROR);
    EXPECT_EQ(gidDetail.detailCode, 0x40010Au);
    EXPECT_EQ(gidDetail.errorMessage, "query all gid failed");
    /**
     * @tc.steps: step4. query all gid reaches the end
     * @tc.expected: step4. proxy returns -E_QUERY_END and does not fetch the detail
     */
    cloudDb->SetQueryAllGidStatus(QUERY_END);
    ErrorDetail gidEndDetail;
    EXPECT_EQ(proxy.QueryAllGid(TABLE_NAME, extend, data, gidEndDetail), -E_QUERY_END);
    EXPECT_EQ(gidEndDetail.detailCode, 0u);
    EXPECT_TRUE(gidEndDetail.errorMessage.empty());
}

/**
 * @tc.name: CloudDBProxyErrorDetail007
 * @tc.desc: Verify proxy download asset fetches error detail, including the skip asset status.
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: ztx
 */
HWTEST_F(DistributedDBCloudDBProxyErrorDetailTest, CloudDBProxyErrorDetail007, TestSize.Level1)
{
    /**
     * @tc.steps: step1. download asset fails with cloud network error
     * @tc.expected: step1. proxy returns -E_CLOUD_NETWORK_ERROR with the external detail
     */
    CloudDBProxy proxy;
    auto loader = std::make_shared<ErrorDetailAssetLoader>();
    loader->SetDownloadStatus(CLOUD_NETWORK_ERROR);
    loader->SetErrorDetailToReturn({ 0x40010Bu, "asset download failed" });
    proxy.SetIAssetLoader(loader);
    std::map<std::string, Assets> assets = { { "field1", { ASSET_FOR_DETAIL } } };
    ErrorDetail errorDetail;
    EXPECT_EQ(proxy.Download(TABLE_NAME, "gid1", Type {}, assets, errorDetail), -E_CLOUD_NETWORK_ERROR);
    EXPECT_EQ(errorDetail.detailCode, 0x40010Bu);
    EXPECT_EQ(errorDetail.errorMessage, "asset download failed");
    /**
     * @tc.steps: step2. download asset is skipped by the cloud
     * @tc.expected: step2. proxy returns the skip status and still fetches the detail
     */
    loader->SetDownloadStatus(SKIP_ASSET);
    loader->SetErrorDetailToReturn({ 0x40010Cu, "asset skipped" });
    ErrorDetail skipDetail;
    EXPECT_EQ(proxy.Download(TABLE_NAME, "gid1", Type {}, assets, skipDetail), static_cast<int>(SKIP_ASSET));
    EXPECT_EQ(skipDetail.detailCode, 0x40010Cu);
    EXPECT_EQ(skipDetail.errorMessage, "asset skipped");
    /**
     * @tc.steps: step3. local asset is not found which is tolerated by the sync flow
     * @tc.expected: step3. proxy returns E_OK but the detail is still fetched
     */
    loader->SetDownloadStatus(LOCAL_ASSET_NOT_FOUND);
    loader->SetErrorDetailToReturn({ 0x40010Du, "local asset not found" });
    ErrorDetail notFoundDetail;
    EXPECT_EQ(proxy.Download(TABLE_NAME, "gid1", Type {}, assets, notFoundDetail), E_OK);
    EXPECT_EQ(notFoundDetail.detailCode, 0x40010Du);
    EXPECT_EQ(notFoundDetail.errorMessage, "local asset not found");
    /**
     * @tc.steps: step4. download succeeds or the assets are empty
     * @tc.expected: step4. proxy returns E_OK and the detail keeps not set
     */
    loader->SetDownloadStatus(OK);
    ErrorDetail successDetail;
    EXPECT_EQ(proxy.Download(TABLE_NAME, "gid1", Type {}, assets, successDetail), E_OK);
    EXPECT_EQ(successDetail.detailCode, 0u);
    EXPECT_TRUE(successDetail.errorMessage.empty());
    ErrorDetail emptyAssetsDetail;
    std::map<std::string, Assets> emptyAssets;
    EXPECT_EQ(proxy.Download(TABLE_NAME, "gid1", Type {}, emptyAssets, emptyAssetsDetail), E_OK);
    EXPECT_EQ(emptyAssetsDetail.detailCode, 0u);
}

/**
 * @tc.name: CloudDBProxyErrorDetail008
 * @tc.desc: Verify proxy remove local assets fetches error detail for both overloads.
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: ztx
 */
HWTEST_F(DistributedDBCloudDBProxyErrorDetailTest, CloudDBProxyErrorDetail008, TestSize.Level1)
{
    /**
     * @tc.steps: step1. remove local assets fails by the asset list overload
     * @tc.expected: step1. proxy returns -E_REMOVE_ASSETS_FAILED with the external detail
     */
    CloudDBProxy proxy;
    auto loader = std::make_shared<ErrorDetailAssetLoader>();
    loader->SetRemoveStatus(CLOUD_ERROR);
    loader->SetErrorDetailToReturn({ 0x40010Eu, "remove local assets failed" });
    proxy.SetIAssetLoader(loader);
    std::vector<Asset> assetList = { ASSET_FOR_DETAIL };
    ErrorDetail errorDetail;
    EXPECT_EQ(proxy.RemoveLocalAssets(assetList, errorDetail), -E_REMOVE_ASSETS_FAILED);
    EXPECT_EQ(errorDetail.detailCode, 0x40010Eu);
    EXPECT_EQ(errorDetail.errorMessage, "remove local assets failed");
    /**
     * @tc.steps: step2. remove local assets fails by the table and gid overload
     * @tc.expected: step2. proxy returns -E_REMOVE_ASSETS_FAILED with the external detail
     */
    loader->SetErrorDetailToReturn({ 0x40010Fu, "remove local assets by gid failed" });
    std::map<std::string, Assets> assetsMap = { { "field1", { ASSET_FOR_DETAIL } } };
    ErrorDetail gidDetail;
    EXPECT_EQ(proxy.RemoveLocalAssets(TABLE_NAME, "gid1", Type {}, assetsMap, gidDetail), -E_REMOVE_ASSETS_FAILED);
    EXPECT_EQ(gidDetail.detailCode, 0x40010Fu);
    EXPECT_EQ(gidDetail.errorMessage, "remove local assets by gid failed");
    /**
     * @tc.steps: step3. remove succeeds or the assets are empty
     * @tc.expected: step3. proxy returns E_OK and the detail keeps not set
     */
    loader->SetRemoveStatus(OK);
    ErrorDetail successDetail;
    EXPECT_EQ(proxy.RemoveLocalAssets(assetList, successDetail), E_OK);
    EXPECT_EQ(successDetail.detailCode, 0u);
    ErrorDetail emptyAssetsDetail;
    std::vector<Asset> emptyAssetList;
    std::map<std::string, Assets> emptyAssets;
    EXPECT_EQ(proxy.RemoveLocalAssets(emptyAssetList, emptyAssetsDetail), E_OK);
    EXPECT_EQ(proxy.RemoveLocalAssets(TABLE_NAME, "gid1", Type {}, emptyAssets, emptyAssetsDetail), E_OK);
    EXPECT_EQ(emptyAssetsDetail.detailCode, 0u);
}

/**
 * @tc.name: CloudDBProxyErrorDetail009
 * @tc.desc: Verify proxy batch download and batch remove assets fetch error detail from failed records.
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: ztx
 */
HWTEST_F(DistributedDBCloudDBProxyErrorDetailTest, CloudDBProxyErrorDetail009, TestSize.Level1)
{
    /**
     * @tc.steps: step1. batch download fails on all records
     * @tc.expected: step1. proxy returns E_OK, record status is failed and the detail is fetched
     */
    CloudDBProxy proxy;
    auto loader = std::make_shared<ErrorDetailAssetLoader>();
    loader->SetDownloadStatus(CLOUD_ERROR);
    loader->SetErrorDetailToReturn({ 0x400110u, "batch download failed" });
    proxy.SetIAssetLoader(loader);
    std::map<std::string, Assets> assetsMap = { { "field1", { ASSET_FOR_DETAIL } } };
    std::vector<IAssetLoader::AssetRecord> records;
    records.emplace_back(IAssetLoader::AssetRecord { "gid1", Type {}, assetsMap, OK });
    ErrorDetail errorDetail;
    EXPECT_EQ(proxy.BatchDownload(TABLE_NAME, records, errorDetail), E_OK);
    EXPECT_EQ(records[0].status, CLOUD_ERROR);
    EXPECT_EQ(errorDetail.detailCode, 0x400110u);
    EXPECT_EQ(errorDetail.errorMessage, "batch download failed");
    /**
     * @tc.steps: step2. batch remove local assets fails on all records
     * @tc.expected: step2. proxy returns E_OK, record status is failed and the detail is fetched
     */
    loader->SetBatchRemoveStatus(DB_ERROR);
    loader->SetErrorDetailToReturn({ 0x400111u, "batch remove failed" });
    std::vector<IAssetLoader::AssetRecord> removeRecords;
    removeRecords.emplace_back(IAssetLoader::AssetRecord { "gid2", Type {}, assetsMap, OK });
    ErrorDetail removeDetail;
    EXPECT_EQ(proxy.BatchRemoveLocalAssets(TABLE_NAME, removeRecords, removeDetail), E_OK);
    EXPECT_EQ(removeRecords[0].status, DB_ERROR);
    EXPECT_EQ(removeDetail.detailCode, 0x400111u);
    EXPECT_EQ(removeDetail.errorMessage, "batch remove failed");
    /**
     * @tc.steps: step3. records contain no assets or all succeed
     * @tc.expected: step3. proxy returns E_OK, loader is not called and the detail keeps not set
     */
    loader->Reset();
    loader->SetDownloadStatus(OK);
    std::vector<IAssetLoader::AssetRecord> emptyAssetRecords;
    emptyAssetRecords.emplace_back(IAssetLoader::AssetRecord { "gid3", Type {}, {}, OK });
    ErrorDetail emptyDetail;
    EXPECT_EQ(proxy.BatchDownload(TABLE_NAME, emptyAssetRecords, emptyDetail), E_OK);
    EXPECT_EQ(loader->GetBatchDownloadCount(), 0u); // filtered by empty assets, loader not called
    EXPECT_EQ(emptyDetail.detailCode, 0u);
    std::vector<IAssetLoader::AssetRecord> successRecords;
    successRecords.emplace_back(IAssetLoader::AssetRecord { "gid4", Type {}, assetsMap, OK });
    ErrorDetail successDetail;
    EXPECT_EQ(proxy.BatchDownload(TABLE_NAME, successRecords, successDetail), E_OK);
    EXPECT_EQ(successRecords[0].status, OK);
    EXPECT_EQ(successDetail.detailCode, 0u);
    EXPECT_TRUE(successDetail.errorMessage.empty());
}

/**
 * @tc.name: CloudDBProxyErrorDetail010
 * @tc.desc: Verify proxy cancel download returns E_OK with no error detail when not downloading.
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: ztx
 */
HWTEST_F(DistributedDBCloudDBProxyErrorDetailTest, CloudDBProxyErrorDetail010, TestSize.Level1)
{
    /**
     * @tc.steps: step1. cancel download without an ongoing download
     * @tc.expected: step1. proxy returns E_OK without fetching the error detail
     */
    CloudDBProxy proxy;
    auto loader = std::make_shared<ErrorDetailAssetLoader>();
    loader->SetErrorDetailToReturn({ 0x400112u, "should not be fetched" });
    proxy.SetIAssetLoader(loader);
    ErrorDetail errorDetail;
    EXPECT_EQ(proxy.CancelDownload(errorDetail), E_OK);
    EXPECT_EQ(errorDetail.detailCode, 0u);
    EXPECT_TRUE(errorDetail.errorMessage.empty());
}

/**
 * @tc.name: CloudDBProxyErrorDetail011
 * @tc.desc: Verify proxy interfaces return errors and keep detail not set when cloud db is absent.
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: ztx
 */
HWTEST_F(DistributedDBCloudDBProxyErrorDetailTest, CloudDBProxyErrorDetail011, TestSize.Level1)
{
    /**
     * @tc.steps: step1. call all cloud db interfaces without a cloud db
     * @tc.expected: step1. all return -E_CLOUD_ERROR and the error details keep not set
     */
    CloudDBProxy proxy;
    CloudSyncBatch batch = BuildOneRecordBatch();
    Info uploadInfo;
    uint32_t retryCount = 0;
    // every interface gets an independent error detail and is asserted right after the call
    ErrorDetail insertDetail;
    EXPECT_EQ(proxy.BatchInsert(TABLE_NAME, batch, uploadInfo, retryCount, insertDetail), -E_CLOUD_ERROR);
    ExpectDetailNotSet(insertDetail);
    // the error is written into the extend for each record
    ASSERT_EQ(batch.extend.size(), 1u);
    EXPECT_NE(batch.extend[0].find(CloudDbConstant::ERROR_FIELD), batch.extend[0].end());

    ErrorDetail updateDetail;
    EXPECT_EQ(proxy.BatchUpdate(TABLE_NAME, batch, uploadInfo, retryCount, updateDetail), -E_CLOUD_ERROR);
    ExpectDetailNotSet(updateDetail);

    ErrorDetail deleteDetail;
    EXPECT_EQ(proxy.BatchDelete(TABLE_NAME, batch, uploadInfo, retryCount, deleteDetail), -E_CLOUD_ERROR);
    ExpectDetailNotSet(deleteDetail);

    VBucket extend;
    std::vector<VBucket> data;
    ErrorDetail queryDetail;
    EXPECT_EQ(proxy.Query(TABLE_NAME, extend, data, queryDetail), -E_CLOUD_ERROR);
    ExpectDetailNotSet(queryDetail);

    ErrorDetail cursorDetail;
    auto cursorRes = proxy.GetEmptyCursor(TABLE_NAME, cursorDetail);
    EXPECT_EQ(cursorRes.first, -E_CLOUD_ERROR);
    EXPECT_TRUE(cursorRes.second.empty());
    ExpectDetailNotSet(cursorDetail);

    ErrorDetail lockDetail;
    auto lockRes = proxy.Lock(lockDetail);
    EXPECT_EQ(lockRes.first, -E_CLOUD_ERROR);
    EXPECT_EQ(lockRes.second, 0u);
    ExpectDetailNotSet(lockDetail);

    ErrorDetail unlockDetail;
    EXPECT_EQ(proxy.UnLock(unlockDetail), -E_CLOUD_ERROR);
    ExpectDetailNotSet(unlockDetail);

    ErrorDetail heartbeatDetail;
    EXPECT_EQ(proxy.HeartBeat(heartbeatDetail), -E_CLOUD_ERROR);
    ExpectDetailNotSet(heartbeatDetail);

    ErrorDetail gidDetail;
    EXPECT_EQ(proxy.QueryAllGid(TABLE_NAME, extend, data, gidDetail), -E_CLOUD_ERROR);
    ExpectDetailNotSet(gidDetail);

    ErrorDetail stopDetail;
    EXPECT_EQ(proxy.StopCloudSync(stopDetail), -E_CLOUD_ERROR);
    ExpectDetailNotSet(stopDetail);
}

/**
 * @tc.name: CloudDBProxyErrorDetail012
 * @tc.desc: Verify proxy asset interfaces return errors and keep detail not set when loader is absent.
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: ztx
 */
HWTEST_F(DistributedDBCloudDBProxyErrorDetailTest, CloudDBProxyErrorDetail012, TestSize.Level1)
{
    /**
     * @tc.steps: step1. call asset interfaces without an asset loader
     * @tc.expected: step1. download and download by batch return -E_NOT_SET, remove returns per definition
     */
    CloudDBProxy proxy;
    std::map<std::string, Assets> assetsMap = { { "field1", { ASSET_FOR_DETAIL } } };
    // every interface gets an independent error detail and is asserted right after the call
    ErrorDetail downloadDetail;
    EXPECT_EQ(proxy.Download(TABLE_NAME, "gid1", Type {}, assetsMap, downloadDetail), -E_NOT_SET);
    EXPECT_EQ(downloadDetail.detailCode, 0u);
    EXPECT_TRUE(downloadDetail.errorMessage.empty());

    // the first remove overload tolerates an absent loader
    std::vector<Asset> assetList = { ASSET_FOR_DETAIL };
    ErrorDetail removeDetail;
    EXPECT_EQ(proxy.RemoveLocalAssets(assetList, removeDetail), E_OK);
    EXPECT_EQ(removeDetail.detailCode, 0u);
    EXPECT_TRUE(removeDetail.errorMessage.empty());

    // the second remove overload and batch operations require the loader
    ErrorDetail removeGidDetail;
    EXPECT_EQ(proxy.RemoveLocalAssets(TABLE_NAME, "gid1", Type {}, assetsMap, removeGidDetail), -E_NOT_SET);
    EXPECT_EQ(removeGidDetail.detailCode, 0u);
    EXPECT_TRUE(removeGidDetail.errorMessage.empty());

    std::vector<IAssetLoader::AssetRecord> records;
    records.emplace_back(IAssetLoader::AssetRecord { "gid1", Type {}, assetsMap, OK });
    ErrorDetail batchDownloadDetail;
    EXPECT_EQ(proxy.BatchDownload(TABLE_NAME, records, batchDownloadDetail), -E_NOT_SET);
    EXPECT_EQ(batchDownloadDetail.detailCode, 0u);
    EXPECT_TRUE(batchDownloadDetail.errorMessage.empty());

    ErrorDetail batchRemoveDetail;
    EXPECT_EQ(proxy.BatchRemoveLocalAssets(TABLE_NAME, records, batchRemoveDetail), -E_NOT_SET);
    EXPECT_EQ(batchRemoveDetail.detailCode, 0u);
    EXPECT_TRUE(batchRemoveDetail.errorMessage.empty());
}

/**
 * @tc.name: CloudDBProxyErrorDetail013
 * @tc.desc: Verify FetchErrorDetailFromCloudDb only fetches on non-ok and non-query-end statuses.
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: ztx
 */
HWTEST_F(DistributedDBCloudDBProxyErrorDetailTest, CloudDBProxyErrorDetail013, TestSize.Level1)
{
    /**
     * @tc.steps: step1. fetch with OK and QUERY_END statuses
     * @tc.expected: step1. the error detail is not overwritten
     */
    auto cloudDb = std::make_shared<ErrorDetailCloudDb>();
    cloudDb->SetErrorDetailToReturn({ 0x400113u, "cloud detail" });
    ErrorDetail errorDetail = { 0x111u, "already set" };
    TestCloudDBProxy::CallFetchErrorDetailFromCloudDb(cloudDb, OK, errorDetail);
    EXPECT_EQ(errorDetail.detailCode, 0x111u);
    EXPECT_EQ(errorDetail.errorMessage, "already set");
    TestCloudDBProxy::CallFetchErrorDetailFromCloudDb(cloudDb, QUERY_END, errorDetail);
    EXPECT_EQ(errorDetail.detailCode, 0x111u);
    /**
     * @tc.steps: step2. fetch with an error status and a null cloud db
     * @tc.expected: step2. the error detail is not overwritten for a null cloud db
     */
    TestCloudDBProxy::CallFetchErrorDetailFromCloudDb(nullptr, CLOUD_ERROR, errorDetail);
    EXPECT_EQ(errorDetail.detailCode, 0x111u);
    EXPECT_EQ(errorDetail.errorMessage, "already set");
    /**
     * @tc.steps: step3. fetch with an error status and a valid cloud db
     * @tc.expected: step3. the error detail is replaced by the external one
     */
    TestCloudDBProxy::CallFetchErrorDetailFromCloudDb(cloudDb, CLOUD_ERROR, errorDetail);
    EXPECT_EQ(errorDetail.detailCode, 0x400113u);
    EXPECT_EQ(errorDetail.errorMessage, "cloud detail");
    /**
     * @tc.steps: step4. the default implementation of the cloud db returns not set
     * @tc.expected: step4. the error detail is cleared to not set
     */
    auto defaultDb = std::make_shared<VirtualCloudDb>();
    ErrorDetail defaultDetail = { 0x111u, "already set" };
    TestCloudDBProxy::CallFetchErrorDetailFromCloudDb(defaultDb, DB_ERROR, defaultDetail);
    EXPECT_EQ(defaultDetail.detailCode, 0u);
    EXPECT_TRUE(defaultDetail.errorMessage.empty());
}

/**
 * @tc.name: CloudDBProxyErrorDetail014
 * @tc.desc: Verify FetchErrorDetailFromAssetRecords only fetches when a record failed.
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: ztx
 */
HWTEST_F(DistributedDBCloudDBProxyErrorDetailTest, CloudDBProxyErrorDetail014, TestSize.Level1)
{
    /**
     * @tc.steps: step1. fetch with no records
     * @tc.expected: step1. the error detail is not overwritten
     */
    auto loader = std::make_shared<ErrorDetailAssetLoader>();
    loader->SetErrorDetailToReturn({ 0x400114u, "loader detail" });
    std::map<std::string, Assets> assetsMap = { { "field1", { ASSET_FOR_DETAIL } } };
    std::vector<IAssetLoader::AssetRecord> records;
    ErrorDetail errorDetail = { 0x222u, "already set" };
    TestCloudDBProxy::CallFetchErrorDetailFromAssetRecords(loader, records, errorDetail);
    EXPECT_EQ(errorDetail.detailCode, 0x222u);
    /**
     * @tc.steps: step2. fetch with all successful records
     * @tc.expected: step2. the error detail is not overwritten
     */
    records.emplace_back(IAssetLoader::AssetRecord { "gid1", Type {}, assetsMap, OK });
    records.emplace_back(IAssetLoader::AssetRecord { "gid2", Type {}, assetsMap, QUERY_END });
    TestCloudDBProxy::CallFetchErrorDetailFromAssetRecords(loader, records, errorDetail);
    EXPECT_EQ(errorDetail.detailCode, 0x222u);
    EXPECT_EQ(errorDetail.errorMessage, "already set");
    /**
     * @tc.steps: step3. fetch with a failed record
     * @tc.expected: step3. the error detail is replaced by the external one
     */
    records.emplace_back(IAssetLoader::AssetRecord { "gid3", Type {}, assetsMap, CLOUD_ERROR });
    TestCloudDBProxy::CallFetchErrorDetailFromAssetRecords(loader, records, errorDetail);
    EXPECT_EQ(errorDetail.detailCode, 0x400114u);
    EXPECT_EQ(errorDetail.errorMessage, "loader detail");
    /**
     * @tc.steps: step4. fetch with a failed record but a null loader
     * @tc.expected: step4. the error detail is not overwritten
     */
    ErrorDetail nullLoaderDetail = { 0x222u, "already set" };
    TestCloudDBProxy::CallFetchErrorDetailFromAssetRecords(nullptr, records, nullLoaderDetail);
    EXPECT_EQ(nullLoaderDetail.detailCode, 0x222u);
}

/**
 * @tc.name: CloudDBProxyErrorDetail015
 * @tc.desc: Verify the action context saves and moves out the error detail exactly once.
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: ztx
 */
HWTEST_F(DistributedDBCloudDBProxyErrorDetailTest, CloudDBProxyErrorDetail015, TestSize.Level1)
{
    /**
     * @tc.steps: step1. set the detail then move it out twice
     * @tc.expected: step1. the first move out returns the detail, the second returns not set
     */
    ErrorDetail inDetail = { 0x400115u, "context detail" };
    auto moveRes = TestCloudDBProxy::CloudActionContextDetailMoveCheck(inDetail);
    EXPECT_EQ(moveRes.first.detailCode, 0x400115u);
    EXPECT_EQ(moveRes.first.errorMessage, "context detail");
    EXPECT_EQ(moveRes.second.detailCode, 0u);
    EXPECT_TRUE(moveRes.second.errorMessage.empty());
    /**
     * @tc.steps: step2. set the detail twice before moving out
     * @tc.expected: step2. the last set detail wins
     */
    ErrorDetail firstDetail = { 0x400115u, "first detail" };
    ErrorDetail secondDetail = { 0x400116u, "second detail" };
    ErrorDetail overwrittenDetail = TestCloudDBProxy::CloudActionContextDetailOverwriteCheck(firstDetail,
        secondDetail);
    EXPECT_EQ(overwrittenDetail.detailCode, 0x400116u);
    EXPECT_EQ(overwrittenDetail.errorMessage, "second detail");
}

/**
 * @tc.name: CloudDBProxyErrorDetail016
 * @tc.desc: Verify the default GetErrorDetail of cloud db and asset loader returns not set.
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: ztx
 */
HWTEST_F(DistributedDBCloudDBProxyErrorDetailTest, CloudDBProxyErrorDetail016, TestSize.Level1)
{
    /**
     * @tc.steps: step1. call the default GetErrorDetail of the cloud db
     * @tc.expected: step1. detailCode is 0 and errorMessage is empty
     */
    VirtualCloudDb cloudDb;
    ErrorDetail cloudDbDetail = cloudDb.GetErrorDetail();
    EXPECT_EQ(cloudDbDetail.detailCode, 0u);
    EXPECT_TRUE(cloudDbDetail.errorMessage.empty());
    /**
     * @tc.steps: step2. call the default GetErrorDetail of the asset loader
     * @tc.expected: step2. detailCode is 0 and errorMessage is empty
     */
    VirtualAssetLoader loader;
    ErrorDetail loaderDetail = loader.GetErrorDetail();
    EXPECT_EQ(loaderDetail.detailCode, 0u);
    EXPECT_TRUE(loaderDetail.errorMessage.empty());
}
