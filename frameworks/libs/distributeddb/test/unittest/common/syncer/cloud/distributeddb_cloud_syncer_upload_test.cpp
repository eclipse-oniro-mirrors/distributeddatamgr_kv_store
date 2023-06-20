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

#include "cloud_syncer_test.h"
#include "distributeddb_tools_unit_test.h"
#include "mock_icloud_sync_storage_interface.h"
#include "mock_iclouddb.h"
#include "sqlite_single_ver_relational_continue_token.h"
#include "store_types.h"
#include "types_export.h"

using namespace testing::ext;
using namespace testing;
using namespace DistributedDB;
using namespace DistributedDBUnitTest;

namespace {

constexpr auto TABLE_NAME_1 = "tableName1";
constexpr auto CLOUD_WATER_MARK = "tableName1";


static void CommonExpectCall(MockICloudSyncStorageInterface *iCloud)
{
    EXPECT_CALL(*iCloud, StartTransaction(_)).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*iCloud, Rollback()).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*iCloud, GetCloudTableSchema(_, _)).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*iCloud, GetMetaData(_, _)).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*iCloud, ChkSchema(_)).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*iCloud, Commit()).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*iCloud, ReleaseCloudDataToken(_)).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*iCloud, PutMetaData(_, _)).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*iCloud, GetCloudDataNext(_, _)).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*iCloud, GetCloudDbSchema(_)).WillRepeatedly(Return(E_OK));
}
class DistributedDBCloudSyncerUploadTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void DistributedDBCloudSyncerUploadTest::SetUpTestCase(void)
{
}

void DistributedDBCloudSyncerUploadTest::TearDownTestCase(void)
{
}

void DistributedDBCloudSyncerUploadTest::SetUp(void)
{
    DistributedDBToolsUnitTest::PrintTestCaseInfo();
}

void DistributedDBCloudSyncerUploadTest::TearDown(void)
{
}

/**
 * @tc.name: UploadModeCheck001
 * @tc.desc: Test different strategies of sync task call DoUpload()
 * @tc.type: FUNC
 * @tc.require: AR000HSNJO
 * @tc.author: huangboxin
 */
HWTEST_F(DistributedDBCloudSyncerUploadTest, UploadModeCheck001, TestSize.Level1)
{
    MockICloudSyncStorageInterface *iCloud = new MockICloudSyncStorageInterface();
    std::shared_ptr<TestStorageProxy> storageProxy = std::make_shared<TestStorageProxy>(iCloud);
    TestCloudSyncer cloudSyncer(storageProxy);
    std::shared_ptr<MockICloudDB> idb = std::make_shared<MockICloudDB>();
    cloudSyncer.SetMockICloudDB(idb);
    TaskId taskId = 1;

    EXPECT_CALL(*iCloud, GetMetaData(_, _)).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*iCloud, ChkSchema(_)).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*iCloud, StartTransaction(_)).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*iCloud, GetUploadCount(_, _, _, _)).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*iCloud, Commit()).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*iCloud, Rollback()).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*iCloud, GetCloudTableSchema(_, _)).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*iCloud, GetCloudData(_, _, _, _)).WillRepeatedly(Return(E_OK));

    cloudSyncer.InitCloudSyncer(taskId, SYNC_MODE_PUSH_ONLY);
    int errCode = cloudSyncer.CallDoUpload(taskId);
    EXPECT_EQ(errCode, -E_INVALID_ARGS);

    cloudSyncer.InitCloudSyncer(taskId, SYNC_MODE_PULL_ONLY);
    errCode = cloudSyncer.CallDoUpload(taskId);
    EXPECT_EQ(errCode, -E_INVALID_ARGS);

    cloudSyncer.InitCloudSyncer(taskId, SYNC_MODE_PUSH_PULL);
    errCode = cloudSyncer.CallDoUpload(taskId);
    EXPECT_EQ(errCode, -E_INVALID_ARGS);

    cloudSyncer.InitCloudSyncer(taskId, SYNC_MODE_CLOUD_MERGE);
    errCode = cloudSyncer.CallDoUpload(taskId);
    EXPECT_EQ(errCode, E_OK);

    cloudSyncer.InitCloudSyncer(taskId, SYNC_MODE_CLOUD_FORCE_PUSH);
    errCode = cloudSyncer.CallDoUpload(taskId);
    EXPECT_EQ(errCode, E_OK);

    cloudSyncer.InitCloudSyncer(taskId, SYNC_MODE_CLOUD_FORCE_PULL);
    errCode = cloudSyncer.CallDoUpload(taskId);
    EXPECT_EQ(errCode, -E_INVALID_ARGS);

    errCode = cloudSyncer.CallDoUpload(taskId);
    EXPECT_EQ(errCode, -E_INVALID_ARGS);

    storageProxy.reset();
    delete iCloud;
    idb = nullptr;
}

/**
 * @tc.name: UploadModeCheck002
 * @tc.desc: Test case1 about getting water mark
 * @tc.type: FUNC
 * @tc.require: AR000HSNJO
 * @tc.author: huangboxin
 */
HWTEST_F(DistributedDBCloudSyncerUploadTest, UploadModeCheck002, TestSize.Level1)
{
    MockICloudSyncStorageInterface *iCloud = new MockICloudSyncStorageInterface();
    std::shared_ptr<TestStorageProxy> storageProxy = std::make_shared<TestStorageProxy>(iCloud);
    TestCloudSyncer cloudSyncer(storageProxy);
    std::shared_ptr<MockICloudDB> idb = std::make_shared<MockICloudDB>();
    cloudSyncer.SetMockICloudDB(idb);
    TaskId taskId = 2u;

    EXPECT_CALL(*iCloud, StartTransaction(_)).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*iCloud, GetUploadCount(_, _, _, _)).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*iCloud, Commit()).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*iCloud, Rollback()).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*iCloud, GetCloudTableSchema(_, _)).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*iCloud, GetCloudData(_, _, _, _)).WillRepeatedly(Return(E_OK));

    //  1. The water level was read successfully
    cloudSyncer.InitCloudSyncer(taskId, SYNC_MODE_CLOUD_MERGE);
    EXPECT_CALL(*iCloud, GetMetaData(_, _)).WillOnce(Return(E_OK));
    EXPECT_CALL(*iCloud, ChkSchema(_)).WillRepeatedly(Return(E_OK));

    int errCode = cloudSyncer.CallDoUpload(taskId);
    EXPECT_EQ(errCode, E_OK);

    storageProxy.reset();
    delete iCloud;
    idb = nullptr;
}
/**
 * @tc.name: UploadModeCheck003
 * @tc.desc: Test case2 about getting water mark
 * @tc.type: FUNC
 * @tc.require: AR000HSNJO
 * @tc.author: huangboxin
 */
HWTEST_F(DistributedDBCloudSyncerUploadTest, UploadModeCheck003, TestSize.Level1)
{
    MockICloudSyncStorageInterface *iCloud = new MockICloudSyncStorageInterface();
    std::shared_ptr<TestStorageProxy> storageProxy = std::make_shared<TestStorageProxy>(iCloud);
    TestCloudSyncer cloudSyncer(storageProxy);
    std::shared_ptr<MockICloudDB> idb = std::make_shared<MockICloudDB>();
    cloudSyncer.SetMockICloudDB(idb);

    EXPECT_CALL(*iCloud, StartTransaction(_)).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*iCloud, GetUploadCount(_, _, _, _)).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*iCloud, Commit()).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*iCloud, Rollback()).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*iCloud, GetCloudTableSchema(_, _)).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*iCloud, GetCloudData(_, _, _, _)).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*iCloud, ChkSchema(_)).WillRepeatedly(Return(E_OK));

    // 2. Failed to read water level
    TaskId taskId = 3u;
    cloudSyncer.InitCloudSyncer(taskId, SYNC_MODE_CLOUD_MERGE);
    EXPECT_CALL(*iCloud, GetMetaData(_, _)).WillOnce(Return(-E_INVALID_DB));
    int errCode = cloudSyncer.CallDoUpload(taskId);
    EXPECT_EQ(errCode, -E_INVALID_DB);

    taskId = 4u;
    cloudSyncer.InitCloudSyncer(taskId, SYNC_MODE_CLOUD_MERGE);
    EXPECT_CALL(*iCloud, GetMetaData(_, _)).WillOnce(Return(-E_SECUREC_ERROR));
    errCode = cloudSyncer.CallDoUpload(taskId);
    EXPECT_EQ(errCode, -E_SECUREC_ERROR);
    
    taskId = 5u;
    cloudSyncer.InitCloudSyncer(taskId, SYNC_MODE_CLOUD_MERGE);
    EXPECT_CALL(*iCloud, GetMetaData(_, _)).WillOnce(Return(-E_INVALID_ARGS));
    errCode = cloudSyncer.CallDoUpload(taskId);
    EXPECT_EQ(errCode, -E_INVALID_ARGS);

    taskId = 6u;
    cloudSyncer.InitCloudSyncer(taskId, SYNC_MODE_CLOUD_MERGE);
    EXPECT_CALL(*iCloud, GetMetaData(_, _)).WillOnce(Return(-E_BUSY));
    errCode = cloudSyncer.CallDoUpload(taskId);
    EXPECT_EQ(errCode, -E_BUSY);

    taskId = 7u;
    cloudSyncer.InitCloudSyncer(taskId, SYNC_MODE_CLOUD_MERGE);
    EXPECT_CALL(*iCloud, GetMetaData(_, _)).WillOnce(Return(-E_NOT_FOUND));
    errCode = cloudSyncer.CallDoUpload(taskId);
    // when we coudln't find key in get meta data, read local water mark will return default value and E_OK
    EXPECT_EQ(errCode, E_OK);

    // Other sqlite error, like SQLITE_ERROR
    taskId = 8u;
    cloudSyncer.InitCloudSyncer(taskId, SYNC_MODE_CLOUD_MERGE);
    EXPECT_CALL(*iCloud, GetMetaData(_, _)).WillOnce(Return(SQLITE_ERROR));
    errCode = cloudSyncer.CallDoUpload(taskId);
    EXPECT_EQ(errCode, SQLITE_ERROR);

    storageProxy.reset();
    delete iCloud;
    idb = nullptr;
}

/**
 * @tc.name: UploadModeCheck004
 * @tc.desc: Test case1 about Getting upload count
 * @tc.type: FUNC
 * @tc.require: AR000HSNJO
 * @tc.author: huangboxin
 */
HWTEST_F(DistributedDBCloudSyncerUploadTest, UploadModeCheck004, TestSize.Level1)
{
    MockICloudSyncStorageInterface *iCloud = new MockICloudSyncStorageInterface();
    std::shared_ptr<TestStorageProxy> storageProxy = std::make_shared<TestStorageProxy>(iCloud);
    TestCloudSyncer cloudSyncer(storageProxy);
    std::shared_ptr<MockICloudDB> idb = std::make_shared<MockICloudDB>();
    cloudSyncer.SetMockICloudDB(idb);
    cloudSyncer.InitCloudSyncer(3u, SYNC_MODE_CLOUD_FORCE_PUSH);
    
    EXPECT_CALL(*iCloud, StartTransaction(_)).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*iCloud, ChkSchema(_)).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*iCloud, Commit()).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*iCloud, Rollback()).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*iCloud, GetMetaData(_, _)).WillRepeatedly(Return(E_OK));

    // 1. Failed to get total data count
    EXPECT_CALL(*iCloud, GetUploadCount(_, _, _, _)).WillOnce(Return(-E_INVALID_DB));
    int errCode = cloudSyncer.CallDoUpload(3u);
    EXPECT_EQ(errCode, -E_INVALID_DB);

    cloudSyncer.InitCloudSyncer(4u, SYNC_MODE_CLOUD_FORCE_PUSH);
    EXPECT_CALL(*iCloud, GetUploadCount(_, _, _, _)).WillOnce(Return(-E_BUSY));
    errCode = cloudSyncer.CallDoUpload(4u);
    EXPECT_EQ(errCode, -E_BUSY);

    cloudSyncer.InitCloudSyncer(5u, SYNC_MODE_CLOUD_FORCE_PUSH);

    EXPECT_CALL(*iCloud, GetUploadCount(_, _, _, _)).WillOnce(Return(-E_OUT_OF_MEMORY));
    errCode = cloudSyncer.CallDoUpload(5u);
    EXPECT_EQ(errCode, -E_OUT_OF_MEMORY);

    cloudSyncer.InitCloudSyncer(6u, SYNC_MODE_CLOUD_FORCE_PUSH);
    EXPECT_CALL(*iCloud, GetUploadCount(_, _, _, _)).WillOnce(Return(-E_INTERNAL_ERROR));
    errCode = cloudSyncer.CallDoUpload(6u);
    EXPECT_EQ(errCode, -E_INTERNAL_ERROR);

    cloudSyncer.InitCloudSyncer(7u, SYNC_MODE_CLOUD_FORCE_PUSH);
    EXPECT_CALL(*iCloud, GetUploadCount(_, _, _, _)).WillOnce(Return(-E_INVALID_QUERY_FORMAT));
    errCode = cloudSyncer.CallDoUpload(7u);
    EXPECT_EQ(errCode, -E_INVALID_QUERY_FORMAT);

    cloudSyncer.InitCloudSyncer(9u, SYNC_MODE_CLOUD_FORCE_PUSH);
    EXPECT_CALL(*iCloud, GetUploadCount(_, _, _, _)).WillOnce(Return(SQLITE_ERROR));
    errCode = cloudSyncer.CallDoUpload(9u);
    EXPECT_EQ(errCode, SQLITE_ERROR);

    RuntimeContext::GetInstance()->StopTaskPool();
    storageProxy.reset();
    delete iCloud;
    idb = nullptr;
}

/**
 * @tc.name: UploadModeCheck005
 * @tc.desc: Test case2 about Getting upload count
 * @tc.type: FUNC
 * @tc.require: AR000HSNJO
 * @tc.author: huangboxin
 */
HWTEST_F(DistributedDBCloudSyncerUploadTest, UploadModeCheck005, TestSize.Level1)
{
    MockICloudSyncStorageInterface *iCloud = new MockICloudSyncStorageInterface();
    std::shared_ptr<TestStorageProxy> storageProxy = std::make_shared<TestStorageProxy>(iCloud);
    TestCloudSyncer cloudSyncer(storageProxy);
    std::shared_ptr<MockICloudDB> idb = std::make_shared<MockICloudDB>();
    cloudSyncer.SetMockICloudDB(idb);
    cloudSyncer.InitCloudSyncer(3u, SYNC_MODE_CLOUD_FORCE_PUSH);

    EXPECT_CALL(*iCloud, StartTransaction(_)).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*iCloud, ChkSchema(_)).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*iCloud, Commit()).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*iCloud, Rollback()).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*iCloud, GetMetaData(_, _)).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*iCloud, GetCloudTableSchema(_, _)).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*iCloud, GetCloudData(_, _, _, _)).WillRepeatedly(Return(E_OK));

    // 2. get total upload count ok
    cloudSyncer.InitCloudSyncer(10u, SYNC_MODE_CLOUD_FORCE_PUSH);
    EXPECT_CALL(*iCloud, GetUploadCount(_, _, _, _)).WillOnce(Return(E_OK));
    int errCode = cloudSyncer.CallDoUpload(10u);
    EXPECT_EQ(errCode, E_OK);

    // 3. get total upload count ok, which is 0
    cloudSyncer.InitCloudSyncer(11u, SYNC_MODE_CLOUD_FORCE_PUSH);
    EXPECT_CALL(*iCloud, GetUploadCount(_, _, _, _))
        .WillOnce([](const std::string &, const Timestamp &, const bool, int64_t & count) {
        count = 0;
        return E_OK;
    });

    errCode = cloudSyncer.CallDoUpload(11u);
    EXPECT_EQ(errCode, E_OK);

    RuntimeContext::GetInstance()->StopTaskPool();
    storageProxy.reset();
    delete iCloud;
    idb = nullptr;
}

/**
 * @tc.name: UploadModeCheck006
 * @tc.desc: Test case1 about CloudSyncData
 * @tc.type: FUNC
 * @tc.require: AR000HSNJO
 * @tc.author: huangboxin
 */
HWTEST_F(DistributedDBCloudSyncerUploadTest, UploadModeCheck006, TestSize.Level1)
{
    MockICloudSyncStorageInterface *iCloud = new MockICloudSyncStorageInterface();
    std::shared_ptr<TestStorageProxy> storageProxy = std::make_shared<TestStorageProxy>(iCloud);
    TestCloudSyncer cloudSyncer(storageProxy);
    std::shared_ptr<MockICloudDB> idb = std::make_shared<MockICloudDB>();
    cloudSyncer.SetMockICloudDB(idb);
    TaskId taskId = 4u;
    cloudSyncer.InitCloudSyncer(taskId, SYNC_MODE_CLOUD_FORCE_PUSH);

    EXPECT_CALL(*idb, BatchInsert(_, _, _)).WillRepeatedly(Return(OK));

    EXPECT_CALL(*iCloud, StartTransaction(_)).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*iCloud, Rollback()).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*iCloud, GetCloudTableSchema(_, _)).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*iCloud, GetMetaData(_, _)).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*iCloud, ChkSchema(_)).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*iCloud, Commit()).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*iCloud, ReleaseCloudDataToken(_)).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*iCloud, GetUploadCount(_, _, _, _))
        .WillRepeatedly([](const std::string &, const Timestamp &, const bool, int64_t & count) {
        count = 1000;
        return E_OK;
    });
    EXPECT_CALL(*iCloud, FillCloudGid(_)).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*iCloud, PutMetaData(_, _)).WillRepeatedly(Return(E_OK));

    VBucket tmp = {pair<std::string, int64_t>(CloudDbConstant::MODIFY_FIELD, 1)};
    CloudSyncData uploadData(cloudSyncer.GetCurrentContextTableName());

    // batch_1 CloudSyncData quantity > total count
    uploadData.insData.record = std::vector<VBucket>(1001, tmp);
    uploadData.insData.extend = std::vector<VBucket>(1001, tmp);
    EXPECT_CALL(*iCloud, GetCloudData(_, _, _, _)).WillOnce(
        [&uploadData](const TableSchema &, const Timestamp &, ContinueToken &, CloudSyncData &cloudDataResult) {
            cloudDataResult = uploadData;
            return E_OK;
    });
    int errCode = cloudSyncer.CallDoUpload(taskId);
    EXPECT_EQ(errCode, -E_INTERNAL_ERROR);

    RuntimeContext::GetInstance()->StopTaskPool();

    storageProxy.reset();
    delete iCloud;
    idb = nullptr;
}

/**
 * @tc.name: UploadModeCheck007
 * @tc.desc: Test case2 about CloudSyncData
 * @tc.type: FUNC
 * @tc.require: AR000HSNJO
 * @tc.author: huangboxin
 */
HWTEST_F(DistributedDBCloudSyncerUploadTest, UploadModeCheck007, TestSize.Level1)
{
    MockICloudSyncStorageInterface *iCloud = new MockICloudSyncStorageInterface();
    std::shared_ptr<TestStorageProxy> storageProxy = std::make_shared<TestStorageProxy>(iCloud);
    TestCloudSyncer cloudSyncer(storageProxy);
    std::shared_ptr<MockICloudDB> idb = std::make_shared<MockICloudDB>();
    cloudSyncer.SetMockICloudDB(idb);
    cloudSyncer.InitCloudSyncer(4u, SYNC_MODE_CLOUD_FORCE_PUSH);

    CommonExpectCall(iCloud);
    EXPECT_CALL(*idb, BatchInsert(_, _, _)).WillRepeatedly(Return(OK));
    EXPECT_CALL(*iCloud, PutMetaData(_, _)).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*iCloud, FillCloudGid(_)).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*iCloud, GetUploadCount(_, _, _, _))
        .WillRepeatedly([](const std::string &, const Timestamp &, const bool, int64_t & count) {
        count = 1000;
        return E_OK;
    });

    // Batch_n CloudSyncData quantity > total count
    cloudSyncer.InitCloudSyncer(5u, SYNC_MODE_CLOUD_FORCE_PUSH);
    CloudSyncData uploadData2(cloudSyncer.GetCurrentContextTableName());
    VBucket tmp = {pair<std::string, int64_t>(CloudDbConstant::MODIFY_FIELD, 1)};
    uploadData2.insData.record = std::vector<VBucket>(1000, tmp);
    uploadData2.insData.extend = std::vector<VBucket>(1000, tmp);
    
    SyncTimeRange syncTimeRange = { .beginTime = 1u };
    Query query1 = Query::Select();
    QueryObject queryObject(query1);
    queryObject.SetTableName(cloudSyncer.GetCurrentContextTableName());
    auto token = new (std::nothrow) SQLiteSingleVerRelationalContinueToken(syncTimeRange, queryObject);
    ContinueToken conStmtToken = static_cast<ContinueToken>(token);
    delete token;
    EXPECT_CALL(*iCloud, GetCloudData(_, _, _, _))
        .WillOnce([&conStmtToken, &uploadData2](const TableSchema &, const Timestamp &,
            ContinueToken &continueStmtToken, CloudSyncData &cloudDataResult) {
            continueStmtToken = conStmtToken;
            cloudDataResult = uploadData2;
            return -E_UNFINISHED;
        });

    CloudSyncData uploadData3(cloudSyncer.GetCurrentContextTableName());
    uploadData3.insData.record = std::vector<VBucket>(1001, tmp);
    uploadData3.insData.extend = std::vector<VBucket>(1001, tmp);
    EXPECT_CALL(*iCloud, GetCloudDataNext(_, _)).WillOnce(
        [&uploadData3](ContinueToken &, CloudSyncData &cloudDataResult) {
        cloudDataResult = uploadData3;
        return E_OK;
    });
    int errCode = cloudSyncer.CallDoUpload(5u);
    EXPECT_EQ(errCode, -E_INTERNAL_ERROR);

    RuntimeContext::GetInstance()->StopTaskPool();

    storageProxy.reset();
    delete iCloud;
    idb = nullptr;
}

/**
 * @tc.name: UploadModeCheck008
 * @tc.desc: Test case3 about CloudSyncData
 * @tc.type: FUNC
 * @tc.require: AR000HSNJO
 * @tc.author: huangboxin
 */
HWTEST_F(DistributedDBCloudSyncerUploadTest, UploadModeCheck008, TestSize.Level1)
{
    MockICloudSyncStorageInterface *iCloud = new MockICloudSyncStorageInterface();
    std::shared_ptr<TestStorageProxy> storageProxy = std::make_shared<TestStorageProxy>(iCloud);
    TestCloudSyncer cloudSyncer(storageProxy);
    std::shared_ptr<MockICloudDB> idb = std::make_shared<MockICloudDB>();
    cloudSyncer.SetMockICloudDB(idb);
    TaskId taskId = 4u;
    cloudSyncer.InitCloudSyncer(taskId, SYNC_MODE_CLOUD_FORCE_PUSH);

    EXPECT_CALL(*idb, BatchInsert(_, _, _)).WillRepeatedly(Return(OK));

    EXPECT_CALL(*iCloud, StartTransaction(_)).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*iCloud, Rollback()).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*iCloud, GetCloudTableSchema(_, _)).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*iCloud, GetMetaData(_, _)).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*iCloud, ChkSchema(_)).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*iCloud, Commit()).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*iCloud, ReleaseCloudDataToken(_)).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*iCloud, GetUploadCount(_, _, _, _))
        .WillRepeatedly([](const std::string &, const Timestamp &, const bool, int64_t & count) {
        count = 1000;
        return E_OK;
    });
    EXPECT_CALL(*iCloud, FillCloudGid(_)).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*iCloud, PutMetaData(_, _)).WillRepeatedly(Return(E_OK));

    // empty CloudSyncData

    taskId = 6u;
    CloudSyncData uploadData2(cloudSyncer.GetCurrentContextTableName());
    cloudSyncer.InitCloudSyncer(taskId, SYNC_MODE_CLOUD_FORCE_PUSH);
    uploadData2.insData.record = std::vector<VBucket>(100);
    uploadData2.insData.extend = std::vector<VBucket>(100);
    EXPECT_CALL(*iCloud, GetCloudData(_, _, _, _))
    .WillOnce([&uploadData2](const TableSchema &, const Timestamp &,
        ContinueToken &continueStmtToken, CloudSyncData &cloudDataResult) {
        cloudDataResult = uploadData2;
        return -E_UNFINISHED;
    });
    
    int errCode = cloudSyncer.CallDoUpload(taskId);
    EXPECT_EQ(errCode, -E_INTERNAL_ERROR);

    RuntimeContext::GetInstance()->StopTaskPool();

    storageProxy.reset();
    delete iCloud;
    idb = nullptr;
}

/**
 * @tc.name: UploadModeCheck009
 * @tc.desc: Test case about CloudSyncData
 * @tc.type: FUNC
 * @tc.require: AR000HSNJO
 * @tc.author: huangboxin
 */
HWTEST_F(DistributedDBCloudSyncerUploadTest, UploadModeCheck009, TestSize.Level1)
{
    // ClouSyncData format is ok
    MockICloudSyncStorageInterface *iCloud = new MockICloudSyncStorageInterface();
    std::shared_ptr<TestStorageProxy> storageProxy = std::make_shared<TestStorageProxy>(iCloud);
    TestCloudSyncer cloudSyncer(storageProxy);
    std::shared_ptr<MockICloudDB> idb = std::make_shared<MockICloudDB>();
    cloudSyncer.SetMockICloudDB(idb);

    TaskId taskId = 5u;
    cloudSyncer.InitCloudSyncer(taskId, SYNC_MODE_CLOUD_FORCE_PUSH);
    VBucket tmp = {pair<std::string, int64_t>(CloudDbConstant::MODIFY_FIELD, 1)};
    CommonExpectCall(iCloud);
    EXPECT_CALL(*iCloud, PutMetaData(_, _)).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*idb, BatchInsert(_, _, _)).WillRepeatedly(Return(OK));
    EXPECT_CALL(*idb, BatchDelete(_, _)).WillRepeatedly(Return(OK));
    EXPECT_CALL(*idb, BatchUpdate(_, _, _)).WillRepeatedly(Return(OK));
    EXPECT_CALL(*iCloud, FillCloudGid(_)).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*iCloud, GetUploadCount(_, _, _, _))
        .WillRepeatedly([](const std::string &, const Timestamp &, const bool, int64_t & count) {
        count = 10000;
        return E_OK;
    });

    CloudSyncData uploadData(cloudSyncer.GetCurrentContextTableName());
    uploadData.insData.record = std::vector<VBucket>(1000, tmp);
    uploadData.insData.extend = std::vector<VBucket>(1000, tmp);
    EXPECT_CALL(*iCloud, GetCloudData(_, _, _, _))
    .WillOnce([&uploadData](const TableSchema &, const Timestamp &,
        ContinueToken &continueStmtToken, CloudSyncData &cloudDataResult) {
        cloudDataResult = uploadData;
        return E_OK;
    });
    int errCode = cloudSyncer.CallDoUpload(taskId);
    EXPECT_EQ(errCode, E_OK);

    // CloudSyncData format error: record does not match extend length
    cloudSyncer.CallClearCloudSyncData(uploadData);
    uploadData.insData.record = std::vector<VBucket>(1000, tmp);
    uploadData.insData.extend = std::vector<VBucket>(999, tmp);
    EXPECT_CALL(*iCloud, GetCloudData(_, _, _, _))
    .WillOnce([&uploadData](const TableSchema &, const Timestamp &,
        ContinueToken &continueStmtToken, CloudSyncData &cloudDataResult) {
        cloudDataResult = uploadData;
        return E_OK;
    });
    errCode = cloudSyncer.CallDoUpload(taskId);
    EXPECT_EQ(errCode, -E_INTERNAL_ERROR);

    RuntimeContext::GetInstance()->StopTaskPool();

    storageProxy.reset();
    delete iCloud;
    idb = nullptr;
}

/**
 * @tc.name: UploadModeCheck017
 * @tc.desc: Test case about CloudSyncData
 * @tc.type: FUNC
 * @tc.require: AR000HSNJO
 * @tc.author: huangboxin
 */
HWTEST_F(DistributedDBCloudSyncerUploadTest, UploadModeCheck017, TestSize.Level1)
{
    // ClouSyncData format is ok
    MockICloudSyncStorageInterface *iCloud = new MockICloudSyncStorageInterface();
    std::shared_ptr<TestStorageProxy> storageProxy = std::make_shared<TestStorageProxy>(iCloud);
    TestCloudSyncer cloudSyncer(storageProxy);
    std::shared_ptr<MockICloudDB> idb = std::make_shared<MockICloudDB>();
    cloudSyncer.SetMockICloudDB(idb);

    TaskId taskId = 5u;
    cloudSyncer.InitCloudSyncer(taskId, SYNC_MODE_CLOUD_FORCE_PUSH);
    VBucket tmp = {pair<std::string, int64_t>(CloudDbConstant::MODIFY_FIELD, 1)};
    CommonExpectCall(iCloud);
    EXPECT_CALL(*iCloud, PutMetaData(_, _)).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*idb, BatchInsert(_, _, _)).WillRepeatedly(Return(OK));
    EXPECT_CALL(*idb, BatchDelete(_, _)).WillRepeatedly(Return(OK));
    EXPECT_CALL(*idb, BatchUpdate(_, _, _)).WillRepeatedly(Return(OK));
    EXPECT_CALL(*iCloud, FillCloudGid(_)).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*iCloud, GetUploadCount(_, _, _, _))
        .WillRepeatedly([](const std::string &, const Timestamp &, const bool, int64_t & count) {
        count = 10000;
        return E_OK;
    });

    // CloudSyncData format error: tableName is different from the table name corresponding to Task
    CloudSyncData uploadData2(cloudSyncer.GetCurrentContextTableName() + "abc");
    uploadData2.insData.record = std::vector<VBucket>(1000, tmp);
    uploadData2.insData.extend = std::vector<VBucket>(1000, tmp);
    EXPECT_CALL(*iCloud, GetCloudData(_, _, _, _))
    .WillOnce([&uploadData2](const TableSchema &, const Timestamp &,
        ContinueToken &continueStmtToken, CloudSyncData &cloudDataResult) {
        cloudDataResult = uploadData2;
        return E_OK;
    });
    int errCode = cloudSyncer.CallDoUpload(taskId);
    EXPECT_EQ(errCode, -E_INTERNAL_ERROR);

    RuntimeContext::GetInstance()->StopTaskPool();

    storageProxy.reset();
    delete iCloud;
    idb = nullptr;
}
/**
 * @tc.name: UploadModeCheck010
 * @tc.desc: Test case1 about batch api in upload
 * @tc.type: FUNC
 * @tc.require: AR000HSNJO
 * @tc.author: huangboxin
 */
HWTEST_F(DistributedDBCloudSyncerUploadTest, UploadModeCheck010, TestSize.Level1)
{
    // insert has data, update has data, delete has data (check whether it is running normally and info count)
    MockICloudSyncStorageInterface *iCloud = new MockICloudSyncStorageInterface();
    std::shared_ptr<TestStorageProxy> storageProxy = std::make_shared<TestStorageProxy>(iCloud);
    TestCloudSyncer cloudSyncer(storageProxy);
    std::shared_ptr<MockICloudDB> idb = std::make_shared<MockICloudDB>();
    cloudSyncer.SetMockICloudDB(idb);

    TaskId taskId = 6u;
    cloudSyncer.InitCloudSyncer(taskId, SYNC_MODE_CLOUD_FORCE_PUSH);
    CloudSyncData uploadData(cloudSyncer.GetCurrentContextTableName());
    cloudSyncer.initFullCloudSyncData(uploadData, 1000);

    EXPECT_CALL(*iCloud, GetCloudData(_, _, _, _))
    .WillOnce([&uploadData](const TableSchema &, const Timestamp &,
        ContinueToken &continueStmtToken, CloudSyncData &cloudDataResult) {
        cloudDataResult = uploadData;
        return E_OK;
    });
    EXPECT_CALL(*iCloud, StartTransaction(_)).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*iCloud, ChkSchema(_)).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*iCloud, GetMetaData(_, _)).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*iCloud, GetUploadCount(_, _, _, _))
        .WillRepeatedly([](const std::string &, const Timestamp &, const bool, int64_t & count) {
        count = 3000;
        return E_OK;
    });
    EXPECT_CALL(*iCloud, Commit()).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*iCloud, Rollback()).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*iCloud, PutMetaData(_, _)).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*idb, BatchInsert(_, _, _)).WillRepeatedly(Return(OK));
    EXPECT_CALL(*idb, BatchDelete(_, _)).WillRepeatedly(Return(OK));
    EXPECT_CALL(*idb, BatchUpdate(_, _, _)).WillRepeatedly(Return(OK));
    EXPECT_CALL(*iCloud, GetCloudDataNext(_, _)).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*iCloud, GetCloudDbSchema(_)).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*iCloud, GetCloudTableSchema(_, _)).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*iCloud, FillCloudGid(_)).WillRepeatedly(Return(E_OK));

    int errCode = cloudSyncer.CallDoUpload(taskId);
    EXPECT_EQ(errCode, E_OK);
    std::this_thread::sleep_for(std::chrono::seconds(1));
    EXPECT_EQ(cloudSyncer.GetUploadSuccessCount(taskId), 3000);
    EXPECT_EQ(cloudSyncer.GetUploadFailCount(taskId), 0);

    RuntimeContext::GetInstance()->StopTaskPool();
    storageProxy.reset();
    delete iCloud;
    idb = nullptr;
}

/**
 * @tc.name: UploadModeCheck011
 * @tc.desc: Test case2 about batch api in upload
 * @tc.type: FUNC
 * @tc.require: AR000HSNJO
 * @tc.author: huangboxin
 */
HWTEST_F(DistributedDBCloudSyncerUploadTest, UploadModeCheck011, TestSize.Level1)
{
    MockICloudSyncStorageInterface *iCloud = new MockICloudSyncStorageInterface();
    std::shared_ptr<TestStorageProxy> storageProxy = std::make_shared<TestStorageProxy>(iCloud);
    TestCloudSyncer cloudSyncer(storageProxy);
    std::shared_ptr<MockICloudDB> idb = std::make_shared<MockICloudDB>();
    cloudSyncer.SetMockICloudDB(idb);
    VBucket tmp = {pair<std::string, int64_t>(CloudDbConstant::MODIFY_FIELD, 1)};
    cloudSyncer.InitCloudSyncer(6u, SYNC_MODE_CLOUD_FORCE_PUSH);

    EXPECT_CALL(*iCloud, StartTransaction(_)).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*iCloud, ChkSchema(_)).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*iCloud, GetMetaData(_, _)).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*iCloud, GetUploadCount(_, _, _, _))
        .WillRepeatedly([](const std::string &, const Timestamp &, const bool, int64_t & count) {
        count = 3000;
        return E_OK;
    });
    EXPECT_CALL(*iCloud, Commit()).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*iCloud, Rollback()).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*iCloud, PutMetaData(_, _)).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*idb, BatchInsert(_, _, _)).WillRepeatedly(Return(OK));
    EXPECT_CALL(*idb, BatchDelete(_, _)).WillRepeatedly(Return(OK));
    EXPECT_CALL(*idb, BatchUpdate(_, _, _)).WillRepeatedly(Return(OK));
    EXPECT_CALL(*iCloud, GetCloudDataNext(_, _)).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*iCloud, GetCloudDbSchema(_)).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*iCloud, GetCloudTableSchema(_, _)).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*iCloud, FillCloudGid(_)).WillRepeatedly(Return(E_OK));

    // insert has no data, update and delete have data
    CloudSyncData uploadData2(cloudSyncer.GetCurrentContextTableName());
    uploadData2.updData.record = std::vector<VBucket>(1000, tmp);
    uploadData2.updData.extend = std::vector<VBucket>(1000, tmp);
    uploadData2.delData.record = std::vector<VBucket>(1000, tmp);
    uploadData2.delData.extend = std::vector<VBucket>(1000, tmp);
    EXPECT_CALL(*iCloud, GetCloudData(_, _, _, _))
    .WillOnce([&uploadData2](const TableSchema &, const Timestamp &,
        ContinueToken &continueStmtToken, CloudSyncData &cloudDataResult) {
        cloudDataResult = uploadData2;
        return E_OK;
    });
    int errCode = cloudSyncer.CallDoUpload(6u);
    std::this_thread::sleep_for(std::chrono::seconds(1));
    EXPECT_EQ(errCode, E_OK);
    EXPECT_EQ(cloudSyncer.GetUploadSuccessCount(6u), 2000);
    EXPECT_EQ(cloudSyncer.GetUploadFailCount(6u), 0);

    RuntimeContext::GetInstance()->StopTaskPool();

    storageProxy.reset();
    delete iCloud;
    idb = nullptr;
}

/**
 * @tc.name: UploadModeCheck012
 * @tc.desc: Test case2 about batch api in upload
 * @tc.type: FUNC
 * @tc.require: AR000HSNJO
 * @tc.author: huangboxin
 */
HWTEST_F(DistributedDBCloudSyncerUploadTest, UploadModeCheck012, TestSize.Level1)
{
    MockICloudSyncStorageInterface *iCloud = new MockICloudSyncStorageInterface();
    std::shared_ptr<TestStorageProxy> storageProxy = std::make_shared<TestStorageProxy>(iCloud);
    TestCloudSyncer cloudSyncer(storageProxy);
    std::shared_ptr<MockICloudDB> idb = std::make_shared<MockICloudDB>();
    cloudSyncer.SetMockICloudDB(idb);
    VBucket tmp = {pair<std::string, int64_t>(CloudDbConstant::MODIFY_FIELD, 1)};
    cloudSyncer.InitCloudSyncer(6u, SYNC_MODE_CLOUD_FORCE_PUSH);

    EXPECT_CALL(*iCloud, StartTransaction(_)).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*iCloud, ChkSchema(_)).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*iCloud, GetMetaData(_, _)).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*iCloud, GetUploadCount(_, _, _, _))
        .WillRepeatedly([](const std::string &, const Timestamp &, const bool, int64_t & count) {
        count = 3000;
        return E_OK;
    });
    EXPECT_CALL(*iCloud, Commit()).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*iCloud, Rollback()).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*iCloud, PutMetaData(_, _)).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*idb, BatchInsert(_, _, _)).WillRepeatedly(Return(OK));
    EXPECT_CALL(*idb, BatchDelete(_, _)).WillRepeatedly(Return(OK));
    EXPECT_CALL(*idb, BatchUpdate(_, _, _)).WillRepeatedly(Return(OK));
    EXPECT_CALL(*iCloud, GetCloudDataNext(_, _)).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*iCloud, GetCloudDbSchema(_)).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*iCloud, GetCloudTableSchema(_, _)).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*iCloud, FillCloudGid(_)).WillRepeatedly(Return(E_OK));

    // insert has data, update has no data, delete has data
    CloudSyncData uploadData3(cloudSyncer.GetCurrentContextTableName());
    uploadData3.insData.record = std::vector<VBucket>(1000, tmp);
    uploadData3.insData.extend = std::vector<VBucket>(1000, tmp);
    uploadData3.delData.record = std::vector<VBucket>(1000, tmp);
    uploadData3.delData.extend = std::vector<VBucket>(1000, tmp);
    EXPECT_CALL(*iCloud, GetCloudData(_, _, _, _))
    .WillOnce([&uploadData3](const TableSchema &, const Timestamp &,
        ContinueToken &continueStmtToken, CloudSyncData &cloudDataResult) {
        cloudDataResult = uploadData3;
        return E_OK;
    });
    int errCode = cloudSyncer.CallDoUpload(6u);
    std::this_thread::sleep_for(std::chrono::seconds(1));
    EXPECT_EQ(errCode, E_OK);
    EXPECT_EQ(cloudSyncer.GetUploadSuccessCount(6u), 2000);
    EXPECT_EQ(cloudSyncer.GetUploadFailCount(6u), 0);

    RuntimeContext::GetInstance()->StopTaskPool();

    storageProxy.reset();
    delete iCloud;
    idb = nullptr;
}

/**
 * @tc.name: UploadModeCheck013
 * @tc.desc: Test case1 about upload when batch api are partially successful.
 * @tc.type: FUNC
 * @tc.require: AR000HSNJO
 * @tc.author: huangboxin
 */
HWTEST_F(DistributedDBCloudSyncerUploadTest, UploadModeCheck013, TestSize.Level1)
{
    // batch api all success.
    MockICloudSyncStorageInterface *iCloud = new MockICloudSyncStorageInterface();
    std::shared_ptr<TestStorageProxy> storageProxy = std::make_shared<TestStorageProxy>(iCloud);
    TestCloudSyncer cloudSyncer(storageProxy);
    std::shared_ptr<MockICloudDB> idb = std::make_shared<MockICloudDB>();
    cloudSyncer.SetMockICloudDB(idb);
    TaskId taskId = 7u;
    cloudSyncer.InitCloudSyncer(taskId, SYNC_MODE_CLOUD_FORCE_PUSH);

    CommonExpectCall(iCloud);
    EXPECT_CALL(*iCloud, PutMetaData(_, _)).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*iCloud, FillCloudGid(_)).WillRepeatedly(Return(E_OK));

    CloudSyncData uploadData(cloudSyncer.GetCurrentContextTableName());
    cloudSyncer.initFullCloudSyncData(uploadData, 1000);
    EXPECT_CALL(*iCloud, GetCloudData(_, _, _, _))
    .WillRepeatedly([&uploadData](const TableSchema &, const Timestamp &,
        ContinueToken &continueStmtToken, CloudSyncData &cloudDataResult) {
        cloudDataResult = uploadData;
        return E_OK;
    });
    EXPECT_CALL(*iCloud, GetUploadCount(_, _, _, _))
        .WillOnce([](const std::string &, const Timestamp &, const bool, int64_t & count) {
        count = 3000;
        return E_OK;
    });
    EXPECT_CALL(*idb, BatchInsert(_, _, _)).WillOnce([&uploadData](const std::string &, std::vector<VBucket> &&record,
        std::vector<VBucket> &extend) {
            record = uploadData.insData.record;
            extend = uploadData.insData.extend;
            return OK;
    });
    EXPECT_CALL(*idb, BatchUpdate(_, _, _)).WillOnce([&uploadData](const std::string &, std::vector<VBucket> &&record,
        std::vector<VBucket> &extend) {
            record = uploadData.updData.record;
            extend = uploadData.updData.extend;
            return OK;
    });
    EXPECT_CALL(*idb, BatchDelete(_, _)).WillOnce([&uploadData](const std::string &, std::vector<VBucket> &extend) {
        extend = uploadData.delData.extend;
        return OK;
    });
    int errCode = cloudSyncer.CallDoUpload(taskId);
    EXPECT_EQ(errCode, E_OK);
    cloudSyncer.CallNotify();
    std::this_thread::sleep_for(std::chrono::seconds(1));
    EXPECT_EQ(cloudSyncer.GetUploadSuccessCount(taskId), 3000);
    EXPECT_EQ(cloudSyncer.GetUploadFailCount(taskId), 0);


    RuntimeContext::GetInstance()->StopTaskPool();
    storageProxy.reset();
    delete iCloud;
}

/**
 * @tc.name: UploadModeCheck014
 * @tc.desc: Test case2 about upload when batch api are partially successful.
 * @tc.type: FUNC
 * @tc.require: AR000HSNJO
 * @tc.author: huangboxin
 */
HWTEST_F(DistributedDBCloudSyncerUploadTest, UploadModeCheck014, TestSize.Level1)
{
    MockICloudSyncStorageInterface *iCloud = new MockICloudSyncStorageInterface();
    std::shared_ptr<TestStorageProxy> storageProxy = std::make_shared<TestStorageProxy>(iCloud);
    TestCloudSyncer cloudSyncer2(storageProxy);
    std::shared_ptr<MockICloudDB> idb2 = std::make_shared<MockICloudDB>();
    cloudSyncer2.SetMockICloudDB(idb2);
    TaskId taskId = 8u;

    CommonExpectCall(iCloud);
    EXPECT_CALL(*iCloud, PutMetaData(_, _)).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*iCloud, FillCloudGid(_)).WillRepeatedly(Return(E_OK));

    // batch api partially success
    cloudSyncer2.InitCloudSyncer(taskId, SYNC_MODE_CLOUD_FORCE_PUSH);
    CloudSyncData uploadData2(cloudSyncer2.GetCurrentContextTableName());
    cloudSyncer2.initFullCloudSyncData(uploadData2, 1000);
    EXPECT_CALL(*iCloud, GetCloudData(_, _, _, _)).WillRepeatedly(
        [&uploadData2](const TableSchema &, const Timestamp &, ContinueToken &, CloudSyncData &cloudDataResult) {
        cloudDataResult = uploadData2; return E_OK;
    });
    EXPECT_CALL(*iCloud, GetUploadCount(_, _, _, _))
        .WillRepeatedly([](const std::string &, const Timestamp &, const bool, int64_t & count) {
        count = 3000;
        return E_OK;
    });
    EXPECT_CALL(*idb2, BatchDelete(_, _)).WillOnce([&uploadData2](const std::string &,
        std::vector<VBucket> &extend) {
            extend = uploadData2.insData.extend;
            return OK;
    });
    EXPECT_CALL(*idb2, BatchInsert(_, _, _)).WillOnce([&uploadData2](const std::string &,
        std::vector<VBucket> &&record, std::vector<VBucket> &extend) {
            record = uploadData2.updData.record;
            extend = uploadData2.updData.extend;
            return DB_ERROR;
    });
    int errCode = cloudSyncer2.CallDoUpload(taskId);
    EXPECT_EQ(errCode, -E_CLOUD_UPLOAD_FAILED);
    cloudSyncer2.CallNotify();
    std::this_thread::sleep_for(std::chrono::seconds(1));
    EXPECT_EQ(cloudSyncer2.GetUploadSuccessCount(taskId), 1000);
    EXPECT_EQ(cloudSyncer2.GetUploadFailCount(taskId), 2000);

    RuntimeContext::GetInstance()->StopTaskPool();
    storageProxy.reset();
    delete iCloud;
    idb2 = nullptr;
}

/**
 * @tc.name: UploadModeCheck015
 * @tc.desc: Test case3 about upload when batch api are partially successful.
 * @tc.type: FUNC
 * @tc.require: AR000HSNJO
 * @tc.author: huangboxin
 */
HWTEST_F(DistributedDBCloudSyncerUploadTest, UploadModeCheck015, TestSize.Level1)
{
    MockICloudSyncStorageInterface *iCloud = new MockICloudSyncStorageInterface();
    std::shared_ptr<TestStorageProxy> storageProxy = std::make_shared<TestStorageProxy>(iCloud);
    TestCloudSyncer cloudSyncer3(storageProxy);
    std::shared_ptr<MockICloudDB> idb3 = std::make_shared<MockICloudDB>();
    cloudSyncer3.SetMockICloudDB(idb3);

    CommonExpectCall(iCloud);
    EXPECT_CALL(*iCloud, PutMetaData(_, _)).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*iCloud, FillCloudGid(_)).WillRepeatedly(Return(E_OK));

    // BatchInsert failed, BatchUpdate ok, BatchDelete ok
    cloudSyncer3.InitCloudSyncer(9u, SYNC_MODE_CLOUD_FORCE_PUSH);
    CloudSyncData uploadData3(cloudSyncer3.GetCurrentContextTableName());
    cloudSyncer3.initFullCloudSyncData(uploadData3, 1000);
    EXPECT_CALL(*iCloud, GetCloudData(_, _, _, _))
    .WillRepeatedly([&uploadData3](const TableSchema &, const Timestamp &, ContinueToken &,
        CloudSyncData &cloudDataResult) {
        cloudDataResult = uploadData3;
        return E_OK;
    });
    EXPECT_CALL(*iCloud, GetUploadCount(_, _, _, _))
        .WillOnce([](const std::string &, const Timestamp &, const bool, int64_t & count) {
        count = 3000;
        return E_OK;
    });
    EXPECT_CALL(*idb3, BatchDelete(_, _)).WillRepeatedly([&uploadData3](const std::string &,
        std::vector<VBucket> &extend) {
            extend = uploadData3.insData.extend;
            return DB_ERROR;
    });
    EXPECT_CALL(*idb3, BatchInsert(_, _, _)).WillRepeatedly([&uploadData3](const std::string &,
        std::vector<VBucket> &&record, std::vector<VBucket> &extend) {
            record = uploadData3.updData.record;
            extend = uploadData3.updData.extend;
            return OK;
    });
    EXPECT_CALL(*idb3, BatchUpdate(_, _, _)).WillRepeatedly([&uploadData3](const std::string &,
        std::vector<VBucket> &&record, std::vector<VBucket> &extend) {
            record = uploadData3.updData.record;
            extend = uploadData3.delData.extend;
        return OK;
    });
    int errCode = cloudSyncer3.CallDoUpload(9u);
    cloudSyncer3.CallNotify();

    RuntimeContext::GetInstance()->StopTaskPool();
    EXPECT_EQ(errCode, -E_CLOUD_UPLOAD_FAILED);
    EXPECT_EQ(cloudSyncer3.GetUploadSuccessCount(9u), 0);
    EXPECT_EQ(cloudSyncer3.GetUploadFailCount(9u), 3000);

    storageProxy.reset();
    delete iCloud;
    idb3 = nullptr;
}

static void ExpectCallForTestCase016(std::shared_ptr<MockICloudDB> idb, CloudSyncData &uploadData)
{
    EXPECT_CALL(*idb, BatchInsert(_, _, _)).WillRepeatedly([&uploadData](const std::string &,
        std::vector<VBucket> &&record, std::vector<VBucket> &extend) {
            record = uploadData.insData.record;
            extend = uploadData.insData.extend;
            return OK;
    });
    EXPECT_CALL(*idb, BatchUpdate(_, _, _)).WillRepeatedly([&uploadData](const std::string &,
    std::vector<VBucket> &&record, std::vector<VBucket> &extend) {
            record = uploadData.updData.record;
            extend = uploadData.updData.extend;
            return OK;
    });
    EXPECT_CALL(*idb, BatchDelete(_, _)).WillRepeatedly([&uploadData](const std::string &,
        std::vector<VBucket> &extend) {
        extend = uploadData.delData.extend;
        return OK;
    });
}

/**
 * @tc.name: UploadModeCheck016
 * @tc.desc: Test case about water level in upload
 * @tc.type: FUNC
 * @tc.require: AR000HSNJO
 * @tc.author: huangboxin
 */
HWTEST_F(DistributedDBCloudSyncerUploadTest, UploadModeCheck016, TestSize.Level1)
{
    // update water level successful
    MockICloudSyncStorageInterface *iCloud = new MockICloudSyncStorageInterface();
    std::shared_ptr<TestStorageProxy> storageProxy = std::make_shared<TestStorageProxy>(iCloud);
    TestCloudSyncer cloudSyncer(storageProxy);
    std::shared_ptr<MockICloudDB> idb = std::make_shared<MockICloudDB>();
    cloudSyncer.SetMockICloudDB(idb);
    cloudSyncer.InitCloudSyncer(8u, SYNC_MODE_CLOUD_MERGE);
    cloudSyncer.SetCloudWaterMarks(TABLE_NAME_1, CLOUD_WATER_MARK);

    CommonExpectCall(iCloud);
    // CheckSchema
    EXPECT_CALL(*iCloud, GetUploadCount(_, _, _, _))
        .WillRepeatedly([](const std::string &, const Timestamp &, const bool, int64_t & count) {
        count = 3000;
        return E_OK;
    });
    VBucket tmp = {pair<std::string, int64_t>(CloudDbConstant::MODIFY_FIELD, 1)};
    CloudSyncData uploadData(cloudSyncer.GetCurrentContextTableName());
    cloudSyncer.initFullCloudSyncData(uploadData, 1000);

    EXPECT_CALL(*iCloud, FillCloudGid(_)).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*iCloud, GetCloudData(_, _, _, _))
    .WillRepeatedly([&uploadData](const TableSchema &, const Timestamp &,
        ContinueToken &continueStmtToken, CloudSyncData &cloudDataResult) {
        cloudDataResult = uploadData;
        return E_OK;
    });
    ExpectCallForTestCase016(idb, uploadData);
    EXPECT_EQ(cloudSyncer.CallDoUpload(8u), E_OK);
    EXPECT_CALL(*iCloud, PutMetaData(_, _)).WillOnce(Return(-E_INVALID_DB));
    EXPECT_EQ(cloudSyncer.CallDoUpload(8u), -E_INVALID_DB);

    EXPECT_CALL(*iCloud, PutMetaData(_, _)).WillOnce(Return(-E_INVALID_ARGS));
    EXPECT_EQ(cloudSyncer.CallDoUpload(8u), -E_INVALID_ARGS);
    RuntimeContext::GetInstance()->StopTaskPool();

    storageProxy.reset();
    delete iCloud;
    idb = nullptr;
}

void MockCall(MockICloudSyncStorageInterface *iCloud, const std::shared_ptr<MockICloudDB> &idb)
{
    EXPECT_CALL(*iCloud, FillCloudGid(_)).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*idb, BatchInsert(_, _, _)).WillRepeatedly(Return(OK));
    EXPECT_CALL(*iCloud, PutMetaData(_, _)).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*iCloud, GetUploadCount(_, _, _, _))
        .WillRepeatedly([](const std::string &, const Timestamp &, const bool, int64_t & count) {
        count = 2000; // total 2000
        return E_OK;
    });
}

/**
 * @tc.name: UploadModeCheck018
 * @tc.desc: Test notify count when upload with two batch
 * @tc.type: FUNC
 * @tc.require: AR000HSNJO
 * @tc.author: zhangqiquan
 */
HWTEST_F(DistributedDBCloudSyncerUploadTest, UploadModeCheck018, TestSize.Level1)
{
    auto *iCloud = new(std::nothrow) MockICloudSyncStorageInterface();
    ASSERT_NE(iCloud, nullptr);
    std::shared_ptr<TestStorageProxy> storageProxy = std::make_shared<TestStorageProxy>(iCloud);
    TestCloudSyncer cloudSyncer(storageProxy);
    auto idb = std::make_shared<MockICloudDB>();
    cloudSyncer.SetMockICloudDB(idb);
    cloudSyncer.InitCloudSyncer(5u, SYNC_MODE_CLOUD_FORCE_PUSH);

    CommonExpectCall(iCloud);
    MockCall(iCloud, idb);

    // Batch_n CloudSyncData quantity > total count
    VBucket tmp = {pair<std::string, int64_t>(CloudDbConstant::MODIFY_FIELD, 1)};
    cloudSyncer.InitCloudSyncer(5u, SYNC_MODE_CLOUD_FORCE_PUSH);
    CloudSyncData uploadData2(cloudSyncer.GetCurrentContextTableName());
    uploadData2.insData.record = std::vector<VBucket>(1000, tmp);
    uploadData2.insData.extend = std::vector<VBucket>(1000, tmp);

    SyncTimeRange syncTimeRange = { .beginTime = 1u };
    QueryObject queryObject(Query::Select());
    queryObject.SetTableName(cloudSyncer.GetCurrentContextTableName());
    auto token = new (std::nothrow) SQLiteSingleVerRelationalContinueToken(syncTimeRange, queryObject);
    auto conStmtToken = static_cast<ContinueToken>(token);
    delete token;
    EXPECT_CALL(*iCloud, GetCloudData(_, _, _, _))
        .WillOnce([&conStmtToken, &uploadData2](const TableSchema &, const Timestamp &,
            ContinueToken &continueStmtToken, CloudSyncData &cloudDataResult) {
            cloudDataResult = uploadData2;
            continueStmtToken = conStmtToken;
            return -E_UNFINISHED;
        });

    CloudSyncData uploadData3(cloudSyncer.GetCurrentContextTableName());
    uploadData3.insData.extend = std::vector<VBucket>(2001, tmp);
    uploadData3.insData.record = std::vector<VBucket>(2001, tmp);
    EXPECT_CALL(*iCloud, GetCloudDataNext(_, _)).WillOnce(
        [&uploadData3](ContinueToken &, CloudSyncData &cloudDataResult) {
        cloudDataResult = uploadData3;
        return E_OK;
    });
    std::atomic<int> callCount = 0;
    cloudSyncer.SetCurrentCloudTaskInfos({"TABLE"}, [&callCount](const std::map<std::string, SyncProcess> &) {
        callCount++;
    });
    int errCode = cloudSyncer.CallDoUpload(5u, true);
    EXPECT_EQ(errCode, -E_INTERNAL_ERROR);

    RuntimeContext::GetInstance()->StopTaskPool();
    EXPECT_EQ(callCount, 1);

    storageProxy.reset();
    delete iCloud;
    idb = nullptr;
}

void MockMethod(const std::shared_ptr<MockICloudDB> &idb, MockICloudSyncStorageInterface *iCloud)
{
    EXPECT_CALL(*idb, BatchInsert(_, _, _)).WillRepeatedly(Return(OK));
    EXPECT_CALL(*idb, BatchUpdate(_, _, _)).WillRepeatedly(Return(OK));
    EXPECT_CALL(*idb, BatchDelete(_, _)).WillRepeatedly(Return(OK));
    EXPECT_CALL(*idb, Query(_, _, _)).WillRepeatedly(Return(QUERY_END));
    EXPECT_CALL(*iCloud, FillCloudGid(_)).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*iCloud, GetUploadCount(_, _, _, _))
        .WillRepeatedly([](const std::string &, const Timestamp &, const bool, int64_t & count) {
            count = 3000; // 3000 is upload count
            return E_OK;
    });
}
/**
 * @tc.name: UploadNotifyCheck001
 * @tc.desc: Test case about multiple tables in upload
 * @tc.type: FUNC
 * @tc.require: AR000HSNJO
 * @tc.author: huangboxin
 */
HWTEST_F(DistributedDBCloudSyncerUploadTest, UploadNotifyCheck001, TestSize.Level1)
{
    MockICloudSyncStorageInterface *iCloud = new MockICloudSyncStorageInterface();
    std::shared_ptr<TestStorageProxy> storageProxy = std::make_shared<TestStorageProxy>(iCloud);
    TestCloudSyncer cloudSyncer(storageProxy);
    std::shared_ptr<MockICloudDB> idb = std::make_shared<MockICloudDB>();
    cloudSyncer.SetMockICloudDB(idb);
    TaskId taskId = 17u;
    cloudSyncer.InitCloudSyncer(taskId, SYNC_MODE_CLOUD_FORCE_PUSH);
    std::string tableName2 = "TestTable2" + std::to_string(taskId);
    std::vector<std::string> tables = {cloudSyncer.GetCurrentContextTableName(), tableName2};
    SyncProcess res;
    TableProcessInfo tbProcessInfo;
    res.tableProcess[cloudSyncer.GetCurrentContextTableName()] = tbProcessInfo;
    res.tableProcess[tableName2] = tbProcessInfo;
    cloudSyncer.SetCurrentCloudTaskInfos(tables, [&res](
        const std::map<std::string, SyncProcess> &process) {
        res = process.begin()->second;
    });
    CommonExpectCall(iCloud);
    MockMethod(idb, iCloud);
    CloudSyncData uploadData(cloudSyncer.GetCurrentContextTableName());
    cloudSyncer.initFullCloudSyncData(uploadData, 1000);    // each size 1000
    CloudSyncData uploadData2(tableName2);
    cloudSyncer.initFullCloudSyncData(uploadData2, 1000);   // each size 1000

    EXPECT_CALL(*iCloud, GetCloudData(_, _, _, _))
        .WillOnce([&uploadData](const TableSchema &, const Timestamp &,
            ContinueToken &, CloudSyncData &cloudDataResult) {
            cloudDataResult = uploadData;
            return E_OK;})
        .WillOnce([&uploadData2](const TableSchema &, const Timestamp &,
            ContinueToken &, CloudSyncData &cloudDataResult) {
            cloudDataResult = uploadData2;
            return E_OK;});

    EXPECT_EQ(cloudSyncer.CallDoSyncInner(cloudSyncer.GetCurrentCloudTaskInfos(), true), E_OK);
    EXPECT_EQ(res.tableProcess[cloudSyncer.GetCurrentContextTableName()].process, PROCESSING);
    cloudSyncer.CallNotify();
    RuntimeContext::GetInstance()->StopTaskPool();
    EXPECT_EQ(res.tableProcess[cloudSyncer.GetCurrentContextTableName()].process, FINISHED);
    EXPECT_EQ(res.tableProcess[tableName2].process, FINISHED);
    storageProxy.reset();
    delete iCloud;
    idb = nullptr;
}

/**
 * @tc.name: UploadNotifyCheck002
 * @tc.desc: Test case about multiple tables in upload
 * @tc.type: FUNC
 * @tc.require: AR000HSNJO
 * @tc.author: huangboxin
 */
HWTEST_F(DistributedDBCloudSyncerUploadTest, UploadNotifyCheck002, TestSize.Level1)
{
    MockICloudSyncStorageInterface *iCloud = new MockICloudSyncStorageInterface();
    std::shared_ptr<TestStorageProxy> storageProxy = std::make_shared<TestStorageProxy>(iCloud);
    TestCloudSyncer cloudSyncer(storageProxy);
    std::shared_ptr<MockICloudDB> idb = std::make_shared<MockICloudDB>();
    cloudSyncer.SetMockICloudDB(idb);
    TaskId taskId = 17u;
    cloudSyncer.InitCloudSyncer(taskId, SYNC_MODE_CLOUD_FORCE_PUSH);
    std::string tableName2 = "TestTable2" + std::to_string(taskId);
    std::vector<std::string> tables = {
        cloudSyncer.GetCurrentContextTableName(), tableName2
    };
    SyncProcess res;
    TableProcessInfo tbProcessInfo;
    res.tableProcess[cloudSyncer.GetCurrentContextTableName()] = tbProcessInfo;
    res.tableProcess[tableName2] = tbProcessInfo;

    cloudSyncer.SetCurrentCloudTaskInfos(tables, [&res](
        const std::map<std::string, SyncProcess> &process) {
        res = process.begin()->second;
    });
    CommonExpectCall(iCloud);
    // table A failed, table B will not be uploaded
    EXPECT_CALL(*idb, BatchInsert(_, _, _)).WillOnce(Return(OK));
    EXPECT_CALL(*idb, BatchUpdate(_, _, _)).WillOnce(Return(DB_ERROR));
    EXPECT_CALL(*idb, Query(_, _, _)).WillRepeatedly(Return(QUERY_END));
    EXPECT_CALL(*iCloud, FillCloudGid(_)).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*iCloud, GetUploadCount(_, _, _, _))
        .WillRepeatedly([](const std::string &, const Timestamp &, const bool, int64_t & count) {
            count = 3000;   // total count is 3000
            return E_OK;
    });
    CloudSyncData uploadData(cloudSyncer.GetCurrentContextTableName());
    cloudSyncer.initFullCloudSyncData(uploadData, 1000);    // each size 1000

    EXPECT_CALL(*iCloud, GetCloudData(_, _, _, _))
        .WillOnce([&uploadData](const TableSchema &, const Timestamp &,
            ContinueToken &, CloudSyncData &cloudDataResult) {
            cloudDataResult = uploadData;
            return E_OK;});

    EXPECT_EQ(cloudSyncer.CallDoSyncInner(cloudSyncer.GetCurrentCloudTaskInfos(), true), -E_CLOUD_UPLOAD_FAILED);
    cloudSyncer.CallNotify();
    RuntimeContext::GetInstance()->StopTaskPool();
    EXPECT_EQ(res.tableProcess[cloudSyncer.GetCurrentContextTableName()].process, PROCESSING);
    EXPECT_EQ(res.tableProcess[tableName2].process, PROCESSING);
    storageProxy.reset();
    delete iCloud;
    idb = nullptr;
}

/**
 * @tc.name: UploadNotifyCheck003
 * @tc.desc: Test case about multiple tables in upload
 * @tc.type: FUNC
 * @tc.require: AR000HSNJO
 * @tc.author: huangboxin
 */
HWTEST_F(DistributedDBCloudSyncerUploadTest, UploadNotifyCheck003, TestSize.Level1)
{
    MockICloudSyncStorageInterface *iCloud = new MockICloudSyncStorageInterface();
    std::shared_ptr<TestStorageProxy> storageProxy = std::make_shared<TestStorageProxy>(iCloud);
    TestCloudSyncer cloudSyncer(storageProxy);
    std::shared_ptr<MockICloudDB> idb = std::make_shared<MockICloudDB>();
    cloudSyncer.SetMockICloudDB(idb);
    TaskId taskId = 19u;
    cloudSyncer.InitCloudSyncer(taskId, SYNC_MODE_CLOUD_FORCE_PUSH);
    std::string tableName2 = "TestTable2" + std::to_string(taskId);
    std::vector<std::string> tables = {
        cloudSyncer.GetCurrentContextTableName(), tableName2
    };
    SyncProcess res;
    TableProcessInfo tbProcessInfo;
    res.tableProcess[cloudSyncer.GetCurrentContextTableName()] = tbProcessInfo;
    res.tableProcess[tableName2] = tbProcessInfo;

    cloudSyncer.SetCurrentCloudTaskInfos(tables, [&res](
        const std::map<std::string, SyncProcess> &process) {
        res = process.begin()->second;
    });
    CommonExpectCall(iCloud);
    EXPECT_CALL(*idb, BatchInsert(_, _, _)).WillRepeatedly(Return(OK));
    EXPECT_CALL(*idb, BatchUpdate(_, _, _)).WillRepeatedly(Return(OK));
    EXPECT_CALL(*idb, BatchDelete(_, _)).WillRepeatedly(Return(OK));
    EXPECT_CALL(*idb, Query(_, _, _)).WillRepeatedly(Return(QUERY_END));
    EXPECT_CALL(*iCloud, FillCloudGid(_)).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*iCloud, GetUploadCount(_, _, _, _))
        .WillRepeatedly([](const std::string &, const Timestamp &, const bool, int64_t & count) {
            count = 0;
            return E_OK;
    });
    // test when count == 0
    EXPECT_EQ(cloudSyncer.CallDoSyncInner(cloudSyncer.GetCurrentCloudTaskInfos(), true), E_OK);
    cloudSyncer.CallNotify();
    RuntimeContext::GetInstance()->StopTaskPool();
    EXPECT_EQ(res.tableProcess[cloudSyncer.GetCurrentContextTableName()].process, FINISHED);
    EXPECT_EQ(res.tableProcess[tableName2].process, FINISHED);
    storageProxy.reset();
    delete iCloud;
    idb = nullptr;
}
}