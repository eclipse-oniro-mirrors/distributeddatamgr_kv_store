/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifdef RELATIONAL_STORE
#include <gtest/gtest.h>
#include "cloud/cloud_db_constant.h"
#include "cloud/cloud_db_types.h"
#include "cloud_db_sync_utils_test.h"
#include "db_common.h"
#include "distributeddb_data_generate_unit_test.h"
#include "log_print.h"
#include "relational_store_delegate.h"
#include "relational_store_instance.h"
#include "relational_store_manager.h"
#include "relational_sync_able_storage.h"
#include "runtime_config.h"
#include "time_helper.h"
#include "virtual_asset_loader.h"
#include "virtual_cloud_data_translate.h"
#include "virtual_cloud_db.h"
#include "virtual_communicator_aggregator.h"

using namespace testing::ext;
using namespace DistributedDB;
using namespace DistributedDBUnitTest;

namespace {
constexpr const char *DB_SUFFIX = ".db";
constexpr const char *STORE_ID = "Relational_Store_ID";
constexpr const char *CREATE_TABLE_A_SQL =
    "CREATE TABLE IF NOT EXISTS worker_a(" \
    "id TEXT PRIMARY KEY," \
    "name TEXT," \
    "height REAL ," \
    "photo BLOB," \
    "age INT);";
constexpr const char *CREATE_TABLE_B_SQL =
    "CREATE TABLE IF NOT EXISTS worker_b(" \
    "id TEXT PRIMARY KEY," \
    "name TEXT," \
    "height REAL ," \
    "photo BLOB," \
    "age INT);";
constexpr const char *CREATE_TABLE_C_SQL =
    "CREATE TABLE IF NOT EXISTS worker_c(" \
    "id TEXT PRIMARY KEY," \
    "name TEXT," \
    "height REAL ," \
    "photo BLOB," \
    "age INT);";
constexpr const char *CREATE_TABLE_D_SQL =
    "CREATE TABLE IF NOT EXISTS worker_d(" \
    "id TEXT PRIMARY KEY," \
    "name TEXT," \
    "height REAL ," \
    "photo BLOB," \
    "age INT);";
const int64_t SYNC_WAIT_TIME = 60;

void CreateUserDBAndTable(sqlite3 *&db)
{
    EXPECT_EQ(RelationalTestUtils::ExecSql(db, "PRAGMA journal_mode=WAL;"), SQLITE_OK);
    EXPECT_EQ(RelationalTestUtils::ExecSql(db, CREATE_TABLE_A_SQL), SQLITE_OK);
    EXPECT_EQ(RelationalTestUtils::ExecSql(db, CREATE_TABLE_B_SQL), SQLITE_OK);
    EXPECT_EQ(RelationalTestUtils::ExecSql(db, CREATE_TABLE_C_SQL), SQLITE_OK);
    EXPECT_EQ(RelationalTestUtils::ExecSql(db, CREATE_TABLE_D_SQL), SQLITE_OK);
}

void PrepareOption(CloudSyncOption &option, const Query &query, bool merge = false)
{
    option.devices = { "CLOUD" };
    option.mode = SYNC_MODE_CLOUD_MERGE;
    option.query = query;
    option.waitTime = SYNC_WAIT_TIME;
    option.priorityTask = false;
    option.compensatedSyncOnly = false;
    option.merge = merge;
}

class DistributedDBCloudTaskMergeTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
protected:
    void InitTestDir();
    DataBaseSchema GetSchema();
    void CloseDb();
    void InsertUserTableRecord(const std::string &tableName, int64_t recordCounts, int64_t begin = 0);
    void CheckCloudTableCount(const std::vector<std::string> &tableName, int64_t expectCount);
    void SetForkQueryForCloudMergeSyncTest001(std::atomic<int> &count);
    static SyncProcessCallback GetProcessCallback(const std::function<void(DBStatus)> &checkFinish,
        std::mutex &callbackMutex, std::condition_variable &callbackCv, size_t &finishCount);
    std::string testDir_;
    std::string storePath_;
    sqlite3 *db_ = nullptr;
    RelationalStoreDelegate *delegate_ = nullptr;
    std::shared_ptr<VirtualCloudDb> virtualCloudDb_ = nullptr;
    std::shared_ptr<VirtualAssetLoader> virtualAssetLoader_ = nullptr;
    std::shared_ptr<RelationalStoreManager> mgr_ = nullptr;
    std::string tableNameA_ = "worker_a";
    std::string tableNameB_ = "worker_b";
    std::string tableNameC_ = "worker_c";
    std::string tableNameD_ = "worker_d";
    std::vector<std::string> tables_ = { tableNameA_, tableNameB_, tableNameC_, tableNameD_ };
    VirtualCommunicatorAggregator *communicatorAggregator_ = nullptr;
};

void DistributedDBCloudTaskMergeTest::SetUpTestCase()
{
}

void DistributedDBCloudTaskMergeTest::TearDownTestCase()
{
}

void DistributedDBCloudTaskMergeTest::SetUp()
{
    DistributedDBToolsUnitTest::PrintTestCaseInfo();
    InitTestDir();
    if (DistributedDBToolsUnitTest::RemoveTestDbFiles(testDir_) != 0) {
        LOGE("rm test db files error.");
    }
    DistributedDBToolsUnitTest::PrintTestCaseInfo();
    LOGD("Test dir is %s", testDir_.c_str());
    db_ = RelationalTestUtils::CreateDataBase(storePath_);
    ASSERT_NE(db_, nullptr);
    CreateUserDBAndTable(db_);
    mgr_ = std::make_shared<RelationalStoreManager>(APP_ID, USER_ID);
    RelationalStoreDelegate::Option option;
    ASSERT_EQ(mgr_->OpenStore(storePath_, STORE_ID_1, option, delegate_), DBStatus::OK);
    ASSERT_NE(delegate_, nullptr);
    for (const auto &table : tables_) {
        ASSERT_EQ(delegate_->CreateDistributedTable(table, CLOUD_COOPERATION), DBStatus::OK);
    }
    virtualCloudDb_ = std::make_shared<VirtualCloudDb>();
    virtualAssetLoader_ = std::make_shared<VirtualAssetLoader>();
    ASSERT_EQ(delegate_->SetCloudDB(virtualCloudDb_), DBStatus::OK);
    ASSERT_EQ(delegate_->SetIAssetLoader(virtualAssetLoader_), DBStatus::OK);
    DataBaseSchema dataBaseSchema = GetSchema();
    ASSERT_EQ(delegate_->SetCloudDbSchema(dataBaseSchema), DBStatus::OK);
    communicatorAggregator_ = new (std::nothrow) VirtualCommunicatorAggregator();
    ASSERT_TRUE(communicatorAggregator_ != nullptr);
    RuntimeContext::GetInstance()->SetCommunicatorAggregator(communicatorAggregator_);
}

void DistributedDBCloudTaskMergeTest::TearDown()
{
    virtualCloudDb_->ForkQuery(nullptr);
    virtualCloudDb_->SetCloudError(false);
    CloseDb();
    EXPECT_EQ(sqlite3_close_v2(db_), SQLITE_OK);
    if (DistributedDBToolsUnitTest::RemoveTestDbFiles(testDir_) != E_OK) {
        LOGE("rm test db files error.");
    }
    RuntimeContext::GetInstance()->SetCommunicatorAggregator(nullptr);
    communicatorAggregator_ = nullptr;
    RuntimeContext::GetInstance()->SetProcessSystemApiAdapter(nullptr);
}

void DistributedDBCloudTaskMergeTest::InitTestDir()
{
    if (!testDir_.empty()) {
        return;
    }
    DistributedDBToolsUnitTest::TestDirInit(testDir_);
    storePath_ = testDir_ + "/" + STORE_ID_1 + ".db";
    LOGI("The test db is:%s", testDir_.c_str());
}

DataBaseSchema DistributedDBCloudTaskMergeTest::GetSchema()
{
    DataBaseSchema schema;
    for (const auto &table : tables_) {
        TableSchema tableSchema;
        tableSchema.name = table;
        tableSchema.fields = {
            {"id", TYPE_INDEX<std::string>, true}, {"name", TYPE_INDEX<std::string>}, {"height", TYPE_INDEX<double>},
            {"photo", TYPE_INDEX<Bytes>}, {"age", TYPE_INDEX<int64_t>}
        };
        schema.tables.push_back(tableSchema);
    }
    return schema;
}

void DistributedDBCloudTaskMergeTest::CloseDb()
{
    virtualCloudDb_ = nullptr;
    if (mgr_ != nullptr) {
        EXPECT_EQ(mgr_->CloseStore(delegate_), DBStatus::OK);
        delegate_ = nullptr;
        mgr_ = nullptr;
    }
}

void DistributedDBCloudTaskMergeTest::InsertUserTableRecord(const std::string &tableName,
    int64_t recordCounts, int64_t begin)
{
    ASSERT_NE(db_, nullptr);
    for (int64_t i = begin; i < begin + recordCounts; ++i) {
        string sql = "INSERT OR REPLACE INTO " + tableName +
            " (id, name, height, photo, age) VALUES ('" + std::to_string(i) + "', 'Local" +
            std::to_string(i) + "', '155.10',  'text', '21');";
        ASSERT_EQ(SQLiteUtils::ExecuteRawSQL(db_, sql), E_OK);
    }
}

void DistributedDBCloudTaskMergeTest::CheckCloudTableCount(const std::vector<std::string> &tableNames,
    int64_t expectCount)
{
    for (const auto &tableName : tableNames) {
        VBucket extend;
        extend[CloudDbConstant::CURSOR_FIELD] = std::to_string(0);
        int64_t realCount = 0;
        std::vector<VBucket> data;
        virtualCloudDb_->Query(tableName, extend, data);
        for (size_t j = 0; j < data.size(); ++j) {
            auto entry = data[j].find(CloudDbConstant::DELETE_FIELD);
            if (entry != data[j].end() && std::get<bool>(entry->second)) {
                continue;
            }
            realCount++;
        }
        LOGI("check table %s", tableName.c_str());
        EXPECT_EQ(realCount, expectCount); // ExpectCount represents the total amount of cloud data.
    }
}

void DistributedDBCloudTaskMergeTest::SetForkQueryForCloudMergeSyncTest001(std::atomic<int> &count)
{
    virtualCloudDb_->ForkQuery([&count](const std::string &, VBucket &) {
        count++;
        if (count == 1) { // taskid1
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    });
}

SyncProcessCallback DistributedDBCloudTaskMergeTest::GetProcessCallback(
    const std::function<void(DBStatus)> &checkFinish, std::mutex &callbackMutex,
    std::condition_variable &callbackCv, size_t &finishCount)
{
    return [checkFinish, &callbackCv, &callbackMutex, &finishCount](const std::map<std::string, SyncProcess> &process) {
        for (const auto &item: process) {
            if (item.second.process == DistributedDB::FINISHED) {
                if (checkFinish) {
                    checkFinish(item.second.errCode);
                }
                {
                    std::lock_guard<std::mutex> callbackAutoLock(callbackMutex);
                    finishCount++;
                }
                LOGW("current finish %zu", finishCount);
                callbackCv.notify_one();
            }
        }
    };
}

/**
 * @tc.name: CloudSyncMergeTaskTest001
 * @tc.desc: test merge sync task
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: chenchaohao
 */
HWTEST_F(DistributedDBCloudTaskMergeTest, CloudSyncMergeTaskTest001, TestSize.Level1)
{
    /**
     * @tc.steps:step1. insert user table record.
     * @tc.expected: step1. ok.
     */
    const int actualCount = 10; // 10 is count of records
    InsertUserTableRecord(tableNameA_, actualCount);
    InsertUserTableRecord(tableNameB_, actualCount);
    /**
     * @tc.steps:step2. set callback to check during sync.
     * @tc.expected: step2. ok.
     */
    std::atomic<int> count = 0;
    SetForkQueryForCloudMergeSyncTest001(count);

    Query normalQuery1 = Query::Select().FromTable({ tableNameA_ });
    CloudSyncOption option;
    PrepareOption(option, normalQuery1, false);
    ASSERT_EQ(delegate_->Sync(option, nullptr), OK);

    std::mutex callbackMutex;
    std::condition_variable callbackCv;
    size_t finishCount = 0u;
    auto callback1 = GetProcessCallback(nullptr, callbackMutex, callbackCv, finishCount);

    Query normalQuery2 = Query::Select().FromTable({ tableNameB_ });
    PrepareOption(option, normalQuery2, true);
    ASSERT_EQ(delegate_->Sync(option, callback1), OK);

    InsertUserTableRecord(tableNameC_, actualCount);
    InsertUserTableRecord(tableNameD_, actualCount);

    Query normalQuery3 = Query::Select().FromTable({ tableNameC_, tableNameD_ });
    PrepareOption(option, normalQuery3, true);
    ASSERT_EQ(delegate_->Sync(option, nullptr), OK);

    Query normalQuery4 = Query::Select().FromTable({ tableNameB_, tableNameC_, tableNameD_ });
    PrepareOption(option, normalQuery4, true);
    ASSERT_EQ(delegate_->Sync(option, nullptr), OK);
    std::unique_lock<std::mutex> callbackLock(callbackMutex);
    callbackCv.wait(callbackLock, [&finishCount]() {
        return (finishCount >= 1u);
    });
    CheckCloudTableCount({ tableNameB_, tableNameC_, tableNameD_ }, actualCount);
}

/**
 * @tc.name: CloudSyncMergeTaskTest002
 * @tc.desc: test merge sync task with different mode.
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: liaoyonghuang
 */
HWTEST_F(DistributedDBCloudTaskMergeTest, CloudSyncMergeTaskTest002, TestSize.Level1)
{
    /**
     * @tc.steps:step1. insert user table record.
     * @tc.expected: step1. ok.
     */
    const int actualCount = 10; // 10 is count of records
    InsertUserTableRecord(tableNameA_, actualCount);
    Query normalQuery1 = Query::Select().FromTable({ tableNameA_ });
    CloudSyncOption option;
    PrepareOption(option, normalQuery1, true);
    /**
     * @tc.steps:step2. set 2s block time for sync task 1st, and start sync task 2nd.
     * @tc.expected: step2. ok.
     */
    virtualCloudDb_->SetBlockTime(2000); // block 1st sync task 2s.
    std::thread syncThread1([&]() {
        ASSERT_EQ(delegate_->Sync(option, nullptr), OK);
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(100)); // sleep 100ms
    std::thread syncThread2([&]() {
        ASSERT_EQ(delegate_->Sync(option, nullptr), OK);
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(100)); // sleep 100ms

    /**
     * @tc.steps:step3. start sync task 3rd.
     * @tc.expected: task CLOUD_SYNC_TASK_MERGED because it was merged into Task 2.
     */
    auto callback3 = [](const std::map<std::string, SyncProcess> &process) {
        for (const auto &item: process) {
            ASSERT_EQ(item.second.errCode, CLOUD_SYNC_TASK_MERGED);
        }
    };
    std::thread syncThread3([&]() {
        ASSERT_EQ(delegate_->Sync(option, callback3), OK);
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(100)); // sleep 100ms

    /**
     * @tc.steps:step4. start sync task 4th.
     * @tc.expected: task was not merged because the mode is not SYNC_MODE_CLOUD_MERGE.
     */
    auto callback4 = [](const std::map<std::string, SyncProcess> &process) {
        for (const auto &item: process) {
            ASSERT_EQ(item.second.errCode, OK);
        }
    };
    std::thread syncThread4([&]() {
        option.mode = SYNC_MODE_CLOUD_FORCE_PUSH;
        ASSERT_EQ(delegate_->Sync(option, callback4), OK);
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(100)); // sleep 100ms

    /**
     * @tc.steps:step5. start sync task 5th.
     * @tc.expected: task CLOUD_SYNC_TASK_MERGED because it was merged into Task 2.
     */
    auto callback5 = [](const std::map<std::string, SyncProcess> &process) {
        for (const auto &item: process) {
            ASSERT_EQ(item.second.errCode, CLOUD_SYNC_TASK_MERGED);
        }
    };
    std::thread syncThread5([&]() {
        option.mode = SYNC_MODE_CLOUD_MERGE;
        ASSERT_EQ(delegate_->Sync(option, callback5), OK);
    });

    syncThread1.join();
    syncThread2.join();
    syncThread3.join();
    syncThread4.join();
    syncThread5.join();
}

/**
 * @tc.name: CloudSyncMergeTaskTest003
 * @tc.desc: test merge sync task which merge is false.
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: liaoyonghuang
 */
HWTEST_F(DistributedDBCloudTaskMergeTest, CloudSyncMergeTaskTest003, TestSize.Level1)
{
    /**
     * @tc.steps:step1. insert user table record.
     * @tc.expected: step1. ok.
     */
    const int actualCount = 10; // 10 is count of records
    InsertUserTableRecord(tableNameA_, actualCount);
    Query normalQuery1 = Query::Select().FromTable({ tableNameA_ });
    CloudSyncOption option;
    PrepareOption(option, normalQuery1, true);
    /**
     * @tc.steps:step2. set 2s block time for sync task 1st, and start sync task 2nd.
     * @tc.expected: step2. ok.
     */
    virtualCloudDb_->SetBlockTime(2000); // block 1st sync task 2s.
    std::thread syncThread1([&]() {
        ASSERT_EQ(delegate_->Sync(option, nullptr), OK);
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(100)); // sleep 100ms
    std::thread syncThread2([&]() {
        ASSERT_EQ(delegate_->Sync(option, nullptr), OK);
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(100)); // sleep 100ms
    /**
     * @tc.steps:step3. start sync task 3rd.
     * @tc.expected: task CLOUD_SYNC_TASK_MERGED because it was merged into Task 2.
     */
    auto callback3 = [](const std::map<std::string, SyncProcess> &process) {
        for (const auto &item: process) {
            ASSERT_EQ(item.second.errCode, CLOUD_SYNC_TASK_MERGED);
            EXPECT_EQ(item.second.tableProcess.size(), 1u);
            for (const auto &table : item.second.tableProcess) {
                EXPECT_EQ(table.second.process, ProcessStatus::FINISHED);
            }
        }
    };
    std::thread syncThread3([&]() {
        ASSERT_EQ(delegate_->Sync(option, callback3), OK);
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(100)); // sleep 100ms
    /**
     * @tc.steps:step4. start sync task 4th.
     * @tc.expected: task OK because it cannot be merged.
     */
    auto callback4 = [](const std::map<std::string, SyncProcess> &process) {
        for (const auto &item: process) {
            ASSERT_EQ(item.second.errCode, OK);
        }
    };
    std::thread syncThread4([&]() {
        option.merge = false;
        ASSERT_EQ(delegate_->Sync(option, callback4), OK);
    });

    syncThread1.join();
    syncThread2.join();
    syncThread3.join();
    syncThread4.join();
}

/**
 * @tc.name: CloudSyncMergeTaskTest004
 * @tc.desc: test merge sync task with async download asset
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: zqq
 */
HWTEST_F(DistributedDBCloudTaskMergeTest, CloudSyncMergeTaskTest004, TestSize.Level1)
{
    size_t finishCount = 0u;
    std::mutex callbackMutex;
    std::condition_variable callbackCv;
    auto callback = GetProcessCallback([](DBStatus status) {
        EXPECT_EQ(status, OK);
    }, callbackMutex, callbackCv, finishCount);

    Query normalQuery = Query::Select().FromTable({ tableNameA_ });
    CloudSyncOption option;
    PrepareOption(option, normalQuery, true);
    ASSERT_EQ(delegate_->Sync(option, callback), OK);
    option.asyncDownloadAssets = true;
    ASSERT_EQ(delegate_->Sync(option, callback), OK);

    std::unique_lock<std::mutex> callbackLock(callbackMutex);
    callbackCv.wait(callbackLock, [&finishCount]() {
        return (finishCount >= 2u); // download 2 times
    });
}
}
#endif