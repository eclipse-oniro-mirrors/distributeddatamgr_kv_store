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

#include <gtest/gtest.h>

#include "cloud_db_types.h"
#include "db_common.h"
#include "db_constant.h"
#include "distributeddb_tools_unit_test.h"
#include "runtime_config.h"
#include "sqlite_relational_utils.h"
#include "sqlite_utils.h"
#include "table_info.h"
#include "tracker_table.h"
#include "virtual_cloud_data_translate.h"

using namespace testing::ext;
using namespace DistributedDB;
using namespace DistributedDBUnitTest;

namespace {
    constexpr const char *CREATE_TABLE_SQL =
        "CREATE TABLE IF NOT EXISTS worker1(" \
        "id INT PRIMARY KEY,"
        "name TEXT," \
        "height REAL ," \
        "married BOOLEAN ," \
        "photo BLOB," \
        "asset BLOB," \
        "assets BLOB);";
    const Asset g_localAsset = {
        .version = 1, .name = "Phone", .assetId = "", .subpath = "/local/sync", .uri = "/local/sync",
        .modifyTime = "123456", .createTime = "", .size = "256", .hash = "ASE"
    };
    std::string g_testDir;
    std::string g_dbDir;
    sqlite3 *g_db = nullptr;

class DistributedDBSqliteRelationalUtilsTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
protected:
    void CreateUserDBAndTable();
    void PrepareStatement(const std::string &sql, sqlite3_stmt *&statement, bool hasCloudDataTranslate);
    std::shared_ptr<VirtualCloudDataTranslate> virtualCloudDataTranslate_ = nullptr;
};

void DistributedDBSqliteRelationalUtilsTest::SetUpTestCase(void)
{
    DistributedDBToolsUnitTest::TestDirInit(g_testDir);
    LOGI("The test db is:%s", g_testDir.c_str());
    g_dbDir = g_testDir + "/";
}

void DistributedDBSqliteRelationalUtilsTest::TearDownTestCase(void)
{
}

void DistributedDBSqliteRelationalUtilsTest::SetUp()
{
    DistributedDBToolsUnitTest::PrintTestCaseInfo();
    g_db = RelationalTestUtils::CreateDataBase(g_dbDir + "test.db");
    CreateUserDBAndTable();
}

void DistributedDBSqliteRelationalUtilsTest::TearDown()
{
    sqlite3_close_v2(g_db);
    g_db = nullptr;
    if (DistributedDBToolsUnitTest::RemoveTestDbFiles(g_testDir) != 0) {
        LOGE("rm test db files error.");
    }
}

void DistributedDBSqliteRelationalUtilsTest::CreateUserDBAndTable()
{
    ASSERT_EQ(RelationalTestUtils::ExecSql(g_db, "PRAGMA journal_mode=WAL;"), SQLITE_OK);
    ASSERT_EQ(RelationalTestUtils::ExecSql(g_db, CREATE_TABLE_SQL), SQLITE_OK);
}

void DistributedDBSqliteRelationalUtilsTest::PrepareStatement(const std::string &sql, sqlite3_stmt *&statement,
    bool hasCloudDataTranslate)
{
    ASSERT_EQ(SQLiteUtils::GetStatement(g_db, sql, statement), E_OK);
    VBucket data;
    data.insert_or_assign("id", 1L);
    data.insert_or_assign("name", "lihua");
    data.insert_or_assign("height", 166.0); // 166.0 is random double value
    data.insert_or_assign("married", true);
    std::vector<uint8_t> photo(1, 'v');
    data.insert_or_assign("photo", photo);
    data.insert_or_assign("asset", g_localAsset);
    Assets assets = { g_localAsset };
    data.insert_or_assign("assets", assets);
    EXPECT_EQ(SQLiteRelationalUtils::BindStatementByType(statement, 1, data["id"]), E_OK); // 1 is id cid
    EXPECT_EQ(SQLiteRelationalUtils::BindStatementByType(statement, 2, data["name"]), E_OK); // 2 is name cid
    EXPECT_EQ(SQLiteRelationalUtils::BindStatementByType(statement, 3, data["height"]), E_OK); // 3 is height cid
    EXPECT_EQ(SQLiteRelationalUtils::BindStatementByType(statement, 4, data["married"]), E_OK); // 4 is married cid
    EXPECT_EQ(SQLiteRelationalUtils::BindStatementByType(statement, 5, data["photo"]), E_OK); // 5 is photo cid
    if (hasCloudDataTranslate) {
        EXPECT_EQ(SQLiteRelationalUtils::BindStatementByType(statement, 6, data["asset"]), E_OK); // 6 is asset cid
        EXPECT_EQ(SQLiteRelationalUtils::BindStatementByType(statement, 7, data["assets"]), E_OK); // 7 is assets cid
    } else {
        RuntimeConfig::SetCloudTranslate(nullptr);
        EXPECT_EQ(SQLiteRelationalUtils::BindStatementByType(statement, 6, data["asset"]), -E_NOT_INIT); // 6 is asset
        EXPECT_EQ(SQLiteRelationalUtils::BindStatementByType(statement, 7, data["assets"]), -E_NOT_INIT); // 7 is assets
    }
}

/**
 * @tc.name: SqliteRelationalUtilsTest001
 * @tc.desc: Test interfaces when statement is nullptr
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: chenchaohao
 */
HWTEST_F(DistributedDBSqliteRelationalUtilsTest, SqliteRelationalUtilsTest001, TestSize.Level0)
{
    /**
     * @tc.steps:step1. statement is nullptr
     * @tc.expected: step1. return OK
     */
    sqlite3_stmt *statement = nullptr;

    /**
     * @tc.steps:step2. test interface
     * @tc.expected: step2. return OK
     */
    DataValue dataValue;
    EXPECT_EQ(SQLiteRelationalUtils::GetDataValueByType(statement, 0, dataValue), -E_INVALID_ARGS);
    Type typeValue;
    EXPECT_EQ(SQLiteRelationalUtils::GetCloudValueByType(statement, TYPE_INDEX<Nil>, 0, typeValue), -E_INVALID_ARGS);
    EXPECT_EQ(SQLiteUtils::StepNext(statement, false), -E_INVALID_ARGS);
    std::string tableName = "worker1";
    EXPECT_NE(SQLiteRelationalUtils::SelectServerObserver(g_db, tableName, false), E_OK);

    /**
     * @tc.steps:step3. close db and test interface
     * @tc.expected: step3. return OK
     */
    sqlite3_close_v2(g_db);
    g_db = nullptr;
    std::string fileName = "";
    EXPECT_FALSE(SQLiteRelationalUtils::GetDbFileName(g_db, fileName));
    EXPECT_EQ(SQLiteRelationalUtils::SelectServerObserver(g_db, tableName, false), -E_INVALID_ARGS);
    std::vector<std::string> devices = {"dev1"};
    int64_t changedRows;
    EXPECT_EQ(SQLiteRelationalUtils::DeleteDistributedExceptDeviceTable(g_db, tableName, devices, changedRows),
        -E_INVALID_DB);
    EXPECT_EQ(SQLiteRelationalUtils::DeleteDistributedExceptDeviceTableLog(g_db, tableName, devices), -E_INVALID_DB);
    EXPECT_EQ(SQLiteRelationalUtils::UpdateTrackerTableSyncDelete(g_db, tableName, devices), -E_INVALID_DB);
    devices = {};
    EXPECT_EQ(SQLiteRelationalUtils::DeleteDistributedExceptDeviceTable(g_db, tableName, devices, changedRows),
        -E_INVALID_ARGS);
    EXPECT_EQ(SQLiteRelationalUtils::DeleteDistributedExceptDeviceTableLog(g_db, tableName, devices), -E_INVALID_ARGS);
    EXPECT_EQ(SQLiteRelationalUtils::UpdateTrackerTableSyncDelete(g_db, tableName, devices), -E_INVALID_ARGS);
}

/**
 * @tc.name: SqliteRelationalUtilsTest002
 * @tc.desc: Test BindStatementByType if dataTranselate is nullptr
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: chenchaohao
 */
HWTEST_F(DistributedDBSqliteRelationalUtilsTest, SqliteRelationalUtilsTest002, TestSize.Level0)
{
    /**
     * @tc.steps:step1. prepare sql and bind statement
     * @tc.expected: step1. return OK
     */
    std::string sql = "INSERT OR REPLACE INTO worker1(id, name, height, married, photo, asset, assets)" \
        "VALUES (?,?,?,?,?,?,?);";
    sqlite3_stmt *statement = nullptr;
    PrepareStatement(sql, statement, false);
    int errCode = E_OK;
    SQLiteUtils::ResetStatement(statement, true, errCode);
    ASSERT_EQ(statement, nullptr);
}

/**
 * @tc.name: SqliteRelationalUtilsTest003
 * @tc.desc: Test GetSelectVBucket
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: chenchaohao
 */
HWTEST_F(DistributedDBSqliteRelationalUtilsTest, SqliteRelationalUtilsTest003, TestSize.Level0)
{
    /**
     * @tc.steps:step1. set CloudDataTranslate
     * @tc.expected: step1. return OK
     */
    virtualCloudDataTranslate_ = std::make_shared<VirtualCloudDataTranslate>();
    RuntimeConfig::SetCloudTranslate(virtualCloudDataTranslate_);

    /**
     * @tc.steps:step2. insert data
     * @tc.expected: step2. return OK
     */
    std::string sql = "INSERT OR REPLACE INTO worker1(id, name, height, married, photo, asset, assets)" \
        "VALUES (?,?,?,?,?,?,?);";
    sqlite3_stmt *statement = nullptr;
    PrepareStatement(sql, statement, true);
    EXPECT_EQ(SQLiteUtils::StepWithRetry(statement), SQLiteUtils::MapSQLiteErrno(SQLITE_DONE));
    int errCode = E_OK;
    SQLiteUtils::ResetStatement(statement, true, errCode);
    ASSERT_EQ(statement, nullptr);

    /**
     * @tc.steps:step3. test GetSelectVBucket
     * @tc.expected: step3. return OK
     */
    VBucket data;
    ASSERT_EQ(SQLiteRelationalUtils::GetSelectVBucket(statement, data), -E_INVALID_ARGS);
    sql = "SELECT id, name, height, married, photo, asset, assets from worker1;";
    ASSERT_EQ(SQLiteUtils::GetStatement(g_db, sql, statement), E_OK);
    EXPECT_EQ(SQLiteRelationalUtils::GetSelectVBucket(statement, data), E_OK);
    SQLiteUtils::ResetStatement(statement, true, errCode);
    ASSERT_EQ(statement, nullptr);
}

/**
 * @tc.name: SqliteRelationalUtilsTest004
 * @tc.desc: Test SqliteStepReturningValues returns error when GetTypeValByStatement fails
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: xfz
 */
HWTEST_F(DistributedDBSqliteRelationalUtilsTest, SqliteRelationalUtilsTest004, TestSize.Level1)
{
    /**
     * @tc.steps:step1. set CloudDataTranslate and insert data
     * @tc.expected: step1. return OK
     */
    virtualCloudDataTranslate_ = std::make_shared<VirtualCloudDataTranslate>();
    RuntimeConfig::SetCloudTranslate(virtualCloudDataTranslate_);
    std::string sql = "INSERT OR REPLACE INTO worker1(id, name, height, married, photo, asset, assets)" \
        "VALUES (?,?,?,?,?,?,?);";
    sqlite3_stmt *statement = nullptr;
    PrepareStatement(sql, statement, true);
    EXPECT_EQ(SQLiteUtils::StepWithRetry(statement), SQLiteUtils::MapSQLiteErrno(SQLITE_DONE));
    int errCode = E_OK;
    SQLiteUtils::ResetStatement(statement, true, errCode);
    ASSERT_EQ(statement, nullptr);

    /**
     * @tc.steps:step2. prepare a SELECT that returns only one column (id)
     * @tc.expected: step2. return OK
     */
    sql = "SELECT id from worker1;";
    ASSERT_EQ(SQLiteUtils::GetStatement(g_db, sql, statement), E_OK);

    /**
     * @tc.steps:step3. call SqliteStepReturningValues with more pkNames than result columns
     * @tc.expected: step3. return -E_INVALID_ARGS because GetTypeValByStatement fails on out-of-range index
     */
    std::vector<std::string> localPkNames = {"id", "name"};
    VBucket vBucket;
    EXPECT_EQ(SQLiteRelationalUtils::SqliteStepReturningValues(localPkNames, statement, vBucket),
        -E_INVALID_ARGS);
    SQLiteUtils::ResetStatement(statement, true, errCode);
    ASSERT_EQ(statement, nullptr);
}

/**
  * @tc.name: UpdateNullCursor001
  * @tc.desc: Test SQLiteRelationalUtils::UpdateNullCursor returns E_OK and makes no changes when
  *           the log table has no rows with cursor IS NULL AND data_key != -1 (early-return path).
  * @tc.type: FUNC
  * @tc.require:
  * @tc.author: zqq
  */
HWTEST_F(DistributedDBSqliteRelationalUtilsTest, UpdateNullCursor001, TestSize.Level0)
{
    const std::string tableName = "test_upd_null_cur_1";
    const std::string logTable = DBCommon::GetLogTableName(tableName);
    /**
     * @tc.steps: step1. Create the meta table and the log table; init cursor in meta.
     * @tc.expected: step1. Both tables created and meta cursor row exists.
     */
    ASSERT_EQ(SQLiteRelationalUtils::CreateRelationalMetaTable(g_db), E_OK);
    std::string createLogSql = "CREATE TABLE IF NOT EXISTS " + logTable +
        "(data_key INT NOT NULL, cursor INT DEFAULT 0, hash_key BLOB NOT NULL);";
    ASSERT_EQ(SQLiteUtils::ExecuteRawSQL(g_db, createLogSql), E_OK);
    ASSERT_EQ(SQLiteRelationalUtils::InitCursorToMeta(g_db, false, tableName), E_OK);
    /**
     * @tc.steps: step2. Insert log rows that do NOT match the null-cursor condition
     *           (cursor IS NOT NULL OR data_key == -1).
     * @tc.expected: step2. Rows inserted; count of null-cursor rows is 0.
     */
    ASSERT_EQ(SQLiteUtils::ExecuteRawSQL(g_db,
        "INSERT INTO " + logTable + "(data_key, cursor, hash_key) VALUES (1, 100, x'11');"), E_OK);
    ASSERT_EQ(SQLiteUtils::ExecuteRawSQL(g_db,
        "INSERT INTO " + logTable + "(data_key, cursor, hash_key) VALUES (-1, NULL, x'22');"), E_OK);
    std::pair<int, bool> checkResult = SQLiteRelationalUtils::ExecuteCheckSql(g_db,
        "SELECT COUNT(1) FROM " + logTable + " WHERE cursor IS NULL AND data_key != -1");
    ASSERT_EQ(checkResult.first, E_OK);
    EXPECT_FALSE(checkResult.second);
    /**
     * @tc.steps: step3. Call UpdateNullCursor; expect early return E_OK with no rows refreshed.
     * @tc.expected: step3. Returns E_OK and no log row's cursor changed.
     */
    EXPECT_EQ(SQLiteRelationalUtils::UpdateNullCursor(g_db, tableName), E_OK);
    int64_t nullCnt = -1;
    ASSERT_EQ(SQLiteUtils::GetCountBySql(g_db,
        "SELECT COUNT(1) FROM " + logTable + " WHERE cursor IS NULL AND data_key != -1", nullCnt), E_OK);
    EXPECT_EQ(nullCnt, 0);
    /**
     * @tc.steps: step4. Verify the non-null cursor row was not touched.
     * @tc.expected: step4. Row with data_key=1 still has cursor=100.
     */
    int64_t preservedCursorCnt = 0;
    ASSERT_EQ(SQLiteUtils::GetCountBySql(g_db,
        "SELECT COUNT(1) FROM " + logTable + " WHERE data_key=1 AND cursor=100", preservedCursorCnt), E_OK);
    EXPECT_EQ(preservedCursorCnt, 1);
}

/**
  * @tc.name: UpdateNullCursor002
  * @tc.desc: Test SQLiteRelationalUtils::UpdateNullCursor refreshes log rows whose cursor IS NULL
  *           and data_key != -1, and bumps the meta cursor by the number of refreshed rows.
  * @tc.type: FUNC
  * @tc.require:
  * @tc.author: zqq
  */
HWTEST_F(DistributedDBSqliteRelationalUtilsTest, UpdateNullCursor002, TestSize.Level0)
{
    const std::string tableName = "test_upd_null_cur_2";
    const std::string logTable = DBCommon::GetLogTableName(tableName);
    /**
     * @tc.steps: step1. Create meta + log tables and initialize the meta cursor to 0.
     * @tc.expected: step1. Tables created, meta cursor row exists.
     */
    ASSERT_EQ(SQLiteRelationalUtils::CreateRelationalMetaTable(g_db), E_OK);
    std::string createLogSql = "CREATE TABLE IF NOT EXISTS " + logTable +
        "(data_key INT NOT NULL, cursor INT, hash_key BLOB NOT NULL);";
    ASSERT_EQ(SQLiteUtils::ExecuteRawSQL(g_db, createLogSql), E_OK);
    ASSERT_EQ(SQLiteRelationalUtils::InitCursorToMeta(g_db, false, tableName), E_OK);
    /**
     * @tc.steps: step2. Insert 3 rows with cursor=NULL and data_key=1,2,3 plus 1 row with
     *           data_key=-1 (should be skipped) and 1 row with cursor already set.
     * @tc.expected: step2. null-cursor (qualifying) row count is 3.
     */
    ASSERT_EQ(SQLiteUtils::ExecuteRawSQL(g_db,
        "INSERT INTO " + logTable + "(data_key, cursor, hash_key) VALUES (1, NULL, x'11');"), E_OK);
    ASSERT_EQ(SQLiteUtils::ExecuteRawSQL(g_db,
        "INSERT INTO " + logTable + "(data_key, cursor, hash_key) VALUES (2, NULL, x'22');"), E_OK);
    ASSERT_EQ(SQLiteUtils::ExecuteRawSQL(g_db,
        "INSERT INTO " + logTable + "(data_key, cursor, hash_key) VALUES (3, NULL, x'33');"), E_OK);
    ASSERT_EQ(SQLiteUtils::ExecuteRawSQL(g_db,
        "INSERT INTO " + logTable + "(data_key, cursor, hash_key) VALUES (-1, NULL, x'44');"), E_OK);
    ASSERT_EQ(SQLiteUtils::ExecuteRawSQL(g_db,
        "INSERT INTO " + logTable + "(data_key, cursor, hash_key) VALUES (4, 100, x'55');"), E_OK);
    std::pair<int, bool> checkResult = SQLiteRelationalUtils::ExecuteCheckSql(g_db,
        "SELECT COUNT(1) FROM " + logTable + " WHERE cursor IS NULL AND data_key != -1");
    ASSERT_EQ(checkResult.first, E_OK);
    ASSERT_TRUE(checkResult.second);
    /**
     * @tc.steps: step3. Call UpdateNullCursor; expect the 3 qualifying rows to be refreshed.
     * @tc.expected: step3. Returns E_OK; null-cursor qualifying count drops to 0.
     */
    EXPECT_EQ(SQLiteRelationalUtils::UpdateNullCursor(g_db, tableName), E_OK);
    int64_t nullCnt = -1;
    ASSERT_EQ(SQLiteUtils::GetCountBySql(g_db,
        "SELECT COUNT(1) FROM " + logTable + " WHERE cursor IS NULL AND data_key != -1", nullCnt), E_OK);
    EXPECT_EQ(nullCnt, 0);
    /**
     * @tc.steps: step4. Verify the refreshed cursors are positive integers (1,2,3 in rowid order
     *           since meta cursor started at 0) and the previously-set cursor is unchanged.
     * @tc.expected: step4. Qualifying rows have cursor IN (1,2,3); row data_key=4 still has cursor=100;
     *               row data_key=-1 still has cursor=NULL.
     */
    int64_t refreshedCnt = 0;
    ASSERT_EQ(SQLiteUtils::GetCountBySql(g_db,
        "SELECT COUNT(1) FROM " + logTable + " WHERE data_key IN (1,2,3) AND cursor > 0", refreshedCnt), E_OK);
    EXPECT_EQ(refreshedCnt, 3);
    int64_t preservedCnt = 0;
    ASSERT_EQ(SQLiteUtils::GetCountBySql(g_db,
        "SELECT COUNT(1) FROM " + logTable + " WHERE data_key=4 AND cursor=100", preservedCnt), E_OK);
    EXPECT_EQ(preservedCnt, 1);
    int64_t skippedCnt = 0;
    ASSERT_EQ(SQLiteUtils::GetCountBySql(g_db,
        "SELECT COUNT(1) FROM " + logTable + " WHERE data_key=-1 AND cursor IS NULL", skippedCnt), E_OK);
    EXPECT_EQ(skippedCnt, 1);
}

/**
  * @tc.name: TrackerTableCheckNullCursorLog001
  * @tc.desc: Test TrackerTable::CheckNullCursorLog leaves existNullCursorLog=false (default) and
  *           IsNeedRepair() returns false when the log table has no null-cursor qualifying rows.
  * @tc.type: FUNC
  * @tc.require:
  * @tc.author: zqq
  */
HWTEST_F(DistributedDBSqliteRelationalUtilsTest, TrackerTableCheckNullCursorLog001, TestSize.Level0)
{
    const std::string tableName = "test_check_null_log_1";
    const std::string logTable = DBCommon::GetLogTableName(tableName);
    /**
     * @tc.steps: step1. Create the log table with rows that do NOT match the null-cursor condition.
     * @tc.expected: step1. Log table created with non-matching rows.
     */
    std::string createLogSql = "CREATE TABLE IF NOT EXISTS " + logTable +
        "(data_key INT NOT NULL, cursor INT, hash_key BLOB NOT NULL);";
    ASSERT_EQ(SQLiteUtils::ExecuteRawSQL(g_db, createLogSql), E_OK);
    ASSERT_EQ(SQLiteUtils::ExecuteRawSQL(g_db,
        "INSERT INTO " + logTable + "(data_key, cursor, hash_key) VALUES (1, 100, x'11');"), E_OK);
    ASSERT_EQ(SQLiteUtils::ExecuteRawSQL(g_db,
        "INSERT INTO " + logTable + "(data_key, cursor, hash_key) VALUES (-1, NULL, x'22');"), E_OK);
    /**
     * @tc.steps: step2. Call CheckNullCursorLog on a TrackerTable bound to tableName.
     * @tc.expected: step2. existNullCursorLog stays false; IsNeedRepair() returns false.
     */
    TrackerTable trackerTable;
    trackerTable.SetTableName(tableName);
    trackerTable.CheckNullCursorLog(g_db);
    EXPECT_FALSE(trackerTable.IsNeedRepair());
}

/**
  * @tc.name: TrackerTableCheckNullCursorLog002
  * @tc.desc: Test TrackerTable::CheckNullCursorLog sets existNullCursorLog=true and IsNeedRepair()
  *           returns true when the log table has rows with cursor IS NULL AND data_key != -1.
  * @tc.type: FUNC
  * @tc.require:
  * @tc.author: zqq
  */
HWTEST_F(DistributedDBSqliteRelationalUtilsTest, TrackerTableCheckNullCursorLog002, TestSize.Level0)
{
    const std::string tableName = "test_check_null_log_2";
    const std::string logTable = DBCommon::GetLogTableName(tableName);
    /**
     * @tc.steps: step1. Create the log table with at least one matching row (cursor NULL, data_key != -1).
     * @tc.expected: step1. Log table created with a qualifying row.
     */
    std::string createLogSql = "CREATE TABLE IF NOT EXISTS " + logTable +
        "(data_key INT NOT NULL, cursor INT, hash_key BLOB NOT NULL);";
    ASSERT_EQ(SQLiteUtils::ExecuteRawSQL(g_db, createLogSql), E_OK);
    ASSERT_EQ(SQLiteUtils::ExecuteRawSQL(g_db,
        "INSERT INTO " + logTable + "(data_key, cursor, hash_key) VALUES (1, NULL, x'11');"), E_OK);
    ASSERT_EQ(SQLiteUtils::ExecuteRawSQL(g_db,
        "INSERT INTO " + logTable + "(data_key, cursor, hash_key) VALUES (2, 50, x'22');"), E_OK);
    /**
     * @tc.steps: step2. Call CheckNullCursorLog on a TrackerTable bound to tableName.
     * @tc.expected: step2. IsNeedRepair() returns true (existNullCursorLog was set).
     */
    TrackerTable trackerTable;
    trackerTable.SetTableName(tableName);
    trackerTable.CheckNullCursorLog(g_db);
    EXPECT_TRUE(trackerTable.IsNeedRepair());
}

/**
  * @tc.name: TrackerTableCheckMissingCursor001
  * @tc.desc: Test TrackerTable::CheckMissingCursor leaves missingCursor=false (default) and
  *           IsNeedRepair() returns false when the cursor row exists in the meta table.
  * @tc.type: FUNC
  * @tc.require:
  * @tc.author: zqq
  */
HWTEST_F(DistributedDBSqliteRelationalUtilsTest, TrackerTableCheckMissingCursor001, TestSize.Level0)
{
    const std::string tableName = "test_check_miss_cur_1";
    /**
     * @tc.steps: step1. Create meta table and initialize the cursor row for tableName.
     * @tc.expected: step1. Meta table created; cursor row exists.
     */
    ASSERT_EQ(SQLiteRelationalUtils::CreateRelationalMetaTable(g_db), E_OK);
    ASSERT_EQ(SQLiteRelationalUtils::InitCursorToMeta(g_db, false, tableName), E_OK);
    /**
     * @tc.steps: step2. Call CheckMissingCursor on a TrackerTable bound to tableName.
     * @tc.expected: step2. missingCursor stays false; IsNeedRepair() returns false.
     */
    TrackerTable trackerTable;
    trackerTable.SetTableName(tableName);
    trackerTable.CheckMissingCursor(g_db, false);
    EXPECT_FALSE(trackerTable.IsNeedRepair());
}

/**
  * @tc.name: TrackerTableCheckMissingCursor002
  * @tc.desc: Test TrackerTable::CheckMissingCursor sets missingCursor=true and IsNeedRepair()
  *           returns true when the cursor row is absent from the meta table.
  * @tc.type: FUNC
  * @tc.require:
  * @tc.author: zqq
  */
HWTEST_F(DistributedDBSqliteRelationalUtilsTest, TrackerTableCheckMissingCursor002, TestSize.Level0)
{
    const std::string tableName = "test_check_miss_cur_2";
    /**
     * @tc.steps: step1. Create the meta table but DO NOT initialize the cursor row for tableName.
     * @tc.expected: step1. Meta table created; cursor row absent.
     */
    ASSERT_EQ(SQLiteRelationalUtils::CreateRelationalMetaTable(g_db), E_OK);
    /**
     * @tc.steps: step2. Call CheckMissingCursor on a TrackerTable bound to tableName.
     * @tc.expected: step2. missingCursor is set; IsNeedRepair() returns true.
     */
    TrackerTable trackerTable;
    trackerTable.SetTableName(tableName);
    trackerTable.CheckMissingCursor(g_db, false);
    EXPECT_TRUE(trackerTable.IsNeedRepair());
}

/**
  * @tc.name: UpdateNullCursor003
  * @tc.desc: Test SQLiteRelationalUtils::UpdateNullCursor returns an error when GetCountBySql fails
  *           (log table does not exist). Covers the early error-return branch of UpdateNullCursor.
  * @tc.type: FUNC
  * @tc.require:
  * @tc.author: zqq
  */
HWTEST_F(DistributedDBSqliteRelationalUtilsTest, UpdateNullCursor003, TestSize.Level0)
{
    const std::string tableName = "test_upd_null_cur_err";
    // Deliberately do NOT create the log table; GetCountBySql should fail.
    /**
     * @tc.steps: step1. Call UpdateNullCursor without creating the log table.
     * @tc.expected: step1. Returns a non-E_OK error (GetCountBySql fails on missing table).
     */
    int errCode = SQLiteRelationalUtils::UpdateNullCursor(g_db, tableName);
    EXPECT_NE(errCode, E_OK);
}

/**
  * @tc.name: UpdateNullCursor004
  * @tc.desc: Test SQLiteRelationalUtils::UpdateNullCursor returns an error when the log table UPDATE
  *           fails because the metadata table (referenced by GetSelectIncCursorSql subquery) does not
  *           exist. Covers the ExecuteRawSQL(updateSQL) error branch.
  * @tc.type: FUNC
  * @tc.require:
  * @tc.author: zqq
  */
HWTEST_F(DistributedDBSqliteRelationalUtilsTest, UpdateNullCursor004, TestSize.Level0)
{
    const std::string tableName = "test_upd_null_cur_upd_err";
    const std::string logTable = DBCommon::GetLogTableName(tableName);
    /**
     * @tc.steps: step1. Create the log table with null-cursor rows but do NOT create the metadata
     *           table. The countSql (log table only) should succeed; the updateSQL contains a
     *           subquery (SELECT value FROM metadata ...) that will fail.
     * @tc.expected: step1. Returns a non-E_OK error from ExecuteRawSQL(updateSQL).
     */
    std::string createLogSql = "CREATE TABLE IF NOT EXISTS " + logTable +
        "(data_key INT NOT NULL, cursor INT, hash_key BLOB NOT NULL);";
    ASSERT_EQ(SQLiteUtils::ExecuteRawSQL(g_db, createLogSql), E_OK);
    ASSERT_EQ(SQLiteUtils::ExecuteRawSQL(g_db,
        "INSERT INTO " + logTable + "(data_key, cursor, hash_key) VALUES (1, NULL, x'11');"), E_OK);
    ASSERT_EQ(SQLiteUtils::ExecuteRawSQL(g_db,
        "INSERT INTO " + logTable + "(data_key, cursor, hash_key) VALUES (2, NULL, x'22');"), E_OK);
    // Verify null count is positive so the function reaches the updateSQL step.
    std::pair<int, bool> checkResult = SQLiteRelationalUtils::ExecuteCheckSql(g_db,
        "SELECT COUNT(1) FROM " + logTable + " WHERE cursor IS NULL AND data_key != -1");
    ASSERT_EQ(checkResult.first, E_OK);
    ASSERT_TRUE(checkResult.second);
    /**
     * @tc.steps: step2. Call UpdateNullCursor; the updateSQL subquery references the metadata table
     *           which does not exist, so ExecuteRawSQL should fail.
     * @tc.expected: step2. Returns a non-E_OK error.
     */
    int errCode = SQLiteRelationalUtils::UpdateNullCursor(g_db, tableName);
    EXPECT_NE(errCode, E_OK);
}

/**
  * @tc.name: TrackerTableCheckNullCursorLog003
  * @tc.desc: Test TrackerTable::CheckNullCursorLog leaves existNullCursorLog=false when the log
  *           table does not exist (ExecuteCheckSql returns error → .second is false). Covers the
  *           ExecuteCheckSql error sub-branch that also falls into the !second early-return path.
  * @tc.type: FUNC
  * @tc.require:
  * @tc.author: zqq
  */
HWTEST_F(DistributedDBSqliteRelationalUtilsTest, TrackerTableCheckNullCursorLog003, TestSize.Level0)
{
    const std::string tableName = "test_check_null_log_3";
    // Deliberately do NOT create the log table; ExecuteCheckSql should return {error, false}.
    /**
     * @tc.steps: step1. Call CheckNullCursorLog without creating the log table.
     * @tc.expected: step1. existNullCursorLog stays false; IsNeedRepair() returns false.
     */
    TrackerTable trackerTable;
    trackerTable.SetTableName(tableName);
    trackerTable.CheckNullCursorLog(g_db);
    EXPECT_FALSE(trackerTable.IsNeedRepair());
}

/**
  * @tc.name: TrackerTableCheckMissingCursor003
  * @tc.desc: Test TrackerTable::CheckMissingCursor leaves missingCursor=false when GetKvData returns
  *           a non-NOT_FOUND error (metadata table does not exist → prepare fails). Covers the
  *           errCode != E_OK && errCode != -E_NOT_FOUND warning-log branch.
  * @tc.type: FUNC
  * @tc.require:
  * @tc.author: zqq
  */
HWTEST_F(DistributedDBSqliteRelationalUtilsTest, TrackerTableCheckMissingCursor003, TestSize.Level0)
{
    const std::string tableName = "test_check_miss_cur_3";
    // Deliberately do NOT create the metadata table; GetKvData should return a non-NOT_FOUND error.
    /**
     * @tc.steps: step1. Call CheckMissingCursor without creating the metadata table.
     * @tc.expected: step1. missingCursor stays false; IsNeedRepair() returns false.
     */
    TrackerTable trackerTable;
    trackerTable.SetTableName(tableName);
    trackerTable.CheckMissingCursor(g_db, false);
    EXPECT_FALSE(trackerTable.IsNeedRepair());
}

/**
  * @tc.name: TrackerTableRepair001
  * @tc.desc: Test TrackerTable::Repair does not invoke the repair callback when IsNeedRepair() is
  *           false (no repair flags set). Covers the !IsNeedRepair() early-return branch.
  * @tc.type: FUNC
  * @tc.require:
  * @tc.author: zqq
  */
HWTEST_F(DistributedDBSqliteRelationalUtilsTest, TrackerTableRepair001, TestSize.Level0)
{
    /**
     * @tc.steps: step1. Create a TrackerTable with no repair checks performed (all flags default
     *           false). Call Repair with a callback that sets a flag if invoked.
     * @tc.expected: step1. IsNeedRepair() is false; callback is NOT invoked.
     */
    TrackerTable trackerTable;
    trackerTable.SetTableName("test_repair_no_need");
    EXPECT_FALSE(trackerTable.IsNeedRepair());
    bool callbackInvoked = false;
    trackerTable.Repair([&callbackInvoked](const TrackerTable::RepairInfo &,
        const std::string &, const std::set<std::string> &) {
        callbackInvoked = true;
    });
    EXPECT_FALSE(callbackInvoked);
}

/**
  * @tc.name: TrackerTableRepair002
  * @tc.desc: Test TrackerTable::Repair invokes the callback with missingCursor=true when
  *           CheckMissingCursor found a missing cursor in meta. Covers the Repair callback
  *           invocation path with the new missingCursor flag.
  * @tc.type: FUNC
  * @tc.require:
  * @tc.author: zqq
  */
HWTEST_F(DistributedDBSqliteRelationalUtilsTest, TrackerTableRepair002, TestSize.Level0)
{
    const std::string tableName = "test_repair_miss_cur";
    /**
     * @tc.steps: step1. Create the metadata table but do NOT init the cursor row, then call
     *           CheckMissingCursor to set missingCursor=true.
     * @tc.expected: step1. IsNeedRepair() returns true after the check.
     */
    ASSERT_EQ(SQLiteRelationalUtils::CreateRelationalMetaTable(g_db), E_OK);
    TrackerTable trackerTable;
    trackerTable.SetTableName(tableName);
    trackerTable.CheckMissingCursor(g_db, false);
    EXPECT_TRUE(trackerTable.IsNeedRepair());
    /**
     * @tc.steps: step2. Call Repair with a callback that captures the RepairInfo.
     * @tc.expected: step2. Callback IS invoked; captured RepairInfo.missingCursor is true.
     */
    bool callbackInvoked = false;
    bool capturedMissingCursor = false;
    std::string capturedTableName;
    trackerTable.Repair([&](const TrackerTable::RepairInfo &repairInfo,
        const std::string &tblName, const std::set<std::string> &) {
        callbackInvoked = true;
        capturedMissingCursor = repairInfo.missingCursor;
        capturedTableName = tblName;
    });
    EXPECT_TRUE(callbackInvoked);
    EXPECT_TRUE(capturedMissingCursor);
    EXPECT_EQ(capturedTableName, tableName);
}

/**
  * @tc.name: TrackerTableRepair003
  * @tc.desc: Test TrackerTable::Repair invokes the callback with existNullCursorLog=true when
  *           CheckNullCursorLog found null-cursor log rows. Covers the Repair callback invocation
  *           path with the new existNullCursorLog flag.
  * @tc.type: FUNC
  * @tc.require:
  * @tc.author: zqq
  */
HWTEST_F(DistributedDBSqliteRelationalUtilsTest, TrackerTableRepair003, TestSize.Level0)
{
    const std::string tableName = "test_repair_null_log";
    const std::string logTable = DBCommon::GetLogTableName(tableName);
    /**
     * @tc.steps: step1. Create the log table with a null-cursor qualifying row, then call
     *           CheckNullCursorLog to set existNullCursorLog=true.
     * @tc.expected: step1. IsNeedRepair() returns true after the check.
     */
    std::string createLogSql = "CREATE TABLE IF NOT EXISTS " + logTable +
        "(data_key INT NOT NULL, cursor INT, hash_key BLOB NOT NULL);";
    ASSERT_EQ(SQLiteUtils::ExecuteRawSQL(g_db, createLogSql), E_OK);
    ASSERT_EQ(SQLiteUtils::ExecuteRawSQL(g_db,
        "INSERT INTO " + logTable + "(data_key, cursor, hash_key) VALUES (1, NULL, x'11');"), E_OK);
    TrackerTable trackerTable;
    trackerTable.SetTableName(tableName);
    trackerTable.CheckNullCursorLog(g_db);
    EXPECT_TRUE(trackerTable.IsNeedRepair());
    /**
     * @tc.steps: step2. Call Repair with a callback that captures the RepairInfo.
     * @tc.expected: step2. Callback IS invoked; captured RepairInfo.existNullCursorLog is true.
     */
    bool callbackInvoked = false;
    bool capturedExistNullCursorLog = false;
    trackerTable.Repair([&](const TrackerTable::RepairInfo &repairInfo,
        const std::string &, const std::set<std::string> &) {
        callbackInvoked = true;
        capturedExistNullCursorLog = repairInfo.existNullCursorLog;
    });
    EXPECT_TRUE(callbackInvoked);
    EXPECT_TRUE(capturedExistNullCursorLog);
}
}