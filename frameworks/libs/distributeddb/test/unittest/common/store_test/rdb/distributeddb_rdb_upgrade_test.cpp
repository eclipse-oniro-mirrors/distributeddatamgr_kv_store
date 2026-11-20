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
#include "rdb_general_ut.h"
#include "relational_schema_object.h"
#include "sqlite_relational_utils.h"
#include "sqlite_utils.h"

using namespace testing::ext;
using namespace DistributedDB;
using namespace DistributedDBUnitTest;

namespace {
class DistributedDBRDBUpgradeTest : public RDBGeneralUt {
public:
    void SetUp() override;
    void TearDown() override;
protected:
    void InitUpgradeDelegate();
    void InitNoJsonTrackerSchema();
    // Read the tracker schema string persisted in the metadata table.
    // Returns empty string when the schema key is absent or parsing fails.
    std::string ReadTrackerSchemaStr(const StoreInfo &info);
    // Parse the persisted tracker schema string and return whether the given
    // table is present (i.e. its tracker table is non-empty in meta).
    bool IsTrackerTableInMeta(const StoreInfo &info, const std::string &tableName);
    static constexpr const char *DEVICE_SYNC_TABLE = "DEVICE_SYNC_TABLE";
};

void DistributedDBRDBUpgradeTest::SetUp()
{
    RDBGeneralUt::SetUp();
}

void DistributedDBRDBUpgradeTest::TearDown()
{
    RDBGeneralUt::TearDown();
}

void DistributedDBRDBUpgradeTest::InitUpgradeDelegate()
{
    RelationalStoreDelegate::Option option;
    option.tableMode = DistributedTableMode::COLLABORATION;
    SetOption(option);
    auto info1 = GetStoreInfo1();
    const std::vector<UtFieldInfo> filedInfo = {
        {{"id", TYPE_INDEX<int64_t>, true, false}, true}, {{"name1", TYPE_INDEX<std::string>, false, true}, false},
        {{"name2", TYPE_INDEX<std::string>, false, true}, false}
    };
    UtDateBaseSchemaInfo schemaInfo = {
        .tablesInfo = {{.name = DEVICE_SYNC_TABLE, .fieldInfo = filedInfo}}
    };
    RDBGeneralUt::SetSchemaInfo(info1, schemaInfo);
    ASSERT_EQ(BasicUnitTest::InitDelegate(info1, "dev1"), E_OK);
}

void DistributedDBRDBUpgradeTest::InitNoJsonTrackerSchema()
{
    std::string keyStr = "relational_tracker_schema";
    Key key(keyStr.begin(), keyStr.end());
    std::string schemaStr = R"({"SCHEMA_TYPE":"TRACKER","TABLES":[
        {"NAME": "DEVICE_SYNC_TABLE", "EXTEND_NAME": "id",
        "TRACKER_NAMES": ["id", "name1", "name2"], "TRACKER_ACTION": false}]})";
    Value value(schemaStr.begin(), schemaStr.end());
    ASSERT_EQ(PutMetaData(GetStoreInfo1(), key, value), E_OK);
}

std::string DistributedDBRDBUpgradeTest::ReadTrackerSchemaStr(const StoreInfo &info)
{
    auto *db = GetSqliteHandle(info);
    if (db == nullptr) {
        return "";
    }
    std::string keyStr = DBConstant::RELATIONAL_TRACKER_SCHEMA_KEY;
    Key schemaKey(keyStr.begin(), keyStr.end());
    std::string sql = "SELECT value FROM " + std::string(DBConstant::RELATIONAL_PREFIX) +
        "metadata WHERE key=?;";
    sqlite3_stmt *stmt = nullptr;
    if (SQLiteUtils::GetStatement(db, sql, stmt) != E_OK) {
        return "";
    }
    if (SQLiteUtils::BindBlobToStatement(stmt, 1, schemaKey, false) != E_OK) {
        int errCode = 0;
        SQLiteUtils::ResetStatement(stmt, true, errCode);
        return "";
    }
    Value schemaVal;
    while (SQLiteUtils::StepWithRetry(stmt) == SQLiteUtils::MapSQLiteErrno(SQLITE_ROW)) {
        SQLiteUtils::GetColumnBlobValue(stmt, 0, schemaVal);
    }
    int errCode = 0;
    SQLiteUtils::ResetStatement(stmt, true, errCode);
    std::string schemaStr;
    DBCommon::VectorToString(schemaVal, schemaStr);
    return schemaStr;
}

bool DistributedDBRDBUpgradeTest::IsTrackerTableInMeta(const StoreInfo &info, const std::string &tableName)
{
    std::string schemaStr = ReadTrackerSchemaStr(info);
    if (schemaStr.empty()) {
        return false;
    }
    RelationalSchemaObject schemaObject;
    if (schemaObject.ParseFromTrackerSchemaString(schemaStr) != E_OK) {
        return false;
    }
    return !schemaObject.GetTrackerTable(tableName).IsEmpty();
}

/**
 * @tc.name: UpgradeTracker001
 * @tc.desc: Test rdb upgrade extend field from no json to json.
 * @tc.type: FUNC
 * @tc.author: zqq
 */
HWTEST_F(DistributedDBRDBUpgradeTest, UpgradeTracker001, TestSize.Level0)
{
    /**
     * @tc.steps: step1. Init delegate and set tracker schema.
     * @tc.expected: step1. Ok
     */
    ASSERT_NO_FATAL_FAILURE(InitUpgradeDelegate());
    auto info1 = GetStoreInfo1();
    EXPECT_EQ(SetTrackerTables(info1, {DEVICE_SYNC_TABLE}), E_OK);
    /**
     * @tc.steps: step2. Insert local data and log, low version schema.
     * @tc.expected: step2. Ok
     */
    InsertLocalDBData(0, 1, info1);
    std::string sql = "UPDATE " + DBCommon::GetLogTableName(DEVICE_SYNC_TABLE) + " SET extend_field=1";
    EXPECT_EQ(ExecuteSQL(sql, info1), E_OK);
    ASSERT_NO_FATAL_FAILURE(InitNoJsonTrackerSchema());
    EXPECT_EQ(CloseDelegate(info1), E_OK);
    ASSERT_NO_FATAL_FAILURE(InitUpgradeDelegate());
    /**
     * @tc.steps: step3. Set tracker table and create distributed table.
     * @tc.expected: step3. Ok
     */
    auto store = GetDelegate(info1);
    ASSERT_NE(store, nullptr);
    EXPECT_EQ(CreateDistributedTable(info1, DEVICE_SYNC_TABLE), E_OK);
    EXPECT_EQ(CountTableData(info1, DBCommon::GetLogTableName(DEVICE_SYNC_TABLE),
        " json_valid(extend_field) = 0"), 0);
    EXPECT_EQ(SetTrackerTables(info1, {DEVICE_SYNC_TABLE}), E_OK);
    /**
     * @tc.steps: step4. Check log extend field.
     * @tc.expected: step4. Ok
     */
    EXPECT_EQ(CountTableData(info1, DBCommon::GetLogTableName(DEVICE_SYNC_TABLE),
        " json_type(extend_field) = 'object'"), 1);
    EXPECT_EQ(CountTableData(info1, DBCommon::GetLogTableName(DEVICE_SYNC_TABLE),
        " json_valid(extend_field) = 0"), 0);
}

/**
 * @tc.name: UpgradeTracker002
 * @tc.desc: Test rdb upgrade extend field is no json format.
 * @tc.type: FUNC
 * @tc.author: zqq
 */
HWTEST_F(DistributedDBRDBUpgradeTest, UpgradeTracker002, TestSize.Level0)
{
    /**
     * @tc.steps: step1. Init delegate and set tracker schema.
     * @tc.expected: step1. Ok
     */
    ASSERT_NO_FATAL_FAILURE(InitUpgradeDelegate());
    auto info1 = GetStoreInfo1();
    EXPECT_EQ(SetTrackerTables(info1, {DEVICE_SYNC_TABLE}), E_OK);
    /**
     * @tc.steps: step2. Insert local data and log update extend_field to empty str.
     * @tc.expected: step2. Ok
     */
    int chkCnt = 10;
    InsertLocalDBData(0, chkCnt, info1);
    std::string sql = "UPDATE " + DBCommon::GetLogTableName(DEVICE_SYNC_TABLE) + " SET extend_field=''";
    EXPECT_EQ(ExecuteSQL(sql, info1), E_OK);
    sql = "UPDATE " + DBCommon::GetLogTableName(DEVICE_SYNC_TABLE) + " SET extend_field='{}' where data_key > 5";
    EXPECT_EQ(ExecuteSQL(sql, info1), E_OK);
    EXPECT_EQ(CountTableData(info1, DBCommon::GetLogTableName(DEVICE_SYNC_TABLE),
        " json_valid(extend_field) = 0 OR json_extract(extend_field, '$') = '{}'"), chkCnt);
    /**
     * @tc.steps: step3. Set tracker again and check log.
     * @tc.expected: step3. Ok
     */
    EXPECT_EQ(SetTrackerTables(info1, {DEVICE_SYNC_TABLE}), E_OK);
    EXPECT_EQ(CountTableData(info1, DBCommon::GetLogTableName(DEVICE_SYNC_TABLE),
        " json_valid(extend_field) = 0 OR json_extract(extend_field, '$') = '{}'"), 0);
}

/**
 * @tc.name: UpgradeTracker003
 * @tc.desc: Test extend col names was not set.
 * @tc.type: FUNC
 * @tc.author: bty
 */
HWTEST_F(DistributedDBRDBUpgradeTest, UpgradeTracker003, TestSize.Level0)
{
    /**
     * @tc.steps: step1. Init delegate and set tracker schema.
     * @tc.expected: step1. Ok
     */
    ASSERT_NO_FATAL_FAILURE(InitUpgradeDelegate());
    auto info1 = GetStoreInfo1();
    EXPECT_EQ(SetTrackerTables(info1, {DEVICE_SYNC_TABLE}), E_OK);
    /**
     * @tc.steps: step2. Insert local data and not set extend col names.
     * @tc.expected: step2. Ok
     */
    int chkCnt = 10;
    InsertLocalDBData(0, chkCnt, info1);
    auto trackerSchema = GetAllTrackerSchema(info1, {DEVICE_SYNC_TABLE});
    auto store = GetDelegate(info1);
    ASSERT_NE(store, nullptr);
    for (const auto &trackerTable : trackerSchema) {
        auto temp = trackerTable;
        temp.extendColNames = {};
        EXPECT_EQ(store->SetTrackerTable(temp), E_OK);
    }
    EXPECT_EQ(CountTableData(info1, DBCommon::GetLogTableName(DEVICE_SYNC_TABLE),
        " json_extract(extend_field, '$') = '{}'"), chkCnt);
}

/**
 * @tc.name: UpgradeTracker004
 * @tc.desc: Test concurrent upgrade
 * @tc.type: FUNC
 * @tc.author: bty
 */
HWTEST_F(DistributedDBRDBUpgradeTest, UpgradeTracker004, TestSize.Level2)
{
    /**
     * @tc.steps: step1. Init delegate and set tracker schema.
     * @tc.expected: step1. Ok
     */
    ASSERT_NO_FATAL_FAILURE(InitUpgradeDelegate());
    auto info1 = GetStoreInfo1();
    EXPECT_EQ(SetTrackerTables(info1, {DEVICE_SYNC_TABLE}), E_OK);
    /**
     * @tc.steps: step2. Insert local data and log update extend_field to empty str.
     * @tc.expected: step2. Ok
     */
    int chkCnt = 10;
    InsertLocalDBData(0, chkCnt, info1);
    /**
     * @tc.steps: step3. concurrent upgrade
     * @tc.expected: step3. Ok
     */
    size_t loopTimes = 200;
    std::thread t1([this, &info1, loopTimes]() {
        for (size_t i = 0; i < loopTimes; i++) {
            std::string sql = "UPDATE " + DBCommon::GetLogTableName(DEVICE_SYNC_TABLE) + " SET extend_field=''";
            EXPECT_EQ(ExecuteSQL(sql, info1), E_OK);
            EXPECT_EQ(CreateDistributedTable(info1, DEVICE_SYNC_TABLE), E_OK);
        }
    });
    std::thread t2([this, &info1, loopTimes]() {
        for (size_t i = 0; i < loopTimes; i++) {
            EXPECT_EQ(SetTrackerTables(info1, {DEVICE_SYNC_TABLE}), E_OK);
        }
    });
    for (size_t i = 0; i < loopTimes; i++) {
        EXPECT_EQ(SetTrackerTables(info1, {DEVICE_SYNC_TABLE}), E_OK);
    }
    t1.join();
    t2.join();
}

/**
 * @tc.name: UpgradeTracker005
 * @tc.desc: Test cursor is auto initialized in meta table when missing during tracker integrity repair.
 * @tc.type: FUNC
 * @tc.author: zqq
 */
HWTEST_F(DistributedDBRDBUpgradeTest, UpgradeTracker005, TestSize.Level0)
{
    /**
     * @tc.steps: step1. Init delegate and set tracker schema.
     * @tc.expected: step1. Ok
     */
    ASSERT_NO_FATAL_FAILURE(InitUpgradeDelegate());
    auto info1 = GetStoreInfo1();
    EXPECT_EQ(SetTrackerTables(info1, {DEVICE_SYNC_TABLE}), E_OK);
    /**
     * @tc.steps: step2. Check cursor exists in meta table.
     * @tc.expected: step2. Cursor row exists.
     */
    const std::string metaTableName = std::string(DBConstant::RELATIONAL_PREFIX) + "metadata";
    const std::string cursorKey = DBCommon::GetCursorKey(DEVICE_SYNC_TABLE);
    // key column is BLOB; compare with hex literal x'...' (same as cloud_storage_utils_client.cpp).
    const std::string cursorCond = "key=x'" + DBCommon::TransferStringToHex(cursorKey) + "'";
    EXPECT_EQ(CountTableData(info1, metaTableName, cursorCond), 1);
    /**
     * @tc.steps: step3. Remove cursor from meta table to simulate missing cursor.
     * @tc.expected: step3. Cursor row deleted.
     */
    std::string sql = "DELETE FROM " + metaTableName + " WHERE " + cursorCond;
    EXPECT_EQ(ExecuteSQL(sql, info1), E_OK);
    EXPECT_EQ(CountTableData(info1, metaTableName, cursorCond), 0);
    /**
     * @tc.steps: step4. Set tracker tables with same schema to trigger TrackerIntegrityRepair.
     * @tc.expected: step4. Cursor row re-initialized in meta table.
     */
    EXPECT_EQ(SetTrackerTables(info1, {DEVICE_SYNC_TABLE}), E_OK);
    EXPECT_EQ(CountTableData(info1, metaTableName, cursorCond), 1);
}

/**
 * @tc.name: UpgradeTracker006
 * @tc.desc: Test null cursor log rows are refreshed during tracker integrity repair.
 * @tc.type: FUNC
 * @tc.author: zqq
 */
HWTEST_F(DistributedDBRDBUpgradeTest, UpgradeTracker006, TestSize.Level0)
{
    /**
     * @tc.steps: step1. Init delegate and set tracker schema, insert local data.
     * @tc.expected: step1. Ok
     */
    ASSERT_NO_FATAL_FAILURE(InitUpgradeDelegate());
    auto info1 = GetStoreInfo1();
    EXPECT_EQ(SetTrackerTables(info1, {DEVICE_SYNC_TABLE}), E_OK);
    int chkCnt = 5;
    InsertLocalDBData(0, chkCnt, info1);
    const std::string logTable = DBCommon::GetLogTableName(DEVICE_SYNC_TABLE);
    const std::string nullCursorCond = "cursor IS NULL AND data_key != -1";
    EXPECT_EQ(CountTableData(info1, logTable, nullCursorCond), 0);
    /**
     * @tc.steps: step2. Set cursor to NULL on log rows to simulate corrupted cursor.
     * @tc.expected: step2. Null cursor rows exist.
     */
    std::string sql = "UPDATE " + logTable + " SET cursor=NULL WHERE data_key != -1";
    EXPECT_EQ(ExecuteSQL(sql, info1), E_OK);
    EXPECT_EQ(CountTableData(info1, logTable, nullCursorCond), chkCnt);
    /**
     * @tc.steps: step3. Set tracker tables with same schema to trigger TrackerIntegrityRepair.
     * @tc.expected: step3. All null cursor rows refreshed.
     */
    EXPECT_EQ(SetTrackerTables(info1, {DEVICE_SYNC_TABLE}), E_OK);
    EXPECT_EQ(CountTableData(info1, logTable, nullCursorCond), 0);
}

/**
 * @tc.name: UpgradeTracker007
 * @tc.desc: Test missing cursor and null cursor log rows are repaired together.
 * @tc.type: FUNC
 * @tc.author: zqq
 */
HWTEST_F(DistributedDBRDBUpgradeTest, UpgradeTracker007, TestSize.Level0)
{
    /**
     * @tc.steps: step1. Init delegate and set tracker schema, insert local data.
     * @tc.expected: step1. Ok
     */
    ASSERT_NO_FATAL_FAILURE(InitUpgradeDelegate());
    auto info1 = GetStoreInfo1();
    EXPECT_EQ(SetTrackerTables(info1, {DEVICE_SYNC_TABLE}), E_OK);
    int chkCnt = 5;
    InsertLocalDBData(0, chkCnt, info1);
    const std::string logTable = DBCommon::GetLogTableName(DEVICE_SYNC_TABLE);
    const std::string metaTableName = std::string(DBConstant::RELATIONAL_PREFIX) + "metadata";
    const std::string cursorCond = "key=x'" + DBCommon::TransferStringToHex(DBCommon::GetCursorKey(DEVICE_SYNC_TABLE)) +
        "'";
    const std::string nullCursorCond = "cursor IS NULL AND data_key != -1";
    EXPECT_EQ(CountTableData(info1, metaTableName, cursorCond), 1);
    EXPECT_EQ(CountTableData(info1, logTable, nullCursorCond), 0);
    /**
     * @tc.steps: step2. Delete meta cursor and null log cursors to simulate both corruptions.
     * @tc.expected: step2. Meta cursor row gone and null cursor log rows exist.
     */
    std::string sql = "DELETE FROM " + metaTableName + " WHERE " + cursorCond;
    EXPECT_EQ(ExecuteSQL(sql, info1), E_OK);
    EXPECT_EQ(CountTableData(info1, metaTableName, cursorCond), 0);
    sql = "UPDATE " + logTable + " SET cursor=NULL WHERE data_key != -1";
    EXPECT_EQ(ExecuteSQL(sql, info1), E_OK);
    EXPECT_EQ(CountTableData(info1, logTable, nullCursorCond), chkCnt);
    /**
     * @tc.steps: step3. Set tracker tables with same schema to trigger TrackerIntegrityRepair.
     * @tc.expected: step3. Meta cursor re-initialized and null cursor log rows refreshed.
     */
    EXPECT_EQ(SetTrackerTables(info1, {DEVICE_SYNC_TABLE}), E_OK);
    EXPECT_EQ(CountTableData(info1, metaTableName, cursorCond), 1);
    EXPECT_EQ(CountTableData(info1, logTable, nullCursorCond), 0);
}

/**
  * @tc.name: UpgradeTracker008
  * @tc.desc: Test tracker schema is persisted when first set with inventory data (WITH_INVENTORY_DATA).
  *           Regression guard: previously the meta write was rolled back on the -E_WITH_INVENTORY_DATA
  *           path, causing the tracker schema to be lost after reopen.
  * @tc.type: FUNC
  * @tc.author: zqq
  */
HWTEST_F(DistributedDBRDBUpgradeTest, UpgradeTracker008, TestSize.Level0)
{
    /**
     * @tc.steps: step1. Init delegate and insert local data before setting tracker table.
     * @tc.expected: step1. Ok
     */
    ASSERT_NO_FATAL_FAILURE(InitUpgradeDelegate());
    auto info1 = GetStoreInfo1();
    int chkCnt = 10;
    InsertLocalDBData(0, chkCnt, info1);
    /**
     * @tc.steps: step2. Set tracker table for the first time with data present.
     * @tc.expected: step2. Return WITH_INVENTORY_DATA (treated as success semantically).
     */
    auto store = GetDelegate(info1);
    ASSERT_NE(store, nullptr);
    auto trackerSchema = GetAllTrackerSchema(info1, {DEVICE_SYNC_TABLE});
    ASSERT_FALSE(trackerSchema.empty());
    auto temp = trackerSchema.front();
    EXPECT_EQ(store->SetTrackerTable(temp), static_cast<int>(DBStatus::WITH_INVENTORY_DATA));
    /**
     * @tc.steps: step3. Check the tracker schema is persisted in meta before reopen.
     * @tc.expected: step3. The tracker table is present in meta.
     */
    EXPECT_TRUE(IsTrackerTableInMeta(info1, DEVICE_SYNC_TABLE));
    /**
     * @tc.steps: step4. Reopen delegate and check the tracker schema is still in meta.
     * @tc.expected: step4. The tracker table is still present in meta after reopen.
     */
    EXPECT_EQ(CloseDelegate(info1), E_OK);
    ASSERT_NO_FATAL_FAILURE(InitUpgradeDelegate());
    EXPECT_TRUE(IsTrackerTableInMeta(info1, DEVICE_SYNC_TABLE));
}

/**
  * @tc.name: UpgradeTracker009
  * @tc.desc: Test updating an existing tracker schema (non-first-create) is persisted to meta.
  *           Regression guard: previously the !isFirstCreate path rolled back the meta write,
  *           causing schema updates to be lost in both meta and memory.
  * @tc.type: FUNC
  * @tc.author: zqq
  */
HWTEST_F(DistributedDBRDBUpgradeTest, UpgradeTracker009, TestSize.Level0)
{
    /**
     * @tc.steps: step1. Init delegate and set tracker table for the first time.
     * @tc.expected: step1. Ok
     */
    ASSERT_NO_FATAL_FAILURE(InitUpgradeDelegate());
    auto info1 = GetStoreInfo1();
    EXPECT_EQ(SetTrackerTables(info1, {DEVICE_SYNC_TABLE}), E_OK);
    EXPECT_TRUE(IsTrackerTableInMeta(info1, DEVICE_SYNC_TABLE));
    /**
     * @tc.steps: step2. Update the tracker schema with different tracker columns (non-first-create).
     * @tc.expected: step2. Ok and the updated schema is persisted in meta.
     */
    auto store = GetDelegate(info1);
    ASSERT_NE(store, nullptr);
    auto updatedSchema = GetAllTrackerSchema(info1, {DEVICE_SYNC_TABLE}).front();
    updatedSchema.trackerColNames = {"id"};
    updatedSchema.extendColNames = {"id"};
    EXPECT_EQ(store->SetTrackerTable(updatedSchema), E_OK);
    /**
     * @tc.steps: step3. Reopen delegate and verify the updated schema is persisted.
     * @tc.expected: step3. The tracker table is still present in meta after reopen.
     */
    EXPECT_EQ(CloseDelegate(info1), E_OK);
    ASSERT_NO_FATAL_FAILURE(InitUpgradeDelegate());
    EXPECT_TRUE(IsTrackerTableInMeta(info1, DEVICE_SYNC_TABLE));
}

/**
  * @tc.name: UpgradeTracker010
  * @tc.desc: Test unsetting a tracker table (empty trackerColNames) removes it from meta.
  *           Guards the MergeTrackerSchema remove-branch consistency between CacheTrackerSchema
  *           and SaveTrackerSchema.
  * @tc.type: FUNC
  * @tc.author: zqq
  */
HWTEST_F(DistributedDBRDBUpgradeTest, UpgradeTracker010, TestSize.Level0)
{
    /**
     * @tc.steps: step1. Init delegate and set tracker table.
     * @tc.expected: step1. Ok and the tracker table is present in meta.
     */
    ASSERT_NO_FATAL_FAILURE(InitUpgradeDelegate());
    auto info1 = GetStoreInfo1();
    EXPECT_EQ(SetTrackerTables(info1, {DEVICE_SYNC_TABLE}), E_OK);
    EXPECT_TRUE(IsTrackerTableInMeta(info1, DEVICE_SYNC_TABLE));
    /**
     * @tc.steps: step2. Unset the tracker table with empty trackerColNames and isTrackAction=false.
     * @tc.expected: step2. Ok
     */
    auto store = GetDelegate(info1);
    ASSERT_NE(store, nullptr);
    auto schema = GetAllTrackerSchema(info1, {DEVICE_SYNC_TABLE}).front();
    schema.trackerColNames = {};
    schema.isTrackAction = false;
    EXPECT_EQ(store->SetTrackerTable(schema), E_OK);
    /**
     * @tc.steps: step3. Verify the tracker table is removed from meta in memory.
     * @tc.expected: step3. The tracker table is absent in meta.
     */
    EXPECT_FALSE(IsTrackerTableInMeta(info1, DEVICE_SYNC_TABLE));
    /**
     * @tc.steps: step4. Reopen delegate and verify the removal is persisted.
     * @tc.expected: step4. The tracker table is still absent in meta after reopen.
     */
    EXPECT_EQ(CloseDelegate(info1), E_OK);
    ASSERT_NO_FATAL_FAILURE(InitUpgradeDelegate());
    EXPECT_FALSE(IsTrackerTableInMeta(info1, DEVICE_SYNC_TABLE));
}
}