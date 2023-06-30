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
#ifdef RELATIONAL_STORE
#include <gtest/gtest.h>
#include <iostream>
#include "distributeddb_tools_unit_test.h"
#include "cloud/cloud_storage_utils.h"
#include "relational_store_manager.h"
#include "distributeddb_data_generate_unit_test.h"
#include "relational_store_instance.h"
#include "sqlite_relational_store.h"
#include "sqlite_relational_utils.h"
#include "store_observer.h"
#include "cloud_db_constant.h"
#include "virtual_cloud_db.h"
#include "time_helper.h"
#include "runtime_config.h"
#include "virtual_cloud_data_translate.h"
#include "virtual_asset_loader.h"

using namespace testing::ext;
using namespace DistributedDB;
using namespace DistributedDBUnitTest;
using namespace std;

namespace {
    string g_storeID = "Relational_Store_SYNC";
    const string g_tableName1 = "worker1";
    const string g_tableName2 = "worker2";
    const string g_tableName3 = "worker3";
    const string DEVICE_CLOUD = "cloud_dev";
    const string DB_SUFFIX = ".db";
    const int64_t g_syncWaitTime = 10;
    const int g_arrayHalfSub = 2;
    int g_syncIndex = 0;
    string g_testDir;
    string g_storePath;
    std::mutex g_processMutex;
    std::condition_variable g_processCondition;
    std::shared_ptr<VirtualCloudDb> g_virtualCloudDb;
    std::shared_ptr<VirtualAssetLoader> g_virtualAssetLoader;
    DistributedDB::RelationalStoreManager g_mgr(APP_ID, USER_ID);
    RelationalStoreObserverUnitTest *g_observer = nullptr;
    SyncProcess g_syncProcess;
    using CloudSyncStatusCallback = std::function<void(const std::map<std::string, SyncProcess> &onProcess)>;
    const std::string CREATE_LOCAL_TABLE_SQL =
            "CREATE TABLE IF NOT EXISTS " + g_tableName1 + "(" \
    "name TEXT PRIMARY KEY," \
    "height REAL ," \
    "married BOOLEAN ," \
    "photo BLOB NOT NULL," \
    "assert BLOB," \
    "age INT);";
    const std::string INTEGER_PRIMARY_KEY_TABLE_SQL =
            "CREATE TABLE IF NOT EXISTS " + g_tableName2 + "(" \
    "id INTEGER PRIMARY KEY," \
    "name TEXT ," \
    "height REAL ," \
    "photo BLOB ," \
    "asserts BLOB," \
    "age INT);";
    const std::string CREATE_LOCAL_TABLE_WITHOUT_PRIMARY_KEY_SQL =
            "CREATE TABLE IF NOT EXISTS " + g_tableName3 + "(" \
    "name TEXT," \
    "height REAL ," \
    "married BOOLEAN ," \
    "photo BLOB NOT NULL," \
    "assert BLOB," \
    "age INT);";
    const std::vector<Field> g_cloudFiled1 = {
        {"name", TYPE_INDEX<std::string>, true}, {"height", TYPE_INDEX<double>},
        {"married", TYPE_INDEX<bool>}, {"photo", TYPE_INDEX<Bytes>, false, false},
        {"assert", TYPE_INDEX<Asset>}, {"age", TYPE_INDEX<int64_t>}
    };
    const std::vector<Field> g_invalidCloudFiled1 = {
        {"name", TYPE_INDEX<std::string>, true}, {"height", TYPE_INDEX<int>},
        {"married", TYPE_INDEX<bool>}, {"photo", TYPE_INDEX<Bytes>, false, false},
        {"assert", TYPE_INDEX<Bytes>}, {"age", TYPE_INDEX<int64_t>}
    };
    const std::vector<Field> g_cloudFiled2 = {
        {"id", TYPE_INDEX<int64_t>, true}, {"name", TYPE_INDEX<std::string>},
        {"height", TYPE_INDEX<double>},  {"photo", TYPE_INDEX<Bytes>},
        {"asserts", TYPE_INDEX<Assets>}, {"age", TYPE_INDEX<int64_t>}
    };
    const std::vector<Field> g_cloudFiledWithOutPrimaryKey3 = {
        {"name", TYPE_INDEX<std::string>, false, true}, {"height", TYPE_INDEX<double>},
        {"married", TYPE_INDEX<bool>}, {"photo", TYPE_INDEX<Bytes>, false, false},
        {"assert", TYPE_INDEX<Bytes>}, {"age", TYPE_INDEX<int64_t>}
    };
    const std::vector<std::string> g_tables = {g_tableName1, g_tableName2};
    const std::vector<std::string> g_tablesPKey = {g_cloudFiled1[0].colName, g_cloudFiled2[0].colName};
    const std::vector<string> g_prefix = {"Local", ""};
    const Asset g_localAsset = {
        .version = 1, .name = "Phone", .assetId = "0", .subpath = "/local/sync", .uri = "/local/sync",
        .modifyTime = "123456", .createTime = "", .size = "256", .hash = "ASE"
    };
    const Asset g_cloudAsset = {
        .version = 2, .name = "Phone", .assetId = "0", .subpath = "/local/sync", .uri = "/cloud/sync",
        .modifyTime = "123456", .createTime = "0", .size = "1024", .hash = "DEC"
    };

    void CreateUserDBAndTable(sqlite3 *&db)
    {
        EXPECT_EQ(RelationalTestUtils::ExecSql(db, "PRAGMA journal_mode=WAL;"), SQLITE_OK);
        EXPECT_EQ(RelationalTestUtils::ExecSql(db, CREATE_LOCAL_TABLE_SQL), SQLITE_OK);
        EXPECT_EQ(RelationalTestUtils::ExecSql(db, INTEGER_PRIMARY_KEY_TABLE_SQL), SQLITE_OK);
        EXPECT_EQ(RelationalTestUtils::ExecSql(db, CREATE_LOCAL_TABLE_WITHOUT_PRIMARY_KEY_SQL), SQLITE_OK);
    }

    void InsertUserTableRecord(sqlite3 *&db, int64_t begin, int64_t count, int64_t photoSize, bool assetIsNull)
    {
        std::string photo(photoSize, 'v');
        int errCode;
        std::vector<uint8_t> assetBlob;
        for (int64_t i = begin; i < begin + count; ++i) {
            Asset asset = g_localAsset;
            asset.name = asset.name + std::to_string(i);
            RuntimeContext::GetInstance()->AssetToBlob(asset, assetBlob);
            string sql = "INSERT OR REPLACE INTO " + g_tableName1
                         + " (name, height, married, photo, assert, age) VALUES ('Local" + std::to_string(i) +
                         "', '175.8', '0', '" + photo + "', ? , '18');";
            sqlite3_stmt *stmt = nullptr;
            ASSERT_EQ(SQLiteUtils::GetStatement(db, sql, stmt), E_OK);
            if (assetIsNull) {
                ASSERT_EQ(sqlite3_bind_null(stmt, 1), SQLITE_OK);
            } else {
                ASSERT_EQ(SQLiteUtils::BindBlobToStatement(stmt, 1, assetBlob, false), E_OK);
            }
            EXPECT_EQ(SQLiteUtils::StepWithRetry(stmt), SQLiteUtils::MapSQLiteErrno(SQLITE_DONE));
            SQLiteUtils::ResetStatement(stmt, true, errCode);
        }
        for (int64_t i = begin; i < begin + count; ++i) {
            std::vector<Asset> assets;
            Asset asset = g_localAsset;
            asset.name = g_localAsset.name + std::to_string(i);
            assets.push_back(asset);
            asset.name = g_localAsset.name + std::to_string(i + 1);
            assets.push_back(asset);
            RuntimeContext::GetInstance()->AssetsToBlob(assets, assetBlob);
            string sql = "INSERT OR REPLACE INTO " + g_tableName2
                         + " (id, name, height, photo, asserts, age) VALUES ('" + std::to_string(i) + "', 'Local"
                         + std::to_string(i) + "', '155.10', '"+ photo + "',  ? , '21');";
            sqlite3_stmt *stmt = nullptr;
            ASSERT_EQ(SQLiteUtils::GetStatement(db, sql, stmt), E_OK);
            if (assetIsNull) {
                ASSERT_EQ(sqlite3_bind_null(stmt, 1), E_OK);
            } else {
                ASSERT_EQ(SQLiteUtils::BindBlobToStatement(stmt, 1, assetBlob, false), E_OK);
            }
            EXPECT_EQ(SQLiteUtils::StepWithRetry(stmt), SQLiteUtils::MapSQLiteErrno(SQLITE_DONE));
            SQLiteUtils::ResetStatement(stmt, true, errCode);
        }
        LOGD("insert user record worker1[primary key]:[local%" PRId64 " - cloud%" PRId64
            ") , worker2[primary key]:[%" PRId64 "- %" PRId64")", begin, count, begin, count);
    }

    void UpdateUserTableRecord(sqlite3 *&db, int64_t begin, int64_t count)
    {
        for (size_t i = 0; i < g_tables.size(); i++) {
            string updateAge = "UPDATE " + g_tables[i] + " SET age = '99' where " + g_tablesPKey[i] + " in (";
            for (int64_t j = begin; j < begin + count; ++j) {
                updateAge += "'" + g_prefix[i] + std::to_string(j) + "',";
            }
            updateAge.pop_back();
            updateAge += ");";
            ASSERT_EQ(RelationalTestUtils::ExecSql(db, updateAge), SQLITE_OK);
        }
        LOGD("update local record worker1[primary key]:[local%" PRId64 " - local%" PRId64
            ") , worker2[primary key]:[%" PRId64 "- %" PRId64")", begin, count, begin, count);
    }

    void DeleteUserTableRecord(sqlite3 *&db, int64_t begin, int64_t count)
    {
        for (size_t i = 0; i < g_tables.size(); i++) {
            string updateAge = "Delete from " + g_tables[i] + " where " + g_tablesPKey[i] + " in (";
            for (int64_t j = begin; j < count; ++j) {
                updateAge += "'" + g_prefix[i] + std::to_string(j) + "',";
            }
            updateAge.pop_back();
            updateAge += ");";
            ASSERT_EQ(RelationalTestUtils::ExecSql(db, updateAge), SQLITE_OK);
        }
        LOGD("delete local record worker1[primary key]:[local%" PRId64 " - local%" PRId64
            ") , worker2[primary key]:[%" PRId64 "- %" PRId64")", begin, count, begin, count);
    }

    void InsertRecordWithoutPk2LocalAndCloud(sqlite3 *&db, int64_t begin, int64_t count, int photoSize)
    {
        std::vector<uint8_t> photo(photoSize, 'v');
        std::string photoLocal(photoSize, 'v');
        Asset asset = { .version = 1, .name = "Phone" };
        std::vector<uint8_t> assetBlob;
        RuntimeContext::GetInstance()->BlobToAsset(assetBlob, asset);
        std::string assetStr(assetBlob.begin(), assetBlob.end());
        std::vector<VBucket> record1;
        std::vector<VBucket> extend1;
        for (int64_t i = begin; i < count; ++i) {
            Timestamp now = TimeHelper::GetSysCurrentTime();
            VBucket data;
            data.insert_or_assign("name", "Cloud" + std::to_string(i));
            data.insert_or_assign("height", 166.0); // 166.0 is random double value
            data.insert_or_assign("married", (bool)0);
            data.insert_or_assign("photo", photo);
            data.insert_or_assign("assert", KEY_1);
            data.insert_or_assign("age", 13L);
            record1.push_back(data);
            VBucket log;
            log.insert_or_assign(CloudDbConstant::CREATE_FIELD, (int64_t)now / CloudDbConstant::TEN_THOUSAND);
            log.insert_or_assign(CloudDbConstant::MODIFY_FIELD, (int64_t)now / CloudDbConstant::TEN_THOUSAND);
            log.insert_or_assign(CloudDbConstant::DELETE_FIELD, false);
            extend1.push_back(log);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));  // wait for 1 ms
        }
        int errCode = g_virtualCloudDb->BatchInsert(g_tableName3, std::move(record1), extend1);
        ASSERT_EQ(errCode, DBStatus::OK);
        for (int64_t i = begin; i < count; ++i) {
            string sql = "INSERT OR REPLACE INTO " + g_tableName3
                         + " (name, height, married, photo, assert, age) VALUES ('Local" + std::to_string(i) +
                         "', '175.8', '0', '" + photoLocal + "', '" + assetStr + "', '18');";
            ASSERT_EQ(RelationalTestUtils::ExecSql(db, sql), SQLITE_OK);
        }
    }

    void InsertCloudTableRecord(int64_t begin, int64_t count, int64_t photoSize, bool assetIsNull)
    {
        std::vector<uint8_t> photo(photoSize, 'v');
        std::vector<VBucket> record1;
        std::vector<VBucket> extend1;
        std::vector<VBucket> record2;
        std::vector<VBucket> extend2;
        Timestamp now = TimeHelper::GetSysCurrentTime();
        for (int64_t i = begin; i < begin + count; ++i) {
            VBucket data;
            data.insert_or_assign("name", "Cloud" + std::to_string(i));
            data.insert_or_assign("height", 166.0); // 166.0 is random double value
            data.insert_or_assign("married", false);
            data.insert_or_assign("photo", photo);
            data.insert_or_assign("age", 13L);
            Asset asset = g_cloudAsset;
            asset.name = asset.name + std::to_string(i);
            assetIsNull ? data.insert_or_assign("assert", Nil()) : data.insert_or_assign("assert", asset);
            record1.push_back(data);
            VBucket log;
            log.insert_or_assign(CloudDbConstant::CREATE_FIELD, (int64_t)now / CloudDbConstant::TEN_THOUSAND + i);
            log.insert_or_assign(CloudDbConstant::MODIFY_FIELD, (int64_t)now / CloudDbConstant::TEN_THOUSAND + i);
            log.insert_or_assign(CloudDbConstant::DELETE_FIELD, false);
            extend1.push_back(log);

            std::vector<Asset> assets;
            data.insert_or_assign("id", i);
            data.insert_or_assign("height", 180.3); // 180.3 is random double value
            for (int64_t j = i; j <= i + 1; j++) {
                asset.name = g_cloudAsset.name + std::to_string(j);
                assets.push_back(asset);
            }
            data.erase("assert");
            data.erase("married");
            assetIsNull ? data.insert_or_assign("asserts", Nil()) : data.insert_or_assign("asserts", assets);
            record2.push_back(data);
            extend2.push_back(log);
        }
        ASSERT_EQ(g_virtualCloudDb->BatchInsert(g_tableName1, std::move(record1), extend1), DBStatus::OK);
        ASSERT_EQ(g_virtualCloudDb->BatchInsert(g_tableName2, std::move(record2), extend2), DBStatus::OK);
        LOGD("insert cloud record worker1[primary key]:[cloud%" PRId64 " - cloud%" PRId64
            ") , worker2[primary key]:[%" PRId64 "- %" PRId64")", begin, count, begin, count);
        std::this_thread::sleep_for(std::chrono::milliseconds(count));
    }

    void UpdateAssetForTest(sqlite3 *&db, AssetOpType opType, int64_t cloudCount, int64_t rowid)
    {
        string sql = "UPDATE " + g_tables[0] + " SET assert = ? where rowid = '" + std::to_string(rowid) + "';";
        std::vector<uint8_t> assetBlob;
        int errCode;
        Asset asset = g_cloudAsset;
        asset.name = "Phone" + std::to_string(rowid - cloudCount - 1);
        if (opType == AssetOpType::UPDATE) {
            asset.uri = "/data/test";
        } else if (opType == AssetOpType::INSERT) {
            asset.name = "Test10";
        }
        asset.status = static_cast<uint32_t>(CloudStorageUtils::FlagToStatus(opType));
        sqlite3_stmt *stmt = nullptr;
        RuntimeContext::GetInstance()->AssetToBlob(asset, assetBlob);
        ASSERT_EQ(SQLiteUtils::GetStatement(db, sql, stmt), E_OK);
        if (SQLiteUtils::BindBlobToStatement(stmt, 1, assetBlob, false) == E_OK) {
            EXPECT_EQ(SQLiteUtils::StepWithRetry(stmt), SQLiteUtils::MapSQLiteErrno(SQLITE_DONE));
        }
        SQLiteUtils::ResetStatement(stmt, true, errCode);
    }

    void UpdateAssetsForTest(sqlite3 *&db, AssetOpType opType, int64_t rowid)
    {
        string sql = "UPDATE " + g_tables[1] + " SET asserts = ? where rowid = '" + std::to_string(rowid) + "';";
        Asset asset1 = g_localAsset;
        Asset asset2 = g_localAsset;
        Assets assets;
        asset1.name = g_localAsset.name + std::to_string(rowid);
        asset1.status = static_cast<uint32_t>(CloudStorageUtils::FlagToStatus(AssetOpType::NO_CHANGE));
        asset2.name = g_localAsset.name + std::to_string(rowid + 1);
        asset2.status = static_cast<uint32_t>(CloudStorageUtils::FlagToStatus(AssetOpType::NO_CHANGE));
        if (opType == AssetOpType::UPDATE) {
            assets.push_back(asset1);
            asset2.uri = "/data/test";
            asset2.status = static_cast<uint32_t>(CloudStorageUtils::FlagToStatus(opType));
            assets.push_back(asset2);
        } else if (opType == AssetOpType::INSERT) {
            assets.push_back(asset1);
            assets.push_back(asset2);
            Asset asset3;
            asset3.status = static_cast<uint32_t>(CloudStorageUtils::FlagToStatus(opType));
            asset3.name = "Test10";
            assets.push_back(asset3);
        } else if (opType == AssetOpType::DELETE) {
            assets.push_back(asset1);
            asset2.status = static_cast<uint32_t>(CloudStorageUtils::FlagToStatus(opType));
            assets.push_back(asset2);
        } else {
            assets.push_back(asset1);
            assets.push_back(asset2);
        }
        sqlite3_stmt *stmt = nullptr;
        std::vector<uint8_t> assetsBlob;
        RuntimeContext::GetInstance()->AssetsToBlob(assets, assetsBlob);
        ASSERT_EQ(SQLiteUtils::GetStatement(db, sql, stmt), E_OK);
        if (SQLiteUtils::BindBlobToStatement(stmt, 1, assetsBlob, false) == E_OK) {
            EXPECT_EQ(SQLiteUtils::StepWithRetry(stmt), SQLiteUtils::MapSQLiteErrno(SQLITE_DONE));
        }
        int errCode;
        SQLiteUtils::ResetStatement(stmt, true, errCode);
    }

    void CheckFillAssetForTest10(sqlite3 *&db)
    {
        std::string sql = "SELECT assert from " + g_tables[0] + " WHERE rowid in ('27','28','29','30');";
        sqlite3_stmt *stmt = nullptr;
        int index = 0;
        ASSERT_EQ(SQLiteUtils::GetStatement(db, sql, stmt), E_OK);
        int suffixId = 6;
        while (SQLiteUtils::StepWithRetry(stmt) == SQLiteUtils::MapSQLiteErrno(SQLITE_ROW)) {
            if (index == 0 || index == 1 || index == 3) { // 3 is rowid index of 29
                ASSERT_EQ(sqlite3_column_type(stmt, 0), SQLITE_BLOB);
                Type cloudValue;
                ASSERT_EQ(SQLiteRelationalUtils::GetCloudValueByType(stmt, TYPE_INDEX<Asset>, 0, cloudValue), E_OK);
                std::vector<uint8_t> assetBlob;
                Asset asset;
                ASSERT_EQ(CloudStorageUtils::GetValueFromOneField(cloudValue, assetBlob), E_OK);
                ASSERT_EQ(RuntimeContext::GetInstance()->BlobToAsset(assetBlob, asset), E_OK);
                ASSERT_EQ(asset.status, static_cast<uint32_t>(AssetStatus::NORMAL));
                if (index == 0) {
                    ASSERT_EQ(asset.name, g_cloudAsset.name + std::to_string(suffixId + index));
                } else if (index == 1) {
                    ASSERT_EQ(asset.name, "Test10");
                } else {
                    ASSERT_EQ(asset.name, g_cloudAsset.name + std::to_string(suffixId + index));
                    ASSERT_EQ(asset.uri, "/data/test");
                }
            } else {
                ASSERT_EQ(sqlite3_column_type(stmt, 0), SQLITE_NULL);
            }
            index++;
        }
        int errCode;
        SQLiteUtils::ResetStatement(stmt, true, errCode);
    }

    void CheckFillAssetsForTest10(sqlite3 *&db)
    {
        std::string sql = "SELECT asserts from " + g_tables[1] + " WHERE rowid in ('0','1','2','3');";
        sqlite3_stmt *stmt = nullptr;
        int index = 0;
        ASSERT_EQ(SQLiteUtils::GetStatement(db, sql, stmt), E_OK);
        int insertIndex = 2;
        while (SQLiteUtils::StepWithRetry(stmt) == SQLiteUtils::MapSQLiteErrno(SQLITE_ROW)) {
            ASSERT_EQ(sqlite3_column_type(stmt, 0), SQLITE_BLOB);
            Type cloudValue;
            ASSERT_EQ(SQLiteRelationalUtils::GetCloudValueByType(stmt, TYPE_INDEX<Assets>, 0, cloudValue), E_OK);
            std::vector<uint8_t> assetsBlob;
            Assets assets;
            ASSERT_EQ(CloudStorageUtils::GetValueFromOneField(cloudValue, assetsBlob), E_OK);
            ASSERT_EQ(RuntimeContext::GetInstance()->BlobToAssets(assetsBlob, assets), E_OK);
            if (index == 0) {
                ASSERT_EQ(assets.size(), 2u);
                ASSERT_EQ(assets[0].name, g_localAsset.name + std::to_string(index));
                ASSERT_EQ(assets[1].name, g_localAsset.name + std::to_string(index + 1));
            } else if (index == 1) {
                ASSERT_EQ(assets.size(), 3u);
                ASSERT_EQ(assets[insertIndex].name, "Test10");
                ASSERT_EQ(assets[insertIndex].status, static_cast<uint32_t>(AssetStatus::NORMAL));
            } else if (index == 2) { // 2 is the third element
                ASSERT_EQ(assets.size(), 1u);
                ASSERT_EQ(assets[0].name, g_cloudAsset.name + std::to_string(index));
            } else {
                ASSERT_EQ(assets.size(), 2u);
                ASSERT_EQ(assets[1].uri, "/data/test");
                ASSERT_EQ(assets[1].status, static_cast<uint32_t>(AssetStatus::NORMAL));
            }
            index++;
        }
        int errCode;
        SQLiteUtils::ResetStatement(stmt, true, errCode);
    }

    int QueryCountCallback(void *data, int count, char **colValue, char **colName)
    {
        if (count != 1) {
            return 0;
        }
        auto expectCount = reinterpret_cast<int64_t>(data);
        EXPECT_EQ(strtol(colValue[0], nullptr, 10), expectCount); // 10: decimal
        return 0;
    }

    void CheckDownloadResult(sqlite3 *&db, std::vector<int64_t> expectCounts)
    {
        for (size_t i = 0; i < g_tables.size(); ++i) {
            string queryDownload = "select count(*) from " + g_tables[i] + " where name "
                                   + " like 'Cloud%'";
            EXPECT_EQ(sqlite3_exec(db, queryDownload.c_str(), QueryCountCallback,
                reinterpret_cast<void *>(expectCounts[i]), nullptr), SQLITE_OK);
        }
    }

    void CheckCloudRecordNum(sqlite3 *&db, std::vector<std::string> tableList, std::vector<int> countList)
    {
        int i = 0;
        for (const auto &tableName: tableList) {
            std::string sql = "select count(*) from " + DBCommon::GetLogTableName(tableName) +
                " where device = 'cloud'" + " and cloud_gid is not null and cloud_gid != '' and flag & 0x2 = 0;";
            EXPECT_EQ(sqlite3_exec(db, sql.c_str(), QueryCountCallback,
                reinterpret_cast<void *>(countList[i]), nullptr), SQLITE_OK);
            i++;
        }
    }

    void CheckCleanLogNum(sqlite3 *&db, const std::vector<std::string> tableList, int count)
    {
        for (const auto &tableName: tableList) {
            std::string sql1 = "select count(*) from " + DBCommon::GetLogTableName(tableName) +
                " where device = 'cloud';";
            EXPECT_EQ(sqlite3_exec(db, sql1.c_str(), QueryCountCallback,
                reinterpret_cast<void *>(count), nullptr), SQLITE_OK);
            std::string sql2 = "select count(*) from " + DBCommon::GetLogTableName(tableName) +
                " where cloud_gid " + " is not null and cloud_gid != '';";
            EXPECT_EQ(sqlite3_exec(db, sql2.c_str(), QueryCountCallback,
                reinterpret_cast<void *>(count), nullptr), SQLITE_OK);
            std::string sql3 = "select count(*) from " + DBCommon::GetLogTableName(tableName) +
                " where flag & 0x02 = 0;";
            EXPECT_EQ(sqlite3_exec(db, sql3.c_str(), QueryCountCallback,
                reinterpret_cast<void *>(count), nullptr), SQLITE_OK);
        }
    }

    void CheckCleanDataAndLogNum(sqlite3 *&db, const std::vector<std::string> tableList, int count,
        std::vector<int> localNum)
    {
        int i = 0;
        for (const auto &tableName: tableList) {
            std::string sql1 = "select count(*) from " + DBCommon::GetLogTableName(tableName) +
                " where device = 'cloud';";
            EXPECT_EQ(sqlite3_exec(db, sql1.c_str(), QueryCountCallback,
                reinterpret_cast<void *>(count), nullptr), SQLITE_OK);
            std::string sql2 = "select count(*) from " + DBCommon::GetLogTableName(tableName) + " where cloud_gid "
                " is not null and cloud_gid != '';";
            EXPECT_EQ(sqlite3_exec(db, sql2.c_str(), QueryCountCallback,
                reinterpret_cast<void *>(count), nullptr), SQLITE_OK);
            std::string sql3 = "select count(*) from " + DBCommon::GetLogTableName(tableName) +
                " where flag & 0x02 = 0;";
            EXPECT_EQ(sqlite3_exec(db, sql3.c_str(), QueryCountCallback,
                reinterpret_cast<void *>(count), nullptr), SQLITE_OK);
            std::string local_sql = "select count(*) from " + tableName +";";
            EXPECT_EQ(sqlite3_exec(db, local_sql.c_str(), QueryCountCallback,
                reinterpret_cast<void *>(localNum[i]), nullptr), SQLITE_OK);
            i++;
        }
    }

    void CheckCloudTotalCount(std::vector<int64_t> expectCounts)
    {
        VBucket extend;
        extend[CloudDbConstant::CURSOR_FIELD] = std::to_string(0);
        for (size_t i = 0; i < g_tables.size(); ++i) {
            int64_t realCount = 0;
            std::vector<VBucket> data;
            g_virtualCloudDb->Query(g_tables[i], extend, data);
            for (size_t j = 0; j < data.size(); ++j) {
                auto entry = data[j].find(CloudDbConstant::DELETE_FIELD);
                if (entry != data[j].end() && std::get<bool>(entry->second)) {
                    continue;
                }
                realCount++;
            }
            EXPECT_EQ(realCount, expectCounts[i]); // ExpectCount represents the total amount of cloud data.
        }
    }

    void GetCloudDbSchema(DataBaseSchema &dataBaseSchema)
    {
        TableSchema tableSchema1 = {
            .name = g_tableName1,
            .fields = g_cloudFiled1
        };
        TableSchema tableSchema2 = {
            .name = g_tableName2,
            .fields = g_cloudFiled2
        };
        TableSchema tableSchemaWithOutPrimaryKey = {
            .name = g_tableName3,
            .fields = g_cloudFiledWithOutPrimaryKey3
        };
        dataBaseSchema.tables.push_back(tableSchema1);
        dataBaseSchema.tables.push_back(tableSchema2);
        dataBaseSchema.tables.push_back(tableSchemaWithOutPrimaryKey);
    }


    void GetInvalidCloudDbSchema(DataBaseSchema &dataBaseSchema)
    {
        TableSchema tableSchema1 = {
            .name = g_tableName1,
            .fields = g_invalidCloudFiled1
        };
        TableSchema tableSchema2 = {
            .name = g_tableName1,
            .fields = g_cloudFiled2
        };
        dataBaseSchema.tables.push_back(tableSchema1);
        dataBaseSchema.tables.push_back(tableSchema2);
    }

    void InitProcessForTest1(const uint32_t &cloudCount, const uint32_t &localCount,
        std::vector<SyncProcess> &expectProcess)
    {
        expectProcess.clear();
        std::vector<TableProcessInfo> infos;
        uint32_t index = 1;
        infos.push_back(TableProcessInfo{
            PROCESSING, {index, cloudCount, cloudCount, 0}, {0, 0, 0, 0}
        });
        infos.push_back(TableProcessInfo{
            PREPARED, {0, 0, 0, 0}, {0, 0, 0, 0}
        });

        infos.push_back(TableProcessInfo{
            PROCESSING, {index, cloudCount, cloudCount, 0}, {0, 0, 0, 0}
        });
        infos.push_back(TableProcessInfo{
            PROCESSING, {index, cloudCount, cloudCount, 0}, {0, 0, 0, 0}
        });

        infos.push_back(TableProcessInfo{
            FINISHED, {index, cloudCount, cloudCount, 0}, {index, localCount, localCount, 0}
        });
        infos.push_back(TableProcessInfo{
            PROCESSING, {index, cloudCount, cloudCount, 0}, {0, 0, 0, 0}
        });

        infos.push_back(TableProcessInfo{
            FINISHED, {index, cloudCount, cloudCount, 0}, {index, localCount, localCount, 0}
        });
        infos.push_back(TableProcessInfo{
            FINISHED, {index, cloudCount, cloudCount, 0}, {index, localCount, localCount, 0}
        });

        for (size_t i = 0; i < infos.size() / g_arrayHalfSub; ++i) {
            SyncProcess syncProcess;
            syncProcess.errCode = OK;
            syncProcess.process = i == infos.size() ? FINISHED : PROCESSING;
            syncProcess.tableProcess.insert_or_assign(g_tables[0], std::move(infos[g_arrayHalfSub * i]));
            syncProcess.tableProcess.insert_or_assign(g_tables[1], std::move(infos[g_arrayHalfSub * i + 1]));
            expectProcess.push_back(syncProcess);
        }
    }
    void InitProcessForMannualSync1(std::vector<SyncProcess> &expectProcess)
    {
        expectProcess.clear();
        std::vector<TableProcessInfo> infos;
        // first notify, first table
        infos.push_back(TableProcessInfo{
            FINISHED, {0, 0, 0, 0}, {0, 0, 0, 0}
        });
        // first notify, second table
        infos.push_back(TableProcessInfo{
            PREPARED, {0, 0, 0, 0}, {0, 0, 0, 0}
        });
        // second notify, first table
        infos.push_back(TableProcessInfo{
            FINISHED, {0, 0, 0, 0}, {0, 0, 0, 0}
        });
        // second notify, second table
        infos.push_back(TableProcessInfo{
            FINISHED, {0, 0, 0, 0}, {0, 0, 0, 0}
        });

        infos.push_back(TableProcessInfo{
            FINISHED, {0, 0, 0, 0}, {0, 0, 0, 0}
        });
        // second notify, second table
        infos.push_back(TableProcessInfo{
            FINISHED, {0, 0, 0, 0}, {0, 0, 0, 0}
        });
        for (size_t i = 0; i < infos.size() / g_arrayHalfSub; ++i) {
            SyncProcess syncProcess;
            syncProcess.errCode = OK;
            syncProcess.process = i == infos.size() ? FINISHED : PROCESSING;
            syncProcess.tableProcess.insert_or_assign(g_tables[0], std::move(infos[g_arrayHalfSub * i]));
            syncProcess.tableProcess.insert_or_assign(g_tables[1], std::move(infos[g_arrayHalfSub * i + 1]));
            expectProcess.push_back(syncProcess);
        }
    }
    void InitProcessForCleanCloudData1(const uint32_t &cloudCount, const uint32_t &localCount,
        std::vector<SyncProcess> &expectProcess)
    {
        // cloudCount also means data count in one batch
        expectProcess.clear();
        std::vector<TableProcessInfo> infos;
        uint32_t index = 1;
        infos.push_back(TableProcessInfo{
            FINISHED, {index, cloudCount, cloudCount, 0}, {0, 0, 0, 0}
        });
        infos.push_back(TableProcessInfo{
            PREPARED, {0, 0, 0, 0}, {0, 0, 0, 0}
        });

        infos.push_back(TableProcessInfo{
            FINISHED, {index, cloudCount, cloudCount, 0}, {0, 0, 0, 0}
        });
        infos.push_back(TableProcessInfo{
            FINISHED, {index, cloudCount, cloudCount, 0}, {0, 0, 0, 0}
        });

        for (size_t i = 0; i < infos.size() / g_arrayHalfSub; ++i) {
            SyncProcess syncProcess;
            syncProcess.errCode = OK;
            syncProcess.process = i == infos.size() ? FINISHED : PROCESSING;
            syncProcess.tableProcess.insert_or_assign(g_tables[0], std::move(infos[g_arrayHalfSub * i]));
            syncProcess.tableProcess.insert_or_assign(g_tables[1], std::move(infos[g_arrayHalfSub * i + 1]));
            expectProcess.push_back(syncProcess);
        }
    }


    void InitProcessForTest2(const uint32_t &cloudCount, const uint32_t &localCount,
        std::vector<SyncProcess> &expectProcess)
    {
        expectProcess.clear();
        std::vector<TableProcessInfo> infos;
        uint32_t index = 1;
        infos.push_back(TableProcessInfo{
            PROCESSING, {index, cloudCount, cloudCount, 0}, {0, 0, 0, 0}
        });
        infos.push_back(TableProcessInfo{
            PREPARED, {0, 0, 0, 0}, {0, 0, 0, 0}
        });

        infos.push_back(TableProcessInfo{
            PROCESSING, {index, cloudCount, cloudCount, 0}, {0, 0, 0, 0}
        });
        infos.push_back(TableProcessInfo{
            PROCESSING, {index, cloudCount, cloudCount, 0}, {0, 0, 0, 0}
        });

        infos.push_back(TableProcessInfo{
            FINISHED, {index, cloudCount, cloudCount, 0}, {index, localCount, localCount, 0}
        });
        infos.push_back(TableProcessInfo{
            PROCESSING, {index, cloudCount, cloudCount, 0}, {0, 0, 0, 0}
        });

        infos.push_back(TableProcessInfo{
            FINISHED, {index, cloudCount, cloudCount, 0}, {index, localCount, localCount, 0}
        });
        infos.push_back(TableProcessInfo{
            FINISHED, {index, cloudCount, cloudCount, 0}, {index, localCount - cloudCount, localCount - cloudCount, 0}
        });

        for (size_t i = 0; i <= infos.size() / g_arrayHalfSub; ++i) {
            SyncProcess syncProcess;
            syncProcess.errCode = OK;
            syncProcess.process = i == infos.size() ? FINISHED : PROCESSING;
            syncProcess.tableProcess.insert_or_assign(g_tables[0], std::move(infos[g_arrayHalfSub * i]));
            syncProcess.tableProcess.insert_or_assign(g_tables[1], std::move(infos[g_arrayHalfSub * i + 1]));
            expectProcess.push_back(syncProcess);
        }
    }

    void InitProcessForTest9(const uint32_t &cloudCount, const uint32_t &localCount,
        std::vector<SyncProcess> &expectProcess)
    {
        expectProcess.clear();
        std::vector<TableProcessInfo> infos;
        uint32_t index = 1;
        infos.push_back(TableProcessInfo{
            PROCESSING, {index, cloudCount, cloudCount, 0}, {0, 0, 0, 0}
        });
        infos.push_back(TableProcessInfo{
            PREPARED, {0, 0, 0, 0}, {0, 0, 0, 0}
        });

        infos.push_back(TableProcessInfo{
            PROCESSING, {index, cloudCount, cloudCount, 0}, {0, 0, 0, 0}
        });
        infos.push_back(TableProcessInfo{
            PROCESSING, {index, cloudCount, cloudCount, 0}, {0, 0, 0, 0}
        });

        infos.push_back(TableProcessInfo{
            FINISHED, {index, cloudCount, cloudCount, 0}, {0, 0, 0, 0}
        });
        infos.push_back(TableProcessInfo{
            PROCESSING, {index, cloudCount, cloudCount, 0}, {0, 0, 0, 0}
        });

        infos.push_back(TableProcessInfo{
            FINISHED, {index, cloudCount, cloudCount, 0}, {0, 0, 0, 0}
        });
        infos.push_back(TableProcessInfo{
            FINISHED, {index, cloudCount, cloudCount, 0}, {0, 0, 0, 0}
        });

        for (size_t i = 0; i <= infos.size() / g_arrayHalfSub; ++i) {
            SyncProcess syncProcess;
            syncProcess.errCode = OK;
            syncProcess.process = i == infos.size() ? FINISHED : PROCESSING;
            syncProcess.tableProcess.insert_or_assign(g_tables[0], std::move(infos[g_arrayHalfSub * i]));
            syncProcess.tableProcess.insert_or_assign(g_tables[1], std::move(infos[g_arrayHalfSub * i + 1]));
            expectProcess.push_back(syncProcess);
        }
    }

    void GetCallback(SyncProcess &syncProcess, CloudSyncStatusCallback &callback,
        std::vector<SyncProcess> &expectProcess)
    {
        g_syncIndex = 0;
        callback = [&syncProcess, &expectProcess](const std::map<std::string, SyncProcess> &process) {
            LOGI("devices size = %d", process.size());
            ASSERT_EQ(process.size(), 1u);
            syncProcess = std::move(process.begin()->second);
            ASSERT_EQ(process.begin()->first, DEVICE_CLOUD);
            ASSERT_NE(syncProcess.tableProcess.empty(), true);
            LOGI("current sync process status:%d, db status:%d ", syncProcess.process, syncProcess.errCode);
            std::for_each(g_tables.begin(), g_tables.end(), [&](const auto &item) {
                auto table1 = syncProcess.tableProcess.find(item);
                if (table1 != syncProcess.tableProcess.end()) {
                    LOGI("table[%s], table process status:%d, [downloadInfo](batchIndex:%u, total:%u, successCount:%u, "
                         "failCount:%u) [uploadInfo](batchIndex:%u, total:%u, successCount:%u,failCount:%u",
                         item.c_str(), table1->second.process, table1->second.downLoadInfo.batchIndex,
                         table1->second.downLoadInfo.total, table1->second.downLoadInfo.successCount,
                         table1->second.downLoadInfo.failCount, table1->second.upLoadInfo.batchIndex,
                         table1->second.upLoadInfo.total, table1->second.upLoadInfo.successCount,
                         table1->second.upLoadInfo.failCount);
                }
            });
            if (expectProcess.empty()) {
                if (syncProcess.process == FINISHED) {
                    g_processCondition.notify_one();
                }
                return;
            }
            ASSERT_LE(static_cast<size_t>(g_syncIndex), expectProcess.size());
            for (size_t i = 0; i < g_tables.size(); ++i) {
                SyncProcess head = expectProcess[g_syncIndex];
                for (auto &expect : head.tableProcess) {
                    auto real = syncProcess.tableProcess.find(expect.first);
                    ASSERT_NE(real, syncProcess.tableProcess.end());
                    EXPECT_EQ(expect.second.process, real->second.process);
                    EXPECT_EQ(expect.second.downLoadInfo.batchIndex, real->second.downLoadInfo.batchIndex);
                    EXPECT_EQ(expect.second.downLoadInfo.total, real->second.downLoadInfo.total);
                    EXPECT_EQ(expect.second.downLoadInfo.successCount, real->second.downLoadInfo.successCount);
                    EXPECT_EQ(expect.second.downLoadInfo.failCount, real->second.downLoadInfo.failCount);
                    EXPECT_EQ(expect.second.upLoadInfo.batchIndex, real->second.upLoadInfo.batchIndex);
                    EXPECT_EQ(expect.second.upLoadInfo.total, real->second.upLoadInfo.total);
                    EXPECT_EQ(expect.second.upLoadInfo.successCount, real->second.upLoadInfo.successCount);
                    EXPECT_EQ(expect.second.upLoadInfo.failCount, real->second.upLoadInfo.failCount);
                }
            }
            g_syncIndex++;
            if (syncProcess.process == FINISHED) {
                g_processCondition.notify_one();
            }
        };
    }

    void CheckAllAssetAfterUpload(int64_t localCount)
    {
        VBucket extend;
        extend[CloudDbConstant::CURSOR_FIELD] = std::to_string(0);
        std::vector<VBucket> data1;
        g_virtualCloudDb->Query(g_tables[0], extend, data1);
        for (size_t j = 0; j < data1.size(); ++j) {
            auto entry = data1[j].find("assert");
            ASSERT_NE(entry, data1[j].end());
            Asset asset = std::get<Asset>(entry->second);
            bool isLocal = j >= (size_t)(localCount / g_arrayHalfSub);
            Asset baseAsset = isLocal ? g_localAsset : g_cloudAsset;
            EXPECT_EQ(asset.version, baseAsset.version);
            EXPECT_EQ(asset.name, baseAsset.name + std::to_string(isLocal ? j - localCount / g_arrayHalfSub : j));
            EXPECT_EQ(asset.uri, baseAsset.uri);
            EXPECT_EQ(asset.modifyTime, baseAsset.modifyTime);
            EXPECT_EQ(asset.createTime, baseAsset.createTime);
            EXPECT_EQ(asset.size, baseAsset.size);
            EXPECT_EQ(asset.hash, baseAsset.hash);
        }

        std::vector<VBucket> data2;
        g_virtualCloudDb->Query(g_tables[1], extend, data2);
        for (size_t j = 0; j < data2.size(); ++j) {
            auto entry = data2[j].find("asserts");
            ASSERT_NE(entry, data2[j].end());
            Assets assets = std::get<Assets>(entry->second);
            Asset baseAsset = j >= (size_t)(localCount / g_arrayHalfSub) ? g_localAsset : g_cloudAsset;
            int index = j;
            for (const auto &asset: assets) {
                EXPECT_EQ(asset.version, baseAsset.version);
                EXPECT_EQ(asset.name, baseAsset.name + std::to_string(index++));
                EXPECT_EQ(asset.uri, baseAsset.uri);
                EXPECT_EQ(asset.modifyTime, baseAsset.modifyTime);
                EXPECT_EQ(asset.createTime, baseAsset.createTime);
                EXPECT_EQ(asset.size, baseAsset.size);
                EXPECT_EQ(asset.hash, baseAsset.hash);
            }
        }
    }

    void CheckAssetsAfterDownload(sqlite3 *&db, int64_t localCount)
    {
        string queryDownload = "select asserts from " + g_tables[1] + " where rowid in (";
        for (int64_t i = 0; i < localCount; ++i) {
            queryDownload +=  "'" + std::to_string(i) + "',";
        }
        queryDownload.pop_back();
        queryDownload += ");";
        sqlite3_stmt *stmt = nullptr;
        ASSERT_EQ(SQLiteUtils::GetStatement(db, queryDownload, stmt), E_OK);
        int index = 0;
        while (SQLiteUtils::StepWithRetry(stmt) == SQLiteUtils::MapSQLiteErrno(SQLITE_ROW)) {
            std::vector<uint8_t> blobValue;
            ASSERT_EQ(SQLiteUtils::GetColumnBlobValue(stmt, 0, blobValue), E_OK);
            Assets assets;
            ASSERT_EQ(RuntimeContext::GetInstance()->BlobToAssets(blobValue, assets), E_OK);
            bool isLocal = index >= localCount / g_arrayHalfSub;
            Asset baseAsset = isLocal ? g_localAsset : g_cloudAsset;
            int nameIndex = index;
            for (const auto &asset: assets) {
                EXPECT_EQ(asset.version, baseAsset.version);
                EXPECT_EQ(asset.name, baseAsset.name + std::to_string(nameIndex));
                EXPECT_EQ(asset.uri, baseAsset.uri);
                EXPECT_EQ(asset.modifyTime, baseAsset.modifyTime);
                EXPECT_EQ(asset.createTime, baseAsset.createTime);
                EXPECT_EQ(asset.size, baseAsset.size);
                EXPECT_EQ(asset.hash, baseAsset.hash);
                EXPECT_EQ(asset.status, static_cast<uint32_t>(AssetStatus::NORMAL));
                nameIndex++;
            }
            index++;
        }
        int errCode;
        SQLiteUtils::ResetStatement(stmt, true, errCode);
    }

    void CheckAssetAfterDownload(sqlite3 *&db, int64_t localCount)
    {
        string queryDownload = "select assert from " + g_tables[0] + " where rowid in (";
        for (int64_t i = 0; i < localCount; ++i) {
            queryDownload +=  "'" + std::to_string(i) + "',";
        }
        queryDownload.pop_back();
        queryDownload += ");";
        sqlite3_stmt *stmt = nullptr;
        ASSERT_EQ(SQLiteUtils::GetStatement(db, queryDownload, stmt), E_OK);
        int index = 0;
        while (SQLiteUtils::StepWithRetry(stmt) == SQLiteUtils::MapSQLiteErrno(SQLITE_ROW)) {
            std::vector<uint8_t> blobValue;
            ASSERT_EQ(SQLiteUtils::GetColumnBlobValue(stmt, 0, blobValue), E_OK);
            Asset asset;
            ASSERT_EQ(RuntimeContext::GetInstance()->BlobToAsset(blobValue, asset), E_OK);
            bool isCloud = index >= localCount;
            Asset baseAsset = isCloud ? g_cloudAsset : g_localAsset;
            EXPECT_EQ(asset.version, baseAsset.version);
            EXPECT_EQ(asset.name,
                baseAsset.name + std::to_string(isCloud ?  index - localCount / g_arrayHalfSub : index));
            EXPECT_EQ(asset.uri, baseAsset.uri);
            EXPECT_EQ(asset.modifyTime, baseAsset.modifyTime);
            EXPECT_EQ(asset.createTime, baseAsset.createTime);
            EXPECT_EQ(asset.size, baseAsset.size);
            EXPECT_EQ(asset.hash, baseAsset.hash);
            EXPECT_EQ(asset.status, static_cast<uint32_t>(AssetStatus::NORMAL));
            index++;
        }
        int errCode;
        SQLiteUtils::ResetStatement(stmt, true, errCode);
    }

    void WaitForSyncFinish(SyncProcess &syncProcess, const int64_t &waitTime)
    {
        std::unique_lock<std::mutex> lock(g_processMutex);
        bool result = g_processCondition.wait_for(lock, std::chrono::seconds(waitTime), [&syncProcess]() {
            return syncProcess.process == FINISHED;
        });
        ASSERT_EQ(result, true);
        LOGD("-------------------sync end--------------");
    }

    class DistributedDBCloudInterfacesRelationalSyncTest : public testing::Test {
    public:
        static void SetUpTestCase(void);
        static void TearDownTestCase(void);
        void SetUp();
        void TearDown();
    protected:
        sqlite3 *db = nullptr;
        RelationalStoreDelegate *delegate = nullptr;
    };


    void DistributedDBCloudInterfacesRelationalSyncTest::SetUpTestCase(void)
    {
        DistributedDBToolsUnitTest::TestDirInit(g_testDir);
        g_storePath = g_testDir + "/" + g_storeID + DB_SUFFIX;
        LOGI("The test db is:%s", g_testDir.c_str());
        RuntimeConfig::SetCloudTranslate(std::make_shared<VirtualCloudDataTranslate>());
    }

    void DistributedDBCloudInterfacesRelationalSyncTest::TearDownTestCase(void)
    {}

    void DistributedDBCloudInterfacesRelationalSyncTest::SetUp(void)
    {
        if (DistributedDBToolsUnitTest::RemoveTestDbFiles(g_testDir) != 0) {
            LOGE("rm test db files error.");
        }
        DistributedDBToolsUnitTest::PrintTestCaseInfo();
        LOGD("Test dir is %s", g_testDir.c_str());
        db = RelationalTestUtils::CreateDataBase(g_storePath);
        ASSERT_NE(db, nullptr);
        CreateUserDBAndTable(db);
        g_observer = new (std::nothrow) RelationalStoreObserverUnitTest();
        ASSERT_NE(g_observer, nullptr);
        ASSERT_EQ(g_mgr.OpenStore(g_storePath, g_storeID, RelationalStoreDelegate::Option { .observer = g_observer },
            delegate), DBStatus::OK);
        ASSERT_NE(delegate, nullptr);
        ASSERT_EQ(delegate->CreateDistributedTable(g_tableName1, CLOUD_COOPERATION), DBStatus::OK);
        ASSERT_EQ(delegate->CreateDistributedTable(g_tableName2, CLOUD_COOPERATION), DBStatus::OK);
        ASSERT_EQ(delegate->CreateDistributedTable(g_tableName3, CLOUD_COOPERATION), DBStatus::OK);
        g_virtualCloudDb = make_shared<VirtualCloudDb>();
        g_virtualAssetLoader = make_shared<VirtualAssetLoader>();
        g_syncProcess = {};
        ASSERT_EQ(delegate->SetCloudDB(g_virtualCloudDb), DBStatus::OK);
        ASSERT_EQ(delegate->SetIAssetLoader(g_virtualAssetLoader), DBStatus::OK);
        // sync before setting cloud db schema,it should return SCHEMA_MISMATCH
        Query query = Query::Select().FromTable(g_tables);
        CloudSyncStatusCallback callback;
        ASSERT_EQ(delegate->Sync({DEVICE_CLOUD}, SYNC_MODE_CLOUD_MERGE, query, callback, g_syncWaitTime),
            DBStatus::SCHEMA_MISMATCH);
        DataBaseSchema dataBaseSchema;
        GetCloudDbSchema(dataBaseSchema);
        ASSERT_EQ(delegate->SetCloudDbSchema(dataBaseSchema), DBStatus::OK);
    }

    void DistributedDBCloudInterfacesRelationalSyncTest::TearDown(void)
    {
        delete g_observer;
        g_virtualCloudDb = nullptr;
        if (delegate != nullptr) {
            EXPECT_EQ(g_mgr.CloseStore(delegate), DBStatus::OK);
            delegate = nullptr;
        }
        EXPECT_EQ(sqlite3_close_v2(db), SQLITE_OK);
        if (DistributedDBToolsUnitTest::RemoveTestDbFiles(g_testDir) != 0) {
            LOGE("rm test db files error.");
        }
    }

/**
 * @tc.name: CloudSyncTest001
 * @tc.desc: Cloud data is older than local data.
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: bty
 */
HWTEST_F(DistributedDBCloudInterfacesRelationalSyncTest, CloudSyncTest001, TestSize.Level0)
{
    int64_t paddingSize = 10;
    int64_t cloudCount = 20;
    int64_t localCount = cloudCount / g_arrayHalfSub;
    ChangedData changedDataForTable1;
    ChangedData changedDataForTable2;
    changedDataForTable1.tableName = g_tableName1;
    changedDataForTable2.tableName = g_tableName2;
    changedDataForTable1.field.push_back(std::string("name"));
    changedDataForTable2.field.push_back(std::string("id"));
    for (int i = 0; i < cloudCount; i++) {
        changedDataForTable1.primaryData[ChangeType::OP_INSERT].push_back({"Cloud" + std::to_string(i)});
        changedDataForTable2.primaryData[ChangeType::OP_INSERT].push_back({(int64_t)i + 10});
    }
    g_observer->SetExpectedResult(changedDataForTable1);
    g_observer->SetExpectedResult(changedDataForTable2);
    InsertCloudTableRecord(0, cloudCount, paddingSize, false);
    InsertUserTableRecord(db, 0, localCount, paddingSize, false);
    Query query = Query::Select().FromTable(g_tables);
    std::vector<SyncProcess> expectProcess;
    InitProcessForTest1(cloudCount, localCount, expectProcess);
    CloudSyncStatusCallback callback;
    GetCallback(g_syncProcess, callback, expectProcess);
    ASSERT_EQ(delegate->Sync({DEVICE_CLOUD}, SYNC_MODE_CLOUD_MERGE, query, callback, g_syncWaitTime), DBStatus::OK);
    WaitForSyncFinish(g_syncProcess, g_syncWaitTime);
    EXPECT_TRUE(g_observer->IsAllChangedDataEq());
    g_observer->ClearChangedData();
    LOGD("expect download:worker1[primary key]:[cloud0 - cloud20), worker2[primary key]:[10 - 20)");
    CheckDownloadResult(db, {20L, 10L}); // 20 and 10 means the num of downloads from cloud db by worker1 and worker2
    LOGD("expect upload:worker1[primary key]:[local0 - local10), worker2[primary key]:[0 - 10)");
    CheckCloudTotalCount({30L, 20L}); // 30 and 20 means the total num of worker1 and worker2 from the cloud db
}

/**
 * @tc.name: CloudSyncTest002
 * @tc.desc: Local data is older than cloud data.
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: bty
 */
HWTEST_F(DistributedDBCloudInterfacesRelationalSyncTest, CloudSyncTest002, TestSize.Level0)
{
    int64_t localCount = 20;
    int64_t cloudCount = 10;
    int64_t paddingSize = 100;
    InsertUserTableRecord(db, 0, localCount, paddingSize, false);
    InsertCloudTableRecord(0, cloudCount, paddingSize, false);
    Query query = Query::Select().FromTable(g_tables);
    std::vector<SyncProcess> expectProcess;
    InitProcessForTest2(cloudCount, localCount, expectProcess);
    CloudSyncStatusCallback callback;
    GetCallback(g_syncProcess, callback, expectProcess);
    ASSERT_EQ(delegate->Sync({DEVICE_CLOUD}, SYNC_MODE_CLOUD_MERGE, query, callback, g_syncWaitTime), DBStatus::OK);
    WaitForSyncFinish(g_syncProcess, g_syncWaitTime);
    LOGD("expect download:worker1[primary key]:[cloud0 - cloud10), worker2[primary key]:[0 - 10)");
    CheckDownloadResult(db, {10L, 10L}); // 10 and 10 means the num of downloads from cloud db by worker1 and worker2
    LOGD("expect upload:worker1[primary key]:[local0 - local20), worker2[primary key]:[10 - 20)");
    CheckCloudTotalCount({30L, 20L}); // 30 and 20 means the total num of worker1 and worker2 from the cloud db
}

/**
 * @tc.name: CloudSyncTest003
 * @tc.desc: test with update and delete operator
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: bty
 */
HWTEST_F(DistributedDBCloudInterfacesRelationalSyncTest, CloudSyncTest003, TestSize.Level0)
{
    int64_t paddingSize = 10;
    int cloudCount = 20;
    InsertCloudTableRecord(0, cloudCount, paddingSize, false);
    InsertUserTableRecord(db, 0, cloudCount, paddingSize, false);
    Query query = Query::Select().FromTable(g_tables);
    std::vector<SyncProcess> expectProcess;
    InitProcessForTest1(cloudCount, cloudCount, expectProcess);
    CloudSyncStatusCallback callback;
    GetCallback(g_syncProcess, callback, expectProcess);
    ASSERT_EQ(delegate->Sync({DEVICE_CLOUD}, SYNC_MODE_CLOUD_MERGE, query, callback, g_syncWaitTime), DBStatus::OK);
    WaitForSyncFinish(g_syncProcess, g_syncWaitTime);
    CheckDownloadResult(db, {20L, 0L}); // 20 and 0 means the num of downloads from cloud db by worker1 and worker2
    CheckCloudTotalCount({40L, 20L}); // 40 and 20 means the total num of worker1 and worker2 from the cloud db

    int updateCount = 10;
    UpdateUserTableRecord(db, 5, updateCount); // 5 is start id to be updated
    g_syncProcess = {};
    InitProcessForTest1(cloudCount, updateCount, expectProcess);
    GetCallback(g_syncProcess, callback, expectProcess);
    LOGD("-------------------sync after update--------------");
    ASSERT_EQ(delegate->Sync({DEVICE_CLOUD}, SYNC_MODE_CLOUD_MERGE, query, callback, g_syncWaitTime), DBStatus::OK);
    WaitForSyncFinish(g_syncProcess, g_syncWaitTime);

    VBucket extend;
    extend[CloudDbConstant::CURSOR_FIELD] = std::to_string(0);
    std::vector<VBucket> data1;
    g_virtualCloudDb->Query(g_tables[0], extend, data1);
    for (int j = 25; j < 35; ++j) { // index[25, 35) in cloud db expected to be updated
        EXPECT_EQ(std::get<int64_t>(data1[j]["age"]), 99); // 99 is the updated age field of cloud db
    }

    std::vector<VBucket> data2;
    g_virtualCloudDb->Query(g_tables[1], extend, data2);
    for (int j = 5; j < 15; ++j) { // index[5, 15) in cloud db expected to be updated
        EXPECT_EQ(std::get<int64_t>(data2[j]["age"]), 99); // 99 is the updated age field of cloud db
    }

    int deleteCount = 3;
    DeleteUserTableRecord(db, 0, deleteCount);
    g_syncProcess = {};
    InitProcessForTest1(updateCount, deleteCount, expectProcess);
    GetCallback(g_syncProcess, callback, expectProcess);
    ASSERT_EQ(delegate->Sync({DEVICE_CLOUD}, SYNC_MODE_CLOUD_MERGE, query, callback, g_syncWaitTime), DBStatus::OK);
    WaitForSyncFinish(g_syncProcess, g_syncWaitTime);

    CheckCloudTotalCount({37L, 17L}); // 37 and 17 means the total num of worker1 and worker2 from the cloud db
}

/**
 * @tc.name: CloudSyncTest004
 * @tc.desc: Random write of local and cloud data
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: bty
 */
HWTEST_F(DistributedDBCloudInterfacesRelationalSyncTest, CloudSyncTest004, TestSize.Level0)
{
    int64_t paddingSize = 1024 * 8;
    vector<thread> threads;
    int cloudCount = 1024;
    threads.emplace_back(InsertCloudTableRecord, 0, cloudCount, paddingSize, false);
    threads.emplace_back(InsertUserTableRecord, std::ref(db), 0, cloudCount, paddingSize, false);
    for (auto &thread: threads) {
        thread.join();
    }
    Query query = Query::Select().FromTable(g_tables);
    std::vector<SyncProcess> expectProcess;
    CloudSyncStatusCallback callback;
    GetCallback(g_syncProcess, callback, expectProcess);
    ASSERT_EQ(delegate->Sync({DEVICE_CLOUD}, SYNC_MODE_CLOUD_MERGE, query, callback, g_syncWaitTime), DBStatus::OK);
    WaitForSyncFinish(g_syncProcess, 20); // 20 is wait time
}

/**
 * @tc.name: CloudSyncTest005
 * @tc.desc: sync with device sync query
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: bty
 */
HWTEST_F(DistributedDBCloudInterfacesRelationalSyncTest, CloudSyncTest005, TestSize.Level0)
{
    Query query = Query::Select().FromTable(g_tables).OrderBy("123", true);
    ASSERT_EQ(delegate->Sync({DEVICE_CLOUD}, SYNC_MODE_CLOUD_MERGE, query, nullptr, g_syncWaitTime),
        DBStatus::NOT_SUPPORT);

    query = Query::Select();
    ASSERT_EQ(delegate->Sync({DEVICE_CLOUD}, SYNC_MODE_CLOUD_MERGE, query, nullptr, g_syncWaitTime),
        DBStatus::INVALID_ARGS);
}

/**
 * @tc.name: CloudSyncTest006
 * @tc.desc: Firstly set a correct schema, and then null or invalid schema
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: wanyi
 */
HWTEST_F(DistributedDBCloudInterfacesRelationalSyncTest, CloudSyncTest006, TestSize.Level0)
{
    int64_t paddingSize = 10;
    int cloudCount = 20;
    ChangedData changedDataForTable1;
    ChangedData changedDataForTable2;
    changedDataForTable1.tableName = g_tableName1;
    changedDataForTable2.tableName = g_tableName2;
    changedDataForTable1.field.push_back(std::string("name"));
    changedDataForTable2.field.push_back(std::string("id"));
    for (int i = 0; i < cloudCount; i++) {
        changedDataForTable1.primaryData[ChangeType::OP_INSERT].push_back({"Cloud" + std::to_string(i)});
        changedDataForTable2.primaryData[ChangeType::OP_INSERT].push_back({(int64_t)i + 10});
    }
    g_observer->SetExpectedResult(changedDataForTable1);
    g_observer->SetExpectedResult(changedDataForTable2);
    InsertCloudTableRecord(0, cloudCount, paddingSize, false);
    InsertUserTableRecord(db, 0, cloudCount / g_arrayHalfSub, paddingSize, false);
    Query query = Query::Select().FromTable(g_tables);
    std::vector<SyncProcess> expectProcess;
    CloudSyncStatusCallback callback;
    GetCallback(g_syncProcess, callback, expectProcess);
    // Set correct cloudDbSchema (correct version)
    DataBaseSchema correctSchema;
    GetCloudDbSchema(correctSchema);
    ASSERT_EQ(delegate->SetCloudDbSchema(correctSchema), DBStatus::OK);
    ASSERT_EQ(delegate->Sync({DEVICE_CLOUD}, SYNC_MODE_CLOUD_MERGE, query, callback, g_syncWaitTime), DBStatus::OK);
    WaitForSyncFinish(g_syncProcess, g_syncWaitTime);
    EXPECT_TRUE(g_observer->IsAllChangedDataEq());
    g_observer->ClearChangedData();
    LOGD("expect download:worker1[primary key]:[cloud0 - cloud20), worker2[primary key]:[10 - 20)");
    CheckDownloadResult(db, {20L, 10L}); // 20 and 10 means the num of downloads from cloud db by worker1 and worker2
    LOGD("expect upload:worker1[primary key]:[local0 - local10), worker2[primary key]:[0 - 10)");
    CheckCloudTotalCount({30L, 20L}); // 30 and 20 means the total num of worker1 and worker2 from the cloud db

    // Reset cloudDbSchema (invalid version - null)
    DataBaseSchema nullSchema;
    ASSERT_EQ(delegate->SetCloudDbSchema(nullSchema), DBStatus::OK);
    ASSERT_EQ(delegate->Sync({DEVICE_CLOUD}, SYNC_MODE_CLOUD_MERGE, query, callback, g_syncWaitTime),
        DBStatus::SCHEMA_MISMATCH);

    // Reset cloudDbSchema (invalid version - field mismatch)
    DataBaseSchema invalidSchema;
    GetInvalidCloudDbSchema(invalidSchema);
    ASSERT_EQ(delegate->SetCloudDbSchema(invalidSchema), DBStatus::OK);
    ASSERT_EQ(delegate->Sync({DEVICE_CLOUD}, SYNC_MODE_CLOUD_MERGE, query, callback, g_syncWaitTime),
        DBStatus::SCHEMA_MISMATCH);
}

/**
 * @tc.name: CloudSyncTest007
 * @tc.desc: Check the asset types after sync
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: bty
 */
HWTEST_F(DistributedDBCloudInterfacesRelationalSyncTest, CloudSyncTest007, TestSize.Level1)
{
    int64_t paddingSize = 100;
    int localCount = 20;
    InsertUserTableRecord(db, 0, localCount, paddingSize, false);
    InsertCloudTableRecord(0, localCount / g_arrayHalfSub, paddingSize, false);
    Query query = Query::Select().FromTable(g_tables);
    std::vector<SyncProcess> expectProcess;
    CloudSyncStatusCallback callback;
    GetCallback(g_syncProcess, callback, expectProcess);
    ASSERT_EQ(delegate->Sync({DEVICE_CLOUD}, SYNC_MODE_CLOUD_MERGE, query, callback, g_syncWaitTime), DBStatus::OK);
    WaitForSyncFinish(g_syncProcess, g_syncWaitTime);

    CheckAssetAfterDownload(db, localCount);
    CheckAllAssetAfterUpload(localCount);
    CheckAssetsAfterDownload(db, localCount);
}

/*
 * @tc.name: CloudSyncTest008
 * @tc.desc: Test sync with invalid param
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: zhangqiquan
 */
HWTEST_F(DistributedDBCloudInterfacesRelationalSyncTest, CloudSyncTest008, TestSize.Level0)
{
    ASSERT_EQ(delegate->SetCloudDB(nullptr), OK);
    Query query = Query::Select().FromTable({g_tableName3});
    ASSERT_EQ(delegate->Sync({DEVICE_CLOUD}, SYNC_MODE_CLOUD_MERGE, query, nullptr, g_syncWaitTime), CLOUD_ERROR);
}

/**
 * @tc.name: CloudSyncTest009
 * @tc.desc: The second time there was no data change and sync was called.
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: bty
 */
HWTEST_F(DistributedDBCloudInterfacesRelationalSyncTest, CloudSyncTest009, TestSize.Level0)
{
    int64_t paddingSize = 10;
    int cloudCount = 20;
    InsertCloudTableRecord(0, cloudCount, paddingSize, false);
    InsertUserTableRecord(db, 0, cloudCount, paddingSize, false);
    Query query = Query::Select().FromTable(g_tables);
    std::vector<SyncProcess> expectProcess;
    InitProcessForTest1(cloudCount, cloudCount, expectProcess);
    CloudSyncStatusCallback callback;
    GetCallback(g_syncProcess, callback, expectProcess);
    ASSERT_EQ(delegate->Sync({DEVICE_CLOUD}, SYNC_MODE_CLOUD_MERGE, query, callback, g_syncWaitTime), DBStatus::OK);
    WaitForSyncFinish(g_syncProcess, g_syncWaitTime);
    LOGD("expect download:worker1[primary key]:[cloud0 - cloud20), worker2[primary key]:none");
    CheckDownloadResult(db, {20L, 0L}); // 20 and 0 means the num of downloads from cloud db by worker1 and worker2
    LOGD("expect upload:worker1[primary key]:[local0 - local20), worker2[primary key]:[0 - 20)");
    CheckCloudTotalCount({40L, 20L}); // 40 and 20 means the total num of worker1 and worker2 from the cloud db

    g_syncProcess = {};
    InitProcessForTest9(cloudCount, 0, expectProcess);
    GetCallback(g_syncProcess, callback, expectProcess);
    LOGD("--------------the second sync-------------");
    ASSERT_EQ(delegate->Sync({DEVICE_CLOUD}, SYNC_MODE_CLOUD_MERGE, query, callback, g_syncWaitTime), DBStatus::OK);
    WaitForSyncFinish(g_syncProcess, g_syncWaitTime);
}

HWTEST_F(DistributedDBCloudInterfacesRelationalSyncTest, CloudSyncTest0010, TestSize.Level0)
{
    int64_t paddingSize = 10;
    int cloudCount = 20;
    int localCount = 10;
    InsertCloudTableRecord(0, cloudCount, paddingSize, false);
    InsertUserTableRecord(db, 0, localCount, paddingSize, false);
    Query query = Query::Select().FromTable(g_tables);
    std::vector<SyncProcess> expectProcess;
    CloudSyncStatusCallback callback;
    GetCallback(g_syncProcess, callback, expectProcess);
    ASSERT_EQ(delegate->Sync({DEVICE_CLOUD}, SYNC_MODE_CLOUD_MERGE, query, callback, g_syncWaitTime), DBStatus::OK);
    WaitForSyncFinish(g_syncProcess, g_syncWaitTime);

    int rowid = 27;
    UpdateAssetForTest(db, AssetOpType::NO_CHANGE, cloudCount, rowid++);
    UpdateAssetForTest(db, AssetOpType::INSERT, cloudCount, rowid++);
    UpdateAssetForTest(db, AssetOpType::DELETE, cloudCount, rowid++);
    UpdateAssetForTest(db, AssetOpType::UPDATE, cloudCount, rowid++);

    int id = 0;
    UpdateAssetsForTest(db, AssetOpType::NO_CHANGE, id++);
    UpdateAssetsForTest(db, AssetOpType::INSERT, id++);
    UpdateAssetsForTest(db, AssetOpType::DELETE, id++);
    UpdateAssetsForTest(db, AssetOpType::UPDATE, id++);

    g_syncProcess = {};
    GetCallback(g_syncProcess, callback, expectProcess);
    LOGD("--------------the second sync-------------");
    ASSERT_EQ(delegate->Sync({DEVICE_CLOUD}, SYNC_MODE_CLOUD_MERGE, query, callback, g_syncWaitTime), DBStatus::OK);
    WaitForSyncFinish(g_syncProcess, g_syncWaitTime);

    CheckFillAssetForTest10(db);
    CheckFillAssetsForTest10(db);
}

/**
 * @tc.name: CloudSyncTest011
 * @tc.desc: Test sync with same table name.
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: zhangqiquan
 */
HWTEST_F(DistributedDBCloudInterfacesRelationalSyncTest, CloudSyncTest011, TestSize.Level0)
{
    Query query = Query::Select().FromTable({g_tableName1, g_tableName1});
    bool syncFinish = false;
    std::mutex syncMutex;
    std::condition_variable cv;
    std::atomic<int> callCount = 0;
    CloudSyncStatusCallback callback = [&callCount, &cv, &syncFinish, &syncMutex](
        const std::map<std::string, SyncProcess> &onProcess) {
        ASSERT_NE(onProcess.find(DEVICE_CLOUD), onProcess.end());
        SyncProcess syncProcess = onProcess.at(DEVICE_CLOUD);
        callCount++;
        if (syncProcess.process == FINISHED) {
            std::lock_guard<std::mutex> autoLock(syncMutex);
            syncFinish = true;
        }
        cv.notify_all();
    };
    ASSERT_EQ(delegate->Sync({DEVICE_CLOUD}, SYNC_MODE_CLOUD_MERGE, query, callback, g_syncWaitTime), DBStatus::OK);
    std::unique_lock<std::mutex> uniqueLock(syncMutex);
    cv.wait(uniqueLock, [&syncFinish]() {
        return syncFinish;
    });
    RuntimeContext::GetInstance()->StopTaskPool();
    EXPECT_EQ(callCount, 2); // 2 is onProcess count
}

HWTEST_F(DistributedDBCloudInterfacesRelationalSyncTest, CloudSyncTest012, TestSize.Level0)
{
    int64_t localCount = 20;
    int64_t cloudCount = 10;
    int64_t paddingSize = 10;
    InsertCloudTableRecord(0, cloudCount, paddingSize, false);
    InsertUserTableRecord(db, 0, localCount, paddingSize, true);
    Query query = Query::Select().FromTable(g_tables);
    std::vector<SyncProcess> expectProcess;
    CloudSyncStatusCallback callback;
    GetCallback(g_syncProcess, callback, expectProcess);
    ASSERT_EQ(delegate->Sync({DEVICE_CLOUD}, SYNC_MODE_CLOUD_MERGE, query, callback, g_syncWaitTime), DBStatus::OK);
    WaitForSyncFinish(g_syncProcess, g_syncWaitTime);

    InsertCloudTableRecord(localCount + cloudCount, cloudCount, paddingSize, false);
    InsertUserTableRecord(db, localCount + cloudCount, localCount, paddingSize, true);
    g_syncProcess = {};
    GetCallback(g_syncProcess, callback, expectProcess);
    ASSERT_EQ(delegate->Sync({DEVICE_CLOUD}, SYNC_MODE_CLOUD_MERGE, query, callback, g_syncWaitTime), DBStatus::OK);
    WaitForSyncFinish(g_syncProcess, g_syncWaitTime);

    InsertCloudTableRecord(2 * (localCount + cloudCount), cloudCount, paddingSize, false); // 2 is offset
    InsertUserTableRecord(db, 2 * (localCount + cloudCount), localCount, paddingSize, false); // 2 is offset
    g_syncProcess = {};
    GetCallback(g_syncProcess, callback, expectProcess);
    ASSERT_EQ(delegate->Sync({DEVICE_CLOUD}, SYNC_MODE_CLOUD_MERGE, query, callback, g_syncWaitTime), DBStatus::OK);
    WaitForSyncFinish(g_syncProcess, g_syncWaitTime);


    InsertCloudTableRecord(3 * (localCount + cloudCount), cloudCount, paddingSize, true); // 3 is offset
    InsertUserTableRecord(db, 3 * (localCount + cloudCount), localCount, paddingSize, true); // 3 is offset
    g_syncProcess = {};
    GetCallback(g_syncProcess, callback, expectProcess);
    ASSERT_EQ(delegate->Sync({DEVICE_CLOUD}, SYNC_MODE_CLOUD_MERGE, query, callback, g_syncWaitTime), DBStatus::OK);
    WaitForSyncFinish(g_syncProcess, g_syncWaitTime);
}

/*
 * @tc.name: CloudSyncTest013
 * @tc.desc: test increment watermark when cloud db query data size is 0
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: zhuwentao
 */
HWTEST_F(DistributedDBCloudInterfacesRelationalSyncTest, CloudSyncTest013, TestSize.Level0)
{
    /**
     * @tc.steps: insert some data into cloud db
     * @tc.expected: return ok.
     */
    int64_t paddingSize = 10;
    int64_t cloudCount = 10;
    SyncProcess syncProcess;
    InsertCloudTableRecord(0, cloudCount, paddingSize, true);
    /**
     * @tc.steps: try to cloud sync
     * @tc.expected: return ok.
     */
    Query query = Query::Select().FromTable(g_tables);
    CloudSyncStatusCallback callback = [&syncProcess](const std::map<std::string, SyncProcess> &process) {
        LOGI("devices size = %d", process.size());
        ASSERT_EQ(process.size(), 1u);
        syncProcess = std::move(process.begin()->second);
        if (syncProcess.process == FINISHED) {
            g_processCondition.notify_one();
        }
    };
    ASSERT_EQ(delegate->Sync({DEVICE_CLOUD}, SYNC_MODE_CLOUD_MERGE, query, callback, g_syncWaitTime), DBStatus::OK);
    WaitForSyncFinish(syncProcess, g_syncWaitTime);
    uint32_t queryTimes = g_virtualCloudDb->GetQueryTimes(g_tableName1);
    /**
     * @tc.steps: insert some increment data into cloud db
     * @tc.expected: return ok.
     */
    VBucket data;
    Timestamp now = TimeHelper::GetSysCurrentTime();
    data.insert_or_assign("name", "Cloud" + std::to_string(0));
    data.insert_or_assign("height", 166.0); // 166.0 is random double value
    data.insert_or_assign("married", false);
    data.insert_or_assign("age", 13L);
    VBucket log;
    log.insert_or_assign(CloudDbConstant::CREATE_FIELD, (int64_t)now / CloudDbConstant::TEN_THOUSAND);
    log.insert_or_assign(CloudDbConstant::MODIFY_FIELD, (int64_t)now / CloudDbConstant::TEN_THOUSAND);
    log.insert_or_assign(CloudDbConstant::DELETE_FIELD, false);
    log.insert_or_assign(CloudDbConstant::CREATE_FIELD, (int64_t)now / CloudDbConstant::TEN_THOUSAND);
    log.insert_or_assign(CloudDbConstant::CURSOR_FIELD, "0123");
    g_virtualCloudDb->SetIncrementData(g_tableName1, data, log);
    syncProcess.process = PREPARED;
    ASSERT_EQ(delegate->Sync({DEVICE_CLOUD}, SYNC_MODE_CLOUD_MERGE, query, callback, g_syncWaitTime), DBStatus::OK);
    WaitForSyncFinish(syncProcess, g_syncWaitTime);
    uint32_t lastQueryTimes = g_virtualCloudDb->GetQueryTimes(g_tableName1);
    ASSERT_EQ(lastQueryTimes - queryTimes, 2u);
}

/*
 * @tc.name: DataNotifier001
 * @tc.desc: Notify data without primary key
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: wanyi
 */
HWTEST_F(DistributedDBCloudInterfacesRelationalSyncTest, DataNotifier001, TestSize.Level0)
{
    int64_t paddingSize = 10;
    int localCount = 20;
    InsertRecordWithoutPk2LocalAndCloud(db, 0, localCount, paddingSize);
    Query query = Query::Select().FromTable({g_tableName3});
    std::vector<SyncProcess> expectProcess;
    CloudSyncStatusCallback callback;
    GetCallback(g_syncProcess, callback, expectProcess);
    ASSERT_EQ(delegate->Sync({DEVICE_CLOUD}, SYNC_MODE_CLOUD_MERGE, query, callback, g_syncWaitTime), DBStatus::OK);
    WaitForSyncFinish(g_syncProcess, g_syncWaitTime);
}

/**
 * @tc.name: CloudSyncAssetTest001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: wanyi
 */
HWTEST_F(DistributedDBCloudInterfacesRelationalSyncTest, CloudSyncAssetTest001, TestSize.Level1)
{
    int64_t paddingSize = 100;
    int localCount = 20;
    InsertUserTableRecord(db, 0, localCount, paddingSize, false);
    InsertCloudTableRecord(0, localCount / g_arrayHalfSub, paddingSize, false);
    Query query = Query::Select().FromTable(g_tables);
    std::vector<SyncProcess> expectProcess;
    CloudSyncStatusCallback callback;
    GetCallback(g_syncProcess, callback, expectProcess);
    ASSERT_EQ(delegate->Sync({DEVICE_CLOUD}, SYNC_MODE_CLOUD_MERGE, query, callback, g_syncWaitTime), DBStatus::OK);
    WaitForSyncFinish(g_syncProcess, g_syncWaitTime);

    CheckAssetAfterDownload(db, localCount);
    CheckAllAssetAfterUpload(localCount);
}

/*
 * @tc.name: MannualNotify001
 * @tc.desc: Test FLAG_ONLY mode of RemoveDeviceData
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: huangboxin
 */
HWTEST_F(DistributedDBCloudInterfacesRelationalSyncTest, MannualNotify001, TestSize.Level0)
{
    int64_t paddingSize = 10;
    int localCount = 10;
    InsertUserTableRecord(db, 0, localCount, paddingSize, false);
    Query query = Query::Select().FromTable(g_tables);
    std::vector<SyncProcess> expectProcess;
    InitProcessForMannualSync1(expectProcess);
    CloudSyncStatusCallback callback;
    GetCallback(g_syncProcess, callback, expectProcess);
    ASSERT_EQ(delegate->Sync({DEVICE_CLOUD}, SYNC_MODE_CLOUD_FORCE_PULL, query, callback, g_syncWaitTime),
        DBStatus::OK);
    WaitForSyncFinish(g_syncProcess, g_syncWaitTime);
}
/*
 * @tc.name: CleanCloudDataTest001
 * @tc.desc: Test FLAG_ONLY mode of RemoveDeviceData
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: huangboxin
 */
HWTEST_F(DistributedDBCloudInterfacesRelationalSyncTest, CleanCloudDataTest001, TestSize.Level0)
{
    int64_t paddingSize = 10;
    int localCount = 10;
    int cloudCount = 20;
    InsertCloudTableRecord(0, cloudCount, paddingSize, false);
    InsertUserTableRecord(db, 0, localCount, paddingSize, false);
    Query query = Query::Select().FromTable(g_tables);
    std::vector<SyncProcess> expectProcess;
    InitProcessForCleanCloudData1(cloudCount, localCount, expectProcess);
    CloudSyncStatusCallback callback;
    GetCallback(g_syncProcess, callback, expectProcess);
    ASSERT_EQ(delegate->Sync({DEVICE_CLOUD}, SYNC_MODE_CLOUD_FORCE_PULL, query, callback, g_syncWaitTime),
        DBStatus::OK);
    WaitForSyncFinish(g_syncProcess, g_syncWaitTime);
    std::string device = "";
    CheckCloudRecordNum(db, g_tables, {20, 20});
    ASSERT_EQ(delegate->RemoveDeviceData(device, FLAG_ONLY), DBStatus::OK);
    CheckCleanLogNum(db, g_tables, 0);
}

/*
 * @tc.name: CleanCloudDataTest002
 * @tc.desc: Test FLAG_AND_DATA mode of RemoveDeviceData
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: huangboxin
 */
HWTEST_F(DistributedDBCloudInterfacesRelationalSyncTest, CleanCloudDataTest002, TestSize.Level0)
{
    int64_t paddingSize = 10;
    int localCount = 10;
    int cloudCount = 20;
    InsertCloudTableRecord(0, cloudCount, paddingSize, false);
    InsertUserTableRecord(db, 0, localCount, paddingSize, false);
    Query query = Query::Select().FromTable(g_tables);
    std::vector<SyncProcess> expectProcess;
    InitProcessForCleanCloudData1(cloudCount, localCount, expectProcess);
    CloudSyncStatusCallback callback;
    GetCallback(g_syncProcess, callback, expectProcess);
    ASSERT_EQ(delegate->Sync({DEVICE_CLOUD}, SYNC_MODE_CLOUD_FORCE_PULL, query, callback, g_syncWaitTime),
        DBStatus::OK);
    WaitForSyncFinish(g_syncProcess, g_syncWaitTime);
    std::string device = "";
    CheckCloudRecordNum(db, g_tables, {20, 20});    // 20 means cloud data num
    ASSERT_EQ(delegate->RemoveDeviceData(device, FLAG_AND_DATA), DBStatus::OK);
    CheckCleanDataAndLogNum(db, g_tables, 0, {localCount, 0});
}

/*
 * @tc.name: CalPrimaryKeyHash001
 * @tc.desc: Test CalcPrimaryKeyHash interface when primary key is string
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: zhuwentao
 */
HWTEST_F(DistributedDBCloudInterfacesRelationalSyncTest, CalPrimaryKeyHash001, TestSize.Level0)
{
   /**
     * @tc.steps: step1. local insert one data, primary key is string
     * @tc.expected: OK.
     */
    std::string photo(1u, 'v');
    std::string name = "Local0";
    std::map<std::string, Type> primaryKey = {{"name", name}};
    string sql = "INSERT OR REPLACE INTO " + g_tableName1
        + " (name, height, married, photo, age) VALUES ('Local" + std::to_string(0) +
        "', '175.8', '0', '" + photo + "', '18');";
    EXPECT_EQ(RelationalTestUtils::ExecSql(db, sql), SQLITE_OK);
    std::vector<uint8_t> result = RelationalStoreManager::CalcPrimaryKeyHash(primaryKey);
    EXPECT_NE(result.size(), 0u);
    std::string logTableName = RelationalStoreManager::GetDistributedLogTableName(g_tableName1);
   /**
     * @tc.steps: step1. query timestamp use hashKey
     * @tc.expected: OK.
     */
    std::string querysql = "select timestamp/10000 from " + logTableName + " where hash_key=?";
    sqlite3_stmt *statement = nullptr;
    int errCode = SQLiteUtils::GetStatement(db, querysql, statement);
    EXPECT_EQ(errCode, E_OK);
    errCode = SQLiteUtils::BindBlobToStatement(statement, 1, result); // 1 means hashkey index
    if (errCode != E_OK) {
        SQLiteUtils::ResetStatement(statement, true, errCode);
        return;
    }
    errCode = SQLiteUtils::StepWithRetry(statement, false);
    if (errCode == SQLiteUtils::MapSQLiteErrno(SQLITE_ROW)) {
        Timestamp timestamp = static_cast<Timestamp>(sqlite3_column_int64(statement, 0));
        LOGD("get timestamp = %" PRIu64, timestamp);
        errCode = E_OK;
    } else if (errCode == SQLiteUtils::MapSQLiteErrno(SQLITE_DONE)) {
        errCode = -E_NOT_FOUND;
    }
    EXPECT_EQ(errCode, E_OK);
    SQLiteUtils::ResetStatement(statement, true, errCode);
}

/*
 * @tc.name: CalPrimaryKeyHash002
 * @tc.desc: Test CalcPrimaryKeyHash interface when primary key is int
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: zhuwentao
 */
HWTEST_F(DistributedDBCloudInterfacesRelationalSyncTest, CalPrimaryKeyHash002, TestSize.Level0)
{
   /**
     * @tc.steps: step1. local insert one data, primary key is int
     * @tc.expected: OK.
     */
    int64_t id = 1;
    std::map<std::string, Type> primaryKey = {{"id", id}};
    std::string sql = "INSERT OR REPLACE INTO " + g_tableName2
        + " (id, name, height) VALUES ('" + '1' + "', 'Local"
        + std::to_string(0) + "', '155.10');";
    EXPECT_EQ(RelationalTestUtils::ExecSql(db, sql), SQLITE_OK);
    std::vector<uint8_t> result = RelationalStoreManager::CalcPrimaryKeyHash(primaryKey);
    EXPECT_NE(result.size(), 0u);
    std::string logTableName = RelationalStoreManager::GetDistributedLogTableName(g_tableName2);
   /**
     * @tc.steps: step1. query timestamp use hashKey
     * @tc.expected: OK.
     */
    std::string querysql = "select timestamp/10000 from " + logTableName + " where hash_key=?";
    sqlite3_stmt *statement = nullptr;
    int errCode = SQLiteUtils::GetStatement(db, querysql, statement);
    EXPECT_EQ(errCode, E_OK);
    errCode = SQLiteUtils::BindBlobToStatement(statement, 1, result); // 1 means hashkey index
    if (errCode != E_OK) {
        SQLiteUtils::ResetStatement(statement, true, errCode);
        return;
    }
    errCode = SQLiteUtils::StepWithRetry(statement, false);
    if (errCode == SQLiteUtils::MapSQLiteErrno(SQLITE_ROW)) {
        Timestamp timestamp = static_cast<Timestamp>(sqlite3_column_int64(statement, 0));
        LOGD("get timestamp = %" PRIu64, timestamp);
        errCode = E_OK;
    } else if (errCode == SQLiteUtils::MapSQLiteErrno(SQLITE_DONE)) {
        errCode = -E_NOT_FOUND;
    }
    EXPECT_EQ(errCode, E_OK);
    SQLiteUtils::ResetStatement(statement, true, errCode);
}

/*
 * @tc.name: CloudSyncAssetTest002
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: huangboxin
 */
HWTEST_F(DistributedDBCloudInterfacesRelationalSyncTest, CloudSyncAssetTest002, TestSize.Level0)
{
    int64_t paddingSize = 10;
    int localCount = 3;
    int cloudCount = 3;
    InsertCloudTableRecord(0, cloudCount, paddingSize, true);
    InsertUserTableRecord(db, 0, localCount, paddingSize, false);
    Query query = Query::Select().FromTable(g_tables);
    std::vector<SyncProcess> expectProcess;
    CloudSyncStatusCallback callback;
    GetCallback(g_syncProcess, callback, expectProcess);
    ASSERT_EQ(delegate->Sync({DEVICE_CLOUD}, SYNC_MODE_CLOUD_FORCE_PUSH, query, callback, g_syncWaitTime),
        DBStatus::OK);
    WaitForSyncFinish(g_syncProcess, g_syncWaitTime);
}
}
#endif // RELATIONAL_STORE
