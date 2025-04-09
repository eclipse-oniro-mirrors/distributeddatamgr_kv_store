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
#include "cloud/cloud_db_constant.h"
#include "cloud/cloud_db_types.h"
#include "distributeddb_data_generate_unit_test.h"
#include "log_print.h"
#include "relational_store_delegate.h"
#include "relational_store_manager.h"
#include "runtime_config.h"
#include "time_helper.h"
#include "virtual_asset_loader.h"
#include "virtual_cloud_data_translate.h"
#include "virtual_cloud_db.h"
#include "virtual_communicator_aggregator.h"
#include "sqlite_relational_utils.h"
#include "cloud/cloud_storage_utils.h"
#include "cloud_db_sync_utils_test.h"

namespace {
using namespace testing::ext;
using namespace DistributedDB;
using namespace DistributedDBUnitTest;
const char *g_createSQL =
    "CREATE TABLE IF NOT EXISTS DistributedDBCloudAssetsOperationSyncTest(" \
    "id TEXT PRIMARY KEY," \
    "name TEXT," \
    "height REAL ," \
    "photo BLOB," \
    "asset ASSET," \
    "assets ASSETS," \
    "age INT);";
const int64_t g_syncWaitTime = 60;
const int g_assetsNum = 3;
const Asset g_localAsset = {
    .version = 2, .name = "Phone", .assetId = "0", .subpath = "/local/sync", .uri = "/cloud/sync",
    .modifyTime = "123456", .createTime = "0", .size = "1024", .hash = "DEC"
};
SyncProcess lastProcess_;

void CreateUserDBAndTable(sqlite3 *&db)
{
    EXPECT_EQ(RelationalTestUtils::ExecSql(db, "PRAGMA journal_mode=WAL;"), SQLITE_OK);
    EXPECT_EQ(RelationalTestUtils::ExecSql(db, g_createSQL), SQLITE_OK);
}

void BlockSync(const Query &query, RelationalStoreDelegate *delegate, SyncMode syncMode = SYNC_MODE_CLOUD_MERGE)
{
    std::mutex dataMutex;
    std::condition_variable cv;
    bool finish = false;
    SyncProcess last;
    auto callback = [&last, &cv, &dataMutex, &finish](const std::map<std::string, SyncProcess> &process) {
        for (const auto &item: process) {
            if (item.second.process == DistributedDB::FINISHED) {
                {
                    std::lock_guard<std::mutex> autoLock(dataMutex);
                    finish = true;
                }
                last = item.second;
                cv.notify_one();
            }
        }
    };
    LOGW("begin call sync");
    ASSERT_EQ(delegate->Sync({ "CLOUD" }, syncMode, query, callback, g_syncWaitTime), OK);
    std::unique_lock<std::mutex> uniqueLock(dataMutex);
    cv.wait(uniqueLock, [&finish]() {
        return finish;
    });
    lastProcess_ = last;
    LOGW("end call sync");
}

class  DistributedDBCloudAssetsOperationSyncTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
    void WriteDataWithoutCommitTransaction();
protected:
    void InitTestDir();
    DataBaseSchema GetSchema();
    void CloseDb();
    void InsertUserTableRecord(const std::string &tableName, int64_t begin, int64_t count, size_t assetCount = 2u,
        const Assets &templateAsset = {});
    void UpdateLocalTableRecord(const std::string &tableName, int64_t begin, int64_t count, size_t assetCount = 2u,
        bool updateAssets = true);
    void UpdateLocalAssetRecord(const std::string &tableName, int64_t begin, int64_t count);
    void CheckAssetsCount(const std::vector<size_t> &expectCount, bool checkAsset = false);
    void UpdateCloudTableRecord(int64_t begin, int64_t count, bool assetIsNull);
    void ForkDownloadAndRemoveAsset(DBStatus removeStatus, int &downLoadCount, int &removeCount);
    void InsertLocalAssetData(const std::string &assetHash);
    void InsertCloudAssetData(const std::string &assetHash);
    void PrepareForAssetOperation010();
    void UpdateAssetWhenSyncUpload();
    DBStatus InsertRecordToCloud(const std::vector<VBucket> &record);
    void PrepareDataInCloud();
    void LocalAssetRemoveTest();

    static std::vector<Asset> GetAssets(const std::string &baseName, const Assets &templateAsset, size_t assetCount);
    static std::vector<VBucket> GenerateAssetsRecords(const std::map<std::string, int32_t> &colType,
        const Asset &templateAsset, int assetsCount, int rowCount);
    static Asset GenerateAsset(const Asset &templateAsset, int id);
    static Assets GenerateAssets(const Asset &templateAsset, int id, int assetsCount);
    std::string testDir_;
    std::string storePath_;
    sqlite3 *db_ = nullptr;
    RelationalStoreDelegate *delegate_ = nullptr;
    std::shared_ptr<VirtualCloudDb> virtualCloudDb_ = nullptr;
    std::shared_ptr<VirtualAssetLoader> virtualAssetLoader_ = nullptr;
    std::shared_ptr<VirtualCloudDataTranslate> virtualTranslator_ = nullptr;
    std::shared_ptr<RelationalStoreManager> mgr_ = nullptr;
    std::string tableName_ = "DistributedDBCloudAssetsOperationSyncTest";
    VirtualCommunicatorAggregator *communicatorAggregator_ = nullptr;
    TrackerSchema trackerSchema = {
        .tableName = tableName_, .extendColNames = {"name"}, .trackerColNames = {"age"}
    };
};

void DistributedDBCloudAssetsOperationSyncTest::SetUpTestCase()
{
    RuntimeConfig::SetCloudTranslate(std::make_shared<VirtualCloudDataTranslate>());
}

void DistributedDBCloudAssetsOperationSyncTest::TearDownTestCase()
{}

void DistributedDBCloudAssetsOperationSyncTest::SetUp()
{
    DistributedDBToolsUnitTest::PrintTestCaseInfo();
    RuntimeContext::GetInstance()->SetBatchDownloadAssets(false);
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
    ASSERT_EQ(delegate_->CreateDistributedTable(tableName_, CLOUD_COOPERATION), DBStatus::OK);
    ASSERT_EQ(delegate_->SetTrackerTable(trackerSchema), DBStatus::OK);
    virtualCloudDb_ = std::make_shared<VirtualCloudDb>();
    virtualAssetLoader_ = std::make_shared<VirtualAssetLoader>();
    ASSERT_EQ(delegate_->SetCloudDB(virtualCloudDb_), DBStatus::OK);
    ASSERT_EQ(delegate_->SetIAssetLoader(virtualAssetLoader_), DBStatus::OK);
    virtualTranslator_ = std::make_shared<VirtualCloudDataTranslate>();
    DataBaseSchema dataBaseSchema = GetSchema();
    ASSERT_EQ(delegate_->SetCloudDbSchema(dataBaseSchema), DBStatus::OK);
    communicatorAggregator_ = new (std::nothrow) VirtualCommunicatorAggregator();
    ASSERT_TRUE(communicatorAggregator_ != nullptr);
    RuntimeContext::GetInstance()->SetCommunicatorAggregator(communicatorAggregator_);
}

void DistributedDBCloudAssetsOperationSyncTest::TearDown()
{
    CloseDb();
    EXPECT_EQ(sqlite3_close_v2(db_), SQLITE_OK);
    if (DistributedDBToolsUnitTest::RemoveTestDbFiles(testDir_) != E_OK) {
        LOGE("rm test db files error.");
    }
    RuntimeContext::GetInstance()->SetCommunicatorAggregator(nullptr);
    communicatorAggregator_ = nullptr;
    RuntimeContext::GetInstance()->SetProcessSystemApiAdapter(nullptr);
}

void DistributedDBCloudAssetsOperationSyncTest::InitTestDir()
{
    if (!testDir_.empty()) {
        return;
    }
    DistributedDBToolsUnitTest::TestDirInit(testDir_);
    storePath_ = testDir_ + "/" + STORE_ID_1 + ".db";
    LOGI("The test db is:%s", testDir_.c_str());
}

DataBaseSchema DistributedDBCloudAssetsOperationSyncTest::GetSchema()
{
    DataBaseSchema schema;
    TableSchema tableSchema;
    tableSchema.name = tableName_;
    tableSchema.sharedTableName = tableName_ + "_shared";
    tableSchema.fields = {
        {"id", TYPE_INDEX<std::string>, true}, {"name", TYPE_INDEX<std::string>}, {"height", TYPE_INDEX<double>},
        {"photo", TYPE_INDEX<Bytes>}, {"asset", TYPE_INDEX<Asset>}, {"assets", TYPE_INDEX<Assets>},
        {"age", TYPE_INDEX<int64_t>}
    };
    schema.tables.push_back(tableSchema);
    return schema;
}

void DistributedDBCloudAssetsOperationSyncTest::CloseDb()
{
    virtualCloudDb_->ForkUpload(nullptr);
    virtualCloudDb_ = nullptr;
    EXPECT_EQ(mgr_->CloseStore(delegate_), DBStatus::OK);
    delegate_ = nullptr;
    mgr_ = nullptr;
}

void DistributedDBCloudAssetsOperationSyncTest::InsertUserTableRecord(const std::string &tableName, int64_t begin,
    int64_t count, size_t assetCount, const Assets &templateAsset)
{
    std::string photo = "phone";
    int errCode;
    std::vector<uint8_t> assetBlob;
    std::vector<uint8_t> assetsBlob;
    const int64_t index2 = 2;
    for (int64_t i = begin; i < begin + count; ++i) {
        std::string name = g_localAsset.name + std::to_string(i);
        Asset asset = g_localAsset;
        asset.name = name;
        RuntimeContext::GetInstance()->AssetToBlob(asset, assetBlob);
        std::vector<Asset> assets = GetAssets(name, templateAsset, assetCount);
        string sql = "INSERT OR REPLACE INTO " + tableName +
            " (id, name, height, photo, asset, assets, age) VALUES ('" + std::to_string(i) +
            "', 'local', '178.0', '" + photo + "', ?, ?, '18');";
        sqlite3_stmt *stmt = nullptr;
        ASSERT_EQ(SQLiteUtils::GetStatement(db_, sql, stmt), E_OK);
        RuntimeContext::GetInstance()->AssetsToBlob(assets, assetsBlob);
        ASSERT_EQ(SQLiteUtils::BindBlobToStatement(stmt, 1, assetBlob, false), E_OK);
        ASSERT_EQ(SQLiteUtils::BindBlobToStatement(stmt, index2, assetsBlob, false), E_OK);
        EXPECT_EQ(SQLiteUtils::StepWithRetry(stmt), SQLiteUtils::MapSQLiteErrno(SQLITE_DONE));
        SQLiteUtils::ResetStatement(stmt, true, errCode);
    }
}

void DistributedDBCloudAssetsOperationSyncTest::UpdateLocalTableRecord(const std::string &tableName, int64_t begin,
    int64_t count, size_t assetCount, bool updateAssets)
{
    int errCode;
    std::vector<uint8_t> assetBlob;
    std::vector<uint8_t> assetsBlob;
    std::string hash = updateAssets ? "new_hash" : g_localAsset.hash;
    for (int64_t i = begin; i < begin + count; ++i) {
        std::string name = g_localAsset.name + std::to_string(i);
        Asset asset = g_localAsset;
        asset.name = name;
        asset.hash = hash;
        RuntimeContext::GetInstance()->AssetToBlob(asset, assetBlob);
        std::vector<Asset> assets = GetAssets(name, {}, assetCount);
        RuntimeContext::GetInstance()->AssetsToBlob(assets, assetsBlob);
        std::string dataName = "new_name_" + std::to_string(i);
        std::string sql = "UPDATE " + tableName + " SET name = ?, asset = ?, assets = ? where id = " +
            std::to_string(i);
        sqlite3_stmt *stmt = nullptr;
        ASSERT_EQ(SQLiteUtils::GetStatement(db_, sql, stmt), E_OK);
        ASSERT_EQ(SQLiteUtils::BindTextToStatement(stmt, 1, dataName), E_OK); // 1st bind
        ASSERT_EQ(SQLiteUtils::BindBlobToStatement(stmt, 2, assetBlob, false), E_OK); // 2nd bind
        ASSERT_EQ(SQLiteUtils::BindBlobToStatement(stmt, 3, assetsBlob, false), E_OK); // 3rd bind
        EXPECT_EQ(SQLiteUtils::StepWithRetry(stmt), SQLiteUtils::MapSQLiteErrno(SQLITE_DONE));
        SQLiteUtils::ResetStatement(stmt, true, errCode);
    }
}

DBStatus DistributedDBCloudAssetsOperationSyncTest::InsertRecordToCloud(const std::vector<VBucket> &record)
{
    std::vector<VBucket> extend;
    for (size_t i = 0; i < record.size(); ++i) {
        VBucket log;
        Timestamp now = TimeHelper::GetSysCurrentTime();
        log.insert_or_assign(CloudDbConstant::CREATE_FIELD, static_cast<int64_t>(
                now / CloudDbConstant::TEN_THOUSAND));
        log.insert_or_assign(CloudDbConstant::MODIFY_FIELD, static_cast<int64_t>(
                now / CloudDbConstant::TEN_THOUSAND));
        log.insert_or_assign(CloudDbConstant::DELETE_FIELD, false);
        extend.push_back(log);
    }
    std::vector<VBucket> copyRecord = record;
    return virtualCloudDb_->BatchInsert(tableName_, std::move(copyRecord), extend);
}

void DistributedDBCloudAssetsOperationSyncTest::PrepareDataInCloud()
{
    std::map<std::string, int32_t> colType;
    colType["asset"] = TYPE_INDEX<Asset>;
    colType["assets"] = TYPE_INDEX<Assets>;
    Asset templateAsset = g_localAsset;
    const int assetsCount = 10;
    const int rowCount = 200;
    auto recordAssets = GenerateAssetsRecords(colType, templateAsset, assetsCount, rowCount);
    EXPECT_EQ(InsertRecordToCloud(recordAssets), OK);
}

std::vector<Asset> DistributedDBCloudAssetsOperationSyncTest::GetAssets(const std::string &baseName,
    const Assets &templateAsset, size_t assetCount)
{
    std::vector<Asset> assets;
    for (size_t i = 1; i <= assetCount; ++i) {
        Asset asset;
        if (i - 1 < templateAsset.size()) {
            asset = templateAsset[i - 1];
        } else {
            asset = g_localAsset;
            asset.name = baseName + "_" + std::to_string(i);
            asset.status = static_cast<uint32_t>(AssetStatus::INSERT);
        }
        assets.push_back(asset);
    }
    return assets;
}

void DistributedDBCloudAssetsOperationSyncTest::UpdateCloudTableRecord(int64_t begin, int64_t count, bool assetIsNull)
{
    std::vector<VBucket> record;
    std::vector<VBucket> extend;
    Timestamp now = TimeHelper::GetSysCurrentTime();
    const int assetCount = 2;
    for (int64_t i = begin; i < (begin + count); ++i) {
        VBucket data;
        data.insert_or_assign("id", std::to_string(i));
        data.insert_or_assign("name", "Cloud" + std::to_string(i));
        Assets assets;
        for (int j = 1; j <= assetCount; ++j) {
            Asset asset;
            asset.name = "Phone_" + std::to_string(j);
            asset.assetId = std::to_string(j);
            asset.status = AssetStatus::UPDATE;
            assets.push_back(asset);
        }
        assetIsNull ? data.insert_or_assign("assets", Nil()) : data.insert_or_assign("assets", assets);
        record.push_back(data);
        VBucket log;
        log.insert_or_assign(CloudDbConstant::CREATE_FIELD, static_cast<int64_t>(
            now / CloudDbConstant::TEN_THOUSAND));
        log.insert_or_assign(CloudDbConstant::MODIFY_FIELD, static_cast<int64_t>(
            now / CloudDbConstant::TEN_THOUSAND));
        log.insert_or_assign(CloudDbConstant::DELETE_FIELD, false);
        log.insert_or_assign(CloudDbConstant::GID_FIELD, std::to_string(i));
        extend.push_back(log);
    }

    ASSERT_EQ(virtualCloudDb_->BatchUpdate(tableName_, std::move(record), extend), DBStatus::OK);
}

void DistributedDBCloudAssetsOperationSyncTest::CheckAssetsCount(const std::vector<size_t> &expectCount,
    bool checkAsset)
{
    std::vector<VBucket> allData;
    auto dbSchema = GetSchema();
    ASSERT_GT(dbSchema.tables.size(), 0u);
    ASSERT_EQ(RelationalTestUtils::SelectData(db_, dbSchema.tables[0], allData), E_OK);
    int index = 0;
    ASSERT_EQ(allData.size(), expectCount.size());
    for (const auto &data : allData) {
        auto colIter = data.find("assets");
        EXPECT_NE(colIter, data.end());
        if (colIter == data.end()) {
            index++;
            continue;
        }
        Type colValue = data.at("assets");
        auto translate = std::dynamic_pointer_cast<ICloudDataTranslate>(virtualTranslator_);
        auto assets = RelationalTestUtils::GetAssets(colValue, translate);
        size_t size = assets.size();
        if (checkAsset) {
            Type colValue1 = data.at("asset");
            auto assets1 = RelationalTestUtils::GetAssets(colValue1, translate, true);
            size += assets1.size();
        }
        LOGI("[DistributedDBCloudAssetsOperationSyncTest] Check data index %d", index);
        EXPECT_EQ(static_cast<size_t>(size), expectCount[index]);
        for (const auto &item : assets) {
            LOGI("[DistributedDBCloudAssetsOperationSyncTest] Asset name %s status %" PRIu32, item.name.c_str(),
                item.status);
        }
        index++;
    }
}

void DistributedDBCloudAssetsOperationSyncTest::ForkDownloadAndRemoveAsset(DBStatus removeStatus, int &downLoadCount,
    int &removeCount)
{
    virtualAssetLoader_->ForkDownload([this, &downLoadCount](const std::string &tableName,
        std::map<std::string, Assets> &assets) {
        downLoadCount++;
        if (downLoadCount == 1) {
            std::string sql = "UPDATE " + tableName_ + " SET assets = NULL WHERE id = 0;";
            ASSERT_EQ(RelationalTestUtils::ExecSql(db_, sql), SQLITE_OK);
        }
    });
    virtualAssetLoader_->ForkRemoveLocalAssets([removeStatus, &removeCount](const std::vector<Asset> &assets) {
        EXPECT_EQ(assets.size(), 2u); // one record has 2 asset
        removeCount++;
        return removeStatus;
    });
}

std::vector<VBucket> DistributedDBCloudAssetsOperationSyncTest::GenerateAssetsRecords(
    const std::map<std::string, int32_t> &colType, const Asset &templateAsset, int assetsCount, int rowCount)
{
    std::vector<VBucket> res;
    for (int i = 0; i < rowCount; ++i) {
        VBucket record;
        record["id"] = std::to_string(i);
        for (const auto &[col, type] : colType) {
            if (type == TYPE_INDEX<Asset>) {
                record[col] = GenerateAsset(templateAsset, i);
            } else if (type == TYPE_INDEX<Assets>) {
                record[col] = GenerateAssets(templateAsset, i, assetsCount);
            }
        }
        res.push_back(record);
    }
    return res;
}

Asset DistributedDBCloudAssetsOperationSyncTest::GenerateAsset(const Asset &templateAsset, int id)
{
    Asset res = templateAsset;
    res.name.append("_").append(std::to_string(id));
    res.hash.append("_").append(std::to_string(id));
    return res;
}

Assets DistributedDBCloudAssetsOperationSyncTest::GenerateAssets(const Asset &templateAsset, int id, int assetsCount)
{
    Assets assets;
    auto baseAsset = GenerateAsset(templateAsset, id);
    for (int i = 0; i < assetsCount; ++i) {
        assets.push_back(GenerateAsset(baseAsset, i));
    }
    return assets;
}

/**
 * @tc.name: SyncWithAssetOperation001
 * @tc.desc: Delete Assets When Download
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: zhangqiquan
 */
HWTEST_F(DistributedDBCloudAssetsOperationSyncTest, SyncWithAssetOperation001, TestSize.Level0)
{
    const int actualCount = 10;
    const int deleteDataCount = 5;
    const int deleteAssetsCount = 4;
    InsertUserTableRecord(tableName_, 0, actualCount);
    std::string tableName = tableName_;
    virtualCloudDb_->ForkUpload([this, deleteDataCount, deleteAssetsCount](const std::string &, VBucket &) {
        for (int64_t i = 0; i < deleteDataCount; i++) {
            std::string sql = "DELETE FROM " + tableName_ + " WHERE id = " + std::to_string(i) + ";";
            ASSERT_EQ(RelationalTestUtils::ExecSql(db_, sql), SQLITE_OK);
        }
        for (int64_t i = deleteDataCount; i < deleteDataCount + deleteAssetsCount; i++) {
            std::string sql = "UPDATE " + tableName_ + " SET asset = NULL, assets = NULL WHERE id = " +
                std::to_string(i) + ";";
            ASSERT_EQ(RelationalTestUtils::ExecSql(db_, sql), SQLITE_OK);
        }
    });
    Query query = Query::Select().FromTable({ tableName_ });
    BlockSync(query, delegate_);
    virtualCloudDb_->ForkUpload(nullptr);
    std::vector<size_t> expectCount(actualCount - deleteDataCount, 0);
    expectCount[expectCount.size() - 1] = 2; // default one row has 2 assets
    CheckAssetsCount(expectCount);
}

/**
 * @tc.name: SyncWithAssetOperation002
 * @tc.desc: Download Assets When local assets was removed
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: zhangqiquan
 */
HWTEST_F(DistributedDBCloudAssetsOperationSyncTest, SyncWithAssetOperation002, TestSize.Level0)
{
    const int actualCount = 1;
    InsertUserTableRecord(tableName_, 0, actualCount);
    Query query = Query::Select().FromTable({ tableName_ });
    BlockSync(query, delegate_);
    int downLoadCount = 0;
    int removeCount = 0;
    ForkDownloadAndRemoveAsset(OK, downLoadCount, removeCount);
    UpdateCloudTableRecord(0, actualCount, false);
    RelationalTestUtils::CloudBlockSync(query, delegate_);
    EXPECT_EQ(downLoadCount, 1); // local asset was removed should download 1 times
    EXPECT_EQ(removeCount, 1);
    virtualAssetLoader_->ForkDownload(nullptr);
    virtualAssetLoader_->ForkRemoveLocalAssets(nullptr);

    std::vector<size_t> expectCount = { 0 };
    CheckAssetsCount(expectCount);
}

/**
 * @tc.name: SyncWithAssetOperation003
 * @tc.desc: Delete Assets When Download
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: bty
 */
HWTEST_F(DistributedDBCloudAssetsOperationSyncTest, SyncWithAssetOperation003, TestSize.Level0)
{
    InsertUserTableRecord(tableName_, 0, 1); // 1 is count
    int uploadCount = 0;
    virtualCloudDb_->ForkUpload([this, &uploadCount](const std::string &, VBucket &) {
        if (uploadCount > 0) {
            return;
        }
        SqlCondition condition;
        condition.sql = "UPDATE " + tableName_ + " SET age = '666' WHERE id = 0;";
        std::vector<VBucket> records;
        EXPECT_EQ(delegate_->ExecuteSql(condition, records), OK);
        uploadCount++;
    });
    Query query = Query::Select().FromTable({ tableName_ });
    BlockSync(query, delegate_);
    virtualCloudDb_->ForkUpload(nullptr);

    std::string sql = "SELECT assets from " + tableName_ + " where id = 0;";
    sqlite3_stmt *stmt = nullptr;
    ASSERT_EQ(SQLiteUtils::GetStatement(db_, sql, stmt), E_OK);
    while (SQLiteUtils::StepWithRetry(stmt) == SQLiteUtils::MapSQLiteErrno(SQLITE_ROW)) {
        ASSERT_EQ(sqlite3_column_type(stmt, 0), SQLITE_BLOB);
        Type cloudValue;
        ASSERT_EQ(SQLiteRelationalUtils::GetCloudValueByType(stmt, TYPE_INDEX<Assets>, 0, cloudValue), E_OK);
        std::vector<uint8_t> assetsBlob;
        Assets assets;
        ASSERT_EQ(CloudStorageUtils::GetValueFromOneField(cloudValue, assetsBlob), E_OK);
        ASSERT_EQ(RuntimeContext::GetInstance()->BlobToAssets(assetsBlob, assets), E_OK);
        ASSERT_EQ(assets.size(), 2u); // 2 is asset num
        for (size_t i = 0; i < assets.size(); ++i) {
            EXPECT_EQ(assets[i].status, AssetStatus::NORMAL);
        }
    }
    int errCode;
    SQLiteUtils::ResetStatement(stmt, true, errCode);
}

void DistributedDBCloudAssetsOperationSyncTest::LocalAssetRemoveTest()
{
    const int actualCount = 5; // 5 record
    InsertUserTableRecord(tableName_, 0, actualCount);
    Query query = Query::Select().FromTable({ tableName_ });
    BlockSync(query, delegate_);
    int downLoadCount = 0;
    int removeCount = 0;
    ForkDownloadAndRemoveAsset(DB_ERROR, downLoadCount, removeCount);
    UpdateCloudTableRecord(0, actualCount, false);
    RelationalTestUtils::CloudBlockSync(query, delegate_, DBStatus::OK, DBStatus::REMOVE_ASSETS_FAIL);
    EXPECT_EQ(downLoadCount, 5); // local asset was removed should download 5 times
    EXPECT_EQ(removeCount, 1);
    virtualAssetLoader_->ForkDownload(nullptr);
    virtualAssetLoader_->ForkRemoveLocalAssets(nullptr);

    std::vector<size_t> expectCount = { 0, 2, 2, 2, 2 };
    CheckAssetsCount(expectCount);
}

/**
 * @tc.name: SyncWithAssetOperation004
 * @tc.desc: Download Assets When local assets was removed
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: zhangqiquan
 */
HWTEST_F(DistributedDBCloudAssetsOperationSyncTest, SyncWithAssetOperation004, TestSize.Level0)
{
    LocalAssetRemoveTest();
}

void DistributedDBCloudAssetsOperationSyncTest::UpdateAssetWhenSyncUpload()
{
    string sql = "UPDATE " + tableName_ + " SET asset = ? WHERE id = '54';";
    Asset asset = g_localAsset;
    asset.hash = "123";
    const int assetId = 54;
    asset.name = g_localAsset.name + std::to_string(assetId);
    std::vector<uint8_t> assetBlob;
    RuntimeContext::GetInstance()->AssetToBlob(asset, assetBlob);
    sqlite3_stmt *stmt = nullptr;
    ASSERT_EQ(SQLiteUtils::GetStatement(db_, sql, stmt), E_OK);
    ASSERT_EQ(SQLiteUtils::BindBlobToStatement(stmt, 1, assetBlob, false), E_OK);
    EXPECT_EQ(SQLiteUtils::StepWithRetry(stmt), SQLiteUtils::MapSQLiteErrno(SQLITE_DONE));
    int errCode;
    SQLiteUtils::ResetStatement(stmt, true, errCode);
}

/**
 * @tc.name: SyncWithAssetOperation005
 * @tc.desc: check asset when update in fill before upload sync process
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: luoguo
 */
HWTEST_F(DistributedDBCloudAssetsOperationSyncTest, SyncWithAssetOperation005, TestSize.Level0)
{
    /**
     * @tc.steps:step1. Insert 60 records.
     * @tc.expected: step1. ok.
     */
    InsertUserTableRecord(tableName_, 0, 60);
    
    /**
     * @tc.steps:step2. Sync to cloud and wait in upload.
     * @tc.expected: step2. ok.
     */
    bool isUpload = false;
    virtualCloudDb_->ForkUpload([&isUpload](const std::string &, VBucket &) {
        if (isUpload == true) {
            return;
        }
        isUpload = true;
        std::this_thread::sleep_for(std::chrono::milliseconds(2000));
    });
    Query query = Query::Select().FromTable({tableName_});

    bool finish = false;
    auto callback = [&finish](const std::map<std::string, SyncProcess> &process) {
        for (const auto &item : process) {
            if (item.second.process == DistributedDB::FINISHED) {
                {
                    finish = true;
                }
            }
        }
    };
    ASSERT_EQ(delegate_->Sync({"CLOUD"}, SYNC_MODE_CLOUD_MERGE, query, callback, g_syncWaitTime), OK);

    while (isUpload == false) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    /**
     * @tc.steps:step3. update asset when sync upload.
     * @tc.expected: step3. ok.
     */
    UpdateAssetWhenSyncUpload();

    /**
     * @tc.steps:step4. check asset data.
     * @tc.expected: step4. ok.
     */
    while (finish == false) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    virtualCloudDb_->ForkUpload(nullptr);
    std::vector<VBucket> allData;
    auto dbSchema = GetSchema();
    ASSERT_GT(dbSchema.tables.size(), 0u);
    ASSERT_EQ(RelationalTestUtils::SelectData(db_, dbSchema.tables[0], allData), E_OK);
    ASSERT_EQ(allData.size(), 60ul);
    auto data = allData[54]; // update data
    auto data1 = allData[55]; // no update data

    Type colValue = data.at("asset");
    auto translate = std::dynamic_pointer_cast<ICloudDataTranslate>(virtualTranslator_);
    auto assets = RelationalTestUtils::GetAssets(colValue, translate, true);
    ASSERT_EQ(assets[0].hash, std::string("123"));

    Type colValue1 = data1.at("asset");
    auto assets1 = RelationalTestUtils::GetAssets(colValue1, translate, true);
    ASSERT_EQ(assets1[0].hash, std::string("DEC"));
}

/**
 * @tc.name: SyncWithAssetOperation006
 * @tc.desc: Remove Local Datas When local assets was empty
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: lijun
 */
HWTEST_F(DistributedDBCloudAssetsOperationSyncTest, SyncWithAssetOperation006, TestSize.Level0)
{
    const int actualCount = 5;
    InsertUserTableRecord(tableName_, 0, actualCount);
    Query query = Query::Select().FromTable({ tableName_ });
    BlockSync(query, delegate_);

    UpdateCloudTableRecord(0, 2, true);
    BlockSync(query, delegate_);

    int removeCount = 0;
    virtualAssetLoader_->ForkRemoveLocalAssets([&removeCount](const std::vector<Asset> &assets) {
        removeCount = assets.size();
        return DBStatus::OK;
    });
    std::string device = "";
    ASSERT_EQ(delegate_->RemoveDeviceData(device, FLAG_AND_DATA), DBStatus::OK);
    ASSERT_EQ(9, removeCount);
    virtualAssetLoader_->ForkRemoveLocalAssets(nullptr);
}

/**
 * @tc.name: SyncWithAssetOperation007
 * @tc.desc: Test assetId fill when assetId changed
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: wangxiangdong
 */
HWTEST_F(DistributedDBCloudAssetsOperationSyncTest, SyncWithAssetOperation007, TestSize.Level0)
{
    /**
     * @tc.steps:step1. Insert 5 records and sync.
     * @tc.expected: step1. ok.
     */
    const int actualCount = 5;
    std::string name = g_localAsset.name + std::to_string(0);
    Assets expectAssets = GetAssets(name, {}, 3u); // contain 3 assets
    expectAssets[0].hash.append("change"); // modify first asset
    InsertUserTableRecord(tableName_, 0, actualCount, expectAssets.size(), expectAssets);
    Query query = Query::Select().FromTable({ tableName_ });
    BlockSync(query, delegate_);
    /**
     * @tc.steps:step2. modify data and sync.
     * @tc.expected: step2. ok.
     */
    UpdateCloudTableRecord(0, 1, true);
    BlockSync(query, delegate_);
    /**
     * @tc.steps:step3. check modified data cursor.
     * @tc.expected: step3. ok.
     */
    std::string sql = "SELECT cursor FROM " + DBCommon::GetLogTableName(tableName_) + " where data_key=1";
    EXPECT_EQ(sqlite3_exec(db_, sql.c_str(), CloudDBSyncUtilsTest::QueryCountCallback,
        reinterpret_cast<void *>(7), nullptr), SQLITE_OK);
    sql = "SELECT cursor FROM " + DBCommon::GetLogTableName(tableName_) + " where data_key=5";
    EXPECT_EQ(sqlite3_exec(db_, sql.c_str(), CloudDBSyncUtilsTest::QueryCountCallback,
        reinterpret_cast<void *>(5), nullptr), SQLITE_OK);
}

/**
 * @tc.name: SyncWithAssetOperation008
 * @tc.desc: Test assetId fill when assetId changed
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: wangxiangdong
 */
HWTEST_F(DistributedDBCloudAssetsOperationSyncTest, SyncWithAssetOperation008, TestSize.Level0)
{
    /**
     * @tc.steps:step1. Insert 5 records and sync.
     * @tc.expected: step1. ok.
     */
    const int actualCount = 5;
    InsertUserTableRecord(tableName_, 0, actualCount);
    Query query = Query::Select().FromTable({ tableName_ });
    BlockSync(query, delegate_);
    /**
     * @tc.steps:step2. modify data and sync.
     * @tc.expected: step2. ok.
     */
    UpdateCloudTableRecord(0, 1, true);
    int removeCount = 0;
    virtualAssetLoader_->SetRemoveLocalAssetsCallback([&removeCount](std::map<std::string, Assets> &assets) {
        removeCount = assets["asset"].size() + assets["assets"].size();
        return LOCAL_ASSET_NOT_FOUND;
    });
    BlockSync(query, delegate_);
    EXPECT_EQ(removeCount, 3); // one record has 3 asset
    virtualAssetLoader_->SetRemoveLocalAssetsCallback(nullptr);
    /**
     * @tc.steps:step3. check asset number.
     * @tc.expected: step3. ok.
     */
    std::vector<size_t> expectCount = { 3, 3, 3, 3, 3 };
    CheckAssetsCount(expectCount, true);
    /**
     * @tc.steps:step4. sync and check.
     * @tc.expected: step4. ok.
     */
    BlockSync(query, delegate_);
    expectCount = { 0, 3, 3, 3, 3 };
    CheckAssetsCount(expectCount, true);
}

/**
 * @tc.name: SyncWithAssetOperation009
 * @tc.desc: Test asset remove local and check db asset empty finally.
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: wangxiangdong
 */
HWTEST_F(DistributedDBCloudAssetsOperationSyncTest, SyncWithAssetOperation009, TestSize.Level0)
{
    /**
     * @tc.steps:step1. Insert 5 records and sync.
     * @tc.expected: step1. ok.
     */
    const int actualCount = 5;
    RelationalTestUtils::InsertCloudRecord(0, actualCount, tableName_, virtualCloudDb_);
    InsertUserTableRecord(tableName_, 0, actualCount);
    /**
     * @tc.steps:step2. modify data and sync.
     * @tc.expected: step2. ok.
     */
    UpdateCloudTableRecord(0, 1, true);
    Query query = Query::Select().FromTable({ tableName_ });
    BlockSync(query, delegate_);
    /**
     * @tc.steps:step3. check asset number.
     * @tc.expected: step3. ok.
     */
    std::vector<size_t> expectCount = { 0, 3, 3, 3, 3 };
    CheckAssetsCount(expectCount, true);
}

void DistributedDBCloudAssetsOperationSyncTest::InsertLocalAssetData(const std::string &assetHash)
{
    Assets assets;
    std::string assetNameBegin = "Phone";
    for (int j = 1; j <= g_assetsNum; ++j) {
        Asset asset;
        asset.name = assetNameBegin + "_" + std::to_string(j);
        asset.status = AssetStatus::NORMAL;
        asset.flag = static_cast<uint32_t>(AssetOpType::NO_CHANGE);
        asset.hash = assetHash + "_" + std::to_string(j);
        asset.assetId = std::to_string(j);
        assets.push_back(asset);
    }
    string sql = "INSERT OR REPLACE INTO " + tableName_ + " (id,name,asset,assets) VALUES('0','CloudTest0',?,?);";
    sqlite3_stmt *stmt = nullptr;
    ASSERT_EQ(SQLiteUtils::GetStatement(db_, sql, stmt), E_OK);
    std::vector<uint8_t> assetBlob;
    std::vector<uint8_t> assetsBlob;
    RuntimeContext::GetInstance()->AssetToBlob(g_localAsset, assetBlob);
    RuntimeContext::GetInstance()->AssetsToBlob(assets, assetsBlob);
    ASSERT_EQ(SQLiteUtils::BindBlobToStatement(stmt, 1, assetBlob, false), E_OK);
    ASSERT_EQ(SQLiteUtils::BindBlobToStatement(stmt, 2, assetsBlob, false), E_OK); // 2 is assetsBlob
    EXPECT_EQ(SQLiteUtils::StepWithRetry(stmt), SQLiteUtils::MapSQLiteErrno(SQLITE_DONE));
    int errCode;
    SQLiteUtils::ResetStatement(stmt, true, errCode);
}

void DistributedDBCloudAssetsOperationSyncTest::InsertCloudAssetData(const std::string &assetHash)
{
    std::vector<VBucket> record;
    std::vector<VBucket> extend;
    Timestamp now = DistributedDB::TimeHelper::GetSysCurrentTime();
    VBucket data;
    data.insert_or_assign("id", "0");
    data.insert_or_assign("name", "CloudTest0");
    Asset asset = g_localAsset;
    data.insert_or_assign("asset", asset);
    Assets assets;
    std::string assetNameBegin = "Phone";
    for (int j = 1; j <= g_assetsNum; ++j) {
        Asset assetTmp;
        assetTmp.name = assetNameBegin + "_" + std::to_string(j);
        assetTmp.status = AssetStatus::NORMAL;
        assetTmp.hash = assetHash + "_" + std::to_string(j);
        assetTmp.assetId = std::to_string(j);
        assets.push_back(assetTmp);
    }
    data.insert_or_assign("assets", assets);
    record.push_back(data);
    VBucket log;
    log.insert_or_assign(DistributedDB::CloudDbConstant::CREATE_FIELD, static_cast<int64_t>(
        now / DistributedDB::CloudDbConstant::TEN_THOUSAND));
    log.insert_or_assign(DistributedDB::CloudDbConstant::MODIFY_FIELD, static_cast<int64_t>(
        now / DistributedDB::CloudDbConstant::TEN_THOUSAND));
    log.insert_or_assign(DistributedDB::CloudDbConstant::DELETE_FIELD, false);
    extend.push_back(log);
    virtualCloudDb_->BatchInsert(tableName_, std::move(record), extend);
}

void DistributedDBCloudAssetsOperationSyncTest::PrepareForAssetOperation010()
{
    InsertCloudAssetData("cloudAsset");
    InsertLocalAssetData("localAsset");
}

/**
 * @tc.name: SyncWithAssetOperation010
 * @tc.desc: Test check status of asset, when the hash of asset is different.
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: liufuchenxing
 */
HWTEST_F(DistributedDBCloudAssetsOperationSyncTest, SyncWithAssetOperation010, TestSize.Level0)
{
    /**
     * @tc.steps:step1. prepare local and cloud asset data.
     * @tc.expected: step1. ok.
     */
    PrepareForAssetOperation010();

    /**
     * @tc.steps:step2. sync and check the status of assets.
     * @tc.expected: step2. ok.
     */
    virtualCloudDb_->ForkBeforeBatchUpdate([](const std::string &, std::vector<VBucket> &record,
        std::vector<VBucket> &extend, bool) {
        ASSERT_EQ(static_cast<int>(record.size()), 1);
        VBucket &bucket = record[0];
        ASSERT_TRUE(bucket.find("assets") != bucket.end());
        Assets assets = std::get<Assets>(bucket["assets"]);
        ASSERT_EQ(static_cast<int>(assets.size()), 3);
        for (size_t i = 0; i < assets.size(); i++) {
            ASSERT_EQ(assets[i].status, AssetStatus::UPDATE);
        }
    });

    Query query = Query::Select().FromTable({ tableName_ });
    BlockSync(query, delegate_, SYNC_MODE_CLOUD_FORCE_PUSH);
}

void DistributedDBCloudAssetsOperationSyncTest::WriteDataWithoutCommitTransaction()
{
    ASSERT_NE(db_, nullptr);
    SQLiteUtils::BeginTransaction(db_);
    InsertLocalAssetData("localAsset");
    constexpr int kSleepDurationSeconds = 3;
    std::this_thread::sleep_for(std::chrono::seconds(kSleepDurationSeconds));
}

/**
 * @tc.name: TestOpenDatabaseBusy001
 * @tc.desc: Test open database when the database is busy.
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: liufuchenxing
 */
HWTEST_F(DistributedDBCloudAssetsOperationSyncTest, TestOpenDatabaseBusy001, TestSize.Level2)
{
    /**
     * @tc.steps:step1. close store.
     * @tc.expected:step1. check ok.
     */
    EXPECT_EQ(mgr_->CloseStore(delegate_), DBStatus::OK);
    delegate_ = nullptr;
    /**
     * @tc.steps:step2. Another thread write data into database into database without commit.
     * @tc.expected:step2. check ok.
     */
    std::thread thread(&DistributedDBCloudAssetsOperationSyncTest::WriteDataWithoutCommitTransaction, this);
    std::this_thread::sleep_for(std::chrono::seconds(1));
    /**
     * @tc.steps:step3. open relational delegate.
     * @tc.expected:step3. open success.
     */
    RelationalStoreDelegate::Option option;
    ASSERT_EQ(mgr_->OpenStore(storePath_, STORE_ID_1, option, delegate_), DBStatus::OK);
    thread.join();
}

/**
 * @tc.name: SyncWithAssetOperation011
 * @tc.desc: Test change assets between download and remove
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: liaoyonghuang
 */
HWTEST_F(DistributedDBCloudAssetsOperationSyncTest, SyncWithAssetOperation011, TestSize.Level0)
{
    /**
     * @tc.steps:step1. Insert 5 records and sync.
     * @tc.expected: step1. ok.
     */
    const int actualCount = 5;
    InsertUserTableRecord(tableName_, 0, actualCount);
    Query query = Query::Select().FromTable({ tableName_ });
    BlockSync(query, delegate_);
    /**
     * @tc.steps:step2. modify assets of cloud data. update 1st asset and delete 2nd asset.
     * @tc.expected: step2. ok.
     */
    std::vector<VBucket> record;
    std::vector<VBucket> extend;
    int dataNum = 0;
    Timestamp now = TimeHelper::GetSysCurrentTime();
    VBucket data;
    data.insert_or_assign("id", std::to_string(dataNum));
    data.insert_or_assign("name", "Cloud" + std::to_string(dataNum));
    Asset cloudAsset = g_localAsset;
    cloudAsset.name += std::to_string(dataNum);
    cloudAsset.hash = "new_hash";
    Assets cloudAssets = {cloudAsset};
    data.insert_or_assign("assets", cloudAssets);
    record.push_back(data);
    VBucket log;
    log.insert_or_assign(CloudDbConstant::CREATE_FIELD, static_cast<int64_t>(
            now / CloudDbConstant::TEN_THOUSAND));
    log.insert_or_assign(CloudDbConstant::MODIFY_FIELD, static_cast<int64_t>(
            now / CloudDbConstant::TEN_THOUSAND));
    log.insert_or_assign(CloudDbConstant::DELETE_FIELD, false);
    log.insert_or_assign(CloudDbConstant::GID_FIELD, std::to_string(dataNum));
    extend.push_back(log);
    ASSERT_EQ(virtualCloudDb_->BatchUpdate(tableName_, std::move(record), extend), DBStatus::OK);
    /**
     * @tc.steps:step3. Update local assets between remove and download, sync and check whether download is invoked.
     * @tc.expected: step3. ok.
     */
    virtualAssetLoader_->SetRemoveLocalAssetsCallback([&](std::map<std::string, Assets> &assets) {
        UpdateLocalTableRecord(tableName_, 0, 1);
        return OK;
    });
    virtualAssetLoader_->ForkDownload([](const std::string &tableName, std::map<std::string, Assets> &assets) {
        EXPECT_TRUE(false);
    });
    BlockSync(query, delegate_);

    virtualAssetLoader_->SetRemoveLocalAssetsCallback(nullptr);
    virtualAssetLoader_->ForkDownload(nullptr);
}

/**
 * @tc.name: SyncWithAssetOperation012
 * @tc.desc: Batch download Assets When local assets was removed
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: liaoyonghuang
 */
HWTEST_F(DistributedDBCloudAssetsOperationSyncTest, SyncWithAssetOperation012, TestSize.Level0)
{
    RuntimeContext::GetInstance()->SetBatchDownloadAssets(true);
    LocalAssetRemoveTest();
    RuntimeContext::GetInstance()->SetBatchDownloadAssets(false);
}

void DistributedDBCloudAssetsOperationSyncTest::UpdateLocalAssetRecord(const std::string &tableName, int64_t begin,
    int64_t count)
{
    int errCode;
    std::vector<uint8_t> assetBlob;
    std::vector<uint8_t> assetsBlob;
    for (int64_t i = begin; i < begin + count; ++i) {
        Asset asset = g_localAsset;
        asset.hash = "new_hash";
        asset.status = static_cast<uint32_t>(AssetStatus::UPDATE);
        RuntimeContext::GetInstance()->AssetToBlob(asset, assetBlob);
        std::vector<Asset> assets;
        assets.push_back(asset);
        RuntimeContext::GetInstance()->AssetsToBlob(assets, assetsBlob);
        std::string sql = "UPDATE " + tableName + " SET height = '175.0', asset = ?, assets = ? where id = " +
            std::to_string(i);
        sqlite3_stmt *stmt = nullptr;
        ASSERT_EQ(SQLiteUtils::GetStatement(db_, sql, stmt), E_OK);
        ASSERT_EQ(SQLiteUtils::BindBlobToStatement(stmt, 1, assetBlob, false), E_OK); // 1st bind
        ASSERT_EQ(SQLiteUtils::BindBlobToStatement(stmt, 2, assetsBlob, false), E_OK); // 2nd bind
        EXPECT_EQ(SQLiteUtils::StepWithRetry(stmt), SQLiteUtils::MapSQLiteErrno(SQLITE_DONE));
        SQLiteUtils::ResetStatement(stmt, true, errCode);
    }
}

/**
 * @tc.name: SyncWithAssetOperation013
 * @tc.desc: Test device modify data and then sync cursor will not changes
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: caihaoting
 */
HWTEST_F(DistributedDBCloudAssetsOperationSyncTest, SyncWithAssetOperation013, TestSize.Level0)
{
    /**
     * @tc.steps:step1. Insert local and cloud asset data and sync.
     * @tc.expected: step1. ok.
     */
    InsertCloudAssetData("assetHash");
    InsertLocalAssetData("assetHash");
    Query query = Query::Select().FromTable({ tableName_ });
    BlockSync(query, delegate_);
    /**
     * @tc.steps:step2. modify data of asset and sync.
     * @tc.expected: step2. ok.
     */
    UpdateLocalAssetRecord(tableName_, 0, 1);
    const int cursor = 2;
    std::string sql = "SELECT cursor FROM " + DBCommon::GetLogTableName(tableName_) + " where data_key=1";
    EXPECT_EQ(sqlite3_exec(db_, sql.c_str(), CloudDBSyncUtilsTest::QueryCountCallback,
        reinterpret_cast<void *>(cursor), nullptr), SQLITE_OK);
    BlockSync(query, delegate_);
    /**
     * @tc.steps:step3. check modified data cursor and cursor is not changed.
     * @tc.expected: step3. ok.
     */
    EXPECT_EQ(sqlite3_exec(db_, sql.c_str(), CloudDBSyncUtilsTest::QueryCountCallback,
        reinterpret_cast<void *>(cursor), nullptr), SQLITE_OK);
}

/**
 * @tc.name: SyncWithAssetOperation014
 * @tc.desc: Test device data does not change while sync and cursor will not changes
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: caihaoting
 */
HWTEST_F(DistributedDBCloudAssetsOperationSyncTest, SyncWithAssetOperation014, TestSize.Level0)
{
    /**
     * @tc.steps:step1. Insert 5 records and sync.
     * @tc.expected: step1. ok.
     */
    const int actualCount = 5;
    RelationalTestUtils::InsertCloudRecord(0, actualCount, tableName_, virtualCloudDb_);
    InsertUserTableRecord(tableName_, 0, actualCount);
    Query query = Query::Select().FromTable({ tableName_ });
    BlockSync(query, delegate_);
    /**
     * @tc.steps:step2. modify data and sync.
     * @tc.expected: step2. ok.
     */
    UpdateLocalAssetRecord(tableName_, 0, 1);
    const int cursor = 6;
    std::string sql = "SELECT cursor FROM " + DBCommon::GetLogTableName(tableName_) + " where data_key=1";
    EXPECT_EQ(sqlite3_exec(db_, sql.c_str(), CloudDBSyncUtilsTest::QueryCountCallback,
        reinterpret_cast<void *>(cursor), nullptr), SQLITE_OK);
    BlockSync(query, delegate_);
    /**
     * @tc.steps:step3. check modified data cursor and cursor is not changed.
     * @tc.expected: step3. ok.
     */
    EXPECT_EQ(sqlite3_exec(db_, sql.c_str(), CloudDBSyncUtilsTest::QueryCountCallback,
        reinterpret_cast<void *>(cursor), nullptr), SQLITE_OK);
}

/**
 * @tc.name: IgnoreRecord001
 * @tc.desc: Download Assets When local assets was removed
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: zhangqiquan
 */
HWTEST_F(DistributedDBCloudAssetsOperationSyncTest, IgnoreRecord001, TestSize.Level0)
{
    const int actualCount = 1;
    InsertUserTableRecord(tableName_, 0, actualCount);
    Query query = Query::Select().FromTable({ tableName_ });
    BlockSync(query, delegate_);
    std::vector<size_t> expectCount = { 2 };
    CheckAssetsCount(expectCount);

    VBucket record;
    record["id"] = std::to_string(0);
    record["assets"] = Assets();
    EXPECT_EQ(delegate_->UpsertData(tableName_, { record }), OK);
    record["id"] = std::to_string(1);
    EXPECT_EQ(delegate_->UpsertData(tableName_, { record }), OK);
    expectCount = { 0, 0 };
    CheckAssetsCount(expectCount);

    std::vector<VBucket> logs;
    EXPECT_EQ(RelationalTestUtils::GetRecordLog(db_, tableName_, logs), E_OK);
    for (const auto &log : logs) {
        int64_t cursor = std::get<int64_t>(log.at("cursor"));
        EXPECT_GE(cursor, 0);
    }
}

/**
 * @tc.name: IgnoreRecord002
 * @tc.desc: Ignore Assets When Download
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: zhangqiquan
 */
HWTEST_F(DistributedDBCloudAssetsOperationSyncTest, IgnoreRecord002, TestSize.Level0)
{
    const int actualCount = 1;
    InsertUserTableRecord(tableName_, 0, actualCount);
    Query query = Query::Select().FromTable({ tableName_ });
    RelationalTestUtils::CloudBlockSync(query, delegate_);
    UpdateCloudTableRecord(0, actualCount, false);

    virtualAssetLoader_->SetDownloadStatus(DBStatus::CLOUD_RECORD_EXIST_CONFLICT);
    RelationalTestUtils::CloudBlockSync(query, delegate_);
    virtualAssetLoader_->SetDownloadStatus(DBStatus::OK);
    std::vector<size_t> expectCount = { 4 };
    CheckAssetsCount(expectCount);
    RelationalTestUtils::CloudBlockSync(query, delegate_);
}

/**
 * @tc.name: IgnoreRecord003
 * @tc.desc: Ignore Assets When Upload
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: zhangqiquan
 */
HWTEST_F(DistributedDBCloudAssetsOperationSyncTest, IgnoreRecord003, TestSize.Level0)
{
    const int actualCount = 1;
    InsertUserTableRecord(tableName_, 0, actualCount);
    Query query = Query::Select().FromTable({ tableName_ });
    virtualCloudDb_->SetConflictInUpload(true);
    RelationalTestUtils::CloudBlockSync(query, delegate_);
    virtualCloudDb_->SetConflictInUpload(false);
    std::vector<size_t> expectCount = { 2 };
    CheckAssetsCount(expectCount);
    RelationalTestUtils::CloudBlockSync(query, delegate_);
}

/**
 * @tc.name: IgnoreRecord004
 * @tc.desc: Ignore Assets When Btch Download
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: luoguo
 */
HWTEST_F(DistributedDBCloudAssetsOperationSyncTest, IgnoreRecord004, TestSize.Level0)
{
    RuntimeContext::GetInstance()->SetBatchDownloadAssets(true);
    const int actualCount = 10;
    InsertUserTableRecord(tableName_, 0, actualCount);
    Query query = Query::Select().FromTable({ tableName_ });
    RelationalTestUtils::CloudBlockSync(query, delegate_);
    UpdateCloudTableRecord(0, actualCount, false);

    virtualAssetLoader_->SetDownloadStatus(DBStatus::CLOUD_RECORD_EXIST_CONFLICT);
    RelationalTestUtils::CloudBlockSync(query, delegate_);
    virtualAssetLoader_->SetDownloadStatus(DBStatus::OK);
    std::vector<size_t> expectCount(10, 4);
    CheckAssetsCount(expectCount);
    RelationalTestUtils::CloudBlockSync(query, delegate_);
    RuntimeContext::GetInstance()->SetBatchDownloadAssets(false);
}

/**
 * @tc.name: UpsertData001
 * @tc.desc: Upsert data after delete it
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: zhangqiquan
 */
HWTEST_F(DistributedDBCloudAssetsOperationSyncTest, UpsertData001, TestSize.Level0)
{
    // insert id 0 to local
    const int actualCount = 1;
    InsertUserTableRecord(tableName_, 0, actualCount); // 10 is phone size
    std::vector<std::map<std::string, std::string>> conditions;
    std::map<std::string, std::string> entries;
    entries["id"] = "0";
    conditions.push_back(entries);
    // delete id 0 in local
    RelationalTestUtils::DeleteRecord(db_, tableName_, conditions);
    // upsert id 0 to local
    VBucket record;
    record["id"] = std::to_string(0);
    record["assets"] = Assets();
    EXPECT_EQ(delegate_->UpsertData(tableName_, { record }), OK);
    // check id 0 exist
    CheckAssetsCount({ 0 });
}

/**
 * @tc.name: UpsertData002
 * @tc.desc: Test sync after Upsert.
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: liaoyonghuang
 */
HWTEST_F(DistributedDBCloudAssetsOperationSyncTest, UpsertData002, TestSize.Level0)
{
    /**
     * @tc.steps:step1. Insert 5 records and sync.
     * @tc.expected: step1. ok.
     */
    const int actualCount = 5;
    InsertUserTableRecord(tableName_, 0, actualCount);
    Query query = Query::Select().FromTable({ tableName_ });
    BlockSync(query, delegate_);

    /**
     * @tc.steps:step2. UpsertData and sync.
     * @tc.expected: step2. ok.
     */
    int dataCnt = -1;
    std::string checkLogSql = "SELECT count(*) FROM " + DBCommon::GetLogTableName(tableName_) + " where cursor = 5";
    RelationalTestUtils::ExecSql(db_, checkLogSql, nullptr, [&dataCnt](sqlite3_stmt *stmt) {
        dataCnt = sqlite3_column_int(stmt, 0);
        return E_OK;
    });
    EXPECT_EQ(dataCnt, 1);
    vector<VBucket> records;
    for (int i = 0; i < actualCount; i++) {
        VBucket record;
        record["id"] = std::to_string(i);
        record["name"] = std::string("UpsertName");
        records.push_back(record);
    }
    EXPECT_EQ(delegate_->UpsertData(tableName_, records), OK);
    // check cursor has been increased
    checkLogSql = "SELECT count(*) FROM " + DBCommon::GetLogTableName(tableName_) + " where cursor = 10";
    RelationalTestUtils::ExecSql(db_, checkLogSql, nullptr, [&dataCnt](sqlite3_stmt *stmt) {
        dataCnt = sqlite3_column_int(stmt, 0);
        return E_OK;
    });
    EXPECT_EQ(dataCnt, 1);
    BlockSync(query, delegate_);

    /**
     * @tc.steps:step3. Check local data.
     * @tc.expected: step3. All local data has been merged by the cloud.
     */
    std::vector<VBucket> allData;
    auto dbSchema = GetSchema();
    ASSERT_GT(dbSchema.tables.size(), 0u);
    ASSERT_EQ(RelationalTestUtils::SelectData(db_, dbSchema.tables[0], allData), E_OK);
    for (const auto &data : allData) {
        ASSERT_EQ(std::get<std::string>(data.at("name")), "local");
    }
}

/**
 * @tc.name: SyncWithAssetConflict001
 * @tc.desc: Upload with asset no change
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: zhangqiquan
 */
HWTEST_F(DistributedDBCloudAssetsOperationSyncTest, SyncWithAssetConflict001, TestSize.Level0)
{
    // cloud and local insert same data
    const int actualCount = 1;
    RelationalTestUtils::InsertCloudRecord(0, actualCount, tableName_, virtualCloudDb_);
    std::this_thread::sleep_for(std::chrono::seconds(1)); // sleep 1s for data conflict
    InsertUserTableRecord(tableName_, 0, actualCount);
    // sync and local asset's status are normal
    Query query = Query::Select().FromTable({ tableName_ });
    RelationalTestUtils::CloudBlockSync(query, delegate_);
    auto dbSchema = GetSchema();
    ASSERT_GT(dbSchema.tables.size(), 0u);
    auto assets = RelationalTestUtils::GetAllAssets(db_, dbSchema.tables[0], virtualTranslator_);
    for (const auto &oneRow : assets) {
        for (const auto &asset : oneRow) {
            EXPECT_EQ(asset.status, static_cast<uint32_t>(AssetStatus::NORMAL));
        }
    }
}

/**
 * @tc.name: UpsertDataInvalid001
 * @tc.desc: Upsert invalid data
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: wangxiangdong
 */
HWTEST_F(DistributedDBCloudAssetsOperationSyncTest, UpsertDataInvalid001, TestSize.Level0)
{
    VBucket record;
    record["id"] = std::to_string(0);
    record["assets"] = Assets();
    /**
     * @tc.steps:step1. UpsertData to empty table.
     * @tc.expected: step1. INVALID_ARGS.
     */
    EXPECT_EQ(delegate_->UpsertData("", { record }), INVALID_ARGS);
    /**
     * @tc.steps:step2. UpsertData to shared table.
     * @tc.expected: step2. INVALID_ARGS.
     */
    EXPECT_EQ(delegate_->UpsertData(tableName_ + "_shared", { record }), NOT_SUPPORT);
    /**
     * @tc.steps:step3. UpsertData to not device table and shared table.
     * @tc.expected: step3. NOT_FOUND.
     */
    const char *createSQL =
        "CREATE TABLE IF NOT EXISTS testing(" \
        "id TEXT PRIMARY KEY," \
        "name TEXT," \
        "height REAL ," \
        "photo BLOB," \
        "asset ASSET," \
        "assets ASSETS," \
        "age INT);";
    EXPECT_EQ(RelationalTestUtils::ExecSql(db_, createSQL), SQLITE_OK);
    EXPECT_EQ(delegate_->UpsertData("testing", { record }), NOT_FOUND);
    /**
     * @tc.steps:step4. UpsertData to not exist table.
     * @tc.expected: step4. NOT_FOUND.
     */
    EXPECT_EQ(delegate_->UpsertData("TABLE_NOT_EXIST", { record }), NOT_FOUND);
}

/**
 * @tc.name: UpsertDataInvalid002
 * @tc.desc: Upsert device data
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: wangxiangdong
 */
HWTEST_F(DistributedDBCloudAssetsOperationSyncTest, UpsertDataInvalid002, TestSize.Level0)
{
    VBucket record;
    record["id"] = std::to_string(0);
    record["assets"] = Assets();
    /**
     * @tc.steps:step1. create user table.
     * @tc.expected: step1. INVALID_ARGS.
     */
    const char *createSQL =
        "CREATE TABLE IF NOT EXISTS deviceTable(" \
        "id TEXT PRIMARY KEY," \
        "name TEXT," \
        "height REAL ," \
        "photo BLOB," \
        "asset ASSET," \
        "assets ASSETS," \
        "age INT);";
    EXPECT_EQ(RelationalTestUtils::ExecSql(db_, createSQL), SQLITE_OK);
    /**
     * @tc.steps:step2. create device table.
     * @tc.expected: step2. OK.
     */
    RelationalStoreDelegate *delegate1 = nullptr;
    std::shared_ptr<RelationalStoreManager> mgr1 = std::make_shared<RelationalStoreManager>(APP_ID, USER_ID);
    RelationalStoreDelegate::Option option;
    ASSERT_EQ(mgr1->OpenStore(storePath_, STORE_ID_1, option, delegate1), DBStatus::OK);
    ASSERT_NE(delegate1, nullptr);
    std::string deviceTableName = "deviceTable";
    ASSERT_EQ(delegate1->CreateDistributedTable(deviceTableName, DEVICE_COOPERATION), DBStatus::OK);
    DataBaseSchema dataBaseSchema;
    TableSchema tableSchema;
    tableSchema.name = deviceTableName;
    tableSchema.sharedTableName = deviceTableName + "_shared";
    tableSchema.fields = {
        {"id", TYPE_INDEX<std::string>, true}, {"name", TYPE_INDEX<std::string>}, {"height", TYPE_INDEX<double>},
        {"photo", TYPE_INDEX<Bytes>}, {"asset", TYPE_INDEX<Asset>}, {"assets", TYPE_INDEX<Assets>},
        {"age", TYPE_INDEX<int64_t>}
    };
    dataBaseSchema.tables.push_back(tableSchema);
    ASSERT_EQ(delegate1->SetCloudDbSchema(dataBaseSchema), DBStatus::OK);
    /**
     * @tc.steps:step3. UpsertData to device table.
     * @tc.expected: step3. NOT_FOUND.
     */
    EXPECT_EQ(delegate1->UpsertData(deviceTableName, { record }), NOT_FOUND);
    EXPECT_EQ(mgr1->CloseStore(delegate1), DBStatus::OK);
    delegate1 = nullptr;
    mgr1 = nullptr;
}

/**
 * @tc.name: DownloadAssetStatusTest004
 * @tc.desc: Test upload asset status
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: zhangqiquan
 */
HWTEST_F(DistributedDBCloudAssetsOperationSyncTest, DownloadAssetStatusTest004, TestSize.Level0)
{
    /**
     * @tc.steps:step1. cloud assets {0, 1}
     * @tc.expected: step1. OK.
     */
    // cloud and local insert same data
    // cloud assets {0, 1} local assets {0, 1, 2}
    const int actualCount = 1;
    RelationalTestUtils::InsertCloudRecord(0, actualCount, tableName_, virtualCloudDb_, 2);
    std::this_thread::sleep_for(std::chrono::milliseconds(100)); // sleep 100ms for data conflict
    /**
     * @tc.steps:step2. local assets {0, 1, 2}, and change assert {0}
     * @tc.expected: step2. OK.
     */
    std::string name = g_localAsset.name + std::to_string(0);
    Assets expectAssets = GetAssets(name, {}, 3u); // contain 3 assets
    expectAssets[0].hash.append("change"); // modify first asset
    InsertUserTableRecord(tableName_, 0, actualCount, expectAssets.size(), expectAssets);
    /**
     * @tc.steps:step3. sync
     * @tc.expected: step3. upload status is {UPDATE, NORMAL, INSERT}
     */
    std::vector<AssetStatus> expectStatus = {
        AssetStatus::UPDATE, AssetStatus::NORMAL, AssetStatus::INSERT
    };
    // sync and local asset's status are normal
    Query query = Query::Select().FromTable({ tableName_ });
    RelationalTestUtils::CloudBlockSync(query, delegate_);
    auto dbSchema = GetSchema();
    ASSERT_GT(dbSchema.tables.size(), 0u);
    // cloud asset status is update normal insert
    VBucket extend;
    extend[CloudDbConstant::CURSOR_FIELD] = std::string("");
    std::vector<VBucket> data;
    ASSERT_EQ(virtualCloudDb_->Query(tableName_, extend, data), QUERY_END);
    ASSERT_EQ(data.size(), static_cast<size_t>(actualCount));
    Assets actualAssets;
    ASSERT_EQ(CloudStorageUtils::GetValueFromType(data[0]["assets"], actualAssets), E_OK);
    ASSERT_EQ(actualAssets.size(), expectStatus.size());
    for (size_t i = 0; i < actualAssets.size(); ++i) {
        EXPECT_EQ(actualAssets[i].status, expectStatus[i]);
    }
    /**
     * @tc.steps:step4. check local assets status.
     * @tc.expected: step4. all assets status is NORMAL.
     */
    auto assets = RelationalTestUtils::GetAllAssets(db_, dbSchema.tables[0], virtualTranslator_);
    for (const auto &oneRow : assets) {
        for (const auto &asset : oneRow) {
            EXPECT_EQ(asset.status, static_cast<uint32_t>(AssetStatus::NORMAL));
        }
    }
}

/**
 * @tc.name: UploadAssetsTest001
 * @tc.desc: Test upload asset with error.
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: liaoyonghuang
 */
HWTEST_F(DistributedDBCloudAssetsOperationSyncTest, UploadAssetsTest001, TestSize.Level1)
{
    /**
     * @tc.steps:step1. Insert 10 records.
     * @tc.expected: step1. ok.
     */
    const int actualCount = 10;
    InsertUserTableRecord(tableName_, 0, actualCount);
    /**
     * @tc.steps:step2. Set callback function to cause some upstream data to fail.
     * @tc.expected: step2. ok.
     */
    int recordIndex = 0;
    Asset tempAsset = {
            .version = 2, .name = "Phone", .assetId = "0", .subpath = "/local/sync", .uri = "/cloud/sync",
            .modifyTime = "123456", .createTime = "0", .size = "1024", .hash = "DEC"
    };
    virtualCloudDb_->ForkUpload([&tempAsset, &recordIndex](const std::string &tableName, VBucket &extend) {
        Asset asset;
        Assets assets;
        switch (recordIndex) {
            case 0: // record[0] is successful because ERROR_FIELD is not verified when BatchInsert returns OK status.
                extend[std::string(CloudDbConstant::ERROR_FIELD)] = static_cast<int64_t>(DBStatus::CLOUD_ERROR);
                break;
            case 1: // record[1] is considered successful because it is a conflict.
                extend[std::string(CloudDbConstant::ERROR_FIELD)] =
                    static_cast<int64_t>(DBStatus::CLOUD_RECORD_EXIST_CONFLICT);
                break;
            case 2: // record[2] fail because of empty gid.
                extend[std::string(CloudDbConstant::GID_FIELD)] = std::string("");
                break;
            case 3: // record[3] fail because of empty assetId.
                asset = tempAsset;
                asset.assetId = "";
                extend[std::string(CloudDbConstant::ASSET)] = asset;
                break;
            case 4: // record[4] fail because of empty assetId.
                assets.push_back(tempAsset);
                assets[0].assetId = "";
                extend[std::string(CloudDbConstant::ASSETS)] = assets;
                break;
            case 5: // record[5] is successful because ERROR_FIELD is not verified when BatchInsert returns OK status.
                extend[std::string(CloudDbConstant::ERROR_FIELD)] = std::string("");
                break;
            default:
                break;
        }
        recordIndex++;
    });
    /**
     * @tc.steps:step3. Sync and check upLoadInfo.
     * @tc.expected: step3. failCount is 5 and successCount is 5.
     */
    Query query = Query::Select().FromTable({ tableName_ });
    BlockSync(query, delegate_);
    for (const auto &table : lastProcess_.tableProcess) {
        EXPECT_EQ(table.second.upLoadInfo.total, 10u);
        EXPECT_EQ(table.second.upLoadInfo.failCount, 3u);
        EXPECT_EQ(table.second.upLoadInfo.successCount, 7u);
    }
    virtualCloudDb_->ForkUpload(nullptr);
}

/**
 * @tc.name: UploadAssetsTest002
 * @tc.desc: Test upload asset with error.
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: liaoyonghuang
 */
HWTEST_F(DistributedDBCloudAssetsOperationSyncTest, UploadAssetsTest002, TestSize.Level1)
{
    /**
     * @tc.steps:step1. Insert 10 records.
     * @tc.expected: step1. ok.
     */
    const int actualCount = 10;
    InsertUserTableRecord(tableName_, 0, actualCount);
    Query query = Query::Select().FromTable({ tableName_ });
    BlockSync(query, delegate_);
    /**
     * @tc.steps:step2. Delete local data.
     * @tc.expected: step2. OK.
     */
    std::string sql = "delete from " + tableName_ + " where id >= " + std::to_string(actualCount / 2);
    EXPECT_EQ(RelationalTestUtils::ExecSql(db_, sql), SQLITE_OK);
    /**
     * @tc.steps:step3. Set callback function to cause some upstream data to fail.
     * @tc.expected: step3. ok.
     */
    virtualCloudDb_->ForkUpload([](const std::string &tableName, VBucket &extend) {
        extend[std::string(CloudDbConstant::GID_FIELD)] = "";
    });
    BlockSync(query, delegate_);
    for (const auto &table : lastProcess_.tableProcess) {
        EXPECT_EQ(table.second.upLoadInfo.total, 5u);
        EXPECT_EQ(table.second.upLoadInfo.failCount, 0u);
        EXPECT_EQ(table.second.upLoadInfo.successCount, 5u);
    }
    virtualCloudDb_->ForkUpload(nullptr);
}

/**
 * @tc.name: UploadAssetsTest003
 * @tc.desc: Test upload asset with error CLOUD_RECORD_ALREADY_EXISTED.
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: liaoyonghuang
 */
HWTEST_F(DistributedDBCloudAssetsOperationSyncTest, UploadAssetsTest003, TestSize.Level0)
{
    /**
     * @tc.steps:step1. Insert 100 records.
     * @tc.expected: step1. ok.
     */
    const int actualCount = 100;
    InsertUserTableRecord(tableName_, 0, actualCount);
    /**
     * @tc.steps:step2. Set callback function to return CLOUD_RECORD_ALREADY_EXISTED in 1st batch.
     * @tc.expected: step2. ok.
     */
    int uploadCount = 0;
    virtualCloudDb_->ForkUpload([&uploadCount](const std::string &tableName, VBucket &extend) {
        if (uploadCount < 30) { // There are a total of 30 pieces of data in one batch of upstream data
            extend[std::string(CloudDbConstant::ERROR_FIELD)] =
                static_cast<int64_t>(DBStatus::CLOUD_RECORD_ALREADY_EXISTED);
        }
        uploadCount++;
    });
    Query query = Query::Select().FromTable({ tableName_ });
    BlockSync(query, delegate_);
    for (const auto &table : lastProcess_.tableProcess) {
        EXPECT_EQ(table.second.upLoadInfo.batchIndex, 4u);
        EXPECT_EQ(table.second.upLoadInfo.total, 100u);
        EXPECT_EQ(table.second.upLoadInfo.failCount, 0u);
        EXPECT_EQ(table.second.upLoadInfo.successCount, 100u);
        EXPECT_EQ(table.second.process, ProcessStatus::FINISHED);
    }
    virtualCloudDb_->ForkUpload(nullptr);
}

/**
 * @tc.name: UploadAssetsTest004
 * @tc.desc: Test batch delete return error CLOUD_RECORD_NOT_FOUND.
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: liaoyonghuang
 */
HWTEST_F(DistributedDBCloudAssetsOperationSyncTest, UploadAssetsTest004, TestSize.Level0)
{
    /**
     * @tc.steps:step1. Insert 100 records and sync to cloud.
     * @tc.expected: step1. ok.
     */
    const int actualCount = 100;
    InsertUserTableRecord(tableName_, 0, actualCount);
    Query query = Query::Select().FromTable({ tableName_ });
    BlockSync(query, delegate_);
    /**
     * @tc.steps:step2. delete 50 records in local.
     * @tc.expected: step2. ok.
     */
    std::string sql = "delete from " + tableName_ + " where CAST(id AS INTEGER) >= " + std::to_string(actualCount / 2);
    EXPECT_EQ(RelationalTestUtils::ExecSql(db_, sql), SQLITE_OK);
    /**
     * @tc.steps:step3. set return error CLOUD_RECORD_NOT_FOUND in batch delete.
     * @tc.expected: step3. ok.
     */
    int index = 0;
    virtualCloudDb_->ForkUpload([&index](const std::string &tableName, VBucket &extend) {
        if (extend.count(CloudDbConstant::DELETE_FIELD) != 0 && index % 2 == 0 &&
            std::get<bool>(extend.at(CloudDbConstant::DELETE_FIELD))) {
            extend[CloudDbConstant::ERROR_FIELD] = static_cast<int64_t>(DBStatus::CLOUD_RECORD_NOT_FOUND);
        }
        index++;
    });
    /**
     * @tc.steps:step4. sync and check result.
     * @tc.expected: step4. ok.
     */
    BlockSync(query, delegate_);
    for (const auto &table : lastProcess_.tableProcess) {
        EXPECT_EQ(table.second.upLoadInfo.total, 50u);
        EXPECT_EQ(table.second.upLoadInfo.failCount, 0u);
        EXPECT_EQ(table.second.upLoadInfo.successCount, 50u);
    }
    virtualCloudDb_->ForkUpload(nullptr);
}

/**
 * @tc.name: BatchNormalDownloadAsset001
 * @tc.desc: Test batch download asset in two batch.
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: zqq
 */
HWTEST_F(DistributedDBCloudAssetsOperationSyncTest, BatchNormalDownloadAsset001, TestSize.Level0)
{
    RuntimeContext::GetInstance()->SetBatchDownloadAssets(true);
    PrepareDataInCloud();

    Query query = Query::Select().FromTable({ tableName_ });
    BlockSync(query, delegate_);
    EXPECT_EQ(virtualAssetLoader_->GetBatchDownloadCount(), 2u); // download 2 times
    EXPECT_EQ(virtualAssetLoader_->GetBatchRemoveCount(), 0u);   // remove 0 times
    virtualAssetLoader_->Reset();
    RuntimeContext::GetInstance()->SetBatchDownloadAssets(false);
}

/**
 * @tc.name: BatchAbnormalDownloadAsset001
 * @tc.desc: Test batch download asset failed.
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: zqq
 */
HWTEST_F(DistributedDBCloudAssetsOperationSyncTest, BatchAbnormalDownloadAsset001, TestSize.Level0)
{
    RuntimeContext::GetInstance()->SetBatchDownloadAssets(true);
    PrepareDataInCloud();
    virtualAssetLoader_->ForkBatchDownload([](int rowIndex, std::map<std::string, Assets> &assets) {
        if (rowIndex > 50) { // 50 record failed
            for (auto &asset : assets) {
                for (auto &item : asset.second) {
                    item.status = AssetStatus::ABNORMAL;
                }
            }
            return DB_ERROR;
        }
        return OK;
    });

    Query query = Query::Select().FromTable({ tableName_ });
    BlockSync(query, delegate_);
    EXPECT_EQ(virtualAssetLoader_->GetBatchDownloadCount(), 1u); // download 1 times
    EXPECT_EQ(virtualAssetLoader_->GetBatchRemoveCount(), 0u);   // remove 0 times
    virtualAssetLoader_->Reset();

    virtualAssetLoader_->ForkBatchDownload(nullptr);
    BlockSync(query, delegate_);
    EXPECT_EQ(virtualAssetLoader_->GetBatchDownloadCount(), 2u); // download 2 times
    EXPECT_EQ(virtualAssetLoader_->GetBatchRemoveCount(), 0u);   // remove 0 times
    RuntimeContext::GetInstance()->SetBatchDownloadAssets(false);
}
}
#endif
