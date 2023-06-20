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
#include "cloud_syncer.h"

#include <gtest/gtest.h>

#include "cloud_syncer_test.h"
#include "cloud_store_types.h"
#include "db_errno.h"
#include "distributeddb_tools_unit_test.h"
#include "relational_store_manager.h"
#include "distributeddb_data_generate_unit_test.h"
#include "relational_sync_able_storage.h"
#include "relational_store_instance.h"
#include "sqlite_relational_store.h"
#include "log_table_manager_factory.h"

using namespace testing::ext;
using namespace DistributedDB;
using namespace DistributedDBUnitTest;
using namespace std;

namespace {
    constexpr auto FIELD_ID = "id";
    constexpr auto FIELD_NAME = "name";
    constexpr auto FIELD_HOUSE = "house";
    constexpr auto FIELD_CARS = "cars";
    const string STORE_ID = "Relational_Store_ID";
    const string TABLE_NAME = "cloudData";
    string STORE_PATH = "./g_store.db";
    string TEST_DIR;
    DistributedDB::RelationalStoreManager g_mgr(APP_ID, USER_ID);
    RelationalStoreDelegate *g_delegate = nullptr;
    IRelationalStore *g_store = nullptr;
    std::shared_ptr<TestStorageProxy> g_storageProxy = nullptr;
    std::shared_ptr<TestCloudSyncer> g_cloudSyncer = nullptr;
    Asset a1;
    Asset a1Changed;
    Asset a2;
    Asset a2Changed;
    Asset a3;
    Asset a3Changed;
    Asset a4;
    Asset a4Changed;
    Asset a5;
    Asset a5Changed;
    const std::vector<Field> ASSET_FIELDS = {
        {FIELD_HOUSE, TYPE_INDEX<Asset>, false}, {FIELD_CARS, TYPE_INDEX<Assets>, false}
    };
    VBucket DATA_BASELINE;
    VBucket DATA_EMPTY_ASSET;
    VBucket DATA_ASSET_SAME_NAME_BUT_CHANGE;
    VBucket DATA_ASSETS_SAME_NAME_PARTIALLY_CHANGED;
    VBucket DATA_ALL_SAME;
    VBucket DATA_ASSETS_MORE_FIELD;
    VBucket DATA_EMPTY;
    VBucket DATA_ASSETS_DIFFERENT_FIELD;
    VBucket DATA_ASSETS_DIFFERENT_CHANGED_FIELD;
    VBucket DATA_ASSETS_SAME_NAME_ALL_CHANGED;
    VBucket DATA_ASSETS_ASSET_SAME_NAME;
    VBucket DATA_NULL_ASSET;
    VBucket DATA_ASSET_IN_ASSETS;
    VBucket DATA_NULL_ASSETS;

    Asset GenAsset(std::string name, std::string hash)
    {
        Asset asset;
        asset.name = name;
        asset.hash = hash;
        return asset;
    }

    VBucket GenDatum(int64_t id, std::string name, Type asset, Type assets)
    {
        VBucket datum;
        datum[FIELD_ID] = id;
        datum[FIELD_NAME] = name;
        datum[FIELD_HOUSE] = asset;
        datum[FIELD_CARS] = assets;
        return datum;
    }

    void GenData()
    {
        a1 = GenAsset("mansion", "mansion1");
        a1Changed = GenAsset("mansion", "mansion1Changed");
        a2 = GenAsset("suv", "suv1");
        a2Changed = GenAsset("suv", "suv1Changed");
        a3 = GenAsset("truck", "truck1");
        a3Changed = GenAsset("truck", "truck1Changed");
        a4 = GenAsset("sedan", "sedan1");
        a4Changed = GenAsset("sedan", "sedan1Changed");
        a5 = GenAsset("truck", "truck1");
        a5Changed = GenAsset("truck", "truck1Changed");
        DATA_BASELINE = GenDatum(1, "Jack", a1, Assets({a2, a3, a4})); // id is 1
        DATA_EMPTY_ASSET = GenDatum(2, "PoorGuy", a1, Assets({})); // id is 2
        DATA_EMPTY_ASSET.erase(FIELD_HOUSE);
        DATA_ASSET_SAME_NAME_BUT_CHANGE = GenDatum(3, "Alice", a1Changed, Assets({a2, a3, a4})); // id is 3
        DATA_ASSETS_SAME_NAME_PARTIALLY_CHANGED = GenDatum(4, "David", a1, Assets({a2, a3Changed, a4})); // id is 4
        DATA_ALL_SAME = GenDatum(5, "Marry", a1, Assets({a2, a3, a4})); // id is 5
        DATA_ASSETS_MORE_FIELD = GenDatum(6, "Carl", a1, Assets({a2, a3, a4, a5})); // id is 6
        DATA_ASSETS_DIFFERENT_FIELD = GenDatum(7, "Carllol", a1, Assets({a2, a3, a5})); // id is 7
        DATA_ASSETS_DIFFERENT_CHANGED_FIELD = GenDatum(8, "Carllol", a1, Assets({a2, a3Changed, a5})); // id is 8
        DATA_ASSETS_SAME_NAME_ALL_CHANGED = GenDatum(
            9, "Lob", a1Changed, Assets({a2Changed, a3Changed, a4Changed})); // id is 9
        DATA_ASSETS_ASSET_SAME_NAME = GenDatum(10, "Lob2", a1, Assets({a1, a2, a3})); // id is 10
        std::monostate nil;
        DATA_NULL_ASSET = GenDatum(11, "Lob3", nil, Assets({a1, a2, a3})); // id is 11
        DATA_ASSET_IN_ASSETS = GenDatum(12, "Lob4", Assets({a1}), Assets({a2, a3, a4})); // id is 12
        DATA_NULL_ASSETS = GenDatum(13, "Lob5", Assets({a1}), nil); // id is 12
    }

    void CreateDB()
    {
        sqlite3 *db = nullptr;
        int errCode = sqlite3_open(STORE_PATH.c_str(), &db);
        if (errCode != SQLITE_OK) {
            LOGE("open db failed:%d", errCode);
            sqlite3_close(db);
            return;
        }
        const string sql =
            "PRAGMA journal_mode=WAL;";
        ASSERT_EQ(SQLiteUtils::ExecuteRawSQL(db, sql.c_str()), E_OK);
        sqlite3_close(db);
    }

    void InitStoreProp(const std::string &storePath, const std::string &appId, const std::string &userId,
        RelationalDBProperties &properties)
    {
        properties.SetStringProp(RelationalDBProperties::DATA_DIR, storePath);
        properties.SetStringProp(RelationalDBProperties::APP_ID, appId);
        properties.SetStringProp(RelationalDBProperties::USER_ID, userId);
        properties.SetStringProp(RelationalDBProperties::STORE_ID, STORE_ID);
        std::string identifier = userId + "-" + appId + "-" + STORE_ID;
        std::string hashIdentifier = DBCommon::TransferHashString(identifier);
        properties.SetStringProp(RelationalDBProperties::IDENTIFIER_DATA, hashIdentifier);
    }

    const RelationalSyncAbleStorage *GetRelationalStore()
    {
        RelationalDBProperties properties;
        InitStoreProp(STORE_PATH, APP_ID, USER_ID, properties);
        int errCode = E_OK;
        g_store = RelationalStoreInstance::GetDataBase(properties, errCode);
        if (g_store == nullptr) {
            LOGE("Get db failed:%d", errCode);
            return nullptr;
        }
        return static_cast<SQLiteRelationalStore *>(g_store)->GetStorageEngine();
    }

    class DistributedDBCloudAssetCompareTest : public testing::Test {
    public:
        static void SetUpTestCase(void);
        static void TearDownTestCase(void);
        void SetUp();
        void TearDown();
    };

    void DistributedDBCloudAssetCompareTest::SetUpTestCase(void)
    {
    }

    void DistributedDBCloudAssetCompareTest::TearDownTestCase(void)
    {
    }

    void DistributedDBCloudAssetCompareTest::SetUp(void)
    {
        DistributedDBToolsUnitTest::PrintTestCaseInfo();
        LOGD("Test dir is %s", TEST_DIR.c_str());
        CreateDB();
        ASSERT_EQ(g_mgr.OpenStore(STORE_PATH, STORE_ID, RelationalStoreDelegate::Option {}, g_delegate), DBStatus::OK);
        ASSERT_NE(g_delegate, nullptr);
        g_storageProxy = std::make_shared<TestStorageProxy>((ICloudSyncStorageInterface *) GetRelationalStore());
        ASSERT_NE(g_storageProxy, nullptr);
        g_cloudSyncer = std::make_shared<TestCloudSyncer>(g_storageProxy);
        ASSERT_NE(g_cloudSyncer, nullptr);
        g_cloudSyncer->SetAssetFields(TABLE_NAME, ASSET_FIELDS);
        GenData();
    }

    void DistributedDBCloudAssetCompareTest::TearDown(void)
    {
        if (g_delegate != nullptr) {
            EXPECT_EQ(g_mgr.CloseStore(g_delegate), DBStatus::OK);
            g_delegate = nullptr;
            g_storageProxy = nullptr;
            g_cloudSyncer = nullptr;
        }
        if (DistributedDBToolsUnitTest::RemoveTestDbFiles(TEST_DIR) != 0) {
            LOGE("rm test db files error.");
        }
    }

    static bool IsAssetEq(Asset &target, Asset &expected)
    {
        if (target.name != expected.name ||
            target.flag != expected.flag ||
            target.flag != expected.flag ||
            target.status != expected.status) {
            return false;
        }
        return true;
    }

    static bool CheckAssetDownloadList(std::string fieldName, std::map<std::string, Assets> &target,
        std::map<std::string, Assets> &expected)
    {
        if (target[fieldName].size() != expected[fieldName].size()) {
            return false;
        }
        for (size_t i = 0; i < target[fieldName].size(); i++) {
            if (!IsAssetEq(target[fieldName][i], expected[fieldName][i])) {
                return false;
            }
        }
        return true;
    }

    static void TagAsset(AssetOpType flag, AssetStatus status, Asset &asset)
    {
        asset.flag = static_cast<uint32_t>(flag);
        asset.status = static_cast<uint32_t>(status);
    }

    /**
     * @tc.name: AssetCmpTest001
     * @tc.desc:
     * @tc.type: FUNC
     * @tc.require:
     * @tc.author: wanyi
     */
    HWTEST_F(DistributedDBCloudAssetCompareTest, AssetCmpTest001, TestSize.Level0)
    {
        auto assetList = g_cloudSyncer->TestTagAssetsInSingleRecord(DATA_BASELINE, DATA_EMPTY);
        std::map<std::string, Assets> expectedList;
        TagAsset(AssetOpType::INSERT, AssetStatus::DOWNLOADING, a1);
        TagAsset(AssetOpType::INSERT, AssetStatus::DOWNLOADING, a2);
        TagAsset(AssetOpType::INSERT, AssetStatus::DOWNLOADING, a3);
        TagAsset(AssetOpType::INSERT, AssetStatus::DOWNLOADING, a4);
        expectedList[FIELD_HOUSE] = { a1 };
        expectedList[FIELD_CARS] = { a2, a3, a4 };
        ASSERT_TRUE(CheckAssetDownloadList(FIELD_HOUSE, assetList, expectedList));
        ASSERT_TRUE(CheckAssetDownloadList(FIELD_CARS, assetList, expectedList));
    }

    /**
     * @tc.name: AssetCmpTest002
     * @tc.desc:
     * @tc.type: FUNC
     * @tc.require:
     * @tc.author: wanyi
     */
    HWTEST_F(DistributedDBCloudAssetCompareTest, AssetCmpTest002, TestSize.Level0)
    {
        auto assetList = g_cloudSyncer->TestTagAssetsInSingleRecord(DATA_BASELINE, DATA_EMPTY_ASSET);
        std::map<std::string, Assets> expectedList;
        TagAsset(AssetOpType::INSERT, AssetStatus::DOWNLOADING, a1);
        TagAsset(AssetOpType::INSERT, AssetStatus::DOWNLOADING, a2);
        TagAsset(AssetOpType::INSERT, AssetStatus::DOWNLOADING, a3);
        TagAsset(AssetOpType::INSERT, AssetStatus::DOWNLOADING, a4);
        expectedList[FIELD_HOUSE] = { a1 };
        expectedList[FIELD_CARS] = { a2, a3, a4 };
        ASSERT_TRUE(CheckAssetDownloadList(FIELD_HOUSE, assetList, expectedList));
        ASSERT_TRUE(CheckAssetDownloadList(FIELD_CARS, assetList, expectedList));
    }

    /**
     * @tc.name: AssetCmpTest003
     * @tc.desc:
     * @tc.type: FUNC
     * @tc.require:
     * @tc.author: wanyi
     */
    HWTEST_F(DistributedDBCloudAssetCompareTest, AssetCmpTest003, TestSize.Level0)
    {
        auto assetList = g_cloudSyncer->TestTagAssetsInSingleRecord(DATA_BASELINE, DATA_ASSET_SAME_NAME_BUT_CHANGE);
        std::map<std::string, Assets> expectedList;
        TagAsset(AssetOpType::UPDATE, AssetStatus::DOWNLOADING, a1);
        expectedList[FIELD_HOUSE] = { a1 };
        expectedList[FIELD_CARS] = {};
        ASSERT_TRUE(CheckAssetDownloadList(FIELD_HOUSE, assetList, expectedList));
        ASSERT_TRUE(CheckAssetDownloadList(FIELD_CARS, assetList, expectedList));
    }

    /**
     * @tc.name: AssetCmpTest004
     * @tc.desc:
     * @tc.type: FUNC
     * @tc.require:
     * @tc.author: wanyi
     */
    HWTEST_F(DistributedDBCloudAssetCompareTest, AssetCmpTest004, TestSize.Level0)
    {
        auto assetList = g_cloudSyncer->TestTagAssetsInSingleRecord(
            DATA_BASELINE, DATA_ASSETS_SAME_NAME_PARTIALLY_CHANGED);
        std::map<std::string, Assets> expectedList;
        TagAsset(AssetOpType::UPDATE, AssetStatus::DOWNLOADING, a3);
        expectedList[FIELD_HOUSE] = {};
        expectedList[FIELD_CARS] = { a3 };
        ASSERT_TRUE(CheckAssetDownloadList(FIELD_HOUSE, assetList, expectedList));
        ASSERT_TRUE(CheckAssetDownloadList(FIELD_CARS, assetList, expectedList));
    }

    /**
     * @tc.name: AssetCmpTest005
     * @tc.desc:
     * @tc.type: FUNC
     * @tc.require:
     * @tc.author: wanyi
     */
    HWTEST_F(DistributedDBCloudAssetCompareTest, AssetCmpTest005, TestSize.Level0)
    {
        auto assetList = g_cloudSyncer->TestTagAssetsInSingleRecord(
            DATA_BASELINE, DATA_ALL_SAME);
        std::map<std::string, Assets> expectedList;
        expectedList[FIELD_HOUSE] = {};
        expectedList[FIELD_CARS] = {};
        ASSERT_TRUE(CheckAssetDownloadList(FIELD_HOUSE, assetList, expectedList));
        ASSERT_TRUE(CheckAssetDownloadList(FIELD_CARS, assetList, expectedList));
    }

    /**
     * @tc.name: AssetCmpTest006
     * @tc.desc:
     * @tc.type: FUNC
     * @tc.require:
     * @tc.author: wanyi
     */
    HWTEST_F(DistributedDBCloudAssetCompareTest, AssetCmpTest006, TestSize.Level0)
    {
        auto assetList = g_cloudSyncer->TestTagAssetsInSingleRecord(
            DATA_BASELINE, DATA_ASSETS_MORE_FIELD);
        std::map<std::string, Assets> expectedList;
        TagAsset(AssetOpType::DELETE, AssetStatus::DOWNLOADING, a5);
        expectedList[FIELD_HOUSE] = {};
        expectedList[FIELD_CARS] = { a5 };
        ASSERT_TRUE(CheckAssetDownloadList(FIELD_HOUSE, assetList, expectedList));
        ASSERT_TRUE(CheckAssetDownloadList(FIELD_CARS, assetList, expectedList));
    }

    /**
     * @tc.name: AssetCmpTest007
     * @tc.desc:
     * @tc.type: FUNC
     * @tc.require:
     * @tc.author: wanyi
     */
    HWTEST_F(DistributedDBCloudAssetCompareTest, AssetCmpTest007, TestSize.Level0)
    {
        auto assetList = g_cloudSyncer->TestTagAssetsInSingleRecord(
            DATA_BASELINE, DATA_ASSETS_DIFFERENT_FIELD);
        std::map<std::string, Assets> expectedList;
        TagAsset(AssetOpType::DELETE, AssetStatus::DOWNLOADING, a5);
        TagAsset(AssetOpType::INSERT, AssetStatus::DOWNLOADING, a4);
        expectedList[FIELD_HOUSE] = {};
        expectedList[FIELD_CARS] = { a5, a4 };
        ASSERT_TRUE(CheckAssetDownloadList(FIELD_HOUSE, assetList, expectedList));
        ASSERT_TRUE(CheckAssetDownloadList(FIELD_CARS, assetList, expectedList));
    }

    /**
     * @tc.name: AssetCmpTest008
     * @tc.desc:
     * @tc.type: FUNC
     * @tc.require:
     * @tc.author: wanyi
     */
    HWTEST_F(DistributedDBCloudAssetCompareTest, AssetCmpTest008, TestSize.Level0)
    {
        auto assetList = g_cloudSyncer->TestTagAssetsInSingleRecord(
            DATA_BASELINE, DATA_ASSETS_DIFFERENT_CHANGED_FIELD);
        std::map<std::string, Assets> expectedList;
        TagAsset(AssetOpType::UPDATE, AssetStatus::DOWNLOADING, a3);
        TagAsset(AssetOpType::DELETE, AssetStatus::DOWNLOADING, a5);
        TagAsset(AssetOpType::INSERT, AssetStatus::DOWNLOADING, a4);
        expectedList[FIELD_HOUSE] = {};
        expectedList[FIELD_CARS] = { a3, a5, a4 };
        ASSERT_TRUE(CheckAssetDownloadList(FIELD_HOUSE, assetList, expectedList));
        ASSERT_TRUE(CheckAssetDownloadList(FIELD_CARS, assetList, expectedList));
    }

    /**
     * @tc.name: AssetCmpTest009
     * @tc.desc:
     * @tc.type: FUNC
     * @tc.require:
     * @tc.author: wanyi
     */
    HWTEST_F(DistributedDBCloudAssetCompareTest, AssetCmpTest009, TestSize.Level0)
    {
        auto assetList = g_cloudSyncer->TestTagAssetsInSingleRecord(
            DATA_BASELINE, DATA_ASSETS_SAME_NAME_ALL_CHANGED);
        std::map<std::string, Assets> expectedList;
        TagAsset(AssetOpType::UPDATE, AssetStatus::DOWNLOADING, a1);
        TagAsset(AssetOpType::UPDATE, AssetStatus::DOWNLOADING, a2);
        TagAsset(AssetOpType::UPDATE, AssetStatus::DOWNLOADING, a3);
        TagAsset(AssetOpType::UPDATE, AssetStatus::DOWNLOADING, a4);
        expectedList[FIELD_HOUSE] = { a1 };
        expectedList[FIELD_CARS] = { a2, a3, a4 };
        ASSERT_TRUE(CheckAssetDownloadList(FIELD_HOUSE, assetList, expectedList));
        ASSERT_TRUE(CheckAssetDownloadList(FIELD_CARS, assetList, expectedList));
    }

    /**
     * @tc.name: AssetCmpTest010
     * @tc.desc:
     * @tc.type: FUNC
     * @tc.require:
     * @tc.author: wanyi
     */
    HWTEST_F(DistributedDBCloudAssetCompareTest, AssetCmpTest010, TestSize.Level0)
    {
        auto assetList = g_cloudSyncer->TestTagAssetsInSingleRecord(
            DATA_EMPTY_ASSET, DATA_BASELINE);
        std::map<std::string, Assets> expectedList;
        TagAsset(AssetOpType::DELETE, AssetStatus::DOWNLOADING, a1);
        TagAsset(AssetOpType::DELETE, AssetStatus::DOWNLOADING, a2);
        TagAsset(AssetOpType::DELETE, AssetStatus::DOWNLOADING, a3);
        TagAsset(AssetOpType::DELETE, AssetStatus::DOWNLOADING, a4);
        expectedList[FIELD_HOUSE] = { a1 };
        expectedList[FIELD_CARS] = { a2, a3, a4 };
        ASSERT_TRUE(CheckAssetDownloadList(FIELD_HOUSE, assetList, expectedList));
        ASSERT_TRUE(CheckAssetDownloadList(FIELD_CARS, assetList, expectedList));
    }

    /**
     * @tc.name: AssetCmpTest011
     * @tc.desc:
     * @tc.type: FUNC
     * @tc.require:
     * @tc.author: wanyi
     */
    HWTEST_F(DistributedDBCloudAssetCompareTest, AssetCmpTest011, TestSize.Level0)
    {
        auto assetList = g_cloudSyncer->TestTagAssetsInSingleRecord(
            DATA_EMPTY_ASSET, DATA_ASSETS_ASSET_SAME_NAME);
        std::map<std::string, Assets> expectedList;
        TagAsset(AssetOpType::DELETE, AssetStatus::DOWNLOADING, a1);
        TagAsset(AssetOpType::DELETE, AssetStatus::DOWNLOADING, a2);
        TagAsset(AssetOpType::DELETE, AssetStatus::DOWNLOADING, a3);
        expectedList[FIELD_HOUSE] = { a1 };
        expectedList[FIELD_CARS] = { a1, a2, a3 };
        ASSERT_TRUE(CheckAssetDownloadList(FIELD_HOUSE, assetList, expectedList));
        ASSERT_TRUE(CheckAssetDownloadList(FIELD_CARS, assetList, expectedList));
    }

    /**
     * @tc.name: AssetCmpTest012
     * @tc.desc:
     * @tc.type: FUNC
     * @tc.require:
     * @tc.author: wanyi
     */
    HWTEST_F(DistributedDBCloudAssetCompareTest, AssetCmpTest012, TestSize.Level0)
    {
        auto assetList = g_cloudSyncer->TestTagAssetsInSingleRecord(
            DATA_EMPTY_ASSET, DATA_ASSETS_ASSET_SAME_NAME);
        std::map<std::string, Assets> expectedList;
        TagAsset(AssetOpType::DELETE, AssetStatus::DOWNLOADING, a1);
        TagAsset(AssetOpType::DELETE, AssetStatus::DOWNLOADING, a2);
        TagAsset(AssetOpType::DELETE, AssetStatus::DOWNLOADING, a3);
        expectedList[FIELD_HOUSE] = { a1 };
        expectedList[FIELD_CARS] = { a1, a2, a3 };
        ASSERT_TRUE(CheckAssetDownloadList(FIELD_HOUSE, assetList, expectedList));
        ASSERT_TRUE(CheckAssetDownloadList(FIELD_CARS, assetList, expectedList));
    }

    /**
     * @tc.name: AssetCmpTest013
     * @tc.desc:
     * @tc.type: FUNC
     * @tc.require:
     * @tc.author: wanyi
     */
    HWTEST_F(DistributedDBCloudAssetCompareTest, AssetCmpTest013, TestSize.Level0)
    {
        auto assetList = g_cloudSyncer->TestTagAssetsInSingleRecord(
            DATA_BASELINE, DATA_ASSET_IN_ASSETS);
        std::map<std::string, Assets> expectedList;
        TagAsset(AssetOpType::NO_CHANGE, AssetStatus::DOWNLOADING, a1);
        TagAsset(AssetOpType::NO_CHANGE, AssetStatus::DOWNLOADING, a2);
        TagAsset(AssetOpType::NO_CHANGE, AssetStatus::DOWNLOADING, a3);
        TagAsset(AssetOpType::NO_CHANGE, AssetStatus::DOWNLOADING, a4);
        expectedList[FIELD_HOUSE] = {};
        expectedList[FIELD_CARS] = {};
        ASSERT_TRUE(CheckAssetDownloadList(FIELD_HOUSE, assetList, expectedList));
        ASSERT_TRUE(CheckAssetDownloadList(FIELD_CARS, assetList, expectedList));
    }

    /**
     * @tc.name: AssetCmpTest014
     * @tc.desc:
     * @tc.type: FUNC
     * @tc.require:
     * @tc.author: wanyi
     */
    HWTEST_F(DistributedDBCloudAssetCompareTest, AssetCmpTest014, TestSize.Level0)
    {
        auto assetList = g_cloudSyncer->TestTagAssetsInSingleRecord(
            DATA_BASELINE, DATA_NULL_ASSETS);
        std::map<std::string, Assets> expectedList;
        TagAsset(AssetOpType::NO_CHANGE, AssetStatus::DOWNLOADING, a1);
        TagAsset(AssetOpType::INSERT, AssetStatus::DOWNLOADING, a2);
        TagAsset(AssetOpType::INSERT, AssetStatus::DOWNLOADING, a3);
        TagAsset(AssetOpType::INSERT, AssetStatus::DOWNLOADING, a4);
        expectedList[FIELD_HOUSE] = {};
        expectedList[FIELD_CARS] = { a2, a3, a4 };
        ASSERT_TRUE(CheckAssetDownloadList(FIELD_HOUSE, assetList, expectedList));
        ASSERT_TRUE(CheckAssetDownloadList(FIELD_CARS, assetList, expectedList));
    }


    /**
     * @tc.name: AssetCmpTest015
     * @tc.desc:
     * @tc.type: FUNC
     * @tc.require:
     * @tc.author: wanyi
     */
    HWTEST_F(DistributedDBCloudAssetCompareTest, AssetCmpTest015, TestSize.Level0)
    {
        auto assetList = g_cloudSyncer->TestTagAssetsInSingleRecord(DATA_ASSET_SAME_NAME_BUT_CHANGE, DATA_BASELINE);
        std::map<std::string, Assets> expectedList;
        TagAsset(AssetOpType::UPDATE, AssetStatus::DOWNLOADING, a1Changed);
        expectedList[FIELD_HOUSE] = { a1Changed };
        expectedList[FIELD_CARS] = {};
        ASSERT_TRUE(CheckAssetDownloadList(FIELD_HOUSE, assetList, expectedList));
        ASSERT_TRUE(CheckAssetDownloadList(FIELD_CARS, assetList, expectedList));
    }

    /**
     * @tc.name: AssetCmpTest016
     * @tc.desc:
     * @tc.type: FUNC
     * @tc.require:
     * @tc.author: wanyi
     */
    HWTEST_F(DistributedDBCloudAssetCompareTest, AssetCmpTest016, TestSize.Level0)
    {
        auto assetList = g_cloudSyncer->TestTagAssetsInSingleRecord(DATA_BASELINE, DATA_ASSET_SAME_NAME_BUT_CHANGE);
        EXPECT_EQ(std::get<Asset>(DATA_BASELINE[FIELD_HOUSE]).flag, static_cast<uint32_t>(AssetOpType::UPDATE));
    }

    /**
     * @tc.name: AssetCmpTest017
     * @tc.desc:
     * @tc.type: FUNC
     * @tc.require:
     * @tc.author: wanyi
     */
    HWTEST_F(DistributedDBCloudAssetCompareTest, AssetCmpTest017, TestSize.Level0)
    {
        auto assetList = g_cloudSyncer->TestTagAssetsInSingleRecord(
            DATA_BASELINE, DATA_ASSETS_SAME_NAME_PARTIALLY_CHANGED, true);
        EXPECT_EQ(std::get<Assets>(DATA_BASELINE[FIELD_CARS])[0].flag, static_cast<uint32_t>(AssetOpType::NO_CHANGE));
        EXPECT_EQ(std::get<Assets>(DATA_BASELINE[FIELD_CARS])[1].flag, static_cast<uint32_t>(AssetOpType::UPDATE));
        EXPECT_EQ(std::get<Assets>(DATA_BASELINE[FIELD_CARS])[2].flag, static_cast<uint32_t>(AssetOpType::NO_CHANGE));
    }

    /**
     * @tc.name: AssetCmpTest018
     * @tc.desc:
     * @tc.type: FUNC
     * @tc.require:
     * @tc.author: wanyi
     */
    HWTEST_F(DistributedDBCloudAssetCompareTest, AssetCmpTest018, TestSize.Level0)
    {
        auto assetList = g_cloudSyncer->TestTagAssetsInSingleRecord(
            DATA_BASELINE, DATA_EMPTY, true);
        EXPECT_EQ(std::get<Asset>(DATA_BASELINE[FIELD_HOUSE]).flag, static_cast<uint32_t>(AssetOpType::INSERT));
        EXPECT_EQ(std::get<Assets>(DATA_BASELINE[FIELD_CARS])[0].flag, static_cast<uint32_t>(AssetOpType::INSERT));
        EXPECT_EQ(std::get<Assets>(DATA_BASELINE[FIELD_CARS])[1].flag, static_cast<uint32_t>(AssetOpType::INSERT));
        EXPECT_EQ(std::get<Assets>(DATA_BASELINE[FIELD_CARS])[2].flag, static_cast<uint32_t>(AssetOpType::INSERT));
    }

    /**
     * @tc.name: AssetCmpTest019
     * @tc.desc:
     * @tc.type: FUNC
     * @tc.require:
     * @tc.author: wanyi
     */
    HWTEST_F(DistributedDBCloudAssetCompareTest, AssetCmpTest019, TestSize.Level0)
    {
        auto assetList = g_cloudSyncer->TestTagAssetsInSingleRecord(
            DATA_EMPTY, DATA_BASELINE, true);
        EXPECT_EQ(std::get<Assets>(DATA_EMPTY[FIELD_CARS])[0].flag, static_cast<uint32_t>(AssetOpType::DELETE));
        EXPECT_EQ(std::get<Assets>(DATA_EMPTY[FIELD_CARS])[1].flag, static_cast<uint32_t>(AssetOpType::DELETE));
        EXPECT_EQ(std::get<Assets>(DATA_EMPTY[FIELD_CARS])[2].flag, static_cast<uint32_t>(AssetOpType::DELETE));
    }
}