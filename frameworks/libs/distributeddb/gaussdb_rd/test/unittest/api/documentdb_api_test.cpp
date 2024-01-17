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

#include "doc_errno.h"
#include "doc_limit.h"
#include "documentdb_test_utils.h"
#include "grd_base/grd_db_api.h"
#include "grd_base/grd_error.h"
#include "grd_document/grd_document_api.h"
#include "rd_log_print.h"
#include "rd_sqlite_utils.h"

using namespace DocumentDB;
using namespace testing::ext;
using namespace DocumentDBUnitTest;

namespace {
class DocumentDBApiTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void DocumentDBApiTest::SetUpTestCase(void) {}

void DocumentDBApiTest::TearDownTestCase(void) {}

void DocumentDBApiTest::SetUp(void) {}

void DocumentDBApiTest::TearDown(void)
{
    DocumentDBTestUtils::RemoveTestDbFiles("./document.db");
}

/**
 * @tc.name: OpenDBTest001
 * @tc.desc: Test open document db
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: lianhuix
 */
HWTEST_F(DocumentDBApiTest, OpenDBTest001, TestSize.Level0)
{
    std::string path = "./document.db";
    GRD_DB *db = nullptr;
    int status = GRD_DBOpen(path.c_str(), nullptr, GRD_DB_OPEN_CREATE, &db);
    EXPECT_EQ(status, GRD_OK);
    EXPECT_NE(db, nullptr);
    GLOGD("Open DB test 001: status: %d", status);

    EXPECT_EQ(GRD_CreateCollection(db, "student", "", 0), GRD_OK);
    EXPECT_EQ(GRD_UpsertDoc(db, "student", R""({"_id":"10001"})"", R""({"name":"Tom", "age":23})"", 0), 1);
    EXPECT_EQ(GRD_DropCollection(db, "student", 0), GRD_OK);
    status = GRD_DBClose(db, GRD_DB_CLOSE);
    EXPECT_EQ(status, GRD_OK);
    db = nullptr;

    DocumentDBTestUtils::RemoveTestDbFiles(path);
}

/**
 * @tc.name: OpenDBTest002
 * @tc.desc: Test open document db with invalid db
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: lianhuix
 */
HWTEST_F(DocumentDBApiTest, OpenDBTest002, TestSize.Level0)
{
    std::string path = "./document.db";
    int status = GRD_DBOpen(path.c_str(), nullptr, GRD_DB_OPEN_CREATE, nullptr);
    EXPECT_EQ(status, GRD_INVALID_ARGS);

    GRD_DB *db = nullptr;
    status = GRD_DBOpen(path.c_str(), nullptr, GRD_DB_OPEN_CREATE, &db);
    EXPECT_EQ(status, GRD_OK);
    EXPECT_NE(db, nullptr);

    status = GRD_DBClose(db, GRD_DB_CLOSE);
    EXPECT_EQ(status, GRD_OK);

    status = GRD_DBOpen(path.c_str(), nullptr, GRD_DB_OPEN_CREATE, &db);
    EXPECT_EQ(status, GRD_OK);

    status = GRD_DBClose(db, GRD_DB_CLOSE);
    EXPECT_EQ(status, GRD_OK);
}

HWTEST_F(DocumentDBApiTest, OpenDBTest003, TestSize.Level0)
{
    std::string path = "./document.db";
    GRD_DB *db = nullptr;
    int status = GRD_DBOpen(path.c_str(), nullptr, GRD_DB_OPEN_CREATE, &db);
    EXPECT_EQ(status, GRD_OK);
    EXPECT_NE(db, nullptr);
    GLOGD("Open DB test 003: status: %d", status);

    GRD_DB *db1 = nullptr;
    status = GRD_DBOpen(path.c_str(), nullptr, GRD_DB_OPEN_CREATE, &db1);
    EXPECT_EQ(status, GRD_OK);
    EXPECT_NE(db1, nullptr);

    status = GRD_DBClose(db, GRD_DB_CLOSE);
    EXPECT_EQ(status, GRD_OK);

    status = GRD_DBClose(db1, GRD_DB_CLOSE);
    EXPECT_EQ(status, GRD_OK);
}

/**
 * @tc.name: OpenDBTest004
 * @tc.desc: Test open document db while db is not db file
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: zhuwentao
 */
HWTEST_F(DocumentDBApiTest, OpenDBTest004, TestSize.Level0)
{
    std::string path = "./test.txt";
    FILE *fp;
    fp = fopen("./test.txt", "w");
    fwrite("hello", 5, 5, fp);
    fclose(fp);
    GRD_DB *db = nullptr;
    int status = GRD_DBOpen(path.c_str(), nullptr, GRD_DB_OPEN_ONLY, &db);
    EXPECT_EQ(status, GRD_INVALID_FILE_FORMAT);

    DocumentDBTestUtils::RemoveTestDbFiles(path);
}

/**
 * @tc.name: OpenDBPathTest001
 * @tc.desc: Test open document db with NULL path
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: lianhuix
 */
HWTEST_F(DocumentDBApiTest, OpenDBPathTest001, TestSize.Level0)
{
    GRD_DB *db = nullptr;
    std::vector<const char *> invalidPath = { nullptr, "" };
    for (auto path : invalidPath) {
        GLOGD("OpenDBPathTest001: open db with path: %s", path);
        int status = GRD_DBOpen(path, nullptr, GRD_DB_OPEN_CREATE, &db);
        EXPECT_EQ(status, GRD_INVALID_ARGS);
    }
}

/**
 * @tc.name: OpenDBPathTest002
 * @tc.desc: Test open document db with file no permission
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: lianhuix
 */
HWTEST_F(DocumentDBApiTest, OpenDBPathTest002, TestSize.Level0)
{
    GRD_DB *db = nullptr;
    std::string pathNoPerm = "/root/document.db";
    int status = GRD_DBOpen(pathNoPerm.c_str(), nullptr, GRD_DB_OPEN_CREATE, &db);
    EXPECT_EQ(status, GRD_FAILED_FILE_OPERATION);
}

/**
 * @tc.name: OpenDBPathTest004
 * @tc.desc: call GRD_DBOpen, input dbFile as existed menu
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: mazhao
 */
HWTEST_F(DocumentDBApiTest, OpenDBPathTest004, TestSize.Level0)
{
    GRD_DB *db = nullptr;
    std::string pathNoPerm = "../test";
    int status = GRD_DBOpen(pathNoPerm.c_str(), nullptr, GRD_DB_OPEN_CREATE, &db);
    EXPECT_EQ(status, GRD_INVALID_ARGS);
}

/**
 * @tc.name: OpenDBConfigTest001
 * @tc.desc: Test open document db with invalid config option
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: lianhuix
 */
HWTEST_F(DocumentDBApiTest, OpenDBConfigTest001, TestSize.Level0)
{
    GRD_DB *db = nullptr;
    std::string path = "./document.db";
    const int MAX_JSON_LEN = 1024 * 1024;
    std::string configStr = std::string(MAX_JSON_LEN, 'a');
    int status = GRD_DBOpen(path.c_str(), configStr.c_str(), GRD_DB_OPEN_CREATE, &db);
    EXPECT_EQ(status, GRD_OVER_LIMIT);
}

/**
 * @tc.name: OpenDBConfigTest002
 * @tc.desc: Test open document db with invalid config format
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: lianhuix
 */
HWTEST_F(DocumentDBApiTest, OpenDBConfigTest002, TestSize.Level0)
{
    GRD_DB *db = nullptr;
    std::string path = "./document.db";
    int status = GRD_DBOpen(path.c_str(), "{aa}", GRD_DB_OPEN_CREATE, &db);
    EXPECT_EQ(status, GRD_INVALID_FORMAT);
}

/**
 * @tc.name: OpenDBConfigTest003
 * @tc.desc: Test open document db with config not support
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: lianhuix
 */
HWTEST_F(DocumentDBApiTest, OpenDBConfigTest003, TestSize.Level0)
{
    GRD_DB *db = nullptr;
    std::string path = "./document.db";
    int status = GRD_DBOpen(path.c_str(), R""({"notSupport":123})"", GRD_DB_OPEN_CREATE, &db);
    EXPECT_EQ(status, GRD_INVALID_ARGS);
}

/**
 * @tc.name: OpenDBConfigTest004
 * @tc.desc: call GRD_DBOpen, input the value's length of configStr is 1024K
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: mazhao
 */

HWTEST_F(DocumentDBApiTest, OpenDBConfigTest004, TestSize.Level0)
{
    /**
     * @tc.steps:step1. input the value's length of configStr is 1024 k(not contained '\0')
    */
    GRD_DB *db = nullptr;
    std::string part1 = "{ \"pageSize\": \" ";
    std::string part2 = "\" }";
    std::string path = "./document.db";
    std::string val = string(MAX_DB_CONFIG_LEN - part1.size() - part2.size(), 'k');
    std::string configStr = part1 + val + part2;
    int ret = GRD_DBOpen(path.c_str(), configStr.c_str(), GRD_DB_OPEN_CREATE, &db);
    EXPECT_EQ(ret, GRD_OVER_LIMIT);
    /**
     * @tc.steps:step2. input the value's length of configStr is 1024 k(contained '\0')
    */
    std::string val2 = string(MAX_DB_CONFIG_LEN - part1.size() - part2.size() - 1, 'k');
    std::string configStr2 = part1 + val2 + part2 + "\0";
    ret = GRD_DBOpen(path.c_str(), configStr2.c_str(), GRD_DB_OPEN_CREATE, &db);
    EXPECT_EQ(ret, GRD_INVALID_ARGS);
}

/**
 * @tc.name: OpenDBConfigTest005
 * @tc.desc: Verify open db with different configStr connection when first connection not close,
 *           return GRD_INVALID_CONFIG_VALUE.
 * @tc.require:
 * @tc.author: mazhao
 */
HWTEST_F(DocumentDBApiTest, OpenDBConfigTest005, TestSize.Level0)
{
    /**
     * @tc.steps:step1. call GRD_DBOPEN to create a db with connection1.
     * @tc.expected:step1. GRD_OK.
    */
    const char *configStr = R"({"pageSize":64, "bufferPoolSize": 4096})";
    GRD_DB *db1 = nullptr;
    std::string path = "./document.db";
    int result = GRD_DBOpen(path.c_str(), configStr, GRD_DB_OPEN_CREATE, &db1);
    ASSERT_EQ(result, GRD_OK);
    /**
     * @tc.steps:step2. connection2 call GRD_DBOpen to open the db with the different configStr.
     * @tc.expected:step2. return GRD_CONFIG_OPTION_MISMATCH.
    */
    const char *configStr_2 = R"({"pageSize":4})";
    GRD_DB *db2 = nullptr;
    result = GRD_DBOpen(path.c_str(), configStr_2, GRD_DB_OPEN_ONLY, &db2);
    ASSERT_EQ(result, GRD_INVALID_ARGS);

    ASSERT_EQ(GRD_DBClose(db1, GRD_DB_CLOSE), GRD_OK);
}
/**
 * @tc.name: OpenDBConfigMaxConnNumTest001
 * @tc.desc: Test open document db with invalid config item maxConnNum
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: lianhuix
 */
HWTEST_F(DocumentDBApiTest, OpenDBConfigMaxConnNumTest001, TestSize.Level0)
{
    GRD_DB *db = nullptr;
    std::string path = "./document.db";

    std::vector<std::string> configList = {
        R""({"maxConnNum":0})"",
        R""({"maxConnNum":15})"",
        R""({"maxConnNum":1025})"",
        R""({"maxConnNum":1000000007})"",
        R""({"maxConnNum":"16"})"",
        R""({"maxConnNum":{"value":17}})"",
        R""({"maxConnNum":[16, 17, 18]})"",
    };
    for (const auto &config : configList) {
        GLOGD("OpenDBConfigMaxConnNumTest001: test with config:%s", config.c_str());
        int status = GRD_DBOpen(path.c_str(), config.c_str(), GRD_DB_OPEN_CREATE, &db);
        ASSERT_EQ(status, GRD_INVALID_ARGS);
    }
}

/**
 * @tc.name: OpenDBConfigMaxConnNumTest002
 * @tc.desc: Test open document db with valid item maxConnNum
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: lianhuix
 */
HWTEST_F(DocumentDBApiTest, OpenDBConfigMaxConnNumTest002, TestSize.Level1)
{
    GRD_DB *db = nullptr;
    std::string path = "./document.db";

    for (int i = 16; i <= 1024; i++) {
        std::string config = "{\"maxConnNum\":" + std::to_string(i) + "}";
        int status = GRD_DBOpen(path.c_str(), config.c_str(), GRD_DB_OPEN_CREATE, &db);
        EXPECT_EQ(status, GRD_OK);
        ASSERT_NE(db, nullptr);

        status = GRD_DBClose(db, GRD_DB_CLOSE);
        EXPECT_EQ(status, GRD_OK);
        db = nullptr;

        DocumentDBTestUtils::RemoveTestDbFiles(path);
    }
}

/**
 * @tc.name: OpenDBConfigMaxConnNumTest003
 * @tc.desc: Test reopen document db with different maxConnNum
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: lianhuix
 */
HWTEST_F(DocumentDBApiTest, OpenDBConfigMaxConnNumTest003, TestSize.Level1)
{
    GRD_DB *db = nullptr;
    std::string path = "./document.db";

    std::string config = R""({"maxConnNum":16})"";
    int status = GRD_DBOpen(path.c_str(), config.c_str(), GRD_DB_OPEN_CREATE, &db);
    EXPECT_EQ(status, GRD_OK);

    GRD_DB *db1 = nullptr;
    config = R""({"maxConnNum":17})"";
    status = GRD_DBOpen(path.c_str(), config.c_str(), GRD_DB_OPEN_CREATE, &db1);
    EXPECT_EQ(status, GRD_INVALID_ARGS);

    status = GRD_DBClose(db, GRD_DB_CLOSE);
    EXPECT_EQ(status, GRD_OK);
    db = nullptr;
    DocumentDBTestUtils::RemoveTestDbFiles(path);
}

/**
 * @tc.name: OpenDBConfigMaxConnNumTest004
 * @tc.desc: Test open document db over maxConnNum
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: lianhuix
 */
HWTEST_F(DocumentDBApiTest, OpenDBConfigMaxConnNumTest004, TestSize.Level1)
{
    std::string path = "./document.db";

    int maxCnt = 16;
    std::string config = "{\"maxConnNum\":" + std::to_string(maxCnt) + "}";

    std::vector<GRD_DB *> dbList;
    while (maxCnt--) {
        GRD_DB *db = nullptr;
        int status = GRD_DBOpen(path.c_str(), config.c_str(), GRD_DB_OPEN_CREATE, &db);
        EXPECT_EQ(status, GRD_OK);
        EXPECT_NE(db, nullptr);
        dbList.push_back(db);
    }

    GRD_DB *db = nullptr;
    int status = GRD_DBOpen(path.c_str(), config.c_str(), GRD_DB_OPEN_CREATE, &db);
    EXPECT_EQ(status, GRD_OK);
    EXPECT_NE(db, nullptr);
    dbList.push_back(db);

    for (auto *it : dbList) {
        status = GRD_DBClose(it, GRD_DB_CLOSE);
        EXPECT_EQ(status, GRD_OK);
    }

    DocumentDBTestUtils::RemoveTestDbFiles(path);
}

/**
 * @tc.name: OpenDBConfigPageSizeTest001
 * @tc.desc: Test open document db with invalid config item pageSize
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: lianhuix
 */
HWTEST_F(DocumentDBApiTest, OpenDBConfigPageSizeTest001, TestSize.Level0)
{
    GRD_DB *db = nullptr;
    std::string path = "./document.db";

    std::vector<std::string> configList = {
        R""({"pageSize":0})"",
        R""({"pageSize":5})"",
        R""({"pageSize":48})"",
        R""({"pageSize":1000000007})"",
        R""({"pageSize":"4"})"",
        R""({"pageSize":{"value":8}})"",
        R""({"pageSize":[16, 32, 64]})"",
    };
    for (const auto &config : configList) {
        GLOGD("OpenDBConfigPageSizeTest001: test with config:%s", config.c_str());
        int status = GRD_DBOpen(path.c_str(), config.c_str(), 0, &db);
        EXPECT_EQ(status, GRD_INVALID_ARGS);
    }
}

namespace {
int GetDBPageSize(const std::string &path)
{
    sqlite3 *db = nullptr;
    int ret = RDSQLiteUtils::CreateDataBase(path, 0, db);
    EXPECT_EQ(ret, E_OK);
    if (db == nullptr) {
        return 0;
    }
    int pageSize = 0;
    RDSQLiteUtils::ExecSql(db, "PRAGMA page_size;", nullptr, [&pageSize](sqlite3_stmt *stmt, bool &isMatchOneData) {
        pageSize = sqlite3_column_int(stmt, 0);
        return E_OK;
    });

    sqlite3_close_v2(db);
    return pageSize;
}
} // namespace

/**
 * @tc.name: OpenDBConfigPageSizeTest002
 * @tc.desc: Test open document db with valid config item pageSize
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: lianhuix
 */
HWTEST_F(DocumentDBApiTest, OpenDBConfigPageSizeTest002, TestSize.Level0)
{
    GRD_DB *db = nullptr;
    std::string path = "./document.db";

    for (int size : { 4, 8, 16, 32, 64 }) {
        std::string config = "{\"pageSize\":" + std::to_string(size) + "}";
        int status = GRD_DBOpen(path.c_str(), config.c_str(), GRD_DB_OPEN_CREATE, &db);
        EXPECT_EQ(status, GRD_OK);

        status = GRD_DBClose(db, GRD_DB_CLOSE);
        EXPECT_EQ(status, GRD_OK);
        db = nullptr;

        EXPECT_EQ(GetDBPageSize(path), size * 1024);
        DocumentDBTestUtils::RemoveTestDbFiles(path);
    }
}

/**
 * @tc.name: OpenDBConfigPageSizeTest003
 * @tc.desc: Test reopen document db with different pageSize
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: lianhuix
 */
HWTEST_F(DocumentDBApiTest, OpenDBConfigPageSizeTest003, TestSize.Level1)
{
    GRD_DB *db = nullptr;
    std::string path = "./document.db";

    std::string config = R""({"pageSize":4})"";
    int status = GRD_DBOpen(path.c_str(), config.c_str(), GRD_DB_OPEN_CREATE, &db);
    EXPECT_EQ(status, GRD_OK);

    status = GRD_DBClose(db, GRD_DB_CLOSE);
    EXPECT_EQ(status, GRD_OK);
    db = nullptr;

    config = R""({"pageSize":8})"";
    status = GRD_DBOpen(path.c_str(), config.c_str(), GRD_DB_OPEN_CREATE, &db);
    EXPECT_EQ(status, GRD_INVALID_ARGS);

    DocumentDBTestUtils::RemoveTestDbFiles(path);
}

/**
 * @tc.name: OpenDBConfigRedoFlushTest001
 * @tc.desc: Test open document db with valid config item redoFlushByTrx
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: lianhuix
 */
HWTEST_F(DocumentDBApiTest, OpenDBConfigRedoFlushTest001, TestSize.Level0)
{
    GRD_DB *db = nullptr;
    std::string path = "./document.db";

    for (int flush : { 0, 1 }) {
        std::string config = "{\"redoFlushByTrx\":" + std::to_string(flush) + "}";
        int status = GRD_DBOpen(path.c_str(), config.c_str(), GRD_DB_OPEN_CREATE, &db);
        EXPECT_EQ(status, GRD_OK);

        status = GRD_DBClose(db, GRD_DB_CLOSE);
        EXPECT_EQ(status, GRD_OK);
        db = nullptr;

        DocumentDBTestUtils::RemoveTestDbFiles(path);
    }
}

/**
 * @tc.name: OpenDBConfigXXXTest001
 * @tc.desc: Test open document db with invalid config item redoFlushByTrx
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: lianhuix
 */
HWTEST_F(DocumentDBApiTest, OpenDBConfigRedoFlushTest002, TestSize.Level0)
{
    GRD_DB *db = nullptr;
    std::string path = "./document.db";

    std::string config = R""({"redoFlushByTrx":3})"";
    int status = GRD_DBOpen(path.c_str(), config.c_str(), GRD_DB_OPEN_CREATE, &db);
    EXPECT_EQ(status, GRD_INVALID_ARGS);
}

/**
 * @tc.name: OpenDBConfigBufferPoolTest001
 * @tc.desc: Test open document db with invalid config item bufferPoolSize
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: lianhuix
 */
HWTEST_F(DocumentDBApiTest, OpenDBConfigBufferPoolTest001, TestSize.Level0)
{
    GRD_DB *db = nullptr;
    std::string path = "./document.db";

    int status = GRD_DBOpen(path.c_str(), R""({"pageSize":64, "bufferPoolSize":4096})"", GRD_DB_OPEN_CREATE, &db);
    EXPECT_EQ(status, GRD_OK);
    EXPECT_EQ(GRD_DBClose(db, 0), GRD_OK);

    status = GRD_DBOpen(path.c_str(), R""({"pageSize":64, "bufferPoolSize":4095})"", GRD_DB_OPEN_CREATE, &db);
    EXPECT_EQ(status, GRD_INVALID_ARGS);

    status = GRD_DBOpen(path.c_str(), R""({"bufferPoolSize":1023})"", GRD_DB_OPEN_CREATE, &db);
    EXPECT_EQ(status, GRD_INVALID_ARGS);

    status = GRD_DBOpen(path.c_str(), R""({"bufferPoolSize":4194304})"", GRD_DB_OPEN_CREATE, &db);
    EXPECT_EQ(status, GRD_INVALID_ARGS);
}

/**
 * @tc.name: OpenDBConfigPubBuffTest001
 * @tc.desc: Test open document db with invalid config item redopubbufsize
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: lianhuix
 */
HWTEST_F(DocumentDBApiTest, OpenDBConfigPubBuffTest001, TestSize.Level0)
{
    GRD_DB *db = nullptr;
    std::string path = "./document.db";

    int status = GRD_DBOpen(path.c_str(), R""({"pageSize":64, "redopubbufsize":4033})"", GRD_DB_OPEN_CREATE, &db);
    EXPECT_EQ(status, GRD_OK);
    EXPECT_EQ(GRD_DBClose(db, 0), GRD_OK);

    status = GRD_DBOpen(path.c_str(), R""({"pageSize":64, "redopubbufsize":4032})"", GRD_DB_OPEN_CREATE, &db);
    EXPECT_EQ(status, GRD_INVALID_ARGS);

    status = GRD_DBOpen(path.c_str(), R""({"redopubbufsize":255})"", GRD_DB_OPEN_CREATE, &db);
    EXPECT_EQ(status, GRD_INVALID_ARGS);

    status = GRD_DBOpen(path.c_str(), R""({"redopubbufsize":16385})"", GRD_DB_OPEN_CREATE, &db);
    EXPECT_EQ(status, GRD_INVALID_ARGS);
}

/**
 * @tc.name: OpenDBConfigShareModeTest001
 * @tc.desc: Test open document db with invalid config item shareMode
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: mazhao
 */
HWTEST_F(DocumentDBApiTest, OpenDBConfigShareModeTest001, TestSize.Level0)
{
    GRD_DB *db = nullptr;
    std::string path = "./document.db";

    int status = GRD_DBOpen(path.c_str(), R""({"sharedmodeenable":0})"", GRD_DB_OPEN_CREATE, &db);
    EXPECT_EQ(status, GRD_OK);
    EXPECT_EQ(GRD_DBClose(db, 0), GRD_OK);

    status = GRD_DBOpen(path.c_str(), R""({"sharedmodeenable":1})"", GRD_DB_OPEN_CREATE, &db);
    EXPECT_EQ(status, GRD_INVALID_ARGS);
}

/**
 * @tc.name: OpenDBFlagTest001
 * @tc.desc: Test open document db with invalid flag
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: lianhuix
 */
HWTEST_F(DocumentDBApiTest, OpenDBFlagTest001, TestSize.Level0)
{
    GRD_DB *db = nullptr;
    std::string path = "./document.db";
    std::vector<unsigned int> invaldFlag = { GRD_DB_OPEN_CHECK_FOR_ABNORMAL | GRD_DB_OPEN_CHECK,
        GRD_DB_OPEN_CREATE | GRD_DB_OPEN_CHECK_FOR_ABNORMAL | GRD_DB_OPEN_CHECK, 0x08, 0xffff, UINT32_MAX };
    for (unsigned int flag : invaldFlag) {
        GLOGD("OpenDBFlagTest001: open doc db with flag %u", flag);
        int status = GRD_DBOpen(path.c_str(), "", flag, &db);
        EXPECT_EQ(status, GRD_INVALID_ARGS);
    }
}

/**
 * @tc.name: OpenDBFlagTest002
 * @tc.desc: Test open document db with valid flag
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: lianhuix
 */
HWTEST_F(DocumentDBApiTest, OpenDBFlagTest002, TestSize.Level0)
{
    GRD_DB *db = nullptr;
    std::string path = "./document.db";
    int status = GRD_DBOpen(path.c_str(), "", GRD_DB_OPEN_ONLY, &db);
    EXPECT_EQ(status, GRD_INVALID_ARGS);

    status = GRD_DBOpen(path.c_str(), "", GRD_DB_OPEN_CREATE, &db);
    EXPECT_EQ(status, GRD_OK);

    status = GRD_DBClose(db, GRD_DB_CLOSE);
    EXPECT_EQ(status, GRD_OK);
    db = nullptr;

    status = GRD_DBOpen(path.c_str(), "", GRD_DB_OPEN_ONLY, &db);
    EXPECT_EQ(status, GRD_OK);

    status = GRD_DBClose(db, GRD_DB_CLOSE);
    EXPECT_EQ(status, GRD_OK);
    db = nullptr;

    status = GRD_DBOpen(path.c_str(), "", GRD_DB_OPEN_CHECK_FOR_ABNORMAL, &db);
    EXPECT_EQ(status, GRD_OK);

    status = GRD_DBClose(db, GRD_DB_CLOSE);
    EXPECT_EQ(status, GRD_OK);
    db = nullptr;

    status = GRD_DBOpen(path.c_str(), "", GRD_DB_OPEN_CHECK, &db);
    EXPECT_EQ(status, GRD_OK);

    status = GRD_DBClose(db, GRD_DB_CLOSE);
    EXPECT_EQ(status, GRD_OK);
    db = nullptr;

    DocumentDBTestUtils::RemoveTestDbFiles(path);
}

/**
 * @tc.name: CloseDBTest001
 * @tc.desc: Test close document db with invalid db
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: lianhuix
 */
HWTEST_F(DocumentDBApiTest, CloseDBTest001, TestSize.Level0)
{
    GRD_DB *db = nullptr;
    int status = GRD_DBClose(db, GRD_DB_CLOSE);
    EXPECT_EQ(status, GRD_INVALID_ARGS);

    status = GRD_DBClose(db, GRD_DB_CLOSE_IGNORE_ERROR);
    EXPECT_EQ(status, GRD_INVALID_ARGS);
    db = nullptr;
}

/**
 * @tc.name: CloseDBFlagTest001
 * @tc.desc: Test close document db with valid flag
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: lianhuix
 */
HWTEST_F(DocumentDBApiTest, CloseDBFlagTest001, TestSize.Level0)
{
    GRD_DB *db = nullptr;
    std::string path = "./document.db";
    int status = GRD_DBOpen(path.c_str(), "", GRD_DB_OPEN_CREATE, &db);
    EXPECT_EQ(status, GRD_OK);
    ASSERT_NE(db, nullptr);

    status = GRD_DBClose(db, GRD_DB_CLOSE);
    EXPECT_EQ(status, GRD_OK);
    db = nullptr;

    DocumentDBTestUtils::RemoveTestDbFiles(path);
}

/**
 * @tc.name: CloseDBFlagTest002
 * @tc.desc: Test close document db with valid flag
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: lianhuix
 */
HWTEST_F(DocumentDBApiTest, CloseDBFlagTest002, TestSize.Level0)
{
    GRD_DB *db = nullptr;
    std::string path = "./document.db";
    int status = GRD_DBOpen(path.c_str(), "", GRD_DB_OPEN_CREATE, &db);
    EXPECT_EQ(status, GRD_OK);
    ASSERT_NE(db, nullptr);

    status = GRD_DBClose(db, GRD_DB_CLOSE_IGNORE_ERROR);
    EXPECT_EQ(status, GRD_OK);
    db = nullptr;

    DocumentDBTestUtils::RemoveTestDbFiles(path);
}

/**
 * @tc.name: CloseDBFlagTest003
 * @tc.desc: Test close document db with invalid flag
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: lianhuix
 */
HWTEST_F(DocumentDBApiTest, CloseDBFlagTest003, TestSize.Level0)
{
    GRD_DB *db = nullptr;
    std::string path = "./document.db";
    int status = GRD_DBOpen(path.c_str(), "", GRD_DB_OPEN_CREATE, &db);
    EXPECT_EQ(status, GRD_OK);
    ASSERT_NE(db, nullptr);

    std::vector<unsigned int> invaldFlag = { 0x02, 0x03, 0xffff, UINT32_MAX };
    for (unsigned int flag : invaldFlag) {
        GLOGD("CloseDBFlagTest003: close doc db with flag %u", flag);
        status = GRD_DBClose(db, flag);
        EXPECT_EQ(status, GRD_INVALID_ARGS);
    }

    status = GRD_DBClose(db, GRD_DB_CLOSE);
    EXPECT_EQ(status, GRD_OK);
    db = nullptr;

    DocumentDBTestUtils::RemoveTestDbFiles(path);
}

/**
 * @tc.name: FlushDBTest001
 * @tc.desc: Test flush document db
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: lianhuix
 */
HWTEST_F(DocumentDBApiTest, FlushDBTest001, TestSize.Level0)
{
    EXPECT_EQ(GRD_Flush(nullptr, GRD_DB_FLUSH_ASYNC), GRD_INVALID_ARGS);
    EXPECT_EQ(GRD_Flush(nullptr, GRD_DB_FLUSH_SYNC), GRD_INVALID_ARGS);

    GRD_DB *db = nullptr;
    std::string path = "./document.db";
    int status = GRD_DBOpen(path.c_str(), "", GRD_DB_OPEN_CREATE, &db);
    EXPECT_EQ(status, GRD_OK);
    ASSERT_NE(db, nullptr);

    EXPECT_EQ(GRD_Flush(db, GRD_DB_FLUSH_ASYNC), GRD_OK);
    EXPECT_EQ(GRD_Flush(db, GRD_DB_FLUSH_SYNC), GRD_OK);
    std::vector<unsigned int> invalidFlags = { 2, 4, 8, 512, 1024, UINT32_MAX };
    for (auto flags : invalidFlags) {
        EXPECT_EQ(GRD_Flush(db, flags), GRD_INVALID_ARGS);
    }

    status = GRD_DBClose(db, GRD_DB_CLOSE);
    EXPECT_EQ(status, GRD_OK);
    db = nullptr;

    DocumentDBTestUtils::RemoveTestDbFiles(path);
}
} // namespace