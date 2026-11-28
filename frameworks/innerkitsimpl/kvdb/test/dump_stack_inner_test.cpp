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

#include <filesystem>
#include <memory>
#include <string>

#include "distributed_kv_data_manager.h"
#include "single_kvstore.h"
#include "types.h"

namespace {
constexpr const char *TEST_BASE_DIR = "/data/service/el1/public/database/KvDumpStackInnerTest";
constexpr const char *TEST_APP_ID = "KvDumpStackInnerTest";

struct DumpStackOptionCase {
    bool syncable;
    bool backup;
    bool dumpStackOnFileDeletion;
};
}

namespace OHOS::Test {
using namespace testing::ext;
using namespace OHOS::DistributedKv;

class KvDumpStackInnerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void);
    void TearDown(void);
};

void KvDumpStackInnerTest::SetUpTestCase(void)
{
    std::error_code error;
    std::filesystem::remove_all(TEST_BASE_DIR, error);
    std::filesystem::create_directories(TEST_BASE_DIR, error);
}

void KvDumpStackInnerTest::TearDownTestCase(void)
{
    std::error_code error;
    std::filesystem::remove_all(TEST_BASE_DIR, error);
}

void KvDumpStackInnerTest::SetUp(void)
{
}

void KvDumpStackInnerTest::TearDown(void)
{
    DistributedKvDataManager manager;
    (void)manager.CloseAllKvStore({ TEST_APP_ID });
}

/**
 * @tc.name: InnerStore_DumpStackOptionMatrix_001
 * @tc.desc: Exercise constructor and restore ACL option matrix via distributeddata_inner public API
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KvDumpStackInnerTest, InnerStore_DumpStackOptionMatrix_001, TestSize.Level0)
{
    const DumpStackOptionCase matrix[] = {
        { true, false, false },
        { false, true, false },
        { false, false, true },
        { false, false, false },
    };
    DistributedKvDataManager manager;
    AppId appId = { TEST_APP_ID };
    int index = 0;
    for (const auto &item : matrix) {
        StoreId storeId = { std::string("InnerDumpStackMatrix") + std::to_string(index++) };
        Options options;
        options.createIfMissing = true;
        options.encrypt = false;
        options.autoSync = false;
        options.securityLevel = S1;
        options.area = EL1;
        options.kvStoreType = SINGLE_VERSION;
        options.role = OWNER;
        options.baseDir = TEST_BASE_DIR;
        options.syncable = item.syncable;
        options.backup = item.backup;
        options.dumpStackOnFileDeletion = item.dumpStackOnFileDeletion;
        (void)manager.DeleteKvStore(appId, storeId, TEST_BASE_DIR);
        std::shared_ptr<SingleKvStore> kvStore = nullptr;
        Status openStatus = manager.GetSingleKvStore(options, appId, storeId, kvStore);
        EXPECT_EQ(openStatus, SUCCESS);
        EXPECT_NE(kvStore, nullptr);
        if (kvStore != nullptr) {
            Status restoreStatus = kvStore->Restore("not_exist_backup", TEST_BASE_DIR);
            EXPECT_EQ(restoreStatus, INVALID_ARGUMENT);
            kvStore = nullptr;
        }
        (void)manager.CloseKvStore(appId, storeId);
        (void)manager.DeleteKvStore(appId, storeId, TEST_BASE_DIR);
    }
}
}
