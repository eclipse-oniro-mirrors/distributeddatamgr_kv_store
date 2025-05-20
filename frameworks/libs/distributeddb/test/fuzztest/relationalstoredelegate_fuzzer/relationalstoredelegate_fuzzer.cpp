/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "relationalstoredelegate_fuzzer.h"
#include "cloud/cloud_store_types.h"
#include "distributeddb_data_generate_unit_test.h"
#include "distributeddb/result_set.h"
#include "distributeddb_tools_test.h"
#include "fuzzer_data.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "log_print.h"
#include "query.h"
#include "relational_store_delegate.h"
#include "relational_store_manager.h"
#include "runtime_context.h"
#include "store_observer.h"
#include "store_types.h"
#include "virtual_communicator_aggregator.h"

namespace OHOS {
using namespace DistributedDB;
using namespace DistributedDBTest;
using namespace DistributedDBUnitTest;
static constexpr const int MOD = 3;
constexpr const char *DB_SUFFIX = ".db";
constexpr const char *STORE_ID = "Relational_Store_ID";
const std::string DEVICE_A = "DEVICE_A";
std::string g_testDir;
std::string g_dbDir;
DistributedDB::RelationalStoreManager g_mgr(APP_ID, USER_ID);
sqlite3 *g_db = nullptr;
RelationalStoreDelegate *g_delegate = nullptr;
VirtualCommunicatorAggregator *g_communicatorAggregator = nullptr;
const std::string NORMAL_CREATE_TABLE_SQL = "CREATE TABLE IF NOT EXISTS sync_data(" \
    "key         BLOB NOT NULL UNIQUE," \
    "value       BLOB," \
    "timestamp   INT  NOT NULL," \
    "flag        INT  NOT NULL," \
    "device      BLOB," \
    "ori_device  BLOB," \
    "hash_key    BLOB PRIMARY KEY NOT NULL," \
    "w_timestamp INT," \
    "UNIQUE(device, ori_device));" \
    "CREATE INDEX key_index ON sync_data (key, flag);";

void Setup()
{
    DistributedDBToolsTest::TestDirInit(g_testDir);
    g_dbDir = g_testDir + "/";
    g_communicatorAggregator = new (std::nothrow) VirtualCommunicatorAggregator();
    if (g_communicatorAggregator == nullptr) {
        return;
    }
    RuntimeContext::GetInstance()->SetCommunicatorAggregator(g_communicatorAggregator);

    g_db = RdbTestUtils::CreateDataBase(g_dbDir + STORE_ID + DB_SUFFIX);
    if (g_db == nullptr) {
        return;
    }
    if (RdbTestUtils::ExecSql(g_db, "PRAGMA journal_mode=WAL;") != SQLITE_OK) {
        return;
    }
    if (RdbTestUtils::ExecSql(g_db, NORMAL_CREATE_TABLE_SQL) != SQLITE_OK) {
        return;
    }
    if (RdbTestUtils::CreateDeviceTable(g_db, "sync_data", DEVICE_A) != 0) {
        return;
    }
    LOGD("open store");
    if (g_mgr.OpenStore(g_dbDir + STORE_ID + DB_SUFFIX, STORE_ID, {}, g_delegate) != E_OK) {
        LOGE("fuzz open store faile");
    }
}

void TearDown()
{
    LOGD("close store");
    g_mgr.CloseStore(g_delegate);
    g_delegate = nullptr;
    RuntimeContext::GetInstance()->SetCommunicatorAggregator(nullptr);
    g_communicatorAggregator = nullptr;
    if (sqlite3_close_v2(g_db) != SQLITE_OK) {
        LOGI("sqlite3_close_v2 faile");
    }
    g_db = nullptr;
    DistributedDBToolsTest::RemoveTestDbFiles(g_testDir);
}

void MultiCombineTest(FuzzedDataProvider *fdp, const std::string &tableName,
    const std::set<std::string> &extendColNames, const std::set<std::string> &trackerColNames, const bool isDeleted)
{
    TrackerSchema schema;
    schema.tableName = tableName;
    schema.extendColNames = extendColNames;
    schema.trackerColNames = trackerColNames;
    g_delegate->SetTrackerTable(schema);
    g_delegate->SetReference({});
    g_delegate->CleanTrackerData(tableName, 0);
    bool logicDelete = isDeleted;
    auto pragmaData = static_cast<PragmaData>(&logicDelete);
    size_t pragmaCmdLen = sizeof(PragmaCmd);
    auto pragmaCmd = static_cast<PragmaCmd>(fdp->ConsumeIntegral<uint32_t>() % pragmaCmdLen);
    g_delegate->Pragma(pragmaCmd, pragmaData);
    VBucket records;
    records[*extendColNames.begin()] = *extendColNames.begin();
    size_t recordStatusLen = sizeof(RecordStatus);
    auto recordStatus = static_cast<RecordStatus>(fdp->ConsumeIntegral<uint32_t>() % recordStatusLen);
    g_delegate->UpsertData(tableName, { records }, recordStatus);
    DistributedDB::SqlCondition sqlCondition;
    std::vector<VBucket> sqlRecords;
    g_delegate->ExecuteSql(sqlCondition, sqlRecords);
}

void TestDistributedSchema(FuzzedDataProvider *fdp)
{
    DistributedSchema schema;
    schema.version = fdp->ConsumeIntegral<uint32_t>();
    auto fieldSize = fdp->ConsumeIntegral<uint32_t>() % 30; // 30 is mod for field size
    auto tableSize = fdp->ConsumeIntegral<uint32_t>() % 30; // 30 is mod for table size
    for (uint32_t i = 0; i < tableSize; ++i) {
        DistributedTable table;
        table.tableName = fdp->ConsumeRandomLengthString();
        for (uint32_t j = 0; j < fieldSize; j++) {
            DistributedField field;
            field.colName = fdp->ConsumeRandomLengthString();
            table.fields.push_back(field);
        }
        schema.tables.push_back(table);
    }
    g_delegate->SetDistributedSchema(schema);
}

void CombineTest(FuzzedDataProvider &fdp)
{
    auto observer = new (std::nothrow) DistributedDB::StoreObserver;
    if (observer == nullptr) {
        delete observer;
        observer = nullptr;
        return;
    }
    if (g_delegate == nullptr) {
        LOGI("delegate is null");
        return;
    }
    g_delegate->RegisterObserver(observer);
    uint32_t len = fdp.ConsumeIntegral<uint32_t>();
    std::string tableName = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(0, MOD));
    g_delegate->CreateDistributedTable(tableName);

    std::vector<std::string> device;
    size_t size = fdp.ConsumeIntegralInRange<size_t>(0, MOD);
    for (int i = 0; i < size; i++) {
        device.push_back(fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(0, MOD)));
    }
    Query query = Query::Select();
    SyncMode mode = len % MOD == 1 ? SyncMode::SYNC_MODE_PULL_ONLY : SyncMode::SYNC_MODE_PUSH_PULL;
    SyncStatusCallback callback = nullptr;
    g_delegate->Sync(device, mode, query, callback, len % 2); // 2 is mod num for wait parameter
    g_delegate->GetCloudSyncTaskCount();
    std::string extendName = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(0, MOD));
    std::set<std::string> extendColNames = {extendName};
    std::string trackName = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(0, MOD));
    std::set<std::string> trackerColNames = {trackName};
    MultiCombineTest(&fdp, tableName, extendColNames, trackerColNames, fdp.ConsumeBool());
    std::string deviceId = device.size() > 0 ? device[0] : tableName;
    g_delegate->RemoveDeviceData();
    g_delegate->RemoveDeviceData(deviceId);
    g_delegate->RemoveDeviceData(deviceId, tableName);

    RemoteCondition rc = { tableName, device };
    std::shared_ptr<ResultSet> resultSet = nullptr;
    uint64_t timeout = len;
    g_delegate->RemoteQuery(deviceId, rc, timeout, resultSet);
    g_delegate->UnRegisterObserver(observer);
    g_delegate->RegisterObserver(observer);
    g_delegate->UnRegisterObserver();
    delete observer;
    observer = nullptr;

    TestDistributedSchema(&fdp);
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::Setup();
    FuzzedDataProvider fdp(data, size);
    OHOS::CombineTest(fdp);
    OHOS::TearDown();
    return 0;
}
