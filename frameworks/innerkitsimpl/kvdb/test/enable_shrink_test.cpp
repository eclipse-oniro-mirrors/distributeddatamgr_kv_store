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

#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>

#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "kv_store_delegate_manager.h"
#include "shrink_manager.h"
#include "single_store_impl.h"
#include "store_manager.h"
#include "types.h"

using namespace testing::ext;
using namespace OHOS::DistributedKv;

namespace OHOS::Test {
namespace {
constexpr const char *BASE_DIR = "/data/service/el1/public/database/SingleStoreImplTest";
constexpr const char *APP_ID = "SingleStoreImplTest";

constexpr int32_t MAX_BATCH_ENTRIES = 128; // DBConstant::MAX_BATCH_SIZE in distributeddb
constexpr uint64_t DISK_BLOCK_SIZE_BYTES = 512;

constexpr int64_t WAIT_SWITCH_TIMEOUT_MS = 5000;

constexpr int64_t WAIT_RECLAIM_TIMEOUT_MS = 15000;
constexpr int64_t RECLAIM_SETTLE_TIMEOUT_MS = 60000;
constexpr int64_t POLL_INTERVAL_MS = 200;
constexpr int64_t SETTLE_INTERVAL_MS = 200;
constexpr int64_t NO_DELETE_OBSERVE_MS = 3000;
constexpr int64_t MAX_ACCEPT_MILLIS = 1000;

constexpr uint64_t HOUSEKEEPING_DROP_PERCENT = 25;

constexpr int32_t RECLAIM_WRITE_BATCHES = 20;
constexpr int32_t RECLAIM_KEYS_PER_BATCH = MAX_BATCH_ENTRIES;
constexpr size_t RECLAIM_VALUE_SIZE = 8 * 1024;
constexpr int32_t RECLAIM_TOTAL_KEYS = RECLAIM_WRITE_BATCHES * RECLAIM_KEYS_PER_BATCH;
constexpr int32_t RECLAIM_PEAK_SCANS = 3;
constexpr int64_t RECLAIM_MIN_DROP_PERCENT = 85;

constexpr int32_t RECLAIM_KEYS_PER_ROUND = 256;

constexpr int32_t PLAIN_KEYS = 512;
constexpr size_t PLAIN_VALUE_SIZE = 4 * 1024;

constexpr int32_t BELOW_THRESHOLD_DELETE_KEYS = 160;

constexpr int32_t CONCURRENT_KEYS = 1024;
constexpr size_t CONCURRENT_VALUE_SIZE = 8 * 1024;
constexpr int32_t CONCURRENT_DELETE_KEYS = 384;
constexpr int32_t CONCURRENT_DELETE_STEP = 2;
constexpr int32_t CONCURRENT_READERS = 3;
constexpr int64_t CONCURRENT_BASELINE_MS = 800;
constexpr int32_t CONCURRENT_DELETE_CHUNK = 16;
constexpr int64_t CONCURRENT_DELETE_SLEEP_MS = 10;
constexpr int64_t CONCURRENT_RECLAIM_TIMEOUT_MS = 30000;
constexpr int64_t CONCURRENT_RECLAIM_WINDOW_MS = 3000;
constexpr int64_t CONCURRENT_RECLAIM_MIN_DROP_PERCENT = 10;
// The two latency bounds below are engineering upper bounds against long blocking/deadlock,
// not spec numbers; spec AC-1.5 itself does not define a fixed millisecond threshold.
constexpr int64_t CONCURRENT_MAX_READ_MICROS = 5 * 1000 * 1000;
constexpr int64_t CONCURRENT_P95_MULTIPLIER = 10;
constexpr int64_t CONCURRENT_P95_FLOOR_MICROS = 1000 * 1000;
constexpr int64_t READER_YIELD_MS = 1;

constexpr int32_t PERF_ROUNDS = 3;
constexpr int32_t PERF_DELETE_SAMPLES = 200;
constexpr int32_t PERF_BATCH_SAMPLES = 200;
constexpr int32_t PERF_BATCH_SIZE = 8;
constexpr size_t PERF_VALUE_SIZE = 1024;

constexpr int64_t PERF_DEGRADE_LIMIT_PERCENT = 10;
constexpr int64_t PERF_ABS_JITTER_US = 200;
constexpr int64_t PERF_RECLAIM_MIN_DROP_PERCENT = 10;


struct DiskUsage {
    uint64_t blockBytes = 0;
    uint64_t dbBlockBytes = 0;
    uint64_t otherBlockBytes = 0;
    uint32_t fileCount = 0;
    uint32_t dbFileCount = 0;
    bool valid = false;
};

struct ShrinkState {
    bool desiredEnabled = false;
    uint32_t pendingTasks = 0;
};

void SleepMillis(int64_t millis)
{
    std::this_thread::sleep_for(std::chrono::milliseconds(millis));
}

int64_t ElapsedMicros(std::chrono::steady_clock::time_point start)
{
    return std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now() - start).count();
}

int64_t Percentile(std::vector<int64_t> samples, int32_t percent)
{
    if (samples.empty()) {
        return 0;
    }
    std::sort(samples.begin(), samples.end());
    size_t index = static_cast<size_t>(percent) * (samples.size() - 1) / 100;
    return samples[index];
}

int64_t Median(std::vector<int64_t> samples)
{
    if (samples.empty()) {
        return 0;
    }
    std::sort(samples.begin(), samples.end());
    size_t middle = samples.size() / 2;
    if (samples.size() % 2 == 0) {
        return (samples[middle - 1] + samples[middle]) / 2;
    }
    return samples[middle];
}

bool EndsWithDbSuffix(const std::string &name)
{
    constexpr const char *DB_SUFFIX = ".db";
    size_t suffixSize = std::string(DB_SUFFIX).size();
    return name.size() >= suffixSize && name.compare(name.size() - suffixSize, suffixSize, DB_SUFFIX) == 0;
}

void AccumulateDiskUsage(const std::string &dir, DiskUsage &usage)
{
    DIR *handle = opendir(dir.c_str());
    if (handle == nullptr) {
        return;
    }
    struct dirent *item = nullptr;
    while ((item = readdir(handle)) != nullptr) {
        std::string name = item->d_name;
        if (name == "." || name == "..") {
            continue;
        }
        std::string path = dir + "/" + name;
        struct stat info {};
        if (lstat(path.c_str(), &info) != 0) {
            continue;
        }
        if (S_ISDIR(info.st_mode)) {
            AccumulateDiskUsage(path, usage);
            continue;
        }
        if (!S_ISREG(info.st_mode)) {
            continue;
        }
        uint64_t blocks = info.st_blocks > 0 ? static_cast<uint64_t>(info.st_blocks) * DISK_BLOCK_SIZE_BYTES : 0;
        usage.blockBytes += blocks;
        usage.fileCount++;
        if (EndsWithDbSuffix(name)) {
            usage.dbBlockBytes += blocks;
            usage.dbFileCount++;
        } else {
            usage.otherBlockBytes += blocks;
        }
    }
    closedir(handle);
}

bool QueryStoreDiskUsage(const std::string &storeId, DiskUsage &usage)
{
    usage = {};
    std::string hashDir;
    if (DistributedDB::KvStoreDelegateManager::GetDatabaseDir(storeId, hashDir) != DistributedDB::DBStatus::OK) {
        return false;
    }
    AccumulateDiskUsage(std::string(BASE_DIR) + "/kvdb/" + hashDir, usage);
    usage.valid = usage.fileCount > 0 && usage.blockBytes > 0;
    return usage.valid;
}

bool CheckpointStore(const std::shared_ptr<SingleStoreImpl> &impl)
{
    if (impl == nullptr || impl->dbStore_ == nullptr) {
        return false;
    }
    DistributedDB::PragmaData data = nullptr;
    return impl->dbStore_->Pragma(DistributedDB::EXEC_CHECKPOINT, data) == DistributedDB::DBStatus::OK;
}

bool EnsureShrinkEngineReadyForTest(const std::shared_ptr<SingleStoreImpl> &impl, std::string &reason)
{
    if (impl == nullptr || impl->dbStore_ == nullptr) {
        reason = "shrink capability probe failed: store is closed";
        return false;
    }
    DistributedDB::ShrinkParam setParam;
    setParam.operation = DistributedDB::ShrinkOperation::SET;
    setParam.enable = false;
    DistributedDB::PragmaData setData = &setParam;
    auto setStatus = impl->dbStore_->Pragma(DistributedDB::SHRINK, setData);
    if (setStatus != DistributedDB::DBStatus::OK) {
        reason = "shrink capability probe failed: SHRINK SET status=" +
            std::to_string(static_cast<int32_t>(setStatus)) +
            " (SQLite fallback or engine without GRD_KVSetDbShrinkEnable)";
        return false;
    }
    DistributedDB::ShrinkParam getParam;
    getParam.operation = DistributedDB::ShrinkOperation::GET;
    DistributedDB::PragmaData getData = &getParam;
    auto getStatus = impl->dbStore_->Pragma(DistributedDB::SHRINK, getData);
    if (getStatus != DistributedDB::DBStatus::OK) {
        reason = "shrink capability probe failed: SHRINK GET status=" +
            std::to_string(static_cast<int32_t>(getStatus)) +
            " (engine without GRD_KVGetDbShrinkEnable)";
        return false;
    }
    return true;
}

bool PutBatchChunked(const std::shared_ptr<SingleKvStore> &store, const std::vector<Entry> &entries)
{
    if (store == nullptr) {
        return false;
    }
    if (entries.empty()) {
        return true;
    }
    size_t offset = 0;
    while (offset < entries.size()) {
        size_t count = std::min(static_cast<size_t>(MAX_BATCH_ENTRIES), entries.size() - offset);
        std::vector<Entry> chunk(entries.begin() + offset, entries.begin() + offset + count);
        if (store->PutBatch(chunk) != SUCCESS) {
            return false;
        }
        offset += count;
    }
    return true;
}

bool DeleteBatchChunked(const std::shared_ptr<SingleKvStore> &store, const std::vector<Key> &keys)
{
    if (store == nullptr) {
        return false;
    }
    if (keys.empty()) {
        return true;
    }
    size_t offset = 0;
    while (offset < keys.size()) {
        size_t count = std::min(static_cast<size_t>(MAX_BATCH_ENTRIES), keys.size() - offset);
        std::vector<Key> chunk(keys.begin() + offset, keys.begin() + offset + count);
        if (store->DeleteBatch(chunk) != SUCCESS) {
            return false;
        }
        offset += count;
    }
    return true;
}

bool HasReclaimDrop(uint64_t peakBytes, uint64_t currentBytes)
{
    if (peakBytes == 0) {
        return false;
    }
    return currentBytes + peakBytes / 10 <= peakBytes;
}

int64_t DropPercent(uint64_t peakBytes, uint64_t currentBytes)
{
    if (peakBytes == 0 || currentBytes >= peakBytes) {
        return 0;
    }
    return static_cast<int64_t>((peakBytes - currentBytes) * 100 / peakBytes);
}

bool ExceedsHousekeepingDrop(uint64_t beforeBytes, uint64_t afterBytes)
{
    if (beforeBytes == 0) {
        return false;
    }
    return afterBytes + beforeBytes * HOUSEKEEPING_DROP_PERCENT / 100 < beforeBytes;
}

std::vector<Entry> MakeEntries(const std::string &prefix, int32_t count, size_t valueSize,
    bool distinct = false)
{
    std::vector<Entry> entries;
    entries.reserve(static_cast<size_t>(count));
    std::string value(valueSize, 'v');
    for (int32_t index = 0; index < count; ++index) {
        Entry entry;
        entry.key = prefix + std::to_string(index);
        if (distinct) {
            std::string distinctValue = "v_" + std::to_string(index) + "_";
            distinctValue.resize(valueSize, 'v');
            entry.value = distinctValue;
        } else {
            entry.value = value;
        }
        entries.push_back(std::move(entry));
    }
    return entries;
}

std::vector<Key> MakeKeys(const std::vector<Entry> &entries)
{
    std::vector<Key> keys;
    keys.reserve(entries.size());
    for (const auto &entry : entries) {
        keys.push_back(entry.key);
    }
    return keys;
}

ShrinkState ReadShrinkState(const SingleStoreImpl &impl)
{
    ShrinkState state;
    impl.GetShrinkStateForTest(state.desiredEnabled, state.pendingTasks);
    return state;
}

bool WaitShrinkSettled(const SingleStoreImpl &impl, bool desiredEnabled, int64_t timeoutMs)
{
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);
    while (std::chrono::steady_clock::now() < deadline) {
        auto state = ReadShrinkState(impl);
        if (state.desiredEnabled == desiredEnabled && state.pendingTasks == 0) {
            return true;
        }
        SleepMillis(POLL_INTERVAL_MS);
    }
    auto state = ReadShrinkState(impl);
    return state.desiredEnabled == desiredEnabled && state.pendingTasks == 0;
}

bool ReadEntriesByPrefix(const std::shared_ptr<SingleStoreImpl> &impl, const Key &prefix,
    std::vector<SingleStoreImpl::DBEntry> &entries)
{
    if (impl == nullptr || impl->dbStore_ == nullptr) {
        return false;
    }
    SingleStoreImpl::DBKey dbPrefix = impl->convertor_.GetPrefix(prefix);
    if (dbPrefix.empty()) {
        return false;
    }
    entries.clear();
    auto status = impl->dbStore_->GetEntries(dbPrefix, entries);
    return status == SingleStoreImpl::DBStatus::OK || status == SingleStoreImpl::DBStatus::NOT_FOUND;
}

bool ReadResultSetByPrefix(const std::shared_ptr<SingleStoreImpl> &impl, const Key &prefix,
    DistributedDB::KvStoreResultSet *&resultSet)
{
    resultSet = nullptr;
    if (impl == nullptr || impl->dbStore_ == nullptr) {
        return false;
    }
    SingleStoreImpl::DBKey dbPrefix = impl->convertor_.GetPrefix(prefix);
    if (dbPrefix.empty()) {
        return false;
    }
    auto status = impl->dbStore_->GetEntries(dbPrefix, resultSet);
    if (status == SingleStoreImpl::DBStatus::OK) {

        return resultSet != nullptr;
    }
    if (status == SingleStoreImpl::DBStatus::NOT_FOUND) {
        return true;
    }
    if (resultSet != nullptr) {
        (void)impl->dbStore_->CloseResultSet(resultSet);
        resultSet = nullptr;
    }
    return false;
}

bool DBEntryMatches(const SingleStoreImpl::DBEntry &entry,
    const std::map<std::string, std::string> &expectedValues)
{
    std::string key(entry.key.begin(), entry.key.end());
    auto iter = expectedValues.find(key);
    if (iter == expectedValues.end()) {
        return false;
    }
    return std::string(entry.value.begin(), entry.value.end()) == iter->second;
}
}

class EnableShrinkTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void);
    void TearDown(void);

    std::shared_ptr<SingleKvStore> OpenStore(const std::string &storeId, KvStoreType type, bool encrypt = false);
    std::shared_ptr<SingleKvStore> CreateStore(const std::string &storeId, KvStoreType type, bool encrypt = false);
    void CloseStore(const std::string &storeId, std::shared_ptr<SingleKvStore> &store);
    static std::shared_ptr<SingleStoreImpl> AsImpl(const std::shared_ptr<SingleKvStore> &store);
};

void EnableShrinkTest::SetUpTestCase(void)
{
    mkdir(BASE_DIR, (S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH));
}

void EnableShrinkTest::TearDownTestCase(void)
{
    (void)rmdir(BASE_DIR);
}

void EnableShrinkTest::SetUp(void) {}

void EnableShrinkTest::TearDown(void) {}

std::shared_ptr<SingleKvStore> EnableShrinkTest::OpenStore(const std::string &storeId, KvStoreType type, bool encrypt)
{
    Options options = {};
    options.kvStoreType = type;
    options.securityLevel = S1;
    options.area = EL1;
    options.backup = true;
    options.encrypt = encrypt;
    options.baseDir = BASE_DIR;
    AppId appId = { APP_ID };
    StoreId id = { storeId };
    Status status = STORE_NOT_FOUND;
    return StoreManager::GetInstance().GetKVStore(appId, id, options, status);
}

std::shared_ptr<SingleKvStore> EnableShrinkTest::CreateStore(const std::string &storeId, KvStoreType type,
    bool encrypt)
{
    AppId appId = { APP_ID };
    StoreId id = { storeId };
    (void)StoreManager::GetInstance().Delete(appId, id, BASE_DIR);
    return OpenStore(storeId, type, encrypt);
}

void EnableShrinkTest::CloseStore(const std::string &storeId, std::shared_ptr<SingleKvStore> &store)
{
    store = nullptr;
    AppId appId = { APP_ID };
    StoreId id = { storeId };
    (void)StoreManager::GetInstance().CloseKVStore(appId, id);
    (void)StoreManager::GetInstance().Delete(appId, id, BASE_DIR);
}

std::shared_ptr<SingleStoreImpl> EnableShrinkTest::AsImpl(const std::shared_ptr<SingleKvStore> &store)
{
    return std::static_pointer_cast<SingleStoreImpl>(store);
}

HWTEST_F(EnableShrinkTest, SetShrinkEnablePhysicalReclaim, TestSize.Level1)
{
    const std::string storeId = "EnableShrinkPhysicalReclaim";
    auto store = CreateStore(storeId, KvStoreType::LOCAL_ONLY);
    ASSERT_NE(store, nullptr);
    auto impl = AsImpl(store);
    ASSERT_NE(impl, nullptr);
    std::string probeReason;
    if (!EnsureShrinkEngineReadyForTest(impl, probeReason)) {
        CloseStore(storeId, store);
        GTEST_SKIP() << probeReason;
    }
    ASSERT_EQ(store->SetShrinkEnable(true), SUCCESS);
    ASSERT_TRUE(WaitShrinkSettled(*impl, true, WAIT_SWITCH_TIMEOUT_MS));

    // AC-1.1: 连续写入约 20MiB（20 批 x 128 条 x 8KiB），确保单个 space 的 free-list 超过 1MiB 回收阈值。
    std::vector<Key> writtenKeys;
    writtenKeys.reserve(static_cast<size_t>(RECLAIM_TOTAL_KEYS));
    for (int32_t batch = 0; batch < RECLAIM_WRITE_BATCHES; ++batch) {
        auto entries = MakeEntries("physical_reclaim_" + std::to_string(batch) + "_",
            RECLAIM_KEYS_PER_BATCH, RECLAIM_VALUE_SIZE);
        for (const auto &entry : entries) {
            writtenKeys.push_back(entry.key);
        }
        ASSERT_TRUE(PutBatchChunked(store, entries)) << "write batch " << batch << " failed";
    }
    bool checkpointBeforeDelete = CheckpointStore(impl);
    SleepMillis(SETTLE_INTERVAL_MS);
    DiskUsage peak;
    for (int32_t scan = 0; scan < RECLAIM_PEAK_SCANS; ++scan) {
        DiskUsage current;
        if (QueryStoreDiskUsage(storeId, current) && current.dbBlockBytes > peak.dbBlockBytes) {
            peak = current;
        }
        SleepMillis(SETTLE_INTERVAL_MS);
    }
    ASSERT_TRUE(DeleteBatchChunked(store, writtenKeys)) << "deleting all written keys failed";
    bool checkpointAfterDelete = CheckpointStore(impl);
    SleepMillis(SETTLE_INTERVAL_MS);

    DiskUsage finalUsage;
    int64_t dropPercent = 0;
    bool reclaimObserved = false;
    if (peak.valid && peak.dbBlockBytes > 0) {
        auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(RECLAIM_SETTLE_TIMEOUT_MS);
        while (std::chrono::steady_clock::now() < deadline) {
            DiskUsage current;
            if (QueryStoreDiskUsage(storeId, current)) {
                int64_t currentDrop = DropPercent(peak.dbBlockBytes, current.dbBlockBytes);
                if (currentDrop > dropPercent) {
                    dropPercent = currentDrop;
                    finalUsage = current;
                }
                if (HasReclaimDrop(peak.dbBlockBytes, current.dbBlockBytes)) {
                    // >=10% only proves shrink is active; the AC-1.1 target is 85%, so keep polling.
                    reclaimObserved = true;
                }
                if (dropPercent >= RECLAIM_MIN_DROP_PERCENT) {
                    break;
                }
            }
            SleepMillis(POLL_INTERVAL_MS);
        }
    }
    if (!finalUsage.valid) {
        (void)QueryStoreDiskUsage(storeId, finalUsage);
        dropPercent = DropPercent(peak.dbBlockBytes, finalUsage.dbBlockBytes);
    }

    RecordProperty("physical_peak_blocks_bytes", static_cast<int64_t>(peak.dbBlockBytes));
    RecordProperty("physical_final_blocks_bytes", static_cast<int64_t>(finalUsage.dbBlockBytes));
    RecordProperty("physical_peak_db_bytes", static_cast<int64_t>(peak.dbBlockBytes));
    RecordProperty("physical_final_db_bytes", static_cast<int64_t>(finalUsage.dbBlockBytes));
    RecordProperty("physical_peak_other_bytes", static_cast<int64_t>(peak.otherBlockBytes));
    RecordProperty("physical_final_other_bytes", static_cast<int64_t>(finalUsage.otherBlockBytes));
    RecordProperty("physical_peak_all_bytes", static_cast<int64_t>(peak.blockBytes));
    RecordProperty("physical_final_all_bytes", static_cast<int64_t>(finalUsage.blockBytes));
    RecordProperty("physical_drop_percent", dropPercent);
    RecordProperty("physical_reclaim_observed", std::string(reclaimObserved ? "true" : "false"));
    RecordProperty("physical_checkpoint_before_delete", std::string(checkpointBeforeDelete ? "true" : "false"));
    RecordProperty("physical_checkpoint_after_delete", std::string(checkpointAfterDelete ? "true" : "false"));
    CloseStore(storeId, store);
    if (!peak.valid || !finalUsage.valid || peak.dbBlockBytes == 0) {
        GTEST_SKIP() << "evidence gap: the RD database directory of the store is not measurable on this image";
    }

    EXPECT_GE(dropPercent, RECLAIM_MIN_DROP_PERCENT)
        << "physical usage only dropped " << dropPercent << "% (peak=" << peak.dbBlockBytes
        << ", final=" << finalUsage.dbBlockBytes << ")";
}

HWTEST_F(EnableShrinkTest, EncryptStoreShrinkCompatibility, TestSize.Level1)
{
    const std::string storeId = "EnableShrinkEncrypted";
    auto store = CreateStore(storeId, KvStoreType::LOCAL_ONLY, true);
    if (store == nullptr) {
        GTEST_SKIP() << "environment limitation: an encrypted LOCAL_ONLY store is not available on this image";
    }
    Status enableStatus = store->SetShrinkEnable(true);
    RecordProperty("encrypt_enable_status", static_cast<int64_t>(static_cast<int32_t>(enableStatus)));
    EXPECT_TRUE(enableStatus == SUCCESS || enableStatus == NOT_SUPPORT);
    auto impl = AsImpl(store);
    ASSERT_NE(impl, nullptr);
    if (enableStatus == SUCCESS) {
        EXPECT_TRUE(WaitShrinkSettled(*impl, true, WAIT_SWITCH_TIMEOUT_MS));
    }
    EXPECT_EQ(store->SetShrinkEnable(false), SUCCESS);
    EXPECT_TRUE(WaitShrinkSettled(*impl, false, WAIT_SWITCH_TIMEOUT_MS));

    Entry entry;
    entry.key = "encrypt_key";
    entry.value = "encrypt_value";
    EXPECT_EQ(store->Put(entry.key, entry.value), SUCCESS);
    Value value;
    EXPECT_EQ(store->Get(entry.key, value), SUCCESS);
    EXPECT_EQ(value.ToString(), entry.value.ToString());
    EXPECT_EQ(store->Delete(entry.key), SUCCESS);
    CloseStore(storeId, store);
}

HWTEST_F(EnableShrinkTest, NoEnableNoReclaim, TestSize.Level1)
{
    const std::string storeId = "EnableShrinkNoEnable";
    auto store = CreateStore(storeId, KvStoreType::LOCAL_ONLY);
    ASSERT_NE(store, nullptr);
    auto impl = AsImpl(store);
    ASSERT_NE(impl, nullptr);
    std::string probeReason;
    if (!EnsureShrinkEngineReadyForTest(impl, probeReason)) {
        CloseStore(storeId, store);
        GTEST_SKIP() << probeReason;
    }
    auto initialState = ReadShrinkState(*impl);
    EXPECT_FALSE(initialState.desiredEnabled);
    EXPECT_EQ(initialState.pendingTasks, 0u);

    auto entries = MakeEntries("noenable_", PLAIN_KEYS, PLAIN_VALUE_SIZE);
    ASSERT_TRUE(PutBatchChunked(store, entries));
    bool checkpointBeforeDelete = CheckpointStore(impl);
    SleepMillis(SETTLE_INTERVAL_MS);
    DiskUsage written;
    bool measuredBefore = QueryStoreDiskUsage(storeId, written);
    ASSERT_TRUE(DeleteBatchChunked(store, MakeKeys(entries)));
    SleepMillis(NO_DELETE_OBSERVE_MS);
    bool checkpointAfterDelete = CheckpointStore(impl);
    SleepMillis(SETTLE_INTERVAL_MS);

    DiskUsage afterDelete;
    bool measuredAfter = QueryStoreDiskUsage(storeId, afterDelete);
    auto endState = ReadShrinkState(*impl);
    EXPECT_FALSE(endState.desiredEnabled);
    EXPECT_EQ(endState.pendingTasks, 0u);
    RecordProperty("noenable_bytes_after_write", static_cast<int64_t>(written.dbBlockBytes));
    RecordProperty("noenable_bytes_after_delete", static_cast<int64_t>(afterDelete.dbBlockBytes));
    RecordProperty("noenable_other_bytes_after_write", static_cast<int64_t>(written.otherBlockBytes));
    RecordProperty("noenable_other_bytes_after_delete", static_cast<int64_t>(afterDelete.otherBlockBytes));
    RecordProperty("noenable_checkpoint_ok",
        std::string((checkpointBeforeDelete && checkpointAfterDelete) ? "true" : "false"));
    RecordProperty("noenable_evidence_gap", std::string("the engine internal file housekeeping is not "
        "controllable; no switch task is ever requested, so the desired state stays false and no task "
        "is pending"));
    CloseStore(storeId, store);
    if (!measuredBefore || !measuredAfter || written.dbBlockBytes == 0) {
        GTEST_SKIP() << "evidence gap: the RD database directory of the store is not measurable on this image";
    }

    EXPECT_FALSE(ExceedsHousekeepingDrop(written.dbBlockBytes, afterDelete.dbBlockBytes))
        << "physical usage dropped although shrink was never enabled";
}

HWTEST_F(EnableShrinkTest, NoDeleteNoReclaim, TestSize.Level1)
{
    const std::string storeId = "EnableShrinkNoDelete";
    auto store = CreateStore(storeId, KvStoreType::LOCAL_ONLY);
    ASSERT_NE(store, nullptr);
    auto impl = AsImpl(store);
    ASSERT_NE(impl, nullptr);
    std::string probeReason;
    if (!EnsureShrinkEngineReadyForTest(impl, probeReason)) {
        CloseStore(storeId, store);
        GTEST_SKIP() << probeReason;
    }
    ASSERT_EQ(store->SetShrinkEnable(true), SUCCESS);
    ASSERT_TRUE(WaitShrinkSettled(*impl, true, WAIT_SWITCH_TIMEOUT_MS));

    auto entries = MakeEntries("nodelete_", PLAIN_KEYS, PLAIN_VALUE_SIZE);
    ASSERT_TRUE(PutBatchChunked(store, entries));
    bool checkpointBeforeObserve = CheckpointStore(impl);
    SleepMillis(SETTLE_INTERVAL_MS);
    DiskUsage baseline;
    bool measured = QueryStoreDiskUsage(storeId, baseline);

    uint64_t minimumBytes = baseline.dbBlockBytes;
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(NO_DELETE_OBSERVE_MS);
    while (std::chrono::steady_clock::now() < deadline) {
        SleepMillis(POLL_INTERVAL_MS);
        DiskUsage sample;
        if (QueryStoreDiskUsage(storeId, sample) && sample.dbBlockBytes < minimumBytes) {
            minimumBytes = sample.dbBlockBytes;
        }
    }
    auto endState = ReadShrinkState(*impl);
    EXPECT_TRUE(endState.desiredEnabled);
    EXPECT_EQ(endState.pendingTasks, 0u);
    bool checkpointAfterObserve = CheckpointStore(impl);
    SleepMillis(SETTLE_INTERVAL_MS);
    DiskUsage finalUsage;
    (void)QueryStoreDiskUsage(storeId, finalUsage);
    RecordProperty("nodelete_baseline_blocks_bytes", static_cast<int64_t>(baseline.dbBlockBytes));
    RecordProperty("nodelete_minimum_blocks_bytes", static_cast<int64_t>(minimumBytes));
    RecordProperty("nodelete_final_blocks_bytes", static_cast<int64_t>(finalUsage.dbBlockBytes));
    RecordProperty("nodelete_baseline_other_bytes", static_cast<int64_t>(baseline.otherBlockBytes));
    RecordProperty("nodelete_final_other_bytes", static_cast<int64_t>(finalUsage.otherBlockBytes));
    RecordProperty("nodelete_checkpoint_ok",
        std::string((checkpointBeforeObserve && checkpointAfterObserve) ? "true" : "false"));
    RecordProperty("nodelete_evidence_gap", std::string("the engine reclamation threshold is internal and "
        "not controllable; normal file housekeeping is tolerated below the shrink scale"));
    CloseStore(storeId, store);
    if (!measured || baseline.dbBlockBytes == 0) {
        GTEST_SKIP() << "evidence gap: the RD database directory of the store is not measurable on this image";
    }
    EXPECT_FALSE(ExceedsHousekeepingDrop(baseline.dbBlockBytes, minimumBytes))
        << "physical usage dropped without deletes";
}

HWTEST_F(EnableShrinkTest, BelowThresholdNoReclaim, TestSize.Level1)
{
    const std::string storeId = "EnableShrinkBelowThreshold";
    auto store = CreateStore(storeId, KvStoreType::LOCAL_ONLY);
    ASSERT_NE(store, nullptr);
    auto impl = AsImpl(store);
    ASSERT_NE(impl, nullptr);
    std::string probeReason;
    if (!EnsureShrinkEngineReadyForTest(impl, probeReason)) {
        CloseStore(storeId, store);
        GTEST_SKIP() << probeReason;
    }
    ASSERT_EQ(store->SetShrinkEnable(true), SUCCESS);
    ASSERT_TRUE(WaitShrinkSettled(*impl, true, WAIT_SWITCH_TIMEOUT_MS));

    auto entries = MakeEntries("below_threshold_", PLAIN_KEYS, PLAIN_VALUE_SIZE);
    ASSERT_TRUE(PutBatchChunked(store, entries));
    bool checkpointBeforeObserve = CheckpointStore(impl);
    SleepMillis(SETTLE_INTERVAL_MS);
    DiskUsage baseline;
    bool measured = QueryStoreDiskUsage(storeId, baseline);

    std::vector<Key> deleteKeys;
    deleteKeys.reserve(BELOW_THRESHOLD_DELETE_KEYS);
    for (int32_t index = 0; index < BELOW_THRESHOLD_DELETE_KEYS; ++index) {
        deleteKeys.push_back(entries[index].key);
    }
    ASSERT_TRUE(DeleteBatchChunked(store, deleteKeys));

    uint64_t minimumBytes = baseline.dbBlockBytes;
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(NO_DELETE_OBSERVE_MS);
    while (std::chrono::steady_clock::now() < deadline) {
        SleepMillis(POLL_INTERVAL_MS);
        DiskUsage sample;
        if (QueryStoreDiskUsage(storeId, sample) && sample.dbBlockBytes < minimumBytes) {
            minimumBytes = sample.dbBlockBytes;
        }
    }
    bool checkpointAfterObserve = CheckpointStore(impl);
    SleepMillis(SETTLE_INTERVAL_MS);
    DiskUsage finalUsage;
    (void)QueryStoreDiskUsage(storeId, finalUsage);
    RecordProperty("below_threshold_deleted_keys", static_cast<int64_t>(BELOW_THRESHOLD_DELETE_KEYS));
    RecordProperty("below_threshold_deleted_bytes",
        static_cast<int64_t>(BELOW_THRESHOLD_DELETE_KEYS) * static_cast<int64_t>(PLAIN_VALUE_SIZE));
    RecordProperty("below_threshold_baseline_blocks_bytes", static_cast<int64_t>(baseline.dbBlockBytes));
    RecordProperty("below_threshold_minimum_blocks_bytes", static_cast<int64_t>(minimumBytes));
    RecordProperty("below_threshold_final_blocks_bytes", static_cast<int64_t>(finalUsage.dbBlockBytes));
    RecordProperty("below_threshold_baseline_other_bytes", static_cast<int64_t>(baseline.otherBlockBytes));
    RecordProperty("below_threshold_final_other_bytes", static_cast<int64_t>(finalUsage.otherBlockBytes));
    RecordProperty("below_threshold_checkpoint_ok",
        std::string((checkpointBeforeObserve && checkpointAfterObserve) ? "true" : "false"));
    RecordProperty("below_threshold_construction_note", std::string("the per-space free-list is internal; "
        "deleted bytes (640 KiB) are below the 1 MiB threshold"));
    CloseStore(storeId, store);
    if (!measured || baseline.dbBlockBytes == 0) {
        GTEST_SKIP() << "environment limitation: the RD database directory of the store is not measurable "
                        "on this image";
    }
    EXPECT_FALSE(ExceedsHousekeepingDrop(baseline.dbBlockBytes, minimumBytes))
        << "physical usage dropped after a below-threshold delete";
}

HWTEST_F(EnableShrinkTest, ConcurrentReadDuringReclaim, TestSize.Level1)
{
    const std::string storeId = "EnableShrinkConcurrentRead";
    auto store = CreateStore(storeId, KvStoreType::LOCAL_ONLY);
    ASSERT_NE(store, nullptr);
    auto impl = AsImpl(store);
    ASSERT_NE(impl, nullptr);
    std::string probeReason;
    if (!EnsureShrinkEngineReadyForTest(impl, probeReason)) {
        CloseStore(storeId, store);
        GTEST_SKIP() << probeReason;
    }
    ASSERT_EQ(store->SetShrinkEnable(true), SUCCESS);
    ASSERT_TRUE(WaitShrinkSettled(*impl, true, WAIT_SWITCH_TIMEOUT_MS));

    // AC-1.5: 写入 1024 x 8KiB = 8MiB，删除 384 条（3MiB）释放超过 1MiB 阈值，回收窗口与读并发。
    auto entries = MakeEntries("concurrent_", CONCURRENT_KEYS, CONCURRENT_VALUE_SIZE, true);
    ASSERT_TRUE(PutBatchChunked(store, entries));
    (void)CheckpointStore(impl);
    SleepMillis(SETTLE_INTERVAL_MS);
    DiskUsage beforeDelete;
    if (!QueryStoreDiskUsage(storeId, beforeDelete) || beforeDelete.dbBlockBytes == 0) {
        CloseStore(storeId, store);
        GTEST_SKIP() << "evidence gap: the RD database directory of the store is not measurable on this image";
    }

    std::map<std::string, std::string> expectedValues;
    for (const auto &entry : entries) {
        expectedValues[entry.key.ToString()] = entry.value.ToString();
    }
    Key stableKey = entries[1].key;
    std::string stableValue = entries[1].value.ToString();
    Key queryPrefix = "concurrent_";
    std::vector<Key> deleteKeys;
    deleteKeys.reserve(static_cast<size_t>(CONCURRENT_DELETE_KEYS));
    for (int32_t index = 0; index < CONCURRENT_DELETE_KEYS * CONCURRENT_DELETE_STEP; index += CONCURRENT_DELETE_STEP) {
        deleteKeys.push_back(entries[index].key);
    }

    std::atomic<bool> reclaimPhase { false };
    std::atomic<bool> stop { false };
    std::vector<std::vector<int64_t>> baselineSamples(CONCURRENT_READERS);
    std::vector<std::vector<int64_t>> reclaimSamples(CONCURRENT_READERS);
    std::vector<int32_t> readFailures(CONCURRENT_READERS, 0);
    std::vector<std::thread> readers;
    for (int32_t reader = 0; reader < CONCURRENT_READERS; ++reader) {
        readers.emplace_back([&, reader]() {
            auto recordSample = [&](std::chrono::steady_clock::time_point start) {
                int64_t micros = ElapsedMicros(start);
                if (reclaimPhase.load()) {
                    reclaimSamples[reader].push_back(micros);
                } else {
                    baselineSamples[reader].push_back(micros);
                }
            };
            while (!stop.load()) {
                auto start = std::chrono::steady_clock::now();
                Value value;
                if (store->Get(stableKey, value) != SUCCESS || value.ToString() != stableValue) {
                    readFailures[reader]++;
                }
                recordSample(start);

                start = std::chrono::steady_clock::now();
                std::vector<SingleStoreImpl::DBEntry> entriesByPrefix;
                bool entriesOk = ReadEntriesByPrefix(impl, queryPrefix, entriesByPrefix);
                for (const auto &entry : entriesByPrefix) {
                    if (!DBEntryMatches(entry, expectedValues)) {
                        entriesOk = false;
                        break;
                    }
                }
                if (!entriesOk) {
                    readFailures[reader]++;
                }
                recordSample(start);

                start = std::chrono::steady_clock::now();
                DistributedDB::KvStoreResultSet *resultSet = nullptr;
                bool resultSetOk = ReadResultSetByPrefix(impl, queryPrefix, resultSet);
                if (resultSet != nullptr) {
                    if (resultSetOk) {
                        int32_t count = resultSet->GetCount();
                        if (count < 0 || count > CONCURRENT_KEYS) {
                            resultSetOk = false;
                        }
                        while (resultSetOk && resultSet->MoveToNext()) {
                            SingleStoreImpl::DBEntry entry;
                            if (resultSet->GetEntry(entry) != SingleStoreImpl::DBStatus::OK ||
                                !DBEntryMatches(entry, expectedValues)) {
                                resultSetOk = false;
                            }
                        }
                    }
                    (void)impl->dbStore_->CloseResultSet(resultSet);
                }
                if (!resultSetOk) {
                    readFailures[reader]++;
                }
                recordSample(start);
                SleepMillis(READER_YIELD_MS);
            }
        });
    }

    SleepMillis(CONCURRENT_BASELINE_MS);
    reclaimPhase.store(true);
    int32_t writeFailures = 0;
    size_t offset = 0;
    auto reclaimWindowDeadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(CONCURRENT_RECLAIM_WINDOW_MS);
    while (offset < deleteKeys.size() && std::chrono::steady_clock::now() < reclaimWindowDeadline) {
        size_t count = std::min(static_cast<size_t>(CONCURRENT_DELETE_CHUNK), deleteKeys.size() - offset);
        std::vector<Key> chunk(deleteKeys.begin() + offset, deleteKeys.begin() + offset + count);
        if (!DeleteBatchChunked(store, chunk)) {
            writeFailures++;
        }
        offset += count;
        SleepMillis(CONCURRENT_DELETE_SLEEP_MS);
    }
    reclaimPhase.store(false);
    stop.store(true);
    for (auto &reader : readers) {
        reader.join();
    }

    std::vector<int64_t> allBaselineSamples;
    std::vector<int64_t> allReclaimSamples;
    int32_t readFailuresTotal = 0;
    for (int32_t reader = 0; reader < CONCURRENT_READERS; ++reader) {
        allBaselineSamples.insert(allBaselineSamples.end(), baselineSamples[reader].begin(),
            baselineSamples[reader].end());
        allReclaimSamples.insert(allReclaimSamples.end(), reclaimSamples[reader].begin(),
            reclaimSamples[reader].end());
        readFailuresTotal += readFailures[reader];
    }
    int64_t baselineP95 = Percentile(allBaselineSamples, 95);
    int64_t reclaimP95 = Percentile(allReclaimSamples, 95);
    int64_t reclaimMax = allReclaimSamples.empty() ? 0 :
        *std::max_element(allReclaimSamples.begin(), allReclaimSamples.end());
    int64_t allowedP95 = std::max(baselineP95 * CONCURRENT_P95_MULTIPLIER, CONCURRENT_P95_FLOOR_MICROS);

    bool checkpointAfterDelete = CheckpointStore(impl);
    SleepMillis(SETTLE_INTERVAL_MS);
    DiskUsage finalUsage;
    int64_t dropPercent = 0;
    bool reclaimObserved = false;
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(CONCURRENT_RECLAIM_TIMEOUT_MS);
    while (std::chrono::steady_clock::now() < deadline) {
        DiskUsage current;
        if (QueryStoreDiskUsage(storeId, current)) {
            int64_t currentDrop = DropPercent(beforeDelete.dbBlockBytes, current.dbBlockBytes);
            if (currentDrop > dropPercent) {
                dropPercent = currentDrop;
                finalUsage = current;
            }
            if (HasReclaimDrop(beforeDelete.dbBlockBytes, current.dbBlockBytes)) {
                reclaimObserved = true;
                break;
            }
        }
        SleepMillis(POLL_INTERVAL_MS);
    }
    DiskUsage afterCheckpoint;
    if (QueryStoreDiskUsage(storeId, afterCheckpoint)) {
        if (DropPercent(beforeDelete.dbBlockBytes, afterCheckpoint.dbBlockBytes) > dropPercent) {
            dropPercent = DropPercent(beforeDelete.dbBlockBytes, afterCheckpoint.dbBlockBytes);
            finalUsage = afterCheckpoint;
        }
    }
    if (!finalUsage.valid) {
        (void)QueryStoreDiskUsage(storeId, finalUsage);
    }

    Value stableCheck;
    EXPECT_EQ(store->Get(stableKey, stableCheck), SUCCESS);
    EXPECT_EQ(stableCheck.ToString(), stableValue);
    EXPECT_EQ(store->Get(entries[0].key, stableCheck), KEY_NOT_FOUND);
    std::vector<SingleStoreImpl::DBEntry> surviving;
    bool readSurviving = ReadEntriesByPrefix(impl, queryPrefix, surviving);
    EXPECT_TRUE(readSurviving);
    EXPECT_EQ(static_cast<int32_t>(surviving.size()), CONCURRENT_KEYS - CONCURRENT_DELETE_KEYS);
    int32_t survivingMismatches = 0;
    std::map<std::string, int32_t> survivingSeen;
    for (const auto &entry : surviving) {
        if (!DBEntryMatches(entry, expectedValues)) {
            survivingMismatches++;
        }
        survivingSeen[std::string(entry.key.begin(), entry.key.end())]++;
    }
    int32_t duplicateSurviving = 0;
    for (const auto &item : survivingSeen) {
        if (item.second != 1) {
            duplicateSurviving++;
        }
    }
    EXPECT_EQ(survivingMismatches, 0);
    EXPECT_EQ(duplicateSurviving, 0);
    EXPECT_EQ(static_cast<int32_t>(survivingSeen.size()), CONCURRENT_KEYS - CONCURRENT_DELETE_KEYS);

    RecordProperty("concurrent_readers", static_cast<int64_t>(CONCURRENT_READERS));
    RecordProperty("concurrent_stock_bytes",
        static_cast<int64_t>(CONCURRENT_KEYS) * static_cast<int64_t>(CONCURRENT_VALUE_SIZE));
    RecordProperty("concurrent_deleted_bytes",
        static_cast<int64_t>(CONCURRENT_DELETE_KEYS) * static_cast<int64_t>(CONCURRENT_VALUE_SIZE));
    RecordProperty("concurrent_baseline_samples", static_cast<int64_t>(allBaselineSamples.size()));
    RecordProperty("concurrent_reclaim_samples", static_cast<int64_t>(allReclaimSamples.size()));
    RecordProperty("concurrent_baseline_p95_us", baselineP95);
    RecordProperty("concurrent_reclaim_p95_us", reclaimP95);
    RecordProperty("concurrent_reclaim_max_us", reclaimMax);
    RecordProperty("concurrent_read_failures", static_cast<int64_t>(readFailuresTotal));
    RecordProperty("concurrent_write_failures", static_cast<int64_t>(writeFailures));
    RecordProperty("concurrent_physical_drop_percent", dropPercent);
    RecordProperty("concurrent_physical_drop_observed", std::string(reclaimObserved ? "true" : "false"));
    RecordProperty("concurrent_reclaim_observed", std::string(reclaimObserved ? "true" : "false"));
    RecordProperty("concurrent_checkpoint_ok", std::string(checkpointAfterDelete ? "true" : "false"));
    RecordProperty("concurrent_evidence_gap", std::string("the engine internal reclamation window is not "
        "directly observable; dbBlockBytes drop and per-phase read latency are used as the closest evidence"));
    CloseStore(storeId, store);
    if (!finalUsage.valid) {
        GTEST_SKIP() << "evidence gap: the RD database directory of the store is not measurable on this image";
    }

    EXPECT_FALSE(allBaselineSamples.empty()) << "readers produced no baseline latency samples";
    EXPECT_FALSE(allReclaimSamples.empty()) << "readers produced no reclaim phase latency samples";
    EXPECT_EQ(readFailuresTotal, 0) << "readers observed errors while deletes were running";
    EXPECT_EQ(writeFailures, 0) << "deletes failed during the reclaim window";
    EXPECT_TRUE(reclaimObserved) << "no shrink driven dbBlockBytes drop was observed (drop="
        << dropPercent << "%, before=" << beforeDelete.dbBlockBytes << ", final=" << finalUsage.dbBlockBytes << ")";
    EXPECT_GE(dropPercent, CONCURRENT_RECLAIM_MIN_DROP_PERCENT)
        << "physical drop below " << CONCURRENT_RECLAIM_MIN_DROP_PERCENT << "% during the reclaim window";
    EXPECT_LE(reclaimP95, allowedP95) << "reclaim phase read P95 " << reclaimP95
        << "us exceeded allowed " << allowedP95 << "us (baseline P95=" << baselineP95 << "us)";
    EXPECT_LT(reclaimMax, CONCURRENT_MAX_READ_MICROS) << "a single read blocked for " << reclaimMax << "us";
}

HWTEST_F(EnableShrinkTest, DisableStopsNewReclaim, TestSize.Level1)
{
    const std::string storeId = "EnableShrinkDisablePending";
    auto store = CreateStore(storeId, KvStoreType::LOCAL_ONLY);
    ASSERT_NE(store, nullptr);
    auto impl = AsImpl(store);
    ASSERT_NE(impl, nullptr);
    std::string probeReason;
    if (!EnsureShrinkEngineReadyForTest(impl, probeReason)) {
        CloseStore(storeId, store);
        GTEST_SKIP() << probeReason;
    }

    ASSERT_EQ(store->SetShrinkEnable(true), SUCCESS);
    ASSERT_TRUE(WaitShrinkSettled(*impl, true, WAIT_SWITCH_TIMEOUT_MS));
    ASSERT_EQ(store->SetShrinkEnable(false), SUCCESS);
    ASSERT_TRUE(WaitShrinkSettled(*impl, false, WAIT_SWITCH_TIMEOUT_MS));
    auto settled = ReadShrinkState(*impl);
    EXPECT_FALSE(settled.desiredEnabled);
    EXPECT_EQ(settled.pendingTasks, 0u);

    EXPECT_EQ(store->SetShrinkEnable(false), SUCCESS);
    ASSERT_TRUE(WaitShrinkSettled(*impl, false, WAIT_SWITCH_TIMEOUT_MS));

    auto entries = MakeEntries("disable_then_delete_", PLAIN_KEYS, PLAIN_VALUE_SIZE);
    ASSERT_TRUE(PutBatchChunked(store, entries));
    bool checkpointBeforeDelete = CheckpointStore(impl);
    SleepMillis(SETTLE_INTERVAL_MS);
    DiskUsage written;
    bool measuredBefore = QueryStoreDiskUsage(storeId, written);
    ASSERT_TRUE(DeleteBatchChunked(store, MakeKeys(entries)));
    SleepMillis(NO_DELETE_OBSERVE_MS);
    bool checkpointAfterDelete = CheckpointStore(impl);
    SleepMillis(SETTLE_INTERVAL_MS);

    DiskUsage afterDelete;
    bool measuredAfter = QueryStoreDiskUsage(storeId, afterDelete);
    auto afterDeletes = ReadShrinkState(*impl);
    EXPECT_FALSE(afterDeletes.desiredEnabled);
    EXPECT_EQ(afterDeletes.pendingTasks, 0u);
    RecordProperty("disable_blocks_after_write", static_cast<int64_t>(written.dbBlockBytes));
    RecordProperty("disable_blocks_after_delete", static_cast<int64_t>(afterDelete.dbBlockBytes));
    RecordProperty("disable_switch_pending_tasks_after_delete",
        static_cast<int64_t>(afterDeletes.pendingTasks));
    RecordProperty("disable_other_bytes_after_write", static_cast<int64_t>(written.otherBlockBytes));
    RecordProperty("disable_other_bytes_after_delete", static_cast<int64_t>(afterDelete.otherBlockBytes));
    RecordProperty("disable_checkpoint_ok",
        std::string((checkpointBeforeDelete && checkpointAfterDelete) ? "true" : "false"));
    RecordProperty("disable_evidence_gap", std::string("an engine call or reclamation that started before "
        "the disable may still complete; no new switch task is queued; normal file housekeeping is tolerated"));
    CloseStore(storeId, store);
    if (!measuredBefore || !measuredAfter || written.dbBlockBytes == 0) {
        GTEST_SKIP() << "evidence gap: the RD database directory of the store is not measurable on this image";
    }

    EXPECT_FALSE(ExceedsHousekeepingDrop(written.dbBlockBytes, afterDelete.dbBlockBytes))
        << "physical usage dropped although shrink was disabled before the deletes";
}

HWTEST_F(EnableShrinkTest, ToggleDuringDeletePhysicalReclaim, TestSize.Level1)
{
    const std::string storeId = "EnableShrinkTogglePhysical";
    auto store = CreateStore(storeId, KvStoreType::LOCAL_ONLY);
    ASSERT_NE(store, nullptr);
    auto impl = AsImpl(store);
    ASSERT_NE(impl, nullptr);
    std::string probeReason;
    if (!EnsureShrinkEngineReadyForTest(impl, probeReason)) {
        CloseStore(storeId, store);
        GTEST_SKIP() << probeReason;
    }

    ASSERT_EQ(store->SetShrinkEnable(true), SUCCESS);
    ASSERT_TRUE(WaitShrinkSettled(*impl, true, WAIT_SWITCH_TIMEOUT_MS));
    auto enabledEntries = MakeEntries("toggle_physical_on_", RECLAIM_KEYS_PER_ROUND, RECLAIM_VALUE_SIZE);
    ASSERT_TRUE(PutBatchChunked(store, enabledEntries));
    bool checkpointEnabledBefore = CheckpointStore(impl);
    SleepMillis(SETTLE_INTERVAL_MS);
    DiskUsage enabledPeak;
    bool enabledMeasured = QueryStoreDiskUsage(storeId, enabledPeak);
    ASSERT_TRUE(DeleteBatchChunked(store, MakeKeys(enabledEntries)));
    bool checkpointEnabledAfter = CheckpointStore(impl);
    DiskUsage enabledFinal;
    bool enabledReclaimed = false;
    if (enabledMeasured) {
        auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(WAIT_RECLAIM_TIMEOUT_MS);
        while (std::chrono::steady_clock::now() < deadline) {
            if (QueryStoreDiskUsage(storeId, enabledFinal) &&
                HasReclaimDrop(enabledPeak.dbBlockBytes, enabledFinal.dbBlockBytes)) {
                enabledReclaimed = true;
                break;
            }
            SleepMillis(POLL_INTERVAL_MS);
        }
        if (!enabledReclaimed) {
            (void)QueryStoreDiskUsage(storeId, enabledFinal);
        }
    }
    RecordProperty("enabled_peak_blocks_bytes", static_cast<int64_t>(enabledPeak.dbBlockBytes));
    RecordProperty("enabled_final_blocks_bytes", static_cast<int64_t>(enabledFinal.dbBlockBytes));
    RecordProperty("enabled_drop_percent", DropPercent(enabledPeak.dbBlockBytes, enabledFinal.dbBlockBytes));
    RecordProperty("enabled_peak_other_bytes", static_cast<int64_t>(enabledPeak.otherBlockBytes));
    RecordProperty("enabled_final_other_bytes", static_cast<int64_t>(enabledFinal.otherBlockBytes));
    RecordProperty("enabled_checkpoint_ok",
        std::string((checkpointEnabledBefore && checkpointEnabledAfter) ? "true" : "false"));
    RecordProperty("enabled_reclaim_observed", std::string(enabledReclaimed ? "true" : "false"));

    ASSERT_EQ(store->SetShrinkEnable(false), SUCCESS);
    ASSERT_TRUE(WaitShrinkSettled(*impl, false, WAIT_SWITCH_TIMEOUT_MS));
    SleepMillis(NO_DELETE_OBSERVE_MS);
    auto disabledEntries = MakeEntries("toggle_physical_off_", RECLAIM_KEYS_PER_ROUND, RECLAIM_VALUE_SIZE);
    ASSERT_TRUE(PutBatchChunked(store, disabledEntries));
    bool checkpointDisabledBefore = CheckpointStore(impl);
    SleepMillis(SETTLE_INTERVAL_MS);
    DiskUsage disabledPeak;
    bool disabledMeasuredBefore = QueryStoreDiskUsage(storeId, disabledPeak);
    ASSERT_TRUE(DeleteBatchChunked(store, MakeKeys(disabledEntries)));
    SleepMillis(NO_DELETE_OBSERVE_MS);
    bool checkpointDisabledAfter = CheckpointStore(impl);
    SleepMillis(SETTLE_INTERVAL_MS);
    DiskUsage disabledFinal;
    bool disabledMeasuredAfter = QueryStoreDiskUsage(storeId, disabledFinal);
    bool disabledDropped = disabledMeasuredBefore && disabledMeasuredAfter &&
        ExceedsHousekeepingDrop(disabledPeak.dbBlockBytes, disabledFinal.dbBlockBytes);
    RecordProperty("disabled_peak_blocks_bytes", static_cast<int64_t>(disabledPeak.dbBlockBytes));
    RecordProperty("disabled_final_blocks_bytes", static_cast<int64_t>(disabledFinal.dbBlockBytes));
    RecordProperty("disabled_drop_percent", DropPercent(disabledPeak.dbBlockBytes, disabledFinal.dbBlockBytes));
    RecordProperty("disabled_peak_other_bytes", static_cast<int64_t>(disabledPeak.otherBlockBytes));
    RecordProperty("disabled_final_other_bytes", static_cast<int64_t>(disabledFinal.otherBlockBytes));
    RecordProperty("disabled_checkpoint_ok",
        std::string((checkpointDisabledBefore && checkpointDisabledAfter) ? "true" : "false"));
    RecordProperty("disabled_drop_observed", std::string(disabledDropped ? "true" : "false"));

    ASSERT_EQ(store->SetShrinkEnable(true), SUCCESS);
    ASSERT_TRUE(WaitShrinkSettled(*impl, true, WAIT_SWITCH_TIMEOUT_MS));
    auto reenabledEntries = MakeEntries("toggle_physical_again_", RECLAIM_KEYS_PER_ROUND, RECLAIM_VALUE_SIZE);
    ASSERT_TRUE(PutBatchChunked(store, reenabledEntries));
    bool checkpointReenabledBefore = CheckpointStore(impl);
    SleepMillis(SETTLE_INTERVAL_MS);
    DiskUsage reenabledPeak;
    bool reenabledMeasured = QueryStoreDiskUsage(storeId, reenabledPeak);
    ASSERT_TRUE(DeleteBatchChunked(store, MakeKeys(reenabledEntries)));
    bool checkpointReenabledAfter = CheckpointStore(impl);
    DiskUsage reenabledFinal;
    bool reenabledReclaimed = false;
    if (reenabledMeasured) {
        auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(WAIT_RECLAIM_TIMEOUT_MS);
        while (std::chrono::steady_clock::now() < deadline) {
            if (QueryStoreDiskUsage(storeId, reenabledFinal) &&
                HasReclaimDrop(reenabledPeak.dbBlockBytes, reenabledFinal.dbBlockBytes)) {
                reenabledReclaimed = true;
                break;
            }
            SleepMillis(POLL_INTERVAL_MS);
        }
        if (!reenabledReclaimed) {
            (void)QueryStoreDiskUsage(storeId, reenabledFinal);
        }
    }
    RecordProperty("reenabled_peak_blocks_bytes", static_cast<int64_t>(reenabledPeak.dbBlockBytes));
    RecordProperty("reenabled_final_blocks_bytes", static_cast<int64_t>(reenabledFinal.dbBlockBytes));
    RecordProperty("reenabled_drop_percent",
        DropPercent(reenabledPeak.dbBlockBytes, reenabledFinal.dbBlockBytes));
    RecordProperty("reenabled_peak_other_bytes", static_cast<int64_t>(reenabledPeak.otherBlockBytes));
    RecordProperty("reenabled_final_other_bytes", static_cast<int64_t>(reenabledFinal.otherBlockBytes));
    RecordProperty("reenabled_checkpoint_ok",
        std::string((checkpointReenabledBefore && checkpointReenabledAfter) ? "true" : "false"));
    RecordProperty("reenabled_reclaim_observed", std::string(reenabledReclaimed ? "true" : "false"));

    CloseStore(storeId, store);
    if (!enabledMeasured || !disabledMeasuredBefore || !disabledMeasuredAfter || !reenabledMeasured) {
        GTEST_SKIP() << "evidence gap: the RD database directory of the store is not measurable on this image";
    }

    EXPECT_FALSE(disabledDropped) << "physical usage dropped although the switch was disabled (peak="
        << disabledPeak.dbBlockBytes << ", final=" << disabledFinal.dbBlockBytes << ")";
    EXPECT_TRUE(enabledReclaimed)
        << "no shrink driven drop observed while enabled (peak=" << enabledPeak.dbBlockBytes
        << ", final=" << enabledFinal.dbBlockBytes << ")";
    EXPECT_TRUE(reenabledReclaimed)
        << "no shrink driven drop observed after re-enabling (peak=" << reenabledPeak.dbBlockBytes
        << ", final=" << reenabledFinal.dbBlockBytes << ")";
}

HWTEST_F(EnableShrinkTest, DeleteP95WithShrinkEnabled, TestSize.Level1)
{
    const std::string plainId = "EnableShrinkP95Plain";
    const std::string enabledId = "EnableShrinkP95Enabled";
    auto plain = CreateStore(plainId, KvStoreType::LOCAL_ONLY);
    ASSERT_NE(plain, nullptr);
    auto enabled = CreateStore(enabledId, KvStoreType::LOCAL_ONLY);
    ASSERT_NE(enabled, nullptr);
    auto impl = AsImpl(enabled);
    ASSERT_NE(impl, nullptr);
    std::string probeReason;
    if (!EnsureShrinkEngineReadyForTest(impl, probeReason)) {
        CloseStore(plainId, plain);
        CloseStore(enabledId, enabled);
        GTEST_SKIP() << probeReason;
    }

    auto acceptStart = std::chrono::steady_clock::now();
    ASSERT_EQ(enabled->SetShrinkEnable(true), SUCCESS);
    int64_t acceptUs = ElapsedMicros(acceptStart);
    ASSERT_TRUE(WaitShrinkSettled(*impl, true, WAIT_SWITCH_TIMEOUT_MS));

    std::vector<int64_t> plainDeleteP95s;
    std::vector<int64_t> enabledDeleteP95s;
    std::vector<int64_t> plainBatchP95s;
    std::vector<int64_t> enabledBatchP95s;
    std::vector<int64_t> plainWriteBytesPerSec;
    std::vector<int64_t> enabledWriteBytesPerSec;
    DiskUsage enabledPeak;
    DiskUsage enabledFinal;
    bool allCheckpointsOk = true;

    for (int32_t round = 0; round < PERF_ROUNDS; ++round) {
        std::string prefix = "perf_" + std::to_string(round) + "_";
        auto deleteEntries = MakeEntries(prefix + "delete_", PERF_DELETE_SAMPLES, PERF_VALUE_SIZE);
        std::vector<Entry> batchEntries;
        batchEntries.reserve(static_cast<size_t>(PERF_BATCH_SAMPLES) * PERF_BATCH_SIZE);
        for (int32_t batch = 0; batch < PERF_BATCH_SAMPLES; ++batch) {
            auto entries = MakeEntries(prefix + "batch_" + std::to_string(batch) + "_",
                PERF_BATCH_SIZE, PERF_VALUE_SIZE);
            batchEntries.insert(batchEntries.end(), entries.begin(), entries.end());
        }
        std::vector<Entry> allEntries = deleteEntries;
        allEntries.insert(allEntries.end(), batchEntries.begin(), batchEntries.end());
        int64_t allBytes = static_cast<int64_t>(allEntries.size() * PERF_VALUE_SIZE);

        auto plainWriteStart = std::chrono::steady_clock::now();
        ASSERT_TRUE(PutBatchChunked(plain, allEntries));
        int64_t plainWriteUs = ElapsedMicros(plainWriteStart);
        auto enabledWriteStart = std::chrono::steady_clock::now();
        ASSERT_TRUE(PutBatchChunked(enabled, allEntries));
        int64_t enabledWriteUs = ElapsedMicros(enabledWriteStart);
        plainWriteBytesPerSec.push_back(plainWriteUs > 0 ? allBytes * 1000000 / plainWriteUs : 0);
        enabledWriteBytesPerSec.push_back(enabledWriteUs > 0 ? allBytes * 1000000 / enabledWriteUs : 0);
        SleepMillis(SETTLE_INTERVAL_MS);
        allCheckpointsOk = CheckpointStore(impl) && allCheckpointsOk;
        SleepMillis(SETTLE_INTERVAL_MS);
        DiskUsage written;
        if (QueryStoreDiskUsage(enabledId, written) && written.dbBlockBytes > enabledPeak.dbBlockBytes) {
            enabledPeak = written;
        }

        std::vector<int64_t> plainSamples;
        plainSamples.reserve(PERF_DELETE_SAMPLES);
        for (int32_t index = 0; index < PERF_DELETE_SAMPLES; ++index) {
            auto start = std::chrono::steady_clock::now();
            EXPECT_EQ(plain->Delete(deleteEntries[index].key), SUCCESS);
            plainSamples.push_back(ElapsedMicros(start));
        }
        std::vector<int64_t> enabledSamples;
        enabledSamples.reserve(PERF_DELETE_SAMPLES);
        for (int32_t index = 0; index < PERF_DELETE_SAMPLES; ++index) {
            auto start = std::chrono::steady_clock::now();
            EXPECT_EQ(enabled->Delete(deleteEntries[index].key), SUCCESS);
            enabledSamples.push_back(ElapsedMicros(start));
        }
        plainDeleteP95s.push_back(Percentile(plainSamples, 95));
        enabledDeleteP95s.push_back(Percentile(enabledSamples, 95));

        std::vector<int64_t> plainBatchSamples;
        plainBatchSamples.reserve(PERF_BATCH_SAMPLES);
        std::vector<int64_t> enabledBatchSamples;
        enabledBatchSamples.reserve(PERF_BATCH_SAMPLES);
        for (int32_t batch = 0; batch < PERF_BATCH_SAMPLES; ++batch) {
            size_t begin = static_cast<size_t>(batch) * PERF_BATCH_SIZE;
            std::vector<Key> batchKeys;
            batchKeys.reserve(PERF_BATCH_SIZE);
            for (int32_t index = 0; index < PERF_BATCH_SIZE; ++index) {
                batchKeys.push_back(batchEntries[begin + index].key);
            }
            auto plainBatchStart = std::chrono::steady_clock::now();
            EXPECT_TRUE(DeleteBatchChunked(plain, batchKeys));
            plainBatchSamples.push_back(ElapsedMicros(plainBatchStart));
            auto enabledBatchStart = std::chrono::steady_clock::now();
            EXPECT_TRUE(DeleteBatchChunked(enabled, batchKeys));
            enabledBatchSamples.push_back(ElapsedMicros(enabledBatchStart));
        }
        plainBatchP95s.push_back(Percentile(plainBatchSamples, 95));
        enabledBatchP95s.push_back(Percentile(enabledBatchSamples, 95));

        SleepMillis(SETTLE_INTERVAL_MS);
        allCheckpointsOk = CheckpointStore(impl) && allCheckpointsOk;
        SleepMillis(SETTLE_INTERVAL_MS);
        DiskUsage afterRound;
        if (QueryStoreDiskUsage(enabledId, afterRound)) {
            if (!enabledFinal.valid || afterRound.dbBlockBytes < enabledFinal.dbBlockBytes) {
                enabledFinal = afterRound;
            }
        }
    }

    if (enabledPeak.valid && enabledPeak.dbBlockBytes > 0) {
        auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(WAIT_RECLAIM_TIMEOUT_MS);
        while (true) {
            DiskUsage current;
            if (QueryStoreDiskUsage(enabledId, current) &&
                (!enabledFinal.valid || current.dbBlockBytes < enabledFinal.dbBlockBytes)) {
                enabledFinal = current;
            }
            int64_t dropped = enabledFinal.valid ?
                static_cast<int64_t>(enabledPeak.dbBlockBytes) -
                static_cast<int64_t>(enabledFinal.dbBlockBytes) : 0;
            if (dropped > 0 &&
                dropped * 100 / static_cast<int64_t>(enabledPeak.dbBlockBytes) >= PERF_RECLAIM_MIN_DROP_PERCENT) {
                break;
            }
            if (std::chrono::steady_clock::now() >= deadline) {
                break;
            }
            SleepMillis(POLL_INTERVAL_MS);
        }
    }

    int64_t plainDeleteP95 = Median(plainDeleteP95s);
    int64_t enabledDeleteP95 = Median(enabledDeleteP95s);
    int64_t plainBatchP95 = Median(plainBatchP95s);
    int64_t enabledBatchP95 = Median(enabledBatchP95s);
    int64_t plainWrite = Median(plainWriteBytesPerSec);
    int64_t enabledWrite = Median(enabledWriteBytesPerSec);
    int64_t deleteDegradePercent = plainDeleteP95 > 0 ?
        (enabledDeleteP95 - plainDeleteP95) * 100 / plainDeleteP95 : 0;
    int64_t batchDegradePercent = plainBatchP95 > 0 ?
        (enabledBatchP95 - plainBatchP95) * 100 / plainBatchP95 : 0;
    int64_t writeDegradePercent = plainWrite > 0 ? (plainWrite - enabledWrite) * 100 / plainWrite : 0;
    int64_t reclaimDropPercent = DropPercent(enabledPeak.dbBlockBytes, enabledFinal.dbBlockBytes);

    auto disableStart = std::chrono::steady_clock::now();
    Status disableStatus = enabled->SetShrinkEnable(false);
    int64_t disableUs = ElapsedMicros(disableStart);
    ASSERT_TRUE(WaitShrinkSettled(*impl, false, WAIT_SWITCH_TIMEOUT_MS));
    RecordProperty("switch_accept_us", acceptUs);
    RecordProperty("switch_disable_us", disableUs);
    RecordProperty("perf_rounds", static_cast<int64_t>(PERF_ROUNDS));
    RecordProperty("delete_p95_plain_us", plainDeleteP95);
    RecordProperty("delete_p95_enabled_us", enabledDeleteP95);
    RecordProperty("delete_p95_degrade_percent", deleteDegradePercent);
    RecordProperty("batch_p95_plain_us", plainBatchP95);
    RecordProperty("batch_p95_enabled_us", enabledBatchP95);
    RecordProperty("batch_p95_degrade_percent", batchDegradePercent);
    RecordProperty("write_plain_bytes_per_sec", plainWrite);
    RecordProperty("write_enabled_bytes_per_sec", enabledWrite);
    RecordProperty("write_degrade_percent", writeDegradePercent);
    RecordProperty("enabled_reclaim_peak_bytes", static_cast<int64_t>(enabledPeak.dbBlockBytes));
    RecordProperty("enabled_reclaim_final_bytes", static_cast<int64_t>(enabledFinal.dbBlockBytes));
    RecordProperty("enabled_reclaim_peak_other_bytes", static_cast<int64_t>(enabledPeak.otherBlockBytes));
    RecordProperty("enabled_reclaim_final_other_bytes", static_cast<int64_t>(enabledFinal.otherBlockBytes));
    RecordProperty("enabled_reclaim_peak_all_bytes", static_cast<int64_t>(enabledPeak.blockBytes));
    RecordProperty("enabled_reclaim_final_all_bytes", static_cast<int64_t>(enabledFinal.blockBytes));
    RecordProperty("enabled_reclaim_drop_percent", reclaimDropPercent);
    RecordProperty("perf_checkpoint_ok", std::string(allCheckpointsOk ? "true" : "false"));

    EXPECT_EQ(disableStatus, SUCCESS);
    EXPECT_LE(acceptUs, MAX_ACCEPT_MILLIS * 1000);
    EXPECT_LE(disableUs, MAX_ACCEPT_MILLIS * 1000);
    CloseStore(enabledId, enabled);
    CloseStore(plainId, plain);

    if (!enabledPeak.valid || !enabledFinal.valid || enabledPeak.dbBlockBytes == 0) {
        GTEST_SKIP() << "evidence gap: the RD database directory of the store is not measurable on this image";
    }
    EXPECT_GE(reclaimDropPercent, PERF_RECLAIM_MIN_DROP_PERCENT)
        << "the enabled store did not show engine reclamation during the measured workload (peak="
        << enabledPeak.dbBlockBytes << ", final=" << enabledFinal.dbBlockBytes << ")";
    int64_t deleteAllowed = std::max(plainDeleteP95 * PERF_DEGRADE_LIMIT_PERCENT / 100, PERF_ABS_JITTER_US);
    int64_t batchAllowed = std::max(plainBatchP95 * PERF_DEGRADE_LIMIT_PERCENT / 100, PERF_ABS_JITTER_US);
    EXPECT_LE(enabledDeleteP95 - plainDeleteP95, deleteAllowed)
        << "Delete P95 degraded by " << deleteDegradePercent << "% (" << plainDeleteP95 << " -> "
        << enabledDeleteP95 << " us)";
    EXPECT_LE(enabledBatchP95 - plainBatchP95, batchAllowed)
        << "DeleteBatch P95 degraded by " << batchDegradePercent << "% (" << plainBatchP95 << " -> "
        << enabledBatchP95 << " us)";
    EXPECT_GE(enabledWrite, plainWrite * (100 - PERF_DEGRADE_LIMIT_PERCENT) / 100)
        << "PutBatch throughput degraded by " << writeDegradePercent << "% (" << plainWrite << " -> "
        << enabledWrite << " bytes/sec)";
}

HWTEST_F(EnableShrinkTest, ShrinkManagerSetDesiredBranches, TestSize.Level1)
{
    ShrinkManager manager;
    EXPECT_TRUE(manager.SetDesired(true));
    EXPECT_FALSE(manager.SetDesired(true));
    bool desired = false;
    uint32_t pending = 0;
    manager.GetState(desired, pending);
    EXPECT_TRUE(desired);
    EXPECT_EQ(pending, 1u);
    EXPECT_TRUE(manager.TryBegin(true));
    EXPECT_FALSE(manager.TryBegin(false));
    manager.Finish();
    manager.GetState(desired, pending);
    EXPECT_EQ(pending, 0u);
    EXPECT_TRUE(manager.SetDesired(true));
    manager.GetState(desired, pending);
    EXPECT_EQ(pending, 1u);
    manager.Finish();
    EXPECT_TRUE(manager.SetDesired(false));
    EXPECT_TRUE(manager.SetDesired(true));
    manager.GetState(desired, pending);
    EXPECT_EQ(pending, 2u);
    manager.Finish();
    manager.Finish();
    manager.GetState(desired, pending);
    EXPECT_EQ(pending, 0u);
}

HWTEST_F(EnableShrinkTest, RunShrinkAfterClose, TestSize.Level1)
{
    const std::string storeId = "EnableShrinkRunAfterClose";
    auto store = CreateStore(storeId, KvStoreType::LOCAL_ONLY);
    ASSERT_NE(store, nullptr);
    auto impl = AsImpl(store);
    ASSERT_NE(impl, nullptr);
    EXPECT_TRUE(impl->shrinkManager_.SetDesired(true));
    auto dbStore = impl->dbStore_;
    impl->dbStore_ = nullptr;
    impl->RunShrink(true);
    impl->dbStore_ = dbStore;
    bool desired = false;
    uint32_t pending = 1;
    impl->GetShrinkStateForTest(desired, pending);
    EXPECT_TRUE(desired);
    EXPECT_EQ(pending, 0u);
    CloseStore(storeId, store);
}
}