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

constexpr int64_t WAIT_SWITCH_TIMEOUT_MS = 5000;

constexpr int64_t WAIT_RECLAIM_TIMEOUT_MS = 15000;
constexpr int64_t POLL_INTERVAL_MS = 200;
constexpr int64_t SETTLE_INTERVAL_MS = 200;
constexpr int64_t NO_DELETE_OBSERVE_MS = 3000;
constexpr int64_t MAX_ACCEPT_MILLIS = 1000;

constexpr uint64_t HOUSEKEEPING_DROP_PERCENT = 25;

constexpr int32_t RECLAIM_ROUNDS = 3;
constexpr int32_t RECLAIM_KEYS_PER_ROUND = 256;
constexpr size_t RECLAIM_VALUE_SIZE = 8 * 1024;

constexpr int32_t RECLAIM_BIG_ROUNDS = 5;
constexpr int32_t RECLAIM_BIG_KEYS_PER_ROUND = 512;
constexpr size_t RECLAIM_BIG_VALUE_SIZE = 8 * 1024;

constexpr int64_t RECLAIM_MIN_DROP_PERCENT = 85;

constexpr int32_t PLAIN_KEYS = 512;
constexpr size_t PLAIN_VALUE_SIZE = 4 * 1024;

constexpr int32_t BELOW_THRESHOLD_DELETE_KEYS = 160;

constexpr int32_t CONCURRENT_KEYS = 512;
constexpr size_t CONCURRENT_VALUE_SIZE = 256;
constexpr int32_t CONCURRENT_READERS = 3;
constexpr int64_t CONCURRENT_WORKLOAD_MS = 2500;
constexpr int64_t READER_YIELD_MS = 1;

constexpr int32_t PERF_ROUNDS = 3;
constexpr int32_t PERF_DELETE_SAMPLES = 200;
constexpr int32_t PERF_BATCH_SAMPLES = 200;
constexpr int32_t PERF_BATCH_SIZE = 8;
constexpr size_t PERF_VALUE_SIZE = 1024;

constexpr int64_t PERF_DEGRADE_LIMIT_PERCENT = 10;
constexpr int64_t PERF_ABS_JITTER_US = 200;


struct DiskUsage {
    uint64_t blockBytes = 0;
    uint32_t fileCount = 0;
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
        if (info.st_blocks > 0) {
            usage.blockBytes += static_cast<uint64_t>(info.st_blocks) * 512ULL;
        }
        usage.fileCount++;
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

std::vector<Entry> MakeEntries(const std::string &prefix, int32_t count, size_t valueSize)
{
    std::vector<Entry> entries;
    entries.reserve(static_cast<size_t>(count));
    std::string value(valueSize, 'v');
    for (int32_t index = 0; index < count; ++index) {
        Entry entry;
        entry.key = prefix + std::to_string(index);
        entry.value = value;
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

bool EntryValueEquals(const SingleStoreImpl::DBEntry &entry, const std::string &expected)
{
    return std::string(entry.value.begin(), entry.value.end()) == expected;
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
    ASSERT_EQ(store->SetShrinkEnable(true), SUCCESS);
    auto impl = AsImpl(store);
    ASSERT_NE(impl, nullptr);
    ASSERT_TRUE(WaitShrinkSettled(*impl, true, WAIT_SWITCH_TIMEOUT_MS));

    DiskUsage peak;
    for (int32_t round = 0; round < RECLAIM_BIG_ROUNDS; ++round) {
        std::string prefix = "reclaim_big_" + std::to_string(round) + "_";
        auto entries = MakeEntries(prefix, RECLAIM_BIG_KEYS_PER_ROUND, RECLAIM_BIG_VALUE_SIZE);
        ASSERT_EQ(store->PutBatch(entries), SUCCESS);
        SleepMillis(SETTLE_INTERVAL_MS);
        DiskUsage written;
        if (QueryStoreDiskUsage(storeId, written) && written.blockBytes > peak.blockBytes) {
            peak = written;
        }
        ASSERT_EQ(store->DeleteBatch(MakeKeys(entries)), SUCCESS);
        SleepMillis(SETTLE_INTERVAL_MS);
    }

    DiskUsage finalUsage;
    int64_t dropPercent = 0;
    if (peak.valid) {
        auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(WAIT_RECLAIM_TIMEOUT_MS);
        while (true) {
            DiskUsage current;
            if (QueryStoreDiskUsage(storeId, current) && current.blockBytes < peak.blockBytes) {
                int64_t dropped = static_cast<int64_t>(peak.blockBytes) - static_cast<int64_t>(current.blockBytes);
                int64_t percent = dropped * 100 / static_cast<int64_t>(peak.blockBytes);
                if (percent > dropPercent) {
                    dropPercent = percent;
                    finalUsage = current;
                }
                if (dropPercent >= RECLAIM_MIN_DROP_PERCENT) {
                    break;
                }
            }
            if (std::chrono::steady_clock::now() >= deadline) {
                break;
            }
            SleepMillis(POLL_INTERVAL_MS);
        }
        if (!finalUsage.valid) {
            (void)QueryStoreDiskUsage(storeId, finalUsage);
        }
    }
    RecordProperty("physical_peak_blocks_bytes", static_cast<int64_t>(peak.blockBytes));
    RecordProperty("physical_final_blocks_bytes", static_cast<int64_t>(finalUsage.blockBytes));
    RecordProperty("physical_drop_percent", dropPercent);
    CloseStore(storeId, store);
    if (!peak.valid) {
        GTEST_SKIP() << "evidence gap: the RD database directory of the store is not measurable on this image";
    }
    EXPECT_GE(dropPercent, RECLAIM_MIN_DROP_PERCENT)
        << "physical usage only dropped " << dropPercent << "% (peak=" << peak.blockBytes
        << ", final=" << finalUsage.blockBytes << ")";
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
    auto initialState = ReadShrinkState(*impl);
    EXPECT_FALSE(initialState.desiredEnabled);
    EXPECT_EQ(initialState.pendingTasks, 0u);

    auto entries = MakeEntries("noenable_", PLAIN_KEYS, PLAIN_VALUE_SIZE);
    ASSERT_EQ(store->PutBatch(entries), SUCCESS);
    SleepMillis(SETTLE_INTERVAL_MS);
    DiskUsage written;
    bool measuredBefore = QueryStoreDiskUsage(storeId, written);
    ASSERT_EQ(store->DeleteBatch(MakeKeys(entries)), SUCCESS);
    SleepMillis(NO_DELETE_OBSERVE_MS);

    DiskUsage afterDelete;
    bool measuredAfter = QueryStoreDiskUsage(storeId, afterDelete);
    auto endState = ReadShrinkState(*impl);
    EXPECT_FALSE(endState.desiredEnabled);
    EXPECT_EQ(endState.pendingTasks, 0u);
    RecordProperty("noenable_bytes_after_write", static_cast<int64_t>(written.blockBytes));
    RecordProperty("noenable_bytes_after_delete", static_cast<int64_t>(afterDelete.blockBytes));
    RecordProperty("noenable_evidence_gap", std::string("the engine internal file housekeeping is not "
        "controllable; no switch task is ever requested, so the desired state stays false and no task "
        "is pending"));
    CloseStore(storeId, store);
    if (!measuredBefore || !measuredAfter) {
        GTEST_SKIP() << "evidence gap: the RD database directory of the store is not measurable on this image";
    }

    EXPECT_FALSE(ExceedsHousekeepingDrop(written.blockBytes, afterDelete.blockBytes))
        << "physical usage dropped although shrink was never enabled";
}

HWTEST_F(EnableShrinkTest, NoDeleteNoReclaim, TestSize.Level1)
{
    const std::string storeId = "EnableShrinkNoDelete";
    auto store = CreateStore(storeId, KvStoreType::LOCAL_ONLY);
    ASSERT_NE(store, nullptr);
    ASSERT_EQ(store->SetShrinkEnable(true), SUCCESS);
    auto impl = AsImpl(store);
    ASSERT_NE(impl, nullptr);
    ASSERT_TRUE(WaitShrinkSettled(*impl, true, WAIT_SWITCH_TIMEOUT_MS));

    auto entries = MakeEntries("nodelete_", PLAIN_KEYS, PLAIN_VALUE_SIZE);
    ASSERT_EQ(store->PutBatch(entries), SUCCESS);
    SleepMillis(SETTLE_INTERVAL_MS);
    DiskUsage baseline;
    bool measured = QueryStoreDiskUsage(storeId, baseline);

    uint64_t minimumBytes = baseline.blockBytes;
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(NO_DELETE_OBSERVE_MS);
    while (std::chrono::steady_clock::now() < deadline) {
        SleepMillis(POLL_INTERVAL_MS);
        DiskUsage sample;
        if (QueryStoreDiskUsage(storeId, sample) && sample.blockBytes < minimumBytes) {
            minimumBytes = sample.blockBytes;
        }
    }
    auto endState = ReadShrinkState(*impl);
    EXPECT_TRUE(endState.desiredEnabled);
    EXPECT_EQ(endState.pendingTasks, 0u);
    RecordProperty("nodelete_baseline_blocks_bytes", static_cast<int64_t>(baseline.blockBytes));
    RecordProperty("nodelete_minimum_blocks_bytes", static_cast<int64_t>(minimumBytes));
    RecordProperty("nodelete_evidence_gap", std::string("the engine reclamation threshold is internal and "
        "not controllable; normal file housekeeping is tolerated below the shrink scale"));
    CloseStore(storeId, store);
    if (!measured) {
        GTEST_SKIP() << "evidence gap: the RD database directory of the store is not measurable on this image";
    }
    EXPECT_FALSE(ExceedsHousekeepingDrop(baseline.blockBytes, minimumBytes))
        << "physical usage dropped without deletes";
}

HWTEST_F(EnableShrinkTest, BelowThresholdNoReclaim, TestSize.Level1)
{
    const std::string storeId = "EnableShrinkBelowThreshold";
    auto store = CreateStore(storeId, KvStoreType::LOCAL_ONLY);
    ASSERT_NE(store, nullptr);
    ASSERT_EQ(store->SetShrinkEnable(true), SUCCESS);
    auto impl = AsImpl(store);
    ASSERT_NE(impl, nullptr);
    ASSERT_TRUE(WaitShrinkSettled(*impl, true, WAIT_SWITCH_TIMEOUT_MS));

    auto entries = MakeEntries("below_threshold_", PLAIN_KEYS, PLAIN_VALUE_SIZE);
    ASSERT_EQ(store->PutBatch(entries), SUCCESS);
    SleepMillis(SETTLE_INTERVAL_MS);
    DiskUsage baseline;
    bool measured = QueryStoreDiskUsage(storeId, baseline);

    std::vector<Key> deleteKeys;
    deleteKeys.reserve(BELOW_THRESHOLD_DELETE_KEYS);
    for (int32_t index = 0; index < BELOW_THRESHOLD_DELETE_KEYS; ++index) {
        deleteKeys.push_back(entries[index].key);
    }
    ASSERT_EQ(store->DeleteBatch(deleteKeys), SUCCESS);

    uint64_t minimumBytes = baseline.blockBytes;
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(NO_DELETE_OBSERVE_MS);
    while (std::chrono::steady_clock::now() < deadline) {
        SleepMillis(POLL_INTERVAL_MS);
        DiskUsage sample;
        if (QueryStoreDiskUsage(storeId, sample) && sample.blockBytes < minimumBytes) {
            minimumBytes = sample.blockBytes;
        }
    }
    RecordProperty("below_threshold_deleted_keys", static_cast<int64_t>(BELOW_THRESHOLD_DELETE_KEYS));
    RecordProperty("below_threshold_deleted_bytes",
        static_cast<int64_t>(BELOW_THRESHOLD_DELETE_KEYS) * static_cast<int64_t>(PLAIN_VALUE_SIZE));
    RecordProperty("below_threshold_baseline_blocks_bytes", static_cast<int64_t>(baseline.blockBytes));
    RecordProperty("below_threshold_minimum_blocks_bytes", static_cast<int64_t>(minimumBytes));
    RecordProperty("below_threshold_construction_note", std::string("the per-space free-list is internal; "
        "deleted bytes (640 KiB) are below the 1 MiB threshold"));
    CloseStore(storeId, store);
    if (!measured) {
        GTEST_SKIP() << "environment limitation: the RD database directory of the store is not measurable "
                        "on this image";
    }
    EXPECT_FALSE(ExceedsHousekeepingDrop(baseline.blockBytes, minimumBytes))
        << "physical usage dropped after a below-threshold delete";
}

HWTEST_F(EnableShrinkTest, ConcurrentReadDuringReclaim, TestSize.Level1)
{
    const std::string storeId = "EnableShrinkConcurrentRead";
    auto store = CreateStore(storeId, KvStoreType::LOCAL_ONLY);
    ASSERT_NE(store, nullptr);
    ASSERT_EQ(store->SetShrinkEnable(true), SUCCESS);
    auto impl = AsImpl(store);
    ASSERT_NE(impl, nullptr);
    ASSERT_TRUE(WaitShrinkSettled(*impl, true, WAIT_SWITCH_TIMEOUT_MS));

    const std::string prefix = "concurrent_stable_";
    auto entries = MakeEntries(prefix, CONCURRENT_KEYS, CONCURRENT_VALUE_SIZE);
    ASSERT_EQ(store->PutBatch(entries), SUCCESS);
    const Key stableKey = entries[1].key;
    const std::string expectedValue = entries[1].value.ToString();
    const Key queryPrefix = prefix;

    DiskUsage before;
    bool measuredBefore = QueryStoreDiskUsage(storeId, before);

    std::atomic<bool> stop { false };
    std::atomic<int32_t> readFailures { 0 };
    std::vector<std::thread> readers;
    readers.reserve(CONCURRENT_READERS);
    for (int32_t index = 0; index < CONCURRENT_READERS; ++index) {
        readers.emplace_back([&store, &stop, &readFailures, impl, stableKey, expectedValue, queryPrefix]() {
            while (!stop.load()) {
                Value value;
                if (store->Get(stableKey, value) != SUCCESS || value.ToString() != expectedValue) {
                    readFailures.fetch_add(1);
                }
                std::vector<SingleStoreImpl::DBEntry> queried;
                if (!ReadEntriesByPrefix(impl, queryPrefix, queried)) {
                    readFailures.fetch_add(1);
                } else {
                    for (const auto &entry : queried) {
                        if (!EntryValueEquals(entry, expectedValue)) {
                            readFailures.fetch_add(1);
                        }
                    }
                }
                DistributedDB::KvStoreResultSet *resultSet = nullptr;
                if (!ReadResultSetByPrefix(impl, queryPrefix, resultSet)) {
                    readFailures.fetch_add(1);
                } else if (resultSet != nullptr) {
                    int32_t count = resultSet->GetCount();

                    if (count < 0 || count > CONCURRENT_KEYS) {
                        readFailures.fetch_add(1);
                    }
                    while (resultSet->MoveToNext()) {
                        SingleStoreImpl::DBEntry entry;
                        if (resultSet->GetEntry(entry) != SingleStoreImpl::DBStatus::OK ||
                            !EntryValueEquals(entry, expectedValue)) {
                            readFailures.fetch_add(1);
                        }
                    }
                    (void)impl->dbStore_->CloseResultSet(resultSet);
                }
                SleepMillis(READER_YIELD_MS);
            }
        });
    }

    std::atomic<int32_t> writeFailures { 0 };
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(CONCURRENT_WORKLOAD_MS);
    int32_t nextIndex = 0;
    while (std::chrono::steady_clock::now() < deadline) {
        if (nextIndex >= CONCURRENT_KEYS) {
            SleepMillis(POLL_INTERVAL_MS);
            continue;
        }
        std::vector<Key> keys;
        for (int32_t step = 0; step < 16 && nextIndex < CONCURRENT_KEYS; step += 2) {
            keys.push_back(entries[nextIndex].key);
            nextIndex += 2;
        }
        if (!keys.empty() && store->DeleteBatch(keys) != SUCCESS) {
            writeFailures.fetch_add(1);
        }
        SleepMillis(10);
    }
    stop.store(true);
    for (auto &reader : readers) {
        reader.join();
    }
    EXPECT_EQ(readFailures.load(), 0);
    EXPECT_EQ(writeFailures.load(), 0);

    Value value;
    EXPECT_EQ(store->Get(stableKey, value), SUCCESS);
    EXPECT_EQ(value.ToString(), expectedValue);
    EXPECT_EQ(store->Get(entries[0].key, value), KEY_NOT_FOUND);

    DiskUsage after;
    bool measuredAfter = QueryStoreDiskUsage(storeId, after);
    bool dropObserved = measuredBefore && measuredAfter && HasReclaimDrop(before.blockBytes, after.blockBytes);
    RecordProperty("concurrent_readers", static_cast<int64_t>(CONCURRENT_READERS));
    RecordProperty("concurrent_physical_drop_observed", std::string(dropObserved ? "true" : "false"));
    RecordProperty("concurrent_evidence_gap", std::string("the engine internal reclamation window is not "
        "directly observable; concurrent reads are verified while shrink is enabled and deletes run"));
    CloseStore(storeId, store);
}

HWTEST_F(EnableShrinkTest, DisableStopsNewReclaim, TestSize.Level1)
{
    const std::string storeId = "EnableShrinkDisablePending";
    auto store = CreateStore(storeId, KvStoreType::LOCAL_ONLY);
    ASSERT_NE(store, nullptr);
    auto impl = AsImpl(store);
    ASSERT_NE(impl, nullptr);

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
    ASSERT_EQ(store->PutBatch(entries), SUCCESS);
    SleepMillis(SETTLE_INTERVAL_MS);
    DiskUsage written;
    bool measuredBefore = QueryStoreDiskUsage(storeId, written);
    ASSERT_EQ(store->DeleteBatch(MakeKeys(entries)), SUCCESS);
    SleepMillis(NO_DELETE_OBSERVE_MS);

    DiskUsage afterDelete;
    bool measuredAfter = QueryStoreDiskUsage(storeId, afterDelete);
    auto afterDeletes = ReadShrinkState(*impl);
    EXPECT_FALSE(afterDeletes.desiredEnabled);
    EXPECT_EQ(afterDeletes.pendingTasks, 0u);
    RecordProperty("disable_blocks_after_write", static_cast<int64_t>(written.blockBytes));
    RecordProperty("disable_blocks_after_delete", static_cast<int64_t>(afterDelete.blockBytes));
    RecordProperty("disable_switch_pending_tasks_after_delete",
        static_cast<int64_t>(afterDeletes.pendingTasks));
    RecordProperty("disable_evidence_gap", std::string("an engine call or reclamation that started before "
        "the disable may still complete; no new switch task is queued; normal file housekeeping is tolerated"));
    CloseStore(storeId, store);
    if (!measuredBefore || !measuredAfter) {
        GTEST_SKIP() << "evidence gap: the RD database directory of the store is not measurable on this image";
    }

    EXPECT_FALSE(ExceedsHousekeepingDrop(written.blockBytes, afterDelete.blockBytes))
        << "physical usage dropped although shrink was disabled before the deletes";
}

HWTEST_F(EnableShrinkTest, ToggleDuringDeletePhysicalReclaim, TestSize.Level1)
{
    const std::string storeId = "EnableShrinkTogglePhysical";
    auto store = CreateStore(storeId, KvStoreType::LOCAL_ONLY);
    ASSERT_NE(store, nullptr);
    auto impl = AsImpl(store);
    ASSERT_NE(impl, nullptr);

    ASSERT_EQ(store->SetShrinkEnable(true), SUCCESS);
    ASSERT_TRUE(WaitShrinkSettled(*impl, true, WAIT_SWITCH_TIMEOUT_MS));
    auto enabledEntries = MakeEntries("toggle_physical_on_", RECLAIM_KEYS_PER_ROUND, RECLAIM_VALUE_SIZE);
    ASSERT_EQ(store->PutBatch(enabledEntries), SUCCESS);
    SleepMillis(SETTLE_INTERVAL_MS);
    DiskUsage enabledPeak;
    bool enabledMeasured = QueryStoreDiskUsage(storeId, enabledPeak);
    ASSERT_EQ(store->DeleteBatch(MakeKeys(enabledEntries)), SUCCESS);
    DiskUsage enabledFinal;
    bool enabledReclaimed = false;
    if (enabledMeasured) {
        auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(WAIT_RECLAIM_TIMEOUT_MS);
        while (std::chrono::steady_clock::now() < deadline) {
            if (QueryStoreDiskUsage(storeId, enabledFinal) &&
                HasReclaimDrop(enabledPeak.blockBytes, enabledFinal.blockBytes)) {
                enabledReclaimed = true;
                break;
            }
            SleepMillis(POLL_INTERVAL_MS);
        }
        if (!enabledReclaimed) {
            (void)QueryStoreDiskUsage(storeId, enabledFinal);
        }
    }
    RecordProperty("enabled_peak_blocks_bytes", static_cast<int64_t>(enabledPeak.blockBytes));
    RecordProperty("enabled_final_blocks_bytes", static_cast<int64_t>(enabledFinal.blockBytes));
    RecordProperty("enabled_drop_percent", DropPercent(enabledPeak.blockBytes, enabledFinal.blockBytes));
    RecordProperty("enabled_reclaim_observed", std::string(enabledReclaimed ? "true" : "false"));

    ASSERT_EQ(store->SetShrinkEnable(false), SUCCESS);
    ASSERT_TRUE(WaitShrinkSettled(*impl, false, WAIT_SWITCH_TIMEOUT_MS));
    SleepMillis(NO_DELETE_OBSERVE_MS);
    auto disabledEntries = MakeEntries("toggle_physical_off_", RECLAIM_KEYS_PER_ROUND, RECLAIM_VALUE_SIZE);
    ASSERT_EQ(store->PutBatch(disabledEntries), SUCCESS);
    SleepMillis(SETTLE_INTERVAL_MS);
    DiskUsage disabledPeak;
    bool disabledMeasuredBefore = QueryStoreDiskUsage(storeId, disabledPeak);
    ASSERT_EQ(store->DeleteBatch(MakeKeys(disabledEntries)), SUCCESS);
    SleepMillis(NO_DELETE_OBSERVE_MS);
    DiskUsage disabledFinal;
    bool disabledMeasuredAfter = QueryStoreDiskUsage(storeId, disabledFinal);
    bool disabledDropped = disabledMeasuredBefore && disabledMeasuredAfter &&
        ExceedsHousekeepingDrop(disabledPeak.blockBytes, disabledFinal.blockBytes);
    RecordProperty("disabled_peak_blocks_bytes", static_cast<int64_t>(disabledPeak.blockBytes));
    RecordProperty("disabled_final_blocks_bytes", static_cast<int64_t>(disabledFinal.blockBytes));
    RecordProperty("disabled_drop_percent", DropPercent(disabledPeak.blockBytes, disabledFinal.blockBytes));
    RecordProperty("disabled_drop_observed", std::string(disabledDropped ? "true" : "false"));

    ASSERT_EQ(store->SetShrinkEnable(true), SUCCESS);
    ASSERT_TRUE(WaitShrinkSettled(*impl, true, WAIT_SWITCH_TIMEOUT_MS));
    auto reenabledEntries = MakeEntries("toggle_physical_again_", RECLAIM_KEYS_PER_ROUND, RECLAIM_VALUE_SIZE);
    ASSERT_EQ(store->PutBatch(reenabledEntries), SUCCESS);
    SleepMillis(SETTLE_INTERVAL_MS);
    DiskUsage reenabledPeak;
    bool reenabledMeasured = QueryStoreDiskUsage(storeId, reenabledPeak);
    ASSERT_EQ(store->DeleteBatch(MakeKeys(reenabledEntries)), SUCCESS);
    DiskUsage reenabledFinal;
    bool reenabledReclaimed = false;
    if (reenabledMeasured) {
        auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(WAIT_RECLAIM_TIMEOUT_MS);
        while (std::chrono::steady_clock::now() < deadline) {
            if (QueryStoreDiskUsage(storeId, reenabledFinal) &&
                HasReclaimDrop(reenabledPeak.blockBytes, reenabledFinal.blockBytes)) {
                reenabledReclaimed = true;
                break;
            }
            SleepMillis(POLL_INTERVAL_MS);
        }
        if (!reenabledReclaimed) {
            (void)QueryStoreDiskUsage(storeId, reenabledFinal);
        }
    }
    RecordProperty("reenabled_peak_blocks_bytes", static_cast<int64_t>(reenabledPeak.blockBytes));
    RecordProperty("reenabled_final_blocks_bytes", static_cast<int64_t>(reenabledFinal.blockBytes));
    RecordProperty("reenabled_drop_percent", DropPercent(reenabledPeak.blockBytes, reenabledFinal.blockBytes));
    RecordProperty("reenabled_reclaim_observed", std::string(reenabledReclaimed ? "true" : "false"));

    CloseStore(storeId, store);
    if (!enabledMeasured || !disabledMeasuredBefore || !disabledMeasuredAfter || !reenabledMeasured) {
        GTEST_SKIP() << "evidence gap: the RD database directory of the store is not measurable on this image";
    }

    EXPECT_FALSE(disabledDropped) << "physical usage dropped although the switch was disabled (peak="
        << disabledPeak.blockBytes << ", final=" << disabledFinal.blockBytes << ")";
    EXPECT_TRUE(enabledReclaimed)
        << "no shrink driven drop observed while enabled (peak=" << enabledPeak.blockBytes
        << ", final=" << enabledFinal.blockBytes << ")";
    EXPECT_TRUE(reenabledReclaimed)
        << "no shrink driven drop observed after re-enabling (peak=" << reenabledPeak.blockBytes
        << ", final=" << reenabledFinal.blockBytes << ")";
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
        ASSERT_EQ(plain->PutBatch(allEntries), SUCCESS);
        int64_t plainWriteUs = ElapsedMicros(plainWriteStart);
        auto enabledWriteStart = std::chrono::steady_clock::now();
        ASSERT_EQ(enabled->PutBatch(allEntries), SUCCESS);
        int64_t enabledWriteUs = ElapsedMicros(enabledWriteStart);
        plainWriteBytesPerSec.push_back(plainWriteUs > 0 ? allBytes * 1000000 / plainWriteUs : 0);
        enabledWriteBytesPerSec.push_back(enabledWriteUs > 0 ? allBytes * 1000000 / enabledWriteUs : 0);
        SleepMillis(SETTLE_INTERVAL_MS);
        DiskUsage written;
        if (QueryStoreDiskUsage(enabledId, written) && written.blockBytes > enabledPeak.blockBytes) {
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
            EXPECT_EQ(plain->DeleteBatch(batchKeys), SUCCESS);
            plainBatchSamples.push_back(ElapsedMicros(plainBatchStart));
            auto enabledBatchStart = std::chrono::steady_clock::now();
            EXPECT_EQ(enabled->DeleteBatch(batchKeys), SUCCESS);
            enabledBatchSamples.push_back(ElapsedMicros(enabledBatchStart));
        }
        plainBatchP95s.push_back(Percentile(plainBatchSamples, 95));
        enabledBatchP95s.push_back(Percentile(enabledBatchSamples, 95));

        SleepMillis(SETTLE_INTERVAL_MS);
        DiskUsage afterRound;
        if (QueryStoreDiskUsage(enabledId, afterRound)) {
            if (!enabledFinal.valid || afterRound.blockBytes < enabledFinal.blockBytes) {
                enabledFinal = afterRound;
            }
        }
    }

    if (enabledPeak.valid) {
        auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(WAIT_RECLAIM_TIMEOUT_MS);
        while (true) {
            DiskUsage current;
            if (QueryStoreDiskUsage(enabledId, current) &&
                (!enabledFinal.valid || current.blockBytes < enabledFinal.blockBytes)) {
                enabledFinal = current;
            }
            int64_t dropped = enabledFinal.valid ?
                static_cast<int64_t>(enabledPeak.blockBytes) - static_cast<int64_t>(enabledFinal.blockBytes) : 0;
            if (dropped > 0 && dropped * 100 / static_cast<int64_t>(enabledPeak.blockBytes) >= 10) {
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
    int64_t reclaimDropPercent = DropPercent(enabledPeak.blockBytes, enabledFinal.blockBytes);

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
    RecordProperty("enabled_reclaim_peak_bytes", static_cast<int64_t>(enabledPeak.blockBytes));
    RecordProperty("enabled_reclaim_final_bytes", static_cast<int64_t>(enabledFinal.blockBytes));
    RecordProperty("enabled_reclaim_drop_percent", reclaimDropPercent);

    EXPECT_EQ(disableStatus, SUCCESS);
    EXPECT_LE(acceptUs, MAX_ACCEPT_MILLIS * 1000);
    EXPECT_LE(disableUs, MAX_ACCEPT_MILLIS * 1000);
    CloseStore(enabledId, enabled);
    CloseStore(plainId, plain);

    if (!enabledPeak.valid || !enabledFinal.valid) {
        GTEST_SKIP() << "evidence gap: the RD database directory of the store is not measurable on this image";
    }
    EXPECT_GE(reclaimDropPercent, 10)
        << "the enabled store did not show engine reclamation during the measured workload (peak="
        << enabledPeak.blockBytes << ", final=" << enabledFinal.blockBytes << ")";
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
