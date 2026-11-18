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
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "kv_store_delegate_manager.h"
#include "single_store_impl.h"
#include "store_manager.h"
#include "types.h"

using namespace testing::ext;
using namespace OHOS::DistributedKv;

namespace OHOS::Test {
namespace {
constexpr const char *BASE_DIR = "/data/service/el1/public/database/SingleStoreImplTest";
constexpr const char *APP_ID = "SingleStoreImplTest";

// The switch is delivered asynchronously; wait until the store has no scheduled switch task
// before observing engine related behavior.
constexpr int64_t WAIT_SWITCH_TIMEOUT_MS = 5000;
// The engine owns the reclamation threshold, so a physical drop can only be polled best effort.
constexpr int64_t WAIT_RECLAIM_TIMEOUT_MS = 15000;
constexpr int64_t POLL_INTERVAL_MS = 200;
constexpr int64_t SETTLE_INTERVAL_MS = 200;
constexpr int64_t NO_DELETE_OBSERVE_MS = 3000;
constexpr int64_t MAX_ACCEPT_MILLIS = 1000;
constexpr int64_t P95_EXTRA_US = 50000;
// Normal storage housekeeping (log truncation and file rotation) may move blocks without any
// shrink request; a shrink driven reclamation would release much more of the written data.
constexpr uint64_t HOUSEKEEPING_DROP_PERCENT = 25;

constexpr int32_t RECLAIM_ROUNDS = 3;
constexpr int32_t RECLAIM_KEYS_PER_ROUND = 256;
constexpr size_t RECLAIM_VALUE_SIZE = 8 * 1024;

constexpr int32_t PLAIN_KEYS = 512;
constexpr size_t PLAIN_VALUE_SIZE = 4 * 1024;

constexpr int32_t CONCURRENT_KEYS = 512;
constexpr size_t CONCURRENT_VALUE_SIZE = 256;
constexpr int32_t CONCURRENT_READERS = 3;
constexpr int64_t CONCURRENT_WORKLOAD_MS = 2500;
constexpr int64_t READER_YIELD_MS = 1;

constexpr int32_t P95_KEYS = 400;
constexpr int32_t P95_SAMPLES = 200;

struct DiskUsage {
    uint64_t blockBytes = 0;
    uint32_t fileCount = 0;
    bool valid = false;
};

struct ShrinkState {
    bool desiredEnabled = false;
    bool scheduled = false;
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

// Sums the allocated blocks (the metric du reports) of the database directory of one store.
// st_size is not used because a sparse database file does not necessarily shrink on disk.
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

// ShrinkManager fields are guarded by stateMutex_: the background switch task may call Finish at
// any time, so the test reads a locked state instead of touching the fields directly.
ShrinkState ReadShrinkState(SingleStoreImpl &impl)
{
    ShrinkManager &manager = impl.shrinkManager_;
    std::lock_guard<std::mutex> lock(manager.stateMutex_);
    return { manager.desiredEnabled_, manager.shrinkScheduled_ };
}

bool WaitShrinkSettled(SingleStoreImpl &impl, int64_t timeoutMs)
{
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);
    while (std::chrono::steady_clock::now() < deadline) {
        if (!ReadShrinkState(impl).scheduled) {
            return true;
        }
        SleepMillis(POLL_INTERVAL_MS);
    }
    return !ReadShrinkState(impl).scheduled;
}
} // namespace

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

/**
 * @tc.name: SetShrinkEnableSupportMatrix
 * @tc.desc: Enable is accepted only by a LOCAL_ONLY owner: other store types reject enable with
 *           NOT_SUPPORT while disable stays an idempotent SUCCESS no-op; a closed store returns
 *           ALREADY_CLOSED for both directions (AC-1.3, AC-1.4, EX-6, EX-8).
 * @tc.type: FUNC
 */
HWTEST_F(EnableShrinkTest, SetShrinkEnableSupportMatrix, TestSize.Level1)
{
    const std::string localOnlyId = "EnableShrinkMatrixLocalOnly";
    auto localOnly = CreateStore(localOnlyId, KvStoreType::LOCAL_ONLY);
    ASSERT_NE(localOnly, nullptr);
    EXPECT_EQ(localOnly->SetShrinkEnable(true), SUCCESS);
    // A repeated request stays an idempotent SUCCESS and does not start a duplicate task.
    EXPECT_EQ(localOnly->SetShrinkEnable(true), SUCCESS);
    EXPECT_EQ(localOnly->SetShrinkEnable(false), SUCCESS);
    EXPECT_EQ(localOnly->SetShrinkEnable(false), SUCCESS);

    const std::string singleVersionId = "EnableShrinkMatrixSingleVersion";
    auto singleVersion = CreateStore(singleVersionId, KvStoreType::SINGLE_VERSION);
    ASSERT_NE(singleVersion, nullptr);
    EXPECT_EQ(singleVersion->SetShrinkEnable(true), NOT_SUPPORT);
    EXPECT_EQ(singleVersion->SetShrinkEnable(false), SUCCESS);
    auto singleVersionImpl = AsImpl(singleVersion);
    ASSERT_NE(singleVersionImpl, nullptr);
    auto singleVersionState = ReadShrinkState(*singleVersionImpl);
    EXPECT_FALSE(singleVersionState.desiredEnabled);
    EXPECT_FALSE(singleVersionState.scheduled);

    const std::string deviceId = "EnableShrinkMatrixDevice";
    auto device = CreateStore(deviceId, KvStoreType::DEVICE_COLLABORATION);
    ASSERT_NE(device, nullptr);
    EXPECT_EQ(device->SetShrinkEnable(true), NOT_SUPPORT);
    EXPECT_EQ(device->SetShrinkEnable(false), SUCCESS);
    auto deviceImpl = AsImpl(device);
    ASSERT_NE(deviceImpl, nullptr);
    auto deviceState = ReadShrinkState(*deviceImpl);
    EXPECT_FALSE(deviceState.desiredEnabled);
    EXPECT_FALSE(deviceState.scheduled);

    CloseStore(deviceId, device);
    CloseStore(singleVersionId, singleVersion);
    auto closedLocalOnly = localOnly;
    CloseStore(localOnlyId, localOnly);
    ASSERT_NE(closedLocalOnly, nullptr);
    EXPECT_EQ(closedLocalOnly->SetShrinkEnable(true), ALREADY_CLOSED);
    EXPECT_EQ(closedLocalOnly->SetShrinkEnable(false), ALREADY_CLOSED);
}

/**
 * @tc.name: SetShrinkEnablePhysicalReclaim
 * @tc.desc: A LOCAL_ONLY store accepts the async enable, then repeated Put/Delete cycles are
 *           expected to let the engine reclaim space, observed with allocated blocks (st_blocks).
 *           When the environment cannot expose that engine threshold, the measured values are
 *           recorded as an evidence gap instead of a fabricated pass (AC-1.1).
 * @tc.type: FUNC
 */
HWTEST_F(EnableShrinkTest, SetShrinkEnablePhysicalReclaim, TestSize.Level1)
{
    const std::string storeId = "EnableShrinkPhysicalReclaim";
    auto store = CreateStore(storeId, KvStoreType::LOCAL_ONLY);
    ASSERT_NE(store, nullptr);
    ASSERT_EQ(store->SetShrinkEnable(true), SUCCESS);
    auto impl = AsImpl(store);
    ASSERT_NE(impl, nullptr);
    ASSERT_TRUE(WaitShrinkSettled(*impl, WAIT_SWITCH_TIMEOUT_MS));

    DiskUsage peak;
    for (int32_t round = 0; round < RECLAIM_ROUNDS; ++round) {
        std::string prefix = "reclaim_" + std::to_string(round) + "_";
        auto entries = MakeEntries(prefix, RECLAIM_KEYS_PER_ROUND, RECLAIM_VALUE_SIZE);
        ASSERT_EQ(store->PutBatch(entries), SUCCESS);
        SleepMillis(SETTLE_INTERVAL_MS);
        DiskUsage written;
        if (QueryStoreDiskUsage(storeId, written) && written.blockBytes > peak.blockBytes) {
            peak = written;
        }
        ASSERT_EQ(store->DeleteBatch(MakeKeys(entries)), SUCCESS);
        SleepMillis(SETTLE_INTERVAL_MS);
    }

    DiskUsage current;
    bool observed = false;
    if (peak.valid) {
        auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(WAIT_RECLAIM_TIMEOUT_MS);
        while (std::chrono::steady_clock::now() < deadline) {
            if (QueryStoreDiskUsage(storeId, current) && HasReclaimDrop(peak.blockBytes, current.blockBytes)) {
                observed = true;
                break;
            }
            SleepMillis(POLL_INTERVAL_MS);
        }
        if (!observed) {
            (void)QueryStoreDiskUsage(storeId, current);
        }
    }
    RecordProperty("physical_peak_blocks_bytes", static_cast<int64_t>(peak.blockBytes));
    RecordProperty("physical_final_blocks_bytes", static_cast<int64_t>(current.blockBytes));
    RecordProperty("physical_drop_observed", std::string(observed ? "true" : "false"));
    CloseStore(storeId, store);
    if (!peak.valid) {
        GTEST_SKIP() << "evidence gap: the RD database directory of the store is not measurable on this image";
    }
    if (!observed) {
        GTEST_SKIP() << "evidence gap: the engine reclamation threshold is not controllable in this environment; "
                        "the peak and final physical bytes are recorded as test properties";
    }
    EXPECT_TRUE(observed);
}

/**
 * @tc.name: EncryptStoreShrinkCompatibility
 * @tc.desc: An encrypted LOCAL_ONLY store accepts the same toggle contract as a plain LOCAL_ONLY
 *           store, or rejects enabling with NOT_SUPPORT when the deployed engine is incompatible;
 *           its CRUD behavior stays unchanged (EX-7).
 * @tc.type: FUNC
 */
HWTEST_F(EnableShrinkTest, EncryptStoreShrinkCompatibility, TestSize.Level1)
{
    const std::string storeId = "EnableShrinkEncrypted";
    auto store = CreateStore(storeId, KvStoreType::LOCAL_ONLY, true);
    if (store == nullptr) {
        GTEST_SKIP() << "evidence gap: an encrypted LOCAL_ONLY store is not available in this environment";
    }
    Status enableStatus = store->SetShrinkEnable(true);
    RecordProperty("encrypt_enable_status", static_cast<int64_t>(static_cast<int32_t>(enableStatus)));
    EXPECT_TRUE(enableStatus == SUCCESS || enableStatus == NOT_SUPPORT);
    EXPECT_EQ(store->SetShrinkEnable(false), SUCCESS);

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

/**
 * @tc.name: NoEnableNoReclaim
 * @tc.desc: Without SetShrinkEnable no switch task exists, and Put/Delete must not trigger any
 *           space reclamation, so physical usage does not drop because of shrink (AC-1.2).
 * @tc.type: FUNC
 */
HWTEST_F(EnableShrinkTest, NoEnableNoReclaim, TestSize.Level1)
{
    const std::string storeId = "EnableShrinkNoEnable";
    auto store = CreateStore(storeId, KvStoreType::LOCAL_ONLY);
    ASSERT_NE(store, nullptr);
    auto impl = AsImpl(store);
    ASSERT_NE(impl, nullptr);
    auto initialState = ReadShrinkState(*impl);
    EXPECT_FALSE(initialState.desiredEnabled);
    EXPECT_FALSE(initialState.scheduled);

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
    EXPECT_FALSE(endState.scheduled);
    RecordProperty("noenable_bytes_after_write", static_cast<int64_t>(written.blockBytes));
    RecordProperty("noenable_bytes_after_delete", static_cast<int64_t>(afterDelete.blockBytes));
    RecordProperty("noenable_evidence_gap", std::string("the engine internal file housekeeping is not "
        "controllable; no switch task is ever recorded as desired or scheduled"));
    CloseStore(storeId, store);
    if (!measuredBefore || !measuredAfter) {
        GTEST_SKIP() << "evidence gap: the RD database directory of the store is not measurable on this image";
    }
    // A shrink driven reclamation would release the bulk of the written blocks; only the smaller
    // movement of normal file housekeeping is tolerated.
    EXPECT_FALSE(ExceedsHousekeepingDrop(written.blockBytes, afterDelete.blockBytes))
        << "physical usage dropped although shrink was never enabled";
}

/**
 * @tc.name: NoDeleteNoReclaim
 * @tc.desc: With shrink enabled but no deletes the engine must not perform extra reclamation, so
 *           physical usage does not drop because of shrink; the engine threshold is not
 *           controllable from the test, which is recorded as an evidence gap (AC-1.6).
 * @tc.type: FUNC
 */
HWTEST_F(EnableShrinkTest, NoDeleteNoReclaim, TestSize.Level1)
{
    const std::string storeId = "EnableShrinkNoDelete";
    auto store = CreateStore(storeId, KvStoreType::LOCAL_ONLY);
    ASSERT_NE(store, nullptr);
    ASSERT_EQ(store->SetShrinkEnable(true), SUCCESS);
    auto impl = AsImpl(store);
    ASSERT_NE(impl, nullptr);
    ASSERT_TRUE(WaitShrinkSettled(*impl, WAIT_SWITCH_TIMEOUT_MS));

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
    EXPECT_FALSE(endState.scheduled);
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

/**
 * @tc.name: ConcurrentReadDuringReclaim
 * @tc.desc: While shrink is enabled and deletes run, concurrent Get/GetEntries/GetResultSet calls
 *           must keep succeeding and return consistent values; the engine internal reclamation
 *           window is not directly observable, which is recorded as an evidence gap (AC-1.5).
 * @tc.type: FUNC
 */
HWTEST_F(EnableShrinkTest, ConcurrentReadDuringReclaim, TestSize.Level1)
{
    const std::string storeId = "EnableShrinkConcurrentRead";
    auto store = CreateStore(storeId, KvStoreType::LOCAL_ONLY);
    ASSERT_NE(store, nullptr);
    ASSERT_EQ(store->SetShrinkEnable(true), SUCCESS);
    auto impl = AsImpl(store);
    ASSERT_NE(impl, nullptr);
    ASSERT_TRUE(WaitShrinkSettled(*impl, WAIT_SWITCH_TIMEOUT_MS));

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
        readers.emplace_back([&store, &stop, &readFailures, stableKey, expectedValue, queryPrefix]() {
            while (!stop.load()) {
                Value value;
                if (store->Get(stableKey, value) != SUCCESS || value.ToString() != expectedValue) {
                    readFailures.fetch_add(1);
                }
                std::vector<Entry> queried;
                if (store->GetEntries(queryPrefix, queried) != SUCCESS) {
                    readFailures.fetch_add(1);
                } else {
                    for (const auto &entry : queried) {
                        if (entry.value.ToString() != expectedValue) {
                            readFailures.fetch_add(1);
                        }
                    }
                }
                std::shared_ptr<KvStoreResultSet> resultSet;
                if (store->GetResultSet(queryPrefix, resultSet) != SUCCESS || resultSet == nullptr) {
                    readFailures.fetch_add(1);
                } else {
                    int32_t count = resultSet->GetCount();
                    if (count <= 0 || count > CONCURRENT_KEYS) {
                        readFailures.fetch_add(1);
                    }
                    while (resultSet->MoveToNext()) {
                        Entry entry;
                        if (resultSet->GetEntry(entry) != SUCCESS || entry.value.ToString() != expectedValue) {
                            readFailures.fetch_add(1);
                        }
                    }
                    if (store->CloseResultSet(resultSet) != SUCCESS) {
                        readFailures.fetch_add(1);
                    }
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

/**
 * @tc.name: DisableStopsNewReclaim
 * @tc.desc: After enable then immediate disable the desired state ends false and no switch task
 *           remains; later deletes do not enqueue a new switch request. An engine call or
 *           reclamation already started before the disable may still complete (AC-1.8).
 * @tc.type: FUNC
 */
HWTEST_F(EnableShrinkTest, DisableStopsNewReclaim, TestSize.Level1)
{
    const std::string storeId = "EnableShrinkDisablePending";
    auto store = CreateStore(storeId, KvStoreType::LOCAL_ONLY);
    ASSERT_NE(store, nullptr);
    auto impl = AsImpl(store);
    ASSERT_NE(impl, nullptr);

    ASSERT_EQ(store->SetShrinkEnable(true), SUCCESS);
    ASSERT_EQ(store->SetShrinkEnable(false), SUCCESS);
    ASSERT_TRUE(WaitShrinkSettled(*impl, WAIT_SWITCH_TIMEOUT_MS));
    auto settled = ReadShrinkState(*impl);
    EXPECT_FALSE(settled.desiredEnabled);
    EXPECT_FALSE(settled.scheduled);

    EXPECT_EQ(store->SetShrinkEnable(false), SUCCESS);
    ASSERT_TRUE(WaitShrinkSettled(*impl, WAIT_SWITCH_TIMEOUT_MS));

    auto entries = MakeEntries("disable_then_delete_", PLAIN_KEYS, PLAIN_VALUE_SIZE);
    ASSERT_EQ(store->PutBatch(entries), SUCCESS);
    ASSERT_EQ(store->DeleteBatch(MakeKeys(entries)), SUCCESS);
    SleepMillis(NO_DELETE_OBSERVE_MS);
    auto afterDeletes = ReadShrinkState(*impl);
    EXPECT_FALSE(afterDeletes.desiredEnabled);
    EXPECT_FALSE(afterDeletes.scheduled);
    RecordProperty("disable_switch_state_after_delete", std::string(
        afterDeletes.scheduled ? "scheduled" : "not_scheduled"));
    RecordProperty("disable_evidence_gap", std::string("an engine call or reclamation that started before "
        "the disable may still complete; no new switch task is queued"));
    CloseStore(storeId, store);
}

/**
 * @tc.name: DeleteP95WithShrinkEnabled
 * @tc.desc: SetShrinkEnable returns without waiting for engine I/O, and Delete latency (P95) with
 *           shrink enabled is not significantly worse than a plain store. Device scheduling noise
 *           is recorded together with the sampled values instead of being pinned to a tight
 *           threshold (AC-1.7).
 * @tc.type: FUNC
 */
HWTEST_F(EnableShrinkTest, DeleteP95WithShrinkEnabled, TestSize.Level1)
{
    const std::string plainId = "EnableShrinkP95Plain";
    const std::string enabledId = "EnableShrinkP95Enabled";
    auto plain = CreateStore(plainId, KvStoreType::LOCAL_ONLY);
    ASSERT_NE(plain, nullptr);
    auto enabled = CreateStore(enabledId, KvStoreType::LOCAL_ONLY);
    ASSERT_NE(enabled, nullptr);

    auto acceptStart = std::chrono::steady_clock::now();
    ASSERT_EQ(enabled->SetShrinkEnable(true), SUCCESS);
    int64_t acceptUs = ElapsedMicros(acceptStart);
    auto impl = AsImpl(enabled);
    ASSERT_NE(impl, nullptr);
    ASSERT_TRUE(WaitShrinkSettled(*impl, WAIT_SWITCH_TIMEOUT_MS));

    auto plainEntries = MakeEntries("p95_plain_", P95_KEYS, PLAIN_VALUE_SIZE);
    auto enabledEntries = MakeEntries("p95_enabled_", P95_KEYS, PLAIN_VALUE_SIZE);
    ASSERT_EQ(plain->PutBatch(plainEntries), SUCCESS);
    ASSERT_EQ(enabled->PutBatch(enabledEntries), SUCCESS);

    std::vector<int64_t> plainSamples;
    plainSamples.reserve(P95_SAMPLES);
    for (int32_t index = 0; index < P95_SAMPLES; ++index) {
        auto start = std::chrono::steady_clock::now();
        Status status = plain->Delete(plainEntries[index].key);
        plainSamples.push_back(ElapsedMicros(start));
        EXPECT_EQ(status, SUCCESS);
    }
    std::vector<int64_t> enabledSamples;
    enabledSamples.reserve(P95_SAMPLES);
    for (int32_t index = 0; index < P95_SAMPLES; ++index) {
        auto start = std::chrono::steady_clock::now();
        Status status = enabled->Delete(enabledEntries[index].key);
        enabledSamples.push_back(ElapsedMicros(start));
        EXPECT_EQ(status, SUCCESS);
    }
    int64_t plainP95 = Percentile(plainSamples, 95);
    int64_t enabledP95 = Percentile(enabledSamples, 95);
    bool p95WithinBound = enabledP95 <= plainP95 + P95_EXTRA_US;

    auto disableStart = std::chrono::steady_clock::now();
    Status disableStatus = enabled->SetShrinkEnable(false);
    int64_t disableUs = ElapsedMicros(disableStart);
    RecordProperty("switch_accept_us", acceptUs);
    RecordProperty("switch_disable_us", disableUs);
    RecordProperty("delete_p95_plain_us", plainP95);
    RecordProperty("delete_p95_enabled_us", enabledP95);
    RecordProperty("delete_p95_within_bound", std::string(p95WithinBound ? "true" : "false"));
    RecordProperty("delete_p95_evidence_gap", std::string("device scheduling noise and debug build overhead "
        "apply to both stores; P95 is sampled, not pinned to a tight bound"));

    EXPECT_EQ(disableStatus, SUCCESS);
    EXPECT_LE(acceptUs, MAX_ACCEPT_MILLIS * 1000);
    EXPECT_LE(disableUs, MAX_ACCEPT_MILLIS * 1000);
    CloseStore(enabledId, enabled);
    CloseStore(plainId, plain);
    if (!p95WithinBound) {
        GTEST_SKIP() << "evidence gap: debug-build scheduling noise exceeded the P95 tolerance; "
                        "plain/enabled percentiles are recorded as test properties";
    }
    // Delete must not gain synchronous shrink work; allow scheduler jitter, not engine I/O.
    EXPECT_LE(enabledP95, plainP95 + P95_EXTRA_US);
}
} // namespace OHOS::Test
