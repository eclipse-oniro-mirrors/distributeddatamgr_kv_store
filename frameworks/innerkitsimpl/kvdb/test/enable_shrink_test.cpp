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

constexpr int32_t PERCENTILE_95 = 95;
constexpr int64_t PERCENT_SCALE = 100;
constexpr uint64_t RECLAIM_DROP_DIVISOR = 10;
constexpr size_t EVEN_SAMPLE_DIVISOR = 2;
constexpr int64_t MICROS_PER_MILLI = 1000;
constexpr int64_t MILLIS_PER_SECOND = 1000;
constexpr int64_t MICROS_PER_SECOND = MICROS_PER_MILLI * MILLIS_PER_SECOND;
constexpr size_t STABLE_ENTRY_INDEX = 1;

constexpr const char *CONCURRENT_PREFIX = "concurrent_";

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
    size_t index = static_cast<size_t>(percent) * (samples.size() - 1) /
        static_cast<size_t>(PERCENT_SCALE);
    return samples[index];
}

int64_t Median(std::vector<int64_t> samples)
{
    if (samples.empty()) {
        return 0;
    }
    std::sort(samples.begin(), samples.end());
    size_t middle = samples.size() / EVEN_SAMPLE_DIVISOR;
    if (samples.size() % EVEN_SAMPLE_DIVISOR == 0) {
        return (samples[middle - 1] + samples[middle]) /
            static_cast<int64_t>(EVEN_SAMPLE_DIVISOR);
    }
    return samples[middle];
}

bool EndsWithDbSuffix(const std::string &name)
{
    constexpr const char *dbSuffix = ".db";
    size_t suffixSize = std::string(dbSuffix).size();
    return name.size() >= suffixSize && name.compare(name.size() - suffixSize, suffixSize, dbSuffix) == 0;
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
    return currentBytes + peakBytes / RECLAIM_DROP_DIVISOR <= peakBytes;
}

int64_t DropPercent(uint64_t peakBytes, uint64_t currentBytes)
{
    if (peakBytes == 0 || currentBytes >= peakBytes) {
        return 0;
    }
    return static_cast<int64_t>((peakBytes - currentBytes) * static_cast<uint64_t>(PERCENT_SCALE) / peakBytes);
}

bool ExceedsHousekeepingDrop(uint64_t beforeBytes, uint64_t afterBytes)
{
    if (beforeBytes == 0) {
        return false;
    }
    return afterBytes + beforeBytes * HOUSEKEEPING_DROP_PERCENT / static_cast<uint64_t>(PERCENT_SCALE) <
        beforeBytes;
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

std::string BoolText(bool value)
{
    return std::string(value ? "true" : "false");
}

struct ReclaimProbe {
    DiskUsage finalUsage;
    int64_t dropPercent = 0;
    bool reclaimObserved = false;
};

DiskUsage ScanPeakUsage(const std::string &storeId, int32_t scans)
{
    DiskUsage peak;
    for (int32_t scan = 0; scan < scans; ++scan) {
        DiskUsage current;
        if (QueryStoreDiskUsage(storeId, current) && current.dbBlockBytes > peak.dbBlockBytes) {
            peak = current;
        }
        SleepMillis(SETTLE_INTERVAL_MS);
    }
    return peak;
}

ReclaimProbe WaitReclaimDrop(const std::string &storeId, uint64_t peakBytes, int64_t timeoutMs,
    int64_t minimumDropPercent)
{
    ReclaimProbe probe;
    if (peakBytes == 0) {
        return probe;
    }
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);
    while (std::chrono::steady_clock::now() < deadline) {
        DiskUsage current;
        if (QueryStoreDiskUsage(storeId, current)) {
            int64_t currentDrop = DropPercent(peakBytes, current.dbBlockBytes);
            if (currentDrop > probe.dropPercent) {
                probe.dropPercent = currentDrop;
                probe.finalUsage = current;
            }
            if (HasReclaimDrop(peakBytes, current.dbBlockBytes)) {
                probe.reclaimObserved = true;
            }
            if (probe.dropPercent >= minimumDropPercent) {
                break;
            }
        }
        SleepMillis(POLL_INTERVAL_MS);
    }
    if (!probe.finalUsage.valid) {
        (void)QueryStoreDiskUsage(storeId, probe.finalUsage);
        probe.dropPercent = DropPercent(peakBytes, probe.finalUsage.dbBlockBytes);
    }
    return probe;
}

struct BatchShape {
    int32_t batches;
    int32_t keysPerBatch;
    size_t valueSize;
};

bool WriteBatches(const std::shared_ptr<SingleKvStore> &store, const std::string &prefix,
    const BatchShape &shape, std::vector<Key> &keys)
{
    keys.clear();
    keys.reserve(static_cast<size_t>(shape.batches) * static_cast<size_t>(shape.keysPerBatch));
    for (int32_t batch = 0; batch < shape.batches; ++batch) {
        auto entries = MakeEntries(prefix + std::to_string(batch) + "_", shape.keysPerBatch,
            shape.valueSize);
        for (const auto &entry : entries) {
            keys.push_back(entry.key);
        }
        if (!PutBatchChunked(store, entries)) {
            return false;
        }
    }
    return true;
}

uint64_t ObserveMinimumDbBytes(const std::string &storeId, uint64_t baselineBytes, int64_t observeMs)
{
    uint64_t minimumBytes = baselineBytes;
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(observeMs);
    while (std::chrono::steady_clock::now() < deadline) {
        SleepMillis(POLL_INTERVAL_MS);
        DiskUsage sample;
        if (QueryStoreDiskUsage(storeId, sample) && sample.dbBlockBytes < minimumBytes) {
            minimumBytes = sample.dbBlockBytes;
        }
    }
    return minimumBytes;
}

std::vector<Key> MakeKeysRange(const std::vector<Entry> &entries, int32_t count)
{
    std::vector<Key> keys;
    size_t limit = std::min(static_cast<size_t>(count), entries.size());
    keys.reserve(limit);
    for (size_t index = 0; index < limit; ++index) {
        keys.push_back(entries[index].key);
    }
    return keys;
}

struct DeleteProbe {
    DiskUsage written;
    DiskUsage afterDelete;
    bool putOk = true;
    bool deleteOk = true;
    bool measuredBefore = false;
    bool measuredAfter = false;
    bool checkpointOk = false;
};

DeleteProbe MeasurePlainDelete(const std::shared_ptr<SingleKvStore> &store, const std::string &storeId,
    const std::shared_ptr<SingleStoreImpl> &impl, const std::string &prefix, int64_t observeMs)
{
    DeleteProbe probe;
    auto entries = MakeEntries(prefix, PLAIN_KEYS, PLAIN_VALUE_SIZE);
    probe.putOk = PutBatchChunked(store, entries);
    if (!probe.putOk) {
        return probe;
    }
    bool checkpointBeforeDelete = CheckpointStore(impl);
    SleepMillis(SETTLE_INTERVAL_MS);
    probe.measuredBefore = QueryStoreDiskUsage(storeId, probe.written);
    probe.deleteOk = DeleteBatchChunked(store, MakeKeys(entries));
    SleepMillis(observeMs);
    bool checkpointAfterDelete = CheckpointStore(impl);
    SleepMillis(SETTLE_INTERVAL_MS);
    probe.measuredAfter = QueryStoreDiskUsage(storeId, probe.afterDelete);
    probe.checkpointOk = checkpointBeforeDelete && checkpointAfterDelete;
    return probe;
}

void RecordDeleteProbeProperties(const std::string &prefix, const DeleteProbe &probe,
    const std::string &units)
{
    testing::Test::RecordProperty(prefix + units + "_after_write",
        static_cast<int64_t>(probe.written.dbBlockBytes));
    testing::Test::RecordProperty(prefix + units + "_after_delete",
        static_cast<int64_t>(probe.afterDelete.dbBlockBytes));
    testing::Test::RecordProperty(prefix + "other_bytes_after_write",
        static_cast<int64_t>(probe.written.otherBlockBytes));
    testing::Test::RecordProperty(prefix + "other_bytes_after_delete",
        static_cast<int64_t>(probe.afterDelete.otherBlockBytes));
    testing::Test::RecordProperty(prefix + "checkpoint_ok", BoolText(probe.checkpointOk));
}

void RecordPhysicalReclaimProperties(const DiskUsage &peak, const ReclaimProbe &probe,
    bool checkpointBeforeDelete, bool checkpointAfterDelete)
{
    testing::Test::RecordProperty("physical_peak_blocks_bytes", static_cast<int64_t>(peak.dbBlockBytes));
    testing::Test::RecordProperty("physical_final_blocks_bytes",
        static_cast<int64_t>(probe.finalUsage.dbBlockBytes));
    testing::Test::RecordProperty("physical_peak_db_bytes", static_cast<int64_t>(peak.dbBlockBytes));
    testing::Test::RecordProperty("physical_final_db_bytes",
        static_cast<int64_t>(probe.finalUsage.dbBlockBytes));
    testing::Test::RecordProperty("physical_peak_other_bytes", static_cast<int64_t>(peak.otherBlockBytes));
    testing::Test::RecordProperty("physical_final_other_bytes",
        static_cast<int64_t>(probe.finalUsage.otherBlockBytes));
    testing::Test::RecordProperty("physical_peak_all_bytes", static_cast<int64_t>(peak.blockBytes));
    testing::Test::RecordProperty("physical_final_all_bytes", static_cast<int64_t>(probe.finalUsage.blockBytes));
    testing::Test::RecordProperty("physical_drop_percent", probe.dropPercent);
    testing::Test::RecordProperty("physical_reclaim_observed", BoolText(probe.reclaimObserved));
    testing::Test::RecordProperty("physical_checkpoint_before_delete", BoolText(checkpointBeforeDelete));
    testing::Test::RecordProperty("physical_checkpoint_after_delete", BoolText(checkpointAfterDelete));
}

struct TogglePhase {
    DiskUsage peak;
    DiskUsage finalUsage;
    bool putOk = true;
    bool deleteOk = true;
    bool peakMeasured = false;
    bool finalMeasured = false;
    bool checkpointOk = false;
    bool reclaimed = false;
};

TogglePhase MeasureReclaimPhase(const std::shared_ptr<SingleKvStore> &store, const std::string &storeId,
    const std::shared_ptr<SingleStoreImpl> &impl, const std::string &prefix, int64_t timeoutMs)
{
    TogglePhase phase;
    auto entries = MakeEntries(prefix, RECLAIM_KEYS_PER_ROUND, RECLAIM_VALUE_SIZE);
    phase.putOk = PutBatchChunked(store, entries);
    if (!phase.putOk) {
        return phase;
    }
    bool checkpointBefore = CheckpointStore(impl);
    SleepMillis(SETTLE_INTERVAL_MS);
    phase.peakMeasured = QueryStoreDiskUsage(storeId, phase.peak);
    phase.deleteOk = DeleteBatchChunked(store, MakeKeys(entries));
    bool checkpointAfter = CheckpointStore(impl);
    phase.checkpointOk = checkpointBefore && checkpointAfter;
    if (!phase.peakMeasured) {
        return phase;
    }
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);
    while (std::chrono::steady_clock::now() < deadline) {
        if (QueryStoreDiskUsage(storeId, phase.finalUsage) &&
            HasReclaimDrop(phase.peak.dbBlockBytes, phase.finalUsage.dbBlockBytes)) {
            phase.reclaimed = true;
            break;
        }
        SleepMillis(POLL_INTERVAL_MS);
    }
    if (!phase.reclaimed) {
        (void)QueryStoreDiskUsage(storeId, phase.finalUsage);
    }
    phase.finalMeasured = phase.finalUsage.valid;
    return phase;
}

TogglePhase MeasureDisabledPhase(const std::shared_ptr<SingleKvStore> &store, const std::string &storeId,
    const std::shared_ptr<SingleStoreImpl> &impl, const std::string &prefix)
{
    TogglePhase phase;
    auto entries = MakeEntries(prefix, RECLAIM_KEYS_PER_ROUND, RECLAIM_VALUE_SIZE);
    phase.putOk = PutBatchChunked(store, entries);
    if (!phase.putOk) {
        return phase;
    }
    bool checkpointBefore = CheckpointStore(impl);
    SleepMillis(SETTLE_INTERVAL_MS);
    phase.peakMeasured = QueryStoreDiskUsage(storeId, phase.peak);
    phase.deleteOk = DeleteBatchChunked(store, MakeKeys(entries));
    SleepMillis(NO_DELETE_OBSERVE_MS);
    bool checkpointAfter = CheckpointStore(impl);
    SleepMillis(SETTLE_INTERVAL_MS);
    phase.finalMeasured = QueryStoreDiskUsage(storeId, phase.finalUsage);
    phase.checkpointOk = checkpointBefore && checkpointAfter;
    return phase;
}

void RecordToggleCommonProperties(const std::string &prefix, const TogglePhase &phase)
{
    testing::Test::RecordProperty(prefix + "peak_blocks_bytes", static_cast<int64_t>(phase.peak.dbBlockBytes));
    testing::Test::RecordProperty(prefix + "final_blocks_bytes",
        static_cast<int64_t>(phase.finalUsage.dbBlockBytes));
    testing::Test::RecordProperty(prefix + "drop_percent",
        DropPercent(phase.peak.dbBlockBytes, phase.finalUsage.dbBlockBytes));
    testing::Test::RecordProperty(prefix + "peak_other_bytes",
        static_cast<int64_t>(phase.peak.otherBlockBytes));
    testing::Test::RecordProperty(prefix + "final_other_bytes",
        static_cast<int64_t>(phase.finalUsage.otherBlockBytes));
    testing::Test::RecordProperty(prefix + "checkpoint_ok", BoolText(phase.checkpointOk));
}

void RecordToggleReclaimProperties(const std::string &prefix, const TogglePhase &phase)
{
    RecordToggleCommonProperties(prefix, phase);
    testing::Test::RecordProperty(prefix + "reclaim_observed", BoolText(phase.reclaimed));
}

void RecordToggleDisabledProperties(const std::string &prefix, const TogglePhase &phase, bool dropped)
{
    RecordToggleCommonProperties(prefix, phase);
    testing::Test::RecordProperty(prefix + "drop_observed", BoolText(dropped));
}

struct PerfSamples {
    std::vector<int64_t> plainDeleteP95s;
    std::vector<int64_t> enabledDeleteP95s;
    std::vector<int64_t> plainBatchP95s;
    std::vector<int64_t> enabledBatchP95s;
    std::vector<int64_t> plainWriteBytesPerSec;
    std::vector<int64_t> enabledWriteBytesPerSec;
    DiskUsage enabledPeak;
    DiskUsage enabledFinal;
    bool checkpointsOk = true;
    bool putOk = true;
};

int64_t BytesPerSecond(int64_t bytes, int64_t micros)
{
    return micros > 0 ? bytes * MICROS_PER_SECOND / micros : 0;
}

std::vector<Entry> MakePerfRoundEntries(int32_t round, std::vector<Entry> &batchEntries)
{
    std::string prefix = "perf_" + std::to_string(round) + "_";
    auto deleteEntries = MakeEntries(prefix + "delete_", PERF_DELETE_SAMPLES, PERF_VALUE_SIZE);
    batchEntries.clear();
    batchEntries.reserve(static_cast<size_t>(PERF_BATCH_SAMPLES) * static_cast<size_t>(PERF_BATCH_SIZE));
    for (int32_t batch = 0; batch < PERF_BATCH_SAMPLES; ++batch) {
        auto entries = MakeEntries(prefix + "batch_" + std::to_string(batch) + "_",
            PERF_BATCH_SIZE, PERF_VALUE_SIZE);
        batchEntries.insert(batchEntries.end(), entries.begin(), entries.end());
    }
    return deleteEntries;
}

struct PerfContext {
    std::shared_ptr<SingleKvStore> plain;
    std::shared_ptr<SingleKvStore> enabled;
    std::shared_ptr<SingleStoreImpl> impl;
    std::string enabledId;
};

bool RunPerfWritePhase(const PerfContext &context, const std::vector<Entry> &allEntries,
    PerfSamples &perf)
{
    int64_t allBytes = static_cast<int64_t>(allEntries.size()) * static_cast<int64_t>(PERF_VALUE_SIZE);
    auto plainStart = std::chrono::steady_clock::now();
    bool plainOk = PutBatchChunked(context.plain, allEntries);
    int64_t plainUs = ElapsedMicros(plainStart);
    auto enabledStart = std::chrono::steady_clock::now();
    bool enabledOk = PutBatchChunked(context.enabled, allEntries);
    int64_t enabledUs = ElapsedMicros(enabledStart);
    perf.putOk = plainOk && enabledOk;
    if (!perf.putOk) {
        return false;
    }
    perf.plainWriteBytesPerSec.push_back(BytesPerSecond(allBytes, plainUs));
    perf.enabledWriteBytesPerSec.push_back(BytesPerSecond(allBytes, enabledUs));
    SleepMillis(SETTLE_INTERVAL_MS);
    perf.checkpointsOk = CheckpointStore(context.impl) && perf.checkpointsOk;
    SleepMillis(SETTLE_INTERVAL_MS);
    DiskUsage written;
    if (QueryStoreDiskUsage(context.enabledId, written) &&
        written.dbBlockBytes > perf.enabledPeak.dbBlockBytes) {
        perf.enabledPeak = written;
    }
    return true;
}

std::vector<int64_t> MeasureDeleteLatency(const std::shared_ptr<SingleKvStore> &store,
    const std::vector<Entry> &deleteEntries)
{
    std::vector<int64_t> samples;
    samples.reserve(PERF_DELETE_SAMPLES);
    for (int32_t index = 0; index < PERF_DELETE_SAMPLES; ++index) {
        auto start = std::chrono::steady_clock::now();
        EXPECT_EQ(store->Delete(deleteEntries[index].key), SUCCESS);
        samples.push_back(ElapsedMicros(start));
    }
    return samples;
}

void RunPerfDeletePhase(const PerfContext &context, const std::vector<Entry> &deleteEntries,
    PerfSamples &perf)
{
    perf.plainDeleteP95s.push_back(Percentile(MeasureDeleteLatency(context.plain, deleteEntries),
        PERCENTILE_95));
    perf.enabledDeleteP95s.push_back(Percentile(MeasureDeleteLatency(context.enabled, deleteEntries),
        PERCENTILE_95));
}

std::vector<Key> MakeBatchKeys(const std::vector<Entry> &batchEntries, int32_t batch)
{
    size_t begin = static_cast<size_t>(batch) * static_cast<size_t>(PERF_BATCH_SIZE);
    std::vector<Key> batchKeys;
    batchKeys.reserve(PERF_BATCH_SIZE);
    for (int32_t index = 0; index < PERF_BATCH_SIZE; ++index) {
        batchKeys.push_back(batchEntries[begin + static_cast<size_t>(index)].key);
    }
    return batchKeys;
}

void RunPerfBatchPhase(const PerfContext &context, const std::vector<Entry> &batchEntries,
    PerfSamples &perf)
{
    std::vector<int64_t> plainSamples;
    std::vector<int64_t> enabledSamples;
    plainSamples.reserve(PERF_BATCH_SAMPLES);
    enabledSamples.reserve(PERF_BATCH_SAMPLES);
    for (int32_t batch = 0; batch < PERF_BATCH_SAMPLES; ++batch) {
        auto batchKeys = MakeBatchKeys(batchEntries, batch);
        auto plainStart = std::chrono::steady_clock::now();
        EXPECT_TRUE(DeleteBatchChunked(context.plain, batchKeys));
        plainSamples.push_back(ElapsedMicros(plainStart));
        auto enabledStart = std::chrono::steady_clock::now();
        EXPECT_TRUE(DeleteBatchChunked(context.enabled, batchKeys));
        enabledSamples.push_back(ElapsedMicros(enabledStart));
    }
    perf.plainBatchP95s.push_back(Percentile(plainSamples, PERCENTILE_95));
    perf.enabledBatchP95s.push_back(Percentile(enabledSamples, PERCENTILE_95));
}

void RunPerfRoundSettle(const PerfContext &context, PerfSamples &perf)
{
    SleepMillis(SETTLE_INTERVAL_MS);
    perf.checkpointsOk = CheckpointStore(context.impl) && perf.checkpointsOk;
    SleepMillis(SETTLE_INTERVAL_MS);
    DiskUsage afterRound;
    if (QueryStoreDiskUsage(context.enabledId, afterRound)) {
        if (!perf.enabledFinal.valid || afterRound.dbBlockBytes < perf.enabledFinal.dbBlockBytes) {
            perf.enabledFinal = afterRound;
        }
    }
}

bool RunPerfRounds(const PerfContext &context, PerfSamples &perf)
{
    for (int32_t round = 0; round < PERF_ROUNDS; ++round) {
        std::vector<Entry> batchEntries;
        std::vector<Entry> deleteEntries = MakePerfRoundEntries(round, batchEntries);
        std::vector<Entry> allEntries = deleteEntries;
        allEntries.insert(allEntries.end(), batchEntries.begin(), batchEntries.end());
        if (!RunPerfWritePhase(context, allEntries, perf)) {
            return false;
        }
        RunPerfDeletePhase(context, deleteEntries, perf);
        RunPerfBatchPhase(context, batchEntries, perf);
        RunPerfRoundSettle(context, perf);
    }
    return true;
}

struct PerfMedians {
    int64_t plainDeleteP95 = 0;
    int64_t enabledDeleteP95 = 0;
    int64_t plainBatchP95 = 0;
    int64_t enabledBatchP95 = 0;
    int64_t plainWrite = 0;
    int64_t enabledWrite = 0;
    int64_t deleteDegradePercent = 0;
    int64_t batchDegradePercent = 0;
    int64_t writeDegradePercent = 0;
    int64_t reclaimDropPercent = 0;
    int64_t deleteAllowed = 0;
    int64_t batchAllowed = 0;
};

int64_t DegradePercent(int64_t plainValue, int64_t enabledValue)
{
    return plainValue > 0 ? (enabledValue - plainValue) * PERCENT_SCALE / plainValue : 0;
}

PerfMedians ComputePerfMedians(const PerfSamples &perf, const DiskUsage &peak, const DiskUsage &finalUsage)
{
    PerfMedians medians;
    medians.plainDeleteP95 = Median(perf.plainDeleteP95s);
    medians.enabledDeleteP95 = Median(perf.enabledDeleteP95s);
    medians.plainBatchP95 = Median(perf.plainBatchP95s);
    medians.enabledBatchP95 = Median(perf.enabledBatchP95s);
    medians.plainWrite = Median(perf.plainWriteBytesPerSec);
    medians.enabledWrite = Median(perf.enabledWriteBytesPerSec);
    medians.deleteDegradePercent = DegradePercent(medians.plainDeleteP95, medians.enabledDeleteP95);
    medians.batchDegradePercent = DegradePercent(medians.plainBatchP95, medians.enabledBatchP95);
    medians.writeDegradePercent = medians.plainWrite > 0 ?
        (medians.plainWrite - medians.enabledWrite) * PERCENT_SCALE / medians.plainWrite : 0;
    medians.reclaimDropPercent = DropPercent(peak.dbBlockBytes, finalUsage.dbBlockBytes);
    medians.deleteAllowed = std::max(medians.plainDeleteP95 * PERF_DEGRADE_LIMIT_PERCENT / PERCENT_SCALE,
        PERF_ABS_JITTER_US);
    medians.batchAllowed = std::max(medians.plainBatchP95 * PERF_DEGRADE_LIMIT_PERCENT / PERCENT_SCALE,
        PERF_ABS_JITTER_US);
    return medians;
}

PerfMedians RunPerfMeasurement(const PerfContext &context, PerfSamples &perf,
    DiskUsage &enabledFinal)
{
    ReclaimProbe probe = WaitReclaimDrop(context.enabledId, perf.enabledPeak.dbBlockBytes,
        WAIT_RECLAIM_TIMEOUT_MS, PERF_RECLAIM_MIN_DROP_PERCENT);
    enabledFinal = probe.finalUsage.valid ? probe.finalUsage : perf.enabledFinal;
    return ComputePerfMedians(perf, perf.enabledPeak, enabledFinal);
}

void ExpectPerfResults(const PerfMedians &medians, const DiskUsage &peak, const DiskUsage &finalUsage)
{
    EXPECT_GE(medians.reclaimDropPercent, PERF_RECLAIM_MIN_DROP_PERCENT) <<
        "the enabled store did not show engine reclamation during the measured workload (peak=" <<
        peak.dbBlockBytes << ", final=" << finalUsage.dbBlockBytes << ")";
    EXPECT_LE(medians.enabledDeleteP95 - medians.plainDeleteP95, medians.deleteAllowed) <<
        "Delete P95 degraded by " << medians.deleteDegradePercent << "% (" << medians.plainDeleteP95 <<
        " -> " << medians.enabledDeleteP95 << " us)";
    EXPECT_LE(medians.enabledBatchP95 - medians.plainBatchP95, medians.batchAllowed) <<
        "DeleteBatch P95 degraded by " << medians.batchDegradePercent << "% (" << medians.plainBatchP95 <<
        " -> " << medians.enabledBatchP95 << " us)";
    EXPECT_GE(medians.enabledWrite, medians.plainWrite * (PERCENT_SCALE - PERF_DEGRADE_LIMIT_PERCENT) /
        PERCENT_SCALE) << "PutBatch throughput degraded by " << medians.writeDegradePercent << "% (" <<
        medians.plainWrite << " -> " << medians.enabledWrite << " bytes/sec)";
}

void RecordPerfTimingProperties(int64_t acceptUs, int64_t disableUs, const PerfSamples &perf)
{
    testing::Test::RecordProperty("switch_accept_us", acceptUs);
    testing::Test::RecordProperty("switch_disable_us", disableUs);
    testing::Test::RecordProperty("perf_rounds", static_cast<int64_t>(PERF_ROUNDS));
    testing::Test::RecordProperty("perf_checkpoint_ok", BoolText(perf.checkpointsOk));
}

void RecordPerfMeasurementProperties(const PerfMedians &medians, const DiskUsage &peak,
    const DiskUsage &finalUsage)
{
    testing::Test::RecordProperty("delete_p95_plain_us", medians.plainDeleteP95);
    testing::Test::RecordProperty("delete_p95_enabled_us", medians.enabledDeleteP95);
    testing::Test::RecordProperty("delete_p95_degrade_percent", medians.deleteDegradePercent);
    testing::Test::RecordProperty("batch_p95_plain_us", medians.plainBatchP95);
    testing::Test::RecordProperty("batch_p95_enabled_us", medians.enabledBatchP95);
    testing::Test::RecordProperty("batch_p95_degrade_percent", medians.batchDegradePercent);
    testing::Test::RecordProperty("write_plain_bytes_per_sec", medians.plainWrite);
    testing::Test::RecordProperty("write_enabled_bytes_per_sec", medians.enabledWrite);
    testing::Test::RecordProperty("write_degrade_percent", medians.writeDegradePercent);
    testing::Test::RecordProperty("enabled_reclaim_peak_bytes", static_cast<int64_t>(peak.dbBlockBytes));
    testing::Test::RecordProperty("enabled_reclaim_final_bytes",
        static_cast<int64_t>(finalUsage.dbBlockBytes));
    testing::Test::RecordProperty("enabled_reclaim_peak_other_bytes",
        static_cast<int64_t>(peak.otherBlockBytes));
    testing::Test::RecordProperty("enabled_reclaim_final_other_bytes",
        static_cast<int64_t>(finalUsage.otherBlockBytes));
    testing::Test::RecordProperty("enabled_reclaim_peak_all_bytes", static_cast<int64_t>(peak.blockBytes));
    testing::Test::RecordProperty("enabled_reclaim_final_all_bytes",
        static_cast<int64_t>(finalUsage.blockBytes));
    testing::Test::RecordProperty("enabled_reclaim_drop_percent", medians.reclaimDropPercent);
}

struct ConcurrentSummary {
    std::vector<int64_t> baselineSamples;
    std::vector<int64_t> reclaimSamples;
    int64_t baselineP95 = 0;
    int64_t reclaimP95 = 0;
    int64_t reclaimMax = 0;
    int64_t allowedP95 = 0;
    int32_t readFailuresTotal = 0;
};

struct ReaderContext {
    std::atomic<bool> reclaimPhase { false };
    std::atomic<bool> stop { false };
    std::vector<std::vector<int64_t>> baselineSamples;
    std::vector<std::vector<int64_t>> reclaimSamples;
    std::vector<int32_t> readFailures;
    std::map<std::string, std::string> expectedValues;
    Key stableKey;
    std::string stableValue;
    Key queryPrefix;
    std::vector<Key> deleteKeys;

    void Init(const std::vector<Entry> &entries)
    {
        baselineSamples.assign(CONCURRENT_READERS, {});
        reclaimSamples.assign(CONCURRENT_READERS, {});
        readFailures.assign(CONCURRENT_READERS, 0);
        for (const auto &entry : entries) {
            expectedValues[entry.key.ToString()] = entry.value.ToString();
        }
        stableKey = entries[STABLE_ENTRY_INDEX].key;
        stableValue = entries[STABLE_ENTRY_INDEX].value.ToString();
        queryPrefix = CONCURRENT_PREFIX;
        deleteKeys.reserve(static_cast<size_t>(CONCURRENT_DELETE_KEYS));
        for (int32_t index = 0; index < CONCURRENT_DELETE_KEYS * CONCURRENT_DELETE_STEP;
             index += CONCURRENT_DELETE_STEP) {
            deleteKeys.push_back(entries[index].key);
        }
    }

    void Record(int32_t reader, std::chrono::steady_clock::time_point start)
    {
        int64_t micros = ElapsedMicros(start);
        if (reclaimPhase.load()) {
            reclaimSamples[reader].push_back(micros);
        } else {
            baselineSamples[reader].push_back(micros);
        }
    }

    void ReportFailure(int32_t reader)
    {
        readFailures[reader]++;
    }
};

bool CheckStableRead(const std::shared_ptr<SingleKvStore> &store, const Key &stableKey,
    const std::string &stableValue)
{
    Value value;
    return store->Get(stableKey, value) == SUCCESS && value.ToString() == stableValue;
}

bool CheckEntriesRead(const std::shared_ptr<SingleStoreImpl> &impl, const Key &prefix,
    const std::map<std::string, std::string> &expectedValues)
{
    std::vector<SingleStoreImpl::DBEntry> entriesByPrefix;
    if (!ReadEntriesByPrefix(impl, prefix, entriesByPrefix)) {
        return false;
    }
    for (const auto &entry : entriesByPrefix) {
        if (!DBEntryMatches(entry, expectedValues)) {
            return false;
        }
    }
    return true;
}

bool CheckResultSetEntries(DistributedDB::KvStoreResultSet &resultSet,
    const std::map<std::string, std::string> &expectedValues)
{
    int32_t count = resultSet.GetCount();
    if (count < 0 || count > CONCURRENT_KEYS) {
        return false;
    }
    while (resultSet.MoveToNext()) {
        SingleStoreImpl::DBEntry entry;
        if (resultSet.GetEntry(entry) != SingleStoreImpl::DBStatus::OK ||
            !DBEntryMatches(entry, expectedValues)) {
            return false;
        }
    }
    return true;
}

bool CheckResultSetRead(const std::shared_ptr<SingleStoreImpl> &impl, const Key &prefix,
    const std::map<std::string, std::string> &expectedValues)
{
    DistributedDB::KvStoreResultSet *resultSet = nullptr;
    bool resultSetOk = ReadResultSetByPrefix(impl, prefix, resultSet);
    if (resultSet != nullptr) {
        resultSetOk = resultSetOk && CheckResultSetEntries(*resultSet, expectedValues);
        (void)impl->dbStore_->CloseResultSet(resultSet);
    }
    return resultSetOk;
}

void RunReaderLoop(const std::shared_ptr<SingleKvStore> &store, const std::shared_ptr<SingleStoreImpl> &impl,
    ReaderContext &context, int32_t reader)
{
    while (!context.stop.load()) {
        auto start = std::chrono::steady_clock::now();
        if (!CheckStableRead(store, context.stableKey, context.stableValue)) {
            context.ReportFailure(reader);
        }
        context.Record(reader, start);

        start = std::chrono::steady_clock::now();
        if (!CheckEntriesRead(impl, context.queryPrefix, context.expectedValues)) {
            context.ReportFailure(reader);
        }
        context.Record(reader, start);

        start = std::chrono::steady_clock::now();
        if (!CheckResultSetRead(impl, context.queryPrefix, context.expectedValues)) {
            context.ReportFailure(reader);
        }
        context.Record(reader, start);
        SleepMillis(READER_YIELD_MS);
    }
}

std::vector<std::thread> StartReaders(const std::shared_ptr<SingleKvStore> &store,
    const std::shared_ptr<SingleStoreImpl> &impl, ReaderContext &context)
{
    std::vector<std::thread> readers;
    readers.reserve(CONCURRENT_READERS);
    for (int32_t reader = 0; reader < CONCURRENT_READERS; ++reader) {
        readers.emplace_back([&store, &impl, &context, reader]() {
            RunReaderLoop(store, impl, context, reader);
        });
    }
    return readers;
}

void JoinReaders(std::vector<std::thread> &readers)
{
    for (auto &reader : readers) {
        reader.join();
    }
}

int32_t DeleteInReclaimWindow(const std::shared_ptr<SingleKvStore> &store,
    const std::vector<Key> &deleteKeys)
{
    int32_t writeFailures = 0;
    size_t offset = 0;
    auto deadline = std::chrono::steady_clock::now() +
        std::chrono::milliseconds(CONCURRENT_RECLAIM_WINDOW_MS);
    while (offset < deleteKeys.size() && std::chrono::steady_clock::now() < deadline) {
        size_t count = std::min(static_cast<size_t>(CONCURRENT_DELETE_CHUNK), deleteKeys.size() - offset);
        std::vector<Key> chunk(deleteKeys.begin() + offset, deleteKeys.begin() + offset + count);
        if (!DeleteBatchChunked(store, chunk)) {
            writeFailures++;
        }
        offset += count;
        SleepMillis(CONCURRENT_DELETE_SLEEP_MS);
    }
    return writeFailures;
}

ConcurrentSummary SummarizeReaderSamples(const ReaderContext &context)
{
    ConcurrentSummary summary;
    for (int32_t reader = 0; reader < CONCURRENT_READERS; ++reader) {
        summary.baselineSamples.insert(summary.baselineSamples.end(),
            context.baselineSamples[reader].begin(), context.baselineSamples[reader].end());
        summary.reclaimSamples.insert(summary.reclaimSamples.end(),
            context.reclaimSamples[reader].begin(), context.reclaimSamples[reader].end());
        summary.readFailuresTotal += context.readFailures[reader];
    }
    summary.baselineP95 = Percentile(summary.baselineSamples, PERCENTILE_95);
    summary.reclaimP95 = Percentile(summary.reclaimSamples, PERCENTILE_95);
    summary.reclaimMax = summary.reclaimSamples.empty() ? 0 :
        *std::max_element(summary.reclaimSamples.begin(), summary.reclaimSamples.end());
    summary.allowedP95 = std::max(summary.baselineP95 * CONCURRENT_P95_MULTIPLIER,
        CONCURRENT_P95_FLOOR_MICROS);
    return summary;
}

void VerifySurvivingEntries(const std::shared_ptr<SingleKvStore> &store,
    const std::shared_ptr<SingleStoreImpl> &impl, const ReaderContext &context)
{
    Value stableCheck;
    EXPECT_EQ(store->Get(context.stableKey, stableCheck), SUCCESS);
    EXPECT_EQ(stableCheck.ToString(), context.stableValue);
    EXPECT_EQ(store->Get(context.deleteKeys[0], stableCheck), KEY_NOT_FOUND);
    std::vector<SingleStoreImpl::DBEntry> surviving;
    EXPECT_TRUE(ReadEntriesByPrefix(impl, context.queryPrefix, surviving));
    EXPECT_EQ(static_cast<int32_t>(surviving.size()), CONCURRENT_KEYS - CONCURRENT_DELETE_KEYS);
    int32_t survivingMismatches = 0;
    std::map<std::string, int32_t> survivingSeen;
    for (const auto &entry : surviving) {
        if (!DBEntryMatches(entry, context.expectedValues)) {
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
}

void RecordConcurrentProperties(const ConcurrentSummary &summary, const ReclaimProbe &probe,
    int32_t writeFailures, bool checkpointOk)
{
    testing::Test::RecordProperty("concurrent_readers", static_cast<int64_t>(CONCURRENT_READERS));
    testing::Test::RecordProperty("concurrent_stock_bytes",
        static_cast<int64_t>(CONCURRENT_KEYS) * static_cast<int64_t>(CONCURRENT_VALUE_SIZE));
    testing::Test::RecordProperty("concurrent_deleted_bytes",
        static_cast<int64_t>(CONCURRENT_DELETE_KEYS) * static_cast<int64_t>(CONCURRENT_VALUE_SIZE));
    testing::Test::RecordProperty("concurrent_baseline_samples",
        static_cast<int64_t>(summary.baselineSamples.size()));
    testing::Test::RecordProperty("concurrent_reclaim_samples",
        static_cast<int64_t>(summary.reclaimSamples.size()));
    testing::Test::RecordProperty("concurrent_baseline_p95_us", summary.baselineP95);
    testing::Test::RecordProperty("concurrent_reclaim_p95_us", summary.reclaimP95);
    testing::Test::RecordProperty("concurrent_reclaim_max_us", summary.reclaimMax);
    testing::Test::RecordProperty("concurrent_read_failures", static_cast<int64_t>(summary.readFailuresTotal));
    testing::Test::RecordProperty("concurrent_write_failures", static_cast<int64_t>(writeFailures));
    testing::Test::RecordProperty("concurrent_physical_drop_percent", probe.dropPercent);
    testing::Test::RecordProperty("concurrent_physical_drop_observed", BoolText(probe.reclaimObserved));
    testing::Test::RecordProperty("concurrent_reclaim_observed", BoolText(probe.reclaimObserved));
    testing::Test::RecordProperty("concurrent_checkpoint_ok", BoolText(checkpointOk));
    testing::Test::RecordProperty("concurrent_evidence_gap", std::string("the engine internal reclamation "
        "window is not directly observable; dbBlockBytes drop and per-phase read latency are used as the "
        "closest evidence"));
}

int32_t RunConcurrentReaders(const std::shared_ptr<SingleKvStore> &store,
    const std::shared_ptr<SingleStoreImpl> &impl, ReaderContext &context)
{
    auto readers = StartReaders(store, impl, context);
    SleepMillis(CONCURRENT_BASELINE_MS);
    context.reclaimPhase.store(true);
    int32_t writeFailures = DeleteInReclaimWindow(store, context.deleteKeys);
    context.reclaimPhase.store(false);
    context.stop.store(true);
    JoinReaders(readers);
    return writeFailures;
}

void ExpectConcurrentResults(const ConcurrentSummary &summary, const ReclaimProbe &probe,
    const DiskUsage &beforeDelete, int32_t writeFailures)
{
    EXPECT_FALSE(summary.baselineSamples.empty()) << "readers produced no baseline latency samples";
    EXPECT_FALSE(summary.reclaimSamples.empty()) << "readers produced no reclaim phase latency samples";
    EXPECT_EQ(summary.readFailuresTotal, 0) << "readers observed errors while deletes were running";
    EXPECT_EQ(writeFailures, 0) << "deletes failed during the reclaim window";
    EXPECT_TRUE(probe.reclaimObserved) << "no shrink driven dbBlockBytes drop was observed (drop=" <<
        probe.dropPercent << "%, before=" << beforeDelete.dbBlockBytes << ", final=" <<
        probe.finalUsage.dbBlockBytes << ")";
    EXPECT_GE(probe.dropPercent, CONCURRENT_RECLAIM_MIN_DROP_PERCENT) << "physical drop below " <<
        CONCURRENT_RECLAIM_MIN_DROP_PERCENT << "% during the reclaim window";
    EXPECT_LE(summary.reclaimP95, summary.allowedP95) << "reclaim phase read P95 " << summary.reclaimP95 <<
        "us exceeded allowed " << summary.allowedP95 << "us (baseline P95=" << summary.baselineP95 << "us)";
    EXPECT_LT(summary.reclaimMax, CONCURRENT_MAX_READ_MICROS) << "a single read blocked for " <<
        summary.reclaimMax << "us";
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
    BatchShape shape { RECLAIM_WRITE_BATCHES, RECLAIM_KEYS_PER_BATCH, RECLAIM_VALUE_SIZE };
    ASSERT_TRUE(WriteBatches(store, "physical_reclaim_", shape, writtenKeys));
    bool checkpointBeforeDelete = CheckpointStore(impl);
    SleepMillis(SETTLE_INTERVAL_MS);
    DiskUsage peak = ScanPeakUsage(storeId, RECLAIM_PEAK_SCANS);
    ASSERT_TRUE(DeleteBatchChunked(store, writtenKeys));
    bool checkpointAfterDelete = CheckpointStore(impl);
    SleepMillis(SETTLE_INTERVAL_MS);
    ReclaimProbe probe = WaitReclaimDrop(storeId, peak.dbBlockBytes, RECLAIM_SETTLE_TIMEOUT_MS,
        RECLAIM_MIN_DROP_PERCENT);
    RecordPhysicalReclaimProperties(peak, probe, checkpointBeforeDelete, checkpointAfterDelete);
    CloseStore(storeId, store);
    if (!peak.valid || !probe.finalUsage.valid || peak.dbBlockBytes == 0) {
        GTEST_SKIP() << "evidence gap: the RD database directory of the store is not measurable on this image";
    }
    EXPECT_GE(probe.dropPercent, RECLAIM_MIN_DROP_PERCENT) << "physical usage only dropped " <<
        probe.dropPercent << "% (peak=" << peak.dbBlockBytes << ", final=" <<
        probe.finalUsage.dbBlockBytes << ")";
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

    DeleteProbe probe = MeasurePlainDelete(store, storeId, impl, "noenable_", NO_DELETE_OBSERVE_MS);
    ASSERT_TRUE(probe.putOk);
    ASSERT_TRUE(probe.deleteOk);
    auto endState = ReadShrinkState(*impl);
    EXPECT_FALSE(endState.desiredEnabled);
    EXPECT_EQ(endState.pendingTasks, 0u);
    RecordDeleteProbeProperties("noenable_", probe, "bytes");
    RecordProperty("noenable_evidence_gap", std::string("the engine internal file housekeeping is not "
        "controllable; no switch task is ever requested, so the desired state stays false and no task "
        "is pending"));
    CloseStore(storeId, store);
    if (!probe.measuredBefore || !probe.measuredAfter || probe.written.dbBlockBytes == 0) {
        GTEST_SKIP() << "evidence gap: the RD database directory of the store is not measurable on this image";
    }
    EXPECT_FALSE(ExceedsHousekeepingDrop(probe.written.dbBlockBytes, probe.afterDelete.dbBlockBytes)) <<
        "physical usage dropped although shrink was never enabled";
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
    uint64_t minimumBytes = ObserveMinimumDbBytes(storeId, baseline.dbBlockBytes, NO_DELETE_OBSERVE_MS);
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
    EXPECT_FALSE(ExceedsHousekeepingDrop(baseline.dbBlockBytes, minimumBytes)) <<
        "physical usage dropped without deletes";
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
    ASSERT_TRUE(DeleteBatchChunked(store, MakeKeysRange(entries, BELOW_THRESHOLD_DELETE_KEYS)));
    uint64_t minimumBytes = ObserveMinimumDbBytes(storeId, baseline.dbBlockBytes, NO_DELETE_OBSERVE_MS);
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
    EXPECT_FALSE(ExceedsHousekeepingDrop(baseline.dbBlockBytes, minimumBytes)) <<
        "physical usage dropped after a below-threshold delete";
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
    auto entries = MakeEntries(CONCURRENT_PREFIX, CONCURRENT_KEYS, CONCURRENT_VALUE_SIZE, true);
    ASSERT_TRUE(PutBatchChunked(store, entries));
    (void)CheckpointStore(impl);
    SleepMillis(SETTLE_INTERVAL_MS);
    DiskUsage beforeDelete;
    if (!QueryStoreDiskUsage(storeId, beforeDelete) || beforeDelete.dbBlockBytes == 0) {
        CloseStore(storeId, store);
        GTEST_SKIP() << "evidence gap: the RD database directory of the store is not measurable on this image";
    }

    ReaderContext context;
    context.Init(entries);
    int32_t writeFailures = RunConcurrentReaders(store, impl, context);
    ConcurrentSummary summary = SummarizeReaderSamples(context);
    bool checkpointAfterDelete = CheckpointStore(impl);
    SleepMillis(SETTLE_INTERVAL_MS);
    ReclaimProbe probe = WaitReclaimDrop(storeId, beforeDelete.dbBlockBytes, CONCURRENT_RECLAIM_TIMEOUT_MS,
        CONCURRENT_RECLAIM_MIN_DROP_PERCENT);
    VerifySurvivingEntries(store, impl, context);
    RecordConcurrentProperties(summary, probe, writeFailures, checkpointAfterDelete);
    CloseStore(storeId, store);
    if (!probe.finalUsage.valid) {
        GTEST_SKIP() << "evidence gap: the RD database directory of the store is not measurable on this image";
    }

    ExpectConcurrentResults(summary, probe, beforeDelete, writeFailures);
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
    DeleteProbe probe = MeasurePlainDelete(store, storeId, impl, "disable_then_delete_", NO_DELETE_OBSERVE_MS);
    ASSERT_TRUE(probe.putOk);
    ASSERT_TRUE(probe.deleteOk);
    auto afterDeletes = ReadShrinkState(*impl);
    EXPECT_FALSE(afterDeletes.desiredEnabled);
    EXPECT_EQ(afterDeletes.pendingTasks, 0u);
    RecordDeleteProbeProperties("disable_", probe, "blocks");
    RecordProperty("disable_switch_pending_tasks_after_delete",
        static_cast<int64_t>(afterDeletes.pendingTasks));
    RecordProperty("disable_evidence_gap", std::string("an engine call or reclamation that started before "
        "the disable may still complete; no new switch task is queued; normal file housekeeping is tolerated"));
    CloseStore(storeId, store);
    if (!probe.measuredBefore || !probe.measuredAfter || probe.written.dbBlockBytes == 0) {
        GTEST_SKIP() << "evidence gap: the RD database directory of the store is not measurable on this image";
    }
    EXPECT_FALSE(ExceedsHousekeepingDrop(probe.written.dbBlockBytes, probe.afterDelete.dbBlockBytes)) <<
        "physical usage dropped although shrink was disabled before the deletes";
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
    TogglePhase enabledPhase = MeasureReclaimPhase(store, storeId, impl, "toggle_physical_on_",
        WAIT_RECLAIM_TIMEOUT_MS);
    ASSERT_TRUE(enabledPhase.putOk);
    ASSERT_TRUE(enabledPhase.deleteOk);
    RecordToggleReclaimProperties("enabled_", enabledPhase);

    ASSERT_EQ(store->SetShrinkEnable(false), SUCCESS);
    ASSERT_TRUE(WaitShrinkSettled(*impl, false, WAIT_SWITCH_TIMEOUT_MS));
    SleepMillis(NO_DELETE_OBSERVE_MS);
    TogglePhase disabledPhase = MeasureDisabledPhase(store, storeId, impl, "toggle_physical_off_");
    ASSERT_TRUE(disabledPhase.putOk);
    ASSERT_TRUE(disabledPhase.deleteOk);
    bool disabledDropped = disabledPhase.peakMeasured && disabledPhase.finalMeasured &&
        ExceedsHousekeepingDrop(disabledPhase.peak.dbBlockBytes, disabledPhase.finalUsage.dbBlockBytes);
    RecordToggleDisabledProperties("disabled_", disabledPhase, disabledDropped);

    ASSERT_EQ(store->SetShrinkEnable(true), SUCCESS);
    ASSERT_TRUE(WaitShrinkSettled(*impl, true, WAIT_SWITCH_TIMEOUT_MS));
    TogglePhase reenabledPhase = MeasureReclaimPhase(store, storeId, impl, "toggle_physical_again_",
        WAIT_RECLAIM_TIMEOUT_MS);
    ASSERT_TRUE(reenabledPhase.putOk);
    ASSERT_TRUE(reenabledPhase.deleteOk);
    RecordToggleReclaimProperties("reenabled_", reenabledPhase);

    CloseStore(storeId, store);
    if (!enabledPhase.peakMeasured || !disabledPhase.peakMeasured || !disabledPhase.finalMeasured ||
        !reenabledPhase.peakMeasured) {
        GTEST_SKIP() << "evidence gap: the RD database directory of the store is not measurable on this image";
    }
    EXPECT_FALSE(disabledDropped) << "physical usage dropped although the switch was disabled (peak=" <<
        disabledPhase.peak.dbBlockBytes << ", final=" << disabledPhase.finalUsage.dbBlockBytes << ")";
    EXPECT_TRUE(enabledPhase.reclaimed) << "no shrink driven drop observed while enabled (peak=" <<
        enabledPhase.peak.dbBlockBytes << ", final=" << enabledPhase.finalUsage.dbBlockBytes << ")";
    EXPECT_TRUE(reenabledPhase.reclaimed) << "no shrink driven drop observed after re-enabling (peak=" <<
        reenabledPhase.peak.dbBlockBytes << ", final=" << reenabledPhase.finalUsage.dbBlockBytes << ")";
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

    PerfContext context { plain, enabled, impl, enabledId };
    PerfSamples perf;
    ASSERT_TRUE(RunPerfRounds(context, perf));
    DiskUsage enabledFinal;
    PerfMedians medians = RunPerfMeasurement(context, perf, enabledFinal);

    auto disableStart = std::chrono::steady_clock::now();
    Status disableStatus = enabled->SetShrinkEnable(false);
    int64_t disableUs = ElapsedMicros(disableStart);
    ASSERT_TRUE(WaitShrinkSettled(*impl, false, WAIT_SWITCH_TIMEOUT_MS));
    RecordPerfTimingProperties(acceptUs, disableUs, perf);
    RecordPerfMeasurementProperties(medians, perf.enabledPeak, enabledFinal);
    EXPECT_EQ(disableStatus, SUCCESS);
    EXPECT_LE(acceptUs, MAX_ACCEPT_MILLIS * MICROS_PER_MILLI);
    EXPECT_LE(disableUs, MAX_ACCEPT_MILLIS * MICROS_PER_MILLI);
    CloseStore(enabledId, enabled);
    CloseStore(plainId, plain);

    if (!perf.enabledPeak.valid || !enabledFinal.valid || perf.enabledPeak.dbBlockBytes == 0) {
        GTEST_SKIP() << "evidence gap: the RD database directory of the store is not measurable on this image";
    }
    ExpectPerfResults(medians, perf.enabledPeak, enabledFinal);
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