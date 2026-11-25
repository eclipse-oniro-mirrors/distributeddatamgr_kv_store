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

#include <chrono>
#include <condition_variable>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "cloud_syncer_test.h"
#include "db_errno.h"
#include "distributeddb_tools_unit_test.h"
#include "mock_iclouddb.h"
#include "mock_icloud_sync_storage_interface.h"
#include "process_notifier.h"
#include "store_types.h"
#include "virtual_communicator_aggregator.h"

using namespace testing::ext;
using namespace testing;
using namespace DistributedDBUnitTest;
using namespace DistributedDB;

namespace {
using CloudTaskInfo = ICloudSyncer::CloudTaskInfo;
using InnerProcessInfo = ICloudSyncer::InnerProcessInfo;

// capture the SyncProcess values notified through the async task queue
class SyncProcessCapture {
public:
    void Notify(const std::map<std::string, SyncProcess> &process)
    {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            notifyCount_++;
            if (!process.empty()) {
                lastProcess_ = process.begin()->second;
            }
        }
        cv_.notify_all();
    }

    // wait until the predicate holds for the latest captured process, the predicate takes
    // (latest process, notify count)
    template<typename Pred>
    bool WaitFor(const Pred &pred, uint32_t timeoutMs = 4000)
    {
        std::unique_lock<std::mutex> lock(mutex_);
        return cv_.wait_for(lock, std::chrono::milliseconds(timeoutMs), [this, &pred]() {
            return pred(lastProcess_, notifyCount_);
        });
    }

    SyncProcess GetLastProcess() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return lastProcess_;
    }

    uint32_t GetNotifyCount() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return notifyCount_;
    }

private:
    mutable std::mutex mutex_;
    std::condition_variable cv_;
    SyncProcess lastProcess_ = {};
    uint32_t notifyCount_ = 0;
};

// a cloud db stub that keeps reporting the given external detail, used to drive the unlock
// failure path which must carry the adapter-provided detail instead of the internal composition
class ExternalDetailCloudDb : public MockICloudDB {
public:
    ExternalDetailCloudDb(uint32_t detailCode, const std::string &message)
        : detailCode_(detailCode), message_(message)
    {
    }

    ErrorDetail GetErrorDetail() const override
    {
        return ErrorDetail{detailCode_, message_};
    }

private:
    uint32_t detailCode_;
    std::string message_;
};

// expose the protected error-detail helpers and task context of CloudSyncer
class ErrorDetailTestCloudSyncer : public TestCloudSyncer {
public:
    explicit ErrorDetailTestCloudSyncer(const std::shared_ptr<TestStorageProxy> &storageProxy)
        : TestCloudSyncer(storageProxy)
    {
    }
    ~ErrorDetailTestCloudSyncer() override = default;
    DISABLE_COPY_ASSIGN_MOVE(ErrorDetailTestCloudSyncer);

    static void CallSetTaskErrorInfo(CloudTaskInfo &taskInfo, int errCode, const std::string &errorMessage,
        uint32_t detailCode)
    {
        CloudSyncer::SetTaskErrorInfo(taskInfo, errCode, errorMessage, detailCode);
    }

    void CallSetTaskFailed(TaskId taskId, int errCode, const std::string &errorMessage = "",
        uint32_t detailCode = 0, const std::string &tableName = "")
    {
        CloudSyncer::SetTaskFailed(taskId, errCode, errorMessage, detailCode, tableName);
    }

    void CallSetCurrentTaskFailedWithoutLock(int errCode, const std::string &errorMessage = "",
        uint32_t detailCode = 0, const std::string &tableName = "")
    {
        CloudSyncer::SetCurrentTaskFailedWithoutLock(errCode, errorMessage, detailCode, tableName);
    }

    void CallHeartBeatFailed(TaskId taskId, int errCode, const ErrorDetail &externalDetail)
    {
        CloudSyncer::HeartBeatFailed(taskId, errCode, externalDetail);
    }

    void CallNotifyDownloadAssetsFail(const std::string &tableName, const ErrorDetail &errorDetail)
    {
        CloudSyncer::NotifyDownloadAssetsFail(tableName, errorDetail);
    }

    void CallSetCurrentStage(SyncStage stage)
    {
        CloudSyncer::SetCurrentStage(stage);
    }

    void CallSetProxyUser(const std::string &user)
    {
        CloudSyncer::SetProxyUser(user);
    }

    void CallSetCurrentTmpError(int errCode, const std::string &errorMessage = "")
    {
        CloudSyncer::SetCurrentTmpError(errCode, errorMessage);
    }

    CloudSyncEvent CallSyncMachineDoFinished()
    {
        return CloudSyncer::SyncMachineDoFinished();
    }

    void CallFillCloudErrorInfoFromProxy(int errCode, const ErrorDetail &externalDetail, InnerProcessInfo &info)
    {
        CloudSyncer::FillCloudErrorInfoFromProxy(errCode, externalDetail, info);
    }

    ErrorDetail CallGetDownloadFailErrorDetail(int errCode, const std::string &tableName,
        const InnerProcessInfo &info) const
    {
        return CloudSyncer::GetDownloadFailErrorDetail(errCode, tableName, info);
    }

    void CallNotifyUploadFailed(int errCode, InnerProcessInfo &info)
    {
        CloudSyncer::NotifyUploadFailed(errCode, info);
    }

    int CallSaveCursorIfNeed(const std::string &tableName, ErrorDetail &errorDetail)
    {
        return CloudSyncer::SaveCursorIfNeed(tableName, errorDetail);
    }

    int CallPrepareAndDownload(const std::string &table, const CloudTaskInfo &taskInfo, bool isFirstDownload)
    {
        return CloudSyncer::PrepareAndDownload(table, taskInfo, isFirstDownload);
    }

    // ExecuteHeartBeatTask decrements the object ref on every path, keep the ref balanced here
    void CallExecuteHeartBeatTask(TaskId taskId)
    {
        RefObject::IncObjRef(this);
        CloudSyncer::ExecuteHeartBeatTask(taskId);
    }

    // establish/release the real cloud lock so the unlock failure wiring runs through the
    // CloudLocker finalize callback, the same path the state machine takes
    int CallLockCloudIfNeed(TaskId taskId)
    {
        return CloudSyncer::LockCloudIfNeed(taskId);
    }

    void CallUnlockIfNeed()
    {
        CloudSyncer::UnlockIfNeed();
    }

    CloudTaskInfo GetTaskInfo(TaskId taskId)
    {
        std::lock_guard<std::mutex> autoLock(dataLock_);
        auto it = cloudTaskInfos_.find(taskId);
        return it == cloudTaskInfos_.end() ? CloudTaskInfo() : it->second;
    }

    void UpdateTaskInfo(TaskId taskId, const std::function<void(CloudTaskInfo &)> &modifier)
    {
        std::lock_guard<std::mutex> autoLock(dataLock_);
        modifier(cloudTaskInfos_[taskId]);
    }

    void SetTaskCallback(TaskId taskId, const SyncProcessCallback &callback)
    {
        std::lock_guard<std::mutex> autoLock(dataLock_);
        cloudTaskInfos_[taskId].callback = callback;
    }

    void SetTaskDevices(TaskId taskId, const std::vector<std::string> &devices)
    {
        std::lock_guard<std::mutex> autoLock(dataLock_);
        cloudTaskInfos_[taskId].devices = devices;
    }

    void SetNeedRealUpload()
    {
        std::lock_guard<std::mutex> autoLock(dataLock_);
        currentContext_.isRealNeedUpload = true;
    }

    std::shared_ptr<ProcessNotifier> GetCurrentNotifier()
    {
        std::lock_guard<std::mutex> autoLock(dataLock_);
        return currentContext_.notifier;
    }

    void SetHeartbeatCount(TaskId taskId, int32_t count)
    {
        std::lock_guard<std::mutex> autoLock(heartbeatMutex_);
        heartbeatCount_[taskId] = count;
    }

    int32_t GetFailedHeartbeatCount(TaskId taskId)
    {
        std::lock_guard<std::mutex> autoLock(heartbeatMutex_);
        return failedHeartbeatCount_[taskId];
    }

    // mimic the counter creation of StartHeartBeatTimer, later heartbeat paths only use find
    void InitHeartbeatCounters(TaskId taskId)
    {
        std::lock_guard<std::mutex> autoLock(heartbeatMutex_);
        heartbeatCount_[taskId] = 0;
        failedHeartbeatCount_[taskId] = 0;
    }
};

void ErrorDetailCommonExpectCall(MockICloudSyncStorageInterface *iCloud)
{
    EXPECT_CALL(*iCloud, StartTransaction(_, false)).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*iCloud, Rollback(false)).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*iCloud, GetCloudTableSchema(_, _)).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*iCloud, GetMetaData(_, _)).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*iCloud, PutMetaData(_, _)).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*iCloud, ChkSchema(_)).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*iCloud, Commit(false)).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*iCloud, ReleaseCloudDataToken(_)).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*iCloud, GetCloudDataNext(_, _)).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*iCloud, GetCloudDbSchema()).WillRepeatedly(Return(nullptr));
}

// finish the task with an ok final result and wait until the reported accumulated detail is reset,
// used to isolate two adjacent merge-rule branches of CloudSyncerErrorDetailCheck026
void ResetTaskDetail(ErrorDetailTestCloudSyncer *cloudSyncer, const std::shared_ptr<ProcessNotifier> &notifier,
    SyncProcessCapture &capture, TaskId taskId, uint32_t expectCount)
{
    cloudSyncer->UpdateTaskInfo(taskId, [](CloudTaskInfo &taskInfo) {
        taskInfo.errCode = E_OK;
        taskInfo.status = FINISHED;
        taskInfo.detailCode = 0u;
        taskInfo.errorMessage.clear();
    });
    notifier->NotifyProcess(cloudSyncer->GetTaskInfo(taskId), {}, true);
    EXPECT_TRUE(capture.WaitFor([expectCount](const SyncProcess &process, uint32_t count) {
        return count >= expectCount && process.cloudErrorInfo.detailCode == 0u;
    }));
}

// one branch of the final report merge rule of CloudSyncerErrorDetailCheck026: accumulate the inner
// detail first, then overwrite the task detail with the latest one, notify the final result and
// assert the merged report carries the expected detail code and message, then return the report
// for the branch specific assertions
SyncProcess RunFinalDetailBranch(ErrorDetailTestCloudSyncer *cloudSyncer,
    const std::shared_ptr<ProcessNotifier> &notifier, SyncProcessCapture &capture, TaskId taskId,
    const InnerProcessInfo &accumulated, int latestErrCode, uint32_t latestDetailCode,
    const std::string &latestMessage, uint32_t expectCount, uint32_t expectDetailCode,
    const std::string &expectMessage)
{
    notifier->UpdateProcess(accumulated);
    cloudSyncer->UpdateTaskInfo(taskId, [latestErrCode, latestDetailCode, latestMessage](CloudTaskInfo &taskInfo) {
        taskInfo.errCode = latestErrCode;
        taskInfo.detailCode = latestDetailCode;
        taskInfo.errorMessage = latestMessage;
    });
    notifier->NotifyProcess(cloudSyncer->GetTaskInfo(taskId), {}, true);
    EXPECT_TRUE(capture.WaitFor([expectCount, expectDetailCode](const SyncProcess &process, uint32_t count) {
        return count >= expectCount && process.cloudErrorInfo.detailCode == expectDetailCode;
    }));
    SyncProcess res = capture.GetLastProcess();
    EXPECT_EQ(res.cloudErrorInfo.errorMessage, expectMessage);
    return res;
}

// wire the capture into the task callback so every notified SyncProcess is recorded
void SetCaptureCallback(ErrorDetailTestCloudSyncer *cloudSyncer, TaskId taskId, SyncProcessCapture &capture)
{
    cloudSyncer->SetTaskCallback(taskId, [&capture](const std::map<std::string, SyncProcess> &process) {
        capture.Notify(process);
    });
}

// build an inner process info carrying the given error detail for the table
InnerProcessInfo BuildInnerDetail(const std::string &tableName, uint32_t detailCode, const std::string &message)
{
    InnerProcessInfo info;
    info.tableName = tableName;
    info.innerCloudErrorInfo.detailCode = detailCode;
    info.innerCloudErrorInfo.errorMessage = message;
    return info;
}

// wait until a report notified after the given count carries the expected detail code and
// return the latest report
SyncProcess WaitForDetailReport(SyncProcessCapture &capture, uint32_t afterCount, uint32_t detailCode)
{
    EXPECT_TRUE(capture.WaitFor([afterCount, detailCode](const SyncProcess &process, uint32_t count) {
        return count > afterCount && process.cloudErrorInfo.detailCode == detailCode;
    }));
    return capture.GetLastProcess();
}

// wire the download mocks shared by the upload-water cases: every download returns the given
// upload data and the storage reports the given count of records to upload
void ExpectUploadWaters(MockICloudSyncStorageInterface *iCloud, const CloudSyncData &uploadData,
    int64_t uploadCount = 3)
{
    EXPECT_CALL(*iCloud, GetCloudData(_, _, _, _, _))
        .WillRepeatedly([&uploadData](const TableSchema &, const QuerySyncObject &, const Timestamp &,
            ContinueToken &, CloudSyncData &cloudDataResult) {
            cloudDataResult = uploadData;
            return E_OK;
        });
    EXPECT_CALL(*iCloud, GetAllUploadCount(_, _, _, _, _))
        .WillRepeatedly([uploadCount](const QuerySyncObject &, const std::vector<Timestamp> &, bool, bool,
            int64_t &count) {
            count = uploadCount; // upload record count reported by the storage
            return E_OK;
        });
}

// wire the batch mocks of CloudSyncerErrorDetailCheck020: every batch call succeeds but each
// insert record comes back marked LOCAL_ASSET_NOT_FOUND through the extends
void ExpectAssetMissingMarkedInserts(const std::shared_ptr<MockICloudDB> &idb)
{
    EXPECT_CALL(*idb, BatchDelete(_, _)).WillRepeatedly(Return(OK));
    EXPECT_CALL(*idb, BatchInsert(_, _, _))
        .WillRepeatedly([](const std::string &, std::vector<VBucket> &&record, std::vector<VBucket> &extend) {
            extend.assign(record.size(), {});
            for (auto &item : extend) {
                item[CloudDbConstant::ERROR_FIELD] = static_cast<int64_t>(DBStatus::LOCAL_ASSET_NOT_FOUND);
            }
            return LOCAL_ASSET_NOT_FOUND;
        });
    EXPECT_CALL(*idb, BatchUpdate(_, _, _)).WillRepeatedly(Return(OK));
}

// wire the batch mocks of CloudSyncerErrorDetailCheck024: the first BatchDelete succeeds so the
// soft error is recorded, and the later ones fail with CLOUD_ERROR written into the extends
void ExpectHardFailureAfterSoftUpload(MockICloudSyncStorageInterface *iCloud,
    const std::shared_ptr<MockICloudDB> &idb, const CloudSyncData &uploadData)
{
    ExpectUploadWaters(iCloud, uploadData);
    EXPECT_CALL(*idb, BatchDelete(_, _))
        .WillOnce(Return(OK))
        .WillRepeatedly([](const std::string &, std::vector<VBucket> &extend) {
            for (auto &item : extend) {
                item[CloudDbConstant::ERROR_FIELD] = static_cast<int64_t>(DBStatus::CLOUD_ERROR);
            }
            return DB_ERROR;
        });
    EXPECT_CALL(*idb, BatchInsert(_, _, _)).WillRepeatedly(Return(OK));
    EXPECT_CALL(*idb, BatchUpdate(_, _, _)).WillRepeatedly(Return(OK));
}

// wire the batch mocks of CloudSyncerErrorDetailCheck015: every BatchDelete fails with CLOUD_ERROR
// written into the extends, and the insert/update batches succeed
void ExpectAllDeleteBatchesFailed(const std::shared_ptr<MockICloudDB> &idb)
{
    EXPECT_CALL(*idb, BatchDelete(_, _)).WillRepeatedly([](const std::string &,
        std::vector<VBucket> &extend) {
        for (auto &item : extend) {
            item[CloudDbConstant::ERROR_FIELD] = static_cast<int64_t>(DBStatus::CLOUD_ERROR);
        }
        return DB_ERROR;
    });
    EXPECT_CALL(*idb, BatchInsert(_, _, _)).WillRepeatedly(Return(OK));
    EXPECT_CALL(*idb, BatchUpdate(_, _, _)).WillRepeatedly(Return(OK));
}

class DistributedDBCloudSyncerErrorDetailTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
protected:
    VirtualCommunicatorAggregator *communicatorAggregator_ = nullptr;

    // shared teardown for the syncer cases: the destroy sequence is identical across cases,
    // one helper holds this file under its 2000-line budget without touching any assertion
    void DestroySyncer(ErrorDetailTestCloudSyncer *cloudSyncer,
        std::shared_ptr<TestStorageProxy> &storageProxy, MockICloudSyncStorageInterface *iCloud)
    {
        RuntimeContext::GetInstance()->StopTaskPool();
        cloudSyncer->CallClose();
        RefObject::KillAndDecObjRef(cloudSyncer);
        storageProxy.reset();
        delete iCloud;
    }
};

void DistributedDBCloudSyncerErrorDetailTest::SetUpTestCase(void)
{
}

void DistributedDBCloudSyncerErrorDetailTest::TearDownTestCase(void)
{
}

void DistributedDBCloudSyncerErrorDetailTest::SetUp(void)
{
    DistributedDBToolsUnitTest::PrintTestCaseInfo();
    communicatorAggregator_ = new (std::nothrow) VirtualCommunicatorAggregator();
    ASSERT_TRUE(communicatorAggregator_ != nullptr);
    RuntimeContext::GetInstance()->SetCommunicatorAggregator(communicatorAggregator_);
}

void DistributedDBCloudSyncerErrorDetailTest::TearDown(void)
{
    RuntimeContext::GetInstance()->SetCommunicatorAggregator(nullptr);
    communicatorAggregator_ = nullptr;
    RuntimeContext::GetInstance()->SetProcessSystemApiAdapter(nullptr);
}

/**
 * @tc.name: CloudSyncerErrorDetailCheck001
 * @tc.desc: Test the last-wins triple overwrite rule of SetTaskErrorInfo
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: ztx
 */
HWTEST_F(DistributedDBCloudSyncerErrorDetailTest, CloudSyncerErrorDetailCheck001, TestSize.Level1)
{
    // 1. a fresh task takes the whole triple
    CloudTaskInfo taskInfo;
    ErrorDetailTestCloudSyncer::CallSetTaskErrorInfo(taskInfo, -E_CLOUD_ERROR, "external message", 0x420001u);
    EXPECT_EQ(taskInfo.errCode, -E_CLOUD_ERROR);
    EXPECT_EQ(taskInfo.errorMessage, "external message");
    EXPECT_EQ(taskInfo.detailCode, 0x420001u);

    // 2. a later error overwrites the whole triple, errCode/detailCode/errorMessage stay
    // consistent with the latest failure
    ErrorDetailTestCloudSyncer::CallSetTaskErrorInfo(taskInfo, -E_INVALID_ARGS, "second message", 0x400001u);
    EXPECT_EQ(taskInfo.errCode, -E_INVALID_ARGS);
    EXPECT_EQ(taskInfo.errorMessage, "second message");
    EXPECT_EQ(taskInfo.detailCode, 0x400001u);

    // 3. an error event without a detail clears the previous detail
    ErrorDetailTestCloudSyncer::CallSetTaskErrorInfo(taskInfo, -E_BUSY, "", 0u);
    EXPECT_EQ(taskInfo.errCode, -E_BUSY);
    EXPECT_TRUE(taskInfo.errorMessage.empty());
    EXPECT_EQ(taskInfo.detailCode, 0u);
}

/**
 * @tc.name: CloudSyncerErrorDetailCheck002
 * @tc.desc: Test the errno mapping and message derivation of ResolveErrorDetail
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: ztx
 */
HWTEST_F(DistributedDBCloudSyncerErrorDetailTest, CloudSyncerErrorDetailCheck002, TestSize.Level1)
{
    // 1. a mapped errCode produces the internal detailCode with empty stage bits and its message;
    // the stage bits are stamped by ProcessNotifier when the detail is written into a CloudErrorInfo
    uint32_t detailCode = 0u;
    std::string errorMessage;
    ProcessNotifier::ResolveErrorDetail(-E_CLOUD_ERROR, "TestTable", detailCode, errorMessage);
    EXPECT_EQ(detailCode, ProcessNotifier::MakeDetailCode(SyncStage::GENERAL, DetailCode::CLOUD_ERROR));
    EXPECT_EQ(errorMessage, ProcessNotifier::GetDetailMsg(DetailCode::CLOUD_ERROR));

    // 2. E_OK and unmapped errCodes keep the detailCode unset
    detailCode = 0u;
    errorMessage.clear();
    ProcessNotifier::ResolveErrorDetail(E_OK, "TestTable", detailCode, errorMessage);
    EXPECT_EQ(detailCode, 0u);
    EXPECT_TRUE(errorMessage.empty());
    ProcessNotifier::ResolveErrorDetail(-E_QUERY_END, "TestTable", detailCode, errorMessage);
    EXPECT_EQ(detailCode, 0u);
    EXPECT_TRUE(errorMessage.empty());

    // 3. an already set external detailCode is kept and no internal message is composed
    detailCode = 0x123456u; // external detail, internal flag not set
    errorMessage.clear();
    ProcessNotifier::ResolveErrorDetail(-E_CLOUD_ERROR, "TestTable", detailCode, errorMessage);
    EXPECT_EQ(detailCode, 0x123456u);
    EXPECT_TRUE(errorMessage.empty());

    // 4. schema details compose their message with the table name
    detailCode = 0u;
    errorMessage.clear();
    ProcessNotifier::ResolveErrorDetail(-E_SCHEMA_NOTEXIST, "StudentTable", detailCode, errorMessage);
    EXPECT_EQ(detailCode, ProcessNotifier::MakeDetailCode(SyncStage::GENERAL, DetailCode::SCHEMA_NOTEXIST));
    EXPECT_EQ(errorMessage, ProcessNotifier::GetDetailMessage(DetailCode::SCHEMA_NOTEXIST, "StudentTable"));

    // 5. a non-empty incoming errorMessage is kept untouched
    detailCode = 0u;
    errorMessage = "kept message";
    ProcessNotifier::ResolveErrorDetail(-E_CLOUD_ERROR, "TestTable", detailCode, errorMessage);
    EXPECT_EQ(detailCode, ProcessNotifier::MakeDetailCode(SyncStage::GENERAL, DetailCode::CLOUD_ERROR));
    EXPECT_EQ(errorMessage, "kept message");
}

/**
 * @tc.name: CloudSyncerErrorDetailCheck003
 * @tc.desc: Test SetTaskFailed for unknown, normal and already failed tasks
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: ztx
 */
HWTEST_F(DistributedDBCloudSyncerErrorDetailTest, CloudSyncerErrorDetailCheck003, TestSize.Level1)
{
    MockICloudSyncStorageInterface *iCloud = new MockICloudSyncStorageInterface();
    std::shared_ptr<TestStorageProxy> storageProxy = std::make_shared<TestStorageProxy>(iCloud);
    ErrorDetailTestCloudSyncer *cloudSyncer = new(std::nothrow) ErrorDetailTestCloudSyncer(storageProxy);
    ASSERT_NE(cloudSyncer, nullptr);
    TaskId taskId = 3u;

    // 1. unknown tasks are ignored
    cloudSyncer->CallSetTaskFailed(taskId, -E_CLOUD_ERROR, "no task", 0x111111u);
    EXPECT_EQ(cloudSyncer->GetTaskInfo(taskId).taskId, 0u);

    // 2. an empty tableName falls back to the current context table
    cloudSyncer->InitCloudSyncer(taskId, SyncMode::SYNC_MODE_CLOUD_MERGE);
    cloudSyncer->CallSetTaskFailed(taskId, -E_CLOUD_ERROR);
    CloudTaskInfo taskInfo = cloudSyncer->GetTaskInfo(taskId);
    EXPECT_EQ(taskInfo.errCode, -E_CLOUD_ERROR);
    EXPECT_EQ(taskInfo.detailCode, ProcessNotifier::MakeDetailCode(SyncStage::GENERAL, DetailCode::CLOUD_ERROR));
    EXPECT_EQ(taskInfo.errorMessage, ProcessNotifier::GetDetailMsg(DetailCode::CLOUD_ERROR));

    // 3. an already failed task keeps the first failure, the later failure is sealed out
    cloudSyncer->CallSetTaskFailed(taskId, -E_INVALID_ARGS, "second", 0x111111u);
    taskInfo = cloudSyncer->GetTaskInfo(taskId);
    EXPECT_EQ(taskInfo.errCode, -E_CLOUD_ERROR);
    EXPECT_EQ(taskInfo.detailCode, ProcessNotifier::MakeDetailCode(SyncStage::GENERAL, DetailCode::CLOUD_ERROR));
    EXPECT_EQ(taskInfo.errorMessage, ProcessNotifier::GetDetailMsg(DetailCode::CLOUD_ERROR));

    // 4. an explicit tableName takes precedence for the composed message
    TaskId secondTaskId = 4u;
    cloudSyncer->InitCloudSyncer(secondTaskId, SyncMode::SYNC_MODE_CLOUD_MERGE);
    cloudSyncer->CallSetTaskFailed(secondTaskId, -E_SCHEMA_NOTEXIST, "", 0u, "SchemaTable");
    taskInfo = cloudSyncer->GetTaskInfo(secondTaskId);
    EXPECT_EQ(taskInfo.errCode, -E_SCHEMA_NOTEXIST);
    EXPECT_EQ(taskInfo.detailCode, ProcessNotifier::MakeDetailCode(SyncStage::GENERAL, DetailCode::SCHEMA_NOTEXIST));
    EXPECT_EQ(taskInfo.errorMessage, ProcessNotifier::GetDetailMessage(DetailCode::SCHEMA_NOTEXIST, "SchemaTable"));

    DestroySyncer(cloudSyncer, storageProxy, iCloud);
}

/**
 * @tc.name: CloudSyncerErrorDetailCheck004
 * @tc.desc: Test SetCurrentTaskFailedWithoutLock for invalid and normal current tasks
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: ztx
 */
HWTEST_F(DistributedDBCloudSyncerErrorDetailTest, CloudSyncerErrorDetailCheck004, TestSize.Level1)
{
    MockICloudSyncStorageInterface *iCloud = new MockICloudSyncStorageInterface();
    std::shared_ptr<TestStorageProxy> storageProxy = std::make_shared<TestStorageProxy>(iCloud);
    ErrorDetailTestCloudSyncer *cloudSyncer = new(std::nothrow) ErrorDetailTestCloudSyncer(storageProxy);
    ASSERT_NE(cloudSyncer, nullptr);
    TaskId taskId = 5u;

    // 1. an invalid current task id is a no-op
    cloudSyncer->CallSetCurrentTaskFailedWithoutLock(-E_CLOUD_ERROR, "no current task", 0x111111u);
    EXPECT_EQ(cloudSyncer->GetTaskInfo(taskId).taskId, 0u);

    // 2. a current task id not present in the task map is a no-op
    cloudSyncer->InitCloudSyncer(taskId, SyncMode::SYNC_MODE_CLOUD_MERGE);
    cloudSyncer->SetCurrentContext(777u);
    cloudSyncer->CallSetCurrentTaskFailedWithoutLock(-E_CLOUD_ERROR, "no such task", 0x111111u);
    EXPECT_EQ(cloudSyncer->GetTaskInfo(taskId).errCode, E_OK);

    // 3. the current task is marked failed with the mapped internal detail
    cloudSyncer->SetCurrentContext(taskId);
    cloudSyncer->CallSetCurrentTaskFailedWithoutLock(-E_CLOUD_LOCK_ERROR);
    CloudTaskInfo taskInfo = cloudSyncer->GetTaskInfo(taskId);
    EXPECT_EQ(taskInfo.errCode, -E_CLOUD_LOCK_ERROR);
    EXPECT_EQ(taskInfo.detailCode, ProcessNotifier::MakeDetailCode(SyncStage::GENERAL, DetailCode::CLOUD_LOCK_ERROR));
    EXPECT_EQ(taskInfo.errorMessage, ProcessNotifier::GetDetailMsg(DetailCode::CLOUD_LOCK_ERROR));

    DestroySyncer(cloudSyncer, storageProxy, iCloud);
}

/**
 * @tc.name: CloudSyncerErrorDetailCheck005
 * @tc.desc: Test HeartBeatFailed with an external detail taking over the internal one
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: ztx
 */
HWTEST_F(DistributedDBCloudSyncerErrorDetailTest, CloudSyncerErrorDetailCheck005, TestSize.Level1)
{
    MockICloudSyncStorageInterface *iCloud = new MockICloudSyncStorageInterface();
    std::shared_ptr<TestStorageProxy> storageProxy = std::make_shared<TestStorageProxy>(iCloud);
    ErrorDetailTestCloudSyncer *cloudSyncer = new(std::nothrow) ErrorDetailTestCloudSyncer(storageProxy);
    ASSERT_NE(cloudSyncer, nullptr);
    // the counting gate and the internal detail are covered by Check018, this case only keeps the
    // external takeover: the failure reaching the limit carries the cloud detail and it wins
    TaskId taskId = 6u;
    cloudSyncer->InitCloudSyncer(taskId, SyncMode::SYNC_MODE_CLOUD_MERGE);
    cloudSyncer->InitHeartbeatCounters(taskId);
    cloudSyncer->CallHeartBeatFailed(taskId, -E_CLOUD_ERROR, ErrorDetail{});
    ErrorDetail externalDetail = { 0x123456u, "cloud unreachable" };
    cloudSyncer->CallHeartBeatFailed(taskId, -E_CLOUD_ERROR, externalDetail);
    CloudTaskInfo taskInfo = cloudSyncer->GetTaskInfo(taskId);
    EXPECT_EQ(taskInfo.errCode, -E_CLOUD_ERROR);
    EXPECT_EQ(taskInfo.detailCode, 0x123456u);
    EXPECT_EQ(taskInfo.errorMessage, "cloud unreachable");

    DestroySyncer(cloudSyncer, storageProxy, iCloud);
}

/**
 * @tc.name: CloudSyncerErrorDetailCheck006
 * @tc.desc: Test RegisterAssetDownloadFailCallback and NotifyDownloadAssetsFail
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: ztx
 */
HWTEST_F(DistributedDBCloudSyncerErrorDetailTest, CloudSyncerErrorDetailCheck006, TestSize.Level1)
{
    MockICloudSyncStorageInterface *iCloud = new MockICloudSyncStorageInterface();
    std::shared_ptr<TestStorageProxy> storageProxy = std::make_shared<TestStorageProxy>(iCloud);
    ErrorDetailTestCloudSyncer *cloudSyncer = new(std::nothrow) ErrorDetailTestCloudSyncer(storageProxy);
    ASSERT_NE(cloudSyncer, nullptr);

    // 1. notifying without a registered callback is a no-op
    std::string notifiedTable;
    ErrorDetail notifiedDetail;
    bool callbackCalled = false;
    cloudSyncer->CallNotifyDownloadAssetsFail("NoCallbackTable", ErrorDetail{ 0x123456u, "none" });
    EXPECT_FALSE(callbackCalled);

    // 2. the registered callback receives the table and the error detail
    cloudSyncer->RegisterAssetDownloadFailCallback([&](const std::string &tableName,
        const ErrorDetail &errorDetail) {
        notifiedTable = tableName;
        notifiedDetail = errorDetail;
        callbackCalled = true;
    });
    cloudSyncer->CallNotifyDownloadAssetsFail("AssetTable", ErrorDetail{ 0x110006u, "asset missing" });
    EXPECT_TRUE(callbackCalled);
    EXPECT_EQ(notifiedTable, "AssetTable");
    EXPECT_EQ(notifiedDetail.detailCode, 0x110006u);
    EXPECT_EQ(notifiedDetail.errorMessage, "asset missing");

    // 3. an empty detail is forwarded as well
    callbackCalled = false;
    cloudSyncer->CallNotifyDownloadAssetsFail("AssetTable2", ErrorDetail{});
    EXPECT_TRUE(callbackCalled);
    EXPECT_EQ(notifiedTable, "AssetTable2");
    EXPECT_EQ(notifiedDetail.detailCode, 0u);
    EXPECT_TRUE(notifiedDetail.errorMessage.empty());

    DestroySyncer(cloudSyncer, storageProxy, iCloud);
}

/**
 * @tc.name: CloudSyncerErrorDetailCheck007
 * @tc.desc: Test the stage maintenance and the auto stage stamp of ProcessNotifier
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: ztx
 */
HWTEST_F(DistributedDBCloudSyncerErrorDetailTest, CloudSyncerErrorDetailCheck007, TestSize.Level1)
{
    MockICloudSyncStorageInterface *iCloud = new MockICloudSyncStorageInterface();
    std::shared_ptr<TestStorageProxy> storageProxy = std::make_shared<TestStorageProxy>(iCloud);
    ErrorDetailTestCloudSyncer *cloudSyncer = new(std::nothrow) ErrorDetailTestCloudSyncer(storageProxy);
    ASSERT_NE(cloudSyncer, nullptr);
    TaskId taskId = 8u;
    cloudSyncer->InitCloudSyncer(taskId, SyncMode::SYNC_MODE_CLOUD_MERGE);
    auto notifier = cloudSyncer->GetCurrentNotifier();
    ASSERT_NE(notifier, nullptr);

    // 1. the default stage is GENERAL
    EXPECT_EQ(notifier->GetStage(), SyncStage::GENERAL);

    // 2. SetCurrentStage forwards the switch to the notifier
    cloudSyncer->CallSetCurrentStage(SyncStage::UPLOAD);
    EXPECT_EQ(notifier->GetStage(), SyncStage::UPLOAD);
    cloudSyncer->CallSetCurrentStage(SyncStage::DOWNLOAD);
    EXPECT_EQ(notifier->GetStage(), SyncStage::DOWNLOAD);

    // 3. StampStage composes the maintained stage into stage-less internal codes
    EXPECT_EQ(notifier->StampStage(ProcessNotifier::MakeDetailCode(SyncStage::GENERAL, DetailCode::CLOUD_ERROR)),
        ProcessNotifier::MakeDetailCode(SyncStage::DOWNLOAD, DetailCode::CLOUD_ERROR));
    // external codes and already stamped codes pass through untouched
    EXPECT_EQ(notifier->StampStage(0x123456u), 0x123456u);
    EXPECT_EQ(notifier->StampStage(ProcessNotifier::MakeDetailCode(SyncStage::UPLOAD, DetailCode::CLOUD_ERROR)),
        ProcessNotifier::MakeDetailCode(SyncStage::UPLOAD, DetailCode::CLOUD_ERROR));

    DestroySyncer(cloudSyncer, storageProxy, iCloud);
}

/**
 * @tc.name: CloudSyncerErrorDetailCheck008
 * @tc.desc: Test FillCloudErrorInfoFromProxy for success, external and internal details
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: ztx
 */
HWTEST_F(DistributedDBCloudSyncerErrorDetailTest, CloudSyncerErrorDetailCheck008, TestSize.Level1)
{
    MockICloudSyncStorageInterface *iCloud = new MockICloudSyncStorageInterface();
    std::shared_ptr<TestStorageProxy> storageProxy = std::make_shared<TestStorageProxy>(iCloud);
    ErrorDetailTestCloudSyncer *cloudSyncer = new(std::nothrow) ErrorDetailTestCloudSyncer(storageProxy);
    ASSERT_NE(cloudSyncer, nullptr);
    TaskId taskId = 8u;
    cloudSyncer->InitCloudSyncer(taskId, SyncMode::SYNC_MODE_CLOUD_MERGE);
    ErrorDetail externalDetail = { 0x123456u, "external detail" };
    InnerProcessInfo info;
    info.tableName = "TestTable8";

    // 1. the E_OK gate only rejects empty details: an empty external detail never fills the info
    // whatever the errCode is, while a non-empty one is the real failure report of the batch
    cloudSyncer->CallFillCloudErrorInfoFromProxy(E_OK, ErrorDetail{}, info);
    EXPECT_EQ(info.innerCloudErrorInfo.detailCode, 0u);
    EXPECT_TRUE(info.innerCloudErrorInfo.errorMessage.empty());
    cloudSyncer->CallFillCloudErrorInfoFromProxy(-E_QUERY_END, ErrorDetail{}, info);
    EXPECT_EQ(info.innerCloudErrorInfo.detailCode, 0u);
    EXPECT_TRUE(info.innerCloudErrorInfo.errorMessage.empty());
    cloudSyncer->CallFillCloudErrorInfoFromProxy(E_OK, externalDetail, info);
    EXPECT_EQ(info.innerCloudErrorInfo.detailCode, 0x123456u);
    EXPECT_EQ(info.innerCloudErrorInfo.errorMessage, "external detail");

    // 2. the external detail is taken and never overwritten afterwards
    cloudSyncer->CallFillCloudErrorInfoFromProxy(-E_CLOUD_ERROR, externalDetail, info);
    EXPECT_EQ(info.innerCloudErrorInfo.detailCode, 0x123456u);
    EXPECT_EQ(info.innerCloudErrorInfo.errorMessage, "external detail");
    cloudSyncer->CallFillCloudErrorInfoFromProxy(-E_INVALID_ARGS, ErrorDetail{ 0x654321u, "other" }, info);
    EXPECT_EQ(info.innerCloudErrorInfo.detailCode, 0x123456u);
    EXPECT_EQ(info.innerCloudErrorInfo.errorMessage, "external detail");

    // 3. without an external detail the errCode is mapped with the current stage
    cloudSyncer->CallSetCurrentStage(SyncStage::DOWNLOAD);
    InnerProcessInfo downloadInfo;
    downloadInfo.tableName = "TestTable8";
    cloudSyncer->CallFillCloudErrorInfoFromProxy(-E_CLOUD_ERROR, ErrorDetail{}, downloadInfo);
    EXPECT_EQ(downloadInfo.innerCloudErrorInfo.detailCode,
        ProcessNotifier::MakeDetailCode(SyncStage::DOWNLOAD, DetailCode::CLOUD_ERROR));
    EXPECT_EQ(downloadInfo.innerCloudErrorInfo.errorMessage, ProcessNotifier::GetDetailMsg(DetailCode::CLOUD_ERROR));

    DestroySyncer(cloudSyncer, storageProxy, iCloud);
}

/**
 * @tc.name: CloudSyncerErrorDetailCheck009
 * @tc.desc: Test GetDownloadFailErrorDetail for kept and derived details
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: ztx
 */
HWTEST_F(DistributedDBCloudSyncerErrorDetailTest, CloudSyncerErrorDetailCheck009, TestSize.Level1)
{
    MockICloudSyncStorageInterface *iCloud = new MockICloudSyncStorageInterface();
    std::shared_ptr<TestStorageProxy> storageProxy = std::make_shared<TestStorageProxy>(iCloud);
    ErrorDetailTestCloudSyncer *cloudSyncer = new(std::nothrow) ErrorDetailTestCloudSyncer(storageProxy);
    ASSERT_NE(cloudSyncer, nullptr);

    // 1. a detail already recorded in the process info is returned unchanged
    InnerProcessInfo info;
    info.innerCloudErrorInfo.detailCode = 0x111111u;
    info.innerCloudErrorInfo.errorMessage = "download failed";
    ErrorDetail errorDetail = cloudSyncer->CallGetDownloadFailErrorDetail(-E_CLOUD_ERROR, "TestTable10", info);
    EXPECT_EQ(errorDetail.detailCode, 0x111111u);
    EXPECT_EQ(errorDetail.errorMessage, "download failed");

    // 2. an empty info falls back to the DOWNLOAD stage mapping
    InnerProcessInfo emptyInfo;
    errorDetail = cloudSyncer->CallGetDownloadFailErrorDetail(-E_CLOUD_ASSET_NOT_FOUND, "TestTable10", emptyInfo);
    EXPECT_EQ(errorDetail.detailCode,
        ProcessNotifier::MakeDetailCode(SyncStage::DOWNLOAD, DetailCode::CLOUD_ASSET_NOT_FOUND));
    EXPECT_EQ(errorDetail.errorMessage, ProcessNotifier::GetDetailMsg(DetailCode::CLOUD_ASSET_NOT_FOUND));

    // 3. a success keeps everything unset
    InnerProcessInfo okInfo;
    errorDetail = cloudSyncer->CallGetDownloadFailErrorDetail(E_OK, "TestTable10", okInfo);
    EXPECT_EQ(errorDetail.detailCode, 0u);
    EXPECT_TRUE(errorDetail.errorMessage.empty());

    DestroySyncer(cloudSyncer, storageProxy, iCloud);
}

/**
 * @tc.name: CloudSyncerErrorDetailCheck010
 * @tc.desc: Test TryToAddSyncTask with an existing taskId fails without any callback
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: ztx
 */
HWTEST_F(DistributedDBCloudSyncerErrorDetailTest, CloudSyncerErrorDetailCheck010, TestSize.Level1)
{
    MockICloudSyncStorageInterface *iCloud = new MockICloudSyncStorageInterface();
    std::shared_ptr<TestStorageProxy> storageProxy = std::make_shared<TestStorageProxy>(iCloud);
    ErrorDetailTestCloudSyncer *cloudSyncer = new(std::nothrow) ErrorDetailTestCloudSyncer(storageProxy);
    ASSERT_NE(cloudSyncer, nullptr);
    TaskId taskId = 11u;
    cloudSyncer->InitCloudSyncer(taskId, SyncMode::SYNC_MODE_CLOUD_MERGE);

    SyncProcessCapture capture;
    CloudTaskInfo taskInfo;
    taskInfo.taskId = taskId; // conflicts with the existing task
    taskInfo.mode = SyncMode::SYNC_MODE_CLOUD_MERGE;
    taskInfo.table = { "TestTable11" };
    taskInfo.devices = { "cloud" };
    taskInfo.callback = [&capture](const std::map<std::string, SyncProcess> &process) {
        capture.Notify(process);
    };

    // adding fails synchronously, the caller takes the non-OK return as "task never started" and
    // must not receive any process callback for it
    EXPECT_EQ(cloudSyncer->CallTryToAddSyncTask(std::move(taskInfo)), -E_INVALID_ARGS);
    EXPECT_FALSE(capture.WaitFor([](const SyncProcess &, uint32_t count) {
        return count > 0;
    }, 500)); // no callback may ever arrive, half a second is far beyond a queued dispatch
    EXPECT_EQ(capture.GetNotifyCount(), 0u);

    DestroySyncer(cloudSyncer, storageProxy, iCloud);
}

/**
 * @tc.name: CloudSyncerErrorDetailCheck011
 * @tc.desc: Test TryToAddSyncTask on a closed syncer fails without any callback
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: ztx
 */
HWTEST_F(DistributedDBCloudSyncerErrorDetailTest, CloudSyncerErrorDetailCheck011, TestSize.Level1)
{
    MockICloudSyncStorageInterface *iCloud = new MockICloudSyncStorageInterface();
    std::shared_ptr<TestStorageProxy> storageProxy = std::make_shared<TestStorageProxy>(iCloud);
    ErrorDetailTestCloudSyncer *cloudSyncer = new(std::nothrow) ErrorDetailTestCloudSyncer(storageProxy);
    ASSERT_NE(cloudSyncer, nullptr);
    cloudSyncer->CallClose(); // sets the closed flag

    SyncProcessCapture capture;
    CloudTaskInfo taskInfo;
    taskInfo.table = { "TestTable12" };
    taskInfo.devices = { "cloud" };
    taskInfo.callback = [&capture](const std::map<std::string, SyncProcess> &process) {
        capture.Notify(process);
    };
    // the closed syncer keeps the contract: a synchronous failure reports via the return value
    // only, no callback fires
    EXPECT_EQ(cloudSyncer->CallTryToAddSyncTask(std::move(taskInfo)), -E_DB_CLOSED);
    EXPECT_FALSE(capture.WaitFor([](const SyncProcess &, uint32_t count) {
        return count > 0;
    }, 500));
    EXPECT_EQ(capture.GetNotifyCount(), 0u);

    RuntimeContext::GetInstance()->StopTaskPool();
    RefObject::KillAndDecObjRef(cloudSyncer);
    storageProxy.reset();
    delete iCloud;
}

/**
 * @tc.name: CloudSyncerErrorDetailCheck012
 * @tc.desc: Test StopAllTasks with the interrupted errCode keeps the current task
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: ztx
 */
HWTEST_F(DistributedDBCloudSyncerErrorDetailTest, CloudSyncerErrorDetailCheck012, TestSize.Level1)
{
    MockICloudSyncStorageInterface *iCloud = new MockICloudSyncStorageInterface();
    std::shared_ptr<TestStorageProxy> storageProxy = std::make_shared<TestStorageProxy>(iCloud);
    ErrorDetailTestCloudSyncer *cloudSyncer = new(std::nothrow) ErrorDetailTestCloudSyncer(storageProxy);
    ASSERT_NE(cloudSyncer, nullptr);
    TaskId firstTaskId = 12u;
    TaskId secondTaskId = 13u;
    cloudSyncer->InitCloudSyncer(firstTaskId, SyncMode::SYNC_MODE_CLOUD_MERGE);
    cloudSyncer->InitCloudSyncer(secondTaskId, SyncMode::SYNC_MODE_CLOUD_MERGE);
    SyncProcessCapture capture;
    cloudSyncer->SetTaskCallback(firstTaskId, [&capture](const std::map<std::string, SyncProcess> &process) {
        capture.Notify(process);
    });
    cloudSyncer->SetTaskDevices(firstTaskId, { "cloud" });

    cloudSyncer->StopAllTasks(-E_TASK_INTERRUPTED);

    // the current task is kept but marked as stopped by a system event
    CloudTaskInfo currentInfo = cloudSyncer->GetTaskInfo(secondTaskId);
    EXPECT_EQ(currentInfo.errCode, -E_TASK_INTERRUPTED);
    EXPECT_EQ(currentInfo.detailCode, ProcessNotifier::MakeDetailCode(SyncStage::GENERAL,
        DetailCode::CLOUD_SYSTEM_EVENT_STOPPED));
    EXPECT_EQ(currentInfo.errorMessage, ProcessNotifier::GetDetailMsg(DetailCode::CLOUD_SYSTEM_EVENT_STOPPED));

    // the queued task is notified with the same detail
    EXPECT_TRUE(capture.WaitFor([](const SyncProcess &process, uint32_t count) {
        return count > 0 && process.cloudErrorInfo.detailCode ==
            ProcessNotifier::MakeDetailCode(SyncStage::GENERAL, DetailCode::CLOUD_SYSTEM_EVENT_STOPPED);
    }));
    SyncProcess res = capture.GetLastProcess();
    EXPECT_EQ(res.errCode, DBStatus::TASK_INTERRUPTED);
    EXPECT_EQ(res.process, FINISHED);
    EXPECT_EQ(res.cloudErrorInfo.errorMessage, ProcessNotifier::GetDetailMsg(DetailCode::CLOUD_SYSTEM_EVENT_STOPPED));

    // the queued task has been removed from the task map
    EXPECT_EQ(cloudSyncer->GetTaskInfo(firstTaskId).taskId, 0u);

    DestroySyncer(cloudSyncer, storageProxy, iCloud);
}

/**
 * @tc.name: CloudSyncerErrorDetailCheck013
 * @tc.desc: Test StopAllTasks with the default errCode notifies every queued task
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: ztx
 */
HWTEST_F(DistributedDBCloudSyncerErrorDetailTest, CloudSyncerErrorDetailCheck013, TestSize.Level1)
{
    MockICloudSyncStorageInterface *iCloud = new MockICloudSyncStorageInterface();
    std::shared_ptr<TestStorageProxy> storageProxy = std::make_shared<TestStorageProxy>(iCloud);
    ErrorDetailTestCloudSyncer *cloudSyncer = new(std::nothrow) ErrorDetailTestCloudSyncer(storageProxy);
    ASSERT_NE(cloudSyncer, nullptr);
    TaskId firstTaskId = 14u;
    TaskId secondTaskId = 15u;
    cloudSyncer->InitCloudSyncer(firstTaskId, SyncMode::SYNC_MODE_CLOUD_MERGE);
    cloudSyncer->InitCloudSyncer(secondTaskId, SyncMode::SYNC_MODE_CLOUD_MERGE);
    SyncProcessCapture capture;
    SyncProcessCallback callback = [&capture](const std::map<std::string, SyncProcess> &process) {
        capture.Notify(process);
    };
    cloudSyncer->SetTaskCallback(firstTaskId, callback);
    cloudSyncer->SetTaskCallback(secondTaskId, callback);
    cloudSyncer->SetTaskDevices(firstTaskId, { "cloud" });
    cloudSyncer->SetTaskDevices(secondTaskId, { "cloud" });
    // simulate that no task is currently running
    cloudSyncer->SetCurrentContext(0u);

    cloudSyncer->StopAllTasks(); // default errCode is -E_USER_CHANGE

    // both queued tasks are notified
    EXPECT_TRUE(capture.WaitFor([](const SyncProcess &process, uint32_t count) {
        return count >= 2 && process.cloudErrorInfo.detailCode ==
            ProcessNotifier::MakeDetailCode(SyncStage::GENERAL, DetailCode::CLOUD_SYSTEM_EVENT_STOPPED);
    }));
    EXPECT_EQ(capture.GetNotifyCount(), 2u);
    SyncProcess res = capture.GetLastProcess();
    EXPECT_EQ(res.errCode, DBStatus::USER_CHANGED);
    EXPECT_EQ(res.process, FINISHED);
    EXPECT_EQ(res.cloudErrorInfo.errorMessage, ProcessNotifier::GetDetailMsg(DetailCode::CLOUD_SYSTEM_EVENT_STOPPED));

    // the task map is cleared
    EXPECT_EQ(cloudSyncer->GetTaskInfo(firstTaskId).taskId, 0u);
    EXPECT_EQ(cloudSyncer->GetTaskInfo(secondTaskId).taskId, 0u);

    DestroySyncer(cloudSyncer, storageProxy, iCloud);
}

/**
 * @tc.name: CloudSyncerErrorDetailCheck014
 * @tc.desc: Test NotifyUploadFailed for common failures and version conflicts
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: ztx
 */
HWTEST_F(DistributedDBCloudSyncerErrorDetailTest, CloudSyncerErrorDetailCheck014, TestSize.Level1)
{
    MockICloudSyncStorageInterface *iCloud = new MockICloudSyncStorageInterface();
    std::shared_ptr<TestStorageProxy> storageProxy = std::make_shared<TestStorageProxy>(iCloud);
    ErrorDetailTestCloudSyncer *cloudSyncer = new(std::nothrow) ErrorDetailTestCloudSyncer(storageProxy);
    ASSERT_NE(cloudSyncer, nullptr);
    TaskId taskId = 16u;
    cloudSyncer->InitCloudSyncer(taskId, SyncMode::SYNC_MODE_CLOUD_MERGE);
    cloudSyncer->CallSetCurrentStage(SyncStage::UPLOAD);

    // 1. a common failure fills the fail count and maps the internal detail by stage
    InnerProcessInfo info;
    info.tableName = cloudSyncer->GetCurrentContextTableName();
    info.upLoadInfo.batchIndex = 1;
    info.upLoadInfo.total = 100;
    info.upLoadInfo.successCount = 40;
    cloudSyncer->CallNotifyUploadFailed(-E_CLOUD_ERROR, info);
    EXPECT_EQ(info.upLoadInfo.failCount, 60u);
    EXPECT_EQ(info.tableStatus, FINISHED);
    EXPECT_EQ(info.innerCloudErrorInfo.detailCode,
        ProcessNotifier::MakeDetailCode(SyncStage::UPLOAD, DetailCode::CLOUD_ERROR));
    EXPECT_EQ(info.innerCloudErrorInfo.errorMessage,
        ProcessNotifier::GetDetailMsg(DetailCode::CLOUD_ERROR));
    auto notifier = cloudSyncer->GetCurrentNotifier();
    ASSERT_NE(notifier, nullptr);
    auto tableProcess = notifier->GetCurrentTableProcess();
    EXPECT_EQ(tableProcess[info.tableName].process, FINISHED);
    EXPECT_EQ(tableProcess[info.tableName].upLoadInfo.failCount, 60u);

    // 2. a version conflict keeps the fail count and maps the conflict detail
    InnerProcessInfo conflictInfo;
    conflictInfo.tableName = cloudSyncer->GetCurrentContextTableName();
    conflictInfo.upLoadInfo.batchIndex = 1;
    conflictInfo.upLoadInfo.total = 50;
    conflictInfo.upLoadInfo.successCount = 10;
    conflictInfo.upLoadInfo.failCount = 5;
    cloudSyncer->CallNotifyUploadFailed(-E_CLOUD_VERSION_CONFLICT, conflictInfo);
    EXPECT_EQ(conflictInfo.upLoadInfo.failCount, 5u);
    EXPECT_EQ(conflictInfo.tableStatus, FINISHED);
    EXPECT_EQ(conflictInfo.innerCloudErrorInfo.detailCode,
        ProcessNotifier::MakeDetailCode(SyncStage::UPLOAD, DetailCode::CLOUD_VERSION_CONFLICT));
    EXPECT_EQ(conflictInfo.innerCloudErrorInfo.errorMessage,
        ProcessNotifier::GetDetailMsg(DetailCode::CLOUD_VERSION_CONFLICT));

    DestroySyncer(cloudSyncer, storageProxy, iCloud);
}

/**
 * @tc.name: CloudSyncerErrorDetailCheck015
 * @tc.desc: Test the upload machine reports the batch failure detail end to end
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: ztx
 */
HWTEST_F(DistributedDBCloudSyncerErrorDetailTest, CloudSyncerErrorDetailCheck015, TestSize.Level1)
{
    MockICloudSyncStorageInterface *iCloud = new MockICloudSyncStorageInterface();
    std::shared_ptr<TestStorageProxy> storageProxy = std::make_shared<TestStorageProxy>(iCloud);
    ErrorDetailTestCloudSyncer *cloudSyncer = new(std::nothrow) ErrorDetailTestCloudSyncer(storageProxy);
    ASSERT_NE(cloudSyncer, nullptr);
    std::shared_ptr<MockICloudDB> idb = std::make_shared<MockICloudDB>();
    cloudSyncer->SetMockICloudDB(idb);
    ErrorDetailCommonExpectCall(iCloud);

    TaskId taskId = 17u;
    cloudSyncer->InitCloudSyncer(taskId, SyncMode::SYNC_MODE_CLOUD_MERGE);
    cloudSyncer->SetNeedRealUpload();
    CloudSyncData uploadData(cloudSyncer->GetCurrentContextTableName());
    cloudSyncer->initFullCloudSyncData(uploadData, 1000);

    // the first water type is DELETE, its cloud batch call fails and every record is marked failed
    ExpectUploadWaters(iCloud, uploadData, 3000); // 3000 is the upload count
    ExpectAllDeleteBatchesFailed(idb);

    SyncProcessCapture capture;
    SetCaptureCallback(cloudSyncer, taskId, capture);

    // the machine sets the UPLOAD stage and marks the current task failed in place
    EXPECT_EQ(cloudSyncer->SyncMachineDoUpload(), CloudSyncEvent::ERROR_EVENT);
    CloudTaskInfo taskInfo = cloudSyncer->GetTaskInfo(taskId);
    EXPECT_EQ(taskInfo.errCode, -E_CLOUD_ERROR);
    // the stage is stamped where the failure happens, so the task info already carries the
    // UPLOAD bits even before the notifier exports it
    const uint32_t uploadDetailCode = ProcessNotifier::MakeDetailCode(SyncStage::UPLOAD, DetailCode::CLOUD_ERROR);
    EXPECT_EQ(taskInfo.detailCode, uploadDetailCode);
    EXPECT_EQ(taskInfo.errorMessage, ProcessNotifier::GetDetailMsg(DetailCode::CLOUD_ERROR));

    // notify the failed task info and check what the user callback receives
    auto notifier = cloudSyncer->GetCurrentNotifier();
    ASSERT_NE(notifier, nullptr);
    notifier->NotifyProcess(taskInfo, {}, true);
    SyncProcess res = WaitForDetailReport(capture, 0, uploadDetailCode);
    EXPECT_EQ(res.errCode, DBStatus::CLOUD_ERROR);
    EXPECT_EQ(res.cloudErrorInfo.errorMessage, ProcessNotifier::GetDetailMsg(DetailCode::CLOUD_ERROR));
    EXPECT_EQ(res.tableProcess[cloudSyncer->GetCurrentContextTableName()].upLoadInfo.failCount, 3000u);

    DestroySyncer(cloudSyncer, storageProxy, iCloud);
    idb = nullptr;
}

/**
 * @tc.name: CloudSyncerErrorDetailCheck016
 * @tc.desc: Test the process notifier merges details and resets them on success
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: ztx
 */
HWTEST_F(DistributedDBCloudSyncerErrorDetailTest, CloudSyncerErrorDetailCheck016, TestSize.Level1)
{
    MockICloudSyncStorageInterface *iCloud = new MockICloudSyncStorageInterface();
    std::shared_ptr<TestStorageProxy> storageProxy = std::make_shared<TestStorageProxy>(iCloud);
    ErrorDetailTestCloudSyncer *cloudSyncer = new(std::nothrow) ErrorDetailTestCloudSyncer(storageProxy);
    ASSERT_NE(cloudSyncer, nullptr);
    TaskId taskId = 18u;
    cloudSyncer->InitCloudSyncer(taskId, SyncMode::SYNC_MODE_CLOUD_MERGE);
    auto notifier = cloudSyncer->GetCurrentNotifier();
    ASSERT_NE(notifier, nullptr);
    SyncProcessCapture capture;
    SetCaptureCallback(cloudSyncer, taskId, capture);

    // 1. process updates keep the first non-zero error detail
    std::string tableName = cloudSyncer->GetCurrentContextTableName();
    notifier->UpdateProcess(BuildInnerDetail(tableName, 0x123456u, "external detail"));
    notifier->UpdateProcess(BuildInnerDetail(tableName, 0x654321u, "later detail"));

    // 2. a failed task notifies the accumulated detail to the user callback
    cloudSyncer->UpdateTaskInfo(taskId, [](CloudTaskInfo &taskInfo) {
        taskInfo.errCode = -E_CLOUD_ERROR;
        taskInfo.status = FINISHED;
    });
    notifier->NotifyProcess(cloudSyncer->GetTaskInfo(taskId), {}, true);
    SyncProcess res = WaitForDetailReport(capture, 0, 0x123456u);
    EXPECT_EQ(res.errCode, DBStatus::CLOUD_ERROR);
    EXPECT_EQ(res.cloudErrorInfo.errorMessage, "external detail");

    // 3. a final success clears the accumulated error detail
    cloudSyncer->UpdateTaskInfo(taskId, [](CloudTaskInfo &taskInfo) {
        taskInfo.errCode = E_OK;
        taskInfo.status = FINISHED;
    });
    notifier->NotifyProcess(cloudSyncer->GetTaskInfo(taskId), {}, true);
    res = WaitForDetailReport(capture, 1, 0u);
    EXPECT_EQ(res.errCode, OK);
    EXPECT_EQ(res.process, FINISHED);
    EXPECT_TRUE(res.cloudErrorInfo.errorMessage.empty());

    // 4. error results are suppressed when notifyWhenError is not requested
    cloudSyncer->UpdateTaskInfo(taskId, [](CloudTaskInfo &taskInfo) {
        taskInfo.errCode = -E_CLOUD_ERROR;
    });
    notifier->NotifyProcess(cloudSyncer->GetTaskInfo(taskId), {}, false);
    EXPECT_EQ(capture.GetNotifyCount(), 2u);

    DestroySyncer(cloudSyncer, storageProxy, iCloud);
}

/**
 * @tc.name: CloudSyncerErrorDetailCheck017
 * @tc.desc: Test SaveCursorIfNeed and the PrepareAndDownload failure wiring
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: ztx
 */
HWTEST_F(DistributedDBCloudSyncerErrorDetailTest, CloudSyncerErrorDetailCheck017, TestSize.Level1)
{
    MockICloudSyncStorageInterface *iCloud = new MockICloudSyncStorageInterface();
    std::shared_ptr<TestStorageProxy> storageProxy = std::make_shared<TestStorageProxy>(iCloud);
    ErrorDetailTestCloudSyncer *cloudSyncer = new(std::nothrow) ErrorDetailTestCloudSyncer(storageProxy);
    ASSERT_NE(cloudSyncer, nullptr);
    std::shared_ptr<MockICloudDB> idb = std::make_shared<MockICloudDB>();
    cloudSyncer->SetMockICloudDB(idb);

    EXPECT_CALL(*iCloud, GetMetaData(_, _)).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*iCloud, PutMetaData(_, _)).WillRepeatedly(Return(E_OK));
    EXPECT_CALL(*idb, GetEmptyCursor(_))
        .WillOnce(Return(std::make_pair(static_cast<DBStatus>(OK), std::string("savedCursor"))))
        .WillRepeatedly(Return(std::make_pair(static_cast<DBStatus>(DB_ERROR), std::string())));

    // 1. the empty cursor is saved as the cloud watermark
    ErrorDetail errorDetail;
    EXPECT_EQ(cloudSyncer->CallSaveCursorIfNeed("SaveCursorTable", errorDetail), E_OK);

    // 2. a failing cloud call aborts with the cloud error
    errorDetail = {};
    EXPECT_EQ(cloudSyncer->CallSaveCursorIfNeed("FailCursorTable", errorDetail), -E_CLOUD_ERROR);

    // 3. PrepareAndDownload wires the download failure into the task info
    TaskId taskId = 19u;
    cloudSyncer->InitCloudSyncer(taskId, SyncMode::SYNC_MODE_CLOUD_MERGE);
    CloudTaskInfo taskInfo = cloudSyncer->GetTaskInfo(taskId);
    EXPECT_EQ(cloudSyncer->CallPrepareAndDownload("TestTable19", taskInfo, false), -E_CLOUD_ERROR);
    taskInfo = cloudSyncer->GetTaskInfo(taskId);
    EXPECT_EQ(taskInfo.errCode, -E_CLOUD_ERROR);
    EXPECT_EQ(taskInfo.detailCode, ProcessNotifier::MakeDetailCode(SyncStage::GENERAL, DetailCode::CLOUD_ERROR));
    EXPECT_EQ(taskInfo.errorMessage, ProcessNotifier::GetDetailMsg(DetailCode::CLOUD_ERROR));

    DestroySyncer(cloudSyncer, storageProxy, iCloud);
    idb = nullptr;
}

/**
 * @tc.name: CloudSyncerErrorDetailCheck018
 * @tc.desc: Test ExecuteHeartBeatTask for blocked and repeatedly failing heartbeats
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: ztx
 */
HWTEST_F(DistributedDBCloudSyncerErrorDetailTest, CloudSyncerErrorDetailCheck018, TestSize.Level1)
{
    MockICloudSyncStorageInterface *iCloud = new MockICloudSyncStorageInterface();
    std::shared_ptr<TestStorageProxy> storageProxy = std::make_shared<TestStorageProxy>(iCloud);
    ErrorDetailTestCloudSyncer *cloudSyncer = new(std::nothrow) ErrorDetailTestCloudSyncer(storageProxy);
    ASSERT_NE(cloudSyncer, nullptr);
    std::shared_ptr<MockICloudDB> idb = std::make_shared<MockICloudDB>();
    cloudSyncer->SetMockICloudDB(idb);
    EXPECT_CALL(*idb, HeartBeat())
        .WillOnce(Return(static_cast<DBStatus>(CLOUD_ERROR)))
        .WillOnce(Return(static_cast<DBStatus>(CLOUD_ERROR)))
        .WillRepeatedly(Return(static_cast<DBStatus>(OK)));

    // 1. heartbeats blocked for a whole period fail the task directly
    TaskId blockedTaskId = 20u;
    cloudSyncer->InitCloudSyncer(blockedTaskId, SyncMode::SYNC_MODE_CLOUD_MERGE);
    cloudSyncer->SetHeartbeatCount(blockedTaskId, 3); // HEARTBEAT_PERIOD is 3
    cloudSyncer->CallExecuteHeartBeatTask(blockedTaskId);
    CloudTaskInfo taskInfo = cloudSyncer->GetTaskInfo(blockedTaskId);
    EXPECT_EQ(taskInfo.errCode, -E_CLOUD_ERROR);
    EXPECT_EQ(taskInfo.detailCode, ProcessNotifier::MakeDetailCode(SyncStage::GENERAL,
        DetailCode::CLOUD_HEARTBEAT_BLOCKED));
    EXPECT_EQ(taskInfo.errorMessage, ProcessNotifier::GetDetailMsg(DetailCode::CLOUD_HEARTBEAT_BLOCKED));

    // 2. failing heartbeats only fail the task on the second consecutive failure
    TaskId retryTaskId = 21u;
    cloudSyncer->InitCloudSyncer(retryTaskId, SyncMode::SYNC_MODE_CLOUD_MERGE);
    cloudSyncer->InitHeartbeatCounters(retryTaskId);
    cloudSyncer->SetHeartbeatCount(retryTaskId, 2);
    cloudSyncer->CallExecuteHeartBeatTask(retryTaskId);
    EXPECT_EQ(cloudSyncer->GetTaskInfo(retryTaskId).errCode, E_OK);
    cloudSyncer->CallExecuteHeartBeatTask(retryTaskId);
    taskInfo = cloudSyncer->GetTaskInfo(retryTaskId);
    EXPECT_EQ(taskInfo.errCode, -E_CLOUD_ERROR);
    EXPECT_EQ(taskInfo.detailCode, ProcessNotifier::MakeDetailCode(SyncStage::GENERAL,
        DetailCode::CLOUD_HEARTBEAT_FAILED));
    EXPECT_EQ(taskInfo.errorMessage, ProcessNotifier::GetDetailMsg(DetailCode::CLOUD_HEARTBEAT_FAILED));

    DestroySyncer(cloudSyncer, storageProxy, iCloud);
    idb = nullptr;
}

/**
 * @tc.name: CloudSyncerErrorDetailCheck020
 * @tc.desc: Test the upload flow reports the no-abort local asset missing temp error end to end
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: ztx
 */
HWTEST_F(DistributedDBCloudSyncerErrorDetailTest, CloudSyncerErrorDetailCheck020, TestSize.Level1)
{
    MockICloudSyncStorageInterface *iCloud = new MockICloudSyncStorageInterface();
    std::shared_ptr<TestStorageProxy> storageProxy = std::make_shared<TestStorageProxy>(iCloud);
    ErrorDetailTestCloudSyncer *cloudSyncer = new(std::nothrow) ErrorDetailTestCloudSyncer(storageProxy);
    ASSERT_NE(cloudSyncer, nullptr);
    std::shared_ptr<MockICloudDB> idb = std::make_shared<MockICloudDB>();
    cloudSyncer->SetMockICloudDB(idb);
    ErrorDetailCommonExpectCall(iCloud);

    TaskId taskId = 21u;
    cloudSyncer->InitCloudSyncer(taskId, SyncMode::SYNC_MODE_CLOUD_MERGE);
    cloudSyncer->UpdateTaskInfo(taskId, [](CloudTaskInfo &taskInfo) {
        taskInfo.lockAction = LockAction::NONE; // keep the no-abort flow away from the cloud lock
    });
    // the insert records are marked as local asset missing, the batch call itself still succeeds;
    // the per-record marks come back through the extend out parameter of the cloud batch call
    CloudSyncData uploadData(cloudSyncer->GetCurrentContextTableName());
    cloudSyncer->initFullCloudSyncData(uploadData, 1);
    ExpectUploadWaters(iCloud, uploadData);
    ExpectAssetMissingMarkedInserts(idb);

    // 1. the marked batch does not abort the flow, the mark becomes the temp error with the composed
    // detail; the mid-batch notify consumes the soft errCode, it is backfilled from the temp code
    // when the task finishes. This case drives DoUploadInNeed directly (no machine entry), so the
    // write point stamps the default GENERAL stage (a no-op) and the export stamps the UPLOAD stage
    // for the stage-less code — both stage expectations hold as they are
    EXPECT_EQ(cloudSyncer->CallDoUpload(taskId, false, LockAction::NONE), E_OK);
    CloudTaskInfo taskInfo = cloudSyncer->GetTaskInfo(taskId);
    EXPECT_EQ(taskInfo.errCode, E_OK);
    EXPECT_EQ(taskInfo.tempErrCode, -E_LOCAL_ASSET_NOT_FOUND);
    EXPECT_EQ(taskInfo.detailCode, ProcessNotifier::MakeDetailCode(SyncStage::GENERAL,
        DetailCode::CLOUD_LOCAL_ASSET_NOT_FOUND));
    EXPECT_EQ(taskInfo.errorMessage, ProcessNotifier::GetDetailMsg(DetailCode::CLOUD_LOCAL_ASSET_NOT_FOUND));

    // 2. the final report backfills the errCode from the temp code, same as the endgame, and stamps
    // the upload stage on the composed detail
    cloudSyncer->CallSetCurrentStage(SyncStage::UPLOAD);
    SyncProcessCapture capture;
    SetCaptureCallback(cloudSyncer, taskId, capture);
    cloudSyncer->UpdateTaskInfo(taskId, [](CloudTaskInfo &info) {
        if (info.errCode == E_OK) {
            info.errCode = info.tempErrCode; // same backfill as the endgame
        }
        info.status = FINISHED;
    });
    taskInfo = cloudSyncer->GetTaskInfo(taskId);
    auto notifier = cloudSyncer->GetCurrentNotifier();
    ASSERT_NE(notifier, nullptr);
    notifier->NotifyProcess(taskInfo, {}, true);
    EXPECT_TRUE(capture.WaitFor([](const SyncProcess &process, uint32_t count) {
        return count > 0 && process.cloudErrorInfo.detailCode ==
            ProcessNotifier::MakeDetailCode(SyncStage::UPLOAD, DetailCode::CLOUD_LOCAL_ASSET_NOT_FOUND);
    }));
    SyncProcess res = capture.GetLastProcess();
    EXPECT_EQ(res.errCode, DBStatus::LOCAL_ASSET_NOT_FOUND);
    EXPECT_EQ(res.cloudErrorInfo.errorMessage, ProcessNotifier::GetDetailMsg(DetailCode::CLOUD_LOCAL_ASSET_NOT_FOUND));

    DestroySyncer(cloudSyncer, storageProxy, iCloud);
    idb = nullptr;
}

/**
 * @tc.name: CloudSyncerErrorDetailCheck022
 * @tc.desc: Test the download machine reports the detail after the expired cursor retries run out
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: ztx
 */
HWTEST_F(DistributedDBCloudSyncerErrorDetailTest, CloudSyncerErrorDetailCheck022, TestSize.Level1)
{
    MockICloudSyncStorageInterface *iCloud = new MockICloudSyncStorageInterface();
    std::shared_ptr<TestStorageProxy> storageProxy = std::make_shared<TestStorageProxy>(iCloud);
    ErrorDetailTestCloudSyncer *cloudSyncer = new(std::nothrow) ErrorDetailTestCloudSyncer(storageProxy);
    ASSERT_NE(cloudSyncer, nullptr);
    std::shared_ptr<MockICloudDB> idb = std::make_shared<MockICloudDB>();
    cloudSyncer->SetMockICloudDB(idb);
    ErrorDetailCommonExpectCall(iCloud);

    TaskId taskId = 23u;
    cloudSyncer->InitCloudSyncer(taskId, SyncMode::SYNC_MODE_CLOUD_MERGE);
    // every cloud query keeps reporting an expired cursor so the retry count is exhausted; the
    // cloud always has updates so the query is reached, and the other calls of the retry chain
    // succeed with the default mock values
    EXPECT_CALL(*idb, HasCloudUpdate(_, _)).WillRepeatedly(Return(true));
    EXPECT_CALL(*idb, GetEmptyCursor(_))
        .WillRepeatedly(Return(std::make_pair(static_cast<DBStatus>(OK), std::string("savedCursor"))));
    EXPECT_CALL(*idb, Query(_, _, _))
        .WillRepeatedly([](const std::string &, VBucket &, std::vector<VBucket> &data) {
            data = {}; // the failure is decided by the returned status
            return EXPIRED_CURSOR;
        });
    SyncProcessCapture capture;
    cloudSyncer->SetTaskCallback(taskId, [&capture](const std::map<std::string, SyncProcess> &process) {
        capture.Notify(process);
    });

    // 1. the machine marks the task failed with the composed detail of the exhausted retries,
    // stamped with the download stage at the write point (the machine entry set the stage)
    EXPECT_EQ(cloudSyncer->SyncMachineDoDownload(), CloudSyncEvent::ERROR_EVENT);
    CloudTaskInfo taskInfo = cloudSyncer->GetTaskInfo(taskId);
    EXPECT_EQ(taskInfo.errCode, -E_EXPIRED_CURSOR);
    EXPECT_EQ(taskInfo.detailCode, ProcessNotifier::MakeDetailCode(SyncStage::DOWNLOAD,
        DetailCode::CLOUD_EXPIRED_CURSOR));
    EXPECT_EQ(taskInfo.errorMessage, ProcessNotifier::GetDetailMsg(DetailCode::CLOUD_EXPIRED_CURSOR));

    // 2. the final report keeps the download stage stamped at the write point, the export does
    // not stamp an already stamped code again
    cloudSyncer->UpdateTaskInfo(taskId, [](CloudTaskInfo &info) { info.status = FINISHED; });
    taskInfo = cloudSyncer->GetTaskInfo(taskId);
    auto notifier = cloudSyncer->GetCurrentNotifier();
    ASSERT_NE(notifier, nullptr);
    notifier->NotifyProcess(taskInfo, {}, true);
    EXPECT_TRUE(capture.WaitFor([](const SyncProcess &process, uint32_t count) {
        return count > 0 && process.cloudErrorInfo.detailCode ==
            ProcessNotifier::MakeDetailCode(SyncStage::DOWNLOAD, DetailCode::CLOUD_EXPIRED_CURSOR);
    }));
    SyncProcess res = capture.GetLastProcess();
    EXPECT_EQ(res.errCode, DBStatus::EXPIRED_CURSOR);
    EXPECT_EQ(res.cloudErrorInfo.errorMessage, ProcessNotifier::GetDetailMsg(DetailCode::CLOUD_EXPIRED_CURSOR));

    DestroySyncer(cloudSyncer, storageProxy, iCloud);
    idb = nullptr;
}

/**
 * @tc.name: CloudSyncerErrorDetailCheck023
 * @tc.desc: Test the merged task reports the task merged detail to its own caller
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: ztx
 */
HWTEST_F(DistributedDBCloudSyncerErrorDetailTest, CloudSyncerErrorDetailCheck023, TestSize.Level1)
{
    MockICloudSyncStorageInterface *iCloud = new MockICloudSyncStorageInterface();
    std::shared_ptr<TestStorageProxy> storageProxy = std::make_shared<TestStorageProxy>(iCloud);
    ErrorDetailTestCloudSyncer *cloudSyncer = new(std::nothrow) ErrorDetailTestCloudSyncer(storageProxy);
    ASSERT_NE(cloudSyncer, nullptr);
    // the merge path adjusts the surviving task tables against the schema, a real schema is required
    auto cloudSchema = std::make_shared<DataBaseSchema>();
    TableSchema tableSchema;
    tableSchema.name = "MergeTable";
    cloudSchema->tables.push_back(tableSchema);
    EXPECT_CALL(*iCloud, GetCloudDbSchema()).WillRepeatedly(Return(cloudSchema));

    SyncProcessCapture firstCapture;
    SyncProcessCapture mergedCapture;

    // 1. queue the first mergeable task
    CloudTaskInfo firstInfo = cloudSyncer->SetAndGetCloudTaskInfo(SyncMode::SYNC_MODE_CLOUD_MERGE,
        { "MergeTable" }, [&firstCapture](const std::map<std::string, SyncProcess> &process) {
            firstCapture.Notify(process);
        }, 5000);
    firstInfo.merge = true;
    firstInfo.devices = { "cloud" };
    EXPECT_EQ(cloudSyncer->CallTryToAddSyncTask(std::move(firstInfo)), E_OK);

    // 2. the just-added task is merged into the queued one, its caller is notified with the merged detail
    CloudTaskInfo secondInfo = cloudSyncer->SetAndGetCloudTaskInfo(SyncMode::SYNC_MODE_CLOUD_MERGE,
        { "MergeTable" }, [&mergedCapture](const std::map<std::string, SyncProcess> &process) {
            mergedCapture.Notify(process);
        }, 5000);
    secondInfo.merge = true;
    secondInfo.devices = { "cloud" };
    EXPECT_EQ(cloudSyncer->CallTryToAddSyncTask(std::move(secondInfo)), E_OK);

    EXPECT_TRUE(mergedCapture.WaitFor([](const SyncProcess &process, uint32_t count) {
        return count > 0 && process.cloudErrorInfo.detailCode ==
            ProcessNotifier::MakeDetailCode(SyncStage::GENERAL, DetailCode::CLOUD_SYNC_TASK_MERGED);
    }));
    SyncProcess res = mergedCapture.GetLastProcess();
    EXPECT_EQ(res.process, FINISHED);
    EXPECT_EQ(res.errCode, DBStatus::CLOUD_SYNC_TASK_MERGED);
    EXPECT_EQ(res.cloudErrorInfo.errorMessage,
        ProcessNotifier::GetDetailMsg(DetailCode::CLOUD_SYNC_TASK_MERGED));

    // the surviving task is untouched by the merge report, its caller hears nothing
    EXPECT_EQ(firstCapture.GetNotifyCount(), 0u);

    DestroySyncer(cloudSyncer, storageProxy, iCloud);
}

/**
 * @tc.name: CloudSyncerErrorDetailCheck024
 * @tc.desc: Test a later hard failure overwrites the whole triple of the earlier soft error
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: ztx
 */
HWTEST_F(DistributedDBCloudSyncerErrorDetailTest, CloudSyncerErrorDetailCheck024, TestSize.Level1)
{
    MockICloudSyncStorageInterface *iCloud = new MockICloudSyncStorageInterface();
    std::shared_ptr<TestStorageProxy> storageProxy = std::make_shared<TestStorageProxy>(iCloud);
    ErrorDetailTestCloudSyncer *cloudSyncer = new(std::nothrow) ErrorDetailTestCloudSyncer(storageProxy);
    ASSERT_NE(cloudSyncer, nullptr);
    std::shared_ptr<MockICloudDB> idb = std::make_shared<MockICloudDB>();
    cloudSyncer->SetMockICloudDB(idb);
    ErrorDetailCommonExpectCall(iCloud);

    TaskId taskId = 24u;
    cloudSyncer->InitCloudSyncer(taskId, SyncMode::SYNC_MODE_CLOUD_MERGE);
    cloudSyncer->SetNeedRealUpload();
    cloudSyncer->UpdateTaskInfo(taskId, [](CloudTaskInfo &taskInfo) {
        taskInfo.lockAction = LockAction::NONE; // the water order keeps the failure away from the lock
    });
    // the first batch succeeds so the soft temp error is recorded, the second batch fails hard
    CloudSyncData uploadData(cloudSyncer->GetCurrentContextTableName());
    cloudSyncer->initFullCloudSyncData(uploadData, 1);
    for (auto &extend : uploadData.insData.extend) {
        extend[CloudDbConstant::ERROR_FIELD] = static_cast<int64_t>(DBStatus::LOCAL_ASSET_NOT_FOUND);
    }
    ExpectHardFailureAfterSoftUpload(iCloud, idb, uploadData);
    SyncProcessCapture capture;
    cloudSyncer->SetTaskCallback(taskId, [&capture](const std::map<std::string, SyncProcess> &process) {
        capture.Notify(process);
    });

    // 1. the hard failure overwrites the whole triple, the report no longer describes the soft
    //    error; the UPLOAD stage is stamped in place where the failure happens
    EXPECT_EQ(cloudSyncer->SyncMachineDoUpload(), CloudSyncEvent::ERROR_EVENT);
    CloudTaskInfo taskInfo = cloudSyncer->GetTaskInfo(taskId);
    EXPECT_EQ(taskInfo.errCode, -E_CLOUD_ERROR);
    EXPECT_EQ(taskInfo.detailCode,
        ProcessNotifier::MakeDetailCode(SyncStage::UPLOAD, DetailCode::CLOUD_ERROR));
    EXPECT_EQ(taskInfo.errorMessage, ProcessNotifier::GetDetailMsg(DetailCode::CLOUD_ERROR));
    // the soft error stays visible as the temp code for the endgame backfill
    EXPECT_EQ(taskInfo.tempErrCode, -E_LOCAL_ASSET_NOT_FOUND);

    // 2. the final report carries the hard failure detail, same source as the reported errCode
    cloudSyncer->UpdateTaskInfo(taskId, [](CloudTaskInfo &info) { info.status = FINISHED; });
    taskInfo = cloudSyncer->GetTaskInfo(taskId);
    auto notifier = cloudSyncer->GetCurrentNotifier();
    ASSERT_NE(notifier, nullptr);
    notifier->NotifyProcess(taskInfo, {}, true);
    EXPECT_TRUE(capture.WaitFor([](const SyncProcess &process, uint32_t count) {
        return count > 0 && process.cloudErrorInfo.detailCode ==
            ProcessNotifier::MakeDetailCode(SyncStage::UPLOAD, DetailCode::CLOUD_ERROR);
    }));
    SyncProcess res = capture.GetLastProcess();
    EXPECT_EQ(res.errCode, DBStatus::CLOUD_ERROR);
    EXPECT_EQ(res.cloudErrorInfo.errorMessage, ProcessNotifier::GetDetailMsg(DetailCode::CLOUD_ERROR));

    DestroySyncer(cloudSyncer, storageProxy, iCloud);
    idb = nullptr;
}

/**
 * @tc.name: CloudSyncerErrorDetailCheck025
 * @tc.desc: Test the failing unlock overwrites the task error with the adapter external detail
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: ztx
 */
HWTEST_F(DistributedDBCloudSyncerErrorDetailTest, CloudSyncerErrorDetailCheck025, TestSize.Level1)
{
    MockICloudSyncStorageInterface *iCloud = new MockICloudSyncStorageInterface();
    std::shared_ptr<TestStorageProxy> storageProxy = std::make_shared<TestStorageProxy>(iCloud);
    ErrorDetailTestCloudSyncer *cloudSyncer = new(std::nothrow) ErrorDetailTestCloudSyncer(storageProxy);
    ASSERT_NE(cloudSyncer, nullptr);
    // the unlock failure must carry the external detail provided by the cloud adapter
    std::shared_ptr<MockICloudDB> idb = std::make_shared<ExternalDetailCloudDb>(0x254321u, "unlock failed");
    cloudSyncer->SetMockICloudDB(idb);
    ErrorDetailCommonExpectCall(iCloud);
    EXPECT_CALL(*idb, Lock()).WillRepeatedly(Return(std::make_pair(static_cast<DBStatus>(OK), 300000u)));
    EXPECT_CALL(*idb, UnLock()).WillRepeatedly(Return(DBStatus::CLOUD_ERROR));

    TaskId taskId = 25u;
    cloudSyncer->InitCloudSyncer(taskId, SyncMode::SYNC_MODE_CLOUD_MERGE);
    SyncProcessCapture capture;
    cloudSyncer->SetTaskCallback(taskId, [&capture](const std::map<std::string, SyncProcess> &process) {
        capture.Notify(process);
    });

    // 1. the cloud is locked for the task and an internal failure is recorded first
    EXPECT_EQ(cloudSyncer->CallLockCloudIfNeed(taskId), E_OK);
    cloudSyncer->CallSetCurrentTaskFailedWithoutLock(-E_CLOUD_ERROR);
    CloudTaskInfo taskInfo = cloudSyncer->GetTaskInfo(taskId);
    EXPECT_EQ(taskInfo.errCode, -E_CLOUD_ERROR);
    EXPECT_EQ(taskInfo.detailCode,
        ProcessNotifier::MakeDetailCode(SyncStage::GENERAL, DetailCode::CLOUD_ERROR));

    // 2. the failing unlock overwrites the whole triple with its external detail, same source as the errCode
    cloudSyncer->CallUnlockIfNeed();
    taskInfo = cloudSyncer->GetTaskInfo(taskId);
    EXPECT_EQ(taskInfo.errCode, -E_CLOUD_ERROR);
    EXPECT_EQ(taskInfo.detailCode, 0x254321u);
    EXPECT_EQ(taskInfo.errorMessage, "unlock failed");

    // 3. the external detail reaches the user callback unchanged
    cloudSyncer->UpdateTaskInfo(taskId, [](CloudTaskInfo &info) { info.status = FINISHED; });
    taskInfo = cloudSyncer->GetTaskInfo(taskId);
    auto notifier = cloudSyncer->GetCurrentNotifier();
    ASSERT_NE(notifier, nullptr);
    notifier->NotifyProcess(taskInfo, {}, true);
    EXPECT_TRUE(capture.WaitFor([](const SyncProcess &process, uint32_t count) {
        return count > 0 && process.cloudErrorInfo.detailCode == 0x254321u;
    }));
    SyncProcess res = capture.GetLastProcess();
    EXPECT_EQ(res.errCode, DBStatus::CLOUD_ERROR);
    EXPECT_EQ(res.cloudErrorInfo.errorMessage, "unlock failed");

    DestroySyncer(cloudSyncer, storageProxy, iCloud);
    idb = nullptr;
}

/**
 * @tc.name: CloudSyncerErrorDetailCheck026
 * @tc.desc: Test the final report merge rule of the task detail and the accumulated detail
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: ztx
 */
HWTEST_F(DistributedDBCloudSyncerErrorDetailTest, CloudSyncerErrorDetailCheck026, TestSize.Level1)
{
    MockICloudSyncStorageInterface *iCloud = new MockICloudSyncStorageInterface();
    std::shared_ptr<TestStorageProxy> storageProxy = std::make_shared<TestStorageProxy>(iCloud);
    ErrorDetailTestCloudSyncer *cloudSyncer = new(std::nothrow) ErrorDetailTestCloudSyncer(storageProxy);
    ASSERT_NE(cloudSyncer, nullptr);
    TaskId taskId = 26u;
    cloudSyncer->InitCloudSyncer(taskId, SyncMode::SYNC_MODE_CLOUD_MERGE);
    auto notifier = cloudSyncer->GetCurrentNotifier();
    ASSERT_NE(notifier, nullptr);
    SyncProcessCapture capture;
    cloudSyncer->SetTaskCallback(taskId, [&capture](const std::map<std::string, SyncProcess> &process) {
        capture.Notify(process);
    });
    std::string tableName = cloudSyncer->GetCurrentContextTableName();

    // 1. the latest external task detail overwrites the accumulated external detail
    InnerProcessInfo info;
    info.tableName = tableName;
    info.innerCloudErrorInfo.detailCode = 0x123456u;
    info.innerCloudErrorInfo.errorMessage = "first external";
    SyncProcess res = RunFinalDetailBranch(cloudSyncer, notifier, capture, taskId, info, -E_CLOUD_ERROR,
        0x254321u, "second external", 1, 0x254321u, "second external");
    // an ok final result resets the accumulated detail for the next branch
    ResetTaskDetail(cloudSyncer, notifier, capture, taskId, 2);

    // 2. the accumulated external detail suppresses the internal composition of the same failure
    res = RunFinalDetailBranch(cloudSyncer, notifier, capture, taskId, info, -E_CLOUD_ERROR,
        ProcessNotifier::MakeDetailCode(SyncStage::GENERAL, DetailCode::CLOUD_ERROR),
        ProcessNotifier::GetDetailMsg(DetailCode::CLOUD_ERROR), 3, 0x123456u, "first external");
    // reset again for the last branch
    ResetTaskDetail(cloudSyncer, notifier, capture, taskId, 4);

    // 3. the latest internal task detail overwrites the accumulated internal detail
    InnerProcessInfo internalInfo;
    internalInfo.tableName = tableName;
    internalInfo.innerCloudErrorInfo.detailCode =
        ProcessNotifier::MakeDetailCode(SyncStage::UPLOAD, DetailCode::CLOUD_ERROR);
    internalInfo.innerCloudErrorInfo.errorMessage = "accumulated internal";
    res = RunFinalDetailBranch(cloudSyncer, notifier, capture, taskId, internalInfo, -E_CLOUD_VERSION_CONFLICT,
        ProcessNotifier::MakeDetailCode(SyncStage::GENERAL, DetailCode::CLOUD_VERSION_CONFLICT),
        ProcessNotifier::GetDetailMsg(DetailCode::CLOUD_VERSION_CONFLICT), 5,
        ProcessNotifier::MakeDetailCode(SyncStage::GENERAL, DetailCode::CLOUD_VERSION_CONFLICT),
        ProcessNotifier::GetDetailMsg(DetailCode::CLOUD_VERSION_CONFLICT));
    EXPECT_EQ(res.errCode, DBStatus::CLOUD_VERSION_CONFLICT);

    DestroySyncer(cloudSyncer, storageProxy, iCloud);
}

/**
 * @tc.name: CloudSyncerErrorDetailCheck027
 * @tc.desc: Test the real finished handler keeps the download stage in the terminal detail
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: ztx
 */
HWTEST_F(DistributedDBCloudSyncerErrorDetailTest, CloudSyncerErrorDetailCheck027, TestSize.Level1)
{
    MockICloudSyncStorageInterface *iCloud = new MockICloudSyncStorageInterface();
    std::shared_ptr<TestStorageProxy> storageProxy = std::make_shared<TestStorageProxy>(iCloud);
    ErrorDetailTestCloudSyncer *cloudSyncer = new(std::nothrow) ErrorDetailTestCloudSyncer(storageProxy);
    ASSERT_NE(cloudSyncer, nullptr);
    std::shared_ptr<MockICloudDB> idb = std::make_shared<MockICloudDB>();
    cloudSyncer->SetMockICloudDB(idb);
    ErrorDetailCommonExpectCall(iCloud);

    TaskId taskId = 27u;
    cloudSyncer->InitCloudSyncer(taskId, SyncMode::SYNC_MODE_CLOUD_MERGE);
    // the first cloud query keeps reporting a hard cloud error so the download aborts; the cloud
    // always has updates so the query is reached, the other retry-chain calls use the mock defaults
    EXPECT_CALL(*idb, HasCloudUpdate(_, _)).WillRepeatedly(Return(true));
    EXPECT_CALL(*idb, GetEmptyCursor(_))
        .WillRepeatedly(Return(std::make_pair(static_cast<DBStatus>(OK), std::string("savedCursor"))));
    EXPECT_CALL(*idb, Query(_, _, _))
        .WillRepeatedly([](const std::string &, VBucket &, std::vector<VBucket> &data) {
            data = {}; // the failure is decided by the returned status
            return DBStatus::CLOUD_ERROR;
        });
    // skip the compensated sync generated after a cloud failure, it would queue a background task
    CloudSyncConfig config;
    config.skipDownloadAssets = true;
    EXPECT_CALL(*iCloud, GetCloudSyncConfig()).WillRepeatedly(Return(config));
    SyncProcessCapture capture;
    cloudSyncer->SetTaskCallback(taskId, [&capture](const std::map<std::string, SyncProcess> &process) {
        capture.Notify(process);
    });

    // 1. the download machine aborts on the hard error, the failure is stamped with the
    //    DOWNLOAD stage in place instead of depositing an unstamped draft
    EXPECT_EQ(cloudSyncer->SyncMachineDoDownload(), CloudSyncEvent::ERROR_EVENT);
    CloudTaskInfo taskInfo = cloudSyncer->GetTaskInfo(taskId);
    EXPECT_EQ(taskInfo.errCode, -E_CLOUD_ERROR);
    EXPECT_EQ(taskInfo.detailCode, ProcessNotifier::MakeDetailCode(SyncStage::DOWNLOAD,
        DetailCode::CLOUD_ERROR));
    EXPECT_EQ(taskInfo.errorMessage, ProcessNotifier::GetDetailMsg(DetailCode::CLOUD_ERROR));

    // 2. the real finished handler exports the terminal report through the notifier, the stage
    // the machine maintained must survive until the export instead of being reset to GENERAL
    EXPECT_EQ(cloudSyncer->SyncMachineDoFinished(), CloudSyncEvent::ALL_TASK_FINISHED_EVENT);
    EXPECT_TRUE(capture.WaitFor([](const SyncProcess &process, uint32_t count) {
        return count > 0 && process.cloudErrorInfo.detailCode ==
            ProcessNotifier::MakeDetailCode(SyncStage::DOWNLOAD, DetailCode::CLOUD_ERROR);
    }));
    SyncProcess res = capture.GetLastProcess();
    EXPECT_EQ(res.process, FINISHED);
    EXPECT_EQ(res.errCode, DBStatus::CLOUD_ERROR);
    EXPECT_EQ(res.cloudErrorInfo.errorMessage, ProcessNotifier::GetDetailMsg(DetailCode::CLOUD_ERROR));

    DestroySyncer(cloudSyncer, storageProxy, iCloud);
    idb = nullptr;
}

/**
 * @tc.name: CloudSyncerErrorDetailCheck029
 * @tc.desc: Test the heartbeat blocked failure keeps its download stage against the machine echo
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: ztx
 */
HWTEST_F(DistributedDBCloudSyncerErrorDetailTest, CloudSyncerErrorDetailCheck029, TestSize.Level1)
{
    MockICloudSyncStorageInterface *iCloud = new MockICloudSyncStorageInterface();
    std::shared_ptr<TestStorageProxy> storageProxy = std::make_shared<TestStorageProxy>(iCloud);
    ErrorDetailTestCloudSyncer *cloudSyncer = new(std::nothrow) ErrorDetailTestCloudSyncer(storageProxy);
    ASSERT_NE(cloudSyncer, nullptr);
    TaskId taskId = 29u;
    cloudSyncer->InitCloudSyncer(taskId, SyncMode::SYNC_MODE_CLOUD_MERGE);

    // 1. the heartbeat blocks the task during the download stage, the failure write stamps the
    //    DOWNLOAD stage in place, the same call shape as ExecuteHeartBeatTask
    cloudSyncer->CallSetCurrentStage(SyncStage::DOWNLOAD);
    cloudSyncer->CallSetTaskFailed(taskId, -E_CLOUD_ERROR, "",
        ProcessNotifier::MakeDetailCode(SyncStage::GENERAL, DetailCode::CLOUD_HEARTBEAT_BLOCKED));
    CloudTaskInfo taskInfo = cloudSyncer->GetTaskInfo(taskId);
    EXPECT_EQ(taskInfo.errCode, -E_CLOUD_ERROR);
    EXPECT_EQ(taskInfo.detailCode, ProcessNotifier::MakeDetailCode(SyncStage::DOWNLOAD,
        DetailCode::CLOUD_HEARTBEAT_BLOCKED));
    EXPECT_EQ(taskInfo.errorMessage, ProcessNotifier::GetDetailMsg(DetailCode::CLOUD_HEARTBEAT_BLOCKED));

    // 2. the machine walks into the upload stage and the preprocess echoes the same bare errno,
    //    the echo must neither erase the heartbeat detail nor drift its stamped stage
    cloudSyncer->CallSetCurrentStage(SyncStage::UPLOAD);
    cloudSyncer->CallSetCurrentTaskFailedWithoutLock(-E_CLOUD_ERROR);
    taskInfo = cloudSyncer->GetTaskInfo(taskId);
    EXPECT_EQ(taskInfo.errCode, -E_CLOUD_ERROR);
    EXPECT_EQ(taskInfo.detailCode, ProcessNotifier::MakeDetailCode(SyncStage::DOWNLOAD,
        DetailCode::CLOUD_HEARTBEAT_BLOCKED));
    EXPECT_EQ(taskInfo.errorMessage, ProcessNotifier::GetDetailMsg(DetailCode::CLOUD_HEARTBEAT_BLOCKED));

    // 3. the final report exports the heartbeat detail as is, the upload stage reached later
    //    must not restamp it
    SyncProcessCapture capture;
    cloudSyncer->SetTaskCallback(taskId, [&capture](const std::map<std::string, SyncProcess> &process) {
        capture.Notify(process);
    });
    cloudSyncer->UpdateTaskInfo(taskId, [](CloudTaskInfo &info) { info.status = FINISHED; });
    taskInfo = cloudSyncer->GetTaskInfo(taskId);
    auto notifier = cloudSyncer->GetCurrentNotifier();
    ASSERT_NE(notifier, nullptr);
    notifier->NotifyProcess(taskInfo, {}, true);
    EXPECT_TRUE(capture.WaitFor([](const SyncProcess &process, uint32_t count) {
        return count > 0 && process.cloudErrorInfo.detailCode ==
            ProcessNotifier::MakeDetailCode(SyncStage::DOWNLOAD, DetailCode::CLOUD_HEARTBEAT_BLOCKED);
    }));
    SyncProcess res = capture.GetLastProcess();
    EXPECT_EQ(res.errCode, DBStatus::CLOUD_ERROR);
    EXPECT_EQ(res.cloudErrorInfo.errorMessage, ProcessNotifier::GetDetailMsg(DetailCode::CLOUD_HEARTBEAT_BLOCKED));

    DestroySyncer(cloudSyncer, storageProxy, iCloud);
}

/**
 * @tc.name: CloudSyncerErrorDetailCheck031
 * @tc.desc: Test the external stage enrichment: the stamp unit assertions and the real
 *           export path carrying the stamped code with the message untouched
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: ztx
 */
HWTEST_F(DistributedDBCloudSyncerErrorDetailTest, CloudSyncerErrorDetailCheck031, TestSize.Level1)
{
    MockICloudSyncStorageInterface *iCloud = new MockICloudSyncStorageInterface();
    std::shared_ptr<TestStorageProxy> storageProxy = std::make_shared<TestStorageProxy>(iCloud);
    ErrorDetailTestCloudSyncer *cloudSyncer = new(std::nothrow) ErrorDetailTestCloudSyncer(storageProxy);
    ASSERT_NE(cloudSyncer, nullptr);
    TaskId taskId = 31u;
    cloudSyncer->InitCloudSyncer(taskId, SyncMode::SYNC_MODE_CLOUD_MERGE);
    auto notifier = cloudSyncer->GetCurrentNotifier();
    ASSERT_NE(notifier, nullptr);
    cloudSyncer->CallSetCurrentStage(SyncStage::UPLOAD);

    // 1. an external code with empty stage bits gets the maintained stage or-ed in
    //    (0x2B: stage field 0; UPLOAD << 16 = 0x20000)
    EXPECT_EQ(notifier->StampStage(0x2Bu), 0x2002Bu);
    // 2. an external number occupying the stage bits (DBStatus DB_ERROR 27328512 =
    //    0x1A10000, stage field 0x21) passes through untouched
    EXPECT_EQ(notifier->StampStage(27328512u), 27328512u);
    // 3. zero means "no detail" and must never be stamped into existence
    EXPECT_EQ(notifier->StampStage(0u), 0u);
    // 4. collision pin: an enriched stage-less code and a native code already occupying
    //    those bits meet at the same exported value — inherent to the layout and documented
    //    in the CloudErrorInfo.detailCode consumer contract; kept explicit against silent drift
    EXPECT_EQ(notifier->StampStage(0x2Bu), notifier->StampStage(0x2002Bu));

    // 5. end to end over the real export path: a single user task fails in the upload stage
    //    with a stage-less adapter code, the export stamps it (0x2B | UPLOAD<<16 = 0x2002B)
    //    while the adapter message and the errCode stay untouched; FINISHED is covered by Check027
    SyncProcessCapture capture;
    cloudSyncer->SetTaskCallback(taskId, [&capture](const std::map<std::string, SyncProcess> &process) {
        capture.Notify(process);
    });
    cloudSyncer->UpdateTaskInfo(taskId, [](CloudTaskInfo &taskInfo) {
        taskInfo.users = { "userA" }; // single user: the finish takes the endgame export branch
    });
    cloudSyncer->CallSetTaskFailed(taskId, -E_CLOUD_ERROR, "adapter cloud failure", 0x2Bu);
    EXPECT_EQ(cloudSyncer->CallSyncMachineDoFinished(), CloudSyncEvent::ALL_TASK_FINISHED_EVENT);
    EXPECT_TRUE(capture.WaitFor([](const SyncProcess &process, uint32_t count) {
        return count > 0 && process.errCode == DBStatus::CLOUD_ERROR &&
            process.cloudErrorInfo.detailCode == 0x2002Bu;
    }));
    EXPECT_EQ(capture.GetLastProcess().cloudErrorInfo.errorMessage, "adapter cloud failure");

    DestroySyncer(cloudSyncer, storageProxy, iCloud);
}

/**
 * @tc.name: CloudSyncerErrorDetailCheck033
 * @tc.desc: Test the stopped message carries the stop source marker and NONE keeps the base text
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: ztx
 */
HWTEST_F(DistributedDBCloudSyncerErrorDetailTest, CloudSyncerErrorDetailCheck033, TestSize.Level1)
{
    // 1. the unlabelled message stays byte-identical, every labelled source appends its marker
    using Source = ProcessNotifier::StopSource;
    const std::string base = ProcessNotifier::GetDetailMsg(DetailCode::CLOUD_SYSTEM_EVENT_STOPPED);
    EXPECT_EQ(ProcessNotifier::GetStoppedMessage(Source::NONE), base);
    EXPECT_EQ(ProcessNotifier::GetStoppedMessage(Source::REMOVE_DEVICE_DATA), base + " (stopped by RemoveDeviceData)");
    EXPECT_EQ(ProcessNotifier::GetStoppedMessage(Source::STOP_TASK), base + " (stopped by StopTask)");
    EXPECT_EQ(ProcessNotifier::GetStoppedMessage(Source::IMPORT), base + " (stopped by Import)");
    EXPECT_EQ(ProcessNotifier::GetStoppedMessage(Source::USER_CHANGE), base + " (stopped by UserChange)");
    EXPECT_EQ(ProcessNotifier::GetStoppedMessage(Source::TABLE_REFERENCE_CHANGED),
        base + " (stopped by TableReferenceChanged)");

    // 2. end to end: a labelled stop notifies the queued task with the marked message
    MockICloudSyncStorageInterface *iCloud = new MockICloudSyncStorageInterface();
    std::shared_ptr<TestStorageProxy> storageProxy = std::make_shared<TestStorageProxy>(iCloud);
    ErrorDetailTestCloudSyncer *cloudSyncer = new(std::nothrow) ErrorDetailTestCloudSyncer(storageProxy);
    ASSERT_NE(cloudSyncer, nullptr);
    TaskId taskId = 33u;
    cloudSyncer->InitCloudSyncer(taskId, SyncMode::SYNC_MODE_CLOUD_MERGE);
    SyncProcessCapture capture;
    cloudSyncer->SetTaskCallback(taskId, [&capture](const std::map<std::string, SyncProcess> &process) {
        capture.Notify(process);
    });
    cloudSyncer->SetTaskDevices(taskId, { "cloud" });
    // simulate that no task is currently running
    cloudSyncer->SetCurrentContext(0u);

    cloudSyncer->StopAllTasks(-E_CLOUD_ERROR, ProcessNotifier::StopSource::REMOVE_DEVICE_DATA);

    EXPECT_TRUE(capture.WaitFor([](const SyncProcess &process, uint32_t count) {
        return count > 0 && process.errCode == DBStatus::CLOUD_ERROR &&
            process.cloudErrorInfo.detailCode ==
            ProcessNotifier::MakeDetailCode(SyncStage::GENERAL, DetailCode::CLOUD_SYSTEM_EVENT_STOPPED);
    }));
    EXPECT_EQ(capture.GetLastProcess().cloudErrorInfo.errorMessage, base + " (stopped by RemoveDeviceData)");

    DestroySyncer(cloudSyncer, storageProxy, iCloud);
}

/**
 * @tc.name: CloudSyncerErrorDetailCheck034
 * @tc.desc: Test the running task stop carries the entry marker and its stage end to end
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: ztx
 */
HWTEST_F(DistributedDBCloudSyncerErrorDetailTest, CloudSyncerErrorDetailCheck034, TestSize.Level1)
{
    // the running-task leg is the primary stop scenario: the marked stop fails the current task
    // in place, the worker's finished handler exports the terminal report, and the stopped
    // detail keeps the UPLOAD stage the notifier maintained (unlike the queued leg's GENERAL)
    MockICloudSyncStorageInterface *iCloud = new MockICloudSyncStorageInterface();
    std::shared_ptr<TestStorageProxy> storageProxy = std::make_shared<TestStorageProxy>(iCloud);
    ErrorDetailTestCloudSyncer *cloudSyncer = new(std::nothrow) ErrorDetailTestCloudSyncer(storageProxy);
    ASSERT_NE(cloudSyncer, nullptr);
    TaskId taskId = 34u;
    cloudSyncer->InitCloudSyncer(taskId, SyncMode::SYNC_MODE_CLOUD_MERGE);
    // skip the compensated sync generated after a cloud failure, it would queue a background task
    CloudSyncConfig config;
    config.skipDownloadAssets = true;
    EXPECT_CALL(*iCloud, GetCloudSyncConfig()).WillRepeatedly(Return(config));
    SyncProcessCapture capture;
    cloudSyncer->SetTaskCallback(taskId, [&capture](const std::map<std::string, SyncProcess> &process) {
        capture.Notify(process);
    });
    cloudSyncer->SetTaskDevices(taskId, { "cloud" });
    // the task is already current (InitCloudSyncer set it); mimic the worker that finishes only
    // after the stop has been written, so StopAllTasks waits for this reset like the real flow
    cloudSyncer->CallSetCurrentStage(SyncStage::UPLOAD);
    std::thread taskWorker([&cloudSyncer, taskId]() {
        while (cloudSyncer->GetTaskInfo(taskId).errCode == E_OK) {
            std::this_thread::yield();
        }
        cloudSyncer->CallSyncMachineDoFinished();
    });

    cloudSyncer->StopAllTasks(-E_CLOUD_ERROR, ProcessNotifier::StopSource::REMOVE_DEVICE_DATA);
    taskWorker.join();

    EXPECT_TRUE(capture.WaitFor([](const SyncProcess &process, uint32_t count) {
        return count > 0 && process.errCode == DBStatus::CLOUD_ERROR &&
            process.cloudErrorInfo.detailCode ==
            ProcessNotifier::MakeDetailCode(SyncStage::UPLOAD, DetailCode::CLOUD_SYSTEM_EVENT_STOPPED);
    }));
    const std::string base = ProcessNotifier::GetDetailMsg(DetailCode::CLOUD_SYSTEM_EVENT_STOPPED);
    EXPECT_EQ(capture.GetLastProcess().cloudErrorInfo.errorMessage, base + " (stopped by RemoveDeviceData)");

    DestroySyncer(cloudSyncer, storageProxy, iCloud);
}

} // namespace
