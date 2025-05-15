/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "db_errno.h"
#include "db_common.h"
#include "distributeddb_data_generate_unit_test.h"
#include "lock_status_observer.h"
#include "log_print.h"
#include "platform_specific.h"
#include "task_queue.h"
#include "time_tick_monitor.h"
#include "user_change_monitor.h"
#include "runtime_context_impl.h"

using namespace testing::ext;
using namespace DistributedDB;
using namespace DistributedDBUnitTest;

namespace {
    std::string g_testDir;

    // define some variables to init a KvStoreDelegateManager object.
    KvStoreDelegateManager g_mgr(APP_ID, USER_ID);
    KvStoreConfig g_config;

    // define the g_kvDelegateCallback, used to get some information when open a kv store.
    DBStatus g_kvDelegateStatus = INVALID_ARGS;

    KvStoreNbDelegate *g_kvNbDelegatePtr = nullptr;
    auto g_kvNbDelegateCallback = bind(&DistributedDBToolsUnitTest::KvStoreNbDelegateCallback,
        std::placeholders::_1, std::placeholders::_2, std::ref(g_kvDelegateStatus), std::ref(g_kvNbDelegatePtr));

class DistributedDBCommonTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void DistributedDBCommonTest::SetUpTestCase(void)
{
    DistributedDBToolsUnitTest::TestDirInit(g_testDir);
    g_config.dataDir = g_testDir;
    g_mgr.SetKvStoreConfig(g_config);
}

void DistributedDBCommonTest::TearDownTestCase(void) {}

void DistributedDBCommonTest::SetUp(void)
{
    DistributedDBToolsUnitTest::PrintTestCaseInfo();
    DistributedDBToolsUnitTest::TestDirInit(g_testDir);
}

void DistributedDBCommonTest::TearDown(void)
{
    if (DistributedDBToolsUnitTest::RemoveTestDbFiles(g_testDir) != 0) {
        LOGI("rm test db files error!");
    }
}

/**
 * @tc.name: RemoveAllFilesOfDirectory
 * @tc.desc: Test delete all file and dir.
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: sunpeng
 */
HWTEST_F(DistributedDBCommonTest, RemoveAllFilesOfDirectory, TestSize.Level1)
{
    EXPECT_EQ(DBCommon::CreateDirectory(g_testDir + "/dirLevel1_1/"), E_OK);
    EXPECT_EQ(DBCommon::CreateDirectory(g_testDir + "/dirLevel1_1/" + "/dirLevel2_1/"), E_OK);
    EXPECT_EQ(DBCommon::CreateDirectory(g_testDir + "/dirLevel1_1/" + "/dirLevel2_2/"), E_OK);
    EXPECT_EQ(DBCommon::CreateDirectory(g_testDir + "/dirLevel1_1/" + "/dirLevel2_2/" + "/dirLevel3_1/"), E_OK);

    EXPECT_EQ(OS::CreateFileByFileName(g_testDir + "/fileLevel1_1"), E_OK);
    EXPECT_EQ(OS::CreateFileByFileName(g_testDir + "/dirLevel1_1/" + "/fileLevel2_1"), E_OK);
    EXPECT_EQ(DBCommon::CreateDirectory(g_testDir + "/dirLevel1_1/" + "/dirLevel2_2/" +
        "/dirLevel3_1/"+ "/fileLevel4_1/"), E_OK);

    EXPECT_EQ(DBCommon::RemoveAllFilesOfDirectory(g_testDir), E_OK);

    EXPECT_EQ(OS::CheckPathExistence(g_testDir), false);
}

#ifdef RUNNING_ON_LINUX
/**
 * @tc.name: InvalidArgsTest001
 * @tc.desc: Test invalid args for file operation.
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: zhangshijie
 */
HWTEST_F(DistributedDBCommonTest, InvalidArgsTest001, TestSize.Level1)
{
    EXPECT_EQ(OS::CloseFile(nullptr), -E_INVALID_ARGS);
    EXPECT_EQ(OS::FileLock(nullptr, false), -E_INVALID_ARGS);
    // unlock nullptr will return E_OK
    EXPECT_EQ(OS::FileUnlock(nullptr), E_OK);
}

/**
 * @tc.name: SameProcessReLockFile
 * @tc.desc: Test same process repeat lock same file.
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: sunpeng
 */
HWTEST_F(DistributedDBCommonTest, SameProcessReLockFile, TestSize.Level1)
{
    // block mode
    EXPECT_EQ(OS::CreateFileByFileName(g_testDir + "/blockmode"), E_OK);
    OS::FileHandle *fd = nullptr;
    EXPECT_EQ(OS::OpenFile(g_testDir + "/blockmode", fd), E_OK);

    EXPECT_EQ(OS::FileLock(fd, true), E_OK);
    EXPECT_EQ(OS::FileLock(fd, true), E_OK);

    // normal mode
    OS::FileHandle *fd2 = nullptr;
    EXPECT_EQ(OS::CreateFileByFileName(g_testDir + "/normalmode"), E_OK);
    EXPECT_EQ(OS::OpenFile(g_testDir + "/normalmode", fd2), E_OK);
    EXPECT_EQ(OS::FileLock(fd2, true), E_OK);
    EXPECT_EQ(OS::FileLock(fd2, true), E_OK);

    // unlock
    EXPECT_EQ(OS::FileUnlock(fd), E_OK);
    EXPECT_EQ(OS::CloseFile(fd), E_OK);
    EXPECT_EQ(OS::FileUnlock(fd2), E_OK);
    EXPECT_EQ(OS::CloseFile(fd2), E_OK);
}

/**
 * @tc.name: SameProcessReUnLockFile
 * @tc.desc: Test same process repeat lock same file.
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: sunpeng
 */
HWTEST_F(DistributedDBCommonTest, SameProcessReUnLockFile, TestSize.Level1)
{
    // unlock normal file twice
    EXPECT_EQ(OS::CreateFileByFileName(g_testDir + "/normalmode"), E_OK);
    OS::FileHandle *fd = nullptr;
    EXPECT_EQ(OS::OpenFile(g_testDir + "/normalmode", fd), E_OK);
    EXPECT_EQ(OS::FileUnlock(fd), E_OK);
    EXPECT_EQ(OS::CloseFile(fd), E_OK);

    // block mode
    EXPECT_EQ(OS::CreateFileByFileName(g_testDir + "/blockmode"), E_OK);
    EXPECT_EQ(OS::OpenFile(g_testDir + "/blockmode", fd), E_OK);

    EXPECT_EQ(OS::FileLock(fd, false), E_OK);
    EXPECT_EQ(OS::FileLock(fd, false), E_OK);
    EXPECT_EQ(OS::FileUnlock(fd), E_OK);
    EXPECT_EQ(OS::CloseFile(fd), E_OK);
}

/**
 * @tc.name: CalcFileSizeTest
 * @tc.desc: Test the file size for function test and the performance test.
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: wangbingquan
 */
HWTEST_F(DistributedDBCommonTest, CalcFileSizeTest, TestSize.Level1)
{
    std::string filePath = g_testDir + "/testFileSize";
    std::ofstream ofs(filePath, std::ofstream::out);
    ASSERT_TRUE(ofs.good());
    ofs << "test file size";
    ofs.close();
    uint64_t fileSize = 0;
    EXPECT_EQ(OS::CalFileSize(filePath, fileSize), E_OK);
    EXPECT_GT(fileSize, 0ULL);
    EXPECT_EQ(OS::RemoveFile(filePath), E_OK);
}

// Distributed db is not recommended to use multiple processes to access
// This testcase only guard for some wrong use on current product
#if defined(RUN_MULTI_PROCESS_TEST)
namespace {
// use file sync diff process information
bool waitForStep(int step, int retryTimes)
{
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
    while (retryTimes >= 0 && !OS::CheckPathExistence(g_testDir + "/LOCK_step_" + std::to_string(step))) {
        retryTimes = retryTimes - 1; // wait 10ms one times
        std::this_thread::sleep_for(std::chrono::milliseconds(10)); // once 10 ms
    }
    return (retryTimes > 0);
}

void createStepFlag(int step)
{
    EXPECT_EQ(OS::CreateFileByFileName(g_testDir + "/LOCK_step_" + std::to_string(step)), E_OK);
}
}

/**
 * @tc.name: DiffProcessLockFile
 * @tc.desc: Test different process repeat lock same file.
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: sunpeng
 */
HWTEST_F(DistributedDBCommonTest, DiffProcessLockFile, TestSize.Level1)
{
    OS::FileHandle *fd = nullptr;
    EXPECT_EQ(OS::OpenFile(g_testDir + DBConstant::DB_LOCK_POSTFIX, fd), E_OK);
    EXPECT_EQ(OS::FileLock(fd, false), E_OK);
    sleep(1);
    LOGI("begin fork new process!!");
    pid_t pid = fork();
    ASSERT_TRUE(pid >= 0);
    if (pid == 0) {
        LOGI("child process begin!");
        OS::FileHandle ChildFd;
        EXPECT_EQ(OS::OpenFile(g_testDir + DBConstant::DB_LOCK_POSTFIX, ChildFd), E_OK);
        ASSERT_TRUE(waitForStep(1, 10));
        EXPECT_EQ(OS::FileLock(ChildFd, false), -E_BUSY);
        createStepFlag(2);
        EXPECT_EQ(OS::CloseFile(ChildFd), E_OK);
        exit(0);
    } else {
        LOGI("main process begin!");
        EXPECT_EQ(OS::FileLock(fd, false), E_OK);
        createStepFlag(1);

        ASSERT_TRUE(waitForStep(2, 100));
        EXPECT_EQ(OS::CloseFile(fd), E_OK); // fd close, lock invalid
    }
}

/**
 * @tc.name: DiffProcessLockFileBlocked
 * @tc.desc: Test different process repeat lock same file.
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: sunpeng
 */
HWTEST_F(DistributedDBCommonTest, DiffProcessLockFileBlocked, TestSize.Level1)
{
    EXPECT_EQ(OS::CreateFileByFileName(g_testDir + DBConstant::DB_LOCK_POSTFIX), E_OK);
    OS::FileHandle fd;
    EXPECT_EQ(OS::OpenFile(g_testDir + DBConstant::DB_LOCK_POSTFIX, fd), E_OK);
    EXPECT_EQ(OS::FileLock(fd, true), E_OK);
    sleep(1);
    LOGI("begin fork new process!!");
    int count = 10; // wait 10 times 10 ms for block wait
    pid_t pid = fork();
    ASSERT_TRUE(pid >= 0);
    if (pid == 0) {
        LOGI("child process begin!");
        EXPECT_FALSE(OS::CheckPathExistence(g_testDir + "/LOCK_step_1"));
        OS::FileHandle ChildFd;
        EXPECT_EQ(OS::OpenFile(g_testDir + DBConstant::DB_LOCK_POSTFIX, ChildFd), E_OK);
        EXPECT_EQ(OS::FileLock(ChildFd, true), E_OK);
        createStepFlag(1);
        EXPECT_EQ(OS::FileUnlock(ChildFd), E_OK);
        EXPECT_EQ(OS::CloseFile(ChildFd), E_OK);
        LOGI("child process finish!");
        exit(0);
    } else {
        LOGI("main process begin!");
        while (count--) {
            LOGI("main process waiting!");
            std::this_thread::sleep_for(std::chrono::milliseconds(10)); // once 10 ms
        }
        ASSERT_FALSE(waitForStep(1, 10));
        EXPECT_EQ(OS::FileUnlock(fd), E_OK);
        EXPECT_EQ(OS::CloseFile(fd), E_OK);
        ASSERT_TRUE(waitForStep(1, 10));
    }
}

/**
  * @tc.name: DiffProcessGetDBBlocked
  * @tc.desc: Test block other process get kvstore when db locked.
  * @tc.type: FUNC
  * @tc.require:
  * @tc.author: sunpeng
  */
HWTEST_F(DistributedDBCommonTest, DiffProcessGetDBBlocked, TestSize.Level1)
{
    std::string storeId = "DiffProcessGetDBBlocked";
    std::string origId = USER_ID + "-" + APP_ID + "-" + storeId;
    std::string identifier = DBCommon::TransferHashString(origId);
    std::string hexDir = DBCommon::TransferStringToHex(identifier);
    std::string lockFile = g_testDir + "/" + hexDir + DBConstant::DB_LOCK_POSTFIX;
    EXPECT_EQ(DBCommon::CreateDirectory(g_testDir + "/" + hexDir), E_OK);
    EXPECT_EQ(OS::CreateFileByFileName(lockFile), E_OK);
    LOGI("Create lock file[%s]", lockFile.c_str());

    LOGI("begin fork new process!!");
    pid_t pid = fork();
    OS::FileHandle fd;
    ASSERT_TRUE(pid >= 0);
    if (pid == 0) {
        LOGI("child process begin!");
        ASSERT_TRUE(waitForStep(1, 10));
        KvStoreNbDelegate::Option option = {true, false, false};
        option.isNeedIntegrityCheck = true;
        g_mgr.GetKvStore(storeId, option, g_kvNbDelegateCallback);
        EXPECT_TRUE(g_kvDelegateStatus == BUSY);
        ASSERT_TRUE(g_kvNbDelegatePtr == nullptr);
        createStepFlag(2);
        exit(0);
    } else {
        LOGI("main process begin!");
        EXPECT_EQ(OS::OpenFile(lockFile, fd), E_OK);
        EXPECT_EQ(OS::FileLock(fd, false), E_OK);
        createStepFlag(1);
    }

    // Prevent the child process from not being completed, the main process ends to clean up resources
    EXPECT_TRUE(waitForStep(2, 1000));
    EXPECT_EQ(OS::FileUnlock(fd), E_OK);
    EXPECT_EQ(OS::CloseFile(fd), E_OK);
}

/**
  * @tc.name: DiffProcessDeleteDBBlocked
  * @tc.desc: Test block other process delete kvstore when db locked.
  * @tc.type: FUNC
  * @tc.require:
  * @tc.author: sunpeng
  */
HWTEST_F(DistributedDBCommonTest, DiffProcessDeleteDBBlocked, TestSize.Level1)
{
    std::string storeId = "DiffProcessDeleteDBBlocked";
    std::string origId = USER_ID + "-" + APP_ID + "-" + storeId;
    std::string identifier = DBCommon::TransferHashString(origId);
    std::string hexDir = DBCommon::TransferStringToHex(identifier);
    std::string lockFile = g_testDir + "/" + hexDir + DBConstant::DB_LOCK_POSTFIX;
    EXPECT_EQ(DBCommon::CreateDirectory(g_testDir + "/" + hexDir), E_OK);
    EXPECT_EQ(OS::CreateFileByFileName(lockFile), E_OK);
    LOGI("Create lock file[%s]", lockFile.c_str());

    KvStoreNbDelegate::Option option = {true, false, false};
    option.isNeedIntegrityCheck = true;
    g_mgr.GetKvStore(storeId, option, g_kvNbDelegateCallback);
    ASSERT_TRUE(g_kvNbDelegatePtr != nullptr);
    EXPECT_TRUE(g_kvDelegateStatus == OK);

    LOGI("begin fork new process!!");
    pid_t pid = fork();
    OS::FileHandle fd;
    ASSERT_TRUE(pid >= 0);
    if (pid == 0) {
        LOGI("child process begin!");
        ASSERT_TRUE(waitForStep(1, 10));
        EXPECT_EQ(g_mgr.DeleteKvStore(storeId), BUSY);
        createStepFlag(2);
        exit(0);
    } else {
        LOGI("main process begin!");
        EXPECT_EQ(OS::OpenFile(lockFile, fd), E_OK);
        EXPECT_EQ(OS::FileLock(fd, false), E_OK);
        createStepFlag(1);
    }

    // Prevent the child process from not being completed, the main process ends to clean up resources
    EXPECT_TRUE(waitForStep(2, 1000));
    EXPECT_EQ(OS::FileUnlock(fd), E_OK);
    EXPECT_EQ(OS::CloseFile(fd), E_OK);
    g_mgr.CloseKvStore(g_kvNbDelegatePtr);
}

/**
  * @tc.name: DiffProcessGetDBBlocked001
  * @tc.desc: Test block other process get kvstore when db locked.
  * @tc.type: FUNC
  * @tc.require:
  * @tc.author: sunpeng
  */
HWTEST_F(DistributedDBCommonTest, DiffProcessGetDBBlocked001, TestSize.Level1)
{
    std::string storeId = "DiffProcessGetDBBlocked001";
    std::string origId = USER_ID + "-" + APP_ID + "-" + storeId;
    std::string identifier = DBCommon::TransferHashString(origId);
    std::string hexDir = DBCommon::TransferStringToHex(identifier);
    std::string lockFile = g_testDir + "/" + hexDir + DBConstant::DB_LOCK_POSTFIX;
    EXPECT_EQ(DBCommon::CreateDirectory(g_testDir + "/" + hexDir), E_OK);
    EXPECT_EQ(OS::CreateFileByFileName(lockFile), E_OK);
    LOGI("Create lock file[%s]", lockFile.c_str());

    LOGI("begin fork new process!!");
    pid_t pid = fork();
    OS::FileHandle fd;
    ASSERT_TRUE(pid >= 0);
    if (pid == 0) {
        LOGI("child process begin!");
        ASSERT_TRUE(waitForStep(1, 10));
        KvStoreNbDelegate::Option option = {true, false, false};
        option.isNeedIntegrityCheck = true;
        g_mgr.GetKvStore(storeId, option, g_kvNbDelegateCallback);
        ASSERT_TRUE(g_kvNbDelegatePtr != nullptr);
        EXPECT_TRUE(g_kvDelegateStatus == OK);
        createStepFlag(2);
        exit(0);
    } else {
        LOGI("main process begin!");
        EXPECT_EQ(OS::OpenFile(lockFile, fd), E_OK);
        EXPECT_EQ(OS::FileLock(fd, false), E_OK);
        createStepFlag(1);
    }
    ASSERT_TRUE(waitForStep(1, 100));

    EXPECT_EQ(OS::FileUnlock(fd), E_OK);
    EXPECT_EQ(OS::CloseFile(fd), E_OK);

    ASSERT_TRUE(waitForStep(2, 100));
}

/**
  * @tc.name: DiffProcessGetDB
  * @tc.desc: Test block other process get kvstore.
  * @tc.type: FUNC
  * @tc.require:
  * @tc.author: sunpeng
  */
HWTEST_F(DistributedDBCommonTest, DiffProcessGetDB, TestSize.Level1)
{
    std::string storeId = "DiffProcessGetDB";
    KvStoreNbDelegate::Option option = {true, false, false};
    option.isNeedIntegrityCheck = true;
    LOGI("begin fork new process!!");
    pid_t pid = fork();
    ASSERT_TRUE(pid >= 0);
    if (pid == 0) {
        LOGI("child process begin!");
        g_mgr.GetKvStore(storeId, option, g_kvNbDelegateCallback);
        ASSERT_TRUE(g_kvNbDelegatePtr != nullptr);
        EXPECT_TRUE(g_kvDelegateStatus == OK);
        createStepFlag(2);
        EXPECT_TRUE(waitForStep(1, 1000));
        exit(0);
    } else {
        LOGI("main process begin!");
        g_mgr.GetKvStore(storeId, option, g_kvNbDelegateCallback);
        ASSERT_TRUE(g_kvNbDelegatePtr != nullptr);
        EXPECT_TRUE(g_kvDelegateStatus == OK);
        createStepFlag(1);
    }
    EXPECT_TRUE(waitForStep(2, 100));
    // Prevent the child process from not being completed, the main process ends to clean up resources
    g_mgr.CloseKvStore(g_kvNbDelegatePtr);
}

/**
  * @tc.name: DiffProcessDeleteDB
  * @tc.desc: Test block other process delete kvstore.
  * @tc.type: FUNC
  * @tc.require:
  * @tc.author: sunpeng
  */
HWTEST_F(DistributedDBCommonTest, DiffProcessDeleteDB, TestSize.Level1)
{
    std::string storeId = "DiffProcessGetDB";
    KvStoreNbDelegate::Option option = {true, false, false};
    option.isNeedIntegrityCheck = true;
    g_mgr.GetKvStore(storeId, option, g_kvNbDelegateCallback);
    ASSERT_TRUE(g_kvNbDelegatePtr != nullptr);
    EXPECT_TRUE(g_kvDelegateStatus == OK);
    g_mgr.CloseKvStore(g_kvNbDelegatePtr);
    LOGI("begin fork new process!!");
    pid_t pid = fork();
    ASSERT_TRUE(pid >= 0);
    if (pid == 0) {
        LOGI("child process begin!");
        g_mgr.GetKvStore(storeId, option, g_kvNbDelegateCallback);
        ASSERT_TRUE(g_kvNbDelegatePtr != nullptr);
        EXPECT_TRUE(g_kvDelegateStatus == OK);
        createStepFlag(2);
        EXPECT_TRUE(waitForStep(1, 1000));
        exit(0);
    } else {
        LOGI("main process begin!");
        g_mgr.DeleteKvStore(storeId);
        createStepFlag(1);
    }
    EXPECT_TRUE(waitForStep(2, 100));

    // Prevent the child process from not being completed, the main process ends to clean up resources
    EXPECT_TRUE(waitForStep(1, 100));
}

/**
  * @tc.name: DiffProcessGetAndDeleteDB
  * @tc.desc: Test block other process delete kvstore.
  * @tc.type: FUNC
  * @tc.require:
  * @tc.author: sunpeng
  */
HWTEST_F(DistributedDBCommonTest, DiffProcessGetAndDeleteDB, TestSize.Level1)
{
    std::string storeId = "DiffProcessGetAndDeleteDB";
    KvStoreNbDelegate::Option option = {true, false, false};
    option.isNeedIntegrityCheck = true;
    g_mgr.GetKvStore(storeId, option, g_kvNbDelegateCallback);
    ASSERT_TRUE(g_kvNbDelegatePtr != nullptr);
    EXPECT_TRUE(g_kvDelegateStatus == OK);
    g_mgr.CloseKvStore(g_kvNbDelegatePtr);
    LOGI("begin fork new process!!");
    pid_t pid = fork();
    ASSERT_TRUE(pid >= 0);
    if (pid == 0) {
        LOGI("child process begin!");
        g_mgr.DeleteKvStore(storeId); // one process OK, one process NOT_FOUND
        createStepFlag(2);
        EXPECT_TRUE(waitForStep(1, 1000));
        exit(0);
    } else {
        LOGI("main process begin!");
        g_mgr.DeleteKvStore(storeId);
        createStepFlag(1);
    }
    EXPECT_TRUE(waitForStep(2, 100));

    // Prevent the child process from not being completed, the main process ends to clean up resources
    EXPECT_TRUE(waitForStep(1, 1000));
}
#endif
#endif

HWTEST_F(DistributedDBCommonTest, StringCaseTest002, TestSize.Level0)
{
    EXPECT_TRUE(DBCommon::CaseInsensitiveCompare("HELLO WORLD.", "hello world."));
    EXPECT_TRUE(DBCommon::CaseInsensitiveCompare("ABCDEFGHIJKLMN", "abcdefghijklmn"));
    EXPECT_TRUE(DBCommon::CaseInsensitiveCompare("OPQRSTUVWXYZ", "opqrstuvwxyz"));
    EXPECT_FALSE(DBCommon::CaseInsensitiveCompare("sqlite", "sqlite3"));
    EXPECT_FALSE(DBCommon::CaseInsensitiveCompare("gitee", "git"));
}

HWTEST_F(DistributedDBCommonTest, PerformanceAnalysisTest001, TestSize.Level1)
{
    int threadCount = 1000;
    int count1 = 0;
    int count2 = 0;
    for (int i = 0; i < threadCount; i++) {
        std::thread t1([&count1] {
            PerformanceAnalysis::GetInstance(20); // 20 is stepNum
            count1++;
        });

        std::thread t2([&count2] {
            PerformanceAnalysis::GetInstance(20); // 20 is stepNum
            count2++;
        });

        t1.join();
        t2.join();
    }
    EXPECT_EQ(count1, count1);
    EXPECT_EQ(count1, threadCount);
}

/**
 * @tc.name: PerformanceAnalysisTest002
 * @tc.desc: Test PerformanceAnalysis interfaces.
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: suyue
 */
HWTEST_F(DistributedDBCommonTest, PerformanceAnalysisTest002, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Get PerformanceAnalysis instance and call interfaces.
     * @tc.expected: step1. success.
     */
    PerformanceAnalysis *performance = PerformanceAnalysis::GetInstance(5); // 5 is stepNum
    ASSERT_NE(performance, nullptr);
    performance->SetFileName("test");
    performance->OpenPerformanceAnalysis();
    performance->TimeRecordStart();
    performance->TimeRecordEnd();

    /**
     * @tc.steps: step2. Call interfaces with the para is greater than stepNum.
     * @tc.expected: step2. success.
     */
    performance->StepTimeRecordStart(RECORD_ACK_RECV_TO_USER_CALL_BACK);
    performance->StepTimeRecordEnd(RECORD_ACK_RECV_TO_USER_CALL_BACK);
    performance->ClosePerformanceAnalysis();
    performance->GetStatistics();
}

/**
 * @tc.name: UserChangeMonitorTest
 * @tc.desc: Test UserChangeMonitor interfaces.
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: suyue
 */
HWTEST_F(DistributedDBCommonTest, UserChangeMonitorTest, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Start UserChangeMonitor.
     * @tc.expected: step1. success.
     */
    UserChangeMonitor monitor;
    EXPECT_EQ(monitor.Start(), E_OK);
    monitor.NotifyUserChanged();

    /**
     * @tc.steps: step2. Call RegisterUserChangedListener with null action.
     * @tc.expected: step2. -E_INVALID_ARGS.
     */
    int errCode = E_OK;
    DistributedDB::UserChangedAction action = nullptr;
    NotificationChain::Listener *ptr = monitor.RegisterUserChangedListener(action,
        monitor.USER_ACTIVE_TO_NON_ACTIVE_EVENT, errCode);
    ASSERT_EQ(ptr, nullptr);
    EXPECT_EQ(errCode, -E_INVALID_ARGS);

    /**
     * @tc.steps: step3. Second start UserChangeMonitor.
     * @tc.expected: step3. success.
     */
    EXPECT_EQ(monitor.Start(), E_OK);
    monitor.Stop();
    monitor.NotifyUserChanged();
}

/**
 * @tc.name: ValueObjectConstructorTest
 * @tc.desc: Test ValueObjectTest.
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: suyue
 */
HWTEST_F(DistributedDBCommonTest, ValueObjectConstructorTest, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Call the default constructor of ValueObject.
     * @tc.expected: step1. success.
     */
    ValueObject valueObj;
    EXPECT_EQ(valueObj.IsValid(), false);

    /**
     * @tc.steps: step2. Call constructor of ValueObject.
     * @tc.expected: step2. success.
     */
    ValueObject valueObj1(valueObj);
    EXPECT_EQ(valueObj1.IsValid(), false);
    valueObj = valueObj1;
}

/**
 * @tc.name: TimeTickMonitorTest
 * @tc.desc: Test TimeTickMonitor interfaces.
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: suyue
 */
HWTEST_F(DistributedDBCommonTest, TimeTickMonitorTest, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Start TimeTickMonitor.
     * @tc.expected: step1. success.
     */
    TimeTickMonitor monitor;
    EXPECT_EQ(monitor.StartTimeTickMonitor(), E_OK);

    /**
     * @tc.steps: step2. Call RegisterTimeChangedLister with null para.
     * @tc.expected: step2. -E_INVALID_ARGS.
     */
    int errCode = E_OK;
    DistributedDB::UserChangedAction action = nullptr;
    TimeFinalizeAction finalize = nullptr;
    NotificationChain::Listener *ptr = monitor.RegisterTimeChangedLister(action, finalize, errCode);
    ASSERT_EQ(ptr, nullptr);
    EXPECT_EQ(errCode, -E_INVALID_ARGS);

    /**
     * @tc.steps: step3. Call RegisterTimeChangedLister after Stop TimeTickMonitor.
     * @tc.expected: step3. success.
     */
    EXPECT_EQ(monitor.StartTimeTickMonitor(), E_OK);
    monitor.StopTimeTickMonitor();
    monitor.NotifyTimeChange(0);

    ptr = monitor.RegisterTimeChangedLister(action, finalize, errCode);
    ASSERT_EQ(ptr, nullptr);
    EXPECT_EQ(errCode, -E_NOT_INIT);
}

/**
 * @tc.name: LockStatusObserverTest
 * @tc.desc: Test LockStatusObserver interfaces.
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: suyue
 */
HWTEST_F(DistributedDBCommonTest, LockStatusObserverTest, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Call RegisterLockStatusChangedLister with null para.
     * @tc.expected: step1. return -E_INVALID_ARGS.
     */
    LockStatusObserver observer;
    EXPECT_EQ(observer.Start(), E_OK);

    int errCode = E_OK;
    DistributedDB::UserChangedAction action = nullptr;
    NotificationChain::Listener *ptr = observer.RegisterLockStatusChangedLister(action, errCode);
    ASSERT_EQ(ptr, nullptr);
    EXPECT_EQ(errCode, -E_INVALID_ARGS);

    /**
     * @tc.steps: step2. Call RegisterLockStatusChangedLister after stop observer.
     * @tc.expected: step2. return -E_NOT_INIT.
     */
    EXPECT_EQ(observer.Start(), E_OK);
    observer.Stop();
    observer.OnStatusChange(true);

    ptr = observer.RegisterLockStatusChangedLister(action, errCode);
    ASSERT_EQ(ptr, nullptr);
    EXPECT_EQ(errCode, -E_NOT_INIT);
}

/**
 * @tc.name: TaskQueueTest
 * @tc.desc: Test TaskQueue interfaces.
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: suyue
 */
HWTEST_F(DistributedDBCommonTest, TaskQueueTest, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Create TaskQueue object whose para is true.
     * @tc.expected: step1. Create success.
     */
    TaskQueue taskObj1(true);
    const Task task1;
    taskObj1.PutTask(task1);
    EXPECT_EQ(taskObj1.IsEmptyAndUnlocked(), true);
    EXPECT_EQ(taskObj1.CanGetTask(), false);

    /**
     * @tc.steps: step2. Create TaskQueue object whose para is false.
     * @tc.expected: step2. Create success.
     */
    TaskQueue taskObj2(false);
    EXPECT_EQ(taskObj2.IsEmptyAndUnlocked(), true);
    EXPECT_EQ(taskObj2.CanGetTask(), false);
}

/**
 * @tc.name: AbnormalTrackerTableTest
 * @tc.desc: Test LockStatusObserver interfaces.
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: suyue
 */
HWTEST_F(DistributedDBCommonTest, AbnormalTrackerTableTest, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Call GetDiffIncCursorSql interface when TrackerTable is not init.
     * @tc.expected: step1. return empty string.
     */
    TrackerTable trackerObj1;
    std::string str = trackerObj1.GetDiffIncCursorSql("test1");
    const std::string emptyStr = "";
    EXPECT_TRUE(str.compare(0, str.length(), emptyStr) == 0);

    /**
     * @tc.steps: step2. Call GetCreateTempTriggerSql interface when para is NONE.
     * @tc.expected: step2. return empty string.
     */
    std::string str1 = trackerObj1.GetCreateTempTriggerSql(TriggerMode::TriggerModeEnum::DELETE);
    EXPECT_TRUE(str1.compare(0, str1.length(), emptyStr) != 0);
    std::string str2 = trackerObj1.GetCreateTempTriggerSql(TriggerMode::TriggerModeEnum::NONE);
    EXPECT_TRUE(str2.compare(0, str2.length(), emptyStr) == 0);

    /**
     * @tc.steps: step3. Call ReBuildTempTrigger interface when db is nullptr.
     * @tc.expected: step3. return -E_INVALID_DB.
     */
    int ret = trackerObj1.ReBuildTempTrigger(nullptr, TriggerMode::TriggerModeEnum::NONE, nullptr);
    EXPECT_EQ(ret, -E_INVALID_DB);

    /**
     * @tc.steps: step4. Test IsChanging interface after setting schema info.
     * @tc.expected: step4. return true.
     */
    const TrackerSchema schema = {
        .tableName = "table1",
        .extendColNames = {"extendCol1"},
        .trackerColNames = {"trackerCol1"},
    };
    trackerObj1.Init(schema);
    EXPECT_EQ(trackerObj1.IsChanging(schema), false);

    const std::set<std::string> trackerNames = {"trackerCol"};
    trackerObj1.SetTrackerNames(trackerNames);
    EXPECT_EQ(trackerObj1.IsChanging(schema), true);
    const std::string colName = "col";
    trackerObj1.SetExtendNames({colName});
    std::set<std::string> extendNames = trackerObj1.GetExtendNames();
    std::string str3 = *extendNames.begin();
    EXPECT_TRUE(str3.compare(0, str3.length(), colName) == 0);
    EXPECT_EQ(trackerObj1.IsChanging(schema), true);
}
}