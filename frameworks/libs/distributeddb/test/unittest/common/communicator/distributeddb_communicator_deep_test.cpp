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
#include <gmock/gmock.h>
#include <new>
#include <thread>
#include "db_errno.h"
#include "distributeddb_communicator_common.h"
#include "distributeddb_tools_unit_test.h"
#include "log_print.h"
#include "network_adapter.h"
#include "message.h"
#include "mock_process_communicator.h"
#include "protocol_proto.h"
#include "res_finalizer.h"
#include "serial_buffer.h"

using namespace std;
using namespace testing::ext;
using namespace DistributedDB;

namespace {
    EnvHandle g_envDeviceA;
    EnvHandle g_envDeviceB;
    EnvHandle g_envDeviceC;
    ICommunicator *g_commAA = nullptr;
    ICommunicator *g_commAB = nullptr;
    ICommunicator *g_commBB = nullptr;
    ICommunicator *g_commBC = nullptr;
    ICommunicator *g_commCC = nullptr;
    ICommunicator *g_commCA = nullptr;
}

class DistributedDBCommunicatorDeepTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void DistributedDBCommunicatorDeepTest::SetUpTestCase(void)
{
    /**
     * @tc.setup: Create and init CommunicatorAggregator and AdapterStub
     */
    LOGI("[UT][DeepTest][SetUpTestCase] Enter.");
    bool isSuccess = SetUpEnv(g_envDeviceA, DEVICE_NAME_A);
    ASSERT_EQ(isSuccess, true);
    isSuccess = SetUpEnv(g_envDeviceB, DEVICE_NAME_B);
    ASSERT_EQ(isSuccess, true);
    isSuccess = SetUpEnv(g_envDeviceC, DEVICE_NAME_C);
    ASSERT_EQ(isSuccess, true);
    DoRegTransformFunction();
    CommunicatorAggregator::EnableCommunicatorNotFoundFeedback(false);
}

void DistributedDBCommunicatorDeepTest::TearDownTestCase(void)
{
    /**
     * @tc.teardown: Finalize and release CommunicatorAggregator and AdapterStub
     */
    LOGI("[UT][DeepTest][TearDownTestCase] Enter.");
    std::this_thread::sleep_for(std::chrono::seconds(7)); // Wait 7 s to make sure all thread quiet and memory released
    TearDownEnv(g_envDeviceA);
    TearDownEnv(g_envDeviceB);
    TearDownEnv(g_envDeviceC);
    CommunicatorAggregator::EnableCommunicatorNotFoundFeedback(true);
}

namespace {
void AllocAllCommunicator()
{
    int errorNo = E_OK;
    g_commAA = g_envDeviceA.commAggrHandle->AllocCommunicator(LABEL_A, errorNo);
    ASSERT_NOT_NULL_AND_ACTIVATE(g_commAA, "");
    g_commAB = g_envDeviceA.commAggrHandle->AllocCommunicator(LABEL_B, errorNo);
    ASSERT_NOT_NULL_AND_ACTIVATE(g_commAB, "");
    g_commBB = g_envDeviceB.commAggrHandle->AllocCommunicator(LABEL_B, errorNo);
    ASSERT_NOT_NULL_AND_ACTIVATE(g_commBB, "");
    g_commBC = g_envDeviceB.commAggrHandle->AllocCommunicator(LABEL_C, errorNo);
    ASSERT_NOT_NULL_AND_ACTIVATE(g_commBC, "");
    g_commCC = g_envDeviceC.commAggrHandle->AllocCommunicator(LABEL_C, errorNo);
    ASSERT_NOT_NULL_AND_ACTIVATE(g_commCC, "");
    g_commCA = g_envDeviceC.commAggrHandle->AllocCommunicator(LABEL_A, errorNo);
    ASSERT_NOT_NULL_AND_ACTIVATE(g_commCA, "");
}

void ReleaseAllCommunicator()
{
    g_envDeviceA.commAggrHandle->ReleaseCommunicator(g_commAA);
    g_commAA = nullptr;
    g_envDeviceA.commAggrHandle->ReleaseCommunicator(g_commAB);
    g_commAB = nullptr;
    g_envDeviceB.commAggrHandle->ReleaseCommunicator(g_commBB);
    g_commBB = nullptr;
    g_envDeviceB.commAggrHandle->ReleaseCommunicator(g_commBC);
    g_commBC = nullptr;
    g_envDeviceC.commAggrHandle->ReleaseCommunicator(g_commCC);
    g_commCC = nullptr;
    g_envDeviceC.commAggrHandle->ReleaseCommunicator(g_commCA);
    g_commCA = nullptr;
}
}

void DistributedDBCommunicatorDeepTest::SetUp()
{
    DistributedDBUnitTest::DistributedDBToolsUnitTest::PrintTestCaseInfo();
    /**
     * @tc.setup: Alloc communicator AA, AB, BB, BC, CC, CA
     */
    AllocAllCommunicator();
}

void DistributedDBCommunicatorDeepTest::TearDown()
{
    /**
     * @tc.teardown: Release communicator AA, AB, BB, BC, CC, CA
     */
    ReleaseAllCommunicator();
    g_envDeviceA.commAggrHandle->ResetRetryCount();
    g_envDeviceB.commAggrHandle->ResetRetryCount();
    g_envDeviceC.commAggrHandle->ResetRetryCount();
    std::this_thread::sleep_for(std::chrono::milliseconds(200)); // Wait 200 ms to make sure all thread quiet
}

/**
 * @tc.name: WaitAndRetrySend 001
 * @tc.desc: Test send retry semantic
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: xiaozhenjian
 */
HWTEST_F(DistributedDBCommunicatorDeepTest, WaitAndRetrySend001, TestSize.Level2)
{
    // Preset
    Message *msgForBB = nullptr;
    g_commBB->RegOnMessageCallback([&msgForBB](const std::string &srcTarget, Message *inMsg) {
        msgForBB = inMsg;
        return E_OK;
    }, nullptr);
    Message *msgForCA = nullptr;
    g_commCA->RegOnMessageCallback([&msgForCA](const std::string &srcTarget, Message *inMsg) {
        msgForCA = inMsg;
        return E_OK;
    }, nullptr);

    /**
     * @tc.steps: step1. connect device A with device B
     */
    AdapterStub::ConnectAdapterStub(g_envDeviceA.adapterHandle, g_envDeviceB.adapterHandle);
    AdapterStub::ConnectAdapterStub(g_envDeviceA.adapterHandle, g_envDeviceC.adapterHandle);
    std::this_thread::sleep_for(std::chrono::milliseconds(200)); // Wait 200 ms to make sure quiet

    /**
     * @tc.steps: step2. device A simulate send retry
     */
    g_envDeviceA.adapterHandle->SimulateSendRetry(DEVICE_NAME_B);

    /**
     * @tc.steps: step3. device A send message to device B using communicator AB
     * @tc.expected: step3. communicator BB received no message
     */
    Message *msgForAB = BuildRegedTinyMessage();
    ASSERT_NE(msgForAB, nullptr);
    SendConfig conf = {true, false, true, 0};
    int errCode = g_commAB->SendMessage(DEVICE_NAME_B, msgForAB, conf);
    EXPECT_EQ(errCode, E_OK);

    Message *msgForAA = BuildRegedTinyMessage();
    ASSERT_NE(msgForAA, nullptr);
    errCode = g_commAA->SendMessage(DEVICE_NAME_C, msgForAA, conf);
    EXPECT_EQ(errCode, E_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(100)); // Wait 100 ms
    EXPECT_EQ(msgForBB, nullptr);
    EXPECT_NE(msgForCA, nullptr);
    delete msgForCA;
    msgForCA = nullptr;

    /**
     * @tc.steps: step4. device A simulate sendable feedback
     * @tc.expected: step4. communicator BB received the message
     */
    g_envDeviceA.adapterHandle->SimulateSendRetryClear(DEVICE_NAME_B);
    std::this_thread::sleep_for(std::chrono::milliseconds(100)); // Wait 100 ms
    EXPECT_NE(msgForBB, nullptr);
    delete msgForBB;
    msgForBB = nullptr;

    // CleanUp
    AdapterStub::DisconnectAdapterStub(g_envDeviceA.adapterHandle, g_envDeviceB.adapterHandle);
    AdapterStub::DisconnectAdapterStub(g_envDeviceA.adapterHandle, g_envDeviceC.adapterHandle);
}

/**
 * @tc.name: WaitAndRetrySend002
 * @tc.desc: Test send return retry but task not retry
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: liaoyonghuang
 */
HWTEST_F(DistributedDBCommunicatorDeepTest, WaitAndRetrySend002, TestSize.Level2)
{
    // Preset
    Message *msgForCA = nullptr;
    g_commCA->RegOnMessageCallback([&msgForCA](const std::string &srcTarget, Message *inMsg) {
        msgForCA = inMsg;
        return E_OK;
    }, nullptr);

    /**
     * @tc.steps: step1. connect device A with device B
     */
    AdapterStub::ConnectAdapterStub(g_envDeviceA.adapterHandle, g_envDeviceC.adapterHandle);
    std::this_thread::sleep_for(std::chrono::milliseconds(200)); // Wait 200 ms to make sure quiet

    /**
     * @tc.steps: step2. device A simulate send retry
     */
    g_envDeviceA.adapterHandle->SimulateSendRetry(DEVICE_NAME_B);

    /**
     * @tc.steps: step3. device A send message to device B using communicator AB
     * @tc.expected: step3. communicator BB received no message
     */
    Message *msgForAB = BuildRegedTinyMessage();
    ASSERT_NE(msgForAB, nullptr);
    SendConfig conf = {true, false, false, 0};
    OnSendEnd onSendEnd = [](int, int) {
        LOGI("[WaitAndRetrySend002] on send end.");
    };
    int errCode = g_commAB->SendMessage(DEVICE_NAME_B, msgForAB, conf, onSendEnd);
    EXPECT_EQ(errCode, E_OK);

    std::this_thread::sleep_for(std::chrono::milliseconds(100)); // Wait 100 ms
    EXPECT_EQ(msgForCA, nullptr);

    /**
     * @tc.steps: step4. device A simulate sendable feedback
     * @tc.expected: step4. communicator BB received the message
     */
    g_envDeviceA.adapterHandle->SimulateSendRetryClear(DEVICE_NAME_B);
    std::this_thread::sleep_for(std::chrono::milliseconds(100)); // Wait 100 ms

    // CleanUp
    AdapterStub::DisconnectAdapterStub(g_envDeviceA.adapterHandle, g_envDeviceC.adapterHandle);
}

static int CreateBufferThenAddIntoScheduler(SendTaskScheduler &scheduler, const std::string &dstTarget, Priority inPrio)
{
    SerialBuffer *eachBuff = new (std::nothrow) SerialBuffer();
    if (eachBuff == nullptr) {
        return -E_OUT_OF_MEMORY;
    }
    int errCode = eachBuff->AllocBufferByTotalLength(100, 0); // 100 totallen without header
    if (errCode != E_OK) {
        delete eachBuff;
        eachBuff = nullptr;
        return errCode;
    }
    SendTask task{eachBuff, dstTarget, nullptr, 0u};
    errCode = scheduler.AddSendTaskIntoSchedule(task, inPrio);
    if (errCode != E_OK) {
        delete eachBuff;
        eachBuff = nullptr;
        return errCode;
    }
    return E_OK;
}

/**
 * @tc.name: SendSchedule 001
 * @tc.desc: Test schedule in Priority order than in send order
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: xiaozhenjian
 */
HWTEST_F(DistributedDBCommunicatorDeepTest, SendSchedule001, TestSize.Level2)
{
    // Preset
    SendTaskScheduler scheduler;
    scheduler.Initialize();

    /**
     * @tc.steps: step1. Add low priority target A buffer to schecduler
     */
    int errCode = CreateBufferThenAddIntoScheduler(scheduler, DEVICE_NAME_A, Priority::LOW);
    EXPECT_EQ(errCode, E_OK);

    /**
     * @tc.steps: step2. Add low priority target B buffer to schecduler
     */
    errCode = CreateBufferThenAddIntoScheduler(scheduler, DEVICE_NAME_B, Priority::LOW);
    EXPECT_EQ(errCode, E_OK);

    /**
     * @tc.steps: step3. Add normal priority target B buffer to schecduler
     */
    errCode = CreateBufferThenAddIntoScheduler(scheduler, DEVICE_NAME_B, Priority::NORMAL);
    EXPECT_EQ(errCode, E_OK);

    /**
     * @tc.steps: step4. Add normal priority target C buffer to schecduler
     */
    errCode = CreateBufferThenAddIntoScheduler(scheduler, DEVICE_NAME_C, Priority::NORMAL);
    EXPECT_EQ(errCode, E_OK);

    /**
     * @tc.steps: step5. Add high priority target C buffer to schecduler
     */
    errCode = CreateBufferThenAddIntoScheduler(scheduler, DEVICE_NAME_C, Priority::HIGH);
    EXPECT_EQ(errCode, E_OK);

    /**
     * @tc.steps: step6. Add high priority target A buffer to schecduler
     */
    errCode = CreateBufferThenAddIntoScheduler(scheduler, DEVICE_NAME_A, Priority::HIGH);
    EXPECT_EQ(errCode, E_OK);

    /**
     * @tc.steps: step7. schedule out buffers one by one
     * @tc.expected: step7. the order is: high priority target C
     *                                    high priority target A
     *                                    normal priority target B
     *                                    normal priority target C
     *                                    low priority target A
     *                                    low priority target B
     */
    SendTask outTask;
    SendTaskInfo outTaskInfo;
    uint32_t totalLength = 0;
    // high priority target C
    errCode = scheduler.ScheduleOutSendTask(outTask, outTaskInfo, totalLength);
    ASSERT_EQ(errCode, E_OK);
    EXPECT_EQ(outTask.dstTarget, DEVICE_NAME_C);
    EXPECT_EQ(outTaskInfo.taskPrio, Priority::HIGH);
    scheduler.FinalizeLastScheduleTask();
    // high priority target A
    errCode = scheduler.ScheduleOutSendTask(outTask, outTaskInfo, totalLength);
    ASSERT_EQ(errCode, E_OK);
    EXPECT_EQ(outTask.dstTarget, DEVICE_NAME_A);
    EXPECT_EQ(outTaskInfo.taskPrio, Priority::HIGH);
    scheduler.FinalizeLastScheduleTask();
    // normal priority target B
    errCode = scheduler.ScheduleOutSendTask(outTask, outTaskInfo, totalLength);
    ASSERT_EQ(errCode, E_OK);
    EXPECT_EQ(outTask.dstTarget, DEVICE_NAME_B);
    EXPECT_EQ(outTaskInfo.taskPrio, Priority::NORMAL);
    scheduler.FinalizeLastScheduleTask();
    // normal priority target C
    errCode = scheduler.ScheduleOutSendTask(outTask, outTaskInfo, totalLength);
    ASSERT_EQ(errCode, E_OK);
    EXPECT_EQ(outTask.dstTarget, DEVICE_NAME_C);
    EXPECT_EQ(outTaskInfo.taskPrio, Priority::NORMAL);
    scheduler.FinalizeLastScheduleTask();
    // low priority target A
    errCode = scheduler.ScheduleOutSendTask(outTask, outTaskInfo, totalLength);
    ASSERT_EQ(errCode, E_OK);
    EXPECT_EQ(outTask.dstTarget, DEVICE_NAME_A);
    EXPECT_EQ(outTaskInfo.taskPrio, Priority::LOW);
    scheduler.FinalizeLastScheduleTask();
    // low priority target B
    errCode = scheduler.ScheduleOutSendTask(outTask, outTaskInfo, totalLength);
    ASSERT_EQ(errCode, E_OK);
    EXPECT_EQ(outTask.dstTarget, DEVICE_NAME_B);
    EXPECT_EQ(outTaskInfo.taskPrio, Priority::LOW);
    scheduler.FinalizeLastScheduleTask();
}

/**
 * @tc.name: Fragment 001
 * @tc.desc: Test fragmentation in send and receive
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: xiaozhenjian
 */
HWTEST_F(DistributedDBCommunicatorDeepTest, Fragment001, TestSize.Level2)
{
    // Preset
    Message *recvMsgForBB = nullptr;
    g_commBB->RegOnMessageCallback([&recvMsgForBB](const std::string &srcTarget, Message *inMsg) {
        recvMsgForBB = inMsg;
        return E_OK;
    }, nullptr);

    /**
     * @tc.steps: step1. connect device A with device B
     */
    AdapterStub::ConnectAdapterStub(g_envDeviceA.adapterHandle, g_envDeviceB.adapterHandle);

    /**
     * @tc.steps: step2. device A send message(registered and giant) to device B using communicator AB
     * @tc.expected: step2. communicator BB received the message
     */
    const uint32_t dataLength = 13 * 1024 * 1024; // 13 MB, 1024 is scale
    Message *sendMsgForAB = BuildRegedGiantMessage(dataLength);
    ASSERT_NE(sendMsgForAB, nullptr);
    SendConfig conf = {false, false, true, 0};
    int errCode = g_commAB->SendMessage(DEVICE_NAME_B, sendMsgForAB, conf);
    EXPECT_EQ(errCode, E_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(2600)); // Wait 2600 ms to make sure send done
    ASSERT_NE(recvMsgForBB, nullptr);
    ASSERT_EQ(recvMsgForBB->GetMessageId(), REGED_GIANT_MSG_ID);

    /**
     * @tc.steps: step3. Compare received data with send data
     * @tc.expected: step3. equal
     */
    Message *oriMsgForAB = BuildRegedGiantMessage(dataLength);
    ASSERT_NE(oriMsgForAB, nullptr);
    const RegedGiantObject *oriObjForAB = oriMsgForAB->GetObject<RegedGiantObject>();
    ASSERT_NE(oriObjForAB, nullptr);
    const RegedGiantObject *recvObjForBB = recvMsgForBB->GetObject<RegedGiantObject>();
    ASSERT_NE(recvObjForBB, nullptr);
    bool isEqual = RegedGiantObject::CheckEqual(*oriObjForAB, *recvObjForBB);
    EXPECT_EQ(isEqual, true);

    // CleanUp
    delete oriMsgForAB;
    oriMsgForAB = nullptr;
    delete recvMsgForBB;
    recvMsgForBB = nullptr;
    AdapterStub::DisconnectAdapterStub(g_envDeviceA.adapterHandle, g_envDeviceB.adapterHandle);
}

/**
 * @tc.name: Fragment 002
 * @tc.desc: Test fragmentation in partial loss
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: xiaozhenjian
 */
HWTEST_F(DistributedDBCommunicatorDeepTest, Fragment002, TestSize.Level2)
{
    // Preset
    Message *recvMsgForCC = nullptr;
    g_commCC->RegOnMessageCallback([&recvMsgForCC](const std::string &srcTarget, Message *inMsg) {
        recvMsgForCC = inMsg;
        return E_OK;
    }, nullptr);

    /**
     * @tc.steps: step1. connect device B with device C
     */
    AdapterStub::ConnectAdapterStub(g_envDeviceB.adapterHandle, g_envDeviceC.adapterHandle);
    std::this_thread::sleep_for(std::chrono::milliseconds(200)); // Wait 200 ms to make sure quiet

    /**
     * @tc.steps: step2. device B simulate partial loss
     */
    g_envDeviceB.adapterHandle->SimulateSendPartialLoss();

    /**
     * @tc.steps: step3. device B send message(registered and giant) to device C using communicator BC
     * @tc.expected: step3. communicator CC not receive the message
     */
    uint32_t dataLength = 13 * 1024 * 1024; // 13 MB, 1024 is scale
    Message *sendMsgForBC = BuildRegedGiantMessage(dataLength);
    ASSERT_NE(sendMsgForBC, nullptr);
    SendConfig conf = {false, false, true, 0};
    int errCode = g_commBC->SendMessage(DEVICE_NAME_C, sendMsgForBC, conf);
    EXPECT_EQ(errCode, E_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(2600)); // Wait 2600 ms to make sure send done
    EXPECT_EQ(recvMsgForCC, nullptr);

    /**
     * @tc.steps: step4. device B not simulate partial loss
     */
    g_envDeviceB.adapterHandle->SimulateSendPartialLossClear();

    /**
     * @tc.steps: step5. device B send message(registered and giant) to device C using communicator BC
     * @tc.expected: step5. communicator CC received the message, the length equal to the one that is second send
     */
    dataLength = 17 * 1024 * 1024; // 17 MB, 1024 is scale
    Message *resendMsgForBC = BuildRegedGiantMessage(dataLength);
    ASSERT_NE(resendMsgForBC, nullptr);
    errCode = g_commBC->SendMessage(DEVICE_NAME_C, resendMsgForBC, conf);
    EXPECT_EQ(errCode, E_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(3400)); // Wait 3400 ms to make sure send done
    ASSERT_NE(recvMsgForCC, nullptr);
    ASSERT_EQ(recvMsgForCC->GetMessageId(), REGED_GIANT_MSG_ID);
    const RegedGiantObject *recvObjForCC = recvMsgForCC->GetObject<RegedGiantObject>();
    ASSERT_NE(recvObjForCC, nullptr);
    EXPECT_EQ(dataLength, recvObjForCC->rawData_.size());

    // CleanUp
    delete recvMsgForCC;
    recvMsgForCC = nullptr;
    AdapterStub::DisconnectAdapterStub(g_envDeviceB.adapterHandle, g_envDeviceC.adapterHandle);
}

/**
 * @tc.name: Fragment 003
 * @tc.desc: Test fragmentation simultaneously
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: xiaozhenjian
 */
HWTEST_F(DistributedDBCommunicatorDeepTest, Fragment003, TestSize.Level3)
{
    // Preset
    std::atomic<int> count {0};
    OnMessageCallback callback = [&count](const std::string &srcTarget, Message *inMsg) {
        delete inMsg;
        inMsg = nullptr;
        count.fetch_add(1, std::memory_order_seq_cst);
        return E_OK;
    };
    g_commBB->RegOnMessageCallback(callback, nullptr);
    g_commBC->RegOnMessageCallback(callback, nullptr);

    /**
     * @tc.steps: step1. connect device A with device B, then device B with device C
     */
    AdapterStub::ConnectAdapterStub(g_envDeviceA.adapterHandle, g_envDeviceB.adapterHandle);
    AdapterStub::ConnectAdapterStub(g_envDeviceB.adapterHandle, g_envDeviceC.adapterHandle);
    std::this_thread::sleep_for(std::chrono::milliseconds(400)); // Wait 400 ms to make sure quiet

    /**
     * @tc.steps: step2. device A and device C simulate send block
     */
    g_envDeviceA.adapterHandle->SimulateSendBlock();
    g_envDeviceC.adapterHandle->SimulateSendBlock();

    /**
     * @tc.steps: step3. device A send message(registered and giant) to device B using communicator AB
     */
    uint32_t dataLength = 23 * 1024 * 1024; // 23 MB, 1024 is scale
    Message *sendMsgForAB = BuildRegedGiantMessage(dataLength);
    ASSERT_NE(sendMsgForAB, nullptr);
    SendConfig conf = {false, false, true, 0};
    int errCode = g_commAB->SendMessage(DEVICE_NAME_B, sendMsgForAB, conf);
    EXPECT_EQ(errCode, E_OK);

    /**
     * @tc.steps: step4. device C send message(registered and giant) to device B using communicator CC
     */
    Message *sendMsgForCC = BuildRegedGiantMessage(dataLength);
    ASSERT_NE(sendMsgForCC, nullptr);
    errCode = g_commCC->SendMessage(DEVICE_NAME_B, sendMsgForCC, conf);
    EXPECT_EQ(errCode, E_OK);

    /**
     * @tc.steps: step5. device A and device C not simulate send block
     * @tc.expected: step5. communicator BB and BV received the message
     */
    g_envDeviceA.adapterHandle->SimulateSendBlockClear();
    g_envDeviceC.adapterHandle->SimulateSendBlockClear();
    std::this_thread::sleep_for(std::chrono::milliseconds(9200)); // Wait 9200 ms to make sure send done
    EXPECT_EQ(count, 2); // 2 combined message received

    // CleanUp
    AdapterStub::DisconnectAdapterStub(g_envDeviceA.adapterHandle, g_envDeviceB.adapterHandle);
    AdapterStub::DisconnectAdapterStub(g_envDeviceB.adapterHandle, g_envDeviceC.adapterHandle);
}

/**
 * @tc.name: Fragment 004
 * @tc.desc: Test fragmentation in send and receive when rate limit
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: zhangqiquan
 */
HWTEST_F(DistributedDBCommunicatorDeepTest, Fragment004, TestSize.Level2)
{
    /**
     * @tc.steps: step1. connect device A with device B
     */
    Message *recvMsgForBB = nullptr;
    g_commBB->RegOnMessageCallback([&recvMsgForBB](const std::string &srcTarget, Message *inMsg) {
        recvMsgForBB = inMsg;
        return E_OK;
    }, nullptr);
    AdapterStub::ConnectAdapterStub(g_envDeviceA.adapterHandle, g_envDeviceB.adapterHandle);
    std::atomic<int> count = 0;
    g_envDeviceA.adapterHandle->ForkSendBytes([&count]() {
        count++;
        if (count % 3 == 0) { // retry each 3 packet
            return -E_WAIT_RETRY;
        }
        return E_OK;
    });
    /**
     * @tc.steps: step2. device A send message(registered and giant) to device B using communicator AB
     * @tc.expected: step2. communicator BB received the message
     */
    const uint32_t dataLength = 13 * 1024 * 1024; // 13 MB, 1024 is scale
    Message *sendMsg = BuildRegedGiantMessage(dataLength);
    ASSERT_NE(sendMsg, nullptr);
    SendConfig conf = {false, false, true, 0};
    int errCode = g_commAB->SendMessage(DEVICE_NAME_B, sendMsg, conf);
    EXPECT_EQ(errCode, E_OK);
    std::this_thread::sleep_for(std::chrono::seconds(1)); // Wait 1s to make sure send done
    g_envDeviceA.adapterHandle->SimulateSendRetry(DEVICE_NAME_B);
    g_envDeviceA.adapterHandle->SimulateSendRetryClear(DEVICE_NAME_B);
    int reTryTimes = 5;
    while (recvMsgForBB == nullptr && reTryTimes > 0) {
        std::this_thread::sleep_for(std::chrono::seconds(3));
        reTryTimes--;
    }
    ASSERT_NE(recvMsgForBB, nullptr);
    ASSERT_EQ(recvMsgForBB->GetMessageId(), REGED_GIANT_MSG_ID);
    /**
     * @tc.steps: step3. Compare received data with send data
     * @tc.expected: step3. equal
     */
    Message *oriMsgForAB = BuildRegedGiantMessage(dataLength);
    ASSERT_NE(oriMsgForAB, nullptr);
    auto *recvObjForBB = recvMsgForBB->GetObject<RegedGiantObject>();
    ASSERT_NE(recvObjForBB, nullptr);
    auto *oriObjForAB = oriMsgForAB->GetObject<RegedGiantObject>();
    ASSERT_NE(oriObjForAB, nullptr);
    bool isEqual = RegedGiantObject::CheckEqual(*oriObjForAB, *recvObjForBB);
    EXPECT_EQ(isEqual, true);
    g_envDeviceA.adapterHandle->ForkSendBytes(nullptr);

    // CleanUp
    AdapterStub::DisconnectAdapterStub(g_envDeviceA.adapterHandle, g_envDeviceB.adapterHandle);
    delete oriMsgForAB;
    oriMsgForAB = nullptr;
    delete recvMsgForBB;
    recvMsgForBB = nullptr;
}

namespace {
void ClearPreviousTestCaseInfluence()
{
    ReleaseAllCommunicator();
    AdapterStub::ConnectAdapterStub(g_envDeviceA.adapterHandle, g_envDeviceB.adapterHandle);
    AdapterStub::ConnectAdapterStub(g_envDeviceB.adapterHandle, g_envDeviceC.adapterHandle);
    AdapterStub::ConnectAdapterStub(g_envDeviceC.adapterHandle, g_envDeviceA.adapterHandle);
    std::this_thread::sleep_for(std::chrono::seconds(10)); // Wait 10 s to make sure all thread quiet
    AdapterStub::DisconnectAdapterStub(g_envDeviceA.adapterHandle, g_envDeviceB.adapterHandle);
    AdapterStub::DisconnectAdapterStub(g_envDeviceB.adapterHandle, g_envDeviceC.adapterHandle);
    AdapterStub::DisconnectAdapterStub(g_envDeviceC.adapterHandle, g_envDeviceA.adapterHandle);
    AllocAllCommunicator();
}
}

/**
 * @tc.name: ReliableOnline 001
 * @tc.desc: Test device online reliability
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: xiaozhenjian
 */
HWTEST_F(DistributedDBCommunicatorDeepTest, ReliableOnline001, TestSize.Level2)
{
    // Preset
    ClearPreviousTestCaseInfluence();
    std::atomic<int> count {0};
    OnConnectCallback callback = [&count](const std::string &target, bool isConnect) {
        if (isConnect) {
            count.fetch_add(1, std::memory_order_seq_cst);
        }
    };
    g_commAA->RegOnConnectCallback(callback, nullptr);
    g_commAB->RegOnConnectCallback(callback, nullptr);
    g_commBB->RegOnConnectCallback(callback, nullptr);
    g_commBC->RegOnConnectCallback(callback, nullptr);
    g_commCC->RegOnConnectCallback(callback, nullptr);
    g_commCA->RegOnConnectCallback(callback, nullptr);

    /**
     * @tc.steps: step1. device A and device B and device C simulate send total loss
     */
    g_envDeviceA.adapterHandle->SimulateSendTotalLoss();
    g_envDeviceB.adapterHandle->SimulateSendTotalLoss();
    g_envDeviceC.adapterHandle->SimulateSendTotalLoss();

    /**
     * @tc.steps: step2. connect device A with device B, device B with device C, device C with device A
     */
    AdapterStub::ConnectAdapterStub(g_envDeviceA.adapterHandle, g_envDeviceB.adapterHandle);
    AdapterStub::ConnectAdapterStub(g_envDeviceB.adapterHandle, g_envDeviceC.adapterHandle);
    AdapterStub::ConnectAdapterStub(g_envDeviceC.adapterHandle, g_envDeviceA.adapterHandle);

    /**
     * @tc.steps: step3. wait a long time
     * @tc.expected: step3. no communicator received the online callback
     */
    std::this_thread::sleep_for(std::chrono::seconds(7)); // Wait 7 s to make sure quiet
    EXPECT_EQ(count, 0); // no online callback received

    /**
     * @tc.steps: step4. device A and device B and device C not simulate send total loss
     */
    g_envDeviceA.adapterHandle->SimulateSendTotalLossClear();
    g_envDeviceB.adapterHandle->SimulateSendTotalLossClear();
    g_envDeviceC.adapterHandle->SimulateSendTotalLossClear();
    std::this_thread::sleep_for(std::chrono::seconds(7)); // Wait 7 s to make sure send done
    EXPECT_EQ(count, 6); // 6 online callback received in total

    // CleanUp
    AdapterStub::DisconnectAdapterStub(g_envDeviceA.adapterHandle, g_envDeviceB.adapterHandle);
    AdapterStub::DisconnectAdapterStub(g_envDeviceB.adapterHandle, g_envDeviceC.adapterHandle);
    AdapterStub::DisconnectAdapterStub(g_envDeviceC.adapterHandle, g_envDeviceA.adapterHandle);
}

/**
 * @tc.name: NetworkAdapter001
 * @tc.desc: Test networkAdapter start func
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: zhangqiquan
 */
HWTEST_F(DistributedDBCommunicatorDeepTest, NetworkAdapter001, TestSize.Level1)
{
    auto processCommunicator = std::make_shared<MockProcessCommunicator>();
    EXPECT_CALL(*processCommunicator, Stop()).WillRepeatedly(testing::Return(OK));
    /**
     * @tc.steps: step1. adapter start with empty label
     * @tc.expected: step1. start failed
     */
    auto adapter = std::make_shared<NetworkAdapter>("");
    EXPECT_EQ(adapter->StartAdapter(), -E_INVALID_ARGS);
    /**
     * @tc.steps: step2. adapter start with not empty label but processCommunicator is null
     * @tc.expected: step2. start failed
     */
    adapter = std::make_shared<NetworkAdapter>("label");
    EXPECT_EQ(adapter->StartAdapter(), -E_INVALID_ARGS);
    /**
     * @tc.steps: step3. processCommunicator start not ok
     * @tc.expected: step3. start failed
     */
    adapter = std::make_shared<NetworkAdapter>("label", processCommunicator);
    EXPECT_CALL(*processCommunicator, Start).WillRepeatedly(testing::Return(DB_ERROR));
    EXPECT_EQ(adapter->StartAdapter(), -E_PERIPHERAL_INTERFACE_FAIL);
    /**
     * @tc.steps: step4. processCommunicator reg not ok
     * @tc.expected: step4. start failed
     */
    EXPECT_CALL(*processCommunicator, Start).WillRepeatedly(testing::Return(OK));
    EXPECT_CALL(*processCommunicator, RegOnDataReceive).WillRepeatedly(testing::Return(DB_ERROR));
    EXPECT_EQ(adapter->StartAdapter(), -E_PERIPHERAL_INTERFACE_FAIL);
    EXPECT_CALL(*processCommunicator, RegOnDataReceive).WillRepeatedly(testing::Return(OK));
    EXPECT_CALL(*processCommunicator, RegOnDeviceChange).WillRepeatedly(testing::Return(DB_ERROR));
    EXPECT_EQ(adapter->StartAdapter(), -E_PERIPHERAL_INTERFACE_FAIL);
    /**
     * @tc.steps: step5. processCommunicator reg ok
     * @tc.expected: step5. start success
     */
    EXPECT_CALL(*processCommunicator, RegOnDeviceChange).WillRepeatedly(testing::Return(OK));
    EXPECT_CALL(*processCommunicator, GetLocalDeviceInfos).WillRepeatedly([]() {
        DeviceInfos deviceInfos;
        deviceInfos.identifier = "DEVICES_A"; // local is deviceA
        return deviceInfos;
    });
    EXPECT_CALL(*processCommunicator, GetRemoteOnlineDeviceInfosList).WillRepeatedly([]() {
        std::vector<DeviceInfos> res;
        DeviceInfos deviceInfos;
        deviceInfos.identifier = "DEVICES_A"; // search local is deviceA
        res.push_back(deviceInfos);
        deviceInfos.identifier = "DEVICES_B"; // search remote is deviceB
        res.push_back(deviceInfos);
        return res;
    });
    EXPECT_CALL(*processCommunicator, IsSameProcessLabelStartedOnPeerDevice).WillRepeatedly([](const DeviceInfos &) {
        return false;
    });
    EXPECT_EQ(adapter->StartAdapter(), E_OK);
    RuntimeContext::GetInstance()->StopTaskPool();
}

/**
 * @tc.name: NetworkAdapter002
 * @tc.desc: Test networkAdapter get mtu func
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: zhangqiquan
 */
HWTEST_F(DistributedDBCommunicatorDeepTest, NetworkAdapter002, TestSize.Level1)
{
    auto processCommunicator = std::make_shared<MockProcessCommunicator>();
    auto adapter = std::make_shared<NetworkAdapter>("label", processCommunicator);
    /**
     * @tc.steps: step1. processCommunicator return 0 mtu
     * @tc.expected: step1. adapter will adjust to min mtu
     */
    EXPECT_CALL(*processCommunicator, GetMtuSize).WillRepeatedly([]() {
        return 0u;
    });
    EXPECT_EQ(adapter->GetMtuSize(), DBConstant::MIN_MTU_SIZE);
    /**
     * @tc.steps: step2. processCommunicator return 2 max mtu
     * @tc.expected: step2. adapter will return min mtu util re make
     */
    EXPECT_CALL(*processCommunicator, GetMtuSize).WillRepeatedly([]() {
        return 2 * DBConstant::MAX_MTU_SIZE;
    });
    EXPECT_EQ(adapter->GetMtuSize(), DBConstant::MIN_MTU_SIZE);
    adapter = std::make_shared<NetworkAdapter>("label", processCommunicator);
    EXPECT_EQ(adapter->GetMtuSize(), DBConstant::MAX_MTU_SIZE);
}

/**
 * @tc.name: NetworkAdapter003
 * @tc.desc: Test networkAdapter get timeout func
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: zhangqiquan
 */
HWTEST_F(DistributedDBCommunicatorDeepTest, NetworkAdapter003, TestSize.Level1)
{
    auto processCommunicator = std::make_shared<MockProcessCommunicator>();
    auto adapter = std::make_shared<NetworkAdapter>("label", processCommunicator);
    /**
     * @tc.steps: step1. processCommunicator return 0 timeout
     * @tc.expected: step1. adapter will adjust to min timeout
     */
    EXPECT_CALL(*processCommunicator, GetTimeout).WillRepeatedly([]() {
        return 0u;
    });
    EXPECT_EQ(adapter->GetTimeout(), DBConstant::MIN_TIMEOUT);
    /**
     * @tc.steps: step2. processCommunicator return 2 max timeout
     * @tc.expected: step2. adapter will adjust to max timeout
     */
    EXPECT_CALL(*processCommunicator, GetTimeout).WillRepeatedly([]() {
        return 2 * DBConstant::MAX_TIMEOUT;
    });
    EXPECT_EQ(adapter->GetTimeout(), DBConstant::MAX_TIMEOUT);
}

/**
 * @tc.name: NetworkAdapter004
 * @tc.desc: Test networkAdapter send bytes func
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: zhangqiquan
 */
HWTEST_F(DistributedDBCommunicatorDeepTest, NetworkAdapter004, TestSize.Level1)
{
    auto processCommunicator = std::make_shared<MockProcessCommunicator>();
    auto adapter = std::make_shared<NetworkAdapter>("label", processCommunicator);

    EXPECT_CALL(*processCommunicator, SendData).WillRepeatedly([](const DeviceInfos &, const uint8_t *, uint32_t) {
        return OK;
    });
    /**
     * @tc.steps: step1. adapter send data with error param
     * @tc.expected: step1. adapter send failed
     */
    auto data = std::make_shared<uint8_t>(1u);
    EXPECT_EQ(adapter->SendBytes("DEVICES_B", nullptr, 1, 0), -E_INVALID_ARGS);
    EXPECT_EQ(adapter->SendBytes("DEVICES_B", data.get(), 0, 0), -E_INVALID_ARGS);
    /**
     * @tc.steps: step2. adapter send data with right param
     * @tc.expected: step2. adapter send ok
     */
    EXPECT_EQ(adapter->SendBytes("DEVICES_B", data.get(), 1, 0), E_OK);
    RuntimeContext::GetInstance()->StopTaskPool();
}

namespace {
void InitAdapter(const std::shared_ptr<NetworkAdapter> &adapter,
    const std::shared_ptr<MockProcessCommunicator> &processCommunicator,
    OnDataReceive &onDataReceive, OnDeviceChange &onDataChange)
{
    EXPECT_CALL(*processCommunicator, Stop).WillRepeatedly([]() {
        return OK;
    });
    EXPECT_CALL(*processCommunicator, Start).WillRepeatedly([](const std::string &) {
        return OK;
    });
    EXPECT_CALL(*processCommunicator, RegOnDataReceive).WillRepeatedly(
        [&onDataReceive](const OnDataReceive &callback) {
            onDataReceive = callback;
            return OK;
    });
    EXPECT_CALL(*processCommunicator, RegOnDeviceChange).WillRepeatedly(
        [&onDataChange](const OnDeviceChange &callback) {
            onDataChange = callback;
            return OK;
    });
    EXPECT_CALL(*processCommunicator, GetRemoteOnlineDeviceInfosList).WillRepeatedly([]() {
        std::vector<DeviceInfos> res;
        return res;
    });
    EXPECT_CALL(*processCommunicator, IsSameProcessLabelStartedOnPeerDevice).WillRepeatedly([](const DeviceInfos &) {
        return false;
    });
    EXPECT_EQ(adapter->StartAdapter(), E_OK);
}
}
/**
 * @tc.name: NetworkAdapter005
 * @tc.desc: Test networkAdapter receive data func
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: zhangqiquan
 */
HWTEST_F(DistributedDBCommunicatorDeepTest, NetworkAdapter005, TestSize.Level1)
{
    auto processCommunicator = std::make_shared<MockProcessCommunicator>();
    auto adapter = std::make_shared<NetworkAdapter>("label", processCommunicator);
    OnDataReceive onDataReceive;
    OnDeviceChange onDeviceChange;
    InitAdapter(adapter, processCommunicator, onDataReceive, onDeviceChange);
    ASSERT_NE(onDataReceive, nullptr);
    /**
     * @tc.steps: step1. adapter recv data with error param
     */
    auto data = std::make_shared<uint8_t>(1);
    DeviceInfos deviceInfos;
    onDataReceive(deviceInfos, nullptr, 1);
    onDataReceive(deviceInfos, data.get(), 0);
    /**
     * @tc.steps: step2. adapter recv data with no permission
     */
    EXPECT_CALL(*processCommunicator, GetDataHeadInfo).WillRepeatedly([](DataHeadInfo, uint32_t &) {
        return NO_PERMISSION;
    });
    onDataReceive(deviceInfos, data.get(), 1);
    EXPECT_CALL(*processCommunicator, GetDataHeadInfo).WillRepeatedly([](DataHeadInfo, uint32_t &) {
        return OK;
    });
    EXPECT_CALL(*processCommunicator, GetDataUserInfo).WillRepeatedly(
        [](DataUserInfo, std::vector<UserInfo> &userInfos) {
            UserInfo userId = {"1"};
            userInfos.emplace_back(userId);
            return OK;
    });
    /**
     * @tc.steps: step3. adapter recv data with no callback
     */
    onDataReceive(deviceInfos, data.get(), 1);
    adapter->RegBytesReceiveCallback([](const ReceiveBytesInfo &, const DataUserInfoProc &) {
    }, nullptr);
    onDataReceive(deviceInfos, data.get(), 1);
    RuntimeContext::GetInstance()->StopTaskPool();
}

/**
 * @tc.name: NetworkAdapter006
 * @tc.desc: Test networkAdapter device change func
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: zhangqiquan
 */
HWTEST_F(DistributedDBCommunicatorDeepTest, NetworkAdapter006, TestSize.Level1)
{
    auto processCommunicator = std::make_shared<MockProcessCommunicator>();
    auto adapter = std::make_shared<NetworkAdapter>("label", processCommunicator);
    OnDataReceive onDataReceive;
    OnDeviceChange onDeviceChange;
    InitAdapter(adapter, processCommunicator, onDataReceive, onDeviceChange);
    ASSERT_NE(onDeviceChange, nullptr);
    DeviceInfos deviceInfos;
    /**
     * @tc.steps: step1. onDeviceChange with no same process
     */
    onDeviceChange(deviceInfos, true);
    /**
     * @tc.steps: step2. onDeviceChange with same process
     */
    EXPECT_CALL(*processCommunicator, IsSameProcessLabelStartedOnPeerDevice).WillRepeatedly([](const DeviceInfos &) {
        return true;
    });
    onDeviceChange(deviceInfos, true);
    adapter->RegTargetChangeCallback([](const std::string &, bool) {
    }, nullptr);
    onDeviceChange(deviceInfos, false);
    /**
     * @tc.steps: step3. adapter send data with db_error
     * @tc.expected: step3. adapter send failed
     */
    onDeviceChange(deviceInfos, true);
    EXPECT_CALL(*processCommunicator, SendData).WillRepeatedly([](const DeviceInfos &, const uint8_t *, uint32_t) {
        return DB_ERROR;
    });
    EXPECT_CALL(*processCommunicator, IsSameProcessLabelStartedOnPeerDevice).WillRepeatedly([](const DeviceInfos &) {
        return false;
    });
    auto data = std::make_shared<uint8_t>(1);
    EXPECT_EQ(adapter->SendBytes("", data.get(), 1, 0), static_cast<int>(DB_ERROR));
    RuntimeContext::GetInstance()->StopTaskPool();
    EXPECT_EQ(adapter->IsDeviceOnline(""), false);
    ExtendInfo info;
    EXPECT_EQ(adapter->GetExtendHeaderHandle(info), nullptr);
}

/**
 * @tc.name: NetworkAdapter007
 * @tc.desc: Test networkAdapter recv invalid head length
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: zhangqiquan
 */
HWTEST_F(DistributedDBCommunicatorDeepTest, NetworkAdapter007, TestSize.Level1)
{
    auto processCommunicator = std::make_shared<MockProcessCommunicator>();
    auto adapter = std::make_shared<NetworkAdapter>("NetworkAdapter007", processCommunicator);
    OnDataReceive onDataReceive;
    OnDeviceChange onDeviceChange;
    InitAdapter(adapter, processCommunicator, onDataReceive, onDeviceChange);
    ASSERT_NE(onDeviceChange, nullptr);
    /**
     * @tc.steps: step1. GetDataHeadInfo return invalid headLen
     * @tc.expected: step1. adapter check this len
     */
    EXPECT_CALL(*processCommunicator, GetDataHeadInfo).WillOnce([](DataHeadInfo, uint32_t &headLen) {
        headLen = UINT32_MAX;
        return OK;
    });
    /**
     * @tc.steps: step2. Adapter ignore data because len is too large
     * @tc.expected: step2. BytesReceive never call
     */
    int callByteReceiveCount = 0;
    int res = adapter->RegBytesReceiveCallback([&callByteReceiveCount](const ReceiveBytesInfo &,
        const DataUserInfoProc &) {
            LOGD("callByteReceiveCount++;");
        callByteReceiveCount++;
    }, nullptr);
    EXPECT_EQ(res, E_OK);
    std::vector<uint8_t> data = { 1u };
    DeviceInfos deviceInfos;
    onDataReceive(deviceInfos, data.data(), 1u);
    LOGD("callByteReceiveCount++%d;", callByteReceiveCount);
    EXPECT_EQ(callByteReceiveCount, 0);
}

/**
 * @tc.name: RetrySendExceededLimit001
 * @tc.desc: Test send result when the number of retry times exceeds the limit
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: suyue
 */
HWTEST_F(DistributedDBCommunicatorDeepTest, RetrySendExceededLimit001, TestSize.Level2)
{
    /**
     * @tc.steps: step1. connect device A with device B and fork SendBytes
     * @tc.expected: step1. operation OK
     */
    AdapterStub::ConnectAdapterStub(g_envDeviceA.adapterHandle, g_envDeviceB.adapterHandle);
    std::atomic<int> count = 0;
    g_envDeviceA.adapterHandle->ForkSendBytes([&count]() {
        count++;
        return -E_WAIT_RETRY;
    });

    /**
     * @tc.steps: step2. the number of retry times for device A to send a message exceeds the limit
     * @tc.expected: step2. sendResult fail
     */
    std::vector<std::pair<int, bool>> sendResult;
    auto sendResultNotifier = [&sendResult](int result, bool isDirectEnd) {
        sendResult.push_back(std::pair<int, bool>(result, isDirectEnd));
    };
    const uint32_t dataLength = 13 * 1024 * 1024; // 13 MB, 1024 is scale
    Message *sendMsg = BuildRegedGiantMessage(dataLength);
    ASSERT_NE(sendMsg, nullptr);
    SendConfig conf = {false, false, true, 0};
    int errCode = g_commAB->SendMessage(DEVICE_NAME_B, sendMsg, conf, sendResultNotifier);
    EXPECT_EQ(errCode, E_OK);
    std::this_thread::sleep_for(std::chrono::seconds(1)); // Wait 1s to make sure send done
    g_envDeviceA.adapterHandle->SimulateSendRetry(DEVICE_NAME_B);
    g_envDeviceA.adapterHandle->SimulateSendRetryClear(DEVICE_NAME_B, -E_BASE);
    int reTryTimes = 5;
    while ((count < 4) && (reTryTimes > 0)) { // Wait to make sure retry exceeds the limit
        std::this_thread::sleep_for(std::chrono::seconds(3));
        reTryTimes--;
    }
    ASSERT_EQ(sendResult.size(), static_cast<size_t>(1)); // only one callback result notification
    EXPECT_EQ(sendResult[0].first, -E_BASE); // index 0 retry fail
    EXPECT_EQ(sendResult[0].second, false);

    g_envDeviceA.adapterHandle->ForkSendBytes(nullptr);
    AdapterStub::DisconnectAdapterStub(g_envDeviceA.adapterHandle, g_envDeviceB.adapterHandle);
}

/**
 * @tc.name: RetrySendExceededLimit002
 * @tc.desc: Test multi thread call SendableCallback when the number of retry times exceeds the limit
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: suyue
 */
HWTEST_F(DistributedDBCommunicatorDeepTest, RetrySendExceededLimit002, TestSize.Level2)
{
    /**
     * @tc.steps: step1. DeviceA send SendMessage and set SendBytes interface return -E_WAIT_RETRY
     * @tc.expected: step1. Send ok
     */
    AdapterStub::ConnectAdapterStub(g_envDeviceA.adapterHandle, g_envDeviceB.adapterHandle);
    std::atomic<int> count = 0;
    g_envDeviceA.adapterHandle->ForkSendBytes([&count]() {
        count++;
        return -E_WAIT_RETRY;
    });
    std::vector<std::pair<int, bool>> sendResult;
    auto sendResultNotifier = [&sendResult](int result, bool isDirectEnd) {
        sendResult.push_back(std::pair<int, bool>(result, isDirectEnd));
    };
    const uint32_t dataLength = 13 * 1024 * 1024; // 13 MB, 1024 is scale
    Message *sendMsg = BuildRegedGiantMessage(dataLength);
    ASSERT_NE(sendMsg, nullptr);
    SendConfig conf = {false, false, true, 0};
    EXPECT_EQ(g_commAB->SendMessage(DEVICE_NAME_B, sendMsg, conf, sendResultNotifier), E_OK);
    std::this_thread::sleep_for(std::chrono::seconds(1)); // Wait 1s to make sure send done

    /**
     * @tc.steps: step2. Triggering multi thread call SendableCallback interface and set errorCode
     * @tc.expected: step2. Callback success
     */
    std::vector<std::thread> threads;
    int threadNum = 3;
    threads.reserve(threadNum);
    for (int n = 0; n < threadNum; n++) {
        threads.emplace_back([&]() {
            g_envDeviceA.adapterHandle->SimulateTriggerSendableCallback(DEVICE_NAME_B, -E_BASE);
        });
    }
    for (std::thread &t : threads) {
        t.join();
    }

    /**
     * @tc.steps: step3. Make The number of messages sent by device A exceed the limit
     * @tc.expected: step3. SendResult is the errorCode set by SendableCallback interface
     */
    int reTryTimes = 5;
    while ((count < 4) && (reTryTimes > 0)) {
        std::this_thread::sleep_for(std::chrono::seconds(3));
        reTryTimes--;
    }
    ASSERT_EQ(sendResult.size(), static_cast<size_t>(1));
    EXPECT_EQ(sendResult[0].first, -E_BASE);
    EXPECT_EQ(sendResult[0].second, false);
    g_envDeviceA.adapterHandle->ForkSendBytes(nullptr);
    AdapterStub::DisconnectAdapterStub(g_envDeviceA.adapterHandle, g_envDeviceB.adapterHandle);
}

/**
 * @tc.name: AllocBufferByPayloadLengthTest001
 * @tc.desc: Test AllocBufferByPayloadLength func
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: tiansimiao
 */
HWTEST_F(DistributedDBCommunicatorDeepTest, AllocBufferByPayloadLengthTest001, TestSize.Level2)
{
    SerialBuffer buffer;
    EXPECT_EQ(buffer.AllocBufferByPayloadLength(100, 20), E_OK);
    EXPECT_EQ(buffer.AllocBufferByPayloadLength(100, 20), -E_NOT_PERMIT);
}

/**
 * @tc.name: AllocBufferByPayloadLengthTest002
 * @tc.desc: Test AllocBufferByPayloadLength func
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: tiansimiao
 */
HWTEST_F(DistributedDBCommunicatorDeepTest, AllocBufferByPayloadLengthTest002, TestSize.Level2)
{
    SerialBuffer buffer;
    uint32_t payloadLen = INT32_MAX - 1;
    uint32_t headerLen = 10;
    EXPECT_EQ(buffer.AllocBufferByPayloadLength(payloadLen, headerLen), -E_INVALID_ARGS);
}

/**
 * @tc.name: AllocBufferByPayloadLengthTest003
 * @tc.desc: Test AllocBufferByPayloadLength func
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: tiansimiao
 */
HWTEST_F(DistributedDBCommunicatorDeepTest, AllocBufferByPayloadLengthTest003, TestSize.Level2)
{
    SerialBuffer buffer;
    const uint8_t externalBuff[100] = {0};
    int ret = buffer.SetExternalBuff(externalBuff, 100, 20);
    EXPECT_EQ(E_OK, ret);
    EXPECT_EQ(buffer.AllocBufferByPayloadLength(100, 20), -E_NOT_PERMIT);
}

/**
 * @tc.name: AllocBufferByTotalLengthTest001
 * @tc.desc: Test AllocBufferByPayloadLength func
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: tiansimiao
 */
HWTEST_F(DistributedDBCommunicatorDeepTest, AllocBufferByTotalLengthTest001, TestSize.Level2)
{
    SerialBuffer buffer;
    uint32_t payloadLen = 100;
    uint32_t headerLen = 20;
    buffer.AllocBufferByPayloadLength(payloadLen, headerLen);
    EXPECT_EQ(buffer.AllocBufferByTotalLength(100, 20), -E_NOT_PERMIT);
}

/**
 * @tc.name: AllocBufferByTotalLengthTest002
 * @tc.desc: Test AllocBufferByPayloadLength func
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: tiansimiao
 */
HWTEST_F(DistributedDBCommunicatorDeepTest, AllocBufferByTotalLengthTest002, TestSize.Level2)
{
    SerialBuffer buffer;
    const uint8_t* externalBuff = new(std::nothrow) uint8_t[100];
    ASSERT_NE(externalBuff, nullptr);
    uint8_t tempArray[100] = {0};
    EXPECT_EQ(memcpy_s(const_cast<uint8_t*>(externalBuff), 100, tempArray, 100), E_OK);
    buffer.SetExternalBuff(externalBuff, 100, 20);
    EXPECT_EQ(buffer.AllocBufferByTotalLength(100, 20), -E_NOT_PERMIT);
    delete[] externalBuff;
    externalBuff = nullptr;
}

/**
 * @tc.name: AllocBufferByTotalLengthTest003
 * @tc.desc: Test AllocBufferByPayloadLength func
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: tiansimiao
 */
HWTEST_F(DistributedDBCommunicatorDeepTest, AllocBufferByTotalLengthTest003, TestSize.Level2)
{
    SerialBuffer buffer;
    EXPECT_EQ(buffer.AllocBufferByTotalLength(0, 20), -E_INVALID_ARGS);
    EXPECT_EQ(buffer.AllocBufferByTotalLength(MAX_TOTAL_LEN + 1, 20), -E_INVALID_ARGS);
    EXPECT_EQ(buffer.AllocBufferByTotalLength(5, 10), -E_INVALID_ARGS);
}

/**
 * @tc.name: SetExternalBuffTest001
 * @tc.desc: Test SetExternalBuff func
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: tiansimiao
 */
HWTEST_F(DistributedDBCommunicatorDeepTest, SetExternalBuffTest001, TestSize.Level2)
{
    SerialBuffer buffer;
    uint32_t payloadLen = 100;
    uint32_t headerLen = 20;
    buffer.AllocBufferByPayloadLength(payloadLen, headerLen);
    const uint8_t* externalBuff = new(std::nothrow) uint8_t[100];
    ASSERT_NE(externalBuff, nullptr);
    EXPECT_EQ(buffer.SetExternalBuff(externalBuff, 100, 20), -E_NOT_PERMIT);
    delete[] externalBuff;
    externalBuff = nullptr;
}

/**
 * @tc.name: SetExternalBuffTest002
 * @tc.desc: Test SetExternalBuff func
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: tiansimiao
 */
HWTEST_F(DistributedDBCommunicatorDeepTest, SetExternalBuffTest002, TestSize.Level2)
{
    SerialBuffer buffer;
    const uint8_t* externalBuff = new(std::nothrow) uint8_t[100];
    ASSERT_NE(externalBuff, nullptr);
    buffer.SetExternalBuff(externalBuff, 100, 20);
    EXPECT_EQ(buffer.SetExternalBuff(externalBuff, 100, 20), -E_NOT_PERMIT);
    delete[] externalBuff;
    externalBuff = nullptr;
}

/**
 * @tc.name: SetExternalBuffTest003
 * @tc.desc: Test SetExternalBuff func
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: tiansimiao
 */
HWTEST_F(DistributedDBCommunicatorDeepTest, SetExternalBuffTest003, TestSize.Level2)
{
    SerialBuffer buffer;
    EXPECT_EQ(buffer.SetExternalBuff(nullptr, 100, 20), -E_INVALID_ARGS);
    const uint8_t* externalBuff = new(std::nothrow) uint8_t[100];
    ASSERT_NE(externalBuff, nullptr);
    uint8_t tempArrayA[100] = {0};
    EXPECT_EQ(memcpy_s(const_cast<uint8_t*>(externalBuff), 100, tempArrayA, 100), E_OK);
    EXPECT_EQ(buffer.SetExternalBuff(externalBuff, 0, 20), -E_INVALID_ARGS);
    delete[] externalBuff;
    externalBuff = nullptr;
    externalBuff = new(std::nothrow) uint8_t[MAX_TOTAL_LEN + 1];
    ASSERT_NE(externalBuff, nullptr);
    EXPECT_EQ(buffer.SetExternalBuff(externalBuff, MAX_TOTAL_LEN + 1, 20), -E_INVALID_ARGS);
    delete[] externalBuff;
    externalBuff = nullptr;
    externalBuff = new(std::nothrow) uint8_t[10];
    ASSERT_NE(externalBuff, nullptr);
    uint8_t tempArrayB[10] = {0};
    EXPECT_EQ(memcpy_s(const_cast<uint8_t*>(externalBuff), 10, tempArrayB, 10), E_OK);
    EXPECT_EQ(buffer.SetExternalBuff(externalBuff, 5, 10), -E_INVALID_ARGS);
    delete[] externalBuff;
    externalBuff = nullptr;
}

/**
 * @tc.name: SerialBufferCloneTest001
 * @tc.desc: Test invalid args of Clone function
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: tiansimiao
 */
HWTEST_F(DistributedDBCommunicatorDeepTest, SerialBufferCloneTest001, TestSize.Level2)
{
    SerialBuffer buffer;
    int errorNo = 0;
    SerialBuffer* clone_ = buffer.Clone(errorNo);
    EXPECT_EQ(clone_, nullptr);
    EXPECT_EQ(errorNo, -E_INVALID_ARGS);
}

/**
 * @tc.name: ConvertForCrossThreadTest001
 * @tc.desc: Test invalid args of ConvertForCrossThread function
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: tiansimiao
 */
HWTEST_F(DistributedDBCommunicatorDeepTest, ConvertForCrossThreadTest001, TestSize.Level2)
{
    SerialBuffer buffer;
    EXPECT_EQ(buffer.ConvertForCrossThread(), -E_INVALID_ARGS);
}

/**
 * @tc.name: GetSizeTest001
 * @tc.desc: Test GetSize function
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: tiansimiao
 */
HWTEST_F(DistributedDBCommunicatorDeepTest, GetSizeTest001, TestSize.Level2)
{
    SerialBuffer buffer;
    EXPECT_EQ(buffer.GetSize(), 0);
}

/**
 * @tc.name: GetWritableBytesTest001
 * @tc.desc: Test GetWritableBytesForEntireBuffer and EntireFrame and Header and Payload function
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: tiansimiao
 */
HWTEST_F(DistributedDBCommunicatorDeepTest, GetWritableBytesTest001, TestSize.Level2)
{
    SerialBuffer buffer;
    EXPECT_EQ(buffer.GetWritableBytesForEntireBuffer().first, nullptr);
    EXPECT_EQ(buffer.GetWritableBytesForEntireBuffer().second, 0);
    EXPECT_EQ(buffer.GetWritableBytesForEntireFrame().first, nullptr);
    EXPECT_EQ(buffer.GetWritableBytesForEntireFrame().second, 0);
    EXPECT_EQ(buffer.GetWritableBytesForHeader().first, nullptr);
    EXPECT_EQ(buffer.GetWritableBytesForHeader().second, 0);
    EXPECT_EQ(buffer.GetWritableBytesForPayload().first, nullptr);
    EXPECT_EQ(buffer.GetWritableBytesForPayload().second, 0);
}

/**
 * @tc.name: GetWritableBytesTest002
 * @tc.desc: Test GetWritableBytesForEntireBuffer function
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: tiansimiao
 */
HWTEST_F(DistributedDBCommunicatorDeepTest, GetWritableBytesTest002, TestSize.Level2)
{
    SerialBuffer buffer;
    uint32_t payloadLen = 100;
    uint32_t headerLen = 20;
    EXPECT_EQ(buffer.AllocBufferByPayloadLength(payloadLen, headerLen), E_OK);
    EXPECT_NE(buffer.GetWritableBytesForEntireBuffer().first, nullptr);
    EXPECT_EQ(buffer.GetWritableBytesForEntireBuffer().second, buffer.GetSize());
}

/**
 * @tc.name: GetReadOnlyBytesTest001
 * @tc.desc: Test GetReadOnlyBytesForEntireBuffer and EntireFrame and Header and Payload function
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: tiansimiao
 */
HWTEST_F(DistributedDBCommunicatorDeepTest, GetReadOnlyBytesTest001, TestSize.Level2)
{
    SerialBuffer buffer;
    EXPECT_EQ(buffer.GetReadOnlyBytesForEntireBuffer().first, nullptr);
    EXPECT_EQ(buffer.GetReadOnlyBytesForEntireBuffer().second, 0);
    EXPECT_EQ(buffer.GetReadOnlyBytesForEntireFrame().first, nullptr);
    EXPECT_EQ(buffer.GetReadOnlyBytesForEntireFrame().second, 0);
    EXPECT_EQ(buffer.GetReadOnlyBytesForHeader().first, nullptr);
    EXPECT_EQ(buffer.GetReadOnlyBytesForHeader().second, 0);
    EXPECT_EQ(buffer.GetReadOnlyBytesForPayload().first, nullptr);
    EXPECT_EQ(buffer.GetReadOnlyBytesForPayload().second, 0);
}

/**
 * @tc.name: GetReadOnlyBytesTest002
 * @tc.desc: Test GetReadOnlyBytesForHeader function
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: tiansimiao
 */
HWTEST_F(DistributedDBCommunicatorDeepTest, GetReadOnlyBytesTest002, TestSize.Level2)
{
    SerialBuffer buffer;
    uint32_t payloadLen = 100;
    uint32_t headerLen = 20;
    EXPECT_EQ(buffer.AllocBufferByPayloadLength(payloadLen, headerLen), E_OK);
    EXPECT_NE(buffer.GetReadOnlyBytesForHeader().first, nullptr);
    EXPECT_NE(buffer.GetReadOnlyBytesForHeader().second, 0);
}

/**
 * @tc.name: DoOnSendEndByTaskIfNeedTest001
 * @tc.desc: Test DoOnSendEndByTaskIfNeed function
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: tiansimiao
 */
HWTEST_F(DistributedDBCommunicatorDeepTest, DoOnSendEndByTaskIfNeedTest001, TestSize.Level1)
{
    std::string dstTarget = DEVICE_NAME_B;
    FrameType inType = FrameType::APPLICATION_MESSAGE;
    TaskConfig config;
    config.nonBlock = true;
    config.isRetryTask = false;
    config.timeout = 1000;
    OnSendEnd onEnd = nullptr;
    const std::shared_ptr<DBStatusAdapter> statusAdapter = std::make_shared<DBStatusAdapter>();
    ASSERT_NE(statusAdapter, nullptr);
    auto adapterStub = std::make_shared<AdapterStub>("");
    IAdapter *adapterPtr = adapterStub.get();
    ASSERT_NE(adapterPtr, nullptr);
    auto aggregator = std::make_unique<CommunicatorAggregator>();
    ASSERT_NE(aggregator, nullptr);
    EXPECT_EQ(aggregator->Initialize(adapterPtr, statusAdapter), E_OK);
    DistributedDB::SerialBuffer *inBuff = new (std::nothrow) SerialBuffer();
    ASSERT_NE(inBuff, nullptr);
    EXPECT_EQ(aggregator->ScheduleSendTask(dstTarget, inBuff, inType, config, onEnd), E_OK);
    inBuff = nullptr; // inBuff was deleted in ScheduleSendTask func
    aggregator->Finalize();
}

/**
 * @tc.name: DoOnSendEndByTaskIfNeedTest002
 * @tc.desc: Test DoOnSendEndByTaskIfNeed function
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: tiansimiao
 */
HWTEST_F(DistributedDBCommunicatorDeepTest, DoOnSendEndByTaskIfNeedTest002, TestSize.Level1)
{
    std::string dstTarget = DEVICE_NAME_B;
    FrameType inType = FrameType::APPLICATION_MESSAGE;
    TaskConfig config;
    config.nonBlock = true;
    config.isRetryTask = false;
    config.timeout = 1000;
    OnSendEnd onEnd = [](int result, bool isDirectEnd) {
        LOGD("OnSendEnd called with result: %d, isDirectEnd: %d", result, isDirectEnd);
    };
    const std::shared_ptr<DBStatusAdapter> statusAdapter = std::make_shared<DBStatusAdapter>();
    ASSERT_NE(statusAdapter, nullptr);
    auto adapterStub = std::make_shared<AdapterStub>("");
    IAdapter *adapterPtr = adapterStub.get();
    ASSERT_NE(adapterPtr, nullptr);
    auto aggregator = std::make_unique<CommunicatorAggregator>();
    ASSERT_NE(aggregator, nullptr);
    EXPECT_EQ(aggregator->Initialize(adapterPtr, statusAdapter), E_OK);
    DistributedDB::SerialBuffer *inBuff = new (std::nothrow) SerialBuffer();
    ASSERT_NE(inBuff, nullptr);
    EXPECT_EQ(aggregator->ScheduleSendTask(dstTarget, inBuff, inType, config, onEnd), E_OK);
    inBuff = nullptr; // inBuff was deleted in ScheduleSendTask func
    aggregator->Finalize();
}

void TriggerSendMsg(const std::shared_ptr<CommunicatorAggregator> &aggregator, const OnSendEnd &onEnd)
{
    Message *msg = BuildRegedTinyMessage();
    ASSERT_NE(msg, nullptr);
    int error = E_OK;
    // if error is not E_OK , null pointer will be returned
    std::shared_ptr<ExtendHeaderHandle> extendHandle;
    SerialBuffer *buffer = ProtocolProto::ToSerialBuffer(msg, extendHandle, false, error);
    ASSERT_NE(buffer, nullptr);
    std::string dstTarget = DEVICE_NAME_B;
    FrameType inType = FrameType::APPLICATION_MESSAGE;
    TaskConfig config;
    config.timeout = 1000; // timeout is 1000ms
    error = aggregator->ScheduleSendTask(dstTarget, buffer, inType, config, onEnd);
    if (error == E_OK) {
        delete msg;
        msg = nullptr;
    } else {
        delete buffer;
        buffer = nullptr;
    }
}

/**
 * @tc.name: SendFailed001
 * @tc.desc: Test send data failed.
 * @tc.type: FUNC
 * @tc.author: zqq
 */
HWTEST_F(DistributedDBCommunicatorDeepTest, SendFailed001, TestSize.Level0)
{
    std::condition_variable cv;
    std::mutex endMutex;
    bool sendEnd = false;
    OnSendEnd onEnd = [&cv, &endMutex, &sendEnd](int, bool) {
        std::lock_guard<std::mutex> autoLock(endMutex);
        sendEnd = true;
        cv.notify_all();
    };
    const std::shared_ptr<DBStatusAdapter> statusAdapter = std::make_shared<DBStatusAdapter>();
    ASSERT_NE(statusAdapter, nullptr);
    auto adapterStub = std::make_shared<AdapterStub>(DEVICE_NAME_A);
    std::atomic<int> count;
    adapterStub->ForkSendBytes([&count]() {
        int current = count++;
        return current == 0 ? -E_WAIT_RETRY : -E_INTERNAL_ERROR;
    });

    IAdapter *adapterPtr = adapterStub.get();
    ASSERT_NE(adapterPtr, nullptr);
    auto aggregator = std::make_shared<CommunicatorAggregator>();
    ASSERT_NE(aggregator, nullptr);
    EXPECT_EQ(aggregator->Initialize(adapterPtr, statusAdapter), E_OK);
    ResFinalizer finalizer([aggregator]() {
        aggregator->Finalize();
    });
    ASSERT_NO_FATAL_FAILURE(TriggerSendMsg(aggregator, onEnd));
    LOGI("[SendFailed001] Begin wait send end");
    std::unique_lock<std::mutex> uniqueLock(endMutex);
    cv.wait_for(uniqueLock, std::chrono::seconds(5), [&sendEnd]() { // wait max 5s
        return sendEnd;
    });
    LOGI("[SendFailed001] End wait send end");
    EXPECT_EQ(aggregator->GetRetryCount(DEVICE_NAME_B), 0);
    EXPECT_EQ(aggregator->GetRetryCount(DEVICE_NAME_A), 0);
}