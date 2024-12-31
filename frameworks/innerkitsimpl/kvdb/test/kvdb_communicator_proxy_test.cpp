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

#include "communicator_proxy.h"
#include "db_constant.h"
#include "distributeddb_tools_unit_test.h"
#include "kv_store_nb_delegate.h"
#include "mock_communicator.h"
#include "virtual_communicator_aggregator.h"

using namespace testing::ext;
using namespace testing;
using namespace DistributedDB;
using namespace DistributedDBUnitTest;
using namespace std;

namespace {
    string g_testDir;
    const string STORE_ID = "kv_store_sync_test";
    const std::string DEVICE_B = "deviceB";
    const std::string DEVICE_C = "deviceC";
    const std::string DEVICE_D = "deviceD";
    const std::string DEVICE_E = "deviceE";


    KvStoreDelegateManager g_mgr(APP_ID, USER_ID);
    KvStoreConfig g_config;
    KvDBToolsUnitTest g_tool;
    DBStatus g_DelegateStatus = INVALID_ARGS;
    KvStoreNbDelegate* g_kvDelegatePtr = nullptr;

    // the type of g_kvDelegateCallback is function<void(DBStatus, KvStoreDelegate*)>
    auto g_kvDelegateCallback = bind(&KvDBToolsUnitTest::KvStoreNbDelegateCallback,
        placeholders::_1, placeholders::_2, std::ref(g_DelegateStatus), std::ref(g_kvDelegatePtr));
}

class KvDBCommunicatorProxyTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

protected:
    MockCommunicator extComm;
    MockCommunicator mainComm;
    CommunicatorProxy *commProxy = nullptr;
};

void KvDBCommunicatorProxyTest::SetUpTestCase(void)
{
    /**
     * @tc.setup: Init datadir and Virtual Communicator.
     */
    KvDBToolsUnitTest::TestDirInit(g_testDir);
    g_config.dataDir = g_testDir;
    g_mgr.SetKvStoreConfig(g_config);

    string dir = g_testDir + "/single_ver";
    DIR* tmp = opendir(dir.c_str());
    if (tmp == nullptr) {
        OS::MakeDBDirectory(dir);
    } else {
        closedir(tmp);
    }

    auto communicatorAggregator = new (std::nothrow) VirtualCommunicatorAggregator();
    ASSERT_TRUE(communicatorAggregator != nullptr);
    RuntimeContext::GetInstance()->SetCommunicatorAggregator(communicatorAggregator);
}

void KvDBCommunicatorProxyTest::TearDownTestCase(void)
{
    /**
     * @tc.teardown: Release virtual Communicator and clear data dir.
     */
    if (KvDBToolsUnitTest::RemoveTestDbFiles(g_testDir) != 0) {
        LOGE("rm test db files error!");
    }
    RuntimeContext::GetInstance()->SetCommunicatorAggregator(nullptr);
}

void KvDBCommunicatorProxyTest::SetUp(void)
{
    KvDBToolsUnitTest::PrintTestCaseInfo();
    /**
     * @tc.setup: Get a KvStoreNbDelegate and init the CommunicatorProxy
     */
    KvStoreNbDelegate::Option option;
    g_mgr.GetKvStore(STORE_ID, option, g_kvDelegateCallback);
    std::string identifier2 = g_mgr.GetKvStoreIdentifier(USER_ID, APP_ID, STORE_ID);
    ASSERT_TRUE(g_DelegateStatus == OK);
    ASSERT_TRUE(g_kvDelegatePtr != nullptr);
    commProxy = new (std::nothrow) CommunicatorProxy();
    ASSERT_TRUE(commProxy != nullptr);
    commProxy->SetMainCommunicator(&mainComm);
    commProxy->SetEqualCommunicator(&extComm, identifier2, { DEVICE_C });
}

void KvDBCommunicatorProxyTest::TearDown(void)
{
    /**
     * @tc.teardown: Release the KvStoreNbDelegate and CommunicatorProxy
     */
    if (g_kvDelegatePtr != nullptr) {
        EXCEPT_EQ(g_mgr.CloseKvStore(g_kvDelegatePtr), OK);
        g_kvDelegatePtr = nullptr;
        DBStatus status = g_mgr.DeleteKvStore(STORE_ID);
        LOGD("delete kv store status %d", status);
        ASSERT_TRUE(status == OK);
    }
    if (commProxy != nullptr) {
        RefObject::DecObjRef(commProxy);
    }
    commProxy = nullptr;
}

/**
 * @tc.name: Interface set equal 001
 * @tc.desc: Test set equal identifier2 from interface.
 * @tc.type: FUNC
 * @tc.require: AR000F4GVG
 * @tc.author: xushaohua
 */
HWTEST_F(KvDBCommunicatorProxyTest, SetEqualId001, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Call GetKvStoreIdentifier to make a store identifier2.
     */
    std::string identifier2 = g_mgr.GetKvStoreIdentifier("default", APP_ID, STORE_ID);

    /**
     * @tc.steps: step2. Call SetEqualIdentifier to set the store identifier2 B, D, E.
     * @tc.expected: step2. SetEqualIdentifier return OK.
     */
    DBStatus status = g_kvDelegatePtr->SetEqualIdentifier(identifier2, { DEVICE_B, DEVICE_D, DEVICE_E });
    EXPECT_EQ(status, DBStatus::OK);

    /**
     * @tc.steps: step2. Call SetEqualIdentifier to set the store identifier2 B.
     * @tc.expected: step2. SetEqualIdentifier return OK and D, E will offline.
     */
    status = g_kvDelegatePtr->SetEqualIdentifier(identifier2, { DEVICE_B });
    EXPECT_EQ(status, DBStatus::OK);
}

/**
 * @tc.name: Interface set equal 002
 * @tc.desc: Test different user set same equal identifier2
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: liaoyonghuang
 */
HWTEST_F(KvDBCommunicatorProxyTest, SetEqualId002, TestSize.Level0)
{
    /**
     * @tc.steps: step1. Get DB of user1
     * @tc.expected: step1. OK.
     */
    std::string userId1 = "user1";
    KvStoreDelegateManager mgr1(APP_ID, userId1);
    KvStoreNbDelegate *delegate1 = nullptr;
    auto delegate1Callback = bind(&KvDBToolsUnitTest::KvStoreNbDelegateCallback,
        placeholders::_1, placeholders::_2, std::ref(g_DelegateStatus), std::ref(delegate1));
    KvStoreNbDelegate::Option option;
    mgr1.SetKvStoreConfig(g_config);
    mgr1.GetKvStore(STORE_ID, option, delegate1Callback);
    ASSERT_TRUE(g_DelegateStatus == OK);
    ASSERT_TRUE(delegate1 != nullptr);
    /**
     * @tc.steps: step2. Get identifier2 with syncDualTupleMode
     * @tc.expected: step2. OK.
     */
    std::string identifier2 = g_mgr.GetKvStoreIdentifier(USER_ID, APP_ID, STORE_ID, true);
    std::string identifier1 = mgr1.GetKvStoreIdentifier(userId1, APP_ID, STORE_ID, true);
    EXPECT_EQ(identifier2, identifier1);
    /**
     * @tc.steps: step3. Set identifier2
     * @tc.expected: step3. OK.
     */
    DBStatus status = g_kvDelegatePtr->SetEqualIdentifier(identifier2, { DEVICE_B, DEVICE_D, DEVICE_E });
    EXPECT_EQ(status, DBStatus::OK);
    DBStatus status1 = delegate1->SetEqualIdentifier(identifier1, { DEVICE_B, DEVICE_D, DEVICE_E });
    EXPECT_EQ(status1, DBStatus::OK);

    EXCEPT_EQ(mgr1.CloseKvStore(delegate1), OK);
    delegate1 = nullptr;
    status = mgr1.DeleteKvStore(STORE_ID);
    ASSERT_TRUE(status == OK);
}

/**
 * @tc.name: Register callback 001
 * @tc.desc: Test register callback from CommunicatorProxy.
 * @tc.type: FUNC
 * @tc.require: AR000F4GVG
 * @tc.author: xushaohua
 */
HWTEST_F(KvDBCommunicatorProxyTest, RegCallBack001, TestSize.Level1)
{
    OnMessageCallback msgCallback;
    OnConnectCallback connCallback;
    std::function<void(void)> sendableCallback;
    Finalizer finalizer;

    /**
     * @tc.steps: step1. Call RegOnMessageCallback from CommProxy.
     * @tc.expected: step1. mainComm and extComm's RegOnMessageCallback should be called once.
     */
    EXPECT_CALL(extComm, RegOnMessageCallback(_, _)).Times(2);
    EXPECT_CALL(mainComm, RegOnMessageCallback(_, _)).Times(2);
    commProxy->RegOnMessageCallback(msgCallback, finalizer);

    /**
     * @tc.steps: step2. Call RegOnConnectCallback from CommProxy.
     * @tc.expected: step2. mainComm and extComm's RegOnConnectCallback should be called once.
     */
    EXPECT_CALL(extComm, RegOnConnectCallback(_, _)).Times(2);
    EXPECT_CALL(mainComm, RegOnConnectCallback(_, _)).Times(2);
    commProxy->RegOnConnectCallback(connCallback, finalizer);

    /**
     * @tc.steps: step3. Call RegOnSendableCallback from CommProxy.
     * @tc.expected: step3. mainComm and extComm's RegOnSendableCallback should be called once.
     */
    EXPECT_CALL(extComm, RegOnSendableCallback(_, _)).Times(2);
    EXPECT_CALL(mainComm, RegOnSendableCallback(_, _)).Times(2);
    commProxy->RegOnSendableCallback(sendableCallback, finalizer);
}

/**
 * @tc.name: Activate 001
 * @tc.desc: Test Activate called from CommunicatorProxy.
 * @tc.type: FUNC
 * @tc.require: AR000F4GVG
 * @tc.author: xushaohua
 */
HWTEST_F(KvDBCommunicatorProxyTest, Activate001, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Call Activate from CommProxy.
     * @tc.expected: step1. mainComm and extComm's Activate should be called once.
     */
    EXPECT_CALL(extComm, Activate("")).Times(2);
    EXPECT_CALL(mainComm, Activate("")).Times(2);
    commProxy->Activate();
}

/**
 * @tc.name: Get mtu 001
 * @tc.desc: Test mtu called from CommunicatorProxy.
 * @tc.type: FUNC
 * @tc.require: AR000F4GVG
 * @tc.author: xushaohua
 */
HWTEST_F(KvDBCommunicatorProxyTest, GetMtu001, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Call GetCommunicatorMtuSize from CommProxy with no param.
     * @tc.expected: step1. GetCommunicatorMtuSize return DBConstant::MIN_MTU_SIZE.
     */
    EXPECT_CALL(mainComm, GetCommunicatorMtuSize()).WillOnce(Return(DBConstant::MIN_MTU_SIZE));
    EXPECT_EQ(commProxy->GetCommunicatorMtuSize(), DBConstant::MIN_MTU_SIZE);

    /**
     * @tc.steps: step2. Call GetCommunicatorMtuSize from CommProxy with param DEVICE_C.
     * @tc.expected: step2. GetCommunicatorMtuSize return DBConstant::MAX_MTU_SIZE.
     */
    EXPECT_CALL(extComm, GetCommunicatorMtuSize(DEVICE_C)).WillOnce(Return(DBConstant::MAX_MTU_SIZE));
    EXPECT_EQ(commProxy->GetCommunicatorMtuSize(DEVICE_C), DBConstant::MAX_MTU_SIZE);
}

/**
 * @tc.name: Get local identify 001
 * @tc.desc: Test Get local identify from CommunicatorProxy.
 * @tc.type: FUNC
 * @tc.require: AR000F4GVG
 * @tc.author: xushaohua
 */
HWTEST_F(KvDBCommunicatorProxyTest, GetLocalIdentity001, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Call GetLocalIdentity from CommProxy, and set mainComm return DEVICE_B.
     * @tc.expected: step1. GetCommunicatorMtuSize return DEVICE_B and function call return E_OK.
     */
    EXPECT_CALL(mainComm, GetLocalIdentity(_)).WillOnce(DoAll(SetArgReferee<0>(DEVICE_B), Return(E_OK)));
    std::string localId;
    EXPECT_EQ(commProxy->GetLocalIdentity(localId), E_OK);
    EXPECT_EQ(localId, DEVICE_B);
}

/**
 * @tc.name: Get remote version 001
 * @tc.desc: Test Get remote version from CommunicatorProxy.
 * @tc.type: FUNC
 * @tc.require: AR000F4GVG
 * @tc.author: xushaohua
 */
HWTEST_F(KvDBCommunicatorProxyTest, GetRemoteVersion001, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Set mainComm called GetRemoteCommunicatorVersion will return SOFTWARE_VERSION_BASE.
     */
    EXPECT_CALL(mainComm, GetRemoteCommunicatorVersion(DEVICE_B, _))
        .WillOnce(DoAll(SetArgReferee<1>(SOFTWARE_VERSION_BASE), Return(E_OK)));

    /**
     * @tc.steps: step2. Call GetRemoteCommunicatorVersion from CommProxy with param DEVICE_B.
     * @tc.expected: step2. GetRemoteCommunicatorVersion return SOFTWARE_VERSION_BASE and function call return E_OK.
     */
    uint16_t version = 0;
    EXPECT_EQ(commProxy->GetRemoteCommunicatorVersion(DEVICE_B, version), E_OK);
    EXPECT_EQ(version, SOFTWARE_VERSION_BASE);

    /**
     * @tc.steps: step3. Set extComm called GetRemoteCommunicatorVersion will return SOFTWARE_VERSION_CURRENT.
     */
    EXPECT_CALL(extComm, GetRemoteCommunicatorVersion(DEVICE_C, _))
        .WillOnce(DoAll(SetArgReferee<1>(SOFTWARE_VERSION_CURRENT), Return(E_OK)));

    /**
     * @tc.steps: step4. Call GetRemoteCommunicatorVersion from CommProxy with param DEVICE_C.
     * @tc.expected: step4. GetRemoteCommunicatorVersion return SOFTWARE_VERSION_CURRENT and function call return E_OK.
     */
    EXPECT_EQ(commProxy->GetRemoteCommunicatorVersion(DEVICE_C, version), E_OK);
    EXPECT_EQ(version, SOFTWARE_VERSION_CURRENT);
}

/**
 * @tc.name: Send message 001
 * @tc.desc: Test Send message from CommunicatorProxy.
 * @tc.type: FUNC
 * @tc.require: AR000F4GVG
 * @tc.author: xushaohua
 */
HWTEST_F(KvDBCommunicatorProxyTest, SendMessage001, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Call SendMessage from CommProxy with param DEVICE_B.
     * @tc.expected: step1. MainComm's SendMessage willed called and return E_OK.
     */
    SendConfig conf = {true, false, 0};
    EXPECT_CALL(mainComm, SendMessage(DEVICE_B, _, _, _)).WillOnce(Return(E_OK));
    EXPECT_EQ(commProxy->SendMessage(DEVICE_B, nullptr, conf, nullptr), E_OK);

    /**
     * @tc.steps: step1. Call SendMessage from CommProxy with param DEVICE_C.
     * @tc.expected: step1. ExtComm's SendMessage willed called and return E_OK.
     */
    EXPECT_CALL(extComm, SendMessage(DEVICE_C, _, _, _)).WillOnce(Return(E_OK));
    EXPECT_EQ(commProxy->SendMessage(DEVICE_C, nullptr, conf, nullptr), E_OK);
}

/**
 * @tc.name: Get timeout time 001
 * @tc.desc: Test get timeout called from CommunicatorProxy.
 * @tc.type: FUNC
 * @tc.require: AR000F4GVG
 * @tc.author: xushaohua
 */
HWTEST_F(KvDBCommunicatorProxyTest, GetTimeout001, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Call GetTimeout from CommProxy with no param.
     * @tc.expected: step1. GetTimeout return DBConstant::MIN_TIMEOUT.
     */
    EXPECT_CALL(mainComm, GetTimeout()).WillOnce(Return(DBConstant::MIN_TIMEOUT));
    EXPECT_EQ(commProxy->GetTimeout(), DBConstant::MIN_TIMEOUT);

    /**
     * @tc.steps: step2. Call GetTimeout from CommProxy with param DEVICE_C.
     * @tc.expected: step2. GetTimeout return DBConstant::MAX_MTU_SIZE.
     */
    EXPECT_CALL(extComm, GetTimeout(DEVICE_C)).WillOnce(Return(DBConstant::MAX_TIMEOUT));
    EXPECT_EQ(commProxy->GetTimeout(DEVICE_C), DBConstant::MAX_TIMEOUT);
}