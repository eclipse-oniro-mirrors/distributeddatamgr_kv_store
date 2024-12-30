/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "accesstoken_kit.h"
#include "distributed_data_mgr.h"
#include "ipc_skeleton.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"
#include "types.h"
#include <gtest/gtest.h>
#include <vector>

using namespace testing::ext;
using namespace OHOS::DistributedKv;
using namespace OHOS::Security::AccessToken;
namespace OHOS::Test {
std::string BUNDLE_NAME = "ohos.distributeddatamgrtest.demo";
static constexpr int32_t TEST_USERID = 100;
static constexpr int32_t APP_INDEX = 0;
class DistributedDataMgrTest : public testing::Test {
public:
    static DistributedDataMgr manager;
    static void SetUpTestCase(void){};
    static void TearDownTestCase(void){};
    void SetUp(){};
    void TearDown(){};
};
DistributedDataMgr DistributedDataMgrTest::manager;

/**
 * @tc.name: ClearAppStorage
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: SQL
 */
HWTEST_F(DistributedDataMgrTest, ClearAppStorage001, TestSize.Level1)
{
    auto tokenId = 0;
    auto ret = manager.ClearAppStorage(BUNDLE_NAME, TEST_USERID, APP_INDEX, tokenId);
    EXPECT_EQ(ret, Status::SUCCESS);
}
} // namespace OHOS::Test