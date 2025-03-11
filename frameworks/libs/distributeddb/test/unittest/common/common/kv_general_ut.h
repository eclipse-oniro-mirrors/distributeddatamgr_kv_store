/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef KV_GENERAL_UT_H
#define KV_GENERAL_UT_H

#include "basic_unit_test.h"
#include "distributeddb_tools_unit_test.h"

namespace DistributedDB {
class KVGeneralUt : public BasicUnitTest {
public:
    void SetUp() override;
    void TearDown() override;
protected:
    int InitDelegate(const StoreInfo &info) override;
    int CloseDelegate(const StoreInfo &info) override;
    void CloseAllDelegate() override;
    void SetOption(const KvStoreNbDelegate::Option &option);
    KvStoreNbDelegate *GetDelegate(const StoreInfo &info) const;
    void BlockPush(const StoreInfo &from, const StoreInfo &to, DBStatus expectRet = DBStatus::OK);
    static KvStoreConfig GetKvStoreConfig();
    static StoreInfo GetStoreInfo1();
    static StoreInfo GetStoreInfo2();
    mutable std::mutex storeMutex_;
    std::optional<KvStoreNbDelegate::Option> option_;
    std::map<StoreInfo, KvStoreNbDelegate *, StoreComparator> stores_;
    DistributedDBUnitTest::DistributedDBToolsUnitTest tool_;
};
}
#endif // KV_GENERAL_UT_H

