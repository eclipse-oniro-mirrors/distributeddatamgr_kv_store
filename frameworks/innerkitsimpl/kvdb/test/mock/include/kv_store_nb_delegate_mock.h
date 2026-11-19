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

#ifndef OHOS_DISTRIBUTED_DATA_KV_STORE_NB_DELEGATE_MOCK_H
#define OHOS_DISTRIBUTED_DATA_KV_STORE_NB_DELEGATE_MOCK_H

#include <string>
#include <vector>

#include "kv_store_nb_delegate.h"

namespace OHOS::DistributedKv {
using namespace DistributedDB;

// Test-only fake KvStoreNbDelegate to control Pragma's return value (B4 branch coverage).
// Stubs all pure virtuals with OK; overrides Pragma to return pragmaResult_.
class FakeKvStoreNbDelegate : public DistributedDB::KvStoreNbDelegate {
public:
    DBStatus pragmaResult_ = DBStatus::OK;
    DBStatus Pragma(PragmaCmd, PragmaData&) override { return pragmaResult_; }

    // Trivial stubs for pure virtuals (not called in B4 test).
    DBStatus Get(const DistributedDB::Key&, DistributedDB::Value&) const override { return DBStatus::OK; }
    DBStatus GetEntries(const DistributedDB::Key&, std::vector<DistributedDB::Entry>&) const override
    {
        return DBStatus::OK;
    }
    DBStatus GetEntries(const DistributedDB::Key&, DistributedDB::KvStoreResultSet*&) const override
    {
        return DBStatus::OK;
    }
    DBStatus GetEntries(const DistributedDB::Query&, std::vector<DistributedDB::Entry>&) const override
    {
        return DBStatus::OK;
    }
    DBStatus GetEntries(const DistributedDB::Query&, DistributedDB::KvStoreResultSet*&) const override
    {
        return DBStatus::OK;
    }
    DBStatus GetCount(const DistributedDB::Query&, int&) const override { return DBStatus::OK; }
    DBStatus CloseResultSet(DistributedDB::KvStoreResultSet*&) override { return DBStatus::OK; }
    DBStatus Put(const DistributedDB::Key&, const DistributedDB::Value&) override { return DBStatus::OK; }
    DBStatus PutBatch(const std::vector<DistributedDB::Entry>&) override { return DBStatus::OK; }
    DBStatus DeleteBatch(const std::vector<DistributedDB::Key>&) override { return DBStatus::OK; }
    DBStatus Delete(const DistributedDB::Key&) override { return DBStatus::OK; }
    DBStatus GetLocal(const DistributedDB::Key&, DistributedDB::Value&) const override { return DBStatus::OK; }
    DBStatus GetLocalEntries(const DistributedDB::Key&, std::vector<DistributedDB::Entry>&) const override
    {
        return DBStatus::OK;
    }
    DBStatus PutLocal(const DistributedDB::Key&, const DistributedDB::Value&) override { return DBStatus::OK; }
    DBStatus DeleteLocal(const DistributedDB::Key&) override { return DBStatus::OK; }
    DBStatus PublishLocal(const DistributedDB::Key&, bool, bool, const KvStoreNbPublishOnConflict&) override
    {
        return DBStatus::OK;
    }
    DBStatus UnpublishToLocal(const DistributedDB::Key&, bool, bool) override { return DBStatus::OK; }
    std::string GetStoreId() const override { return {}; }
    DBStatus SetConflictNotifier(int, const KvStoreNbConflictNotifier&) override { return DBStatus::OK; }
    DBStatus Rekey(const CipherPassword&) override { return DBStatus::OK; }
    DBStatus Export(const std::string&, const CipherPassword&, bool) override { return DBStatus::OK; }
    DBStatus Import(const std::string&, const CipherPassword&, bool) override { return DBStatus::OK; }
    DBStatus StartTransaction() override { return DBStatus::OK; }
    DBStatus Commit() override { return DBStatus::OK; }
    DBStatus Rollback() override { return DBStatus::OK; }
    DBStatus PutLocalBatch(const std::vector<DistributedDB::Entry>&) override { return DBStatus::OK; }
    DBStatus DeleteLocalBatch(const std::vector<DistributedDB::Key>&) override { return DBStatus::OK; }
    DBStatus GetSecurityOption(SecurityOption&) const override { return DBStatus::OK; }
    DBStatus CheckIntegrity() const override { return DBStatus::OK; }
    DBStatus GetKeys(const DistributedDB::Key&, std::vector<DistributedDB::Key>&) const override
    {
        return DBStatus::OK;
    }
    DBStatus UpdateKey(const UpdateKeyCallback&) override { return DBStatus::OK; }
    DBStatus GetDeviceEntries(const std::string&, std::vector<DistributedDB::Entry>&) const override
    {
        return DBStatus::OK;
    }
};
} // namespace OHOS::DistributedKv
#endif // OHOS_DISTRIBUTED_DATA_KV_STORE_NB_DELEGATE_MOCK_H
