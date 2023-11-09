/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef RD_SINGLE_VER_RESULT_SET_H
#define RD_SINGLE_VER_RESULT_SET_H
#include "ikvdb_result_set.h"
#include "grd_resultset_api.h"
#include "rd_single_ver_natural_store.h"
#include "rd_single_ver_storage_executor.h"

namespace DistributedDB {
class RdSingleVerResultSet : public IKvDBResultSet {
public:
    RdSingleVerResultSet(RdSingleVerNaturalStore *kvDB, const Key &key);
    ~RdSingleVerResultSet() override;

    // Initialize logic
    int Open(bool isMemDb) override;

    // Finalize logic
    int Close() override;

    // Get total entries count.
    // >= 0: count, < 0: errCode.
    int GetCount() const override;

    // Get current read position.
    // >= 0: position, < 0: errCode
    int GetPosition() const override;

    // Move the read position to an absolute position value.
    int MoveTo(int position) const override;

    // Get the entry of current position.
    int GetEntry(Entry &entry) const override;

    int MoveToNext();

    int MoveToPrev();

private:
    int PreCheckResultSet() const;

    mutable std::mutex mutex_;

    mutable bool isOpen_ = false;

    mutable int position_ = INIT_POSITION; // The position in the overall result

    // For KeyPrefix Type Or Query Type. (RD not support query type)
    const ResultSetType type_ = ResultSetType::KEYPREFIX;

    Key key_;

    // Common Pointer For Use, Not Own it, Not Responsible To Release It.
    RdSingleVerNaturalStore *kvDB_ = nullptr;

    // Cache EntryId Mode Using StorageExecutor, Own It, Responsible To Release It.
    RdSingleVerStorageExecutor *handle_ = nullptr;

    GRD_ResultSet *resultSet_ = nullptr;
};
} // namespace DistributedDB
#endif // RD_SINGLE_VER_RESULT_SET_H