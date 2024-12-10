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

#ifndef OHOS_DISTRIBUTED_DATA_FRAMEWORKS_CONVERTOR_MOCK_H
#define OHOS_DISTRIBUTED_DATA_FRAMEWORKS_CONVERTOR_MOCK_H
#include "convertor.h"
#include <gmock/gmock.h>
#include <memory>

namespace OHOS::DistributedKv {
using Key = OHOS::DistributedKv::Blob;
using DBKey = DistributedDB::Key;
using DBQuery = DistributedDB::Query;

class BConvertor {
public:
    virtual std::vector<uint8_t> ToLocalDBKey(const Key&) const = 0;
    virtual std::vector<uint8_t> ToWholeDBKey(const Key&) const = 0;
    virtual Key ToKey(DBKey &&key, std::string&) const = 0;
    virtual std::vector<uint8_t> GetPrefix(const Key&) const = 0;
    virtual std::vector<uint8_t> GetPrefix(const DataQuery&) const = 0;
    virtual std::string GetRealKey(const std::string&, const DataQuery&) const = 0;
    virtual DBQuery GetDBQuery(const DataQuery&) const = 0;
    virtual std::vector<uint8_t> TrimKey(const Key&) const = 0;
    BConvertor() = default;
    virtual ~BConvertor() = default;
public:
    static inline std::shared_ptr<BConvertor> convertor = nullptr;
};

class ConvertorMock : public BConvertor {
public:
    MOCK_METHOD(std::vector<uint8_t>, ToLocalDBKey, (const Key&), (const));
    MOCK_METHOD(std::vector<uint8_t>, ToWholeDBKey, (const Key&), (const));
    MOCK_METHOD(Key, ToKey, (DBKey&&, std::string&), (const));
    MOCK_METHOD(std::vector<uint8_t>, GetPrefix, (const Key&), (const));
    MOCK_METHOD(std::vector<uint8_t>, GetPrefix, (const DataQuery&), (const));
    MOCK_METHOD(std::string, GetRealKey, (const std::string&, const DataQuery&), (const));
    MOCK_METHOD(DBQuery, GetDBQuery, (const DataQuery&), (const));
    MOCK_METHOD(std::vector<uint8_t>, TrimKey, (const Key&), (const));
};
} // namespace OHOS::DistributedKv
#endif // OHOS_DISTRIBUTED_DATA_FRAMEWORKS_CONVERTOR_MOCK_H