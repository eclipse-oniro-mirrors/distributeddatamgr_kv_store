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
#include "query.h"
namespace DistributedDB {
Query::Query(const std::string &tableName)
{
    queryExpression_.SetTableName(tableName);
}
Query Query::Select()
{
    Query query;
    return query;
}

Query Query::Select(const std::string &tableName)
{
    Query query(tableName);
    return query;
}


Query &Query::FromTable(const std::vector<std::string> &tableNames)
{
    queryExpression_.SetTables(tableNames);
    return *this;
}

Query &Query::BeginGroup()
{
    queryExpression_.BeginGroup();
    queryExpression_.SetIsDeviceSyncQuery(true);
    return *this;
}

Query &Query::EndGroup()
{
    queryExpression_.EndGroup();
    queryExpression_.SetIsDeviceSyncQuery(true);
    return *this;
}

Query &Query::IsNotNull(const std::string &field)
{
    queryExpression_.IsNotNull(field);
    queryExpression_.SetIsDeviceSyncQuery(true);
    return *this;
}

Query &Query::PrefixKey(const std::vector<uint8_t> &key)
{
    queryExpression_.QueryByPrefixKey(key);
    queryExpression_.SetIsDeviceSyncQuery(true);
    return *this;
}

Query &Query::SuggestIndex(const std::string &indexName)
{
    queryExpression_.QueryBySuggestIndex(indexName);
    queryExpression_.SetIsDeviceSyncQuery(true);
    return *this;
}

Query &Query::InKeys(const std::set<Key> &keys)
{
    queryExpression_.InKeys(keys);
    queryExpression_.SetIsDeviceSyncQuery(true);
    return *this;
}

Query &Query::OrderBy(const std::string &field, bool isAsc)
{
    queryExpression_.OrderBy(field, isAsc);
    queryExpression_.SetIsDeviceSyncQuery(true);
    return *this;
}

Query &Query::OrderByWriteTime(bool isAsc)
{
    queryExpression_.SetSortType(isAsc);
    queryExpression_.SetIsDeviceSyncQuery(true);
    return *this;
}

Query &Query::Limit(int number, int offset)
{
    queryExpression_.Limit(number, offset);
    queryExpression_.SetIsDeviceSyncQuery(true);
    return *this;
}

Query &Query::Like(const std::string &field, const std::string &value)
{
    queryExpression_.Like(field, value);
    queryExpression_.SetIsDeviceSyncQuery(true);
    return *this;
}

Query &Query::NotLike(const std::string &field, const std::string &value)
{
    queryExpression_.NotLike(field, value);
    queryExpression_.SetIsDeviceSyncQuery(true);
    return *this;
}

Query &Query::IsNull(const std::string &field)
{
    queryExpression_.IsNull(field);
    queryExpression_.SetIsDeviceSyncQuery(true);
    return *this;
}

Query &Query::And()
{
    queryExpression_.And();
    queryExpression_.SetIsDeviceSyncQuery(true);
    return *this;
}

Query &Query::Or()
{
    queryExpression_.Or();
    queryExpression_.SetIsDeviceSyncQuery(true);
    return *this;
}

void Query::ExecuteCompareOperation(QueryObjType operType, const std::string &field, const QueryValueType type,
    const FieldValue &fieldValue)
{
    switch (operType) {
        case QueryObjType::EQUALTO:
            queryExpression_.EqualTo(field, type, fieldValue);
            break;
        case QueryObjType::NOT_EQUALTO:
            queryExpression_.NotEqualTo(field, type, fieldValue);
            break;
        case QueryObjType::GREATER_THAN:
            queryExpression_.GreaterThan(field, type, fieldValue);
            break;
        case QueryObjType::LESS_THAN:
            queryExpression_.LessThan(field, type, fieldValue);
            break;
        case QueryObjType::GREATER_THAN_OR_EQUALTO:
            queryExpression_.GreaterThanOrEqualTo(field, type, fieldValue);
            break;
        case QueryObjType::LESS_THAN_OR_EQUALTO:
            queryExpression_.LessThanOrEqualTo(field, type, fieldValue);
            break;
        default:
            return;
    }
}

void Query::ExecuteCompareOperation(QueryObjType operType, const std::string &field, const QueryValueType type,
    const std::vector<FieldValue> &fieldValues)
{
    switch (operType) {
        case QueryObjType::IN:
            queryExpression_.In(field, type, fieldValues);
            break;
        case QueryObjType::NOT_IN:
            queryExpression_.NotIn(field, type, fieldValues);
            break;
        default:
            return;
    }
}

void Query::SetIsDeviceSyncQuery(bool isDeviceSync)
{
    queryExpression_.SetIsDeviceSyncQuery(isDeviceSync);
}
}  // namespace DistributedDB