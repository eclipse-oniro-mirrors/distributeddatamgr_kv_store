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

#ifndef RD_JSON_OBJECT_H
#define RD_JSON_OBJECT_H

#include <memory>
#include <set>
#include <string>
#include <typeinfo>
#include <vector>

#ifndef OMIT_cJSON
#include "cJSON.h"
#endif

#ifdef OMIT_cJSON
typedef void cJSON;
#endif

namespace DocumentDB {
class ValueObject {
public:
    enum class ValueType {
        VALUE_NULL = 0,
        VALUE_BOOL,
        VALUE_NUMBER,
        VALUE_STRING,
    };
    ValueObject() = default;
    explicit ValueObject(bool val);
    explicit ValueObject(double val);
    explicit ValueObject(const char *val);

    ValueType GetValueType() const;
    bool GetBoolValue() const;
    int64_t GetIntValue() const;
    double GetDoubleValue() const;
    std::string GetStringValue() const;

private:
    ValueType valueType = ValueType::VALUE_NULL;
    union {
        bool boolValue;
        double doubleValue;
    };
    std::string stringValue;
};
using JsonFieldPath = std::vector<std::string>;

using ResultValue = ValueObject;
using JsonFieldPath = std::vector<std::string>;

class JsonObject {
public:
    static JsonObject Parse(const std::string &jsonStr, int &errCode, bool caseSensitive = false,
        bool isFilter = false);
    bool operator==(const JsonObject &other) const; // If the two nodes exist with a different fieldName, then return 0.
    ~JsonObject();

    std::string Print() const;

    JsonObject GetObjectItem(const std::string &field, int &errCode);

    JsonObject GetNext() const;
    JsonObject GetChild() const;

    int DeleteItemFromObject(const std::string &field);
    int AddItemToObject(const std::string &fieldName, const JsonObject &item);
    int AddItemToObject(const std::string &fieldName);

    ValueObject GetItemValue() const;
    void ReplaceItemInArray(const int &index, const JsonObject &newItem, int &errCode);
    void ReplaceItemInObject(const std::string &fieldName, const JsonObject &newItem, int &errCode);
    int InsertItemObject(int which, const JsonObject &newItem);

    std::string GetItemField() const;
    std::string GetItemField(int &errCode) const;

    bool IsFieldExists(const JsonFieldPath &jsonPath) const;
    bool IsFieldExistsPowerMode(const JsonFieldPath &jsonPath) const;
    JsonObject FindItem(const JsonFieldPath &jsonPath, int &errCode) const;
    JsonObject FindItemPowerMode(const JsonFieldPath &jsonPath, int &errCode) const;
    ValueObject GetObjectByPath(const JsonFieldPath &jsonPath, int &errCode) const;
    int DeleteItemDeeplyOnTarget(const JsonFieldPath &path);
    bool IsNull() const;
    int GetDeep();
    enum class Type {
        JSON_LEAF, // Corresponds to nodes of type null, number, string, true false in CJSON
        JSON_OBJECT,
        JSON_ARRAY
    };
    Type GetType() const;

private:
    JsonObject();
    int Init(const std::string &str, bool isFilter = false);
    int CheckJsonRepeatField(cJSON *object, bool isFirstFloor);
    int CheckSubObj(std::set<std::string> &fieldSet, cJSON *subObj, int parentType, bool isFirstFloor);
    int GetDeep(cJSON *cjson);
    int CheckNumber(cJSON *cJSON);
    cJSON *cjson_ = nullptr;
    int jsonDeep_ = 0;
    bool isOwner_ = false;
    bool caseSensitive_ = false;
};
} // namespace DocumentDB
#endif // JSON_OBJECT_H
