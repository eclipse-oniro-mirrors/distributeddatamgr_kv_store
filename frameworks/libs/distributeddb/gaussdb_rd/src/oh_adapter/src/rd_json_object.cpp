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

#include "rd_json_object.h"

#include <algorithm>
#include <cmath>
#include <queue>

#include "doc_errno.h"
#include "rd_log_print.h"

namespace DocumentDB {
#ifndef OMIT_cJSON
namespace {
bool IsNumber(const std::string &str)
{
    return std::all_of(str.begin(), str.end(), [](char c) {
        return std::isdigit(c);
    });
}
} // namespace

ValueObject::ValueObject(bool val)
{
    valueType = ValueType::VALUE_BOOL;
    boolValue = val;
}

ValueObject::ValueObject(double val)
{
    valueType = ValueType::VALUE_NUMBER;
    doubleValue = val;
}

ValueObject::ValueObject(const char *val)
{
    valueType = ValueType::VALUE_STRING;
    stringValue = val;
}

ValueObject::ValueType ValueObject::GetValueType() const
{
    return valueType;
}

bool ValueObject::GetBoolValue() const
{
    return boolValue;
}

int64_t ValueObject::GetIntValue() const
{
    return static_cast<int64_t>(std::llround(doubleValue));
}

double ValueObject::GetDoubleValue() const
{
    return doubleValue;
}

std::string ValueObject::GetStringValue() const
{
    return stringValue;
}

JsonObject JsonObject::Parse(const std::string &jsonStr, int &errCode, bool caseSensitive, bool isFilter)
{
    JsonObject obj;
    errCode = obj.Init(jsonStr, isFilter);
    obj.caseSensitive_ = caseSensitive;
    return obj;
}

JsonObject::JsonObject()
{
    cjson_ = nullptr;
}

JsonObject::~JsonObject()
{
    if (isOwner_) {
        cJSON_Delete(cjson_);
    }
}

bool JsonObject::operator==(const JsonObject &other) const
{
    return (cJSON_Compare(this->cjson_, other.cjson_, true) != 0); // CaseSensitive
}

bool JsonObject::IsNull() const
{
    return (cjson_ == nullptr);
}

JsonObject::Type JsonObject::GetType() const
{
    if (cjson_->type == cJSON_Object) {
        return JsonObject::Type::JSON_OBJECT;
    } else if (cjson_->type == cJSON_Array) {
        return JsonObject::Type::JSON_ARRAY;
    }
    return JsonObject::Type::JSON_LEAF;
}

int JsonObject::GetDeep()
{
    if (cjson_ == nullptr) {
        GLOGE("cJson is nullptr,deep is 0");
        return 0;
    }
    if (jsonDeep_ != 0) {
        return jsonDeep_;
    }
    jsonDeep_ = GetDeep(cjson_);
    return jsonDeep_;
}

int JsonObject::GetDeep(cJSON *cjson)
{
    if (cjson->child == nullptr) {
        jsonDeep_ = 0;
        return 0; // leaf node
    }

    int depth = -1;
    cJSON *child = cjson->child;
    while (child != nullptr) {
        depth = std::max(depth, GetDeep(child) + 1);
        child = child->next;
    }
    jsonDeep_ = depth;
    return depth;
}

int JsonObject::CheckNumber(cJSON *item)
{
    std::queue<cJSON *> cjsonQueue;
    cjsonQueue.push(item);
    while (!cjsonQueue.empty()) {
        cJSON *node = cjsonQueue.front();
        cjsonQueue.pop();
        if (node == nullptr) {
            return -E_INVALID_ARGS;
        }
        if (cJSON_IsNumber(node)) { // node is not null all the time
            double value = cJSON_GetNumberValue(node);
            if (value > __DBL_MAX__ || value < -__DBL_MAX__) {
                return -E_INVALID_ARGS;
            }
        }
        if (node->child != nullptr) {
            cjsonQueue.push(node->child);
        }
        if (node->next != nullptr) {
            cjsonQueue.push(node->next);
        }
    }
    return E_OK;
}

int JsonObject::Init(const std::string &str, bool isFilter)
{
    const char *end = NULL;
    isOwner_ = true;
    cjson_ = cJSON_ParseWithOpts(str.c_str(), &end, true);
    if (cjson_ == nullptr) {
        GLOGE("Json's format is wrong");
        return -E_INVALID_JSON_FORMAT;
    }

    if (cjson_->type != cJSON_Object) {
        GLOGE("after Parse,cjson_'s type is not cJSON_Object");
        return -E_INVALID_ARGS;
    }

    int ret = CheckNumber(cjson_);
    if (ret == -E_INVALID_ARGS) {
        GLOGE("Int value is larger than double");
        return -E_INVALID_ARGS;
    }
    if (!isFilter) {
        bool isFirstFloor = true;
        ret = CheckJsonRepeatField(cjson_, isFirstFloor);
        if (ret != E_OK) {
            return ret;
        }
    }
    return E_OK;
}

int JsonObject::CheckJsonRepeatField(cJSON *object, bool isFirstFloor)
{
    if (object == nullptr) {
        return -E_INVALID_ARGS;
    }
    int ret = E_OK;
    int type = object->type;
    if (type != cJSON_Object && type != cJSON_Array) {
        return ret;
    }
    std::set<std::string> fieldSet;
    cJSON *subObj = object->child;
    while (subObj != nullptr) {
        ret = CheckSubObj(fieldSet, subObj, type, isFirstFloor);
        if (ret != E_OK) {
            break;
        }
        subObj = subObj->next;
    }
    return ret;
}

bool IsFieldNameLegal(const std::string &fieldName)
{
    for (auto oneChar : fieldName) {
        if (!((isalpha(oneChar)) || (isdigit(oneChar)) || (oneChar == '_'))) {
            return false;
        }
    }
    return true;
}

int JsonObject::CheckSubObj(std::set<std::string> &fieldSet, cJSON *subObj, int parentType, bool isFirstFloor)
{
    if (subObj == nullptr) {
        return -E_INVALID_ARGS;
    }
    std::string fieldName;
    if (subObj->string != nullptr) {
        fieldName = subObj->string;
        if (!isFirstFloor) {
            if (!IsFieldNameLegal(fieldName)) {
                return -E_INVALID_ARGS;
            }
        }
        if (!fieldName.empty() && isdigit(fieldName[0])) {
            return -E_INVALID_ARGS;
        }
    }
    isFirstFloor = false;
    if (parentType == cJSON_Array) {
        return CheckJsonRepeatField(subObj, isFirstFloor);
    }
    if (fieldName.empty()) {
        return -E_INVALID_JSON_FORMAT;
    }
    if (fieldSet.find(fieldName) == fieldSet.end()) {
        fieldSet.insert(fieldName);
    } else {
        return -E_INVALID_JSON_FORMAT;
    }
    return CheckJsonRepeatField(subObj, isFirstFloor);
}

std::string JsonObject::Print() const
{
    if (cjson_ == nullptr) {
        return "";
    }
    char *ret = cJSON_PrintUnformatted(cjson_);
    std::string str = (ret == nullptr ? "" : ret);
    cJSON_free(ret);
    return str;
}

JsonObject JsonObject::GetObjectItem(const std::string &field, int &errCode)
{
    if (cjson_ == nullptr || cjson_->type != cJSON_Object) {
        errCode = -E_INVALID_ARGS;
        return JsonObject();
    }

    JsonObject item;
    item.caseSensitive_ = caseSensitive_;
    if (caseSensitive_) {
        item.cjson_ = cJSON_GetObjectItemCaseSensitive(cjson_, field.c_str());
    } else {
        item.cjson_ = cJSON_GetObjectItem(cjson_, field.c_str());
    }
    if (item.cjson_ == nullptr) {
        errCode = -E_NOT_FOUND;
    }
    return item;
}

JsonObject JsonObject::GetNext() const
{
    if (cjson_ == nullptr) {
        return JsonObject();
    }
    JsonObject next;
    next.caseSensitive_ = caseSensitive_;
    if (cjson_->next == nullptr) {
        return JsonObject();
    }
    next.cjson_ = cjson_->next;
    return next;
}

JsonObject JsonObject::GetChild() const
{
    if (cjson_ == nullptr) {
        return JsonObject();
    }
    JsonObject child;
    child.caseSensitive_ = caseSensitive_;
    if (cjson_->child == nullptr) {
        return JsonObject();
    }
    child.cjson_ = cjson_->child;
    return child;
}

int JsonObject::DeleteItemFromObject(const std::string &field)
{
    if (field.empty()) {
        return E_OK;
    }
    cJSON_DeleteItemFromObjectCaseSensitive(cjson_, field.c_str());
    return E_OK;
}

int JsonObject::AddItemToObject(const std::string &fieldName, const JsonObject &item)
{
    if (cjson_ == nullptr) {
        return -E_ERROR;
    }

    if (item.IsNull()) {
        GLOGD("Add null object.");
        return E_OK;
    }
    if (cjson_->type == cJSON_Array) {
        int n = 0;
        cJSON *child = cjson_->child;
        while (child != nullptr) {
            child = child->next;
            n++;
        }
        if (IsNumber(fieldName) && n <= std::stoi(fieldName)) {
            GLOGE("Add item object to array over size.");
            return -E_NO_DATA;
        }
    }
    if (cjson_->type != cJSON_Object) {
        GLOGE("type conflict.");
        return -E_DATA_CONFLICT;
    }
    cJSON *cpoyItem = cJSON_Duplicate(item.cjson_, true);
    cJSON_AddItemToObject(cjson_, fieldName.c_str(), cpoyItem);
    return E_OK;
}

int JsonObject::AddItemToObject(const std::string &fieldName)
{
    if (cjson_->type == cJSON_Array) {
        int n = 0;
        cJSON *child = cjson_->child;
        while (child != nullptr) {
            child = child->next;
            n++;
        }
        if (IsNumber(fieldName) && n <= std::stoi(fieldName)) {
            GLOGE("Add item object to array over size.");
            return -E_NO_DATA;
        }
    }
    if (cjson_->type != cJSON_Object) {
        GLOGE("type conflict.");
        return -E_DATA_CONFLICT;
    }
    cJSON *emptyitem = cJSON_CreateObject();
    cJSON_AddItemToObject(cjson_, fieldName.c_str(), emptyitem);
    return E_OK;
}

ValueObject JsonObject::GetItemValue() const
{
    if (cjson_ == nullptr) {
        return ValueObject();
    }
    ValueObject value;
    switch (cjson_->type) {
        case cJSON_False:
        case cJSON_True:
            return ValueObject(cjson_->type == cJSON_True);
        case cJSON_NULL:
            return ValueObject();
        case cJSON_Number:
            return ValueObject(cjson_->valuedouble);
        case cJSON_String:
            return ValueObject(cjson_->valuestring);
        case cJSON_Array:
        case cJSON_Object:
        default:
            GLOGW("Invalid json type: %d", cjson_->type);
            break;
    }

    return value;
}

void JsonObject::ReplaceItemInObject(const std::string &fieldName, const JsonObject &newItem, int &errCode)
{
    if (!newItem.IsNull() || !this->IsNull()) {
        if (this->GetType() == JsonObject::Type::JSON_OBJECT) {
            if (!(this->GetObjectItem(fieldName.c_str(), errCode).IsNull())) {
                cJSON *copyItem = cJSON_Duplicate(newItem.cjson_, true);
                cJSON_ReplaceItemInObjectCaseSensitive(this->cjson_, fieldName.c_str(), copyItem);
            } else {
                cJSON *copyItem = cJSON_Duplicate(newItem.cjson_, true);
                cJSON_AddItemToObject(this->cjson_, fieldName.c_str(), copyItem);
            }
        }
    }
}

void JsonObject::ReplaceItemInArray(const int &index, const JsonObject &newItem, int &errCode)
{
    if (!newItem.IsNull() || !this->IsNull()) {
        if (this->GetType() == JsonObject::Type::JSON_ARRAY) {
            cJSON *copyItem = cJSON_Duplicate(newItem.cjson_, true);
            cJSON_ReplaceItemInArray(this->cjson_, index, copyItem);
        }
    }
}

int JsonObject::InsertItemObject(int which, const JsonObject &newItem)
{
    if (cjson_ == nullptr) {
        return E_OK;
    }
    if (newItem.IsNull()) {
        GLOGD("Add null object.");
        return E_OK;
    }
    cJSON *cpoyItem = cJSON_Duplicate(newItem.cjson_, true);
    cJSON_InsertItemInArray(cjson_, which, cpoyItem);
    return E_OK;
}

std::string JsonObject::GetItemField() const
{
    if (cjson_ == nullptr) {
        return "";
    }

    if (cjson_->string == nullptr) {
        cJSON *tail = cjson_;
        while (tail->next != nullptr) {
            tail = tail->next;
        }

        int index = 0;
        cJSON *head = cjson_;
        while (head->prev != tail) {
            head = head->prev;
            index++;
        }
        return std::to_string(index);
    } else {
        return cjson_->string;
    }
}

std::string JsonObject::GetItemField(int &errCode) const
{
    if (cjson_ == nullptr || cjson_->string == nullptr) {
        errCode = E_INVALID_ARGS;
        return "";
    }
    errCode = E_OK;
    return cjson_->string;
}

cJSON *GetChild(cJSON *cjson, const std::string &field, bool caseSens)
{
    if (cjson->type == cJSON_Object) {
        if (caseSens) {
            return cJSON_GetObjectItemCaseSensitive(cjson, field.c_str());
        } else {
            return cJSON_GetObjectItem(cjson, field.c_str());
        }
    } else if (cjson->type == cJSON_Array) {
        if (!IsNumber(field)) {
            GLOGW("Invalid json field path, expect array index.");
            return nullptr;
        }
        return cJSON_GetArrayItem(cjson, std::stoi(field));
    }

    GLOGW("Invalid json field type, expect object or array.");
    return nullptr;
}

cJSON *GetChildPowerMode(cJSON *cjson, const std::string &field, bool caseSens)
{
    if (cjson->type != cJSON_Object && cjson->type != cJSON_Array) {
        GLOGW("Invalid json field type, expect object or array.");
        return nullptr;
    } else if (cjson->type == cJSON_Object) {
        if (caseSens) {
            return cJSON_GetObjectItemCaseSensitive(cjson, field.c_str());
        } else {
            return cJSON_GetObjectItem(cjson, field.c_str());
        }
    }

    // type is cJSON_Array
    if (!IsNumber(field)) {
        cjson = cjson->child;
        while (cjson != nullptr) {
            cJSON *resultItem = GetChild(cjson, field, caseSens);
            if (resultItem != nullptr) {
                return resultItem;
            }
            cjson = cjson->next;
        }
        return nullptr;
    }
    return cJSON_GetArrayItem(cjson, std::stoi(field));
}

cJSON *MoveToPath(cJSON *cjson, const JsonFieldPath &jsonPath, bool caseSens)
{
    for (const auto &field : jsonPath) {
        cjson = GetChild(cjson, field, caseSens);
        if (cjson == nullptr) {
            break;
        }
    }
    return cjson;
}

cJSON *MoveToPathPowerMode(cJSON *cjson, const JsonFieldPath &jsonPath, bool caseSens)
{
    for (const auto &field : jsonPath) {
        cjson = GetChildPowerMode(cjson, field, caseSens);
        if (cjson == nullptr) {
            break;
        }
    }
    return cjson;
}

bool JsonObject::IsFieldExists(const JsonFieldPath &jsonPath) const
{
    return (MoveToPath(cjson_, jsonPath, caseSensitive_) != nullptr);
}

bool JsonObject::IsFieldExistsPowerMode(const JsonFieldPath &jsonPath) const
{
    return (MoveToPathPowerMode(cjson_, jsonPath, caseSensitive_) != nullptr);
}

JsonObject JsonObject::FindItem(const JsonFieldPath &jsonPath, int &errCode) const
{
    if (jsonPath.empty()) {
        JsonObject curr = JsonObject();
        curr.cjson_ = cjson_;
        curr.caseSensitive_ = caseSensitive_;
        curr.isOwner_ = false;
        return curr;
    }

    cJSON *findItem = MoveToPath(cjson_, jsonPath, caseSensitive_);
    if (findItem == nullptr) {
        GLOGE("Find item failed. json field path not found.");
        errCode = -E_JSON_PATH_NOT_EXISTS;
        return {};
    }

    JsonObject item;
    item.caseSensitive_ = caseSensitive_;
    item.cjson_ = findItem;
    return item;
}

// Compared with the non-powerMode mode, the node found by this function is an Array, and target is an object,
// if the Array contains the same object as the target, it can match this object in this mode.
JsonObject JsonObject::FindItemPowerMode(const JsonFieldPath &jsonPath, int &errCode) const
{
    if (jsonPath.empty()) {
        JsonObject curr = JsonObject();
        curr.cjson_ = cjson_;
        curr.caseSensitive_ = caseSensitive_;
        curr.isOwner_ = false;
        return curr;
    }

    cJSON *findItem = MoveToPathPowerMode(cjson_, jsonPath, caseSensitive_);
    if (findItem == nullptr) {
        GLOGE("Find item failed. json field path not found.");
        errCode = -E_JSON_PATH_NOT_EXISTS;
        return {};
    }
    JsonObject item;
    item.caseSensitive_ = caseSensitive_;
    item.cjson_ = findItem;
    return item;
}

ValueObject JsonObject::GetObjectByPath(const JsonFieldPath &jsonPath, int &errCode) const
{
    JsonObject objGot = FindItem(jsonPath, errCode);
    if (errCode != E_OK) {
        GLOGE("Get json value object failed. %d", errCode);
        return {};
    }
    return objGot.GetItemValue();
}

int JsonObject::DeleteItemDeeplyOnTarget(const JsonFieldPath &path)
{
    if (path.empty()) {
        return -E_INVALID_ARGS;
    }

    std::string fieldName = path.back();
    JsonFieldPath patherPath = path;
    patherPath.pop_back();

    cJSON *nodeFather = MoveToPath(cjson_, patherPath, caseSensitive_);
    if (nodeFather == nullptr) {
        return -E_JSON_PATH_NOT_EXISTS;
    }

    if (nodeFather->type == cJSON_Object) {
        if (caseSensitive_) {
            cJSON_DeleteItemFromObjectCaseSensitive(nodeFather, fieldName.c_str());
            if (nodeFather->child == nullptr && path.size() > 1) {
                JsonFieldPath fatherPath(path.begin(), path.end() - 1);
                DeleteItemDeeplyOnTarget(fatherPath);
            }
        } else {
            cJSON_DeleteItemFromObject(nodeFather, fieldName.c_str());
            if (nodeFather->child == nullptr && path.size() > 1) {
                JsonFieldPath fatherPath(path.begin(), path.end() - 1);
                DeleteItemDeeplyOnTarget(fatherPath);
            }
        }
    } else if (nodeFather->type == cJSON_Array) {
        if (!IsNumber(fieldName)) {
            GLOGW("Invalid json field path, expect array index.");
            return -E_JSON_PATH_NOT_EXISTS;
        }
        cJSON_DeleteItemFromArray(nodeFather, std::stoi(fieldName));
        if (nodeFather->child == nullptr && path.size() > 1) {
            JsonFieldPath fatherPath(path.begin(), path.end() - 1);
            DeleteItemDeeplyOnTarget(fatherPath);
        }
    }

    return E_OK;
}
#else
ValueObject::ValueObject(bool val)
{
    valueType = ValueType::VALUE_BOOL;
    boolValue = val;
}

ValueObject::ValueObject(double val)
{
    valueType = ValueType::VALUE_NUMBER;
    doubleValue = val;
}

ValueObject::ValueObject(const char *val)
{
    valueType = ValueType::VALUE_STRING;
    stringValue = val;
}

ValueObject::ValueType ValueObject::GetValueType() const
{
    return valueType;
}

bool ValueObject::GetBoolValue() const
{
    return boolValue;
}

int64_t ValueObject::GetIntValue() const
{
    return static_cast<int64_t>(std::llround(doubleValue));
}

double ValueObject::GetDoubleValue() const
{
    return doubleValue;
}

std::string ValueObject::GetStringValue() const
{
    return stringValue;
}

JsonObject JsonObject::Parse(const std::string &jsonStr, int &errCode, bool caseSensitive, bool isFilter)
{
    (void)jsonStr;
    (void)errCode;
    (void)caseSensitive;
    (void)isFilter;
    return {};
}

JsonObject::JsonObject()
{
    cjson_ = nullptr;
    jsonDeep_ = 0;
    isOwner_ = false;
    caseSensitive_ = false;
}

JsonObject::~JsonObject()
{
}

bool JsonObject::operator==(const JsonObject &other) const
{
    return true;
}


bool JsonObject::IsNull() const
{
    return true;
}

JsonObject::Type JsonObject::GetType() const
{
    return JsonObject::Type::JSON_LEAF;
}

int JsonObject::GetDeep()
{
    return jsonDeep_;
}

int JsonObject::GetDeep(cJSON *cjson)
{
    return jsonDeep_;
}

int JsonObject::CheckNumber(cJSON *item)
{
    (void)item;
    return E_OK;
}

int JsonObject::Init(const std::string &str, bool isFilter)
{
    (void)str;
    (void)isFilter;
    return E_OK;
}

int JsonObject::CheckJsonRepeatField(cJSON *object, bool isFirstFloor)
{
    (void)object;
    (void)isFirstFloor;
    return E_OK;
}

bool IsFieldNameLegal(const std::string &fieldName)
{
    (void)fieldName;
    return true;
}

int JsonObject::CheckSubObj(std::set<std::string> &fieldSet, cJSON *subObj, int parentType, bool isFirstFloor)
{
    (void)fieldSet;
    (void)subObj;
    (void)parentType;
    (void)isFirstFloor;
    return true;
}

std::string JsonObject::Print() const
{
    return std::string();
}

JsonObject JsonObject::GetObjectItem(const std::string &field, int &errCode)
{
    (void)field;
    (void)errCode;
    return {};
}

JsonObject JsonObject::GetNext() const
{
    return {};
}

JsonObject JsonObject::GetChild() const
{
    return {};
}

int JsonObject::DeleteItemFromObject(const std::string &field)
{
    (void)field;
    return E_OK;
}

int JsonObject::AddItemToObject(const std::string &fieldName, const JsonObject &item)
{
    (void)fieldName;
    (void)item;
    return E_OK;
}

int JsonObject::AddItemToObject(const std::string &fieldName)
{
    (void)fieldName;
    return E_OK;
}

ValueObject JsonObject::GetItemValue() const
{
    return {};
}

void JsonObject::ReplaceItemInObject(const std::string &fieldName, const JsonObject &newItem, int &errCode)
{
    (void)fieldName;
    (void)newItem;
    (void)errCode;
}

void JsonObject::ReplaceItemInArray(const int &index, const JsonObject &newItem, int &errCode)
{
    (void)index;
    (void)newItem;
    (void)errCode;
}

int JsonObject::InsertItemObject(int which, const JsonObject &newItem)
{
    (void)which;
    (void)newItem;
    return E_OK;
}

std::string JsonObject::GetItemField() const
{
    return std::string();
}

std::string JsonObject::GetItemField(int &errCode) const
{
    (void)errCode;
    return std::string();
}

cJSON *GetChild(cJSON *cjson, const std::string &field, bool caseSens)
{
    (void)cjson;
    (void)field;
    (void)caseSens;
    return nullptr;
}

cJSON *GetChildPowerMode(cJSON *cjson, const std::string &field, bool caseSens)
{
    (void)cjson;
    (void)field;
    (void)caseSens;
    return nullptr;
}

cJSON *MoveToPath(cJSON *cjson, const JsonFieldPath &jsonPath, bool caseSens)
{
    (void)cjson;
    (void)jsonPath;
    (void)caseSens;
    return nullptr;
}

cJSON *MoveToPathPowerMode(cJSON *cjson, const JsonFieldPath &jsonPath, bool caseSens)
{
    (void)jsonPath;
    (void)caseSens;
    return nullptr;
}

bool JsonObject::IsFieldExists(const JsonFieldPath &jsonPath) const
{
    (void)jsonPath;
    return true;
}

bool JsonObject::IsFieldExistsPowerMode(const JsonFieldPath &jsonPath) const
{
    (void)jsonPath;
    return true;
}

JsonObject JsonObject::FindItem(const JsonFieldPath &jsonPath, int &errCode) const
{
    (void)jsonPath;
    (void)errCode;
    return {};
}

// Compared with the non-powerMode mode, the node found by this function is an Array, and target is an object,
// if the Array contains the same object as the target, it can match this object in this mode.
JsonObject JsonObject::FindItemPowerMode(const JsonFieldPath &jsonPath, int &errCode) const
{
    (void)jsonPath;
    (void)errCode;
    return {};
}

ValueObject JsonObject::GetObjectByPath(const JsonFieldPath &jsonPath, int &errCode) const
{
    (void)jsonPath;
    (void)errCode;
    return {};
}

int JsonObject::DeleteItemDeeplyOnTarget(const JsonFieldPath &path)
{
    (void)path;
    return E_OK;
}
#endif
} // namespace DocumentDB
