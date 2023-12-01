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
#include "json_common.h"

#include <queue>

#include "doc_errno.h"
#include "rd_log_print.h"

namespace DocumentDB {
ValueObject JsonCommon::GetValueInSameLevel(JsonObject &node, const std::string &field)
{
    while (!node.IsNull()) {
        if (node.GetItemField() == field) {
            ValueObject itemValue = node.GetItemValue();
            return itemValue;
        }
        if (node.GetNext().IsNull()) {
            return ValueObject();
        }
        JsonObject nodeNew = node.GetNext();
        node = nodeNew;
    }
    return ValueObject();
}

ValueObject JsonCommon::GetValueInSameLevel(JsonObject &node, const std::string &field, bool &isFieldExist)
{
    while (!node.IsNull()) {
        if (node.GetItemField() == field) {
            ValueObject itemValue = node.GetItemValue();
            isFieldExist = true;
            return itemValue;
        }
        if (node.GetNext().IsNull()) {
            isFieldExist = false;
            return ValueObject();
        }
        JsonObject nodeNew = node.GetNext();
        node = nodeNew;
    }
    isFieldExist = false;
    return ValueObject();
}

void JsonCommon::CheckLeafNode(const JsonObject &node, std::vector<ValueObject> &leafValue)
{
    if (node.GetChild().IsNull()) {
        ValueObject itemValue = node.GetItemValue();
        leafValue.emplace_back(itemValue);
    }
    if (!node.GetChild().IsNull()) {
        JsonObject nodeNew = node.GetChild();
        CheckLeafNode(nodeNew, leafValue);
    }
    if (!node.GetNext().IsNull()) {
        JsonObject nodeNew = node.GetNext();
        CheckLeafNode(nodeNew, leafValue);
    }
}

std::vector<ValueObject> JsonCommon::GetLeafValue(const JsonObject &node)
{
    std::vector<ValueObject> leafValue;
    if (node.IsNull()) {
        GLOGE("Get leafValue faied, node is empty");
        return leafValue;
    }
    CheckLeafNode(node, leafValue);
    return leafValue;
}

bool JsonCommon::CheckNode(JsonObject &node)
{
    std::queue<JsonObject> jsonQueue;
    jsonQueue.push(node);
    while (!jsonQueue.empty()) {
        std::set<std::string> fieldSet;
        bool isFieldNameExist = true;
        int ret = E_OK;
        JsonObject item = jsonQueue.front();
        jsonQueue.pop();
        std::string fieldName = item.GetItemField(ret);
        if (ret != E_OK) {
            isFieldNameExist = false;
        }
        if (fieldSet.find(fieldName) != fieldSet.end()) {
            return false;
        }
        if (isFieldNameExist) {
            fieldSet.insert(fieldName);
            if (fieldName.empty()) {
                return false;
            }
        }
        for (size_t i = 0; i < fieldName.size(); i++) {
            if (!((isalpha(fieldName[i])) || (isdigit(fieldName[i])) || fieldName[i] == '_')) {
                return false;
            }
            if (i == 0 && (isdigit(fieldName[i]))) {
                return false;
            }
        }
        if (!item.GetChild().IsNull()) {
            jsonQueue.push(item.GetChild());
        }
        if (!item.GetNext().IsNull()) {
            jsonQueue.push(item.GetNext());
        }
    }
    return true;
}

bool JsonCommon::CheckJsonField(JsonObject &jsonObj)
{
    return CheckNode(jsonObj);
}

bool JsonCommon::CheckProjectionNode(JsonObject &node, bool isFirstLevel, int &errCode)
{
    std::queue<JsonObject> jsonQueue;
    jsonQueue.push(node);
    while (!jsonQueue.empty()) {
        int ret = 0;
        std::set<std::string> fieldSet;
        JsonObject item = jsonQueue.front();
        jsonQueue.pop();
        std::string fieldName = item.GetItemField(ret);
        if (fieldName.empty()) {
            errCode = -E_INVALID_ARGS;
            return false;
        }
        if (fieldSet.find(fieldName) == fieldSet.end() && ret == E_OK) {
            fieldSet.insert(fieldName);
        } else {
            errCode = -E_INVALID_JSON_FORMAT;
            return false;
        }
        for (size_t i = 0; i < fieldName.size(); i++) {
            if (!((isalpha(fieldName[i])) || (isdigit(fieldName[i])) || (fieldName[i] == '_') ||
                    (isFirstLevel && fieldName[i] == '.'))) {
                errCode = -E_INVALID_ARGS;
                return false;
            }
            if (i == 0 && (isdigit(fieldName[i]))) {
                errCode = -E_INVALID_ARGS;
                return false;
            }
        }
        if (!item.GetNext().IsNull()) {
            jsonQueue.push(item.GetNext());
        }
        if (!item.GetChild().IsNull()) {
            jsonQueue.push(item.GetChild());
        }
    }
    return true;
}

bool JsonCommon::CheckProjectionField(JsonObject &jsonObj, int &errCode)
{
    bool isFirstLevel = true;
    return CheckProjectionNode(jsonObj, isFirstLevel, errCode);
}

namespace {
int SplitFieldName(const std::string &fieldName, std::vector<std::string> &allFieldsName, int &insertCount)
{
    std::string tempParseName;
    std::string priFieldName = fieldName;
    for (size_t j = 0; j < priFieldName.size(); j++) {
        if (priFieldName[j] != '.') {
            tempParseName += priFieldName[j];
        }
        if (priFieldName[j] == '.' || j == priFieldName.size() - 1) {
            if ((j > 0 && priFieldName[j] == '.' && priFieldName[j - 1] == '.') ||
                (priFieldName[j] == '.' && j == priFieldName.size() - 1)) {
                return -E_INVALID_ARGS;
            }
            allFieldsName.emplace_back(tempParseName);
            insertCount++;
            tempParseName.clear();
        }
    }
    return E_OK;
}
} // namespace

int JsonCommon::ParseNode(JsonObject &node, std::vector<std::string> singlePath,
    std::vector<std::vector<std::string>> &resultPath, bool isFirstLevel)
{
    while (!node.IsNull()) {
        int insertCount = 0;
        if (isFirstLevel) {
            std::vector<std::string> allFieldsName;
            int errCode = SplitFieldName(node.GetItemField(), allFieldsName, insertCount);
            if (errCode != E_OK) {
                return errCode;
            }
            singlePath.insert(singlePath.end(), allFieldsName.begin(), allFieldsName.end());
        } else {
            std::vector<std::string> allFieldsName;
            allFieldsName.emplace_back(node.GetItemField());
            insertCount++;
            singlePath.insert(singlePath.end(), allFieldsName.begin(), allFieldsName.end());
        }
        if (!node.GetChild().IsNull() && node.GetChild().GetItemField() != "") {
            JsonObject nodeNew = node.GetChild();
            int ret = ParseNode(nodeNew, singlePath, resultPath, false);
            if (ret != E_OK) {
                return ret;
            }
        } else {
            resultPath.emplace_back(singlePath);
        }
        for (int i = 0; i < insertCount; i++) {
            singlePath.pop_back();
        }
        node = node.GetNext();
    }
    return E_OK;
}

std::vector<std::vector<std::string>> JsonCommon::ParsePath(const JsonObject &root, int &errCode)
{
    std::vector<std::vector<std::string>> resultPath;
    JsonObject projectionJson = root.GetChild();
    std::vector<std::string> singlePath;
    errCode = ParseNode(projectionJson, singlePath, resultPath, true);
    return resultPath;
}

namespace {
JsonFieldPath SplitePath(const JsonFieldPath &path, bool &isCollapse)
{
    if (path.size() != 1) { // only first level has collapse field
        return path;
    }
    JsonFieldPath splitPath;
    const std::string &str = path[0];
    size_t start = 0;
    size_t end = 0;
    while ((end = str.find('.', start)) != std::string::npos) {
        splitPath.push_back(str.substr(start, end - start));
        start = end + 1;
    }
    if (start < str.length()) {
        splitPath.push_back(str.substr(start));
    }
    isCollapse = (splitPath.size() > 1);
    return splitPath;
}

JsonFieldPath ExpendPathForField(const JsonFieldPath &path, bool &isCollapse)
{
    JsonFieldPath splitPath;
    if (path.empty()) {
        return path;
    }
    const std::string &str = path.back();
    size_t start = 0;
    size_t end = 0;
    while ((end = str.find('.', start)) != std::string::npos) {
        splitPath.push_back(str.substr(start, end - start));
        start = end + 1;
    }
    if (start < str.length()) {
        splitPath.push_back(str.substr(start));
    }
    isCollapse = (splitPath.size() > 1);
    for (size_t i = 1; i < path.size(); i++) {
        splitPath.emplace_back(path[i]);
    }
    return splitPath;
}

void JsonObjectIterator(const JsonObject &obj, const JsonFieldPath &path,
    std::function<bool(const JsonFieldPath &path, const JsonObject &father, const JsonObject &item)> AppendFoo)
{
    JsonObject child = obj.GetChild();
    while (!child.IsNull()) {
        JsonFieldPath childPath = path;
        childPath.push_back(child.GetItemField());
        if (AppendFoo != nullptr && AppendFoo(childPath, obj, child)) {
            JsonObjectIterator(child, childPath, AppendFoo);
        }
        child = child.GetNext();
    }
}

void JsonObjectIterator(const JsonObject &obj, JsonFieldPath path,
    std::function<bool(JsonFieldPath &path, const JsonObject &item)> matchFoo)
{
    JsonObject child = obj.GetChild();
    while (!child.IsNull()) {
        JsonFieldPath childPath = path;
        childPath.push_back(child.GetItemField());
        if (matchFoo != nullptr && matchFoo(childPath, child)) {
            JsonObjectIterator(child, childPath, matchFoo);
        }
        child = child.GetNext();
    }
}

bool IsNumber(const std::string &str)
{
    return std::all_of(str.begin(), str.end(), [](char c) {
        return std::isdigit(c);
    });
}

bool AddSpliteHitField(const JsonObject &src, const JsonObject &item, JsonFieldPath &hitPath,
    JsonFieldPath &abandonPath, int &externErrCode)
{
    if (hitPath.empty()) {
        return true;
    }

    int errCode = E_OK;
    JsonFieldPath preHitPath = hitPath;
    preHitPath.pop_back();
    JsonObject preHitItem = src.FindItem(preHitPath, errCode);
    // if FindItem errCode is not E_OK, GetObjectItem errCode should be E_NOT_FOUND
    JsonObject hitItem = preHitItem.GetObjectItem(hitPath.back(), errCode);
    if (errCode == -E_NOT_FOUND) {
        return true;
    }

    if (!abandonPath.empty()) {
        abandonPath.pop_back();
    }

    if (hitItem.IsNull()) {
        return true;
    }

    for (int32_t i = static_cast<int32_t>(abandonPath.size()) - 1; i > -1; i--) {
        if (hitItem.GetType() != JsonObject::Type::JSON_OBJECT) {
            GLOGE("Add collapse item to object failed, path not exist.");
            externErrCode = -E_DATA_CONFLICT;
            return false;
        }
        if (IsNumber(abandonPath[i])) {
            externErrCode = -E_DATA_CONFLICT;
            return false;
        }
        errCode = (i == 0) ? hitItem.AddItemToObject(abandonPath[i], item) : hitItem.AddItemToObject(abandonPath[i]);
        externErrCode = (externErrCode == E_OK ? errCode : externErrCode);
    }
    return false;
}

bool AddSpliteField(const JsonObject &src, const JsonObject &item, const JsonFieldPath &itemPath, int &externErrCode)
{
    int errCode = E_OK;
    JsonFieldPath abandonPath;
    JsonFieldPath hitPath = itemPath;
    while (!hitPath.empty()) {
        abandonPath.emplace_back(hitPath.back());
        JsonObject srcFatherItem = src.FindItem(hitPath, errCode);
        if (errCode == E_OK) {
            break;
        }
        if (!srcFatherItem.IsNull()) {
            break;
        }
        hitPath.pop_back();
    }

    if (!AddSpliteHitField(src, item, hitPath, abandonPath, externErrCode)) {
        return false;
    }

    JsonObject hitItem = src.FindItem(hitPath, errCode);
    if (errCode != E_OK) {
        return false;
    }
    JsonFieldPath newHitPath;
    for (int32_t i = static_cast<int32_t>(abandonPath.size()) - 1; i > -1; i--) {
        if (hitItem.GetType() != JsonObject::Type::JSON_OBJECT) {
            GLOGE("Add collapse item to object failed, path not exist.");
            externErrCode = -E_DATA_CONFLICT;
            return false;
        }
        if (IsNumber(abandonPath[i])) {
            externErrCode = -E_DATA_CONFLICT;
            return false;
        }
        errCode = (i == 0 ? hitItem.AddItemToObject(abandonPath[i], item) : hitItem.AddItemToObject(abandonPath[i]));
        externErrCode = (externErrCode == E_OK ? errCode : externErrCode);
        newHitPath.emplace_back(abandonPath[i]);
        hitItem = hitItem.FindItem(newHitPath, errCode);
        if (errCode != E_OK) {
            return false;
        }
        newHitPath.pop_back();
    }
    return false;
}

bool JsonValueReplace(const JsonObject &src, const JsonFieldPath &fatherPath, const JsonObject &father,
    const JsonObject &item, int &externErrCode)
{
    int errCode = E_OK;
    JsonFieldPath granPaPath = fatherPath;
    if (!granPaPath.empty()) {
        granPaPath.pop_back();
        JsonObject fatherItem = src.FindItem(granPaPath, errCode);
        if (errCode != E_OK) {
            externErrCode = (externErrCode == E_OK ? errCode : externErrCode);
            GLOGE("Find father item in source json object failed. %d", errCode);
            return false;
        }
        fatherItem.ReplaceItemInObject(item.GetItemField().c_str(), item, errCode);
        if (errCode != E_OK) {
            externErrCode = (externErrCode == E_OK ? errCode : externErrCode);
            GLOGE("Find father item in source json object failed. %d", errCode);
            return false;
        }
    } else {
        JsonObject fatherItem = src.FindItem(fatherPath, errCode);
        if (errCode != E_OK) {
            externErrCode = (externErrCode == E_OK ? errCode : externErrCode);
            GLOGE("Find father item in source json object failed. %d", errCode);
            return false;
        }
        if (father.GetChild().IsNull()) {
            externErrCode = -E_NO_DATA;
            GLOGE("Replace falied, no data match");
            return false;
        }
        if (!item.GetItemField(errCode).empty()) {
            fatherItem.ReplaceItemInObject(item.GetItemField().c_str(), item, errCode);
            if (errCode != E_OK) {
                return false;
            }
        }
    }
    return true;
}

bool JsonNodeReplace(const JsonObject &src, const JsonFieldPath &itemPath, const JsonObject &father,
    const JsonObject &item, int &externErrCode)
{
    int errCode = E_OK;
    JsonFieldPath fatherPath = itemPath;
    fatherPath.pop_back();
    if (!fatherPath.empty()) {
        JsonObject fatherItem = src.FindItem(fatherPath, errCode);
        if (errCode != E_OK) {
            externErrCode = (externErrCode == E_OK ? errCode : externErrCode);
            GLOGE("Find father item in source json object failed. %d", errCode);
            return false;
        }
        if (fatherItem.GetType() == JsonObject::Type::JSON_ARRAY && IsNumber(itemPath.back())) {
            fatherItem.ReplaceItemInArray(std::stoi(itemPath.back()), item, errCode);
            if (errCode != E_OK) {
                externErrCode = (externErrCode == E_OK ? errCode : externErrCode);
                GLOGE("Find father item in source json object failed. %d", errCode);
            }
            return false;
        }
        fatherItem.ReplaceItemInObject(itemPath.back().c_str(), item, errCode);
        if (errCode != E_OK) {
            externErrCode = (externErrCode == E_OK ? errCode : externErrCode);
            GLOGE("Find father item in source json object failed. %d", errCode);
            return false;
        }
    } else {
        JsonObject fatherItem = src.FindItem(fatherPath, errCode);
        if (errCode != E_OK) {
            externErrCode = (externErrCode == E_OK ? errCode : externErrCode);
            GLOGE("Find father item in source json object failed. %d", errCode);
            return false;
        }
        if (father.GetChild().IsNull()) {
            externErrCode = -E_NO_DATA;
            GLOGE("Replace falied, no data match");
            return false;
        }
        fatherItem.ReplaceItemInObject(itemPath.back().c_str(), item, errCode);
        if (errCode != E_OK) {
            externErrCode = (externErrCode == E_OK ? errCode : externErrCode);
            GLOGE("Find father item in source json object failed. %d", errCode);
            return false;
        }
    }
    return true;
}

bool JsonNodeAppend(const JsonObject &src, const JsonFieldPath &path, const JsonObject &father, const JsonObject &item,
    int &externErrCode)
{
    bool isCollapse = false;
    JsonFieldPath itemPath = ExpendPathForField(path, isCollapse);
    JsonFieldPath fatherPath = itemPath;
    fatherPath.pop_back();

    int errCode = E_OK;
    JsonObject srcFatherItem = src.FindItem(fatherPath, errCode);
    std::string lastFieldName = itemPath.back();
    if (errCode != E_OK) {
        AddSpliteField(src, item, itemPath, externErrCode);
        return false;
    }
    // This condition is to determine that the path has a point operator,
    // and the name of the last path cannot be a number or the srcItem to be added is an array, otherwise.
    // adding a node with the number fieldName does not legal.
    if (isCollapse && (!IsNumber(lastFieldName) || srcFatherItem.GetType() == JsonObject::Type::JSON_ARRAY)) {
        errCode = srcFatherItem.AddItemToObject(lastFieldName, item);
        if (errCode != E_OK) {
            externErrCode = (externErrCode == E_OK ? errCode : externErrCode);
            GLOGE("Add item to object failed. %d", errCode);
            return false;
        }
        return false;
    }
    if (!isCollapse) {
        bool ret = JsonValueReplace(src, fatherPath, father, item, externErrCode);
        if (!ret) {
            return false; // replace failed
        }
        return false; // Different node types, overwrite directly, skip child node
    }
    GLOGE("Add nothing because data conflict");
    externErrCode = -E_DATA_CONFLICT;
    return false; // Source path not exist, overwrite directly, skip child node
}
} // namespace

int JsonCommon::Append(const JsonObject &src, const JsonObject &add, bool isReplace)
{
    int externErrCode = E_OK;
    JsonObjectIterator(add, {},
        [&src, &externErrCode, &isReplace](const JsonFieldPath &path,
            const JsonObject &father, const JsonObject &item) {
            bool isCollapse = false; // Whether there is a path generated by the dot operator, such as t1.t2.t3
            JsonFieldPath itemPath = ExpendPathForField(path, isCollapse);
            if (src.IsFieldExists(itemPath)) {
                int errCode = E_OK;
                JsonObject srcItem = src.FindItem(itemPath, errCode);
                if (errCode != E_OK) {
                    externErrCode = (externErrCode == E_OK ? errCode : externErrCode);
                    GLOGE("Find item in source json object failed. %d", errCode);
                    return false;
                }
                bool ret = JsonNodeReplace(src, itemPath, father, item, externErrCode);
                if (!ret) {
                    return false;
                }
                return false;
            } else {
                if (isReplace) {
                    GLOGE("path not exist, replace failed");
                    externErrCode = -E_NO_DATA;
                    return false;
                }
                return JsonNodeAppend(src, path, father, item, externErrCode);
            }
        });
    return externErrCode;
}

bool JsonCommon::isValueEqual(const ValueObject &srcValue, const ValueObject &targetValue)
{
    if (srcValue.GetValueType() == targetValue.GetValueType()) {
        switch (srcValue.GetValueType()) {
            case ValueObject::ValueType::VALUE_NULL:
                return true;
            case ValueObject::ValueType::VALUE_BOOL:
                return srcValue.GetBoolValue() == targetValue.GetBoolValue();
            case ValueObject::ValueType::VALUE_NUMBER:
                return srcValue.GetDoubleValue() == targetValue.GetDoubleValue();
            case ValueObject::ValueType::VALUE_STRING:
                return srcValue.GetStringValue() == targetValue.GetStringValue();
        }
    }
    return false;
}

bool JsonCommon::IsArrayMatch(const JsonObject &src, const JsonObject &target, int &isAlreadyMatched)
{
    JsonObject srcChild = src.GetChild();
    JsonObject targetObj = target;
    bool isMatch = false;
    int errCode = E_OK;
    while (!srcChild.IsNull()) {
        if (srcChild.GetType() == JsonObject::Type::JSON_OBJECT && target.GetType() == JsonObject::Type::JSON_OBJECT &&
            (IsJsonNodeMatch(srcChild, target, errCode))) { // The return value reflects the value of errCode
            isMatch = true;
            isAlreadyMatched = 1;
            break;
        }
        srcChild = srcChild.GetNext();
    }
    return isMatch;
}

bool JsonCommon::IsObjectItemMatch(const JsonObject &srcItem, const JsonObject &item, int &isAlreadyMatched,
    bool &isCollapse, int &isMatchFlag)
{
    if (srcItem.GetType() == JsonObject::Type::JSON_ARRAY && item.GetType() == JsonObject::Type::JSON_ARRAY &&
        !isAlreadyMatched) {
        bool isEqual = (srcItem == item);
        if (!isEqual) { // Filter value is No equal with src
            isMatchFlag = isEqual;
        }
        isAlreadyMatched = isMatchFlag;
        return false; // Both leaf node, no need iterate
    }
    if (srcItem.GetType() == JsonObject::Type::JSON_LEAF && item.GetType() == JsonObject::Type::JSON_LEAF &&
        !isAlreadyMatched) {
        bool isEqual = isValueEqual(srcItem.GetItemValue(), item.GetItemValue());
        if (!isEqual) { // Filter value is No equal with src
            isMatchFlag = isEqual;
        }
        isAlreadyMatched = isMatchFlag;
        return false; // Both leaf node, no need iterate
    } else if (srcItem.GetType() != item.GetType()) {
        if (srcItem.GetType() == JsonObject::Type::JSON_ARRAY) { // srcItem Type is ARRAY, item Type is not ARRAY
            bool isEqual = IsArrayMatch(srcItem, item, isAlreadyMatched);
            if (!isEqual) {
                isMatchFlag = isEqual;
            }
            return true;
        }
        isMatchFlag = false;
        return false; // Different node types, overwrite directly, skip child node
    }
    return true; // Both array or object
}

bool JsonCommon::JsonEqualJudge(const JsonFieldPath &itemPath, const JsonObject &src, const JsonObject &item,
    bool &isCollapse, int &isMatchFlag)
{
    int errCode = E_OK;
    JsonObject srcItem = src.FindItemPowerMode(itemPath, errCode);
    if (errCode != -E_JSON_PATH_NOT_EXISTS && srcItem == item) {
        isMatchFlag = true;
        return false;
    }
    JsonFieldPath granpaPath = itemPath;
    std::string lastFieldName = granpaPath.back();
    granpaPath.pop_back();
    JsonObject granpaItem = src.FindItemPowerMode(granpaPath, errCode);
    if (errCode != -E_JSON_PATH_NOT_EXISTS && granpaItem.GetType() == JsonObject::Type::JSON_ARRAY && isCollapse) {
        JsonObject fatherItem = granpaItem.GetChild();
        while (!fatherItem.IsNull()) {
            if ((fatherItem.GetObjectItem(lastFieldName, errCode) == item)) { // this errCode is always E_OK
                isMatchFlag = true;
                break;
            }
            isMatchFlag = false;
            fatherItem = fatherItem.GetNext();
        }
        return false;
    }
    int isAlreadyMatched = 0; // means no match anything
    return IsObjectItemMatch(srcItem, item, isAlreadyMatched, isCollapse, isMatchFlag);
}

bool JsonCommon::IsJsonNodeMatch(const JsonObject &src, const JsonObject &target, int &errCode)
{
    errCode = E_OK;
    int isMatchFlag = true;
    JsonObjectIterator(target, {}, [&src, &isMatchFlag, &errCode](const JsonFieldPath &path, const JsonObject &item) {
        int isAlreadyMatched = 0;
        bool isCollapse = false;
        if (isMatchFlag == false) {
            return false;
        }
        JsonFieldPath itemPath = SplitePath(path, isCollapse);
        if (src.IsFieldExistsPowerMode(itemPath)) {
            if (isCollapse) {
                return JsonEqualJudge(itemPath, src, item, isCollapse, isMatchFlag);
            } else {
                JsonObject srcItem = src.FindItemPowerMode(itemPath, errCode);
                if (errCode != E_OK) {
                    return false;
                }
                if (srcItem.GetType() == JsonObject::Type::JSON_ARRAY) {
                    return JsonEqualJudge(itemPath, src, item, isCollapse, isMatchFlag);
                }
                if (srcItem == item) {
                    isMatchFlag = true;
                    isAlreadyMatched = true;
                    return false;
                }
                isMatchFlag = false;
                return false;
            }
        } else {
            std::vector<ValueObject> ItemLeafValue = GetLeafValue(item);
            for (auto ValueItem : ItemLeafValue) {
                // filter leaf is null, Src leaf is dont exist.
                if (ValueItem.GetValueType() == ValueObject::ValueType::VALUE_NULL) {
                    isMatchFlag = true;
                    return false;
                }
            }
            if (isCollapse) { // Match failed, path not exist
                isMatchFlag = false;
                return false;
            }
            if (isAlreadyMatched == 0) { // Not match anything
                isMatchFlag = false;
            }
            // Source path not exist, if leaf value is null, isMatchFlag become true, else it will become false.
            return false;
        }
    });
    return isMatchFlag;
}
} // namespace DocumentDB