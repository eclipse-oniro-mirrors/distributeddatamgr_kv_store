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
#include "check_common.h"

#include <algorithm>
#include <climits>

#include "doc_errno.h"
#include "grd_base/grd_db_api.h"
#include "rd_log_print.h"
#include "securec.h"

using namespace DocumentDB;
namespace DocumentDB {
namespace {
constexpr const char *KEY_ID = "_id";
constexpr const char *COLLECTION_PREFIX_GRD = "GRD_";
constexpr const char *COLLECTION_PREFIX_GM_SYS = "GM_SYS";
const int MAX_COLLECTION_NAME = 512;
const int MAX_ID_LENS = 900;
const int JSON_DEEP_MAX = 4;

bool CheckCollectionNamePrefix(const std::string &name, const std::string &prefix)
{
    if (name.length() < prefix.length()) {
        return false;
    }

    return (strncasecmp(name.c_str(), prefix.c_str(), prefix.length()) == 0);
}

void ReplaceAll(std::string &inout, const std::string &what, const std::string &with)
{
    std::string::size_type pos{};
    while ((pos = inout.find(what.data(), pos, what.length())) != std::string::npos) {
        inout.replace(pos, what.length(), with.data(), with.length());
        pos += with.length();
    }
}
} // namespace

bool CheckCommon::CheckCollectionName(const std::string &collectionName, std::string &formattedName, int &errCode)
{
    if (collectionName.empty()) {
        errCode = -E_INVALID_ARGS;
        return false;
    }
    if (collectionName.length() + 1 > MAX_COLLECTION_NAME) { // with '\0'
        errCode = -E_OVER_LIMIT;
        return false;
    }
    if (CheckCollectionNamePrefix(collectionName, COLLECTION_PREFIX_GRD) ||
        CheckCollectionNamePrefix(collectionName, COLLECTION_PREFIX_GM_SYS)) {
        GLOGE("Collection name is illegal");
        errCode = -E_INVALID_COLL_NAME_FORMAT;
        return false;
    }

    formattedName = collectionName;
    std::transform(formattedName.begin(), formattedName.end(), formattedName.begin(), [](unsigned char c) {
        return std::tolower(c);
    });

    ReplaceAll(formattedName, "'", R"('')");
    return true;
}

static int CheckSingleFilterPath(std::vector<std::string> &singleFilterPath)
{
    if (singleFilterPath.empty()) {
        return -E_INVALID_JSON_FORMAT;
    }
    for (size_t j = 0; j < singleFilterPath.size(); j++) {
        if (singleFilterPath[j].empty()) {
            return -E_INVALID_ARGS;
        }
        for (auto oneChar : singleFilterPath[j]) {
            if (!((isalpha(oneChar)) || (isdigit(oneChar)) || (oneChar == '_'))) {
                return -E_INVALID_ARGS;
            }
        }
    }
    if (!singleFilterPath.empty() && !singleFilterPath[0].empty() && isdigit(singleFilterPath[0][0])) {
        return -E_INVALID_ARGS;
    }
    return E_OK;
}

int CheckCommon::CheckFilter(JsonObject &filterObj, std::vector<std::vector<std::string>> &filterPath, bool &isIdExist)
{
    for (size_t i = 0; i < filterPath.size(); i++) {
        if (filterPath[i].size() > JSON_DEEP_MAX) {
            GLOGE("filter's json deep is deeper than JSON_DEEP_MAX");
            return -E_INVALID_ARGS;
        }
    }
    int ret = E_OK;
    for (size_t i = 0; i < filterPath.size(); i++) {
        ret = CheckSingleFilterPath(filterPath[i]);
        if (ret != E_OK) {
            return ret;
        }
    }
    ret = CheckIdFormat(filterObj, isIdExist);
    if (ret != E_OK) {
        GLOGE("Filter Id format is illegal");
        return ret;
    }
    return ret;
}

int CheckCommon::CheckIdFormat(JsonObject &idObj, bool &isIdExisit)
{
    JsonObject idObjChild = idObj.GetChild();
    ValueObject idValue = JsonCommon::GetValueInSameLevel(idObjChild, KEY_ID, isIdExisit);
    if ((idValue.GetValueType() == ValueObject::ValueType::VALUE_NULL) && isIdExisit == false) {
        return E_OK;
    }
    if (idValue.GetValueType() != ValueObject::ValueType::VALUE_STRING) {
        return -E_INVALID_ARGS;
    }
    if (idValue.GetStringValue().length() + 1 > MAX_ID_LENS) { // with '\0'
        return -E_OVER_LIMIT;
    }
    return E_OK;
}

int CheckCommon::CheckDocument(JsonObject &documentObj, bool &isIdExist)
{
    if (documentObj.GetDeep() > JSON_DEEP_MAX) {
        GLOGE("documentObj's json deep is deeper than JSON_DEEP_MAX");
        return -E_INVALID_ARGS;
    }
    int ret = CheckIdFormat(documentObj, isIdExist);
    if (ret != E_OK) {
        return ret;
    }
    JsonObject documentObjChild = documentObj.GetChild();
    if (!JsonCommon::CheckJsonField(documentObjChild)) {
        GLOGE("Document json field format is illegal");
        return -E_INVALID_ARGS;
    }
    return E_OK;
}

int SplitFieldName(const std::string &fieldName, std::vector<std::string> &allFieldsName)
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
            tempParseName.clear();
        }
    }
    return E_OK;
}

static int CheckSingleUpdataDocPath(std::vector<std::string> &singleUpdataPath)
{
    for (const auto &fieldName : singleUpdataPath) {
        for (auto oneChar : fieldName) {
            if (!((isalpha(oneChar)) || (isdigit(oneChar)) || (oneChar == '_'))) {
                GLOGE("updata fieldName is illegal");
                return -E_INVALID_ARGS;
            }
        }
    }
    return E_OK;
}

int CheckCommon::CheckUpdata(JsonObject &updataObj)
{
    JsonObject jsonTemp = updataObj.GetChild();
    size_t maxDeep = 0;
    while (!jsonTemp.IsNull()) {
        std::vector<std::string> allFieldsName;
        int errCode = SplitFieldName(jsonTemp.GetItemField(), allFieldsName);
        if (errCode != E_OK) {
            return errCode;
        }
        errCode = CheckSingleUpdataDocPath(allFieldsName);
        if (errCode != E_OK) {
            return errCode;
        }
        maxDeep = std::max(allFieldsName.size() + jsonTemp.GetDeep(), maxDeep);
        if (maxDeep > JSON_DEEP_MAX) {
            GLOGE("document's json deep is deeper than JSON_DEEP_MAX");
            return -E_INVALID_ARGS;
        }
        jsonTemp = jsonTemp.GetNext();
    }
    bool isIdExist = true;
    CheckIdFormat(updataObj, isIdExist);
    if (isIdExist) {
        return -E_INVALID_ARGS;
    }
    return E_OK;
}

static int CheckSingleProjectionDocPath(std::vector<std::string> &singleProjectionPath)
{
    for (const auto &fieldName : singleProjectionPath) {
        if (fieldName.empty()) {
            return -E_INVALID_ARGS;
        }
        for (size_t j = 0; j < fieldName.size(); j++) {
            if (!((isalpha(fieldName[j])) || (isdigit(fieldName[j])) || (fieldName[j] == '_'))) {
                return -E_INVALID_ARGS;
            }
            if (j == 0 && (isdigit(fieldName[j]))) {
                return -E_INVALID_ARGS;
            }
        }
    }
    return E_OK;
}

int CheckCommon::CheckProjection(JsonObject &projectionObj, std::vector<std::vector<std::string>> &path)
{
    if (projectionObj.GetDeep() > JSON_DEEP_MAX) {
        GLOGE("projectionObj's json deep is deeper than JSON_DEEP_MAX");
        return -E_INVALID_ARGS;
    }
    int errCode = E_OK;
    if (!projectionObj.GetChild().IsNull()) {
        JsonObject projectionObjChild = projectionObj.GetChild();
        if (!JsonCommon::CheckProjectionField(projectionObjChild, errCode)) {
            GLOGE("projection json field format is illegal");
            return errCode;
        }
    }
    for (size_t i = 0; i < path.size(); i++) {
        if (path[i].empty()) {
            return -E_INVALID_JSON_FORMAT;
        }
        errCode = CheckSingleProjectionDocPath(path[i]);
        if (errCode != E_OK) {
            return errCode;
        }
    }
    return E_OK;
}
} // namespace DocumentDB