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

#include "collection.h"

#include "check_common.h"
#include "rd_db_constant.h"
#include "doc_errno.h"
#include "document_key.h"
#include "rd_log_print.h"

namespace DocumentDB {
Collection::Collection(const std::string &name, KvStoreExecutor *executor) : executor_(executor)
{
    std::string lowerCaseName = name;
    std::transform(lowerCaseName.begin(), lowerCaseName.end(), lowerCaseName.begin(), [](unsigned char c) {
        return std::tolower(c);
    });
    name_ = DBConstant::COLL_PREFIX + lowerCaseName;
}

Collection::~Collection()
{
    executor_ = nullptr;
}

int Collection::InsertUntilSuccess(Key &key, const std::string &id, Value &valSet)
{
    DocKey docKey;
    key.assign(id.begin(), id.end());
    int errCode = executor_->InsertData(name_, key, valSet);
    while (errCode == -E_DATA_CONFLICT) { // if id alreay exist, create new one.
        DocumentKey::GetOidDocKey(docKey);
        key.assign(docKey.key.begin(), docKey.key.end());
        errCode = executor_->InsertData(name_, key, valSet);
    }
    return errCode;
}
int Collection::InsertDocument(const std::string &id, const std::string &document, bool &isIdExist)
{
    if (executor_ == nullptr) {
        return -E_INNER_ERROR;
    }
    int errCode = E_OK;
    bool isCollectionExist = IsCollectionExists(errCode);
    if (errCode != E_OK) {
        return errCode;
    }
    if (!isCollectionExist) {
        return -E_INVALID_ARGS;
    }
    Key key;
    Value valSet(document.begin(), document.end());
    if (!isIdExist) {
        return InsertUntilSuccess(key, id, valSet);
    }
    key.assign(id.begin(), id.end());
    return executor_->InsertData(name_, key, valSet);
}

int Collection::GetDocumentById(Key &key, Value &document) const
{
    if (executor_ == nullptr) {
        return -E_INNER_ERROR;
    }
    return executor_->GetDataById(name_, key, document);
}

int Collection::DeleteDocument(Key &key)
{
    if (executor_ == nullptr) {
        return -E_INNER_ERROR;
    }
    int errCode = E_OK;
    bool isCollectionExist = IsCollectionExists(errCode);
    if (errCode != E_OK) {
        return errCode;
    }
    if (!isCollectionExist) {
        return -E_INVALID_ARGS;
    }
    return executor_->DelData(name_, key);
}

int Collection::GetMatchedDocument(const JsonObject &filterObj, Key &key, std::pair<std::string, std::string> &values,
    int isIdExist) const
{
    if (executor_ == nullptr) {
        return -E_INNER_ERROR;
    }
    return executor_->GetDataByFilter(name_, key, filterObj, values, isIdExist);
}

int Collection::IsCollectionExists(int &errCode)
{
    return executor_->IsCollectionExists(name_, errCode);
}

int Collection::UpsertDocument(const std::string &id, const std::string &newDocument, bool &isDataExist)
{
    if (executor_ == nullptr) {
        return -E_INNER_ERROR;
    }
    int errCode = E_OK;
    bool isCollExist = executor_->IsCollectionExists(name_, errCode);
    if (errCode != E_OK) {
        GLOGE("Check collection failed. %d", errCode);
        return -errCode;
    }
    if (!isCollExist) {
        GLOGE("Collection not created.");
        return -E_INVALID_ARGS;
    }
    Key key;
    Value valSet(newDocument.begin(), newDocument.end());
    if (!isDataExist) {
        return InsertUntilSuccess(key, id, valSet);
    }
    key.assign(id.begin(), id.end());
    return executor_->PutData(name_, key, valSet);
}

int Collection::UpdateDocument(const std::string &id, const std::string &newDocument)
{
    if (executor_ == nullptr) {
        return -E_INNER_ERROR;
    }
    int errCode = E_OK;
    bool isCollExist = executor_->IsCollectionExists(name_, errCode);
    if (errCode != E_OK) {
        GLOGE("Check collection failed. %d", errCode);
        return -errCode;
    }
    if (!isCollExist) {
        GLOGE("Collection not created.");
        return -E_INVALID_ARGS;
    }
    Key keyId(id.begin(), id.end());
    Value valSet(newDocument.begin(), newDocument.end());
    return executor_->PutData(name_, keyId, valSet);
}
} // namespace DocumentDB
