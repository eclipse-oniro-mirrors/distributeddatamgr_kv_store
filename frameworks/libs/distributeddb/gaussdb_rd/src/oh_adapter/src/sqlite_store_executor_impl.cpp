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

#include "sqlite_store_executor_impl.h"

#include "check_common.h"
#include "rd_db_constant.h"
#include "doc_errno.h"
#include "document_key.h"
#include "rd_log_print.h"
#include "rd_sqlite_utils.h"

namespace DocumentDB {
constexpr const uint8_t KEY_TYPE = uint8_t(DocIdType::STRING);
int SqliteStoreExecutorImpl::CreateDatabase(const std::string &path, const DBConfig &config, sqlite3 *&db)
{
    if (db != nullptr) {
        return -E_INVALID_ARGS;
    }

    int errCode = RDSQLiteUtils::CreateDataBase(path, 0, db);
    if (errCode != E_OK || db == nullptr) {
        GLOGE("Open or create database failed. %d", errCode);
        return errCode;
    }

    std::string pageSizeSql = "PRAGMA page_size=" + std::to_string(config.GetPageSize() * 1024);
    errCode = RDSQLiteUtils::ExecSql(db, pageSizeSql);
    if (errCode != E_OK) {
        GLOGE("Set db page size failed. %d", errCode);
        goto END;
    }

    errCode = RDSQLiteUtils::ExecSql(db, "PRAGMA journal_mode=WAL;");
    if (errCode != E_OK) {
        GLOGE("Set db journal_mode failed. %d", errCode);
        goto END;
    }

    errCode = RDSQLiteUtils::ExecSql(db, "CREATE TABLE IF NOT EXISTS grd_meta (key BLOB PRIMARY KEY, value BLOB);");
    if (errCode != E_OK) {
        GLOGE("Create meta table failed. %d", errCode);
        goto END;
    }

    return E_OK;

END:
    sqlite3_close_v2(db);
    db = nullptr;
    return errCode;
}

SqliteStoreExecutorImpl::SqliteStoreExecutorImpl(sqlite3 *handle) : dbHandle_(handle) {}

SqliteStoreExecutorImpl::~SqliteStoreExecutorImpl()
{
    sqlite3_close_v2(dbHandle_);
    dbHandle_ = nullptr;
}

int SqliteStoreExecutorImpl::GetDBConfig(std::string &config)
{
    std::string dbConfigKeyStr = "DB_CONFIG";
    Key dbConfigKey = { dbConfigKeyStr.begin(), dbConfigKeyStr.end() };
    Value dbConfigVal;
    int errCode = GetDataByKey("grd_meta", dbConfigKey, dbConfigVal);
    config.assign(dbConfigVal.begin(), dbConfigVal.end());
    return errCode;
}

int SqliteStoreExecutorImpl::SetDBConfig(const std::string &config)
{
    std::string dbConfigKeyStr = "DB_CONFIG";
    Key dbConfigKey = { dbConfigKeyStr.begin(), dbConfigKeyStr.end() };
    Value dbConfigVal = { config.begin(), config.end() };
    return PutData("grd_meta", dbConfigKey, dbConfigVal, false); // dont need to add Key type;
}

int SqliteStoreExecutorImpl::StartTransaction()
{
    return RDSQLiteUtils::BeginTransaction(dbHandle_, TransactType::IMMEDIATE);
}

int SqliteStoreExecutorImpl::Commit()
{
    return RDSQLiteUtils::CommitTransaction(dbHandle_);
}

int SqliteStoreExecutorImpl::Rollback()
{
    return RDSQLiteUtils::RollbackTransaction(dbHandle_);
}

int SqliteStoreExecutorImpl::PutData(const std::string &collName, Key &key, const Value &value, bool isNeedAddKeyType)
{
    if (dbHandle_ == nullptr) {
        return -E_ERROR;
    }
    if (isNeedAddKeyType) {
        key.push_back(KEY_TYPE); // Stitching ID type
    }
    std::string sql = "INSERT OR REPLACE INTO '" + collName + "' VALUES (?,?);";
    int errCode = RDSQLiteUtils::ExecSql(
        dbHandle_, sql,
        [key, value](sqlite3_stmt *stmt) {
            RDSQLiteUtils::BindBlobToStatement(stmt, 1, key);
            RDSQLiteUtils::BindBlobToStatement(stmt, 2, value);
            return E_OK;
        },
        nullptr);
    if (errCode != E_OK) {
        GLOGE("[sqlite executor] Put data failed. err=%d", errCode);
        if (errCode == -E_ERROR) {
            GLOGE("Cant find the collection");
            return -E_INVALID_ARGS;
        }
        return errCode;
    }
    return E_OK;
}

int SqliteStoreExecutorImpl::InsertData(const std::string &collName, Key &key, const Value &value,
    bool isNeedAddKeyType)
{
    if (dbHandle_ == nullptr) {
        return -E_ERROR;
    }
    if (isNeedAddKeyType) {
        key.push_back(KEY_TYPE); // Stitching ID type
    }
    std::string sql = "INSERT INTO '" + collName + "' VALUES (?,?);";
    int errCode = RDSQLiteUtils::ExecSql(
        dbHandle_, sql,
        [key, value](sqlite3_stmt *stmt) {
            RDSQLiteUtils::BindBlobToStatement(stmt, 1, key);
            RDSQLiteUtils::BindBlobToStatement(stmt, 2, value);
            return E_OK;
        },
        nullptr);
    if (errCode != E_OK) {
        GLOGE("[sqlite executor] Put data failed. err=%d", errCode);
        if (errCode == -E_ERROR) {
            GLOGE("have same ID before");
            return -E_DATA_CONFLICT;
        }
        return errCode;
    }
    return E_OK;
}

int SqliteStoreExecutorImpl::GetDataByKey(const std::string &collName, Key &key, Value &value) const
{
    if (dbHandle_ == nullptr) {
        GLOGE("Invalid db handle.");
        return -E_ERROR;
    }
    int innerErrorCode = -E_NOT_FOUND;
    std::string sql = "SELECT value FROM '" + collName + "' WHERE key=?;";
    int errCode = RDSQLiteUtils::ExecSql(
        dbHandle_, sql,
        [key](sqlite3_stmt *stmt) {
            RDSQLiteUtils::BindBlobToStatement(stmt, 1, key);
            return E_OK;
        },
        [&value, &innerErrorCode](sqlite3_stmt *stmt, bool &isMatchOneData) {
            RDSQLiteUtils::GetColumnBlobValue(stmt, 0, value);
            innerErrorCode = E_OK;
            return E_OK;
        });
    if (errCode != E_OK) {
        GLOGE("[sqlite executor] Get data failed. err=%d", errCode);
        return errCode;
    }
    return innerErrorCode;
}

int SqliteStoreExecutorImpl::GetDataById(const std::string &collName, Key &key, Value &value) const
{
    if (dbHandle_ == nullptr) {
        GLOGE("Invalid db handle.");
        return -E_ERROR;
    }
    key.push_back(KEY_TYPE); // Stitching ID type
    int innerErrorCode = -E_NOT_FOUND;
    std::string sql = "SELECT value FROM '" + collName + "' WHERE key=?;";
    int errCode = RDSQLiteUtils::ExecSql(
        dbHandle_, sql,
        [key](sqlite3_stmt *stmt) {
            RDSQLiteUtils::BindBlobToStatement(stmt, 1, key);
            return E_OK;
        },
        [&value, &innerErrorCode](sqlite3_stmt *stmt, bool &isMatchOneData) {
            RDSQLiteUtils::GetColumnBlobValue(stmt, 0, value);
            innerErrorCode = E_OK;
            return E_OK;
        });
    if (errCode != E_OK) {
        GLOGE("[sqlite executor] Get data failed. err=%d", errCode);
        return errCode;
    }
    return innerErrorCode;
}

std::string GeneralInsertSql(const std::string &collName, Key &key, int isIdExist)
{
    std::string sqlEqual = "SELECT key, value FROM '" + collName + "' WHERE key=?;";
    std::string sqlOrder = "SELECT key, value FROM '" + collName + "' ORDER BY KEY;";
    std::string sqlLarger = "SELECT key, value FROM '" + collName + "' WHERE key>?;";
    if (isIdExist) {
        return sqlEqual;
    } else {
        return (key.empty()) ? sqlOrder : sqlLarger;
    }
}

void AssignValueToData(std::string &keyStr, const std::string &valueStr, std::pair<std::string, std::string> &values,
    int &innerErrorCode, bool &isMatchOneData)
{
    keyStr.pop_back(); // get id from really key.
    values.first = keyStr;
    values.second = valueStr;
    innerErrorCode = E_OK;
    isMatchOneData = true; // this args work in ExecSql fuction
}

int SqliteStoreExecutorImpl::GetDataByFilter(const std::string &collName, Key &key, const JsonObject &filterObj,
    std::pair<std::string, std::string> &values, int isIdExist) const
{
    if (dbHandle_ == nullptr) {
        GLOGE("Invalid db handle.");
        return -E_ERROR;
    }
    Value keyResult;
    Value valueResult;
    bool isFindMatch = false;
    int innerErrorCode = -E_NOT_FOUND;
    std::string sql = GeneralInsertSql(collName, key, isIdExist);
    key.push_back(KEY_TYPE);
    std::string keyStr(key.begin(), key.end());
    int errCode = RDSQLiteUtils::ExecSql(
        dbHandle_, sql,
        [key](sqlite3_stmt *stmt) {
            if (!key.empty()) {
                RDSQLiteUtils::BindBlobToStatement(stmt, 1, key);
            }
            return E_OK;
        },
        [&keyResult, &innerErrorCode, &valueResult, &filterObj, &values, &isFindMatch](sqlite3_stmt *stmt,
            bool &isMatchOneData) {
            RDSQLiteUtils::GetColumnBlobValue(stmt, 0, keyResult);
            RDSQLiteUtils::GetColumnBlobValue(stmt, 1, valueResult);
            std::string keyStr(keyResult.begin(), keyResult.end());
            std::string valueStr(valueResult.begin(), valueResult.end());
            JsonObject srcObj = JsonObject::Parse(valueStr, innerErrorCode, true);
            if (innerErrorCode != E_OK) {
                GLOGE("srcObj Parsed failed");
                return innerErrorCode;
            }
            if (JsonCommon::IsJsonNodeMatch(srcObj, filterObj, innerErrorCode)) {
                isFindMatch = true; // this args work in this function
                (void)AssignValueToData(keyStr, valueStr, values, innerErrorCode, isMatchOneData);
                return E_OK; // match count;
            }
            innerErrorCode = E_OK;
            return E_OK;
        });
    if (errCode != E_OK) {
        GLOGE("[sqlite executor] Get data failed. err=%d", errCode);
        return errCode;
    }
    if (!isFindMatch) {
        return -E_NOT_FOUND;
    }
    return innerErrorCode;
}

int SqliteStoreExecutorImpl::DelData(const std::string &collName, Key &key)
{
    if (dbHandle_ == nullptr) {
        GLOGE("Invalid db handle.");
        return -E_ERROR;
    }
    key.push_back(KEY_TYPE);
    int errCode = 0;
    Value valueRet;
    if (GetDataByKey(collName, key, valueRet) != E_OK) {
        return -E_NO_DATA;
    }
    std::string sql = "DELETE FROM '" + collName + "' WHERE key=?;";
    errCode = RDSQLiteUtils::ExecSql(
        dbHandle_, sql,
        [key](sqlite3_stmt *stmt) {
            RDSQLiteUtils::BindBlobToStatement(stmt, 1, key);
            return E_OK;
        },
        nullptr);
    if (errCode != E_OK) {
        GLOGE("[sqlite executor] Delete data failed. err=%d", errCode);
        if (errCode == -E_ERROR) {
            GLOGE("Cant find the collection");
            return -E_NO_DATA;
        }
    }
    return errCode;
}

int SqliteStoreExecutorImpl::CreateCollection(const std::string &name, const std::string &option, bool ignoreExists)
{
    if (dbHandle_ == nullptr) {
        return -E_ERROR;
    }
    std::string collName = DBConstant::COLL_PREFIX + name;
    int errCode = E_OK;
    bool isExists = IsCollectionExists(collName, errCode);
    if (errCode != E_OK) {
        return errCode;
    }

    if (isExists) {
        GLOGW("[sqlite executor] Create collection failed, collection already exists.");
        return ignoreExists ? E_OK : -E_COLLECTION_CONFLICT;
    }

    std::string sql = "CREATE TABLE IF NOT EXISTS '" + collName + "' (key BLOB PRIMARY KEY, value BLOB);";
    errCode = RDSQLiteUtils::ExecSql(dbHandle_, sql);
    if (errCode != E_OK) {
        GLOGE("[sqlite executor] Create collection failed. err=%d", errCode);
        return errCode;
    }

    errCode = SetCollectionOption(name, option);
    if (errCode != E_OK) {
        GLOGE("[sqlite executor] Set collection option failed. err=%d", errCode);
    }
    return errCode;
}

int SqliteStoreExecutorImpl::DropCollection(const std::string &name, bool ignoreNonExists)
{
    if (dbHandle_ == nullptr) {
        return -E_ERROR;
    }

    std::string collName = DBConstant::COLL_PREFIX + name;
    if (!ignoreNonExists) {
        int errCode = E_OK;
        bool isExists = IsCollectionExists(collName, errCode);
        if (errCode != E_OK) {
            return errCode;
        }
        if (!isExists) {
            GLOGE("[sqlite executor] Drop collection failed, collection not exists.");
            return -E_INVALID_ARGS;
        }
    }

    std::string sql = "DROP TABLE IF EXISTS '" + collName + "';";
    int errCode = RDSQLiteUtils::ExecSql(dbHandle_, sql);
    if (errCode != E_OK) {
        GLOGE("[sqlite executor] Drop collection failed. err=%d", errCode);
    }
    return errCode;
}

bool SqliteStoreExecutorImpl::IsCollectionExists(const std::string &name, int &errCode)
{
    bool isExists = false;
    std::string sql = "SELECT tbl_name FROM sqlite_master WHERE tbl_name=?;";
    errCode = RDSQLiteUtils::ExecSql(
        dbHandle_, sql,
        [name](sqlite3_stmt *stmt) {
            RDSQLiteUtils::BindTextToStatement(stmt, 1, name);
            return E_OK;
        },
        [&isExists](sqlite3_stmt *stmt, bool &isMatchOneData) {
            isExists = true;
            return E_OK;
        });
    if (errCode != E_OK) {
        GLOGE("Check collection exist failed. %d", errCode);
    }
    return isExists;
}

int SqliteStoreExecutorImpl::SetCollectionOption(const std::string &name, const std::string &option)
{
    std::string collOptKeyStr = "COLLECTION_OPTION_" + name;
    Key collOptKey = { collOptKeyStr.begin(), collOptKeyStr.end() };
    Value collOptVal = { option.begin(), option.end() };
    return PutData("grd_meta", collOptKey, collOptVal, false); // dont need to add key type;
}

int SqliteStoreExecutorImpl::CleanCollectionOption(const std::string &name)
{
    std::string collOptKeyStr = "COLLECTION_OPTION_" + name;
    Key collOptKey = { collOptKeyStr.begin(), collOptKeyStr.end() };
    return DelData("grd_meta", collOptKey);
}
} // namespace DocumentDB