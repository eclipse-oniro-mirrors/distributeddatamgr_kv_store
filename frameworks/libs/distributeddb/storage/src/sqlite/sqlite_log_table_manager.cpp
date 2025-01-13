/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "db_common.h"
#include "sqlite_log_table_manager.h"

namespace DistributedDB {
int SqliteLogTableManager::AddRelationalLogTableTrigger(sqlite3 *db, const TableInfo &table,
    const std::string &identity)
{
    std::vector<std::string> sqls = GetDropTriggers(table);
    std::string insertTrigger = GetInsertTrigger(table, identity);
    if (!insertTrigger.empty()) {
        sqls.emplace_back(insertTrigger);
    }
    std::string updateTrigger = GetUpdateTrigger(table, identity);
    if (!updateTrigger.empty()) {
        sqls.emplace_back(updateTrigger);
    }
    std::string deleteTrigger = GetDeleteTrigger(table, identity);
    if (!deleteTrigger.empty()) {
        sqls.emplace_back(deleteTrigger);
    }
    std::string updatePkTrigger = GetUpdatePkTrigger(table, identity);
    if (!updatePkTrigger.empty()) {
        sqls.emplace_back(updatePkTrigger);
    }
    // add insert,update,delete,update pk trigger
    for (const auto &sql : sqls) {
        int errCode = SQLiteUtils::ExecuteRawSQL(db, sql);
        if (errCode != E_OK) {
            LOGE("[LogTableManager] execute create log trigger sql failed, errCode=%d", errCode);
            return errCode;
        }
    }
    return E_OK;
}

int SqliteLogTableManager::CreateRelationalLogTable(sqlite3 *db, const TableInfo &table)
{
    const std::string tableName = GetLogTableName(table);
    std::string primaryKey = GetPrimaryKeySql(table);

    std::string createTableSql = "CREATE TABLE IF NOT EXISTS " + tableName + "(" \
        "data_key    INT NOT NULL," \
        "device      BLOB," \
        "ori_device  BLOB," \
        "timestamp   INT  NOT NULL," \
        "wtimestamp  INT  NOT NULL," \
        "flag        INT  NOT NULL," \
        "hash_key    BLOB NOT NULL," \
        "cloud_gid   TEXT," + \
        "extend_field BLOB," + \
        "cursor INT DEFAULT 0," + \
        "version TEXT DEFAULT ''," + \
        "sharing_resource TEXT DEFAULT ''," + \
        "status INT DEFAULT 0," + \
        primaryKey + ");";
    std::vector<std::string> logTableSchema;
    logTableSchema.emplace_back(createTableSql);
    GetIndexSql(table, logTableSchema);

    for (const auto &sql : logTableSchema) {
        int errCode = SQLiteUtils::ExecuteRawSQL(db, sql);
        if (errCode != E_OK) {
            LOGE("[LogTableManager] execute create log table schema failed, errCode=%d", errCode);
            return errCode;
        }
    }
    return E_OK;
}

int SqliteLogTableManager::CreateKvSyncLogTable(sqlite3 *db)
{
    const std::string tableName = "naturalbase_kv_aux_sync_data_log";
    const std::string primaryKey = "PRIMARY KEY(userid, hash_key)";
    std::string createTableSql = "CREATE TABLE IF NOT EXISTS " + tableName + "(" \
        "userid    TEXT NOT NULL," + \
        "hash_key  BLOB NOT NULL," + \
        "cloud_gid TEXT," + \
        "version   TEXT," + \
        "cloud_flag INT DEFAULT 0," + \
        primaryKey + ");";
    int errCode = SQLiteUtils::ExecuteRawSQL(db, createTableSql);
    if (errCode != E_OK) {
        LOGE("[LogTableManager] execute create cloud log table schema failed, errCode=%d", errCode);
        return errCode;
    }
    std::string createIndexSql = "CREATE INDEX IF NOT EXISTS gid_hash_key ON " + tableName + "(cloud_gid, hash_key)";
    errCode = SQLiteUtils::ExecuteRawSQL(db, createIndexSql);
    if (errCode != E_OK) {
        LOGE("[LogTableManager] execute create gid index failed, errCode=%d", errCode);
    }
    return UpgradeKvSyncLogTable(tableName, db);
}

void SqliteLogTableManager::GetIndexSql(const TableInfo &table, std::vector<std::string> &schema)
{
    const std::string tableName = GetLogTableName(table);

    std::string indexTimestampFlag = "CREATE INDEX IF NOT EXISTS " + std::string(DBConstant::RELATIONAL_PREFIX) +
        "time_flag_index ON " + tableName + "(timestamp, flag);";
    schema.emplace_back(indexTimestampFlag);

    std::string indexHashkey = "CREATE INDEX IF NOT EXISTS " + std::string(DBConstant::RELATIONAL_PREFIX) +
        "hashkey_index ON " + tableName + "(hash_key);";
    schema.emplace_back(indexHashkey);
}

std::string SqliteLogTableManager::GetLogTableName(const TableInfo &table) const
{
    return DBConstant::RELATIONAL_PREFIX + table.GetTableName() + "_log";
}

int SqliteLogTableManager::UpgradeKvSyncLogTable(const std::string &tableName, sqlite3 *db)
{
    TableInfo tableInfo;
    int errCode = SQLiteUtils::AnalysisSchemaFieldDefine(db, tableName, tableInfo);
    if (errCode != E_OK) {
        return errCode;
    }
    auto fields = tableInfo.GetFields();
    if (fields.find("cloud_flag") != fields.end()) {
        return CreateKvCloudFlagIndex(tableName, db);
    }
    std::string addFlagSql = "ALTER TABLE " + tableName + " ADD COLUMN cloud_flag INT DEFAULT 0";
    errCode = SQLiteUtils::ExecuteRawSQL(db, addFlagSql);
    if (errCode != E_OK) {
        LOGE("[LogTableManager] add cloud_flag failed, errCode=%d", errCode);
        return errCode;
    }
    return CreateKvCloudFlagIndex(tableName, db);
}

int SqliteLogTableManager::CreateKvCloudFlagIndex(const std::string &tableName, sqlite3 *db)
{
    std::string createIndexSql = "CREATE INDEX IF NOT EXISTS gid_hash_key_flag ON " + tableName +
        "(cloud_gid, hash_key, cloud_flag)";
    int errCode = SQLiteUtils::ExecuteRawSQL(db, createIndexSql);
    if (errCode != E_OK) {
        LOGE("[LogTableManager] add cloud_flag index failed, errCode=%d", errCode);
    }
    return errCode;
}

std::string SqliteLogTableManager::GetUpdatePkTrigger([[gnu::unused]] const TableInfo &table,
    [[gnu::unused]] const std::string &identity)
{
    return "";
}

std::string SqliteLogTableManager::GetUpdateTimestamp(const TableInfo &table, bool defaultNewTime)
{
    return GetUpdateWithAssignSql(table, "get_sys_time(0)", "get_sys_time(0)",
        defaultNewTime ? "get_sys_time(0)" : "timestamp");
}

std::string SqliteLogTableManager::GetUpdateWithAssignSql(const TableInfo &table, const std::string &emptyValue,
    const std::string &matchValue, const std::string &missMatchValue)
{
    auto syncFields = table.GetSyncField();
    if (syncFields.empty() || table.GetFields().size() <= syncFields.size()) {
        return emptyValue;
    }
    std::string sql = " CASE WHEN (";
    for (const auto &field : syncFields) {
        sql.append("(").append("OLD.'").append(field).append("'!= NEW.'").append(field).append("') OR");
    }
    // pop last OR
    sql.pop_back();
    sql.pop_back();
    sql.append(") THEN ").append(matchValue).append(" ELSE ").append(missMatchValue).append(" END");
    return sql;
}

int CheckTriggerExist(sqlite3 *db, const TableInfo &table, const std::string &triggerType, bool &exist)
{
    std::string checkSql = "select count(*) from sqlite_master where type = 'trigger' and tbl_name = '" +
        table.GetTableName() + "' and name = 'naturalbase_rdb_" + table.GetTableName() + "_ON_" + triggerType + "';";
    int count = 0;
    int errCode = SQLiteUtils::GetCountBySql(db, checkSql, count);
    if (errCode != E_OK) {
        LOGW("query trigger from db fail, errCode=%d", errCode);
        return errCode;
    }
    exist = count != 0;
    return E_OK;
}

void SqliteLogTableManager::CheckAndCreateTrigger(sqlite3 *db, const TableInfo &table, const std::string &identity)
{
    std::vector<std::string> sqls;
    bool insertTriggerExist = false;
    const std::string &tableName = table.GetTableName();
    if (CheckTriggerExist(db, table, "INSERT", insertTriggerExist) == E_OK && !insertTriggerExist) {
        LOGW("[%s [%zu]] Insert trigger does not exist, will be recreated",
            DBCommon::StringMiddleMasking(tableName).c_str(), tableName.size());
        std::string insertTriggerSql = GetInsertTrigger(table, identity);
        if (!insertTriggerSql.empty()) {
            sqls.emplace_back(insertTriggerSql);
        }
    }

    bool updateTriggerExist = false;
    if (CheckTriggerExist(db, table, "UPDATE", updateTriggerExist) == E_OK && !updateTriggerExist) {
        LOGW("[%s [%zu]] Update trigger does not exist, will be recreated",
            DBCommon::StringMiddleMasking(tableName).c_str(), tableName.size());
        std::string updateTriggerSql = GetUpdateTrigger(table, identity);
        if (!updateTriggerSql.empty()) {
            sqls.emplace_back(updateTriggerSql);
        }
    }

    bool deleteTriggerExist = false;
    if (CheckTriggerExist(db, table, "DELETE", deleteTriggerExist) == E_OK && !deleteTriggerExist) {
        LOGW("[%s [%zu]] Delete trigger does not exist, will be recreated",
            DBCommon::StringMiddleMasking(tableName).c_str(), tableName.size());
        std::string deleteTriggerSql = GetDeleteTrigger(table, identity);
        if (!deleteTriggerSql.empty()) {
            sqls.emplace_back(deleteTriggerSql);
        }
    }

    for (const auto &sql : sqls) {
        int errCode = SQLiteUtils::ExecuteRawSQL(db, sql);
        if (errCode != E_OK) {
            LOGW("[%s [%zu]] Failed to recreate trigger, errCode=%d", DBCommon::StringMiddleMasking(tableName).c_str(),
                tableName.size(), errCode);
        }
    }
}

std::string SqliteLogTableManager::CalcPkHash(const std::string &references, const std::vector<std::string> &pk)
{
    std::string sql;
    if (pk.size() == 1u) {
        sql = "calc_hash(" + references + "'" + pk.at(0) + "', 0)";
    } else {
        sql = "calc_hash(";
        for (const auto &it : pk) {
            sql += "calc_hash(" + references + "'" + it + "', 0)||";
        }
        sql.pop_back();
        sql.pop_back();
        sql += ", 0)";
    }
    return sql;
}
}