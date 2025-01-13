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
#ifndef SQLITE_LOG_TABLE_MANAGER_H
#define SQLITE_LOG_TABLE_MANAGER_H
#include <mutex>

#include "relational_schema_object.h"
#include "sqlite_utils.h"

namespace DistributedDB {
class SqliteLogTableManager {
public:
    SqliteLogTableManager() = default;
    virtual ~SqliteLogTableManager() = default;

    virtual std::string CalcPrimaryKeyHash(const std::string &references, const TableInfo &table,
        const std::string &identity) = 0;

    // The parameter "identity" is a hash string that identifies a device
    int AddRelationalLogTableTrigger(sqlite3 *db, const TableInfo &table, const std::string &identity);

    int CreateRelationalLogTable(sqlite3 *db, const TableInfo &table);

    static int CreateKvSyncLogTable(sqlite3 *db);

    void CheckAndCreateTrigger(sqlite3 *db, const TableInfo &table, const std::string &identity);
protected:
    virtual void GetIndexSql(const TableInfo &table, std::vector<std::string> &schema);
    std::string GetLogTableName(const TableInfo &table) const;

    virtual std::string GetUpdatePkTrigger(const TableInfo &table, const std::string &identity);

    static std::string GetUpdateTimestamp(const TableInfo &table, bool defaultNewTime);

    static std::string GetUpdateWithAssignSql(const TableInfo &table, const std::string &emptyValue,
        const std::string &matchValue, const std::string &missMatchValue);

    static std::string CalcPkHash(const std::string &references, const std::vector<std::string> &pk);
private:
    virtual std::string GetInsertTrigger(const TableInfo &table, const std::string &identity) = 0;
    virtual std::string GetUpdateTrigger(const TableInfo &table, const std::string &identity) = 0;
    virtual std::string GetDeleteTrigger(const TableInfo &table, const std::string &identity) = 0;
    virtual std::vector<std::string> GetDropTriggers(const TableInfo &table) = 0;

    virtual std::string GetPrimaryKeySql(const TableInfo &table) = 0;

    static int UpgradeKvSyncLogTable(const std::string &tableName, sqlite3 *db);
    static int CreateKvCloudFlagIndex(const std::string &tableName, sqlite3 *db);
};
}
#endif // SQLITE_LOG_TABLE_MANAGER_H