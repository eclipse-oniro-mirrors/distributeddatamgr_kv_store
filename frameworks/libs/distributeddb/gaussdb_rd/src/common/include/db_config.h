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

#ifndef DB_CONFIG_H
#define DB_CONFIG_H

#include <string>

namespace DocumentDB {
class DBConfig final {
public:
    static DBConfig ReadConfig(const std::string &confStr, int &errCode);
    ~DBConfig() = default;

    std::string ToString() const;

    int32_t GetPageSize() const;

    bool operator==(const DBConfig &targetConfig) const;
    bool operator!=(const DBConfig &targetConfig) const;

    bool CheckPersistenceEqual(const DBConfig &targetConfig) const;

private:
    static DBConfig GetDBConfigFromJsonStr(const std::string &confStr, int &errCode);
    DBConfig() = default;
    DBConfig(const DBConfig&) = default;
    DBConfig(DBConfig&&) = default;
    std::string configStr_ = {};
    int32_t pageSize_ = 4;           // 4: default page size k
    uint32_t redoFlushByTrx_ = 0;
    uint32_t redoPubBufSize_ = 1024; // 1024: default 1024k buff size
    int32_t maxConnNum_ = 100;       // 100: default max conn
    uint32_t bufferPoolSize_ = 1024; // 100: default 1024k pool size
    uint32_t crcCheckEnable_ = 1;
    uint32_t shareModeEnable_ = 0;
};
} // namespace DocumentDB
#endif // DB_CONFIG_H