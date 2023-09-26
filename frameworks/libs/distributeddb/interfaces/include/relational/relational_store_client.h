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

#ifndef RELATIONAL_STORE_CLIENT_H
#define RELATIONAL_STORE_CLIENT_H

#include <cstdint>
#include <functional>
#include <string>
#include <set>

#include "store_types.h"

typedef struct sqlite3 sqlite3;

struct ClientChangedData {
    std::map<std::string, DistributedDB::ChangeProperties> tableData;
};

using ClientObserver = std::function<void(ClientChangedData &clientChangedData)>;

DB_API DistributedDB::DBStatus RegisterClientObserver(sqlite3 *db, const ClientObserver &clientObserver);

DB_API DistributedDB::DBStatus UnRegisterClientObserver(sqlite3 *db);

#endif // RELATIONAL_STORE_CLIENT_H
