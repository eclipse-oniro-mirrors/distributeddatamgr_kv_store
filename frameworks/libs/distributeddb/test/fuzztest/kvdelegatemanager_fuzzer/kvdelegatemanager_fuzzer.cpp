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

#include "kvdelegatemanager_fuzzer.h"
#include <list>
#include <securec.h>
#include "kv_store_delegate_manager.h"
#include "log_print.h"

class KvDelegateManagerFuzzer {
    /* Keep C++ file names the same as the class name. */
};

namespace OHOS {
using namespace DistributedDB;

std::string GetRandomString(const uint8_t* data, size_t size, size_t len, uint32_t &start)
{
    std::string res;
    if (size == 0) {
        return "";
    }
    if (start >= size || start + len >= size) {
        return std::string(data, data + size - 1);
    }
    if (start + len > size) {
        res = std::string(data + start, data + start + size - 1);
        start += size;
    } else {
        res = std::string(data + start, data + start + len - 1);
        start += len;
    }
    return res;
}

void CombineTest(const uint8_t* data, size_t size)
{
    LOGD("Begin KvDelegateManagerFuzzer");
    const int paramCount = 3;
    for (size_t len = 1; len < (size / paramCount); len++) {
        uint32_t start = 0;
        std::string appId = GetRandomString(data, size, len, start);
        std::string userId = GetRandomString(data, size, len, start);
        std::string storeId = GetRandomString(data, size, len, start);
        std::string dir;
        (void) KvStoreDelegateManager::GetDatabaseDir(storeId, appId, userId, dir);
        (void) KvStoreDelegateManager::GetDatabaseDir(storeId, dir);
        (void) KvStoreDelegateManager::SetProcessLabel(appId, userId);
        bool syncDualTupleMode = static_cast<bool>(*data);
        (void) KvStoreDelegateManager::GetKvStoreIdentifier(userId, appId, storeId, syncDualTupleMode);
        AutoLaunchOption option;
        (void) KvStoreDelegateManager::EnableKvStoreAutoLaunch(userId, appId, storeId, option, nullptr);
        (void) KvStoreDelegateManager::DisableKvStoreAutoLaunch(userId, appId, storeId);
    }
    LOGD("End KvDelegateManagerFuzzer");
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::CombineTest(data, size);
    return 0;
}
