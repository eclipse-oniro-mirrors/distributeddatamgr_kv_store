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
#include "js_util.h"
#include "securec.h"

#define OHOS_ABILITY_RUNTIME_ABILITY_H
#define ABILITY_RUNTIME_NAPI_BASE_CONTEXT_H
#define DISTRIBUTEDDATAMGR_ENDIAN_CONVERTER_H
#define FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_BASE_INCLUDE_HAP_MODULE_INFO_H

#ifdef LOG_TAG
#undef LOG_TAG
#endif

#define be32toh(data) data
#define be64toh(data) data
#define htobe32(data) data
#define htobe64(data) data

#define GetCurrentAbility(env)    GetAbility()

#ifdef _WIN32
#define mkdir(dir, mode)  mkdir(dir)
#endif

#ifndef _WIN32
#define memcpy_s(t, tLen, s, len) memcpy(t, s, std::min(tlen, slen))
#endif

class AbilityMock {
public:
        
    AbilityMock() = default;

    ~AbilityMock() = default;
    
    struct moduleInfo {
        std::string moduleName = "com.example.myapplication";
    };
    
    class contextMcok
    {        
    public:
        int GetArea()
        {
            return OHOS::DistributedKv::Area::EL1;
        };
        
        std::string GetDatabaseDir()
        {
        #ifdef _WIN32
            std::string baseDir = getenv("TEMP");
        #else
            std::string baseDir = getenv("LOGNAME");
            baseDir = "/Users/" + baseDir + "/Library/Caches";
        #endif
            baseDir = baseDir + "/HuaweiDevEcoStudioDatabases";
            mkdir(baseDir.c_str(), MODE);
            return baseDir;
        }
        
        std::shared_ptr<moduleInfo> GetHapModuleInfo()
        {
            return std::make_shared<moduleInfo>();
        }
    };

    std::shared_ptr<contextMcok> GetAbilityContext()
    {
        return std::make_shared<contextMcok>();
    }    
};

namespace AbilityRuntime {
    std::shared_ptr<AbilityMock> GetAbility()
    {
        return std::make_shared<AbilityMock>();
    }
}

#include "frameworks/jskitsimpl/distributedkvstore/src/js_util.cpp"
