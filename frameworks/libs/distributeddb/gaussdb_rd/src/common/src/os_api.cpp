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
#include "os_api.h"

#include <climits>
#include <cstdlib>
#include <sys/stat.h>
#include <unistd.h>

#include "doc_errno.h"
#include "rd_log_print.h"
#include "securec.h"

namespace DocumentDB {
namespace {
const int ACCESS_MODE_EXISTENCE = 0;
}
namespace OSAPI {
bool CheckPathPermission(const std::string &filePath)
{
    return (access(filePath.c_str(), R_OK) == 0) && (access(filePath.c_str(), W_OK) == 0);
}

bool IsPathExist(const std::string &filePath)
{
    return (access(filePath.c_str(), ACCESS_MODE_EXISTENCE) == 0);
}

int GetRealPath(const std::string &inOriPath, std::string &outRealPath)
{
    const unsigned int maxPathLength = PATH_MAX;
    if (inOriPath.length() > maxPathLength) { // max limit is 64K(0x10000).
        GLOGE("[OS_API] OriPath too long.");
        return -E_INVALID_ARGS;
    }

    char *realPath = new (std::nothrow) char[maxPathLength + 1];
    if (realPath == nullptr) {
        return -E_OUT_OF_MEMORY;
    }
    if (memset_s(realPath, maxPathLength + 1, 0, maxPathLength + 1) != EOK) {
        delete[] realPath;
        return -E_SECUREC_ERROR;
    }
#ifndef _WIN32
    if (realpath(inOriPath.c_str(), realPath) == nullptr) {
        GLOGE("[OS_API] Realpath error:%d.", errno);
        delete[] realPath;
        return -E_SYSTEM_API_FAIL;
    }
#else
    if (_fullpath(realPath, inOriPath.c_str(), maxPathLength) == nullptr) {
        GLOGE("[OS] Realpath error:%d.", errno);
        delete [] realPath;
        return -E_SYSTEM_API_FAIL;
    }
#endif
    outRealPath = std::string(realPath);
    delete[] realPath;
    return E_OK;
}

void SplitFilePath(const std::string &filePath, std::string &fieldir, std::string &fileName)
{
    if (filePath.empty()) {
        return;
    }

    auto slashPos = filePath.find_last_of('/');
    if (slashPos == std::string::npos) {
        fileName = filePath;
        fieldir = "";
        return;
    }

    fieldir = filePath.substr(0, slashPos);
    fileName = filePath.substr(slashPos + 1);
}
} // namespace OSAPI
} // namespace DocumentDB