/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#define LOG_TAG "HmfsTagUtil"
#include "hmfs_tag_util.h"

#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <string>

namespace OHOS::DistributedKv {
namespace {
constexpr unsigned long HMFS_IOCTL_MAGIC = 0xF5;

struct HmfsKeyFileArgs {
    char filename[256];
    uint32_t flags;
};

constexpr unsigned long HMFS_GET_FLAGS = _IOWR(HMFS_IOCTL_MAGIC, 73, HmfsKeyFileArgs);
constexpr unsigned long HMFS_CLEAR_FLAGS = _IOW(HMFS_IOCTL_MAGIC, 74, HmfsKeyFileArgs);

class ScopedErrno final {
public:
    ScopedErrno() : errno_(errno) {}
    ~ScopedErrno()
    {
        errno = errno_;
    }
private:
    int errno_;
};
} // namespace

bool HmfsTagUtil::IsValidFileName(const std::string &fileName)
{
    if (fileName.empty() || fileName.length() > static_cast<size_t>(MAX_FILE_NAME_LEN)) {
        return false;
    }
    if (fileName == "." || fileName == "..") {
        return false;
    }
    return fileName.find('/') == std::string::npos;
}

int HmfsTagUtil::ExecuteIoctl(int dirFd, unsigned long cmd, const std::string &fileName, uint32_t *outFlags)
{
    if (!IsValidFileName(fileName)) {
        return -EINVAL;
    }
    HmfsKeyFileArgs args = { { 0 }, 0 };
    fileName.copy(args.filename, sizeof(args.filename) - 1);
    args.filename[fileName.size()] = 0;
    if (ioctl(dirFd, cmd, &args) != 0) {
        return -errno;
    }
    if (outFlags != nullptr) {
        *outFlags = args.flags;
    }
    return 0;
}

int HmfsTagUtil::ExecuteByPath(unsigned long cmd, const std::string &path, uint32_t *outFlags)
{
    if (path.empty()) {
        return -EINVAL;
    }
    auto pos = path.find_last_of('/');
    if (pos == std::string::npos || pos == 0 || pos + 1 == path.length()) {
        return -EINVAL;
    }
    std::string dir = path.substr(0, pos);
    std::string fileName = path.substr(pos + 1);
    int dirFd = open(dir.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dirFd < 0) {
        return -errno;
    }
    uint64_t tag = fdsan_create_owner_tag(FDSAN_OWNER_TYPE_FILE, 0xD001650);
    fdsan_exchange_owner_tag(dirFd, 0, tag);
    int ret = ExecuteIoctl(dirFd, cmd, fileName, outFlags);
    fdsan_close_with_tag(dirFd, tag);
    return ret;
}

int HmfsTagUtil::GetKeyFileFlag(int dirFd, const std::string &fileName)
{
    uint32_t flags = 0;
    int ret = ExecuteIoctl(dirFd, HMFS_GET_FLAGS, fileName, &flags);
    if (ret != 0) {
        return ret;
    }
    return (flags == static_cast<uint32_t>(FLAG_SET)) ? FLAG_SET : FLAG_UNSET;
}

int HmfsTagUtil::ClearKeyFileFlag(int dirFd, const std::string &fileName)
{
    return ExecuteIoctl(dirFd, HMFS_CLEAR_FLAGS, fileName, nullptr);
}

int HmfsTagUtil::GetKeyFileFlag(const std::string &path)
{
    uint32_t flags = 0;
    int ret = ExecuteByPath(HMFS_GET_FLAGS, path, &flags);
    if (ret != 0) {
        return ret;
    }
    return (flags == static_cast<uint32_t>(FLAG_SET)) ? FLAG_SET : FLAG_UNSET;
}

int HmfsTagUtil::ClearKeyFileFlag(const std::string &path)
{
    return ExecuteByPath(HMFS_CLEAR_FLAGS, path, nullptr);
}

void HmfsTagUtil::ClearDbFileTags(const std::string &dbPath)
{
    ScopedErrno scopedErrno;
    static const char *suffixes[] = { "", "-wal", "-shm" };
    for (auto suffix : suffixes) {
        std::string file = dbPath + suffix;
        if (GetKeyFileFlag(file) != FLAG_SET) {
            continue;
        }
        (void)ClearKeyFileFlag(file);
    }
}
} // namespace OHOS::DistributedKv
