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

#include <fcntl.h>
#include <gtest/gtest.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstdarg>
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

#include "hmfs_tag_util.h"

namespace {
constexpr unsigned long HMFS_IOCTL_MAGIC = 0xF5;
constexpr const char *TEST_BASE_DIR = "/data/service/el1/public/database/HmfsTagUtilTest";
constexpr const char *TEST_FILE_NAME = "file.db";
constexpr const char *MISSING_RELATIVE_PATH = "hmfs_missing_dir_001/file.db";
constexpr const char *MISSING_PROBE_FILE = "hmfs_missing_probe.db";
constexpr uint32_t FLAG_SET_VALUE = 1;
constexpr size_t EXPECTED_GET_COUNT = 2;
constexpr size_t EXPECTED_CLEAR_COUNT = 1;
constexpr size_t EXPECTED_DB_FILE_COUNT = 3;
constexpr size_t EXPECTED_MIXED_IOCTL_COUNT = 4;

struct HmfsKeyFileArgs {
    char filename[256];
    uint32_t flags;
};

constexpr uint32_t HMFS_GET_FLAGS = static_cast<uint32_t>(_IOWR(HMFS_IOCTL_MAGIC, 73, HmfsKeyFileArgs));
constexpr uint32_t HMFS_CLEAR_FLAGS = static_cast<uint32_t>(_IOW(HMFS_IOCTL_MAGIC, 74, HmfsKeyFileArgs));

std::vector<std::string> gGetFiles;
std::vector<std::string> gGetPaths;
std::vector<std::string> gClearFiles;
std::vector<std::string> gRequests;
std::vector<std::string> gTaggedFileNames;
bool gTaggedFiles = false;
bool gIoctlFail = false;

void ResetIoctlState()
{
    gGetFiles.clear();
    gGetPaths.clear();
    gClearFiles.clear();
    gRequests.clear();
    gTaggedFileNames.clear();
    gTaggedFiles = false;
    gIoctlFail = false;
}

std::string DirOfFd(int fd)
{
    std::string link = "/proc/self/fd/" + std::to_string(fd);
    char dir[4096] = { 0 };
    ssize_t len = readlink(link.c_str(), dir, sizeof(dir) - 1);
    if (len <= 0) {
        return "";
    }
    return std::string(dir, static_cast<size_t>(len));
}

std::string TestDir()
{
    std::error_code error;
    std::filesystem::path basePath = std::filesystem::canonical(TEST_BASE_DIR, error);
    if (error) {
        return TEST_BASE_DIR;
    }
    return basePath.string();
}

std::string DbDir()
{
    return TestDir() + "/single_ver";
}

const std::vector<std::string> &ExpectedDbFileNames()
{
    static const std::vector<std::string> fileNames = {
        "clear_tags.db",
        "clear_tags.db-wal",
        "clear_tags.db-shm",
    };
    return fileNames;
}

std::vector<std::string> ExpectedDbPaths()
{
    std::vector<std::string> paths;
    for (const auto &fileName : ExpectedDbFileNames()) {
        paths.push_back(DbDir() + "/" + fileName);
    }
    return paths;
}
}

extern "C" int __real_ioctl(int fd, unsigned long request, ...); /* NOLINT */

extern "C" int __wrap_ioctl(int fd, unsigned long request, ...) /* NOLINT */
{
    va_list args;
    va_start(args, request);
    void *arg = va_arg(args, void *);
    va_end(args);
    uint32_t cmd = static_cast<uint32_t>(request);
    if (cmd != HMFS_GET_FLAGS && cmd != HMFS_CLEAR_FLAGS) {
        return __real_ioctl(fd, request, arg);
    }
    auto *hmfsArgs = static_cast<HmfsKeyFileArgs *>(arg);
    if (hmfsArgs == nullptr) {
        errno = EINVAL;
        return -1;
    }
    std::string fileName(hmfsArgs->filename);
    gRequests.push_back(fileName);
    if (gIoctlFail) {
        errno = EACCES;
        return -1;
    }
    if (cmd == HMFS_GET_FLAGS) {
        gGetFiles.push_back(fileName);
        gGetPaths.push_back(DirOfFd(fd) + "/" + fileName);
        bool tagged = gTaggedFiles ||
            std::find(gTaggedFileNames.begin(), gTaggedFileNames.end(), fileName) != gTaggedFileNames.end();
        hmfsArgs->flags = tagged ? 1 : 0;
        return 0;
    }
    gClearFiles.push_back(fileName);
    return 0;
}

namespace OHOS::Test {
using namespace testing::ext;
using namespace OHOS::DistributedKv;

class HmfsTagUtilTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void);
    void TearDown(void);
};

void HmfsTagUtilTest::SetUpTestCase(void)
{
    std::error_code error;
    std::filesystem::remove_all(TEST_BASE_DIR, error);
    std::filesystem::create_directories(TEST_BASE_DIR, error);
}

void HmfsTagUtilTest::TearDownTestCase(void)
{
    std::error_code error;
    std::filesystem::remove_all(TEST_BASE_DIR, error);
}

void HmfsTagUtilTest::SetUp(void)
{
    ResetIoctlState();
    std::error_code error;
    std::filesystem::create_directories(DbDir(), error);
}

void HmfsTagUtilTest::TearDown(void)
{
}

HWTEST_F(HmfsTagUtilTest, HmfsTagUtil_IsValidFileName_001, TestSize.Level0)
{
    EXPECT_TRUE(HmfsTagUtil::IsValidFileName("test.db"));
    EXPECT_TRUE(HmfsTagUtil::IsValidFileName("test.db-wal"));
    EXPECT_TRUE(HmfsTagUtil::IsValidFileName("test.db-shm"));
    EXPECT_TRUE(HmfsTagUtil::IsValidFileName(std::string(HmfsTagUtil::MAX_FILE_NAME_LEN, 'a')));
    EXPECT_FALSE(HmfsTagUtil::IsValidFileName(""));
    EXPECT_FALSE(HmfsTagUtil::IsValidFileName(std::string(HmfsTagUtil::MAX_FILE_NAME_LEN + 1, 'a')));
    EXPECT_FALSE(HmfsTagUtil::IsValidFileName("."));
    EXPECT_FALSE(HmfsTagUtil::IsValidFileName(".."));
    EXPECT_FALSE(HmfsTagUtil::IsValidFileName("dir/test.db"));
    EXPECT_FALSE(HmfsTagUtil::IsValidFileName("/test.db"));
}

HWTEST_F(HmfsTagUtilTest, HmfsTagUtil_ExecuteIoctl_InvalidName_001, TestSize.Level0)
{
    int dirFd = open(TestDir().c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    ASSERT_GE(dirFd, 0);
    EXPECT_EQ(HmfsTagUtil::ExecuteIoctl(dirFd, HMFS_GET_FLAGS, "", nullptr), -EINVAL);
    EXPECT_EQ(HmfsTagUtil::ExecuteIoctl(dirFd, HMFS_GET_FLAGS, ".", nullptr), -EINVAL);
    EXPECT_EQ(HmfsTagUtil::ExecuteIoctl(dirFd, HMFS_GET_FLAGS, "..", nullptr), -EINVAL);
    EXPECT_EQ(HmfsTagUtil::ExecuteIoctl(dirFd, HMFS_GET_FLAGS,
        std::string(HmfsTagUtil::MAX_FILE_NAME_LEN + 1, 'a'), nullptr), -EINVAL);
    EXPECT_EQ(HmfsTagUtil::ExecuteIoctl(dirFd, HMFS_GET_FLAGS, "single_ver/file.db", nullptr), -EINVAL);
    EXPECT_TRUE(gRequests.empty());
    EXPECT_TRUE(gGetFiles.empty());
    EXPECT_TRUE(gClearFiles.empty());
    (void)close(dirFd);
}

HWTEST_F(HmfsTagUtilTest, HmfsTagUtil_ExecuteIoctl_Success_001, TestSize.Level0)
{
    int dirFd = open(TestDir().c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    ASSERT_GE(dirFd, 0);
    uint32_t flags = 0;
    gTaggedFiles = true;
    EXPECT_EQ(HmfsTagUtil::ExecuteIoctl(dirFd, HMFS_GET_FLAGS, TEST_FILE_NAME, &flags), 0);
    EXPECT_EQ(flags, 1U);
    gTaggedFiles = false;
    EXPECT_EQ(HmfsTagUtil::ExecuteIoctl(dirFd, HMFS_GET_FLAGS, TEST_FILE_NAME, &flags), 0);
    EXPECT_EQ(flags, 0U);
    EXPECT_EQ(HmfsTagUtil::ExecuteIoctl(dirFd, HMFS_CLEAR_FLAGS, TEST_FILE_NAME, nullptr), 0);
    EXPECT_EQ(gRequests.size(), 3U);
    EXPECT_EQ(gGetFiles.size(), 2U);
    EXPECT_EQ(gGetPaths.size(), 2U);
    EXPECT_EQ(gGetPaths[0], TestDir() + "/" + TEST_FILE_NAME);
    EXPECT_EQ(gClearFiles.size(), 1U);
    (void)close(dirFd);
}

HWTEST_F(HmfsTagUtilTest, HmfsTagUtil_ExecuteIoctl_IoctlFail_001, TestSize.Level0)
{
    int dirFd = open(TestDir().c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    ASSERT_GE(dirFd, 0);
    gIoctlFail = true;
    EXPECT_EQ(HmfsTagUtil::ExecuteIoctl(dirFd, HMFS_GET_FLAGS, TEST_FILE_NAME, nullptr), -EACCES);
    EXPECT_EQ(HmfsTagUtil::ExecuteIoctl(dirFd, HMFS_CLEAR_FLAGS, TEST_FILE_NAME, nullptr), -EACCES);
    EXPECT_EQ(gRequests.size(), 2U);
    EXPECT_TRUE(gGetFiles.empty());
    EXPECT_TRUE(gGetPaths.empty());
    EXPECT_TRUE(gClearFiles.empty());
    (void)close(dirFd);
}

HWTEST_F(HmfsTagUtilTest, HmfsTagUtil_ExecuteIoctl_CurrentDirFd_001, TestSize.Level0)
{
    int dirFd = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    ASSERT_GE(dirFd, 0);
    EXPECT_EQ(HmfsTagUtil::ExecuteIoctl(dirFd, HMFS_GET_FLAGS, "", nullptr), -EINVAL);
    uint32_t flags = 0;
    gTaggedFiles = true;
    EXPECT_EQ(HmfsTagUtil::ExecuteIoctl(dirFd, HMFS_GET_FLAGS, TEST_FILE_NAME, &flags), 0);
    EXPECT_EQ(flags, FLAG_SET_VALUE);
    gTaggedFiles = false;
    EXPECT_EQ(HmfsTagUtil::ExecuteIoctl(dirFd, HMFS_GET_FLAGS, TEST_FILE_NAME, &flags), 0);
    EXPECT_EQ(flags, 0U);
    EXPECT_EQ(HmfsTagUtil::ExecuteIoctl(dirFd, HMFS_CLEAR_FLAGS, TEST_FILE_NAME, nullptr), 0);
    EXPECT_EQ(gGetFiles.size(), EXPECTED_GET_COUNT);
    EXPECT_EQ(gGetFiles[0], TEST_FILE_NAME);
    EXPECT_EQ(gClearFiles.size(), EXPECTED_CLEAR_COUNT);
    EXPECT_EQ(gClearFiles[0], TEST_FILE_NAME);
    (void)close(dirFd);
}

HWTEST_F(HmfsTagUtilTest, HmfsTagUtil_ExecuteByPath_InvalidPath_001, TestSize.Level0)
{
    EXPECT_EQ(HmfsTagUtil::ExecuteByPath(HMFS_GET_FLAGS, "", nullptr), -EINVAL);
    EXPECT_EQ(HmfsTagUtil::ExecuteByPath(HMFS_GET_FLAGS, "plainname", nullptr), -EINVAL);
    EXPECT_EQ(HmfsTagUtil::ExecuteByPath(HMFS_GET_FLAGS, "/file.db", nullptr), -EINVAL);
    EXPECT_EQ(HmfsTagUtil::ExecuteByPath(HMFS_GET_FLAGS, TestDir() + "/", nullptr), -EINVAL);
    EXPECT_EQ(HmfsTagUtil::ExecuteByPath(HMFS_CLEAR_FLAGS, "", nullptr), -EINVAL);
    EXPECT_TRUE(gRequests.empty());
    EXPECT_TRUE(gGetFiles.empty());
    EXPECT_TRUE(gClearFiles.empty());
}

HWTEST_F(HmfsTagUtilTest, HmfsTagUtil_ExecuteByPath_OpenFail_001, TestSize.Level0)
{
    std::string path = TestDir() + "/not_exist_dir/" + TEST_FILE_NAME;
    EXPECT_EQ(HmfsTagUtil::ExecuteByPath(HMFS_GET_FLAGS, path, nullptr), -ENOENT);
    EXPECT_TRUE(gRequests.empty());
    EXPECT_TRUE(gGetFiles.empty());
    EXPECT_TRUE(gClearFiles.empty());
}

HWTEST_F(HmfsTagUtilTest, HmfsTagUtil_ExecuteByPath_OpenFailRelative_001, TestSize.Level0)
{
    EXPECT_EQ(HmfsTagUtil::ExecuteByPath(HMFS_GET_FLAGS, MISSING_RELATIVE_PATH, nullptr), -ENOENT);
    EXPECT_EQ(HmfsTagUtil::ExecuteByPath(HMFS_CLEAR_FLAGS, MISSING_RELATIVE_PATH, nullptr), -ENOENT);
    EXPECT_TRUE(gRequests.empty());
    EXPECT_TRUE(gGetFiles.empty());
    EXPECT_TRUE(gClearFiles.empty());
}

HWTEST_F(HmfsTagUtilTest, HmfsTagUtil_ExecuteByPath_Success_001, TestSize.Level0)
{
    std::string path = TestDir() + "/" + TEST_FILE_NAME;
    uint32_t flags = 0;
    gTaggedFiles = true;
    EXPECT_EQ(HmfsTagUtil::ExecuteByPath(HMFS_GET_FLAGS, path, &flags), 0);
    EXPECT_EQ(flags, 1U);
    EXPECT_EQ(gGetPaths.size(), 1U);
    EXPECT_EQ(gGetPaths[0], path);
    EXPECT_EQ(HmfsTagUtil::ExecuteByPath(HMFS_CLEAR_FLAGS, path, nullptr), 0);
    EXPECT_EQ(gClearFiles.size(), 1U);
    EXPECT_EQ(gClearFiles[0], TEST_FILE_NAME);
    EXPECT_EQ(gRequests.size(), 2U);
}

HWTEST_F(HmfsTagUtilTest, HmfsTagUtil_GetKeyFileFlag_001, TestSize.Level0)
{
    std::string path = TestDir() + "/" + TEST_FILE_NAME;
    gTaggedFiles = true;
    EXPECT_EQ(HmfsTagUtil::GetKeyFileFlag(path), HmfsTagUtil::FLAG_SET);
    gTaggedFiles = false;
    EXPECT_EQ(HmfsTagUtil::GetKeyFileFlag(path), 0);
    gIoctlFail = true;
    EXPECT_EQ(HmfsTagUtil::GetKeyFileFlag(path), -EACCES);
    EXPECT_EQ(gRequests.size(), 3U);
    EXPECT_EQ(gGetFiles.size(), 2U);
}

HWTEST_F(HmfsTagUtilTest, HmfsTagUtil_GetKeyFileFlag_IoctlError_001, TestSize.Level0)
{
    int dirFd = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    ASSERT_GE(dirFd, 0);
    gIoctlFail = true;
    EXPECT_EQ(HmfsTagUtil::GetKeyFileFlag(dirFd, TEST_FILE_NAME), -EACCES);
    EXPECT_EQ(HmfsTagUtil::GetKeyFileFlag(TestDir() + "/" + TEST_FILE_NAME), -EACCES);
    EXPECT_EQ(gRequests.size(), EXPECTED_GET_COUNT);
    EXPECT_TRUE(gGetFiles.empty());
    (void)close(dirFd);
}

HWTEST_F(HmfsTagUtilTest, HmfsTagUtil_ClearKeyFileFlag_001, TestSize.Level0)
{
    std::string path = TestDir() + "/" + TEST_FILE_NAME;
    EXPECT_EQ(HmfsTagUtil::ClearKeyFileFlag(path), 0);
    EXPECT_EQ(gClearFiles.size(), 1U);
    gIoctlFail = true;
    EXPECT_EQ(HmfsTagUtil::ClearKeyFileFlag(path), -EACCES);
    EXPECT_EQ(gClearFiles.size(), 1U);
    EXPECT_EQ(gRequests.size(), 2U);
}

HWTEST_F(HmfsTagUtilTest, HmfsTagUtil_DirFd_001, TestSize.Level0)
{
    int dirFd = open(TestDir().c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    ASSERT_GE(dirFd, 0);
    EXPECT_EQ(HmfsTagUtil::GetKeyFileFlag(dirFd, "../escape.db"), -EINVAL);
    EXPECT_EQ(HmfsTagUtil::ClearKeyFileFlag(dirFd,
        std::string(HmfsTagUtil::MAX_FILE_NAME_LEN + 1, 'a')), -EINVAL);
    gTaggedFiles = true;
    EXPECT_EQ(HmfsTagUtil::GetKeyFileFlag(dirFd, TEST_FILE_NAME), HmfsTagUtil::FLAG_SET);
    EXPECT_EQ(HmfsTagUtil::ClearKeyFileFlag(dirFd, TEST_FILE_NAME), 0);
    gTaggedFiles = false;
    EXPECT_EQ(HmfsTagUtil::GetKeyFileFlag(dirFd, TEST_FILE_NAME), 0);
    gIoctlFail = true;
    EXPECT_EQ(HmfsTagUtil::GetKeyFileFlag(dirFd, TEST_FILE_NAME), -EACCES);
    (void)close(dirFd);
}

HWTEST_F(HmfsTagUtilTest, HmfsTagUtil_ClearDbFileTags_TaggedAndUntagged_001, TestSize.Level0)
{
    std::string dbPath = DbDir() + "/clear_tags.db";
    gTaggedFiles = true;
    HmfsTagUtil::ClearDbFileTags(dbPath);
    EXPECT_EQ(gGetFiles, ExpectedDbFileNames());
    EXPECT_EQ(gGetPaths, ExpectedDbPaths());
    EXPECT_EQ(gClearFiles, ExpectedDbFileNames());
    EXPECT_EQ(gRequests.size(), 6U);

    ResetIoctlState();
    HmfsTagUtil::ClearDbFileTags(dbPath);
    EXPECT_EQ(gGetFiles, ExpectedDbFileNames());
    EXPECT_EQ(gGetPaths, ExpectedDbPaths());
    EXPECT_TRUE(gClearFiles.empty());
    EXPECT_EQ(gRequests.size(), 3U);
}

HWTEST_F(HmfsTagUtilTest, HmfsTagUtil_ClearDbFileTags_MixedTag_001, TestSize.Level0)
{
    std::string dbPath = DbDir() + "/clear_tags.db";
    gTaggedFileNames = { "clear_tags.db-wal" };
    HmfsTagUtil::ClearDbFileTags(dbPath);
    EXPECT_EQ(gGetFiles, ExpectedDbFileNames());
    EXPECT_EQ(gGetPaths, ExpectedDbPaths());
    EXPECT_EQ(gClearFiles.size(), EXPECTED_CLEAR_COUNT);
    EXPECT_EQ(gClearFiles[0], "clear_tags.db-wal");
    EXPECT_EQ(gRequests.size(), EXPECTED_MIXED_IOCTL_COUNT);
}

HWTEST_F(HmfsTagUtilTest, HmfsTagUtil_ClearDbFileTags_IoctlFail_001, TestSize.Level0)
{
    std::string dbPath = DbDir() + "/clear_tags.db";
    gTaggedFiles = true;
    gIoctlFail = true;
    HmfsTagUtil::ClearDbFileTags(dbPath);
    EXPECT_EQ(gRequests.size(), 3U);
    EXPECT_TRUE(gGetPaths.empty());
    EXPECT_TRUE(gClearFiles.empty());
}

HWTEST_F(HmfsTagUtilTest, HmfsTagUtil_ClearDbFileTags_InvalidPath_001, TestSize.Level0)
{
    HmfsTagUtil::ClearDbFileTags("");
    HmfsTagUtil::ClearDbFileTags("plainname");
    EXPECT_TRUE(gRequests.empty());
    EXPECT_TRUE(gGetPaths.empty());
    EXPECT_TRUE(gClearFiles.empty());
}

HWTEST_F(HmfsTagUtilTest, HmfsTagUtil_ClearDbFileTags_ErrnoPreserved_001, TestSize.Level0)
{
    const std::string dbPath = DbDir() + "/" + TEST_FILE_NAME;
    const std::string probePath = TestDir() + "/" + MISSING_PROBE_FILE;
    gIoctlFail = true;
    int probeFd = open(probePath.c_str(), O_RDONLY | O_CLOEXEC);
    const int expectedErrno = errno;
    if (probeFd >= 0) {
        (void)close(probeFd);
    }
    HmfsTagUtil::ClearDbFileTags(dbPath);
    const int actualErrno = errno;
    ASSERT_EQ(probeFd, -1);
    EXPECT_EQ(expectedErrno, ENOENT);
    EXPECT_EQ(actualErrno, expectedErrno);
    EXPECT_EQ(gRequests.size(), EXPECTED_DB_FILE_COUNT);
    EXPECT_TRUE(gGetFiles.empty());
    EXPECT_TRUE(gClearFiles.empty());
}
}
