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

#include <cerrno>
#include <cstdarg>
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

#include "acl.h"
#include "kv_store_delegate_manager.h"
#include "store_manager.h"
#include "store_util.h"
#include "types.h"

using namespace OHOS::DATABASE_UTILS;

namespace {
constexpr unsigned long HMFS_IOCTL_MAGIC = 0xF5;
constexpr const char *TEST_BASE_DIR = "/data/service/el1/public/database/KvDumpStackOnFileDeletionTest";
constexpr const char *TEST_APP_ID = "KvDumpStackOnFileDeletionTest";

struct HmfsKeyFileArgs {
    char filename[256];
    uint32_t flags;
};

struct DumpStackFlagCase {
    bool syncable;
    bool backup;
    bool dumpStackOnFileDeletion;
};

constexpr uint32_t HMFS_GET_FLAGS = static_cast<uint32_t>(_IOWR(HMFS_IOCTL_MAGIC, 73, HmfsKeyFileArgs));
constexpr uint32_t HMFS_CLEAR_FLAGS = static_cast<uint32_t>(_IOW(HMFS_IOCTL_MAGIC, 74, HmfsKeyFileArgs));

std::vector<std::string> g_getFiles;
std::vector<std::string> g_getPaths;
std::vector<std::string> g_clearFiles;
std::vector<std::string> g_requests;
bool g_taggedFiles = false;
bool g_ioctlFail = false;

void ResetIoctlState()
{
    g_getFiles.clear();
    g_getPaths.clear();
    g_clearFiles.clear();
    g_requests.clear();
    g_taggedFiles = false;
    g_ioctlFail = false;
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

constexpr int32_t TEST_SERVICE_GID = 3012;

bool HasServiceAcl(const std::string &dbFile)
{
    if (dbFile.empty() || access(dbFile.c_str(), F_OK) != 0) {
        return false;
    }
    Acl acl(dbFile, Acl::ACL_XATTR_ACCESS);
    return acl.HasAccessGroup(TEST_SERVICE_GID, Acl::R_RIGHT | Acl::W_RIGHT | Acl::E_RIGHT);
}

const std::vector<std::string> &ExpectedFileNames()
{
    static const std::vector<std::string> fileNames = {
        "gen_natural_store.db",
        "gen_natural_store.db-wal",
        "gen_natural_store.db-shm",
        "meta.db",
        "meta.db-wal",
        "meta.db-shm",
    };
    return fileNames;
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
    g_requests.push_back(fileName);
    if (g_ioctlFail) {
        errno = EACCES;
        return -1;
    }
    if (cmd == HMFS_GET_FLAGS) {
        g_getFiles.push_back(fileName);
        g_getPaths.push_back(DirOfFd(fd) + "/" + fileName);
        hmfsArgs->flags = g_taggedFiles ? 1 : 0;
        return 0;
    }
    g_clearFiles.push_back(fileName);
    return 0;
}

namespace OHOS::Test {
using namespace testing::ext;
using namespace OHOS::DistributedKv;

class KvDumpStackOnFileDeletionTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void);
    void TearDown(void);

    static std::string BaseDir();
    static std::string CanonicalDir(const std::string &dir);
    static std::string SingleVerDir(const std::string &storeIdName);
    static std::string DbFilePath(const std::string &storeIdName);
    static std::vector<std::string> ExpectedPaths(const std::string &storeIdName);
    static std::shared_ptr<SingleKvStore> OpenStore(const std::string &storeIdName, bool dumpStack, Status &status,
        bool syncable = false, bool backup = false);
    static void CloseStore(const std::string &storeIdName);
    static Status DeleteStore(const std::string &storeIdName);
};

void KvDumpStackOnFileDeletionTest::SetUpTestCase(void)
{
    std::error_code error;
    std::filesystem::remove_all(TEST_BASE_DIR, error);
    std::filesystem::create_directories(TEST_BASE_DIR, error);
}

void KvDumpStackOnFileDeletionTest::TearDownTestCase(void)
{
    std::error_code error;
    std::filesystem::remove_all(TEST_BASE_DIR, error);
}

void KvDumpStackOnFileDeletionTest::SetUp(void)
{
    ResetIoctlState();
}

void KvDumpStackOnFileDeletionTest::TearDown(void)
{
    (void)StoreManager::GetInstance().CloseAllKVStore({ TEST_APP_ID });
}

std::string KvDumpStackOnFileDeletionTest::CanonicalDir(const std::string &dir)
{
    std::error_code error;
    std::filesystem::path resolved = std::filesystem::canonical(dir, error);
    if (error) {
        return dir;
    }
    return resolved.string();
}

std::string KvDumpStackOnFileDeletionTest::BaseDir()
{
    return CanonicalDir(TEST_BASE_DIR);
}

std::string KvDumpStackOnFileDeletionTest::SingleVerDir(const std::string &storeIdName)
{
    std::string storeDir;
    if (DistributedDB::KvStoreDelegateManager::GetDatabaseDir(storeIdName, storeDir) != DistributedDB::DBStatus::OK) {
        return "";
    }
    return BaseDir() + "/kvdb/" + storeDir + "/single_ver";
}

std::string KvDumpStackOnFileDeletionTest::DbFilePath(const std::string &storeIdName)
{
    return SingleVerDir(storeIdName) + "/main/gen_natural_store.db";
}

std::vector<std::string> KvDumpStackOnFileDeletionTest::ExpectedPaths(const std::string &storeIdName)
{
    std::string dir = SingleVerDir(storeIdName) + "/";
    return {
        dir + "main/gen_natural_store.db",
        dir + "main/gen_natural_store.db-wal",
        dir + "main/gen_natural_store.db-shm",
        dir + "meta/meta.db",
        dir + "meta/meta.db-wal",
        dir + "meta/meta.db-shm",
    };
}

std::shared_ptr<SingleKvStore> KvDumpStackOnFileDeletionTest::OpenStore(const std::string &storeIdName, bool dumpStack,
    Status &status, bool syncable, bool backup)
{
    AppId appId = { TEST_APP_ID };
    StoreId storeId = { storeIdName };
    Options options;
    options.kvStoreType = SINGLE_VERSION;
    options.securityLevel = S1;
    options.encrypt = false;
    options.autoSync = false;
    options.backup = backup;
    options.syncable = syncable;
    options.area = EL1;
    options.role = OWNER;
    options.baseDir = TEST_BASE_DIR;
    options.dumpStackOnFileDeletion = dumpStack;
    return StoreManager::GetInstance().GetKVStore(appId, storeId, options, status);
}

void KvDumpStackOnFileDeletionTest::CloseStore(const std::string &storeIdName)
{
    (void)StoreManager::GetInstance().CloseKVStore({ TEST_APP_ID }, { storeIdName });
}

Status KvDumpStackOnFileDeletionTest::DeleteStore(const std::string &storeIdName)
{
    return StoreManager::GetInstance().Delete({ TEST_APP_ID }, { storeIdName }, TEST_BASE_DIR);
}

HWTEST_F(KvDumpStackOnFileDeletionTest, GetOrOpenStore_ClearBeforeOpen_001, TestSize.Level0)
{
    std::string storeIdName = "OpenClearStore";
    Status status = ERROR;
    auto kvStore = OpenStore(storeIdName, true, status);
    ASSERT_EQ(status, SUCCESS);
    ASSERT_NE(kvStore, nullptr);
    CloseStore(storeIdName);
    kvStore = nullptr;
    ResetIoctlState();
    g_taggedFiles = true;
    status = ERROR;
    auto reopenedStore = OpenStore(storeIdName, true, status);
    ASSERT_EQ(status, SUCCESS);
    ASSERT_NE(reopenedStore, nullptr);
    EXPECT_TRUE(HasServiceAcl(DbFilePath(storeIdName)));
    EXPECT_EQ(g_getPaths, ExpectedPaths(storeIdName));
    EXPECT_EQ(g_clearFiles, ExpectedFileNames());
    EXPECT_EQ(g_requests.size(), 12U);
    CloseStore(storeIdName);
    reopenedStore = nullptr;
    (void)DeleteStore(storeIdName);
}

HWTEST_F(KvDumpStackOnFileDeletionTest, GetOrOpenStore_CacheHitNoClear_001, TestSize.Level0)
{
    std::string storeIdName = "CacheHitStore";
    Status status = ERROR;
    auto kvStore = OpenStore(storeIdName, false, status);
    ASSERT_EQ(status, SUCCESS);
    ASSERT_NE(kvStore, nullptr);
    EXPECT_FALSE(HasServiceAcl(DbFilePath(storeIdName)));
    ResetIoctlState();
    g_taggedFiles = true;
    Status hitStatus = ERROR;
    auto sameStore = OpenStore(storeIdName, false, hitStatus);
    ASSERT_EQ(hitStatus, SUCCESS);
    ASSERT_NE(sameStore, nullptr);
    EXPECT_EQ(sameStore.get(), kvStore.get());
    EXPECT_TRUE(g_requests.empty());
    EXPECT_TRUE(g_getPaths.empty());
    EXPECT_TRUE(g_clearFiles.empty());
    CloseStore(storeIdName);
    kvStore = nullptr;
    sameStore = nullptr;
    (void)DeleteStore(storeIdName);
}

HWTEST_F(KvDumpStackOnFileDeletionTest, DeleteKvStore_ClearBeforeDelete_001, TestSize.Level0)
{
    std::string storeIdName = "DeleteClearStore";
    Status status = ERROR;
    auto kvStore = OpenStore(storeIdName, true, status);
    ASSERT_EQ(status, SUCCESS);
    ASSERT_NE(kvStore, nullptr);
    CloseStore(storeIdName);
    kvStore = nullptr;
    ResetIoctlState();
    g_taggedFiles = true;
    Status deleteStatus = DeleteStore(storeIdName);
    ASSERT_EQ(deleteStatus, SUCCESS);
    EXPECT_EQ(g_getPaths, ExpectedPaths(storeIdName));
    EXPECT_EQ(g_clearFiles, ExpectedFileNames());
    EXPECT_EQ(g_requests.size(), 12U);
    EXPECT_NE(access(DbFilePath(storeIdName).c_str(), F_OK), 0);
}

HWTEST_F(KvDumpStackOnFileDeletionTest, DeleteKvStore_IoctlFailStillDeletes_001, TestSize.Level0)
{
    std::string storeIdName = "DeleteIoctlFailStore";
    Status status = ERROR;
    auto kvStore = OpenStore(storeIdName, true, status);
    ASSERT_EQ(status, SUCCESS);
    ASSERT_NE(kvStore, nullptr);
    CloseStore(storeIdName);
    kvStore = nullptr;
    ResetIoctlState();
    g_taggedFiles = true;
    g_ioctlFail = true;
    Status deleteStatus = DeleteStore(storeIdName);
    ASSERT_EQ(deleteStatus, SUCCESS);
    EXPECT_EQ(g_requests.size(), 6U);
    EXPECT_TRUE(g_clearFiles.empty());
    EXPECT_NE(access(DbFilePath(storeIdName).c_str(), F_OK), 0);
}

HWTEST_F(KvDumpStackOnFileDeletionTest, Restore_ClearBeforeImport_001, TestSize.Level0)
{
    std::string storeIdName = "RestoreClearStore";
    Status status = ERROR;
    auto kvStore = OpenStore(storeIdName, true, status);
    ASSERT_EQ(status, SUCCESS);
    ASSERT_NE(kvStore, nullptr);
    ResetIoctlState();
    g_taggedFiles = true;
    Status restoreStatus = kvStore->Restore("not_exist_backup", TEST_BASE_DIR);
    EXPECT_NE(restoreStatus, SUCCESS);
    EXPECT_TRUE(HasServiceAcl(DbFilePath(storeIdName)));
    EXPECT_EQ(g_getPaths, ExpectedPaths(storeIdName));
    EXPECT_EQ(g_clearFiles, ExpectedFileNames());
    EXPECT_EQ(g_requests.size(), 12U);
    CloseStore(storeIdName);
    kvStore = nullptr;
    (void)DeleteStore(storeIdName);
}

HWTEST_F(KvDumpStackOnFileDeletionTest, Constructor_DumpStackFlagMatrix_001, TestSize.Level0)
{
    const DumpStackFlagCase matrix[] = {
        { true, false, false },
        { false, true, false },
        { false, false, true },
        { false, false, false },
    };
    int index = 0;
    for (const auto &flags : matrix) {
        std::string storeIdName = std::string("DumpStackConstructor") + std::to_string(index++);
        Status status = ERROR;
        auto store = OpenStore(storeIdName, flags.dumpStackOnFileDeletion, status,
            flags.syncable, flags.backup);
        EXPECT_EQ(status, SUCCESS);
        EXPECT_NE(store, nullptr);
        store = nullptr;
        CloseStore(storeIdName);
        (void)DeleteStore(storeIdName);
    }
}

HWTEST_F(KvDumpStackOnFileDeletionTest, Restore_DumpStackFlagMatrix_001, TestSize.Level0)
{
    const DumpStackFlagCase matrix[] = {
        { true, false, false },
        { false, true, false },
        { false, false, true },
        { false, false, false },
    };
    int index = 0;
    for (const auto &flags : matrix) {
        std::string storeIdName = std::string("DumpStackRestore") + std::to_string(index++);
        Status status = ERROR;
        auto store = OpenStore(storeIdName, flags.dumpStackOnFileDeletion, status,
            flags.syncable, flags.backup);
        EXPECT_EQ(status, SUCCESS);
        EXPECT_NE(store, nullptr);
        if (store != nullptr) {
            Status restoreStatus = store->Restore("not_exist_backup", BaseDir());
            EXPECT_EQ(restoreStatus, INVALID_ARGUMENT);
            store = nullptr;
        }
        CloseStore(storeIdName);
        (void)DeleteStore(storeIdName);
    }
}
}
