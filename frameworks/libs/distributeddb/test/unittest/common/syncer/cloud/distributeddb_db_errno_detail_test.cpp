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

#include <gtest/gtest.h>

#include <cstdint>
#include <string>
#include <utility>

#include "db_errno.h"
#include "distributeddb_tools_unit_test.h"
#include "process_notifier.h"
#include "store_types.h"

using namespace testing::ext;
using namespace DistributedDBUnitTest;
using namespace DistributedDB;

namespace {
class DistributedDBDbErrnoDetailTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void DistributedDBDbErrnoDetailTest::SetUpTestCase(void)
{
}

void DistributedDBDbErrnoDetailTest::TearDownTestCase(void)
{
}

void DistributedDBDbErrnoDetailTest::SetUp(void)
{
    DistributedDBToolsUnitTest::PrintTestCaseInfo();
}

void DistributedDBDbErrnoDetailTest::TearDown(void)
{
}

constexpr uint32_t EXPECT_HEARTBEAT_FAILED_CODE = 0x40100Fu;     // GENERAL stage + CLOUD_HEARTBEAT_FAILED
constexpr uint32_t EXPECT_HEARTBEAT_BLOCKED_CODE = 0x40100Eu;    // GENERAL stage + CLOUD_HEARTBEAT_BLOCKED
constexpr uint32_t EXPECT_SYSTEM_EVENT_STOPPED_CODE = 0x401010u; // GENERAL stage + CLOUD_SYSTEM_EVENT_STOPPED
constexpr uint32_t EXPECT_SCHEMA_NOTEXIST_CODE = 0x402000u;      // GENERAL stage + SCHEMA_NOTEXIST
constexpr uint32_t EXPECT_UPLOAD_CLOUD_ERROR_CODE = 0x421001u;    // UPLOAD stage + CLOUD_ERROR
constexpr uint32_t EXPECT_DOWNLOAD_CLOUD_ERROR_CODE = 0x411001u; // DOWNLOAD stage + CLOUD_ERROR
constexpr uint32_t EXPECT_GENERAL_DB_CLOSED_CODE = 0x400004u;    // GENERAL stage + GENERAL_DB_CLOSED

// one entry of the errno to detail number mapping, errnoCode is the negative errno
struct ErrnoDetailEntry {
    int errnoCode;
    uint32_t detailNumber;
};

// the whole errno to detail number mapping, each mapped errno returns its detail number
constexpr ErrnoDetailEntry ERRNO_DETAIL_MAP[] = {
    {-E_INVALID_ARGS, static_cast<uint32_t>(DetailCode::GENERAL_INVALID_ARGS)},
    {-E_INVALID_DB, static_cast<uint32_t>(DetailCode::GENERAL_INVALID_DB)},
    {-E_INVALID_CONNECTION, static_cast<uint32_t>(DetailCode::GENERAL_INVALID_CONNECTION)},
    {-E_DB_CLOSED, static_cast<uint32_t>(DetailCode::GENERAL_DB_CLOSED)},
    {-E_BUSY, static_cast<uint32_t>(DetailCode::GENERAL_BUSY)},
    {-E_INTERNAL_ERROR, static_cast<uint32_t>(DetailCode::GENERAL_INTERNAL_ERROR)},
    {-E_NOT_FOUND, static_cast<uint32_t>(DetailCode::GENERAL_NOT_FOUND)},
    {-E_NOT_SET, static_cast<uint32_t>(DetailCode::GENERAL_NOT_SET)},
    {-E_PERMISSION, static_cast<uint32_t>(DetailCode::GENERAL_PERMISSION)},
    {-E_FIRST_PAGE_CORRUPTED, static_cast<uint32_t>(DetailCode::GENERAL_FIRST_PAGE_CORRUPTED)},
    {-E_INVALID_PASSWD_OR_CORRUPTED_DB, static_cast<uint32_t>(DetailCode::GENERAL_CORRUPTED_DB)},
    {-E_EKEYREVOKED, static_cast<uint32_t>(DetailCode::GENERAL_EKEYREVOKED)},
    {-E_SQLITE_CANT_OPEN, static_cast<uint32_t>(DetailCode::GENERAL_SQLITE_CANT_OPEN)},
    {-E_CONSTRAINT, static_cast<uint32_t>(DetailCode::GENERAL_CONSTRAINT)},
    {-E_DENIED_SQL, static_cast<uint32_t>(DetailCode::GENERAL_DENIED_SQL)},
    {-E_CLOUD_NETWORK_ERROR, static_cast<uint32_t>(DetailCode::CLOUD_NETWORK_ERROR)},
    {-E_CLOUD_ERROR, static_cast<uint32_t>(DetailCode::CLOUD_ERROR)},
    {-E_CLOUD_FULL_RECORDS, static_cast<uint32_t>(DetailCode::CLOUD_FULL_RECORDS)},
    {-E_CLOUD_RECORD_EXIST_CONFLICT, static_cast<uint32_t>(DetailCode::CLOUD_RECORD_CONFLICT)},
    {-E_CLOUD_GID_MISMATCH, static_cast<uint32_t>(DetailCode::CLOUD_GID_MISMATCH)},
    {-E_CLOUD_INVALID_ASSET, static_cast<uint32_t>(DetailCode::CLOUD_INVALID_ASSET)},
    {-E_CLOUD_ASSET_NOT_FOUND, static_cast<uint32_t>(DetailCode::CLOUD_ASSET_NOT_FOUND)},
    {-E_ASSET_NOT_FOUND_FOR_DOWN_ONLY, static_cast<uint32_t>(DetailCode::CLOUD_ASSET_NOT_FOUND_DOWN_ONLY)},
    {-E_REMOVE_ASSETS_FAILED, static_cast<uint32_t>(DetailCode::CLOUD_REMOVE_ASSETS_FAILED)},
    {-E_CLOUD_LOCK_ERROR, static_cast<uint32_t>(DetailCode::CLOUD_LOCK_ERROR)},
    {-E_CLOUD_VERSION_CONFLICT, static_cast<uint32_t>(DetailCode::CLOUD_VERSION_CONFLICT)},
    {-E_CLOUD_SYNC_UNSET, static_cast<uint32_t>(DetailCode::CLOUD_SYNC_UNSET)},
    {-E_CLOUD_DISABLED, static_cast<uint32_t>(DetailCode::CLOUD_DISABLED)},
    {-E_CLOUD_ASSET_SPACE_INSUFFICIENT, static_cast<uint32_t>(DetailCode::CLOUD_ASSET_SPACE_INSUFFICIENT)},
    {-E_LOCAL_ASSET_NOT_FOUND, static_cast<uint32_t>(DetailCode::CLOUD_LOCAL_ASSET_NOT_FOUND)},
    {-E_SKIP_WHEN_CLOUD_SPACE_INSUFFICIENT, static_cast<uint32_t>(DetailCode::CLOUD_SPACE_INSUFFICIENT_SKIPPED)},
    {-E_EXPIRED_CURSOR, static_cast<uint32_t>(DetailCode::CLOUD_EXPIRED_CURSOR)},
    {-E_CLOUD_SYNC_TASK_MERGED, static_cast<uint32_t>(DetailCode::CLOUD_SYNC_TASK_MERGED)},
    {-E_SCHEMA_NOTEXIST, static_cast<uint32_t>(DetailCode::SCHEMA_NOTEXIST)},
    {-E_SCHEMA_MISMATCH, static_cast<uint32_t>(DetailCode::SCHEMA_MISMATCH)},
};

// key errnos used by the cloud sync flow whose detail number layout is pinned by the requirement
constexpr ErrnoDetailEntry KEY_ERRNO_DETAIL_NUMBERS[] = {
    {-E_INVALID_ARGS, 0x0001u},
    {-E_INVALID_DB, 0x0002u},
    {-E_INVALID_CONNECTION, 0x0003u},
    {-E_DB_CLOSED, 0x0004u},
    {-E_BUSY, 0x0005u},
    {-E_INTERNAL_ERROR, 0x0006u},
    {-E_NOT_FOUND, 0x0007u},
    {-E_NOT_SET, 0x0008u},
    {-E_CLOUD_ERROR, 0x1001u},
    {-E_CLOUD_NETWORK_ERROR, 0x1000u},
    {-E_CLOUD_LOCK_ERROR, 0x1009u},
    {-E_CLOUD_ASSET_NOT_FOUND, 0x1006u},
    {-E_ASSET_NOT_FOUND_FOR_DOWN_ONLY, 0x1007u},
    {-E_REMOVE_ASSETS_FAILED, 0x1008u},
    {-E_CLOUD_DISABLED, 0x100Cu},
    {-E_LOCAL_ASSET_NOT_FOUND, 0x1011u},
    {-E_SKIP_WHEN_CLOUD_SPACE_INSUFFICIENT, 0x1012u},
    {-E_EXPIRED_CURSOR, 0x1013u},
    {-E_CLOUD_SYNC_TASK_MERGED, 0x1014u},
    {-E_PERMISSION, 0x0009u},
    {-E_CONSTRAINT, 0x000Eu},
    {-E_SCHEMA_NOTEXIST, 0x2000u},
    {-E_SCHEMA_MISMATCH, 0x2001u},
};

// Detail codes that carry a direct static message in GetDetailMsg.
constexpr DetailCode DIRECT_MSG_CODES[] = {
    DetailCode::GENERAL_INVALID_ARGS,
    DetailCode::GENERAL_INVALID_DB,
    DetailCode::GENERAL_INVALID_CONNECTION,
    DetailCode::GENERAL_DB_CLOSED,
    DetailCode::GENERAL_BUSY,
    DetailCode::GENERAL_INTERNAL_ERROR,
    DetailCode::GENERAL_NOT_FOUND,
    DetailCode::GENERAL_NOT_SET,
    DetailCode::GENERAL_PERMISSION,
    DetailCode::GENERAL_FIRST_PAGE_CORRUPTED,
    DetailCode::GENERAL_CORRUPTED_DB,
    DetailCode::GENERAL_EKEYREVOKED,
    DetailCode::GENERAL_SQLITE_CANT_OPEN,
    DetailCode::GENERAL_CONSTRAINT,
    DetailCode::GENERAL_DENIED_SQL,
    DetailCode::CLOUD_NETWORK_ERROR,
    DetailCode::CLOUD_ERROR,
    DetailCode::CLOUD_FULL_RECORDS,
    DetailCode::CLOUD_RECORD_CONFLICT,
    DetailCode::CLOUD_GID_MISMATCH,
    DetailCode::CLOUD_INVALID_ASSET,
    DetailCode::CLOUD_ASSET_NOT_FOUND,
    DetailCode::CLOUD_ASSET_NOT_FOUND_DOWN_ONLY,
    DetailCode::CLOUD_REMOVE_ASSETS_FAILED,
    DetailCode::CLOUD_LOCK_ERROR,
    DetailCode::CLOUD_VERSION_CONFLICT,
    DetailCode::CLOUD_SYNC_UNSET,
    DetailCode::CLOUD_DISABLED,
    DetailCode::CLOUD_ASSET_SPACE_INSUFFICIENT,
    DetailCode::CLOUD_LOCAL_ASSET_NOT_FOUND,
    DetailCode::CLOUD_SPACE_INSUFFICIENT_SKIPPED,
    DetailCode::CLOUD_EXPIRED_CURSOR,
    DetailCode::CLOUD_SYNC_TASK_MERGED,
    DetailCode::CLOUD_HEARTBEAT_BLOCKED,
    DetailCode::CLOUD_HEARTBEAT_FAILED,
    DetailCode::CLOUD_SYSTEM_EVENT_STOPPED,
};

struct KeyDetailMsg {
    DetailCode code;
    const char *msg;
};

// Key detail codes whose exact message is pinned by the requirement.
constexpr KeyDetailMsg KEY_DETAIL_MSGS[] = {
    {DetailCode::GENERAL_DB_CLOSED, "The database has been closed, all sync tasks are terminated"},
    {DetailCode::CLOUD_ERROR, "Cloud sync error"},
    {DetailCode::CLOUD_NETWORK_ERROR, "Cloud network error"},
    {DetailCode::CLOUD_LOCK_ERROR, "Failed to get cloud sync lock"},
    {DetailCode::CLOUD_HEARTBEAT_FAILED, "Heartbeat failed too many times"},
    {DetailCode::CLOUD_HEARTBEAT_BLOCKED, "Heartbeat blocked twice, task aborted"},
    {DetailCode::CLOUD_SYSTEM_EVENT_STOPPED, "Sync tasks have been stopped due to a system event"},
    {DetailCode::GENERAL_BUSY, "Database is busy, retry later"},
    {DetailCode::GENERAL_NOT_SET, "Sync option not set"},
    {DetailCode::GENERAL_PERMISSION, "Permission denied by the file system or database"},
    {DetailCode::GENERAL_FIRST_PAGE_CORRUPTED, "Database file is corrupted (not a database)"},
    {DetailCode::GENERAL_CORRUPTED_DB, "Database password is invalid or the file is corrupted"},
    {DetailCode::GENERAL_EKEYREVOKED, "Database key has been revoked"},
    {DetailCode::GENERAL_SQLITE_CANT_OPEN, "Failed to open the database file"},
    {DetailCode::GENERAL_CONSTRAINT, "SQLite constraint check failed"},
    {DetailCode::GENERAL_DENIED_SQL, "SQL execution is denied by authorization"},
    {DetailCode::CLOUD_LOCAL_ASSET_NOT_FOUND, "Local asset not found when uploading"},
    {DetailCode::CLOUD_SPACE_INSUFFICIENT_SKIPPED, "Records skipped for insufficient cloud space"},
    {DetailCode::CLOUD_EXPIRED_CURSOR, "Cloud cursor expired after retries"},
    {DetailCode::CLOUD_SYNC_TASK_MERGED, "Sync task has been merged into another task"},
};
}

/**
 * @tc.name: DbErrnoDetailCheck001
 * @tc.desc: Verify detail code bit layout composed by MakeDetailCode with different sync stages.
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: ztx
 */
HWTEST_F(DistributedDBDbErrnoDetailTest, DbErrnoDetailCheck001, TestSize.Level0)
{
    /**
     * @tc.steps: step1. check sync stage enum layout
     * @tc.expected: step1. GENERAL/DOWNLOAD/UPLOAD are low bits, MAX_SYNC_STAGE is sentinel
     */
    EXPECT_EQ(static_cast<uint32_t>(SyncStage::GENERAL), 0x00u);
    EXPECT_EQ(static_cast<uint32_t>(SyncStage::DOWNLOAD), 0x01u);
    EXPECT_EQ(static_cast<uint32_t>(SyncStage::UPLOAD), 0x02u);
    EXPECT_EQ(static_cast<uint32_t>(SyncStage::MAX_SYNC_STAGE), 0x3Fu);
    /**
     * @tc.steps: step2. check detail code layout constants
     * @tc.expected: stage shift is 16, internal flag is 0x400000, number mask is 0xFFFF
     */
    EXPECT_EQ(ProcessNotifier::DETAIL_CODE_STAGE_SHIFT, 16u);
    EXPECT_EQ(ProcessNotifier::DETAIL_CODE_INTERNAL_FLAG, 0x400000u);
    EXPECT_EQ(ProcessNotifier::DETAIL_CODE_NUMBER_MASK, 0xFFFFu);
    /**
     * @tc.steps: step3. compose detail code for each stage
     * @tc.expected: [bit22 internal flag][bits16-21 stage][bits0-15 error number]
     */
    EXPECT_EQ(ProcessNotifier::MakeDetailCode(SyncStage::GENERAL, DetailCode::GENERAL_DB_CLOSED),
        EXPECT_GENERAL_DB_CLOSED_CODE);
    EXPECT_EQ(ProcessNotifier::MakeDetailCode(SyncStage::GENERAL, DetailCode::GENERAL_INVALID_ARGS),
        0x400001u);
    EXPECT_EQ(ProcessNotifier::MakeDetailCode(SyncStage::DOWNLOAD, DetailCode::CLOUD_ERROR),
        EXPECT_DOWNLOAD_CLOUD_ERROR_CODE);
    EXPECT_EQ(ProcessNotifier::MakeDetailCode(SyncStage::UPLOAD, DetailCode::CLOUD_ERROR),
        EXPECT_UPLOAD_CLOUD_ERROR_CODE);
    EXPECT_EQ(ProcessNotifier::MakeDetailCode(SyncStage::GENERAL, DetailCode::CLOUD_ERROR), 0x401001u);
    EXPECT_EQ(ProcessNotifier::MakeDetailCode(SyncStage::GENERAL, DetailCode::CLOUD_HEARTBEAT_FAILED),
        EXPECT_HEARTBEAT_FAILED_CODE);
    EXPECT_EQ(ProcessNotifier::MakeDetailCode(SyncStage::GENERAL, DetailCode::CLOUD_HEARTBEAT_BLOCKED),
        EXPECT_HEARTBEAT_BLOCKED_CODE);
    EXPECT_EQ(ProcessNotifier::MakeDetailCode(SyncStage::GENERAL, DetailCode::CLOUD_SYSTEM_EVENT_STOPPED),
        EXPECT_SYSTEM_EVENT_STOPPED_CODE);
    EXPECT_EQ(ProcessNotifier::MakeDetailCode(SyncStage::GENERAL, DetailCode::SCHEMA_NOTEXIST),
        EXPECT_SCHEMA_NOTEXIST_CODE);
    EXPECT_EQ(ProcessNotifier::MakeDetailCode(SyncStage::DOWNLOAD, DetailCode::SCHEMA_MISMATCH), 0x412001u);
    EXPECT_EQ(ProcessNotifier::MakeDetailCode(SyncStage::UPLOAD, DetailCode::CLOUD_LOCK_ERROR), 0x421009u);
    /**
     * @tc.steps: step4. compose with the sentinels
     * @tc.expected: all bits of stage field and number field are set
     */
    EXPECT_EQ(ProcessNotifier::MakeDetailCode(SyncStage::MAX_SYNC_STAGE, DetailCode::MAX_DETAIL_CODE), 0x7FFFFFu);
}

/**
 * @tc.name: DbErrnoDetailCheck002
 * @tc.desc: Verify errno to detail number mapping covers all mapped errnos and rejects unmapped errnos.
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: ztx
 */
HWTEST_F(DistributedDBDbErrnoDetailTest, DbErrnoDetailCheck002, TestSize.Level0)
{
    /**
     * @tc.steps: step1. traverse the whole errno-detail mapping
     * @tc.expected: each mapped errno returns its detail number
     */
    for (const auto &entry : ERRNO_DETAIL_MAP) {
        EXPECT_EQ(ProcessNotifier::MapErrnoToDetailNumber(entry.errnoCode), entry.detailNumber);
    }
    EXPECT_EQ(sizeof(ERRNO_DETAIL_MAP) / sizeof(ERRNO_DETAIL_MAP[0]), 35u); // 15 general + 18 cloud + 2 schema
    /**
     * @tc.steps: step2. check key errnos used by the cloud sync flow
     * @tc.expected: mapped to the expected detail numbers
     */
    for (const auto &entry : KEY_ERRNO_DETAIL_NUMBERS) {
        EXPECT_EQ(ProcessNotifier::MapErrnoToDetailNumber(entry.errnoCode), entry.detailNumber);
    }
    /**
     * @tc.steps: step3. check unmapped errnos
     * @tc.expected: unmapped errnos keep detail code unset, return 0
     */
    EXPECT_EQ(ProcessNotifier::MapErrnoToDetailNumber(E_OK), 0u);
    EXPECT_EQ(ProcessNotifier::MapErrnoToDetailNumber(-E_QUERY_END), 0u);
    EXPECT_EQ(ProcessNotifier::MapErrnoToDetailNumber(-E_TASK_INTERRUPTED), 0u);
    EXPECT_EQ(ProcessNotifier::MapErrnoToDetailNumber(E_CLOUD_ERROR), 0u); // only negative errno is mapped
    EXPECT_EQ(ProcessNotifier::MapErrnoToDetailNumber(-12345), 0u); // never used errno
}

/**
 * @tc.name: DbErrnoDetailCheck003
 * @tc.desc: Verify GetDetailMsg returns the message of each detail code and empty for sentinels.
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: ztx
 */
HWTEST_F(DistributedDBDbErrnoDetailTest, DbErrnoDetailCheck003, TestSize.Level0)
{
    /**
     * @tc.steps: step1. traverse all detail codes that carry a direct message
     * @tc.expected: each detail code matches its message
     */
    for (auto code : DIRECT_MSG_CODES) {
        EXPECT_STRNE(ProcessNotifier::GetDetailMsg(code), "");
    }
    EXPECT_EQ(sizeof(DIRECT_MSG_CODES) / sizeof(DIRECT_MSG_CODES[0]), 36u); // all codes except the two schema codes
    /**
     * @tc.steps: step2. check some key messages
     * @tc.expected: the messages are the same as the requirement defines
     */
    for (const auto &entry : KEY_DETAIL_MSGS) {
        EXPECT_STREQ(ProcessNotifier::GetDetailMsg(entry.code), entry.msg);
    }
    /**
     * @tc.steps: step3. check the codes which are composed at runtime
     * @tc.expected: schema codes and sentinels have no static message
     */
    EXPECT_STREQ(ProcessNotifier::GetDetailMsg(DetailCode::SCHEMA_NOTEXIST), "");
    EXPECT_STREQ(ProcessNotifier::GetDetailMsg(DetailCode::SCHEMA_MISMATCH), "");
    EXPECT_STREQ(ProcessNotifier::GetDetailMsg(DetailCode::MAX_DETAIL_CODE), "");
}

/**
 * @tc.name: DbErrnoDetailCheck004
 * @tc.desc: Verify GetDetailMessage composes schema messages with table name and falls back for others.
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: ztx
 */
HWTEST_F(DistributedDBDbErrnoDetailTest, DbErrnoDetailCheck004, TestSize.Level0)
{
    /**
     * @tc.steps: step1. compose schema messages with the table name
     * @tc.expected: the message contains the table name
     */
    EXPECT_EQ(ProcessNotifier::GetDetailMessage(DetailCode::SCHEMA_NOTEXIST, "Student"),
        "Schema does not exist for table: Student");
    EXPECT_EQ(ProcessNotifier::GetDetailMessage(DetailCode::SCHEMA_MISMATCH, "Student"),
        "Schema mismatch for table: Student");
    EXPECT_EQ(ProcessNotifier::GetDetailMessage(DetailCode::SCHEMA_NOTEXIST, ""), "Schema does not exist for table: ");
    /**
     * @tc.steps: step2. fall back to the static message for non-schema codes
     * @tc.expected: the table name is ignored and the static message is returned
     */
    EXPECT_EQ(ProcessNotifier::GetDetailMessage(DetailCode::GENERAL_DB_CLOSED, "Student"),
        "The database has been closed, all sync tasks are terminated");
    EXPECT_EQ(ProcessNotifier::GetDetailMessage(DetailCode::CLOUD_ERROR, "Student"), "Cloud sync error");
    EXPECT_EQ(ProcessNotifier::GetDetailMessage(DetailCode::CLOUD_HEARTBEAT_BLOCKED, ""),
        "Heartbeat blocked twice, task aborted");
    EXPECT_EQ(ProcessNotifier::GetDetailMessage(DetailCode::MAX_DETAIL_CODE, "Student"), "");
}

/**
 * @tc.name: DbErrnoDetailCheck005
 * @tc.desc: Verify default values of ErrorDetail and CloudErrorInfo, zero means not set.
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: ztx
 */
HWTEST_F(DistributedDBDbErrnoDetailTest, DbErrnoDetailCheck005, TestSize.Level0)
{
    /**
     * @tc.steps: step1. check the default constructed error detail
     * @tc.expected: detailCode is 0 and errorMessage is empty which means not set
     */
    ErrorDetail errorDetail;
    EXPECT_EQ(errorDetail.detailCode, 0u);
    EXPECT_TRUE(errorDetail.errorMessage.empty());
    ErrorDetail specifiedDetail = { EXPECT_UPLOAD_CLOUD_ERROR_CODE, "Cloud sync error" };
    EXPECT_EQ(specifiedDetail.detailCode, EXPECT_UPLOAD_CLOUD_ERROR_CODE);
    EXPECT_EQ(specifiedDetail.errorMessage, "Cloud sync error");
    /**
     * @tc.steps: step2. check the default constructed cloud error info carried in SyncProcess
     * @tc.expected: action is default, detailCode is 0 and errorMessage is empty
     */
    CloudErrorInfo cloudErrorInfo;
    EXPECT_EQ(cloudErrorInfo.cloudAction, CloudErrorAction::ACTION_DEFAULT);
    EXPECT_EQ(cloudErrorInfo.detailCode, 0u);
    EXPECT_TRUE(cloudErrorInfo.errorMessage.empty());
    SyncProcess syncProcess;
    EXPECT_EQ(syncProcess.cloudErrorInfo.detailCode, 0u);
    EXPECT_TRUE(syncProcess.cloudErrorInfo.errorMessage.empty());
    syncProcess.cloudErrorInfo.cloudAction = CloudErrorAction::ACTION_RETRY_SYNC_TASK;
    syncProcess.cloudErrorInfo.detailCode = EXPECT_GENERAL_DB_CLOSED_CODE;
    syncProcess.cloudErrorInfo.errorMessage = "The database has been closed, all sync tasks are terminated";
    EXPECT_EQ(syncProcess.cloudErrorInfo.cloudAction, CloudErrorAction::ACTION_RETRY_SYNC_TASK);
    EXPECT_EQ(syncProcess.cloudErrorInfo.detailCode, EXPECT_GENERAL_DB_CLOSED_CODE);
}
