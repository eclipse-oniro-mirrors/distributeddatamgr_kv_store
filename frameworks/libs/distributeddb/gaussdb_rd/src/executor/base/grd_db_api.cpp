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
#include "grd_base/grd_db_api.h"

#include "check_common.h"
#include "doc_errno.h"
#include "document_store_manager.h"
#include "grd_api_manager.h"
#include "grd_base/grd_error.h"
#include "grd_type_inner.h"
#include "rd_log_print.h"

using namespace DocumentDB;
static GRD_APIInfo *GRD_DBApiInfo = GetApiInfo();

GRD_API int32_t GRD_DBOpen(const char *dbPath, const char *configStr, uint32_t flags, GRD_DB **db)
{
    InitApiInfo(configStr);
    GetApiInfoInstance();
    if (GRD_DBApiInfo->DBOpenApi == nullptr) {
        GLOGE("Fail to dlysm RD api symbol");
        return GRD_INNER_ERR;
    }
    int32_t ret = GRD_DBApiInfo->DBOpenApi(dbPath, configStr, flags, db);
    if (ret != GRD_OK) {
        GLOGE("Fail to open db");
        UnloadApiInfo(GRD_DBApiInfo);
        return ret;
    }
    return ret;
}

GRD_API int32_t GRD_DBClose(GRD_DB *db, uint32_t flags)
{
    if (GRD_DBApiInfo->DBCloseApi == nullptr) {
        GLOGE("Fail to dlysm RD api symbol");
        return GRD_INNER_ERR;
    }
    int32_t ret = GRD_DBApiInfo->DBCloseApi(db, flags);
    if (ret != GRD_OK) {
        GLOGE("Fail to close db");
    }
    UnloadApiInfo(GRD_DBApiInfo);
    return ret;
}

GRD_API int32_t GRD_DBBackup(GRD_DB *db, const char *backupDbFile, uint8_t *encryptedKey, uint32_t encryptedKeyLen)
{
    if (GRD_DBApiInfo->DBBackupApi == nullptr) {
        GLOGE("Fail to dlysm RD api symbol");
        return GRD_INNER_ERR;
    }
    GRD_CipherInfoT cipherInfo = {.hexPassword = nullptr};
    return GRD_DBApiInfo->DBBackupApi(db, backupDbFile, &cipherInfo);
}

GRD_API int32_t GRD_DBRestore(const char *dbFile, const char *backupDbFile, uint8_t *decryptedKey,
    uint32_t decryptedKeyLen)
{
    // db restore operation will start after dbclose, should reload so to link api func
    GetApiInfoInstance();
    if (GRD_DBApiInfo->DBRestoreApi == nullptr) {
        GLOGE("Fail to dlysm RD api symbol");
        UnloadApiInfo(GRD_DBApiInfo);
        return GRD_INNER_ERR;
    }
    GRD_CipherInfoT cipherInfo = {.hexPassword = nullptr};
    int32_t ret = GRD_DBApiInfo->DBRestoreApi(dbFile, backupDbFile, &cipherInfo);
    if (ret != GRD_OK) {
        GLOGE("Fail to restore db");
    }
    UnloadApiInfo(GRD_DBApiInfo);
    return ret;
}

GRD_API int32_t GRD_Flush(GRD_DB *db, uint32_t flags)
{
    if (GRD_DBApiInfo->FlushApi == nullptr) {
        GLOGE("Fail to dlysm RD api symbol");
        return GRD_INNER_ERR;
    }
    return GRD_DBApiInfo->FlushApi(db, flags);
}

GRD_API int32_t GRD_IndexPreload(GRD_DB *db, const char *collectionName)
{
    if (GRD_DBApiInfo->IndexPreloadApi == nullptr) {
        GLOGE("Fail to dlysm RD api symbol");
        return GRD_INNER_ERR;
    }
    return GRD_DBApiInfo->IndexPreloadApi(db, collectionName);
}
