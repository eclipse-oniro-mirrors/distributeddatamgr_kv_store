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

#ifndef GRD_DB_API_H
#define GRD_DB_API_H
#include <cstdint>

#include "grd_type_export.h"
#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

GRD_API int32_t GRD_DBOpen(const char *dbPath, const char *configStr, uint32_t flags, GRD_DB **db);

GRD_API int32_t GRD_DBClose(GRD_DB *db, uint32_t flags);

GRD_API int32_t GRD_IndexPreload(GRD_DB *db, const char *collectionName);

GRD_API int32_t GRD_Flush(GRD_DB *db, uint32_t flags);

GRD_API void GRD_SetLibType(bool isHash = false);
#ifdef __cplusplus
}
#endif // __cplusplus
#endif // GRD_DB_API_H