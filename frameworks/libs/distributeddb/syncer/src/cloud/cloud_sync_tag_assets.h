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
#ifndef CLOUD_SYNC_TAG_ASSETS_H
#define CLOUD_SYNC_TAG_ASSETS_H

#include <cstdint>
#include <string>

#include "cloud/cloud_db_constant.h"
#include "cloud/cloud_storage_utils.h"
#include "cloud/cloud_store_types.h"
#include "cloud/cloud_sync_utils.h"
#include "db_errno.h"
#include "icloud_sync_storage_interface.h"
#include "log_print.h"
#include "platform_specific.h"


namespace DistributedDB {
struct TagAssetsInfo {
    VBucket &coveredData;
    VBucket &beCoveredData;
    bool setNormalStatus = false;
    bool isFrocePullAssets = false;
};

struct TagAssetInfo {
    Asset &covered;
    Asset &beCovered;
    bool setNormalStatus = false;
    bool isFrocePullAssets = false;
};

Assets TagAssetsInSingleCol(TagAssetsInfo &tagAssetsInfo, const Field &assetField, int &errCode);
Type &GetAssetsCaseInsensitive(const std::string &assetFieldName, VBucket &vBucket);
void TagAssetsInSingleCol(const Field &assetField, bool isInsert, VBucket &coveredData);
} // namespace DistributedDB
#endif // CLOUD_SYNC_TAG_ASSETS_H