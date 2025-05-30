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
#include "cloud/cloud_sync_tag_assets.h"
#include "cloud/asset_operation_utils.h"
#include "db_common.h"

namespace DistributedDB {
namespace {
void TagSingleAssetForDownload(AssetOpType flag, Asset &asset, Assets &res, int &errCode)
{
    uint32_t newStatus = static_cast<uint32_t>(AssetStatus::DOWNLOADING);
    if (flag == AssetOpType::DELETE &&
        (AssetOperationUtils::EraseBitMask(asset.status) == AssetStatus::ABNORMAL ||
         asset.status == (AssetStatus::DOWNLOADING | AssetStatus::DOWNLOAD_WITH_NULL))) {
        asset.flag = static_cast<uint32_t>(AssetOpType::DELETE);
        res.push_back(asset);
        return;
    }
    if (AssetOperationUtils::EraseBitMask(asset.status) == static_cast<uint32_t>(AssetStatus::DELETE)) {
        newStatus = AssetStatus::DELETE;
        asset.flag = static_cast<uint32_t>(AssetOpType::DELETE);
    } else {
        asset.flag = static_cast<uint32_t>(flag);
    }
    if (flag == AssetOpType::INSERT) {
        newStatus |= AssetStatus::DOWNLOAD_WITH_NULL;
    }
    asset.status = static_cast<uint32_t>(newStatus);

    Timestamp timestamp;
    errCode = OS::GetCurrentSysTimeInMicrosecond(timestamp);
    if (errCode != E_OK) {
        LOGE("Can not get current timestamp.");
        return;
    }
    asset.timestamp = static_cast<int64_t>(timestamp / CloudDbConstant::TEN_THOUSAND);
    asset.status = asset.flag == static_cast<uint32_t>(AssetOpType::NO_CHANGE) ?
        static_cast<uint32_t>(AssetStatus::NORMAL) : asset.status;
    res.push_back(asset);
}

void TagSingleAssetForUpload(AssetOpType flag, Asset &asset, Assets &res)
{
    uint32_t lowBitStatus = AssetOperationUtils::EraseBitMask(asset.status);
    if (lowBitStatus == static_cast<uint32_t>(AssetStatus::DELETE)) {
        return;
    }
    switch (flag) {
        case AssetOpType::INSERT: {
            asset.assetId.clear();
            asset.status = static_cast<uint32_t>(AssetStatus::INSERT);
            break;
        }
        case AssetOpType::DELETE: {
            if (lowBitStatus != static_cast<uint32_t>(AssetStatus::DELETE)) {
                asset.status = static_cast<uint32_t>(AssetStatus::DELETE | AssetStatus::HIDDEN);
            }
            break;
        }
        case AssetOpType::UPDATE: {
            asset.status = static_cast<uint32_t>(AssetStatus::UPDATE);
            break;
        }
        case AssetOpType::NO_CHANGE: {
            asset.status = static_cast<uint32_t>(AssetStatus::NORMAL);
            break;
        }
        default:
            break;
    }
    res.push_back(asset);
}

void TagAssetWithNormalStatus(const bool isNormalStatus, AssetOpType flag,
    Asset &asset, Assets &res, int &errCode)
{
    if (isNormalStatus) {
        TagSingleAssetForUpload(flag, asset, res);
        return;
    }
    TagSingleAssetForDownload(flag, asset, res, errCode);
}

void TagAssetsWithNormalStatus(const bool isNormalStatus, AssetOpType flag,
    Assets &assets, Assets &res, int &errCode)
{
    for (Asset &asset : assets) {
        TagAssetWithNormalStatus(isNormalStatus, flag, asset, res, errCode);
        if (errCode != E_OK) {
            break;
        }
    }
}

template<typename T>
bool IsDataContainField(const std::string &assetFieldName, const VBucket &data)
{
    Type type;
    bool isExisted = CloudStorageUtils::GetTypeCaseInsensitive(assetFieldName, data, type);
    if (!isExisted) {
        return false;
    }
    // When type of Assets is not Nil but a vector which size is 0, we think data is not contain this field.
    if (type.index() == TYPE_INDEX<Assets>) {
        if (std::get<Assets>(type).empty()) {
            return false;
        }
    }
    if (type.index() != TYPE_INDEX<T>) {
        return false;
    }
    return true;
}

void TagAssetWithSameHash(const bool isNormalStatus, Asset &beCoveredAsset, Asset &coveredAsset, Assets &res,
    int &errCode)
{
    TagAssetWithNormalStatus(isNormalStatus, (
        AssetOperationUtils::EraseBitMask(beCoveredAsset.status) == AssetStatus::DELETE ||
        AssetOperationUtils::EraseBitMask(beCoveredAsset.status) == AssetStatus::ABNORMAL ||
        beCoveredAsset.status == (AssetStatus::DOWNLOADING | DOWNLOAD_WITH_NULL)) ?
        AssetOpType::INSERT : AssetOpType::NO_CHANGE, coveredAsset, res, errCode);
}

std::pair<bool, Assets> TagForNotContainsAsset(
    const std::string &assetFieldName, TagAssetsInfo &tagAssetsInfo, int &errCode)
{
    bool setNormalStatus = tagAssetsInfo.setNormalStatus;
    VBucket &coveredData = tagAssetsInfo.coveredData;
    VBucket &beCoveredData = tagAssetsInfo.beCoveredData;
    std::pair<bool, Assets> res = { true, {} };
    bool beCoveredHasAssets = IsDataContainField<Assets>(assetFieldName, beCoveredData);
    bool coveredHasAssets = IsDataContainField<Assets>(assetFieldName, coveredData);
    if (!beCoveredHasAssets) {
        if (coveredHasAssets) {
            // all the element in assets will be set to INSERT
            TagAssetsWithNormalStatus(setNormalStatus, AssetOpType::INSERT,
                std::get<Assets>(GetAssetsCaseInsensitive(assetFieldName, coveredData)), res.second, errCode);
        }
        return res;
    }
    if (!coveredHasAssets) {
        // all the element in assets will be set to DELETE
        TagAssetsWithNormalStatus(setNormalStatus, AssetOpType::DELETE,
            std::get<Assets>(GetAssetsCaseInsensitive(assetFieldName, beCoveredData)), res.second, errCode);
        GetAssetsCaseInsensitive(assetFieldName, coveredData) = res.second;
        return res;
    }
    return { false, {} };
}

static Assets TagAssetsInner(const std::string &assetFieldName, TagAssetsInfo &tagAssetsInfo, int &errCode)
{
    VBucket &coveredData = tagAssetsInfo.coveredData;
    VBucket &beCoveredData = tagAssetsInfo.beCoveredData;
    bool setNormalStatus = tagAssetsInfo.setNormalStatus;
    bool isFrocePullAssets = tagAssetsInfo.isFrocePullAssets;
    Assets res = {};
    if (!std::holds_alternative<Assets>(GetAssetsCaseInsensitive(assetFieldName, coveredData)) ||
        !std::holds_alternative<Assets>(GetAssetsCaseInsensitive(assetFieldName, beCoveredData))) {
        LOGE("[TagAssetsInner] coveredData or beCoveredData does not have assets");
        return {};
    }
    Assets &covered = std::get<Assets>(GetAssetsCaseInsensitive(assetFieldName, coveredData));
    Assets &beCovered = std::get<Assets>(GetAssetsCaseInsensitive(assetFieldName, beCoveredData));
    std::map<std::string, size_t> coveredAssetsIndexMap = CloudStorageUtils::GenAssetsIndexMap(covered);
    for (Asset &beCoveredAsset : beCovered) {
        auto it = coveredAssetsIndexMap.find(beCoveredAsset.name);
        if (it == coveredAssetsIndexMap.end()) {
            TagAssetWithNormalStatus(setNormalStatus, AssetOpType::DELETE, beCoveredAsset, res, errCode);
            covered.push_back(beCoveredAsset);
            continue;
        }
        Asset &coveredAsset = covered[it->second];
        if (setNormalStatus) {
            // fill asset id for upload data
            coveredAsset.assetId = beCoveredAsset.assetId;
        }
        if (!setNormalStatus && (beCoveredAsset.hash != coveredAsset.hash || isFrocePullAssets)) {
            TagAssetWithNormalStatus(setNormalStatus, AssetOpType::UPDATE, coveredAsset, res, errCode);
        } else if (setNormalStatus && beCoveredAsset.hash != coveredAsset.hash) {
            TagAssetWithNormalStatus(setNormalStatus, AssetOpType::UPDATE, coveredAsset, res, errCode);
        } else {
            TagAssetWithSameHash(setNormalStatus, beCoveredAsset, coveredAsset, res, errCode);
        }
        // Erase element which has been handled, remaining element will be set to Insert
        coveredAssetsIndexMap.erase(it);
        if (errCode != E_OK) {
            LOGE("Tag assets UPDATE or NO_CHANGE fail!");
            return {};
        }
    }
    for (const auto &noHandledAssetKvPair : coveredAssetsIndexMap) {
        TagAssetWithNormalStatus(setNormalStatus, AssetOpType::INSERT,
            covered[noHandledAssetKvPair.second], res, errCode);
        if (errCode != E_OK) {
            LOGE("Tag assets INSERT fail!");
            return {};
        }
    }
    return res;
}

// AssetOpType and AssetStatus will be tagged, assets to be changed will be returned
// use VBucket rather than Type because we need to check whether it is empty
Assets TagAssets(const std::string &assetFieldName, TagAssetsInfo &tagAssetsInfo, int &errCode)
{
    auto [isReturn, resAsset] = TagForNotContainsAsset(assetFieldName, tagAssetsInfo, errCode);
    if (isReturn) {
        return resAsset;
    }
    return TagAssetsInner(assetFieldName, tagAssetsInfo, errCode);
}

static void TagCoveredAssetInner(TagAssetInfo &tagAssetInfo, Assets &res,
    int &errCode)
{
    Asset &covered = tagAssetInfo.covered;
    Asset &beCovered = tagAssetInfo.beCovered;
    bool setNormalStatus = tagAssetInfo.setNormalStatus;
    bool isFrocePullAssets = tagAssetInfo.isFrocePullAssets;
    if (!setNormalStatus && AssetOperationUtils::IsAssetNeedDownload(beCovered)) {
        TagAssetWithNormalStatus(setNormalStatus, AssetOpType::INSERT, covered, res, errCode);
    } else if (covered.hash != beCovered.hash || isFrocePullAssets) {
        TagAssetWithNormalStatus(setNormalStatus, AssetOpType::UPDATE, covered, res, errCode);
    } else {
        Assets tmpAssets = {};
        TagAssetWithNormalStatus(true, AssetOpType::NO_CHANGE, covered, tmpAssets, errCode);
    }
}

void TagAssetCoveredWithNoAsset(
    const std::string &assetFieldName, TagAssetsInfo &tagAssetsInfo, Assets &res, int &errCode)
{
    VBucket &coveredData = tagAssetsInfo.coveredData;
    VBucket &beCoveredData = tagAssetsInfo.beCoveredData;
    bool setNormalStatus = tagAssetsInfo.setNormalStatus;
    if (GetAssetsCaseInsensitive(assetFieldName, beCoveredData).index() == TYPE_INDEX<Asset>) {
        TagAssetWithNormalStatus(setNormalStatus, AssetOpType::DELETE,
            std::get<Asset>(GetAssetsCaseInsensitive(assetFieldName, beCoveredData)), res, errCode);
        if (!setNormalStatus) {
            // only not normal need fillback asset data
            coveredData[assetFieldName] = std::get<Asset>(GetAssetsCaseInsensitive(assetFieldName, beCoveredData));
        }
    } else if (GetAssetsCaseInsensitive(assetFieldName, beCoveredData).index() == TYPE_INDEX<Assets>) {
        TagAssetsWithNormalStatus(setNormalStatus, AssetOpType::DELETE,
            std::get<Assets>(GetAssetsCaseInsensitive(assetFieldName, beCoveredData)), res, errCode);
    }
}

// AssetOpType and AssetStatus will be tagged, assets to be changed will be returned
Assets TagAsset(const std::string &assetFieldName, TagAssetsInfo &tagAssetsInfo, int &errCode)
{
    VBucket &coveredData = tagAssetsInfo.coveredData;
    VBucket &beCoveredData = tagAssetsInfo.beCoveredData;
    bool setNormalStatus = tagAssetsInfo.setNormalStatus;
    Assets res = {};
    bool beCoveredHasAsset = IsDataContainField<Asset>(assetFieldName, beCoveredData) ||
        IsDataContainField<Assets>(assetFieldName, beCoveredData);
    bool coveredHasAsset = IsDataContainField<Asset>(assetFieldName, coveredData);
    if (!beCoveredHasAsset) {
        if (!coveredHasAsset) {
            LOGD("[CloudSyncer] Both data do not contain certain asset field");
            return res;
        }
        TagAssetWithNormalStatus(setNormalStatus, AssetOpType::INSERT,
            std::get<Asset>(GetAssetsCaseInsensitive(assetFieldName, coveredData)), res, errCode);
        return res;
    }
    if (!coveredHasAsset) {
        TagAssetCoveredWithNoAsset(assetFieldName, tagAssetsInfo, res, errCode);
        return res;
    }
    Asset &covered = std::get<Asset>(GetAssetsCaseInsensitive(assetFieldName, coveredData));
    Asset beCovered;
    if (GetAssetsCaseInsensitive(assetFieldName, beCoveredData).index() == TYPE_INDEX<Asset>) {
        // This indicates that asset in cloudData is stored as Asset
        beCovered = std::get<Asset>(GetAssetsCaseInsensitive(assetFieldName, beCoveredData));
    } else if (GetAssetsCaseInsensitive(assetFieldName, beCoveredData).index() == TYPE_INDEX<Assets>) {
        // Stored as ASSETS, first element in assets will be the target asset
        beCovered = (std::get<Assets>(GetAssetsCaseInsensitive(assetFieldName, beCoveredData)))[0];
    } else {
        LOGE("The type of data is neither Asset nor Assets");
        return res;
    }
    if (covered.name != beCovered.name) {
        TagAssetWithNormalStatus(setNormalStatus, AssetOpType::INSERT, covered, res, errCode);
        TagAssetWithNormalStatus(setNormalStatus, AssetOpType::DELETE, beCovered, res, errCode);
        return res;
    }
    if (setNormalStatus) {
        // fill asset id for upload data
        covered.assetId = beCovered.assetId;
    }
    TagAssetInfo tagAssetInfo = {covered, beCovered, tagAssetsInfo.setNormalStatus, tagAssetsInfo.isFrocePullAssets};
    TagCoveredAssetInner(tagAssetInfo, res, errCode);
    return res;
}

void MarkAssetForUpload(bool isInsert, Asset &asset)
{
    uint32_t lowBitStatus = AssetOperationUtils::EraseBitMask(asset.status);
    if (lowBitStatus == AssetStatus::DELETE) {
        asset.flag = static_cast<uint32_t>(AssetOpType::DELETE);
    } else if (isInsert) {
        asset.flag = static_cast<uint32_t>(AssetOpType::INSERT);
        lowBitStatus = static_cast<uint32_t>(AssetStatus::INSERT);
    } else if (asset.status == AssetStatus::NORMAL) {
        asset.flag = static_cast<uint32_t>(AssetOpType::NO_CHANGE);
    } else if (asset.assetId.empty()) {
        asset.flag = static_cast<uint32_t>(AssetOpType::INSERT);
        lowBitStatus = static_cast<uint32_t>(AssetStatus::INSERT);
    } else if (!asset.assetId.empty()) {
        asset.flag = static_cast<uint32_t>(AssetOpType::UPDATE);
        lowBitStatus = static_cast<uint32_t>(AssetStatus::UPDATE);
    } else {
        asset.flag = static_cast<uint32_t>(AssetOpType::NO_CHANGE);
    }
    asset.status = lowBitStatus;
    Timestamp timestamp;
    int errCode = OS::GetCurrentSysTimeInMicrosecond(timestamp);
    if (errCode != E_OK) {
        LOGE("Can not get current timestamp. %d", errCode);
        return;
    }
    asset.timestamp = static_cast<int64_t>(timestamp / CloudDbConstant::TEN_THOUSAND);
}

void TagAssetsForUpload(const std::string &filedName, bool isInsert, VBucket &coveredData)
{
    if (!IsDataContainField<Assets>(filedName, coveredData)) {
        return;
    }
    Assets &covered = std::get<Assets>(GetAssetsCaseInsensitive(filedName, coveredData));
    for (auto &asset: covered) {
        MarkAssetForUpload(isInsert, asset);
    }
}

void TagAssetForUpload(const std::string &filedName, bool isInsert, VBucket &coveredData)
{
    if (!IsDataContainField<Asset>(filedName, coveredData)) {
        return;
    }
    Asset &asset = std::get<Asset>(GetAssetsCaseInsensitive(filedName, coveredData));
    MarkAssetForUpload(isInsert, asset);
}
} // namespace

Assets TagAssetsInSingleCol(TagAssetsInfo &tagAssetsInfo, const Field &assetField, int &errCode)
{
    // Define a list to store the tagged result
    Assets assets = {};
    switch (assetField.type) {
        case TYPE_INDEX<Assets>: {
            assets = TagAssets(assetField.colName, tagAssetsInfo, errCode);
            break;
        }
        case TYPE_INDEX<Asset>: {
            assets = TagAsset(assetField.colName, tagAssetsInfo, errCode);
            break;
        }
        default:
            LOGW("[CloudSyncer] Meet an unexpected type %d", assetField.type);
            break;
    }
    return assets;
}

Type &GetAssetsCaseInsensitive(const std::string &assetFieldName, VBucket &vBucket)
{
    for (auto &item : vBucket) {
        if (DBCommon::CaseInsensitiveCompare(item.first, assetFieldName)) {
            return item.second;
        }
    }
    return vBucket[assetFieldName];
}

void TagAssetsInSingleCol(const Field &assetField, bool isInsert, VBucket &coveredData)
{
    switch (assetField.type) {
        case TYPE_INDEX<Assets>: {
            TagAssetsForUpload(assetField.colName, isInsert, coveredData);
            break;
        }
        case TYPE_INDEX<Asset>: {
            TagAssetForUpload(assetField.colName, isInsert, coveredData);
            break;
        }
        default:
            LOGW("[CloudSyncer] Meet an unexpected type %d", assetField.type);
            break;
    }
}
} // namespace DistributedDB
