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
#define LOG_TAG "SECURITYMANAGER"
#include "security_manager.h"
#include <limits>
#include <random>
#include <unistd.h>
#include "log_print.h"
#include "hks_api.h"
#include "hks_param.h"
#include "file_ex.h"
#include "securec.h"
#include "store_util.h"
#include "task_executor.h"
namespace OHOS::DistributedKv {
SecurityManager::SecurityManager()
{
    vecRootKeyAlias_ = std::vector<uint8_t>(ROOT_KEY_ALIAS, ROOT_KEY_ALIAS + strlen(ROOT_KEY_ALIAS));
    vecNonce_ = std::vector<uint8_t>(HKS_BLOB_TYPE_NONCE, HKS_BLOB_TYPE_NONCE + strlen(HKS_BLOB_TYPE_NONCE));
    vecAad_ = std::vector<uint8_t>(HKS_BLOB_TYPE_AAD, HKS_BLOB_TYPE_AAD + strlen(HKS_BLOB_TYPE_AAD));
}

SecurityManager::~SecurityManager()
{}

SecurityManager &SecurityManager::GetInstance()
{
    static SecurityManager instance;
    return instance;
}

bool SecurityManager::Retry()
{
    auto status = CheckRootKey();
    if (status == HKS_SUCCESS) {
        hasRootKey_ = true;
        ZLOGE("root key already exist.");
        return true;
    }

    if (status == HKS_ERROR_NOT_EXIST && GenerateRootKey() == HKS_SUCCESS) {
        hasRootKey_ = true;
        ZLOGE("GenerateRootKey success.");
        return true;
    }

    constexpr int32_t interval = 100;
    TaskExecutor::GetInstance().Execute([this] { Retry(); }, interval);
    return false;
}

SecurityManager::DBPassword SecurityManager::GetDBPassword(const std::string &name, const std::string &path,
    bool needCreate)
{
    DBPassword password;
    auto secKey = LoadKeyFromFile(name, path);
    if (secKey.empty() && needCreate) {
        secKey = Random(KEY_SIZE);
        if (!SaveKeyToFile(name, path, secKey)) {
            secKey.assign(secKey.size(), 0);
            return password;
        }
    }

    password.SetValue(secKey.data(), secKey.size());
    secKey.assign(secKey.size(), 0);
    return password;
}

bool SecurityManager::SaveDBPassword(const std::string &name, const std::string &path,
    const SecurityManager::DBPassword &key)
{
    std::vector<uint8_t> pwd(key.GetData(), key.GetData() + key.GetSize());
    auto result = SaveKeyToFile(name, path, pwd);
    pwd.assign(pwd.size(), 0);
    return result;
}

void SecurityManager::DelDBPassword(const std::string &name, const std::string &path)
{
    auto keyPath = path + "/key/" + name + ".key";
    StoreUtil::Remove(keyPath);
}

std::vector<uint8_t> SecurityManager::Random(int32_t len)
{
    std::random_device randomDevice;
    std::uniform_int_distribution<int> distribution(0, std::numeric_limits<uint8_t>::max());
    std::vector<uint8_t> key(len);
    for (int32_t i = 0; i < len; i++) {
        key[i] = static_cast<uint8_t>(distribution(randomDevice));
    }
    return key;
}

std::vector<uint8_t> SecurityManager::LoadKeyFromFile(const std::string &name, const std::string &path)
{
    auto keyPath = path + "/key/" + name + ".key";
    if (!FileExists(keyPath)) {
        return {};
    }

    std::vector<char> content;
    auto loaded = LoadBufferFromFile(keyPath, content);
    if (!loaded) {
        return {};
    }

    if (content.size() < (sizeof(time_t) / sizeof(uint8_t)) + KEY_SIZE + 1) {
        return {};
    }

    size_t offset = 0;
    if (content[offset] != char((sizeof(time_t) / sizeof(uint8_t)) + KEY_SIZE)) {
        return {};
    }

    offset++;
    std::vector<uint8_t> date;
    date.assign(content.begin() + offset, content.begin() + (sizeof(time_t) / sizeof(uint8_t)) + offset);
    offset += (sizeof(time_t) / sizeof(uint8_t));
    std::vector<uint8_t> key{content.begin() + offset, content.end()};
    content.assign(content.size(), 0);
    std::vector<uint8_t> secretKey {};
    if(!Decrypt(key, secretKey)) {
        ZLOGE("client Decrypt failed");
        return {};
    }
    return secretKey;
}

bool SecurityManager::SaveKeyToFile(const std::string &name, const std::string &path, std::vector<uint8_t> &key)
{
    if (!hasRootKey_ && !Retry()) {
        ZLOGE("failed! no root key and generation failed");
        return false;
    }
    
    auto secretKey = Encrypt(key);
    auto keyPath = path + "/key";
    StoreUtil::InitPath(keyPath);
    std::vector<char> content;
    auto time = std::chrono::system_clock::to_time_t(std::chrono::system_clock::system_clock::now());
    std::vector<uint8_t> date(reinterpret_cast<uint8_t *>(&time), reinterpret_cast<uint8_t *>(&time) + sizeof(time));
    content.push_back(char((sizeof(time_t) / sizeof(uint8_t)) + KEY_SIZE));
    content.insert(content.end(), date.begin(), date.end());
    content.insert(content.end(), secretKey.begin(), secretKey.end());
    auto keyFullPath = keyPath+ "/" + name + ".key";
    auto ret = SaveBufferToFile(keyFullPath, content);
    content.assign(content.size(), 0);
    if (!ret) {
        ZLOGE("client SaveSecretKey failed!");
        return false;
    }
    return ret;
}

std::vector<uint8_t> SecurityManager::Encrypt(const std::vector<uint8_t> &key)
{
    struct HksBlob blobAad = { uint32_t(vecAad_.size()), vecAad_.data() };
    struct HksBlob blobNonce = { uint32_t(vecNonce_.size()), vecNonce_.data() };
    struct HksBlob rootKeyName = { uint32_t(vecRootKeyAlias_.size()), vecRootKeyAlias_.data() };
    struct HksBlob plainKey = { uint32_t(key.size()), const_cast<uint8_t *>(key.data()) };
    struct HksParamSet *params = nullptr;
    int32_t ret = HksInitParamSet(&params);
    if (ret != HKS_SUCCESS) {
        ZLOGE("HksInitParamSet failed, status: %{public}d", ret);
        return {};
    }
    struct HksParam hksParam[] = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT },
        { .tag = HKS_TAG_DIGEST, .uint32Param = 0 },
        { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_GCM },
        { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
        { .tag = HKS_TAG_NONCE, .blob = blobNonce },
        { .tag = HKS_TAG_ASSOCIATED_DATA, .blob = blobAad },
    };
    ret = HksAddParams(params, hksParam, sizeof(hksParam) / sizeof(hksParam[0]));
    if (ret != HKS_SUCCESS) {
        ZLOGE("HksAddParams failed, status: %{public}d", ret);
        HksFreeParamSet(&params);
        return {};
    }

    ret = HksBuildParamSet(&params);
    if (ret != HKS_SUCCESS) {
        ZLOGE("HksBuildParamSet failed, status: %{public}d", ret);
        HksFreeParamSet(&params);
        return {};
    }

    uint8_t cipherBuf[256] = { 0 };
    struct HksBlob cipherText = { sizeof(cipherBuf), cipherBuf };
    ret = HksEncrypt(&rootKeyName, params, &plainKey, &cipherText);
    (void)HksFreeParamSet(&params);
    if (ret != HKS_SUCCESS) {
        ZLOGE("HksEncrypt failed, status: %{public}d", ret);
        return {};
    }
    std::vector<uint8_t> encryptedKey(cipherText.data, cipherText.data + cipherText.size);
    (void)memset_s(cipherBuf, sizeof(cipherBuf), 0, sizeof(cipherBuf));
    return encryptedKey;
}

bool SecurityManager::Decrypt(std::vector<uint8_t> &source, std::vector<uint8_t> &key)
{
    struct HksBlob blobAad = { uint32_t(vecAad_.size()), &(vecAad_[0]) };
    struct HksBlob blobNonce = { uint32_t(vecNonce_.size()), &(vecNonce_[0]) };
    struct HksBlob rootKeyName = { uint32_t(vecRootKeyAlias_.size()), &(vecRootKeyAlias_[0]) };
    struct HksBlob encryptedKeyBlob = { uint32_t(source.size()), source.data() };

    struct HksParamSet *params = nullptr;
    int32_t ret = HksInitParamSet(&params);
    if (ret != HKS_SUCCESS) {
        ZLOGE("HksInitParamSet failed, status: %{public}d", ret);
        return false;
    }
    struct HksParam hksParam[] = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_DECRYPT },
        { .tag = HKS_TAG_DIGEST, .uint32Param = 0 },
        { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_GCM },
        { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
        { .tag = HKS_TAG_NONCE, .blob = blobNonce },
        { .tag = HKS_TAG_ASSOCIATED_DATA, .blob = blobAad },
    };
    ret = HksAddParams(params, hksParam, sizeof(hksParam) / sizeof(hksParam[0]));
    if (ret != HKS_SUCCESS) {
        ZLOGE("HksAddParams failed, status: %{public}d", ret);
        HksFreeParamSet(&params);
        return false;
    }

    ret = HksBuildParamSet(&params);
    if (ret != HKS_SUCCESS) {
        ZLOGE("HksBuildParamSet failed, status: %{public}d", ret);
        HksFreeParamSet(&params);
        return false;
    }

    uint8_t plainBuf[256] = { 0 };
    struct HksBlob plainKeyBlob = { sizeof(plainBuf), plainBuf };
    ret = HksDecrypt(&rootKeyName, params, &encryptedKeyBlob, &plainKeyBlob);
    (void)HksFreeParamSet(&params);
    if (ret != HKS_SUCCESS) {
        ZLOGE("HksDecrypt, status: %{public}d", ret);
        return false;
    }

    key.assign(plainKeyBlob.data, plainKeyBlob.data + plainKeyBlob.size);
    (void)memset_s(plainBuf, sizeof(plainBuf), 0, sizeof(plainBuf));
    return true;
}

int32_t SecurityManager::GenerateRootKey()
{
    struct HksBlob rootKeyName = { uint32_t(vecRootKeyAlias_.size()), vecRootKeyAlias_.data() };
    struct HksParamSet *params = nullptr;
    int32_t ret = HksInitParamSet(&params);
    if (ret != HKS_SUCCESS) {
        ZLOGE("HksInitParamSet failed, status: %{public}d", ret);
        return ret;
    }

    struct HksParam hksParam[] = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_256 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
        { .tag = HKS_TAG_DIGEST, .uint32Param = 0 },
        { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
        { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_GCM },
    };

    ret = HksAddParams(params, hksParam, sizeof(hksParam) / sizeof(hksParam[0]));
    if (ret != HKS_SUCCESS) {
        ZLOGE("HksAddParams failed, status: %{public}d", ret);
        HksFreeParamSet(&params);
        return ret;
    }

    ret = HksBuildParamSet(&params);
    if (ret != HKS_SUCCESS) {
        ZLOGE("HksBuildParamSet failed, status: %{public}d", ret);
        HksFreeParamSet(&params);
        return ret;
    }

    ret = HksGenerateKey(&rootKeyName, params, nullptr);
    HksFreeParamSet(&params);
    ZLOGI("HksGenerateKey status: %{public}d", ret);
    return ret;
}

int32_t SecurityManager::CheckRootKey()
{
    struct HksBlob rootKeyName = { uint32_t(vecRootKeyAlias_.size()), vecRootKeyAlias_.data() };
    struct HksParamSet *params = nullptr;
    int32_t ret = HksInitParamSet(&params);
    if (ret != HKS_SUCCESS) {
        ZLOGE("HksInitParamSet failed, status: %{public}d", ret);
        return ret;
    }

    struct HksParam hksParam[] = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_256 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
        { .tag = HKS_TAG_DIGEST, .uint32Param = 0 },
        { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
        { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_GCM },
    };

    ret = HksAddParams(params, hksParam, sizeof(hksParam) / sizeof(hksParam[0]));
    if (ret != HKS_SUCCESS) {
        ZLOGE("HksAddParams failed, status: %{public}d", ret);
        HksFreeParamSet(&params);
        return ret;
    }

    ret = HksBuildParamSet(&params);
    if (ret != HKS_SUCCESS) {
        ZLOGE("HksBuildParamSet failed, status: %{public}d", ret);
        HksFreeParamSet(&params);
        return ret;
    }

    ret = HksKeyExist(&rootKeyName, params);
    HksFreeParamSet(&params);
    ZLOGI("HksKeyExist status: %{public}d", ret);
    return ret;
}

bool SecurityManager::IsKeyOutdated(const SecurityManager::DBPassword &key, bool encrypt)
{
    ZLOGE("Size of key is: %{public}d, and time size is: %{public}d ",key.GetSize(),(sizeof(time_t) / sizeof(uint8_t)));
    if (!encrypt) {
        ZLOGE("No encrypt db");
        return false;
    }
    if (key.GetSize() < (sizeof(time_t) / sizeof(uint8_t)) + KEY_SIZE) {
        ZLOGE("Key check failed, size og key is %{public}d", sizeof(time_t) / sizeof(uint8_t) + KEY_SIZE);
        return false;
    }
    auto secData = key.GetData();
    std::vector<uint8_t> timeVec;
    for (int i = 0; i < static_cast<int>(sizeof(time_t) / sizeof(uint8_t)); i++) {
        timeVec.push_back(secData[i]);
    }

    time_t createTime = TransferByteArrayToType<time_t>(timeVec);
    std::chrono::system_clock::time_point createTimePointer = std::chrono::system_clock::from_time_t(createTime);
    time_t oneYearLater = std::chrono::system_clock::to_time_t(createTimePointer + std::chrono::hours(525600));
    std::chrono::system_clock::time_point currentTimePointer = std::chrono::system_clock::now();
    time_t currentTime = std::chrono::system_clock::to_time_t(currentTimePointer);
    return (oneYearLater > currentTime);
}

bool SecurityManager::ReKey(const std::string &name, const std::string &path, DBStore *store)
{
    if (store == nullptr) {
        ZLOGE("Pointer store is nullptr");
        return false;
    }
    std::vector<uint8_t> secKey = Random(KEY_SIZE);
    DBPassword password;
    auto status = password.SetValue(secKey.data(), secKey.size());
    if (status != DBPassword::ErrorCode::OK) {
        ZLOGE("Failed to set the password.");
        return false;
    }
    DBStatus dbStatus = store->Rekey(password);
    if (dbStatus != DBStatus::OK) {
        ZLOGE("Rekey failed");
        return false;
    }
    bool isSaved = SaveKeyToFile(name, path, secKey);
    if (isSaved) {
        ZLOGE("Rekey success");
    }
    secKey.assign(secKey.size(), 0);
    return isSaved;
}
} // namespace OHOS::DistributedKv