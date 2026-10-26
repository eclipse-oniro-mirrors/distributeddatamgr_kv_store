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

#include "value_hash_calc.h"
#include "db_errno.h"
#include "log_print.h"
#ifdef USE_HITLS
#include "crypt_eal_md.h"
#include "crypt_errno.h"
#else
#include <openssl/sha.h>
#endif

namespace DistributedDB {
struct ValueHashCalc::ValueHashCalcContext {
#ifdef USE_HITLS
    CRYPT_EAL_MdCTX *ctx = nullptr;
#else
    SHA256_CTX *ctx = nullptr;
#endif
};

ValueHashCalc::ValueHashCalc() : context_(new (std::nothrow) ValueHashCalcContext)
{
}

ValueHashCalc::~ValueHashCalc()
{
    if (context_ != nullptr) {
        if (context_->ctx != nullptr) {
#ifdef USE_HITLS
            CRYPT_EAL_MdFreeCtx(context_->ctx);
#else
            delete context_->ctx;
#endif
            context_->ctx = nullptr;
        }
        delete context_;
        context_ = nullptr;
    }
}

int ValueHashCalc::Initialize() const
{
    if (context_ == nullptr) {
        return -E_OUT_OF_MEMORY;
    }
    if (context_->ctx != nullptr) {
        return -E_CALC_HASH;
    }
#ifdef USE_HITLS
    context_->ctx = CRYPT_EAL_MdNewCtx(CRYPT_MD_SHA256);
    if (context_->ctx == nullptr) {
        LOGE("openhitls md new ctx failed");
        return -E_CALC_HASH;
    }
    int32_t ret = CRYPT_EAL_MdInit(context_->ctx);
    if (ret != CRYPT_SUCCESS) {
        LOGE("openhitls md init failed:%d", ret);
        CRYPT_EAL_MdFreeCtx(context_->ctx);
        context_->ctx = nullptr;
        return -E_CALC_HASH;
    }
#else
    context_->ctx = new (std::nothrow) SHA256_CTX;
    if (context_->ctx == nullptr) {
        return -E_OUT_OF_MEMORY;
    }
    int errCode = SHA256_Init(context_->ctx);
    if (errCode == 0) {
        LOGE("sha init falied:%d", errCode);
        delete context_->ctx;
        context_->ctx = nullptr;
        return -E_CALC_HASH;
    }
#endif
    return E_OK;
}

int ValueHashCalc::Update(const std::vector<uint8_t> &value) const
{
    if (context_ == nullptr || context_->ctx == nullptr) {
        return -E_CALC_HASH;
    }
#ifdef USE_HITLS
    int32_t ret = CRYPT_EAL_MdUpdate(context_->ctx, value.data(), value.size());
    if (ret != CRYPT_SUCCESS) {
        LOGE("openhitls md update failed:%d", ret);
        return -E_CALC_HASH;
    }
#else
    int errCode = SHA256_Update(context_->ctx, value.data(), value.size());
    if (errCode == 0) {
        LOGE("sha update falied:%d", errCode);
        return -E_CALC_HASH;
    }
#endif
    return E_OK;
}

int ValueHashCalc::GetResult(std::vector<uint8_t> &value) const
{
    if (context_ == nullptr || context_->ctx == nullptr) {
        return -E_CALC_HASH;
    }
#ifdef USE_HITLS
    const uint32_t digestSize = CRYPT_EAL_MdGetDigestSize(CRYPT_MD_SHA256); //32
    value.resize(digestSize);
    uint32_t mdSize = digestSize;
    int32_t ret = CRYPT_EAL_MdFinal(context_->ctx, value.data(), &mdSize);
    if (ret != CRYPT_SUCCESS) {
        LOGE("openhitls md final failed:%d", ret);
        return -E_CALC_HASH;
    }
#else
    value.resize(SHA256_DIGEST_LENGTH);
    int errCode = SHA256_Final(value.data(), context_->ctx);
    if (errCode == 0) {
        LOGE("sha get result falied:%d", errCode);
        return -E_CALC_HASH;
    }
#endif
    return E_OK;
}
}
