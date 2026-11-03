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

#include <atomic>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <vector>

// value_hash_calc.h must be included before the openssl header: it transitively
// includes db_constant.h, which declares a member named SHA256_DIGEST_LENGTH that
// would otherwise be broken by the SHA256_DIGEST_LENGTH macro of openssl/sha.h.
// This is the same include order as value_hash_calc.cpp itself.
#include "db_errno.h"
#include "value_hash_calc.h"

#ifdef USE_HITLS
#include "crypt_eal_md.h"
#include "crypt_errno.h"
#else
#include <openssl/sha.h>
#endif

using namespace testing::ext;
using namespace DistributedDB;

namespace {
/*
 * Failure-injection switches of the crypto stubs below. All switches are off by
 * default, which means the stubs forward every call to the real crypto library
 * loaded from the shared library, so the behaviour observed by all other test
 * cases stays exactly the same as without these stubs. Each abnormal test case
 * turns on exactly one switch and all switches are restored in SetUp/TearDown,
 * so the result of every test case is deterministic.
 */
std::atomic<bool> g_stubMdNewCtxFail { false }; // HITLS only: MdNewCtx returns nullptr.
std::atomic<bool> g_stubMdInitFail { false }; // init of the digest context fails.
std::atomic<bool> g_stubMdUpdateFail { false }; // update of the digest fails.
std::atomic<bool> g_stubMdFinalFail { false }; // final of the digest fails.

constexpr uint8_t STUB_DIGEST_BYTE = 0x5A; // deterministic filler for the no-library fallback.
constexpr uint32_t STUB_DIGEST_LENGTH = 32; // SHA256 digest size in bytes, same as the real one.

/*
 * Resolve the real function from the shared library that follows this test
 * executable in the symbol search order. The local stub definitions preempt
 * the shared library ones for direct calls, while dlsym(RTLD_NEXT, ...) still
 * finds them, so the default behaviour stays fully transparent.
 */
template<typename RealFunc>
RealFunc GetRealCryptoFunc(const char *name)
{
    static RealFunc realFunc = reinterpret_cast<RealFunc>(dlsym(RTLD_NEXT, name));
    return realFunc;
}

void ResetStubSwitches()
{
    g_stubMdNewCtxFail = false;
    g_stubMdInitFail = false;
    g_stubMdUpdateFail = false;
    g_stubMdFinalFail = false;
}

class DistributedDBValueHashCalcTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void DistributedDBValueHashCalcTest::SetUpTestCase(void) {}

void DistributedDBValueHashCalcTest::TearDownTestCase(void) {}

void DistributedDBValueHashCalcTest::SetUp()
{
    ResetStubSwitches();
}

void DistributedDBValueHashCalcTest::TearDown()
{
    ResetStubSwitches();
}
} // namespace

/*
 * The functions below have the same signatures as the real crypto library.
 * By default every call is forwarded to the real implementation of the shared
 * library, so test cases that need the real crypto behaviour are not affected
 * even when all test files are linked into one executable. Only the switches
 * above turn a function into a failing one, which is used to cover the error
 * branches of ValueHashCalc.
 */
#ifdef USE_HITLS
extern "C" {
CRYPT_EAL_MdCTX *CRYPT_EAL_MdNewCtx(CRYPT_MD_AlgId id)
{
    if (g_stubMdNewCtxFail) {
        return nullptr;
    }
    using RealFunc = CRYPT_EAL_MdCTX *(*)(CRYPT_MD_AlgId);
    RealFunc realFunc = GetRealCryptoFunc<RealFunc>("CRYPT_EAL_MdNewCtx");
    if (realFunc != nullptr) {
        return realFunc(id);
    }
    // Fallback when the real library is not reachable: the context is opaque to
    // the product code, a non-null dummy is enough.
    return static_cast<CRYPT_EAL_MdCTX *>(std::malloc(sizeof(int)));
}

void CRYPT_EAL_MdFreeCtx(CRYPT_EAL_MdCTX *ctx)
{
    using RealFunc = void (*)(CRYPT_EAL_MdCTX *);
    RealFunc realFunc = GetRealCryptoFunc<RealFunc>("CRYPT_EAL_MdFreeCtx");
    if (realFunc != nullptr) {
        realFunc(ctx);
        return;
    }
    std::free(ctx); // only the dummy from the fallback above can reach here.
}

int32_t CRYPT_EAL_MdInit(CRYPT_EAL_MdCTX *ctx)
{
    if (g_stubMdInitFail) {
        return CRYPT_EAL_ERR_STATE;
    }
    using RealFunc = int32_t (*)(CRYPT_EAL_MdCTX *);
    RealFunc realFunc = GetRealCryptoFunc<RealFunc>("CRYPT_EAL_MdInit");
    if (realFunc != nullptr) {
        return realFunc(ctx);
    }
    return CRYPT_SUCCESS;
}

int32_t CRYPT_EAL_MdUpdate(CRYPT_EAL_MdCTX *ctx, const uint8_t *data, uint32_t len)
{
    if (g_stubMdUpdateFail) {
        return CRYPT_EAL_ERR_STATE;
    }
    using RealFunc = int32_t (*)(CRYPT_EAL_MdCTX *, const uint8_t *, uint32_t);
    RealFunc realFunc = GetRealCryptoFunc<RealFunc>("CRYPT_EAL_MdUpdate");
    if (realFunc != nullptr) {
        return realFunc(ctx, data, len);
    }
    return CRYPT_SUCCESS;
}

int32_t CRYPT_EAL_MdFinal(CRYPT_EAL_MdCTX *ctx, uint8_t *out, uint32_t *len)
{
    if (g_stubMdFinalFail) {
        return CRYPT_EAL_ERR_STATE;
    }
    using RealFunc = int32_t (*)(CRYPT_EAL_MdCTX *, uint8_t *, uint32_t *);
    RealFunc realFunc = GetRealCryptoFunc<RealFunc>("CRYPT_EAL_MdFinal");
    if (realFunc != nullptr) {
        return realFunc(ctx, out, len);
    }
    if (out != nullptr && len != nullptr && *len != 0) {
        for (uint32_t i = 0; i < *len; ++i) {
            out[i] = STUB_DIGEST_BYTE;
        }
    }
    return CRYPT_SUCCESS;
}

uint32_t CRYPT_EAL_MdGetDigestSize(CRYPT_MD_AlgId id)
{
    using RealFunc = uint32_t (*)(CRYPT_MD_AlgId);
    RealFunc realFunc = GetRealCryptoFunc<RealFunc>("CRYPT_EAL_MdGetDigestSize");
    if (realFunc != nullptr) {
        return realFunc(id);
    }
    return STUB_DIGEST_LENGTH;
}
}
#else
extern "C" {
int SHA256_Init(SHA256_CTX *ctx)
{
    if (g_stubMdInitFail) {
        return 0; // 0 means failure, same contract as the real interface.
    }
    using RealFunc = int (*)(SHA256_CTX *);
    RealFunc realFunc = GetRealCryptoFunc<RealFunc>("SHA256_Init");
    if (realFunc != nullptr) {
        return realFunc(ctx);
    }
    return 1;
}

int SHA256_Update(SHA256_CTX *ctx, const void *data, size_t len)
{
    if (g_stubMdUpdateFail) {
        return 0;
    }
    using RealFunc = int (*)(SHA256_CTX *, const void *, size_t);
    RealFunc realFunc = GetRealCryptoFunc<RealFunc>("SHA256_Update");
    if (realFunc != nullptr) {
        return realFunc(ctx, data, len);
    }
    return 1;
}

int SHA256_Final(unsigned char *md, SHA256_CTX *ctx)
{
    if (g_stubMdFinalFail) {
        return 0;
    }
    using RealFunc = int (*)(unsigned char *, SHA256_CTX *);
    RealFunc realFunc = GetRealCryptoFunc<RealFunc>("SHA256_Final");
    if (realFunc != nullptr) {
        return realFunc(md, ctx);
    }
    if (md != nullptr) {
        for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
            md[i] = STUB_DIGEST_BYTE;
        }
    }
    return 1;
}
}
#endif

namespace {
/**
 * @tc.name: ValueHashCalcStub001
 * @tc.desc: Test ValueHashCalc Update and GetResult return -E_CALC_HASH before Initialize
 * @tc.type: FUNC
 * @tc.author: ztx
 */
HWTEST_F(DistributedDBValueHashCalcTest, ValueHashCalcStub001, TestSize.Level0)
{
    ValueHashCalc hashCalc;
    const std::vector<uint8_t> input = {'a', 'b', 'c'};
    std::vector<uint8_t> digest;
    EXPECT_EQ(hashCalc.Update(input), -E_CALC_HASH);
    EXPECT_EQ(hashCalc.GetResult(digest), -E_CALC_HASH);
    EXPECT_TRUE(digest.empty());
}

/**
 * @tc.name: ValueHashCalcStub002
 * @tc.desc: Test ValueHashCalc Initialize returns -E_CALC_HASH when creating the digest context fails
 * @tc.type: FUNC
 * @tc.author: ztx
 */
HWTEST_F(DistributedDBValueHashCalcTest, ValueHashCalcStub002, TestSize.Level0)
{
#ifdef USE_HITLS
    g_stubMdNewCtxFail = true; // CRYPT_EAL_MdNewCtx returns nullptr.
#else
    g_stubMdInitFail = true; // SHA256_Init returns 0.
#endif
    ValueHashCalc hashCalc;
    EXPECT_EQ(hashCalc.Initialize(), -E_CALC_HASH);
    // After the failed Initialize, Update and GetResult must fail as well.
    const std::vector<uint8_t> input = {'a', 'b', 'c'};
    std::vector<uint8_t> digest;
    EXPECT_EQ(hashCalc.Update(input), -E_CALC_HASH);
    EXPECT_EQ(hashCalc.GetResult(digest), -E_CALC_HASH);
}

#ifdef USE_HITLS
/**
 * @tc.name: ValueHashCalcStub003
 * @tc.desc: Test ValueHashCalc Initialize returns -E_CALC_HASH when MdInit fails after MdNewCtx succeeds
 * @tc.type: FUNC
 * @tc.author: ztx
 */
HWTEST_F(DistributedDBValueHashCalcTest, ValueHashCalcStub003, TestSize.Level0)
{
    g_stubMdInitFail = true; // CRYPT_EAL_MdInit fails while CRYPT_EAL_MdNewCtx still succeeds.
    ValueHashCalc hashCalc;
    EXPECT_EQ(hashCalc.Initialize(), -E_CALC_HASH);
    const std::vector<uint8_t> input = {'a', 'b', 'c'};
    std::vector<uint8_t> digest;
    EXPECT_EQ(hashCalc.Update(input), -E_CALC_HASH);
    EXPECT_EQ(hashCalc.GetResult(digest), -E_CALC_HASH);
}
#endif

/**
 * @tc.name: ValueHashCalcStub004
 * @tc.desc: Test ValueHashCalc Update returns -E_CALC_HASH when the digest update fails
 * @tc.type: FUNC
 * @tc.author: ztx
 */
HWTEST_F(DistributedDBValueHashCalcTest, ValueHashCalcStub004, TestSize.Level0)
{
    g_stubMdUpdateFail = true;
    ValueHashCalc hashCalc;
    EXPECT_EQ(hashCalc.Initialize(), E_OK);
    const std::vector<uint8_t> input = {'a', 'b', 'c'};
    EXPECT_EQ(hashCalc.Update(input), -E_CALC_HASH);
}

/**
 * @tc.name: ValueHashCalcStub005
 * @tc.desc: Test ValueHashCalc GetResult returns -E_CALC_HASH when the digest final fails
 * @tc.type: FUNC
 * @tc.author: ztx
 */
HWTEST_F(DistributedDBValueHashCalcTest, ValueHashCalcStub005, TestSize.Level0)
{
    g_stubMdFinalFail = true;
    ValueHashCalc hashCalc;
    EXPECT_EQ(hashCalc.Initialize(), E_OK);
    const std::vector<uint8_t> input = {'a', 'b', 'c'};
    EXPECT_EQ(hashCalc.Update(input), E_OK);
    std::vector<uint8_t> digest;
    EXPECT_EQ(hashCalc.GetResult(digest), -E_CALC_HASH);
}

/**
 * @tc.name: ValueHashCalcStub006
 * @tc.desc: Test ValueHashCalc full flow succeeds and repeated Initialize fails with the transparent stubs
 * @tc.type: FUNC
 * @tc.author: ztx
 */
HWTEST_F(DistributedDBValueHashCalcTest, ValueHashCalcStub006, TestSize.Level0)
{
    ValueHashCalc hashCalc;
    EXPECT_EQ(hashCalc.Initialize(), E_OK);
    // The second Initialize must fail because the inner context already exists.
    EXPECT_EQ(hashCalc.Initialize(), -E_CALC_HASH);
    const std::vector<uint8_t> input = {'a', 'b', 'c'};
    EXPECT_EQ(hashCalc.Update(input), E_OK);
    std::vector<uint8_t> digest;
    EXPECT_EQ(hashCalc.GetResult(digest), E_OK);
    EXPECT_EQ(digest.size(), static_cast<size_t>(STUB_DIGEST_LENGTH));
}
} // namespace
