/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef DISTRIBUTEDDB_TYPES_EXPORT_H
#define DISTRIBUTEDDB_TYPES_EXPORT_H

#include <climits>
#include <cstdint>
#include <functional>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace DistributedDB {
#ifdef _WIN32
    #ifdef DB_DLL_EXPORT
        #define DB_API __declspec(dllexport)
    #else
        #define DB_API
    #endif
#else
    #define DB_API __attribute__ ((visibility ("default")))
#endif

#define DB_SYMBOL DB_API

using Key = std::vector<uint8_t>;
using Value = std::vector<uint8_t>;

using AssetsMap = std::map<std::string, std::set<std::string>>;
using AssetsGroupMap = std::map<uint32_t, AssetsMap>;

struct Entry {
    Key key;
    Value value;
};

enum class CipherType {
    DEFAULT,
    AES_256_GCM, // AES-256-GCM
};

class CipherPassword final {
public:
    enum ErrorCode {
        OK = 0,
        OVERSIZE,
        INVALID_INPUT,
        SECUREC_ERROR,
    };

    DB_API CipherPassword();
    DB_API ~CipherPassword();

    DB_API bool operator==(const CipherPassword &input) const;
    DB_API bool operator!=(const CipherPassword &input) const;

    DB_API size_t GetSize() const;
    DB_API const uint8_t *GetData() const;
    DB_API int SetValue(const uint8_t *inputData, size_t inputSize);
    DB_API int Clear();

private:
    static const size_t MAX_PASSWORD_SIZE = 128;
    uint8_t data_[MAX_PASSWORD_SIZE] = {UCHAR_MAX};
    size_t size_ = 0;
};

using PragmaData = void *;

struct PragmaEntryDeviceIdentifier {
    Key key;
    bool origDevice = true;
    std::string deviceIdentifier;
};

struct PragmaDeviceIdentifier {
    std::string deviceID;
    std::string deviceIdentifier;
};

enum WipePolicy {
    RETAIN_STALE_DATA = 1, // remote stale data will be retained in syncing when remote db rebuiled.
    WIPE_STALE_DATA // remote stale data will be wiped when in syncing remote db rebuiled.
};

// We don't parse, read or modify the array type, so there are not a corresponding array value
// The leaf object is empty, an internal object always composed by other type values.
struct FieldValue {
    union {
        bool boolValue;
        int32_t integerValue;
        int64_t longValue = 0;
        double doubleValue;
    };
    std::string stringValue;
};

enum PermissionCheckFlag {
    CHECK_FLAG_SEND = 1, // send
    CHECK_FLAG_RECEIVE = 2, // receive
    CHECK_FLAG_AUTOSYNC = 4, // autosync flag
    CHECK_FLAG_SPONSOR = 8, // sync sponsor
};

struct PermissionCheckParam {
    std::string userId;
    std::string appId;
    std::string storeId;
    std::string deviceId;
    std::string subUserId;
    int32_t instanceId = 0;
    std::map<std::string, std::string> extraConditions;
};

struct PermissionCheckParamV4 {
    std::string userId;
    std::string appId;
    std::string storeId;
    std::string deviceId;
    std::string subUserId;
};

struct ActivationCheckParam {
    std::string userId;
    std::string appId;
    std::string storeId;
    std::string subUserId;
    int32_t instanceId = 0;
};

struct PermissionConditionParam {
    std::string userId;
    std::string appId;
    std::string storeId;
    std::string subUserId;
    int32_t instanceId = 0;
};

struct StoreStatusNotifierParam {
    std::string userId;
    std::string appId;
    std::string storeId;
    std::string subUserId;
    std::string deviceId;
};

using PermissionCheckCallback = std::function<bool (const std::string &userId, const std::string &appId,
    const std::string &storeId, uint8_t flag)>;

using PermissionCheckCallbackV2 = std::function<bool (const std::string &userId, const std::string &appId,
    const std::string &storeId, const std::string &deviceId, uint8_t flag)>;

using PermissionCheckCallbackV3 = std::function<bool (const PermissionCheckParam &param, uint8_t flag)>;

using PermissionCheckCallbackV4 = std::function<bool (const PermissionCheckParamV4 &param, uint8_t flag)>;

using StoreStatusNotifier = std::function<void (std::string userId, std::string appId, std::string storeId,
    const std::string deviceId, bool onlineStatus)>; // status, 1: online, 0: offline

using StoreStatusNotifierV2 = std::function<void (StoreStatusNotifierParam param,
    bool onlineStatus)>; // status, 1: online, 0: offline

using SyncActivationCheckCallback = std::function<bool (const std::string &userId, const std::string &appId,
    const std::string &storeId)>;

using SyncActivationCheckCallbackV2 = std::function<bool (const ActivationCheckParam &param)>;

using PermissionConditionCallback =
    std::function<std::map<std::string, std::string> (const PermissionConditionParam &param)>;

enum AutoLaunchStatus {
    WRITE_OPENED = 1,
    WRITE_CLOSED = 2,
    INVALID_PARAM = 3, // AutoLaunchRequestCallback, if param check failed
};

using AutoLaunchNotifier = std::function<void (const std::string &userId,
    const std::string &appId, const std::string &storeId, AutoLaunchStatus status)>;

enum SecurityLabel : int {
    INVALID_SEC_LABEL = -1,
    NOT_SET = 0,
    S0,
    S1,
    S2,
    S3,
    S4
};

// security flag type
enum SecurityFlag : int {
    INVALID_SEC_FLAG = -1,
    ECE = 0,
    SECE
};

struct SecurityOption {
    int securityLabel = 0; // the securityLabel is the class of data sensitive, see enum SecurityLabel
    int securityFlag = 0;  // the securityFlag is the encryption method of the file only used for S3 like 0:ECE, 1:SECE
    bool operator==(const SecurityOption &rhs) const
    {
        return securityLabel == rhs.securityLabel && securityFlag == rhs.securityFlag;
    }

    bool operator!=(const SecurityOption &rhs) const
    {
        return !(*this == rhs);
    }
};

enum class ResultSetCacheMode : int {
    CACHE_FULL_ENTRY = 0,       // Ordinary mode efficient when sequential access, the default mode
    CACHE_ENTRY_ID_ONLY = 1,    // Special mode efficient when random access
};

struct RemotePushNotifyInfo {
    std::string deviceId;
};
using RemotePushFinishedNotifier = std::function<void (const RemotePushNotifyInfo &info)>;
using RemotePushFinisheNotifier = RemotePushFinishedNotifier; // To correct spelling errors in the previous version

struct StoreInfo {
    std::string userId;
    std::string appId;
    std::string storeId;

    bool operator<(const StoreInfo &other) const
    {
        return std::tie(userId, appId, storeId) < std::tie(other.userId, other.appId, other.storeId);
    }
};
using TranslateToDeviceIdCallback = std::function<std::string (const std::string &oriDevId, const StoreInfo &info)>;

struct DeviceSyncNotifyInfo {
    std::string deviceId;
};

enum class DeviceSyncEvent : int {
    REMOTE_PULL_STARTED = 0
};
using DeviceSyncNotifier = std::function<void (const DeviceSyncNotifyInfo &info)>;
} // namespace DistributedDB
#endif // DISTRIBUTEDDB_TYPES_EXPORT_H
