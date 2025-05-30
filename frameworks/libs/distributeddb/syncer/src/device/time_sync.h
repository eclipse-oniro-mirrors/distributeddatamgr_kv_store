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

#ifndef TIME_SYNC_H
#define TIME_SYNC_H

#include "icommunicator.h"
#include "meta_data.h"
#include "sync_task_context.h"
#include "time_helper.h"

namespace DistributedDB {
class TimeSyncPacket {
public:
    TimeSyncPacket();
    ~TimeSyncPacket();

    void SetSourceTimeBegin(Timestamp sourceTimeBegin);

    Timestamp GetSourceTimeBegin() const;

    void SetSourceTimeEnd(Timestamp sourceTimeEnd);

    Timestamp GetSourceTimeEnd() const;

    void SetTargetTimeBegin(Timestamp targetTimeBegin);

    Timestamp GetTargetTimeBegin() const;

    void SetTargetTimeEnd(Timestamp targetTimeEnd);

    Timestamp GetTargetTimeEnd() const;

    void SetVersion(uint32_t version);

    uint32_t GetVersion() const;

    void SetRequestLocalOffset(TimeOffset offset);

    TimeOffset GetRequestLocalOffset() const;

    void SetResponseLocalOffset(TimeOffset offset);

    TimeOffset GetResponseLocalOffset() const;

    static uint32_t CalculateLen();
private:
    Timestamp sourceTimeBegin_;  // start point time on peer
    Timestamp sourceTimeEnd_;    // end point time on local
    Timestamp targetTimeBegin_;  // start point time on peer
    Timestamp targetTimeEnd_;    // end point time on peer
    uint32_t version_;
    TimeOffset requestLocalOffset_; // local system time offset in request device
    TimeOffset responseLocalOffset_; // local system time offset in response device
};

class TimeSync : public std::enable_shared_from_this<TimeSync> {
public:
    TimeSync();
    virtual ~TimeSync();

    DISABLE_COPY_ASSIGN_MOVE(TimeSync);

    static int RegisterTransformFunc();

    static uint32_t CalculateLen(const Message *inMsg);

    static int Serialization(uint8_t *buffer, uint32_t length, const Message *inMsg); // register to communicator

    static int DeSerialization(const uint8_t *buffer, uint32_t length, Message *inMsg); // register to communicator

    int Initialize(ICommunicator *communicator, const std::shared_ptr<Metadata> &metadata,
        const ISyncInterface *storage, const DeviceID &deviceId, const DeviceID &userId);

    virtual int SyncStart(const CommErrHandler &handler = nullptr, uint32_t sessionId = 0); // send timesync request

    int AckRecv(const Message *message, uint32_t targetSessionId = 0);

    int RequestRecv(const Message *message);

    // Get timeoffset from metadata
    int GetTimeOffset(TimeOffset &outOffset, uint32_t timeout, uint32_t sessionId = 0);

    bool IsNeedSync() const;

    void SetOnline(bool isOnline);

    void Close();

    TimeSyncPacket BuildAckPacket(const TimeSyncPacket &request);

    void SetTimeSyncFinishIfNeed();

    void ClearTimeSyncFinish();

    int GenerateTimeOffsetIfNeed(TimeOffset systemOffset, TimeOffset senderLocalOffset);

    bool IsRemoteLowVersion(uint32_t checkVersion);

    // Used in send msg, as execution is asynchronous, should use this function to handle result.
    static void CommErrHandlerFunc(int errCode, TimeSync *timeSync);

protected:
    static const int MAX_RETRY_TIME = 1;

    static std::pair<TimeOffset, TimeOffset> CalculateTimeOffset(const TimeSyncPacket &timeSyncInfo);

    static bool IsPacketValid(const Message *inMsg, uint16_t messageType);

    void Finalize();

    int SaveTimeOffset(const DeviceID &deviceID, const DeviceID &userId, TimeOffset timeOffset);

    int SendPacket(const DeviceID &deviceId, const Message *message, const CommErrHandler &handler = nullptr);

    int TimeSyncDriver(TimerId timerId);

    void ResetTimer();

    bool IsClosed() const;

    int SendMessageWithSendEnd(const Message *message, const CommErrHandler &handler);

    Timestamp GetSourceBeginTime(Timestamp packetBeginTime, uint32_t sessionId);

    void ReTimeSyncIfNeed(const TimeSyncPacket &ackPacket);

    bool CheckReTimeSyncIfNeedWithLowVersion(TimeOffset timeOffsetIgnoreRtt);

    bool CheckReTimeSyncIfNeedWithHighVersion(TimeOffset timeOffsetIgnoreRtt, const TimeSyncPacket &ackPacket);

    int SaveOffsetWithAck(const TimeSyncPacket &ackPacket);

    bool CheckSkipTimeSync(const DeviceTimeInfo &info);

    void SetTimeSyncFinishInner(bool finish);

    static TimeOffset CalculateRawTimeOffset(const TimeSyncPacket &timeSyncInfo, TimeOffset deltaTime);

    ICommunicator *communicateHandle_;
    std::shared_ptr<Metadata> metadata_;
    std::unique_ptr<TimeHelper> timeHelper_;
    DeviceID deviceId_;
    DeviceID userId_;
    int retryTime_;
    TimerId driverTimerId_;
    TimerAction driverCallback_;
    bool isSynced_;
    bool isAckReceived_;
    std::condition_variable conditionVar_;
    mutable std::mutex cvLock_;
    NotificationChain::Listener *timeChangedListener_;
    std::condition_variable timeDriverCond_;
    std::mutex timeDriverLock_;
    int timeDriverLockCount_;
    bool isOnline_;
    bool closed_;
    std::mutex beginTimeMutex_;
    std::map<uint32_t, Timestamp> sessionBeginTime_;
    std::vector<uint8_t> dbId_;
    static std::mutex timeSyncSetLock_;
    static std::set<TimeSync *> timeSyncSet_;
};
} // namespace DistributedDB

#endif // TIME_SYNC_H
