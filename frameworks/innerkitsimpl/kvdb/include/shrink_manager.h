#ifndef OHOS_DISTRIBUTED_DATA_FRAMEWORKS_KVDB_SHRINK_MANAGER_H
#define OHOS_DISTRIBUTED_DATA_FRAMEWORKS_KVDB_SHRINK_MANAGER_H

#include <atomic>
#include <functional>
#include <future>
#include <mutex>

namespace OHOS::DistributedKv {
class ShrinkManager {
public:
    using ShrinkCallback = std::function<void()>;

    explicit ShrinkManager(ShrinkCallback callback);
    ~ShrinkManager();

    void Enable();
    void Disable();
    void OnDelete();

private:
    void TryTriggerShrink();

    ShrinkCallback shrinkCallback_;
    std::atomic<bool> enabled_{ false };
    std::atomic<uint64_t> deleteCount_{ 0 };
    std::mutex taskMutex_;
    std::future<void> pendingTask_;
    std::atomic<bool> shrinkInProgress_{ false };

    static constexpr uint64_t SHRINK_THRESHOLD = 1000;
};
} // namespace OHOS::DistributedKv
#endif // OHOS_DISTRIBUTED_DATA_FRAMEWORKS_KVDB_SHRINK_MANAGER_H
