#define LOG_TAG "ShrinkManager"
#include "shrink_manager.h"

#include "log_print.h"

namespace OHOS::DistributedKv {
ShrinkManager::ShrinkManager(ShrinkCallback callback) : shrinkCallback_(std::move(callback)) {}

ShrinkManager::~ShrinkManager()
{
    Disable();
}

void ShrinkManager::Enable()
{
    enabled_.store(true);
    deleteCount_.store(0);
}

void ShrinkManager::Disable()
{
    enabled_.store(false);
    std::lock_guard<std::mutex> lock(taskMutex_);
    deleteCount_.store(0);
}

void ShrinkManager::OnDelete()
{
    if (!enabled_.load()) {
        return;
    }
    deleteCount_.fetch_add(1);
    TryTriggerShrink();
}

void ShrinkManager::TryTriggerShrink()
{
    if (deleteCount_.load() < SHRINK_THRESHOLD) {
        return;
    }
    bool expected = false;
    if (!shrinkInProgress_.compare_exchange_strong(expected, true)) {
        return;
    }
    auto callback = shrinkCallback_;
    std::lock_guard<std::mutex> lock(taskMutex_);
    pendingTask_ = std::async(std::launch::async, [this, callback]() {
        if (!enabled_.load()) {
            return;
        }
        if (callback) {
            callback();
        }
        deleteCount_.store(0);
        shrinkInProgress_.store(false);
    });
}
} // namespace OHOS::DistributedKv
