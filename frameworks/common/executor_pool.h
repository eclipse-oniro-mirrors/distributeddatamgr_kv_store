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

#ifndef OHOS_DISTRIBUTED_DATA_KV_STORE_FRAMEWORKS_COMMON_EXECUTOR_POOL_H
#define OHOS_DISTRIBUTED_DATA_KV_STORE_FRAMEWORKS_COMMON_EXECUTOR_POOL_H
#include <atomic>
#include <condition_variable>
#include <mutex>
#include <queue>
#include <set>
#include <thread>

#include "pool.h"
#include "priority_queue.h"
namespace OHOS {
class ExecutorPool {
public:
    using TaskId = uint64_t;
    using Task = std::function<void()>;
    using Duration = std::chrono::steady_clock::duration;
    using Time = std::chrono::steady_clock::time_point;
    static constexpr Time INVALID_TIME = std::chrono::time_point<std::chrono::steady_clock, std::chrono::seconds>();
    static constexpr Duration INVALID_INTERVAL = std::chrono::milliseconds(0);
    static constexpr uint64_t UNLIMITED_TIMES = std::numeric_limits<uint64_t>::max();
    static constexpr Duration INVALID_DELAY = std::chrono::seconds(0);
    static constexpr TaskId START_TASK_ID = static_cast<uint64_t>(1l);
    static constexpr TaskId INVALID_TASK_ID = static_cast<uint64_t>(0l);
    ExecutorPool(size_t max, size_t min)
    {
        pool_ = new (std::nothrow) Pool<Executor>(max, min);
        execs_ = std::make_shared<PriorityQueue<InnerTask, Time, TaskId>>();
        delayTasks_ = std::make_shared<PriorityQueue<InnerTask, Time, TaskId>>();
    }
    ~ExecutorPool()
    {
        poolStatus = IS_STOPPING;
        execs_->Clean();
        delayTasks_->Clean();
        if (scheduler_ != nullptr) {
            scheduler_->Stop(true);
        }

        pool_->Clean([](std::shared_ptr<Executor> executor) {
            executor->Stop(true);
        });
        poolStatus = STOPPED;
    }

    TaskId Execute(Task task)
    {
        if (poolStatus != RUNNING) {
            return INVALID_TASK_ID;
        }
        return Execute(std::move(task), GenTaskId());
    }

    TaskId Execute(Task task, Duration delay)
    {
        return Schedule(std::move(task), delay, INVALID_INTERVAL, 1);
    }

    TaskId Schedule(Task task, Duration interval)
    {
        return Schedule(std::move(task), INVALID_DELAY, interval, UNLIMITED_TIMES);
    }

    TaskId Schedule(Task task, Duration delay, Duration interval)
    {
        return Schedule(std::move(task), delay, interval, UNLIMITED_TIMES);
    }

    TaskId Schedule(Task task, Duration delay, Duration interval, uint64_t times)
    {
        InnerTask innerTask;
        innerTask.managed = std::move(task);
        innerTask.startTime = std::chrono::steady_clock::now() + delay;
        innerTask.interval = interval;
        innerTask.times = times;
        innerTask.taskId = GenTaskId();
        return Schedule(std::move(innerTask));
    }

    bool Remove(TaskId taskId, bool wait = false)
    {
        std::unique_lock<decltype(mtx_)> lock(mtx_);
        bool res = true;
        if (scheduler_->IsRunningTask(taskId)) {
            res = false;
            delCon_.wait(lock, [this, taskId, wait] {
                return !scheduler_->IsRunningTask(taskId);
            });
        }
        delayTasks_->Remove(taskId);
        execs_->Remove(taskId);
        if (res) {
            return true;
        }
        if (runningSet_.find(taskId) != runningSet_.end()) {
            delCon_.wait(lock, [this, taskId, wait] {
                return (!wait || runningSet_.find(taskId) == runningSet_.end());
            });
            return false;
        }
        return true;
    }

    TaskId Reset(TaskId taskId, Duration interval)
    {
        return Reset(taskId, INVALID_DELAY, interval);
    }

    TaskId Reset(TaskId taskId, Duration delay, Duration interval)
    {
        InnerTask innerTask;
        {
            std::lock_guard<decltype(mtx_)> lock(mtx_);
            innerTask = delayTasks_->Find(taskId);
            if (!innerTask.Valid()) {
                return INVALID_TASK_ID;
            }
            if (!delayTasks_->Remove(taskId)) {
                return INVALID_TASK_ID;
            }
            innerTask.startTime = std::chrono::steady_clock::now() + delay;
            innerTask.interval = interval;
        }
        Schedule(innerTask);
        return taskId;
    }

private:
    enum Status {
        RUNNING,
        IS_STOPPING,
        STOPPED
    };
    struct InnerTask {
        Task managed = [] {};
        std::function<void(InnerTask &)> exec = [this](InnerTask innerTask = InnerTask(INVALID_TASK_ID)) {
            innerTask.managed();
        };
        Duration interval = INVALID_INTERVAL;
        uint64_t times = UNLIMITED_TIMES;
        TaskId taskId = INVALID_TASK_ID;
        Time startTime = INVALID_TIME;
        InnerTask() = default;

        explicit InnerTask(TaskId id) : taskId(id)
        {
            managed = [] {};
        }

        bool Valid() const
        {
            return taskId != INVALID_TASK_ID;
        }

        TaskId GetId()
        {
            return this->taskId;
        }
    };
    class Executor : public std::enable_shared_from_this<Executor> {
    public:
        void Start()
        {
            thisPtr_ = shared_from_this();
            thread_ = std::thread([this] {
                Run();
            });
        }
        void Bind(std::shared_ptr<PriorityQueue<InnerTask, Time, TaskId>> &queue,
            std::function<void(std::shared_ptr<Executor>)> idle,
            std::function<bool(std::shared_ptr<Executor>, bool)> release, InnerTask &innerTask)
        {
            std::unique_lock<decltype(mutex_)> lock(mutex_);
            waits_ = queue;
            idle_ = std::move(idle);
            release_ = std::move(release);
            currentTask_ = innerTask;
            condition_.notify_one();
        }

        void Stop(bool wait = false)
        {
            {
                std::unique_lock<decltype(mutex_)> lock(mutex_);
                running_ = IS_STOPPING;
                condition_.notify_one();
            }
            if (wait) {
                thread_.join();
            }
        }
        void SetTask(InnerTask &innerTask)
        {
            std::unique_lock<decltype(mutex_)> lock(mutex_);
            currentTask_ = innerTask;
        }

        bool IsRunningTask(TaskId taskId)
        {
            return taskId == currentTask_.taskId;
        }

    private:
        static constexpr Duration TIME_OUT = std::chrono::seconds(2);
        void Run()
        {
            std::unique_lock<decltype(mutex_)> lock(mutex_);
            bool forceStop = false;
            do {
                do {
                    condition_.wait(lock, [this] {
                        return running_ == IS_STOPPING || (waits_ != nullptr && currentTask_.Valid());
                    });
                    InnerTask innerTask = currentTask_;
                    while (running_ == RUNNING && innerTask.Valid()) {
                        lock.unlock();
                        innerTask.exec(innerTask);
                        lock.lock();
                        currentTask_ = waits_->Pop();
                        innerTask = currentTask_;
                    }
                    waits_ = nullptr;
                    idle_(thisPtr_);
                } while (running_ == RUNNING &&
                         condition_.wait_until(lock, std::chrono::steady_clock::now() + TIME_OUT, [this]() {
                             return (currentTask_.Valid());
                         }));
                forceStop = running_ != RUNNING;
            } while (!release_(thisPtr_, forceStop));
            running_ = STOPPED;
        }

        Status running_ = RUNNING;
        std::mutex mutex_;
        std::shared_ptr<PriorityQueue<InnerTask, Time, TaskId>> waits_;
        InnerTask currentTask_ = InnerTask();
        std::thread thread_;
        std::shared_ptr<Executor> thisPtr_;
        std::condition_variable condition_;
        std::function<void(std::shared_ptr<Executor>)> idle_;
        std::function<bool(std::shared_ptr<Executor>, bool)> release_;
    };

    TaskId Execute(Task task, TaskId taskId)
    {
        auto run = [this](InnerTask &innerTask) {
            innerTask.managed();
            std::unique_lock<decltype(mtx_)> lock(mtx_);
            runningSet_.erase(innerTask.taskId);
            delCon_.notify_all();
        };
        InnerTask innerTask;
        innerTask.managed = task;
        innerTask.taskId = taskId;
        innerTask.exec = run;
        auto executor = pool_->Get();
        if (executor == nullptr) {
            execs_->Push(innerTask);
            return innerTask.taskId;
        }
        runningSet_.insert(innerTask.taskId);
        executor->Bind(
            execs_,
            [this](std::shared_ptr<Executor> exe) {
                return pool_->Idle(exe);
            },
            [this](std::shared_ptr<Executor> exe, bool force) -> bool {
                return pool_->Release(exe, force);
            },
            innerTask);
        return innerTask.taskId;
    }

    TaskId Schedule(InnerTask innerTask)
    {
        auto run = [this](InnerTask &task) {
            if (task.interval != INVALID_INTERVAL && --task.times > 0) {
                task.startTime = std::chrono::steady_clock::now() + task.interval;
                delayTasks_->Push(task);
            }
            {
                std::lock_guard<decltype(mtx_)> lock(mtx_);
                Execute(task.managed, task.taskId);
                scheduler_->SetTask(startTask);
                delCon_.notify_all();
            }
        };
        innerTask.exec = run;
        delayTasks_->Push(innerTask);
        std::lock_guard<decltype(mtx_)> scheduleLock(mtx_);
        if (scheduler_ == nullptr) {
            scheduler_ = pool_->Get(true);
            scheduler_->Bind(
                delayTasks_,
                [this](std::shared_ptr<Executor> exe) {
                    std::unique_lock<decltype(mtx_)> lock(mtx_);
                    scheduler_ = nullptr;
                    pool_->Idle(exe);
                },
                [this](std::shared_ptr<Executor> exe, bool force) -> bool {
                    return pool_->Release(exe, force);
                },
                startTask);
        }
        return innerTask.taskId;
    }

    TaskId GenTaskId()
    {
        auto taskId = ++taskId_;
        while (taskId == INVALID_TASK_ID || taskId == START_TASK_ID) {
            ++taskId_;
        }
        return taskId;
    }

    Status poolStatus = RUNNING;
    std::mutex mtx_;
    std::condition_variable delCon_;
    Pool<Executor> *pool_;
    InnerTask startTask = InnerTask(START_TASK_ID);
    std::shared_ptr<Executor> scheduler_ = nullptr;
    std::set<TaskId> runningSet_;
    std::shared_ptr<PriorityQueue<InnerTask, Time, TaskId>> execs_;
    std::shared_ptr<PriorityQueue<InnerTask, Time, TaskId>> delayTasks_;
    std::atomic<TaskId> taskId_ = START_TASK_ID;
};
} // namespace OHOS

#endif // OHOS_DISTRIBUTED_DATA_KV_STORE_FRAMEWORKS_COMMON_EXECUTOR_POOL_H
