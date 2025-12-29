#pragma once

#include <condition_variable>
#include <cstddef>
#include <mutex>
#include <queue>
#include <thread>
#include <vector>
#include <functional>
#include <optional>

namespace replicapulse {

template <typename T>
class BoundedQueue {
public:
    explicit BoundedQueue(size_t capacity) : capacity_(capacity) {}

    bool push(const T &item) {
        std::unique_lock<std::mutex> lock(mutex_);
        cond_not_full_.wait(lock, [&] { return queue_.size() < capacity_ || stopped_; });
        if (stopped_) return false;
        queue_.push(item);
        cond_not_empty_.notify_one();
        return true;
    }

    bool push(T &&item) {
        std::unique_lock<std::mutex> lock(mutex_);
        cond_not_full_.wait(lock, [&] { return queue_.size() < capacity_ || stopped_; });
        if (stopped_) return false;
        queue_.push(std::move(item));
        cond_not_empty_.notify_one();
        return true;
    }

    bool pop(T &out) {
        std::unique_lock<std::mutex> lock(mutex_);
        cond_not_empty_.wait(lock, [&] { return !queue_.empty() || stopped_; });
        if (queue_.empty()) return false;
        out = std::move(queue_.front());
        queue_.pop();
        cond_not_full_.notify_one();
        return true;
    }

    void stop() {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            stopped_ = true;
        }
        cond_not_full_.notify_all();
        cond_not_empty_.notify_all();
    }

private:
    size_t capacity_;
    std::queue<T> queue_;
    bool stopped_{false};
    std::mutex mutex_;
    std::condition_variable cond_not_full_;
    std::condition_variable cond_not_empty_;
};

} // namespace replicapulse
