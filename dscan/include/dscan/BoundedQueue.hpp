#pragma once
#include <condition_variable>
#include <mutex>
#include <optional>
#include <queue>

namespace dscan {

template <typename T>
class BoundedQueue {
public:
    explicit BoundedQueue(size_t cap) : cap_(cap) {}

    void push(T v) {
        std::unique_lock lk(m_);
        notFull_.wait(lk, [&]{ return q_.size() < cap_ || closed_; });
        if (closed_) return;
        q_.push(std::move(v));
        notEmpty_.notify_one();
    }

    std::optional<T> pop() {
        std::unique_lock lk(m_);
        notEmpty_.wait(lk, [&]{ return !q_.empty() || closed_; });
        if (q_.empty()) return std::nullopt; // closed & drained
        T v = std::move(q_.front());
        q_.pop();
        notFull_.notify_one();
        return v;
    }

    void close() {
        std::lock_guard lk(m_);
        closed_ = true;
        notEmpty_.notify_all();
        notFull_.notify_all();
    }

private:
    size_t cap_;
    bool closed_ = false;
    std::queue<T> q_;
    std::mutex m_;
    std::condition_variable notEmpty_, notFull_;
};

} // namespace dscan
