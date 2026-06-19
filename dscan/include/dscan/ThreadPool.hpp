#pragma once
#include <atomic>
#include <functional>
#include <thread>
#include <vector>
#include <algorithm>
#include "BoundedQueue.hpp"

namespace dscan {

// Simple worker pool that pulls FileTask paths off a shared bounded queue.
class ThreadPool {
public:
    using Job = std::function<void()>;

    explicit ThreadPool(unsigned n) {
        if (n == 0) n = std::max(1u, std::thread::hardware_concurrency());
        workers_.reserve(n);
    }

    template <typename Fn>
    void run(unsigned n, Fn worker_body) {
        for (unsigned i = 0; i < n; ++i)
            workers_.emplace_back(worker_body);
    }

    void join() {
        for (auto& t : workers_) if (t.joinable()) t.join();
        workers_.clear();
    }

private:
    std::vector<std::thread> workers_;
};

} // namespace dscan
