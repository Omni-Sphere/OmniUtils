#pragma once

#include <string>
#include <queue>
#include <functional>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <atomic>

namespace omnisphere::utils
{
    /// Dedicated thread & task queue per domain.
    /// Guarantees strict execution isolation so tasks in one domain (e.g., Meta/WhatsApp)
    /// do not block or interfere with tasks in another domain (e.g., Stripe, DB).
    class DomainTaskDispatcher
    {
    public:
        explicit DomainTaskDispatcher(std::string domainName = "DomainWorkerThread");
        ~DomainTaskDispatcher();

        DomainTaskDispatcher(const DomainTaskDispatcher&) = delete;
        DomainTaskDispatcher& operator=(const DomainTaskDispatcher&) = delete;

        /// Enqueue a task to be processed asynchronously by this domain's dedicated thread.
        void Enqueue(std::function<void()> task);

        /// Returns current number of pending tasks in the queue.
        size_t PendingTasks() const;

        /// Name of this domain dispatcher.
        const std::string& DomainName() const noexcept { return m_domainName; }

        /// Stop accepting new tasks and wait for worker thread to complete remaining tasks.
        void Shutdown();

    private:
        void WorkerLoop();

        std::string m_domainName;
        std::queue<std::function<void()>> m_tasks;
        mutable std::mutex m_mutex;
        std::condition_variable m_cv;
        std::atomic<bool> m_stopping{false};
        std::thread m_workerThread;
    };
} // namespace omnisphere::utils
