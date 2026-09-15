#include "DomainTaskDispatcher.hpp"
#include "Logger.hpp"
#include <iostream>

namespace omnisphere::utils
{
    DomainTaskDispatcher::DomainTaskDispatcher(std::string domainName)
        : m_domainName(std::move(domainName))
    {
        Logger::LogInfo("DomainTaskDispatcher", "Starting dedicated worker thread for domain [" + m_domainName + "]");
        m_workerThread = std::thread(&DomainTaskDispatcher::WorkerLoop, this);
    }

    DomainTaskDispatcher::~DomainTaskDispatcher()
    {
        Shutdown();
    }

    void DomainTaskDispatcher::Enqueue(std::function<void()> task)
    {
        if (!task) return;

        {
            std::lock_guard<std::mutex> lock(m_mutex);
            if (m_stopping)
            {
                Logger::LogWarning("DomainTaskDispatcher", "[" + m_domainName + "] Cannot enqueue task: Dispatcher is shutting down.");
                return;
            }
            m_tasks.push(std::move(task));
        }

        m_cv.notify_one();
    }

    size_t DomainTaskDispatcher::PendingTasks() const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_tasks.size();
    }

    void DomainTaskDispatcher::Shutdown()
    {
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            if (m_stopping) return;
            m_stopping = true;
        }

        m_cv.notify_all();

        if (m_workerThread.joinable())
        {
            Logger::LogInfo("DomainTaskDispatcher", "Shutting down dedicated worker thread [" + m_domainName + "]...");
            m_workerThread.join();
            Logger::LogInfo("DomainTaskDispatcher", "Dedicated worker thread [" + m_domainName + "] terminated cleanly.");
        }
    }

    void DomainTaskDispatcher::WorkerLoop()
    {
        while (true)
        {
            std::function<void()> task;

            {
                std::unique_lock<std::mutex> lock(m_mutex);
                m_cv.wait(lock, [this] {
                    return m_stopping || !m_tasks.empty();
                });

                if (m_stopping && m_tasks.empty())
                {
                    break;
                }

                if (!m_tasks.empty())
                {
                    task = std::move(m_tasks.front());
                    m_tasks.pop();
                }
            }

            if (task)
            {
                try
                {
                    task();
                }
                catch (const std::exception& ex)
                {
                    Logger::LogError("DomainTaskDispatcher", "[" + m_domainName + "] Exception during task execution: " + std::string(ex.what()));
                    std::cerr << "[DomainTaskDispatcher Error - " << m_domainName << "] " << ex.what() << std::endl;
                }
                catch (...)
                {
                    Logger::LogError("DomainTaskDispatcher", "[" + m_domainName + "] Unknown exception occurred during task execution.");
                    std::cerr << "[DomainTaskDispatcher Error - " << m_domainName << "] Unknown exception" << std::endl;
                }
            }
        }
    }
} // namespace omnisphere::utils
