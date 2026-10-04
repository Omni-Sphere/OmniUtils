#pragma once

#include <iostream>
#include <fstream>
#include <string>
#include <filesystem>
#include <mutex>
#include <chrono>
#include <iomanip>
#include <boost/json.hpp>
#include <atomic>
#include <memory>

namespace omnisphere::net
{
    class Request;
    class Response;
}

namespace omnisphere::utils
{
    enum class LogType
    {
        DEBUG,
        INFO,
        WARNING,
        ERROR
    };

    std::ostream& operator<<(std::ostream& strm, LogType level);

    struct RequestContext
    {
        std::string requestId;
        std::string clientIp;
        std::string userCode;
        std::string clientId;
    };

    /**
     * @brief RAII scope that sets the thread-local RequestContext on construction
     * and automatically restores the previous context on destruction.
     */
    class RequestContextScope
    {
    public:
        RequestContextScope(std::string reqId, std::string clientIp, std::string user = "", std::string client = "");
        ~RequestContextScope();

        RequestContextScope(const RequestContextScope&) = delete;
        RequestContextScope& operator=(const RequestContextScope&) = delete;

    private:
        RequestContext m_prevContext;
    };

    class Logger
    {
    private:
        static std::atomic<bool> s_extendedLogEnabled;

    public:
        static constexpr long long SLOW_SQL_THRESHOLD_MS = 100;
        static constexpr long long SLOW_HTTP_THRESHOLD_MS = 250;

        /**
        * @brief Set whether extended logging (SQL/GraphQL queries) is enabled.
        */
        static void SetExtendedLog(bool enabled);

        /**
        * @brief Check if extended logging is enabled.
        */
        static bool IsExtendedLogEnabled();

        /**
        * @brief Initialize the logging system and base directories.
        */
        static void Init();

        /**
        * @brief Thread-local context management
        */
        static void SetCurrentContext(const RequestContext& ctx);
        static RequestContext GetCurrentContext();
        static void ClearCurrentContext();

        /**
        * @brief Log a system event from a specific class.
        * File: Logs/<IP>/system_YYYYMMDDHH.log (or Logs/server/)
        * Console: High-contrast status line.
        */
        static void LogSystem(LogType type, const std::string& className, const std::string& message);

        /**
        * @brief Convenience helpers
        */
        static void LogInfo(const std::string& className, const std::string& message);
        static void LogWarning(const std::string& className, const std::string& message);
        static void LogError(const std::string& className, const std::string& message);
        static void LogDebug(const std::string& className, const std::string& message);

        /**
        * @brief Log incoming HTTP Request (detailed to Logs/<IP>/net_YYYYMMDDHH.log; no console spam).
        */
        static void LogHttpRequest(const omnisphere::net::Request& req);

        /**
        * @brief Log completed HTTP Response (detailed to Logs/<IP>/net_YYYYMMDDHH.log; concise live line on console with SLOW/ERROR alerts).
        */
        static void LogHttpResponse(const omnisphere::net::Request& req, const omnisphere::net::Response& resp, long long durationMs);

        /**
        * @brief Log an SQL query.
        * File: Logs/<IP>/sql_YYYYMMDDHH.log (or Logs/server/)
        * Console: Only alert if durationMs >= SLOW_SQL_THRESHOLD_MS (100ms) or on error. Fast queries are omitted from console.
        */
        static void LogSQL(const std::string& dbEngine, const std::string& message, long long durationMs = -1);

        /**
        * @brief Log a GraphQL transaction (detailed to Logs/<IP>/system_YYYYMMDDHH.log; errors highlighted on console).
        */
        static void LogGraphQL(const std::string& endpoint, const std::string& request, const std::string& response);

        /**
        * @brief Get the current stack trace as a string.
        */
        static std::string GetStackTrace();

        /**
        * @brief Log the current stack trace.
        */
        static void LogTrace(const std::string& className, const std::string& message = "Stack Trace");

        /**
        * @brief Utility for JSON formatting
        */
        static std::string prettyPrintJson(const boost::json::value& jv, int indent = 0);
    };
}
