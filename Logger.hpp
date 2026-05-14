#pragma once

#include <iostream>
#include <fstream>
#include <string>
#include <filesystem>
#include <mutex>
#include <chrono>
#include <iomanip>
#include <boost/json.hpp>

namespace omnisphere::utils
{
    enum class LogType
    {
        DEBUG,
        INFO,
        WARNING,
        ERROR
    };

    class Logger
    {
    public:
        /**
         * @brief Initialize the logging system.
         * Sets up hourly rotation (YYYYMMDDHH.log) in the Logs/ directory.
         */
        static void Init();

        /**
         * @brief Log a system event from a specific class.
         * Format: [Timestamp] [SYSTEM] [ClassName] Message
         */
        static void LogSystem(LogType type, const std::string& className, const std::string& message);

        /**
         * @brief Log a debug message.
         * Format: [Timestamp] [DEBUG] [ClassName] Message
         */
        static void LogDebug(const std::string& className, const std::string& message);

        /**
         * @brief Log a GraphQL transaction.
         * Format: [Timestamp] [GRAPHQL] [Endpoint] Request/Response details
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
