#pragma once

#include <iostream>
#include <fstream>
#include <string>
#include <filesystem>
#include <mutex>
#include <chrono>
#include <iomanip>
#include <boost/json.hpp>

namespace omnicore::utils
{
    enum class LogType
    {
        INFO,
        WARNING,
        ERROR,
        DEBUG
    };

    class Logger
    {
    public:
        static void Log(const std::string &message, LogType type = LogType::INFO)
        {
            std::lock_guard<std::mutex> lock(consoleMutex);
            
            std::string colorCode;
            std::string typeStr;

            switch (type)
            {
            case LogType::INFO:
                colorCode = "\033[32m"; // Green
                typeStr = "[INFO]";
                break;
            case LogType::WARNING:
                colorCode = "\033[33m"; // Yellow
                typeStr = "[WARNING]";
                break;
            case LogType::ERROR:
                colorCode = "\033[31m"; // Red
                typeStr = "[ERROR]";
                break;
            case LogType::DEBUG:
                colorCode = "\033[36m"; // Cyan
                typeStr = "[DEBUG]";
                break;
            }

            std::cout << colorCode << typeStr << " " << message << "\033[0m" << std::endl;
        }

        static std::string prettyPrintJson(const boost::json::value& jv, int indent = 0)
        {
            std::string result;
            std::string indentStr(indent * 2, ' ');
            std::string nextIndentStr((indent + 1) * 2, ' ');
            
            if (jv.is_object())
            {
                auto& obj = jv.get_object();
                result += "{\n";
                bool first = true;
                for (auto& kv : obj)
                {
                    if (!first) result += ",\n";
                    result += nextIndentStr + "\"" + std::string(kv.key()) + "\": ";
                    result += prettyPrintJson(kv.value(), indent + 1);
                    first = false;
                }
                result += "\n" + indentStr + "}";
            }
            else if (jv.is_array())
            {
                auto& arr = jv.get_array();
                result += "[\n";
                bool first = true;
                for (auto& item : arr)
                {
                    if (!first) result += ",\n";
                    result += nextIndentStr + prettyPrintJson(item, indent + 1);
                    first = false;
                }
                result += "\n" + indentStr + "]";
            }
            else if (jv.is_string())
            {
                result += "\"" + std::string(jv.get_string()) + "\"";
            }
            else if (jv.is_int64())
            {
                result += std::to_string(jv.get_int64());
            }
            else if (jv.is_uint64())
            {
                result += std::to_string(jv.get_uint64());
            }
            else if (jv.is_double())
            {
                result += std::to_string(jv.get_double());
            }
            else if (jv.is_bool())
            {
                result += jv.get_bool() ? "true" : "false";
            }
            else if (jv.is_null())
            {
                result += "null";
            }
            
            return result;
        }

        static void LogRequest(const std::string &traceId, const std::string &remoteIp, 
                              const std::string &method, const std::string &target,
                              const std::string &headers, const std::string &body)
        {
            try
            {
                std::filesystem::path logDir = "Errors";
                std::filesystem::path traceDir = logDir / traceId;

                try {
                    if (!std::filesystem::exists(logDir))
                    {
                        std::filesystem::create_directories(logDir);
                    }
                    if (!std::filesystem::exists(traceDir))
                    {
                        std::filesystem::create_directories(traceDir);
                    }
                } catch (const std::filesystem::filesystem_error& e) {
                    Log("Failed to create log directories: " + std::string(e.what()), LogType::ERROR);
                    return;
                }

                std::filesystem::path logFile = traceDir / "request.json";
                std::ofstream ofs(logFile, std::ios::app);
                
                if (ofs.is_open())
                {
                    auto now = std::chrono::system_clock::now();
                    auto in_time_t = std::chrono::system_clock::to_time_t(now);
                    
                    std::stringstream timestamp;
                    timestamp << std::put_time(std::localtime(&in_time_t), "%Y-%m-%d %X");

                    boost::json::object logEntry;
                    logEntry["timestamp"] = timestamp.str();
                    logEntry["traceId"] = traceId;
                    logEntry["remoteIp"] = remoteIp;
                    logEntry["method"] = method;
                    logEntry["target"] = target;
                    
                    try {
                        logEntry["headers"] = boost::json::parse(headers);
                    } catch (...) {
                        logEntry["headers"] = headers;
                    }
                    
                    try {
                        logEntry["body"] = boost::json::parse(body);
                    } catch (...) {
                        logEntry["body"] = body;
                    }
                    
                    ofs << prettyPrintJson(logEntry) << "\n";
                    ofs.close();
                }
                else
                {
                    Log("Failed to open log file for writing: " + logFile.string(), LogType::ERROR);
                }
            }
            catch (const std::exception &e)
            {
                Log("Failed to log request: " + std::string(e.what()), LogType::ERROR);
            }
        }

        static void LogError(const std::string &traceId, const std::string &errorMessage)
        {
            try
            {
                std::filesystem::path logDir = "Errors";
                std::filesystem::path traceDir = logDir / traceId;

                // Always ensure directories exist before writing
                try {
                    if (!std::filesystem::exists(logDir))
                    {
                        std::filesystem::create_directories(logDir);
                    }
                    if (!std::filesystem::exists(traceDir))
                    {
                        std::filesystem::create_directories(traceDir);
                    }
                } catch (const std::filesystem::filesystem_error& e) {
                    Log("Failed to create error log directories: " + std::string(e.what()), LogType::ERROR);
                    return;
                }

                std::filesystem::path errorFile = traceDir / "errors.txt";
                std::ofstream ofs(errorFile, std::ios::app);
                
                if (ofs.is_open())
                {
                    auto now = std::chrono::system_clock::now();
                    auto in_time_t = std::chrono::system_clock::to_time_t(now);

                    ofs << "Timestamp: " << std::put_time(std::localtime(&in_time_t), "%Y-%m-%d %X") << "\n";
                    ofs << "ERROR: " << errorMessage << "\n";
                    ofs << "--------------------------------------------------\n";
                    ofs.close();
                }
                else
                {
                    Log("Failed to open error log file for writing: " + errorFile.string(), LogType::ERROR);
                }
            }
            catch (const std::exception &e)
            {
                Log("Failed to log error: " + std::string(e.what()), LogType::ERROR);
            }
        }

    private:
        static inline std::mutex consoleMutex;
    };
}
