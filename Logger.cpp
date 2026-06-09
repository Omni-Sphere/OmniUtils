#define BOOST_STACKTRACE_GNU_SOURCE_NOT_REQUIRED
#include "Logger.hpp"
#include <boost/stacktrace.hpp>
#include <boost/log/attributes.hpp>
#include <boost/log/core.hpp>
#include <boost/log/expressions.hpp>
#include <boost/log/sinks/text_file_backend.hpp>
#include <boost/log/sources/severity_channel_logger.hpp>
#include <boost/log/support/date_time.hpp>
#include <boost/log/utility/manipulators/add_value.hpp>
#include <boost/log/utility/setup/common_attributes.hpp>
#include <boost/log/utility/setup/console.hpp>
#include <boost/log/utility/setup/file.hpp>
#include <filesystem>
#include <iostream>

namespace logging = boost::log;
namespace src = boost::log::sources;
namespace sinks = boost::log::sinks;
namespace expr = boost::log::expressions;
namespace keywords = boost::log::keywords;
namespace attrs = boost::log::attributes;

namespace omnisphere::utils
{
    // Define global attributes
    BOOST_LOG_ATTRIBUTE_KEYWORD(severity, "Severity", LogType)
    BOOST_LOG_ATTRIBUTE_KEYWORD(channel, "Channel", std::string)
    BOOST_LOG_ATTRIBUTE_KEYWORD(origin, "Origin", std::string)

    void Logger::Init()
    {
        try
        {
            // Ensure Logs directory exists
            std::filesystem::path logDir = "Logs";

            if (!std::filesystem::exists(logDir))
            {
                std::filesystem::create_directories(logDir);
            }

            // Set up common attributes (timestamp, etc.)
            logging::add_common_attributes();
            logging::core::get()->add_global_attribute("Scope", attrs::named_scope());

            // --- SYSTEM LOG SINK ---
            auto systemSink = logging::add_file_log(
                keywords::file_name = "Logs/System_%Y%m%d%H.log",
                keywords::open_mode = std::ios_base::app | std::ios_base::out,
                keywords::time_based_rotation =
                sinks::file::rotation_at_time_interval(boost::posix_time::hours(1)),
                keywords::auto_flush = true);
            systemSink->set_filter(channel == "SYSTEM");
            systemSink->set_formatter(expr::format("%1% %2% %3%") %
                                      expr::format_date_time<boost::posix_time::ptime>(
                                          "TimeStamp", "%Y-%m-%d %H:%M:%S.%f") %
                                      origin % expr::smessage);

            // --- DEBUG LOG SINK ---
            auto debugSink = logging::add_file_log(
                keywords::file_name = "Logs/Debug_%Y%m%d%H.log",
                keywords::open_mode = std::ios_base::app | std::ios_base::out,
                keywords::time_based_rotation =
                sinks::file::rotation_at_time_interval(boost::posix_time::hours(1)),
                keywords::auto_flush = true);
            debugSink->set_filter(channel == "DEBUG");
            debugSink->set_formatter(expr::format("%1% %2% %3%") %
                                     expr::format_date_time<boost::posix_time::ptime>(
                                         "TimeStamp", "%Y-%m-%d %H:%M:%S.%f") %
                                     origin % expr::smessage);

            // --- GRAPHQL LOG SINK ---
            auto gqlSink = logging::add_file_log(
                keywords::file_name = "Logs/GraphQL_%Y%m%d%H.log",
                keywords::open_mode = std::ios_base::app | std::ios_base::out,
                keywords::time_based_rotation =
                sinks::file::rotation_at_time_interval(boost::posix_time::hours(1)),
                keywords::auto_flush = true);
            gqlSink->set_filter(channel == "GRAPHQL");
            gqlSink->set_formatter(expr::format("%1% %2%") %
                                   expr::format_date_time<boost::posix_time::ptime>(
                                       "TimeStamp", "%Y-%m-%d %H:%M:%S.%f") %
                                   expr::smessage);

            // --- CONSOLE SINK (for development) ---
            auto consoleSink = logging::add_console_log(std::clog);
            consoleSink->set_formatter(expr::format("%1% %2% %3%") %
                                       expr::format_date_time<boost::posix_time::ptime>(
                                           "TimeStamp", "%H:%M:%S") %
                                       origin % expr::smessage);

            logging::core::get()->set_filter(severity >= LogType::DEBUG);
            std::cout << "[Logger] Advanced multi-channel logging system active. "
            "Directory: Logs/"
            << std::endl;
        }
        catch (const std::exception &e)
        {
            std::cerr << "CRITICAL: Failed to initialize Logger: " << e.what()
            << std::endl;
        }
    }

    void Logger::LogSystem(LogType type, const std::string &className,
                           const std::string &message)
    {
        src::severity_channel_logger_mt<LogType, std::string> logger(
            keywords::channel = "SYSTEM");
        BOOST_LOG_SEV(logger, type)
        << logging::add_value("Origin", className) << message;
    }

    void Logger::LogDebug(const std::string &className, const std::string &message)
    {
        src::severity_channel_logger_mt<LogType, std::string> logger(
            keywords::channel = "DEBUG");
        BOOST_LOG_SEV(logger, LogType::DEBUG)
        << logging::add_value("Origin", className) << message;
    }

    void Logger::LogGraphQL(const std::string &endpoint, const std::string &request,
                            const std::string &response)
    {
        src::severity_channel_logger_mt<LogType, std::string> logger(
            keywords::channel = "GRAPHQL");

        std::string prettyRequest = request;
        std::string prettyResponse = response;

        try
        {
            auto reqJson = boost::json::parse(request);
            prettyRequest = prettyPrintJson(reqJson, 1);

            // Extract entity name for better logging
            std::string entityName;
            std::string qStr;

            if (reqJson.is_array() && !reqJson.get_array().empty())
            {
                auto &first = reqJson.get_array()[0];

                if (first.is_object() && first.as_object().contains("query"))
                {
                    qStr = std::string(first.as_object().at("query").as_string());
                }
            }
            else if (reqJson.is_object() && reqJson.as_object().contains("query"))
            {
                qStr = std::string(reqJson.as_object().at("query").as_string());
            }

            if (!qStr.empty())
            {
                size_t start = qStr.find('{');

                if (start != std::string::npos)
                {
                    // Find the word after the first brace
                    size_t entityStart = qStr.find_first_not_of(" \t\n\r", start + 1);

                    if (entityStart != std::string::npos)
                    {
                        size_t entityEnd = qStr.find_first_of(" \t\n\r{", entityStart);

                        if (entityEnd != std::string::npos)
                        {
                            entityName = qStr.substr(entityStart, entityEnd - entityStart);
                            // If it's a wrapper like 'query', skip it

                            if (entityName == "query" || entityName == "mutation")
                            {
                                start = qStr.find('{', entityEnd);

                                if (start != std::string::npos)
                                {
                                    entityStart = qStr.find_first_not_of(" \t\n\r", start + 1);
                                    entityEnd = qStr.find_first_of(" \t\n\r{", entityStart);

                                    if (entityStart != std::string::npos && entityEnd != std::string::npos)
                                    {
                                        entityName = qStr.substr(entityStart, entityEnd - entityStart);
                                    }
                                }
                            }
                        }
                    }
                }
            }

            if (!entityName.empty())
            {
                prettyRequest = entityName + "\n" + prettyRequest;
            }
        }
        catch (...) {}

        try
        {
            auto resJson = boost::json::parse(response);
            prettyResponse = prettyPrintJson(resJson, 1);
        }
        catch (...) {}

        std::string entry = prettyRequest + "\n" + prettyResponse + "\n";

        BOOST_LOG_SEV(logger, LogType::INFO)
        << logging::add_value("Origin", endpoint) << entry;
    }

    std::string Logger::GetStackTrace()
    {
        std::stringstream ss;
        ss << boost::stacktrace::stacktrace();

        return ss.str();
    }

    void Logger::LogTrace(const std::string &className, const std::string &message)
    {
        std::string trace = GetStackTrace();
        LogDebug(className, message + "\n--- STACK TRACE ---\n" + trace + "\n-------------------");
    }

    std::string Logger::prettyPrintJson(const boost::json::value &jv, int indent)
    {
        std::string result;
        std::string indentStr(indent * 2, ' ');
        std::string nextIndentStr((indent + 1) * 2, ' ');

        if (jv.is_object())
        {
            auto &obj = jv.get_object();
            result += "{\n";
            bool first = true;

            for (auto &kv : obj)
            {
                if (!first)
                    result += ",\n";
                result += nextIndentStr + "\"" + std::string(kv.key()) + "\": ";
                result += prettyPrintJson(kv.value(), indent + 1);
                first = false;
            }
            result += "\n" + indentStr + "}";
        }
        else if (jv.is_array())
        {
            auto &arr = jv.get_array();
            result += "[\n";
            bool first = true;

            for (auto &item : arr)
            {
                if (!first)
                    result += ",\n";
                result += nextIndentStr + prettyPrintJson(item, indent + 1);
                first = false;
            }
            result += "\n" + indentStr + "]";
        }
        else if (jv.is_string())
        {
            std::string s = std::string(jv.get_string());

            if (s.find('{') != std::string::npos)
            {
                // Potential GraphQL query - expand and indent
                std::string expanded;
                int gqlDepth = 0;
                bool lastWasSpace = false;
                std::string baseGqlIndent = nextIndentStr + "  ";

                expanded += "\"\n" + baseGqlIndent;

                for (size_t i = 0; i < s.size(); ++i)
                {
                    char c = s[i];

                    if (c == '{')
                    {
                        gqlDepth++;
                        expanded += " {\n" + baseGqlIndent + std::string(gqlDepth * 2, ' ');
                        lastWasSpace = true;
                    }
                    else if (c == '}')
                    {
                        if (gqlDepth > 0) gqlDepth--;
                        expanded += "\n" + baseGqlIndent + std::string(gqlDepth * 2, ' ') + "}";
                        lastWasSpace = false;
                    }
                    else if (std::isspace(c))
                    {
                        if (!lastWasSpace && !expanded.empty() && expanded.back() != '\n' && expanded.back() != '{')
                        {
                            // Convert spaces between fields into new lines if inside braces

                            if (gqlDepth > 0)
                            {
                                expanded += "\n" + baseGqlIndent + std::string(gqlDepth * 2, ' ');
                            }
                            else
                            {
                                expanded += " ";
                            }
                        }
                        lastWasSpace = true;
                    }
                    else
                    {
                        expanded += c;
                        lastWasSpace = false;
                    }
                }
                expanded += "\n" + nextIndentStr + "\"";
                result += expanded;
            }
            else
            {
                result += "\"" + s + "\"";
            }
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
} // namespace omnisphere::utils
