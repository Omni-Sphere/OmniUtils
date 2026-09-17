#define BOOST_STACKTRACE_GNU_SOURCE_NOT_REQUIRED
#include "Logger.hpp"
#include "PathUtils.hpp"
#include "Http/Request.hpp"
#include <algorithm>
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
    std::atomic<bool> Logger::s_extendedLogEnabled{true};

    void Logger::SetExtendedLog(bool enabled)
    {
        s_extendedLogEnabled = enabled;
        std::cout << "[Logger] Extended logging state changed to: " << (enabled ? "ENABLED" : "DISABLED") << std::endl;
    }

    bool Logger::IsExtendedLogEnabled()
    {
        return s_extendedLogEnabled;
    }

    std::ostream& operator<<(std::ostream& strm, LogType level)
    {
        static const char* const strings[] =
        {
            "DEBUG",
            "INFO",
            "WARNING",
            "ERROR"
        };

        if (static_cast<std::size_t>(level) < sizeof(strings) / sizeof(*strings))
            strm << strings[static_cast<std::size_t>(level)];
        else
            strm << static_cast<int>(level);

        return strm;
    }

    // Define global attributes
    BOOST_LOG_ATTRIBUTE_KEYWORD(severity, "Severity", LogType)
    BOOST_LOG_ATTRIBUTE_KEYWORD(channel, "Channel", std::string)
    BOOST_LOG_ATTRIBUTE_KEYWORD(origin, "Origin", std::string)

    static std::string g_currentLogDir;
    static bool g_loggerInitialized = false;

    static void CheckLogFileExists()
    {
        if (!g_loggerInitialized || g_currentLogDir.empty()) return;

        std::time_t t = std::time(nullptr);
        std::tm tm = *std::localtime(&t);
        char buf[64];
        std::strftime(buf, sizeof(buf), "%Y%m%d%H.log", &tm);
        std::filesystem::path currentLogFile = std::filesystem::path(g_currentLogDir) / buf;

        if (!std::filesystem::exists(currentLogFile))
        {
            logging::core::get()->remove_all_sinks();
            g_loggerInitialized = false;
            Logger::Init();
        }
    }

    void Logger::Init()
    {
        if (g_loggerInitialized) return;
        try
        {
            // Ensure Logs directory exists relative to binary executable
            std::filesystem::path exeDir = GetExecutableDir();
            std::filesystem::path logDir = exeDir / "Logs";
            g_currentLogDir = logDir.string();

            if (!std::filesystem::exists(logDir))
            {
                std::filesystem::create_directories(logDir);
            }

            // Set up common attributes (timestamp, etc.)
            logging::add_common_attributes();
            logging::core::get()->add_global_attribute("Scope", attrs::named_scope());

            // --- UNIFIED LOG SINK (File log - plain text) ---
            std::string logFileNamePattern = (logDir / "%Y%m%d%H.log").string();
            auto fileSink = logging::add_file_log(
                keywords::file_name = logFileNamePattern,
                keywords::open_mode = std::ios_base::app | std::ios_base::out,
                keywords::time_based_rotation =
                sinks::file::rotation_at_time_interval(boost::posix_time::hours(1)),
                keywords::auto_flush = true);
            fileSink->set_formatter(expr::format("[%1%] [%2%] [%3%] [%4%] %5%") %
                                    expr::format_date_time<boost::posix_time::ptime>(
                                        "TimeStamp", "%Y-%m-%d %H:%M:%S.%f") %
                                    severity % channel % origin % expr::smessage);

            // --- CONSOLE SINK (With High-Legibility Modern ANSI Theme) ---
            auto consoleSink = logging::add_console_log(std::clog);
            consoleSink->set_formatter([](logging::record_view const& rec, logging::formatting_ostream& strm) {
                auto timeStamp = logging::extract<boost::posix_time::ptime>("TimeStamp", rec);
                auto sev = logging::extract<LogType>("Severity", rec);
                auto ch = logging::extract<std::string>("Channel", rec);
                auto orig = logging::extract<std::string>("Origin", rec);
                auto msg = rec[expr::smessage];

                // ANSI styles & palette (Truecolor Dracula/Modern high-contrast)
                constexpr const char* RESET       = "\033[0m";
                constexpr const char* CLR_TIME    = "\033[38;2;120;130;150m";          // Muted slate gray
                constexpr const char* TAG_DEBUG   = "\033[38;2;139;233;253m⚙ DEBUG \033[0m "; // Cyan
                constexpr const char* TAG_INFO    = "\033[38;2;80;250;123m\033[1m● INFO  \033[0m ";  // Vivid Emerald Green
                constexpr const char* TAG_WARN    = "\033[38;2;241;250;140m\033[1m▲ WARN  \033[0m ";  // Warm Amber
                constexpr const char* TAG_ERROR   = "\033[38;2;255;85;85m\033[1m✖ ERROR \033[0m ";   // Bright Crimson

                constexpr const char* CLR_CH_SQL  = "\033[38;2;255;184;108m\033[1m"; // Warm Orange
                constexpr const char* CLR_CH_GQL  = "\033[38;2;255;121;198m\033[1m"; // Pink / Magenta
                constexpr const char* CLR_CH_HTTP = "\033[38;2;189;147;249m\033[1m"; // Purple
                constexpr const char* CLR_CH_SYS  = "\033[38;2;139;233;253m\033[1m"; // Cyan
                constexpr const char* CLR_CH_DEF  = "\033[38;2;189;147;249m\033[1m";

                constexpr const char* CLR_ORIGIN  = "\033[38;2;140;160;185m";        // Slate blue
                constexpr const char* CLR_MSG_ERR = "\033[38;2;255;105;105m\033[1m"; // Crisp prominent red
                constexpr const char* CLR_MSG_WRN = "\033[38;2;245;220;120m";        // Warm amber message
                constexpr const char* CLR_MSG_SQL = "\033[38;2;245;225;185m";        // Readable warm cream for queries
                constexpr const char* CLR_MSG_DBG = "\033[38;2;150;160;175m";        // Subdued gray
                constexpr const char* CLR_MSG_DEF = "\033[38;2;248;248;242m";        // High-contrast clean white

                // 1. Timestamp [HH:MM:SS.mmm]
                if (timeStamp) {
                    std::string tStr = boost::posix_time::to_simple_string(timeStamp.get().time_of_day());
                    if (tStr.length() > 12) tStr = tStr.substr(0, 12);
                    strm << CLR_TIME << "[" << tStr << "] " << RESET;
                }

                // 2. Severity (aligned width + distinctive icon)
                LogType currentSev = LogType::INFO;
                if (sev) {
                    currentSev = sev.get();
                    switch (currentSev) {
                        case LogType::DEBUG:   strm << TAG_DEBUG; break;
                        case LogType::INFO:    strm << TAG_INFO;  break;
                        case LogType::WARNING: strm << TAG_WARN;  break;
                        case LogType::ERROR:   strm << TAG_ERROR; break;
                    }
                }

                // 3. Channel with specific color
                std::string channelName;
                if (ch) {
                    channelName = ch.get();
                    const char* clrCh = CLR_CH_DEF;
                    if (channelName == "SQL") clrCh = CLR_CH_SQL;
                    else if (channelName == "GRAPHQL") clrCh = CLR_CH_GQL;
                    else if (channelName == "HTTP_REQ" || channelName == "HTTP") clrCh = CLR_CH_HTTP;
                    else if (channelName == "SYSTEM") clrCh = CLR_CH_SYS;

                    strm << clrCh << "[" << channelName << "]" << RESET << " ";
                }

                // 4. Origin ([OmniRouteAPI], [PostgreSQL], [/graphql], etc.)
                if (orig) {
                    strm << CLR_ORIGIN << "[" << orig.get() << "]" << RESET << " ";
                }

                // 5. Message with adaptive color and newline safety
                if (msg) {
                    const char* msgColor = CLR_MSG_DEF;
                    if (currentSev == LogType::ERROR) {
                        msgColor = CLR_MSG_ERR;
                    } else if (currentSev == LogType::WARNING) {
                        msgColor = CLR_MSG_WRN;
                    } else if (currentSev == LogType::DEBUG) {
                        msgColor = CLR_MSG_DBG;
                    } else if (channelName == "SQL") {
                        msgColor = CLR_MSG_SQL;
                    }

                    std::string msgStr = msg.get();
                    strm << msgColor << msgStr << RESET;
                    if (msgStr.empty() || msgStr.back() != '\n') {
                        strm << "\n";
                    }
                } else {
                    strm << "\n";
                }
            });

            logging::core::get()->set_filter(severity >= LogType::DEBUG);
            g_loggerInitialized = true;
            std::cout << "\033[32m[Logger] Unified single-file logging system active. Directory: " << logDir.string() << "\033[0m" << std::endl;
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
        CheckLogFileExists();
        src::severity_channel_logger_mt<LogType, std::string> logger(
            keywords::channel = "SYSTEM");
        BOOST_LOG_SEV(logger, type)
        << logging::add_value("Origin", className) << message;
    }

    void Logger::LogInfo(const std::string &className, const std::string &message)
    {
        LogSystem(LogType::INFO, className, message);
    }

    void Logger::LogWarning(const std::string &className, const std::string &message)
    {
        LogSystem(LogType::WARNING, className, message);
    }

    void Logger::LogError(const std::string &className, const std::string &message)
    {
        LogSystem(LogType::ERROR, className, message);
    }

    void Logger::LogDebug(const std::string &className, const std::string &message)
    {
        CheckLogFileExists();
        src::severity_channel_logger_mt<LogType, std::string> logger(
            keywords::channel = "DEBUG");
        BOOST_LOG_SEV(logger, LogType::DEBUG)
        << logging::add_value("Origin", className) << message;
    }

    void Logger::LogHttpRequest(const omnisphere::net::Request& req)
    {
        CheckLogFileExists();
        src::severity_channel_logger_mt<LogType, std::string> logger(keywords::channel = "HTTP_REQ");

        std::string reqLog = req.TraceContext() + " " + req.Method() + " " + req.Target();

        if (!req.QueryParams().empty())
        {
            reqLog += "\n  [Query Params]:";
            for (const auto& [k, v] : req.QueryParams())
            {
                reqLog += "\n    " + k + " = " + v;
            }
        }

        if (!req.Headers().empty())
        {
            reqLog += "\n  [Headers]:";
            for (const auto& [k, v] : req.Headers())
            {
                std::string lowerK = k;
                std::transform(lowerK.begin(), lowerK.end(), lowerK.begin(), [](unsigned char c){ return std::tolower(c); });
                if (lowerK == "authorization" && v.length() > 15)
                {
                    reqLog += "\n    " + k + ": " + v.substr(0, 15) + "... [REDACTED]";
                }
                else
                {
                    reqLog += "\n    " + k + ": " + v;
                }
            }
        }

        if (!req.Body().empty())
        {
            reqLog += "\n  [Body Payload]:\n" + req.Body();
        }

        BOOST_LOG_SEV(logger, LogType::INFO)
            << logging::add_value("Origin", req.Target()) << reqLog;
    }

    void Logger::LogSQL(const std::string &dbEngine, const std::string &message)
    {
        CheckLogFileExists();
        if (!s_extendedLogEnabled)
        {
            return;
        }

        src::severity_channel_logger_mt<LogType, std::string> logger(
            keywords::channel = "SQL");
        BOOST_LOG_SEV(logger, LogType::INFO)
        << logging::add_value("Origin", dbEngine) << message;
    }

    void Logger::LogGraphQL(const std::string &endpoint, const std::string &request,
                            const std::string &response)
    {
        CheckLogFileExists();
        bool hasErrors = false;
        std::string prettyRequest = request;
        std::string prettyResponse = response;

        try
        {
            auto resJson = boost::json::parse(response);
            prettyResponse = prettyPrintJson(resJson, 1);
            if (resJson.is_object() && resJson.as_object().contains("errors"))
            {
                hasErrors = true;
            }
        }
        catch (...) {}

        // If there are errors in response, ALWAYS log as ERROR regardless of ExtendedLog state
        if (hasErrors)
        {
            LogError("GraphQL", "Error in GraphQL request on endpoint '" + endpoint + "':\n" + prettyResponse);
        }

        if (!s_extendedLogEnabled)
        {
            return;
        }

        src::severity_channel_logger_mt<LogType, std::string> logger(
            keywords::channel = "GRAPHQL");

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
