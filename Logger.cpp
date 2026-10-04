#define BOOST_STACKTRACE_GNU_SOURCE_NOT_REQUIRED
#include "Logger.hpp"
#include "PathUtils.hpp"
#include "Http/Request.hpp"
#include "Http/Response.hpp"

#include <algorithm>
#include <boost/stacktrace.hpp>
#include <filesystem>
#include <iostream>
#include <sstream>
#include <ctime>

namespace omnisphere::utils
{
    std::atomic<bool> Logger::s_extendedLogEnabled{true};

    // ANSI Colors and Styles
    static constexpr const char* RESET       = "\033[0m";
    static constexpr const char* CLR_TIME    = "\033[38;2;120;130;150m";          // Muted slate gray
    static constexpr const char* TAG_DEBUG   = "\033[38;2;139;233;253m⚙ DEBUG \033[0m "; // Cyan
    static constexpr const char* TAG_INFO    = "\033[38;2;80;250;123m\033[1m● INFO  \033[0m ";  // Vivid Emerald Green
    static constexpr const char* TAG_WARN    = "\033[38;2;241;250;140m\033[1m▲ WARN  \033[0m ";  // Warm Amber
    static constexpr const char* TAG_ERROR   = "\033[38;2;255;85;85m\033[1m✖ ERROR \033[0m ";   // Bright Crimson
    static constexpr const char* TAG_SLOW    = "\033[38;2;255;184;108m\033[1m▲ SLOW  \033[0m "; // Warm Orange

    static constexpr const char* CLR_ORIGIN  = "\033[38;2;140;160;185m";        // Slate blue
    static constexpr const char* CLR_IP      = "\033[38;2;189;147;249m";        // Purple
    static constexpr const char* CLR_MSG_ERR = "\033[38;2;255;105;105m\033[1m"; // Prominent Red
    static constexpr const char* CLR_MSG_WRN = "\033[38;2;245;220;120m";        // Amber
    static constexpr const char* CLR_MSG_SQL = "\033[38;2;245;225;185m";        // Cream
    static constexpr const char* CLR_MSG_DEF = "\033[38;2;248;248;242m";        // High contrast white

    // Global file path and synchronization
    static std::string g_currentLogDir;
    static bool g_loggerInitialized = false;
    static std::mutex g_fileWriteMutex;
    static std::mutex g_consoleMutex;

    // Thread-local correlation context
    static thread_local RequestContext t_currentContext;

    RequestContextScope::RequestContextScope(std::string reqId, std::string clientIp, std::string user, std::string client)
    {
        m_prevContext = t_currentContext;
        t_currentContext = RequestContext{
            std::move(reqId),
            std::move(clientIp),
            std::move(user),
            std::move(client)
        };
    }

    RequestContextScope::~RequestContextScope()
    {
        t_currentContext = m_prevContext;
    }

    void Logger::SetCurrentContext(const RequestContext& ctx)
    {
        t_currentContext = ctx;
    }

    RequestContext Logger::GetCurrentContext()
    {
        return t_currentContext;
    }

    void Logger::ClearCurrentContext()
    {
        t_currentContext = RequestContext{};
    }

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

    static std::string SanitizeClientDirectory(const std::string& raw)
    {
        if (raw.empty() || raw == "unknown" || raw == "server") return "server";
        std::string out;
        out.reserve(raw.size());
        for (char c : raw)
        {
            if (c == ':') out.push_back('_');
            else if (std::isalnum(static_cast<unsigned char>(c)) || c == '.' || c == '-' || c == '_')
                out.push_back(c);
        }
        return out.empty() ? "server" : out;
    }

    static std::string GetCurrentTimestampString()
    {
        auto now = std::chrono::system_clock::now();
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;
        std::time_t t = std::chrono::system_clock::to_time_t(now);
        std::tm tm{};
        localtime_r(&t, &tm);
        char buf[32];
        std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm);
        std::ostringstream oss;
        oss << buf << '.' << std::setfill('0') << std::setw(3) << ms.count();
        return oss.str();
    }

    static std::string GetCurrentTimeString()
    {
        auto now = std::chrono::system_clock::now();
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;
        std::time_t t = std::chrono::system_clock::to_time_t(now);
        std::tm tm{};
        localtime_r(&t, &tm);
        char buf[16];
        std::strftime(buf, sizeof(buf), "%H:%M:%S", &tm);
        std::ostringstream oss;
        oss << buf << '.' << std::setfill('0') << std::setw(3) << ms.count();
        return oss.str();
    }

    static void WriteLogToFile(const std::string& subDir, const std::string& channel, const std::string& line)
    {
        try
        {
            std::lock_guard<std::mutex> lock(g_fileWriteMutex);
            if (g_currentLogDir.empty())
            {
                std::filesystem::path exeDir = GetExecutableDir();
                std::filesystem::path logDir = exeDir / "Logs";
                g_currentLogDir = logDir.string();
            }

            std::filesystem::path targetDir = std::filesystem::path(g_currentLogDir) / subDir;
            if (!std::filesystem::exists(targetDir))
            {
                std::filesystem::create_directories(targetDir);
            }

            std::time_t t = std::time(nullptr);
            std::tm tm{};
            localtime_r(&t, &tm);
            char hourBuf[32];
            std::strftime(hourBuf, sizeof(hourBuf), "%Y%m%d%H", &tm);

            std::filesystem::path logFilePath = targetDir / (channel + "_" + std::string(hourBuf) + ".log");
            std::ofstream ofs(logFilePath, std::ios_base::app | std::ios_base::out);
            if (ofs.is_open())
            {
                ofs << line;
                if (line.empty() || line.back() != '\n')
                    ofs << "\n";
            }
        }
        catch (...)
        {
            // Logging failure must not crash the service
        }
    }

    void Logger::Init()
    {
        if (g_loggerInitialized) return;
        try
        {
            std::filesystem::path exeDir = GetExecutableDir();
            std::filesystem::path logDir = exeDir / "Logs";
            g_currentLogDir = logDir.string();

            if (!std::filesystem::exists(logDir))
            {
                std::filesystem::create_directories(logDir);
            }

            g_loggerInitialized = true;
            std::cout << "\033[32m[Logger] Multi-client isolated logging system initialized. Base Directory: " 
                      << logDir.string() << "\033[0m" << std::endl;
        }
        catch (const std::exception &e)
        {
            std::cerr << "CRITICAL: Failed to initialize Logger: " << e.what() << std::endl;
        }
    }

    void Logger::LogSystem(LogType type, const std::string &className, const std::string &message)
    {
        Init();

        RequestContext ctx = t_currentContext;
        std::string subDir = SanitizeClientDirectory(ctx.clientIp);
        std::string ts = GetCurrentTimestampString();

        std::ostringstream ss;
        ss << "[" << ts << "] [" << type << "] [SYSTEM] [" << className << "]";
        if (!ctx.requestId.empty()) ss << " [" << ctx.requestId << "]";
        if (!ctx.clientIp.empty()) ss << " [IP: " << ctx.clientIp << "]";
        if (!ctx.userCode.empty()) ss << " [User: " << ctx.userCode << "]";
        ss << " " << message;

        WriteLogToFile(subDir, "system", ss.str());

        // Console Output
        {
            std::lock_guard<std::mutex> lock(g_consoleMutex);
            std::string timeStr = GetCurrentTimeString();
            std::cout << CLR_TIME << "[" << timeStr << "] " << RESET;

            switch (type)
            {
                case LogType::DEBUG:   std::cout << TAG_DEBUG; break;
                case LogType::INFO:    std::cout << TAG_INFO;  break;
                case LogType::WARNING: std::cout << TAG_WARN;  break;
                case LogType::ERROR:   std::cout << TAG_ERROR; break;
            }

            std::cout << CLR_ORIGIN << "[" << className << "]" << RESET << " ";
            if (!ctx.clientIp.empty())
            {
                std::cout << CLR_IP << "[" << ctx.clientIp << "]" << RESET << " ";
            }

            if (type == LogType::ERROR) std::cout << CLR_MSG_ERR;
            else if (type == LogType::WARNING) std::cout << CLR_MSG_WRN;
            else std::cout << CLR_MSG_DEF;

            std::cout << message << RESET;
            if (message.empty() || message.back() != '\n') std::cout << "\n";
            std::cout.flush();
        }
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
        LogSystem(LogType::DEBUG, className, message);
    }

    void Logger::LogHttpRequest(const omnisphere::net::Request& req)
    {
        Init();

        std::string ip = req.ClientIP();
        std::string subDir = SanitizeClientDirectory(ip);
        std::string ts = GetCurrentTimestampString();

        std::ostringstream ss;
        ss << "[" << ts << "] [INFO] [HTTP_REQ] [" << req.RequestId() << "] [IP: " << ip << "] "
           << req.Method() << " " << req.Target();

        if (!req.QueryParams().empty())
        {
            ss << "\n  [Query Params]:";
            for (const auto& [k, v] : req.QueryParams())
            {
                ss << "\n    " << k << " = " << v;
            }
        }

        if (!req.Headers().empty())
        {
            ss << "\n  [Headers]:";
            for (const auto& [k, v] : req.Headers())
            {
                std::string lowerK = k;
                std::transform(lowerK.begin(), lowerK.end(), lowerK.begin(), [](unsigned char c){ return std::tolower(c); });
                if (lowerK == "authorization" && v.length() > 15)
                {
                    ss << "\n    " << k << ": " << v.substr(0, 15) << "... [REDACTED]";
                }
                else
                {
                    ss << "\n    " << k << ": " << v;
                }
            }
        }

        if (!req.Body().empty())
        {
            ss << "\n  [Body Payload]:\n" << req.Body();
        }

        WriteLogToFile(subDir, "net", ss.str());
        // Clean console: NO full body/headers dump to console.
    }

    void Logger::LogHttpResponse(const omnisphere::net::Request& req, const omnisphere::net::Response& resp, long long durationMs)
    {
        Init();

        std::string ip = req.ClientIP();
        std::string subDir = SanitizeClientDirectory(ip);
        std::string ts = GetCurrentTimestampString();
        int status = resp.StatusCode();
        size_t bodySize = resp.Body().size();

        std::ostringstream ss;
        ss << "[" << ts << "] [INFO] [HTTP_RES] [" << req.RequestId() << "] [IP: " << ip << "] "
           << "Status: " << status << " | Duration: " << durationMs << " ms | Size: " << bodySize << " bytes"
           << " | " << req.Method() << " " << req.Target();

        WriteLogToFile(subDir, "net", ss.str());

        // Live Dashboard Console Output
        {
            std::lock_guard<std::mutex> lock(g_consoleMutex);
            std::string timeStr = GetCurrentTimeString();
            std::cout << CLR_TIME << "[" << timeStr << "] " << RESET;

            if (status >= 500)
            {
                std::cout << TAG_ERROR << CLR_ORIGIN << "[HTTP " << status << "]" << RESET << " "
                          << CLR_IP << "[" << ip << "]" << RESET << " "
                          << CLR_MSG_ERR << req.Method() << " " << req.Target() 
                          << " (" << durationMs << " ms) #" << req.RequestId() << RESET << "\n";
            }
            else if (durationMs >= SLOW_HTTP_THRESHOLD_MS)
            {
                std::cout << TAG_SLOW << CLR_ORIGIN << "[SLOW REQ]" << RESET << " "
                          << CLR_IP << "[" << ip << "]" << RESET << " "
                          << CLR_MSG_WRN << req.Method() << " " << req.Target()
                          << " (" << durationMs << " ms | HTTP " << status << ") #" << req.RequestId() << RESET << "\n";
            }
            else if (status >= 400)
            {
                std::cout << TAG_WARN << CLR_ORIGIN << "[HTTP " << status << "]" << RESET << " "
                          << CLR_IP << "[" << ip << "]" << RESET << " "
                          << CLR_MSG_WRN << req.Method() << " " << req.Target()
                          << " (" << durationMs << " ms) #" << req.RequestId() << RESET << "\n";
            }
            else
            {
                std::cout << TAG_INFO << CLR_ORIGIN << "[HTTP]" << RESET << " "
                          << CLR_IP << "[" << ip << "]" << RESET << " "
                          << CLR_MSG_DEF << req.Method() << " " << req.Target() << " -> " << status
                          << " (" << durationMs << " ms) #" << req.RequestId() << RESET << "\n";
            }
            std::cout.flush();
        }
    }

    void Logger::LogSQL(const std::string &dbEngine, const std::string &message, long long durationMs)
    {
        Init();
        if (!s_extendedLogEnabled) return;

        RequestContext ctx = t_currentContext;
        std::string subDir = SanitizeClientDirectory(ctx.clientIp);
        std::string ts = GetCurrentTimestampString();

        std::ostringstream ss;
        ss << "[" << ts << "] [INFO] [SQL] [" << dbEngine << "]";
        if (!ctx.requestId.empty()) ss << " [" << ctx.requestId << "]";
        if (!ctx.clientIp.empty()) ss << " [IP: " << ctx.clientIp << "]";
        if (durationMs >= 0) ss << " [Duration: " << durationMs << " ms]";
        ss << " " << message;

        WriteLogToFile(subDir, "sql", ss.str());

        // Console Output: Only show in console if it is a SLOW query (>= 100ms) or has an SQL Error
        bool isSlow = (durationMs >= SLOW_SQL_THRESHOLD_MS);
        bool isError = (message.find("ERROR") != std::string::npos || message.find("Error") != std::string::npos);

        if (isSlow || isError)
        {
            std::lock_guard<std::mutex> lock(g_consoleMutex);
            std::string timeStr = GetCurrentTimeString();
            std::cout << CLR_TIME << "[" << timeStr << "] " << RESET;

            if (isError)
            {
                std::cout << TAG_ERROR << CLR_ORIGIN << "[SQL " << dbEngine << "]" << RESET << " ";
                if (!ctx.clientIp.empty()) std::cout << CLR_IP << "[" << ctx.clientIp << "]" << RESET << " ";
                std::cout << CLR_MSG_ERR << message;
            }
            else
            {
                std::cout << TAG_SLOW << CLR_ORIGIN << "[SLOW SQL]" << RESET << " ";
                if (!ctx.clientIp.empty()) std::cout << CLR_IP << "[" << ctx.clientIp << "]" << RESET << " ";
                std::cout << CLR_MSG_SQL << "(" << durationMs << " ms) [" << dbEngine << "] " << message;
            }

            if (!ctx.requestId.empty())
            {
                std::cout << " #" << ctx.requestId;
            }
            std::cout << RESET << "\n";
            std::cout.flush();
        }
    }

    void Logger::LogGraphQL(const std::string &endpoint, const std::string &request,
                            const std::string &response)
    {
        Init();

        RequestContext ctx = t_currentContext;
        std::string subDir = SanitizeClientDirectory(ctx.clientIp);
        std::string ts = GetCurrentTimestampString();

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

        if (hasErrors)
        {
            LogError("GraphQL", "Error in GraphQL request on endpoint '" + endpoint + "':\n" + prettyResponse);
        }

        if (!s_extendedLogEnabled) return;

        try
        {
            auto reqJson = boost::json::parse(request);
            prettyRequest = prettyPrintJson(reqJson, 1);
        }
        catch (...) {}

        std::ostringstream ss;
        ss << "[" << ts << "] [INFO] [GRAPHQL] [" << endpoint << "]";
        if (!ctx.requestId.empty()) ss << " [" << ctx.requestId << "]";
        if (!ctx.clientIp.empty()) ss << " [IP: " << ctx.clientIp << "]";
        ss << "\n--- REQUEST ---\n" << prettyRequest << "\n--- RESPONSE ---\n" << prettyResponse;

        WriteLogToFile(subDir, "system", ss.str());
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
} // namespace omnisphere::utils
