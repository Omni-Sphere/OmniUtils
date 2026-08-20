#include "HttpServer.hpp"
#include "CorsMiddleware.hpp"
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/thread_pool.hpp>
#include <boost/asio/post.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/filesystem.hpp>
#include <boost/json.hpp>
#include <iostream>
#include <fstream>
#include <thread>
#include <vector>
#include <chrono>
#include <cctype>

#include "../JWT.hpp"

namespace beast = boost::beast;
namespace bhttp = boost::beast::http;
namespace asio = boost::asio;
using tcp = asio::ip::tcp;

namespace omnisphere::net
{
    static std::string GetMimeType(const std::string& path)
    {
        std::string ext = boost::filesystem::path(path).extension().string();
        std::string lowerExt;
        for (char c : ext) lowerExt += static_cast<char>(std::tolower(c));

        if (lowerExt == ".png") return "image/png";
        if (lowerExt == ".jpg" || lowerExt == ".jpeg") return "image/jpeg";
        if (lowerExt == ".webp") return "image/webp";
        if (lowerExt == ".gif") return "image/gif";
        if (lowerExt == ".svg") return "image/svg+xml";
        if (lowerExt == ".pdf") return "application/pdf";
        if (lowerExt == ".json") return "application/json";
        if (lowerExt == ".txt") return "text/plain";
        if (lowerExt == ".html") return "text/html";
        if (lowerExt == ".css") return "text/css";
        if (lowerExt == ".js") return "application/javascript";

        return "application/octet-stream";
    }

    static bool IsAllowedImageExtension(const std::string& path)
    {
        std::string ext = boost::filesystem::path(path).extension().string();
        std::string lowerExt;
        for (char c : ext) lowerExt += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

        return (lowerExt == ".png" || lowerExt == ".jpg" || lowerExt == ".jpeg" ||
                lowerExt == ".webp" || lowerExt == ".gif" || lowerExt == ".svg");
    }

    static bool IsValidImageMagicBytes(const std::string& data, const std::string& filename)
    {
        std::string ext = boost::filesystem::path(filename).extension().string();
        std::string lowerExt;
        for (char c : ext) lowerExt += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

        if (data.empty()) return false;

        const unsigned char* bytes = reinterpret_cast<const unsigned char*>(data.data());
        size_t len = data.size();

        if (lowerExt == ".png")
        {
            if (len < 8) return false;
            return (bytes[0] == 0x89 && bytes[1] == 0x50 && bytes[2] == 0x4E && bytes[3] == 0x47 &&
                    bytes[4] == 0x0D && bytes[5] == 0x0A && bytes[6] == 0x1A && bytes[7] == 0x0A);
        }
        if (lowerExt == ".jpg" || lowerExt == ".jpeg")
        {
            if (len < 3) return false;
            return (bytes[0] == 0xFF && bytes[1] == 0xD8 && bytes[2] == 0xFF);
        }
        if (lowerExt == ".gif")
        {
            if (len < 4) return false;
            return (bytes[0] == 'G' && bytes[1] == 'I' && bytes[2] == 'F' && bytes[3] == '8');
        }
        if (lowerExt == ".webp")
        {
            if (len < 12) return false;
            return (bytes[0] == 'R' && bytes[1] == 'I' && bytes[2] == 'F' && bytes[3] == 'F' &&
                    bytes[8] == 'W' && bytes[9] == 'E' && bytes[10] == 'B' && bytes[11] == 'P');
        }
        if (lowerExt == ".svg")
        {
            std::string sample = data.substr(0, std::min<size_t>(len, 1024));
            for (char& c : sample) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            return (sample.find("<svg") != std::string::npos || sample.find("<?xml") != std::string::npos);
        }

        return false;
    }

    static std::string SanitizeFileName(const std::string& input)
    {
        std::string clean;
        for (char c : input)
        {
            if (c == '/' || c == '\\' || c == ':' || c == '*' || c == '?' || c == '"' || c == '<' || c == '>' || c == '|' || c == '\0')
            {
                clean += '_';
            }
            else
            {
                clean += c;
            }
        }
        while (clean.find("..") != std::string::npos)
        {
            size_t pos = clean.find("..");
            clean.erase(pos, 2);
        }
        return clean.empty() ? "image.png" : clean;
    }

    static std::string SanitizeSubPath(const std::string& input)
    {
        std::string clean = input;
        while (clean.find("..") != std::string::npos)
        {
            size_t pos = clean.find("..");
            clean.erase(pos, 2);
        }
        while (!clean.empty() && (clean.front() == '/' || clean.front() == '\\')) clean.erase(0, 1);
        while (!clean.empty() && (clean.back() == '/' || clean.back() == '\\')) clean.pop_back();

        std::string result;
        for (char c : clean)
        {
            if (c == '\\') c = '/';
            if (c == ':' || c == '*' || c == '?' || c == '"' || c == '<' || c == '>' || c == '|' || c == '\0')
            {
                result += '_';
            }
            else
            {
                result += c;
            }
        }
        return result;
    }

    static std::string ExtractTokenFromRequest(const bhttp::request<bhttp::string_body>& req)
    {
        std::string token;

        auto authIt = req.find(bhttp::field::authorization);
        if (authIt != req.end())
        {
            std::string authVal = std::string(authIt->value());
            if (authVal.rfind("Bearer ", 0) == 0 || authVal.rfind("bearer ", 0) == 0)
            {
                token = authVal.substr(7);
            }
            else
            {
                token = authVal;
            }
        }

        if (token.empty())
        {
            std::string target = std::string(req.target());
            size_t queryPos = target.find("token=");
            if (queryPos != std::string::npos)
            {
                size_t tokenStart = queryPos + 6;
                size_t tokenEnd = target.find('&', tokenStart);
                if (tokenEnd == std::string::npos)
                {
                    token = target.substr(tokenStart);
                }
                else
                {
                    token = target.substr(tokenStart, tokenEnd - tokenStart);
                }
            }
        }

        return token;
    }

    struct HttpServer::Impl
    {
        GqlHandler gqlHandler;
        std::string host;
        unsigned short port;
        std::size_t maxBodySize;
        std::size_t threadPoolSize;

        asio::io_context ioc{1};
        std::unique_ptr<tcp::acceptor> acceptor;
        std::unique_ptr<asio::thread_pool> workerPool;
        std::thread acceptorThread;
        std::atomic<bool> isRunning{false};

        Impl(GqlHandler handler, const std::string& h, unsigned short p, std::size_t bodyLimit, std::size_t poolSize)
            : gqlHandler(std::move(handler)), host(h), port(p), maxBodySize(bodyLimit), threadPoolSize(poolSize)
        {
            if (threadPoolSize == 0)
            {
                threadPoolSize = std::max<std::size_t>(2, std::thread::hardware_concurrency());
            }
        }

        void HandleSession(tcp::socket socket)
        {
            beast::error_code ec;
            beast::flat_buffer buffer;
            beast::tcp_stream stream(std::move(socket));

            for (;;)
            {
                stream.expires_after(std::chrono::seconds(30));

                bhttp::request_parser<bhttp::string_body> parser;
                parser.body_limit(maxBodySize);

                bhttp::read(stream, buffer, parser, ec);

                bhttp::response<bhttp::string_body> res;

                if (ec == bhttp::error::body_limit || ec == bhttp::error::buffer_overflow)
                {
                    res.result(bhttp::status::payload_too_large);
                    res.set(bhttp::field::content_type, "application/json");
                    res.body() = R"({"errors":[{"message":"Payload too large. Request body exceeds maximum allowed size."}]})";
                    res.prepare_payload();
                    bhttp::write(stream, res, ec);
                    break;
                }
                
                if (ec == bhttp::error::end_of_stream || ec == beast::error::timeout)
                {
                    break;
                }

                if (ec)
                {
                    break;
                }

                auto const& req = parser.get();

                res.version(req.version());
                res.keep_alive(req.keep_alive());

                CorsMiddleware::ApplySecurityHeaders(res);

                std::string clientIp = stream.socket().remote_endpoint().address().to_string();
                std::string method = std::string(req.method_string());
                std::string target = std::string(req.target());
                
                std::string clientType = "unknown";
                if (req.find("X-Client-Type") != req.end())
                    clientType = std::string(req.at("X-Client-Type"));

                std::string userAgent = "unknown";
                if (req.find(bhttp::field::user_agent) != req.end())
                    userAgent = std::string(req.at(bhttp::field::user_agent));

                std::cout << "\n========================================\n";
                std::cout << "[HTTP Request] " << method << " " << target << "\n";
                std::cout << "[Client IP]    " << clientIp << "\n";
                std::cout << "[Client Type]  " << clientType << "\n";
                std::cout << "[User-Agent]   " << userAgent << "\n";
                std::cout << "========================================" << std::endl;

                if (req.method() == bhttp::verb::options)
                {
                    res.result(bhttp::status::no_content);
                    res.prepare_payload();
                }
                else if (req.target().starts_with("/health"))
                {
                    if (req.method() != bhttp::verb::get)
                    {
                        res.result(bhttp::status::method_not_allowed);
                        res.set(bhttp::field::content_type, "application/json");
                        res.body() = R"({"error":"Method Not Allowed: /health accepts GET requests only."})";
                        res.prepare_payload();
                    }
                    else
                    {
                        bool dbConnected = (gqlHandler != nullptr);

                        boost::json::object hObj;
                        hObj["status"] = "UP";
                        hObj["service"] = "OmniServer";
                        hObj["database"] = dbConnected ? "CONNECTED" : "DISCONNECTED";

                        res.result(bhttp::status::ok);
                        res.set(bhttp::field::content_type, "application/json");
                        res.body() = boost::json::serialize(hObj);
                        res.prepare_payload();
                    }
                }
                else if (req.target() == "/upload")
                {
                    if (req.method() != bhttp::verb::post)
                    {
                        res.result(bhttp::status::method_not_allowed);
                        res.set(bhttp::field::content_type, "application/json");
                        res.body() = R"({"error":"Method Not Allowed: /upload accepts POST requests only."})";
                        res.prepare_payload();
                    }
                    else
                    {
                        std::string token = ExtractTokenFromRequest(req);
                        bool authorized = false;

                        if (!token.empty())
                        {
                            try
                            {
                                omnisphere::utils::JWT::ValidateToken(token);
                                authorized = true;
                            }
                            catch (const std::exception&)
                            {
                                authorized = false;
                            }
                        }

                        if (!authorized)
                        {
                            res.result(bhttp::status::unauthorized);
                            res.set(bhttp::field::content_type, "application/json");
                            res.body() = R"({"error":"Unauthorized: Valid Administrator Bearer token required for upload."})";
                            res.prepare_payload();
                        }
                        else
                        {
                            try
                            {
                                std::string rawFileName = "upload_" + std::to_string(std::chrono::system_clock::now().time_since_epoch().count()) + ".png";
                                std::string rawSubPath = "Uploads";

                                if (req.find("X-File-Name") != req.end())
                                {
                                    rawFileName = std::string(req.at("X-File-Name"));
                                }
                                if (req.find("X-File-Path") != req.end())
                                {
                                    rawSubPath = std::string(req.at("X-File-Path"));
                                }

                                std::string fileName = SanitizeFileName(rawFileName);
                                std::string subPath = SanitizeSubPath(rawSubPath);

                                if (!IsAllowedImageExtension(fileName))
                                {
                                    res.result(bhttp::status::bad_request);
                                    res.set(bhttp::field::content_type, "application/json");
                                    res.body() = R"({"success":false, "error":"Invalid file extension. Only image formats (.png, .jpg, .jpeg, .webp, .gif, .svg) are allowed."})";
                                    res.prepare_payload();
                                }
                                else if (!IsValidImageMagicBytes(req.body(), fileName))
                                {
                                    res.result(bhttp::status::bad_request);
                                    res.set(bhttp::field::content_type, "application/json");
                                    res.body() = R"({"success":false, "error":"Invalid image format. File content does not match a valid image signature."})";
                                    res.prepare_payload();
                                }
                                else
                                {
                                    std::string dirPath = "Storage";
                                    if (!subPath.empty())
                                    {
                                        dirPath += "/" + subPath;
                                    }

                                    boost::filesystem::create_directories(dirPath);
                                    std::string fullFilePath = dirPath + "/" + fileName;

                                    std::ofstream ofs(fullFilePath, std::ios::binary);
                                    if (!ofs.is_open())
                                    {
                                        throw std::runtime_error("Could not open file for writing: " + fullFilePath);
                                    }

                                    ofs.write(req.body().data(), req.body().size());
                                    ofs.close();

                                    std::string publicUrl = "/cdn/";
                                    if (!subPath.empty())
                                    {
                                        publicUrl += subPath + "/";
                                    }
                                    publicUrl += fileName;

                                    boost::json::object resObj;
                                    resObj["success"] = true;
                                    resObj["fileName"] = fileName;
                                    resObj["url"] = publicUrl;
                                    resObj["path"] = fullFilePath;

                                    res.result(bhttp::status::ok);
                                    res.set(bhttp::field::content_type, "application/json");
                                    res.body() = boost::json::serialize(resObj);
                                    res.prepare_payload();
                                }
                            }
                            catch (const std::exception& e)
                            {
                                std::cerr << "[HttpServer Upload Error] " << e.what() << std::endl;
                                res.result(bhttp::status::internal_server_error);
                                res.set(bhttp::field::content_type, "application/json");
                                res.body() = R"({"success":false, "error":"Failed to upload image."})";
                                res.prepare_payload();
                            }
                        }
                    }
                }
                else if (req.target().starts_with("/cdn/"))
                {
                    if (req.method() != bhttp::verb::get)
                    {
                        res.result(bhttp::status::method_not_allowed);
                        res.set(bhttp::field::content_type, "text/plain");
                        res.body() = "405 Method Not Allowed";
                        res.prepare_payload();
                    }
                    else
                    {
                        try
                        {
                            std::string rawTarget = std::string(req.target());
                            size_t qPos = rawTarget.find('?');
                            std::string pathOnly = (qPos != std::string::npos) ? rawTarget.substr(0, qPos) : rawTarget;
                            std::string relPath = pathOnly.substr(5);

                            if (relPath.find("..") != std::string::npos)
                            {
                                res.result(bhttp::status::forbidden);
                                res.set(bhttp::field::content_type, "text/plain");
                                res.body() = "403 Forbidden";
                                res.prepare_payload();
                            }
                            else if (!IsAllowedImageExtension(relPath))
                            {
                                res.result(bhttp::status::not_found);
                                res.set(bhttp::field::content_type, "text/plain");
                                res.body() = "404 Not Found";
                                res.prepare_payload();
                            }
                            else
                            {
                                std::string filePath = "Storage/" + relPath;
                                if (boost::filesystem::exists(filePath) && !boost::filesystem::is_directory(filePath))
                                {
                                    std::ifstream ifs(filePath, std::ios::binary);
                                    if (ifs.is_open())
                                    {
                                        std::string content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
                                        res.result(bhttp::status::ok);
                                        res.set(bhttp::field::content_type, GetMimeType(filePath));
                                        res.set(bhttp::field::cache_control, "public, max-age=2592000");
                                        res.body() = std::move(content);
                                        res.prepare_payload();
                                    }
                                    else
                                    {
                                        res.result(bhttp::status::not_found);
                                        res.set(bhttp::field::content_type, "text/plain");
                                        res.body() = "404 Not Found";
                                        res.prepare_payload();
                                    }
                                }
                                else
                                {
                                    res.result(bhttp::status::not_found);
                                    res.set(bhttp::field::content_type, "text/plain");
                                    res.body() = "404 Not Found";
                                    res.prepare_payload();
                                }
                            }
                        }
                        catch (const std::exception& e)
                        {
                            std::cerr << "[HttpServer CDN Error] " << e.what() << std::endl;
                            res.result(bhttp::status::internal_server_error);
                            res.set(bhttp::field::content_type, "text/plain");
                            res.body() = "500 Internal Server Error";
                            res.prepare_payload();
                        }
                    }
                }
                else if (req.target() == "/graphql")
                {
                    if (req.method() != bhttp::verb::post)
                    {
                        res.result(bhttp::status::method_not_allowed);
                        res.set(bhttp::field::content_type, "application/json");
                        res.body() = R"({"errors":[{"message":"Method Not Allowed: /graphql accepts POST requests only."}]})";
                        res.prepare_payload();
                    }
                    else
                    {
                        try
                        {                       
                            std::string token = ExtractTokenFromRequest(req);
                            auto parsed = boost::json::parse(req.body());
                            std::string query;
                            boost::json::value variables = nullptr;

                            if (parsed.is_object())
                            {
                                auto const& obj = parsed.as_object();
                                if (obj.contains("query") && obj.at("query").is_string())
                                {
                                    query = std::string(obj.at("query").as_string());
                                }
                                if (obj.contains("variables"))
                                {
                                    variables = obj.at("variables");
                                }
                            }

                            boost::json::value resultVal;
                            if (gqlHandler)
                            {
                                resultVal = gqlHandler(query, variables);
                            }

                            res.result(bhttp::status::ok);
                            res.set(bhttp::field::content_type, "application/json");
                            res.body() = boost::json::serialize(resultVal);
                            res.prepare_payload();
                        }
                        catch (const std::exception& e)
                        {
                            std::cerr << "[HttpServer Error] Internal Exception: " << e.what() << std::endl;

                            res.result(bhttp::status::internal_server_error);
                            res.set(bhttp::field::content_type, "application/json");
                            res.body() = R"({"errors":[{"message":"Internal server error"}]})";
                            res.prepare_payload();
                        }
                    }
                }
                else
                {
                    res.result(bhttp::status::not_found);
                    res.set(bhttp::field::content_type, "application/json");
                    res.body() = R"({"error":"404 Not Found"})";
                    res.prepare_payload();
                }

                stream.expires_after(std::chrono::seconds(30));
                bhttp::write(stream, res, ec);
                if (ec) break;

                if (!req.keep_alive()) break;
            }

            stream.socket().shutdown(tcp::socket::shutdown_send, ec);
        }

        void AcceptLoop()
        {
            while (isRunning)
            {
                beast::error_code ec;
                tcp::socket socket{ioc};
                acceptor->accept(socket, ec);
                if (!ec && isRunning)
                {
                    asio::post(*workerPool, [this, sock = std::move(socket)]() mutable {
                        HandleSession(std::move(sock));
                    });
                }
            }
        }
    };

    HttpServer::HttpServer(GqlHandler gqlHandler, const std::string& host, unsigned short port, std::size_t maxBodySize, std::size_t threadPoolSize)
        : pImpl(std::make_unique<Impl>(std::move(gqlHandler), host, port, maxBodySize, threadPoolSize)) {}

    HttpServer::~HttpServer()
    {
        Stop();
    }

    void HttpServer::Start()
    {
        auto address = asio::ip::make_address(pImpl->host);
        pImpl->acceptor = std::make_unique<tcp::acceptor>(pImpl->ioc, tcp::endpoint{address, pImpl->port});
        pImpl->workerPool = std::make_unique<asio::thread_pool>(pImpl->threadPoolSize);
        pImpl->isRunning = true;

        std::cout << "[OmniNet::HttpServer] Secure HTTP Server listening on http://" << pImpl->host << ":" << pImpl->port
                  << " (Thread Pool: " << pImpl->threadPoolSize << " threads, Max Body: " << (pImpl->maxBodySize / (1024 * 1024)) << " MB)" << std::endl;

        pImpl->acceptorThread = std::thread([this]() {
            pImpl->AcceptLoop();
        });
    }

    void HttpServer::Stop()
    {
        if (pImpl->isRunning.exchange(false))
        {
            if (pImpl->acceptor)
            {
                beast::error_code ec;
                pImpl->acceptor->close(ec);
            }
            if (pImpl->workerPool)
            {
                pImpl->workerPool->join();
            }
            if (pImpl->acceptorThread.joinable())
            {
                pImpl->acceptorThread.join();
            }
        }
    }

} // namespace omnisphere::net
