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

#include "JWT.hpp"
#include "../Logger.hpp"

namespace beast = boost::beast;
namespace bhttp = boost::beast::http;
namespace asio = boost::asio;
using tcp = asio::ip::tcp;

namespace omnisphere::net
{
    struct HttpServer::Impl
    {
        std::shared_ptr<Router> router;
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

        Impl(std::shared_ptr<Router> r, const std::string& h, unsigned short p, std::size_t bodyLimit, std::size_t poolSize)
            : router(std::move(r)), host(h), port(p), maxBodySize(bodyLimit), threadPoolSize(poolSize)
        {
            if (threadPoolSize == 0)
            {
                threadPoolSize = std::max<std::size_t>(2, std::thread::hardware_concurrency());
            }
        }

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
                
                if (ec == bhttp::error::end_of_stream || ec == beast::error::timeout || ec)
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

                if (req.method() == bhttp::verb::options)
                {
                    res.result(bhttp::status::no_content);
                    res.prepare_payload();
                }
                else if (router)
                {
                    Request netReq;
                    netReq.SetMethod(method);
                    netReq.SetTarget(target);
                    netReq.SetBody(req.body());

                    for (auto const& field : req)
                    {
                        netReq.SetHeader(std::string(field.name_string()), std::string(field.value()));
                    }

                    Response netRes = router->Dispatch(netReq);

                    res.result(static_cast<bhttp::status>(netRes.StatusCode()));
                    res.set(bhttp::field::content_type, netRes.ContentType());
                    for (const auto& [hdrK, hdrV] : netRes.Headers())
                    {
                        res.set(hdrK, hdrV);
                    }
                    res.body() = netRes.Body();
                    res.prepare_payload();
                }
                else if (target == "/graphql" && req.method() == bhttp::verb::post)
                {
                    try
                    {
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
                        res.result(bhttp::status::internal_server_error);
                        res.set(bhttp::field::content_type, "application/json");
                        res.body() = R"({"errors":[{"message":"Internal server error"}]})";
                        res.prepare_payload();
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

    HttpServer::HttpServer(std::shared_ptr<Router> router, const std::string& host, unsigned short port, std::size_t maxBodySize, std::size_t threadPoolSize)
        : pImpl(std::make_unique<Impl>(std::move(router), host, port, maxBodySize, threadPoolSize)) {}

    HttpServer::HttpServer(GqlHandler gqlHandler, const std::string& host, unsigned short port, std::size_t maxBodySize, std::size_t threadPoolSize)
        : pImpl(std::make_unique<Impl>(std::move(gqlHandler), host, port, maxBodySize, threadPoolSize)) {}

    HttpServer::~HttpServer()
    {
        Stop();
    }

    void HttpServer::Start()
    {
        auto address = asio::ip::make_address(pImpl->host);
        tcp::endpoint endpoint{address, pImpl->port};

        pImpl->acceptor = std::make_unique<tcp::acceptor>(pImpl->ioc);

        beast::error_code ec;
        pImpl->acceptor->open(endpoint.protocol(), ec);
        if (ec)
        {
            std::string errStr = "Failed to open socket on " + pImpl->host + ":" + std::to_string(pImpl->port) + " (" + ec.message() + ")";
            omnisphere::utils::Logger::LogError("HttpServer", errStr);
            throw std::runtime_error(errStr);
        }

        pImpl->acceptor->set_option(asio::socket_base::reuse_address(true), ec);

        pImpl->acceptor->bind(endpoint, ec);
        if (ec)
        {
            std::string errStr = "Cannot bind to " + pImpl->host + ":" + std::to_string(pImpl->port) + " - Port is already in use by another process or permission denied. (" + ec.message() + ")";
            omnisphere::utils::Logger::LogError("HttpServer", errStr);
            throw std::runtime_error(errStr);
        }

        pImpl->acceptor->listen(asio::socket_base::max_listen_connections, ec);
        if (ec)
        {
            std::string errStr = "Failed to listen on " + pImpl->host + ":" + std::to_string(pImpl->port) + " (" + ec.message() + ")";
            omnisphere::utils::Logger::LogError("HttpServer", errStr);
            throw std::runtime_error(errStr);
        }

        pImpl->workerPool = std::make_unique<asio::thread_pool>(pImpl->threadPoolSize);
        pImpl->isRunning = true;

        std::cout << "\033[32m[OmniNet::HttpServer] Router HTTP Server listening on http://" << pImpl->host << ":" << pImpl->port
                  << " (Thread Pool: " << pImpl->threadPoolSize << " threads)\033[0m" << std::endl;

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
