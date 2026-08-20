#pragma once

#include <memory>
#include <string>
#include <functional>
#include <boost/json.hpp>

namespace omnisphere::net
{
    using GqlHandler = std::function<boost::json::value(const std::string& query, const boost::json::value& variables)>;
    using RouteHandler = std::function<std::string(const std::string& method, const std::string& target, const std::string& body)>;

    class HttpServer
    {
    public:
        HttpServer(
            GqlHandler gqlHandler,
            const std::string& host = "0.0.0.0",
            unsigned short port = 8080,
            std::size_t maxBodySize = 10 * 1024 * 1024,
            std::size_t threadPoolSize = 0
        );

        ~HttpServer();

        void Start();
        void Stop();

    private:
        struct Impl;
        std::unique_ptr<Impl> pImpl;
    };
} // namespace omnisphere::net
