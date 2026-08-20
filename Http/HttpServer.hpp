#pragma once

#include "Request.hpp"
#include "Response.hpp"
#include "Router.hpp"
#include <memory>
#include <string>
#include <functional>
#include <boost/json.hpp>

namespace omnisphere::net
{
    using GqlHandler = std::function<boost::json::value(const std::string& query, const boost::json::value& variables)>;

    class HttpServer
    {
    public:
        HttpServer(
            std::shared_ptr<Router> router,
            const std::string& host = "0.0.0.0",
            unsigned short port = 8080,
            std::size_t maxBodySize = 10 * 1024 * 1024,
            std::size_t threadPoolSize = 0
        );

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
