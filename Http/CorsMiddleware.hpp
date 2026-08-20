#pragma once

#include <string>
#include <map>
#include <boost/beast/http.hpp>

namespace omnisphere::net
{
    class CorsMiddleware
    {
    public:
        static void ApplyCorsHeaders(std::map<std::string, std::string>& headers, const std::string& allowedOrigin = "*")
        {
            headers["Access-Control-Allow-Origin"] = allowedOrigin;
            headers["Access-Control-Allow-Methods"] = "POST, GET, OPTIONS";
            headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-Requested-With, X-File-Name, X-File-Path";
            headers["Access-Control-Max-Age"] = "86400";
            headers["X-Content-Type-Options"] = "nosniff";
            headers["X-Frame-Options"] = "DENY";
            headers["X-XSS-Protection"] = "1; mode=block";
            headers["Referrer-Policy"] = "strict-origin-when-cross-origin";
            headers["Server"] = "OmniServer";
        }

        template <typename Response>
        static void ApplySecurityHeaders(Response& res, const std::string& allowedOrigin = "*")
        {
            res.set(boost::beast::http::field::access_control_allow_origin, allowedOrigin);
            res.set(boost::beast::http::field::access_control_allow_methods, "POST, GET, OPTIONS");
            res.set(boost::beast::http::field::access_control_allow_headers, "Content-Type, Authorization, X-Requested-With, X-File-Name, X-File-Path");
            res.set(boost::beast::http::field::server, "OmniServer");
            res.set("X-Content-Type-Options", "nosniff");
            res.set("X-Frame-Options", "DENY");
            res.set("X-XSS-Protection", "1; mode=block");
            res.set("Referrer-Policy", "strict-origin-when-cross-origin");
        }
    };
} // namespace omnisphere::net
