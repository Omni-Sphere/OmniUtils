#pragma once

#include <string>
#include <map>
#include <boost/json.hpp>

namespace omnisphere::net
{
    class Response
    {
    public:
        Response(int statusCode = 200, std::string contentType = "application/json", std::string body = "")
            : m_statusCode(statusCode), m_contentType(std::move(contentType)), m_body(std::move(body)) {}

        int StatusCode() const { return m_statusCode; }
        const std::string& ContentType() const { return m_contentType; }
        const std::string& Body() const { return m_body; }
        const std::map<std::string, std::string>& Headers() const { return m_headers; }

        Response& Status(int code)
        {
            m_statusCode = code;
            return *this;
        }

        Response& Header(std::string key, std::string value)
        {
            m_headers[std::move(key)] = std::move(value);
            return *this;
        }

        static Response Json(const boost::json::value& jsonVal, int status = 200)
        {
            return Response(status, "application/json", boost::json::serialize(jsonVal));
        }

        static Response Text(const std::string& text, int status = 200)
        {
            return Response(status, "text/plain", text);
        }

        static Response Html(const std::string& html, int status = 200)
        {
            return Response(status, "text/html", html);
        }

        static Response NotFound(const std::string& message = R"({"error":"404 Not Found"})")
        {
            return Response(404, "application/json", message);
        }

        static Response MethodNotAllowed(const std::string& message = R"({"error":"405 Method Not Allowed"})")
        {
            return Response(405, "application/json", message);
        }

        static Response BadRequest(const std::string& message = R"({"error":"400 Bad Request"})")
        {
            return Response(400, "application/json", message);
        }

        static Response InternalError(const std::string& message = R"({"error":"500 Internal Server Error"})")
        {
            return Response(500, "application/json", message);
        }

    private:
        int m_statusCode = 200;
        std::string m_contentType = "application/json";
        std::string m_body;
        std::map<std::string, std::string> m_headers;
    };
} // namespace omnisphere::net
