#pragma once

#include "Request.hpp"
#include "Response.hpp"
#include <string>
#include <vector>
#include <functional>
#include <memory>

namespace omnisphere::net
{
    using HandlerFunc = std::function<Response(const Request& req)>;
    using MiddlewareFunc = std::function<bool(const Request& req, Response& outResponse)>;
    using AuthCheckerFunc = std::function<bool(const Request& req, const std::vector<std::string>& roles, Response& outErrorResponse)>;

    struct RouteEntry
    {
        std::string method;        // "GET", "POST", "PUT", "DELETE", "*"
        std::string pathPattern;   // "/health", "/whatsapp/webhook", "/cdn/*", "/users/:id"
        HandlerFunc handler;
        bool isAuthorized = false;
        std::vector<std::string> requiredRoles;
    };

    class Router
    {
    public:
        Router() = default;

        // Middlewares globales y Auth Checker
        void Use(MiddlewareFunc middleware);
        void SetAuthorizationChecker(AuthCheckerFunc checker);

        // Rutas Estándar (Públicas)
        void Get(const std::string& pathPattern, HandlerFunc handler);
        void Post(const std::string& pathPattern, HandlerFunc handler);
        void Put(const std::string& pathPattern, HandlerFunc handler);
        void Delete(const std::string& pathPattern, HandlerFunc handler);
        void Any(const std::string& pathPattern, HandlerFunc handler);

        // Rutas Protegidas por JWT / Autorización (Estilo @Authorized())
        void GetAuthorized(const std::string& pathPattern, HandlerFunc handler, std::vector<std::string> requiredRoles = {});
        void PostAuthorized(const std::string& pathPattern, HandlerFunc handler, std::vector<std::string> requiredRoles = {});
        void PutAuthorized(const std::string& pathPattern, HandlerFunc handler, std::vector<std::string> requiredRoles = {});
        void DeleteAuthorized(const std::string& pathPattern, HandlerFunc handler, std::vector<std::string> requiredRoles = {});

        Response Dispatch(Request& req) const;

    private:
        std::vector<RouteEntry> m_routes;
        std::vector<MiddlewareFunc> m_middlewares;
        AuthCheckerFunc m_authChecker;

        static bool MatchRoute(const std::string& pattern, const std::string& target, Request& req);
    };
} // namespace omnisphere::net
