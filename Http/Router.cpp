#include "Router.hpp"
#include "JWT.hpp"
#include <sstream>
#include <iostream>
#include <algorithm>

namespace omnisphere::net
{
    void Router::Use(MiddlewareFunc middleware)
    {
        m_middlewares.push_back(std::move(middleware));
    }

    void Router::SetAuthorizationChecker(AuthCheckerFunc checker)
    {
        m_authChecker = std::move(checker);
    }

    void Router::Get(const std::string& pathPattern, HandlerFunc handler)
    {
        m_routes.push_back({"GET", pathPattern, std::move(handler), false, {}});
    }

    void Router::Post(const std::string& pathPattern, HandlerFunc handler)
    {
        m_routes.push_back({"POST", pathPattern, std::move(handler), false, {}});
    }

    void Router::Put(const std::string& pathPattern, HandlerFunc handler)
    {
        m_routes.push_back({"PUT", pathPattern, std::move(handler), false, {}});
    }

    void Router::Delete(const std::string& pathPattern, HandlerFunc handler)
    {
        m_routes.push_back({"DELETE", pathPattern, std::move(handler), false, {}});
    }

    void Router::Any(const std::string& pathPattern, HandlerFunc handler)
    {
        m_routes.push_back({"*", pathPattern, std::move(handler), false, {}});
    }

    void Router::GetAuthorized(const std::string& pathPattern, HandlerFunc handler, std::vector<std::string> requiredRoles)
    {
        m_routes.push_back({"GET", pathPattern, std::move(handler), true, std::move(requiredRoles)});
    }

    void Router::PostAuthorized(const std::string& pathPattern, HandlerFunc handler, std::vector<std::string> requiredRoles)
    {
        m_routes.push_back({"POST", pathPattern, std::move(handler), true, std::move(requiredRoles)});
    }

    void Router::PutAuthorized(const std::string& pathPattern, HandlerFunc handler, std::vector<std::string> requiredRoles)
    {
        m_routes.push_back({"PUT", pathPattern, std::move(handler), true, std::move(requiredRoles)});
    }

    void Router::DeleteAuthorized(const std::string& pathPattern, HandlerFunc handler, std::vector<std::string> requiredRoles)
    {
        m_routes.push_back({"DELETE", pathPattern, std::move(handler), true, std::move(requiredRoles)});
    }

    bool Router::MatchRoute(const std::string& pattern, const std::string& target, Request& req)
    {
        std::string pathOnly = target;
        size_t queryPos = target.find('?');
        if (queryPos != std::string::npos)
        {
            pathOnly = target.substr(0, queryPos);
            std::string queryString = target.substr(queryPos + 1);
            std::stringstream ss(queryString);
            std::string item;
            while (std::getline(ss, item, '&'))
            {
                size_t eqPos = item.find('=');
                if (eqPos != std::string::npos)
                {
                    req.SetQueryParam(item.substr(0, eqPos), item.substr(eqPos + 1));
                }
                else
                {
                    req.SetQueryParam(item, "");
                }
            }
        }

        if (!pattern.empty() && pattern.back() == '*')
        {
            std::string prefix = pattern.substr(0, pattern.size() - 1);
            if (pathOnly.rfind(prefix, 0) == 0)
            {
                return true;
            }
        }

        if (pattern == pathOnly)
        {
            return true;
        }

        std::stringstream pStream(pattern);
        std::stringstream tStream(pathOnly);
        std::string pSeg, tSeg;

        while (std::getline(pStream, pSeg, '/') && std::getline(tStream, tSeg, '/'))
        {
            if (pSeg.empty() && tSeg.empty()) continue;
            if (!pSeg.empty() && pSeg.front() == ':')
            {
                std::string paramKey = pSeg.substr(1);
                req.SetParam(paramKey, tSeg);
            }
            else if (pSeg != tSeg)
            {
                return false;
            }
        }

        return pStream.eof() && tStream.eof();
    }

    Response Router::Dispatch(Request& req) const
    {
        // 1. Extracción e inspección automática de JWT Token gestionada nativamente por OmniUtils
        std::string authHeader = req.Header("Authorization");
        std::string token;
        if (authHeader.rfind("Bearer ", 0) == 0 || authHeader.rfind("bearer ", 0) == 0)
        {
            token = authHeader.substr(7);
        }
        else
        {
            token = authHeader;
        }
        if (token.empty())
        {
            token = req.QueryParam("token");
        }

        if (!token.empty())
        {
            try
            {
                auto claims = omnisphere::utils::JWT::ValidateToken(token);
                req.SetUserClaims(claims);
            }
            catch (...)
            {
                // Token inválido o expirado
            }
        }

        // 2. Ejecutar middlewares globales primero
        for (const auto& mw : m_middlewares)
        {
            Response mwResponse;
            if (!mw(req, mwResponse))
            {
                return mwResponse;
            }
        }

        bool pathMatched = false;

        for (const auto& route : m_routes)
        {
            if (MatchRoute(route.pathPattern, req.Target(), req))
            {
                pathMatched = true;
                if (route.method == "*" || route.method == req.Method())
                {
                    // 3. Verificar autorización si la ruta la requiere (@Authorized)
                    if (route.isAuthorized)
                    {
                        if (m_authChecker)
                        {
                            Response authError;
                            if (!m_authChecker(req, route.requiredRoles, authError))
                            {
                                return authError;
                            }
                        }
                        else
                        {
                            // Verificación nativa automática de JWT en OmniUtils
                            if (!req.IsAuthenticated())
                            {
                                return Response(401, "application/json", R"({"error":"Unauthorized: Missing or invalid JWT Bearer token."})");
                            }

                            if (!route.requiredRoles.empty())
                            {
                                std::string userRole = req.UserRole();
                                bool hasRole = false;
                                for (const auto& r : route.requiredRoles)
                                {
                                    if (r == userRole) { hasRole = true; break; }
                                }
                                if (!hasRole)
                                {
                                    return Response(403, "application/json", R"({"error":"Forbidden: Insufficient role privileges."})");
                                }
                            }
                        }
                    }

                    // 4. Ejecutar el handler de la ruta
                    return route.handler(req);
                }
            }
        }

        if (pathMatched)
        {
            return Response::MethodNotAllowed(R"({"error":"405 Method Not Allowed"})");
        }

        return Response::NotFound(R"({"error":"404 Not Found"})");
    }
} // namespace omnisphere::net
