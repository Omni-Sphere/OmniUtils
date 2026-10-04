#include "Router.hpp"
#include "JWT.hpp"
#include "Logger.hpp"
#include <sstream>
#include <iostream>
#include <algorithm>
#include <chrono>

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

        // Normalize trailing slashes for path matching
        if (pathOnly.length() > 1 && pathOnly.back() == '/')
        {
            pathOnly.pop_back();
        }
        std::string normPattern = pattern;
        if (normPattern.length() > 1 && normPattern.back() == '/')
        {
            normPattern.pop_back();
        }

        if (!normPattern.empty() && normPattern.back() == '*')
        {
            std::string prefix = normPattern.substr(0, normPattern.size() - 1);
            if (pathOnly.rfind(prefix, 0) == 0)
            {
                return true;
            }
        }

        if (normPattern == pathOnly)
        {
            return true;
        }

        std::stringstream pStream(normPattern);
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
        auto startTime = std::chrono::steady_clock::now();

        // 0. Establecer ámbito de contexto por hilo (RequestId, ClientIP, User, Client)
        omnisphere::utils::RequestContextScope scope(req.RequestId(), req.ClientIP(), req.UserCode(), req.ClientId());

        // Registrar de forma automática la petición HTTP recibida en Logger (archivo net_<hora>.log)
        omnisphere::utils::Logger::LogHttpRequest(req);

        auto finalizeResponse = [&](Response resp) -> Response
        {
            auto endTime = std::chrono::steady_clock::now();
            long long durationMs = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count();
            omnisphere::utils::Logger::LogHttpResponse(req, resp, durationMs);
            return resp;
        };

        // 1. Extracción e inspección automática de JWT Token gestionada nativamente por OmniUtils
        // Estándar Dual Formal:
        //   Canal A (M2M / Mobile / SDK / CLI): Cabecera estándar RFC 6750 ("Authorization: Bearer <token>")
        //   Canal B (Web / Navegador): Cookie de sesión segura HttpOnly ("Cookie: authToken=<token>")
        std::string token;
        const std::string authHeader = req.Header("Authorization");
        if (authHeader.rfind("Bearer ", 0) == 0 || authHeader.rfind("bearer ", 0) == 0)
        {
            token = authHeader.substr(7);
        }
        else
        {
            // Extraer de cookie de sesión Web si no se provee cabecera RFC 6750
            token = req.Cookie("authToken");
        }

        if (!token.empty())
        {
            try
            {
                auto claims = omnisphere::utils::JWT::ValidateToken(token);
                req.SetUserClaims(claims);
                // Actualizar contexto con la identidad autenticada
                omnisphere::utils::Logger::SetCurrentContext({req.RequestId(), req.ClientIP(), req.UserCode(), req.ClientId()});
            }
            catch (const std::exception& e)
            {
                std::cerr << "[OmniUtils Router Auth] Token validation failed: " << e.what() << std::endl;
            }
            catch (...)
            {
                std::cerr << "[OmniUtils Router Auth] Unknown exception during token validation" << std::endl;
            }
        }

        // 2. Ejecutar middlewares globales primero
        for (const auto& mw : m_middlewares)
        {
            Response mwResponse;
            if (!mw(req, mwResponse))
            {
                return finalizeResponse(mwResponse);
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
                                return finalizeResponse(authError);
                            }
                        }
                        else
                        {
                            // Verificación nativa automática de JWT en OmniUtils
                            if (!req.IsAuthenticated())
                            {
                                return finalizeResponse(Response(401, "application/json", R"({"error":"Unauthorized: Missing or invalid JWT Bearer token."})"));
                            }
                        }
                    }

                    // 4. Ejecutar el handler de la ruta
                    return finalizeResponse(route.handler(req));
                }
            }
        }

        if (pathMatched)
        {
            omnisphere::utils::Logger::LogWarning("Router", req.TraceContext() + " HTTP 405 Method Not Allowed: " + req.Method() + " " + req.Target());
            return finalizeResponse(Response::MethodNotAllowed(R"({"error":"405 Method Not Allowed"})"));
        }

        omnisphere::utils::Logger::LogWarning("Router", req.TraceContext() + " HTTP 404 Not Found: " + req.Method() + " " + req.Target());
        return finalizeResponse(Response::NotFound(R"({"error":"404 Not Found"})"));
    }
} // namespace omnisphere::net
