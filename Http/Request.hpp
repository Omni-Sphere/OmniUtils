#pragma once

#include <string>
#include <unordered_map>
#include <map>
#include <boost/json.hpp>
#include <chrono>
#include <atomic>

namespace omnisphere::net
{
    class Request
    {
    public:
        Request() = default;

        void SetMethod(std::string m) { method = std::move(m); }
        void SetTarget(std::string t) { target = std::move(t); }
        void SetBody(std::string b) { body = std::move(b); }
        void SetHeader(std::string k, std::string v) { headers[std::move(k)] = std::move(v); }
        void SetParam(std::string k, std::string v) { pathParams[std::move(k)] = std::move(v); }
        void SetQueryParam(std::string k, std::string v) { queryParams[std::move(k)] = std::move(v); }
        void SetClientIP(std::string ip) { clientIp = std::move(ip); }
        void SetUserClaims(boost::json::object claims)
        {
            userClaims = std::move(claims);
            isAuthenticated = true;
        }

        const std::string& Method() const { return method; }
        const std::string& Target() const { return target; }
        const std::string& Body() const { return body; }
        bool IsAuthenticated() const { return isAuthenticated; }
        const boost::json::object& UserClaims() const { return userClaims; }
        const std::map<std::string, std::string>& Headers() const { return headers; }
        const std::unordered_map<std::string, std::string>& QueryParams() const { return queryParams; }

        std::string RequestId() const
        {
            std::string reqHeader = Header("X-Request-ID");
            if (reqHeader.empty()) reqHeader = Header("X-Correlation-ID");
            if (!reqHeader.empty()) return reqHeader;

            if (generatedRequestId.empty())
            {
                static std::atomic<uint64_t> s_counter{1000};
                auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count();
                generatedRequestId = "req_" + std::to_string(now) + "_" + std::to_string(++s_counter);
            }
            return generatedRequestId;
        }

        std::string ClientId() const
        {
            if (userClaims.contains("tenantId") && userClaims.at("tenantId").is_string())
                return std::string(userClaims.at("tenantId").as_string());
            if (userClaims.contains("client") && userClaims.at("client").is_string())
                return std::string(userClaims.at("client").as_string());
            std::string user = UserCode();
            if (!user.empty()) return user;
            return "DEFAULT";
        }

        std::string ClientIP() const
        {
            std::string xff = Header("X-Forwarded-For");
            if (!xff.empty())
            {
                size_t comma = xff.find(',');
                if (comma != std::string::npos)
                {
                    std::string firstIp = xff.substr(0, comma);
                    while (!firstIp.empty() && (firstIp.back() == ' ' || firstIp.back() == '\t')) firstIp.pop_back();
                    return firstIp;
                }
                return xff;
            }
            std::string realIp = Header("X-Real-IP");
            if (!realIp.empty()) return realIp;

            if (!clientIp.empty()) return clientIp;
            return "127.0.0.1";
        }

        std::string SanitizedClientIP() const
        {
            std::string raw = ClientIP();
            if (raw.empty() || raw == "unknown") return "127.0.0.1";
            std::string sanitized;
            sanitized.reserve(raw.size());
            for (char c : raw)
            {
                if (c == ':') sanitized.push_back('_');
                else if (std::isalnum(static_cast<unsigned char>(c)) || c == '.' || c == '-' || c == '_')
                    sanitized.push_back(c);
            }
            return sanitized.empty() ? "127.0.0.1" : sanitized;
        }

        std::string TraceContext() const
        {
            return "[ReqID: " + RequestId() + "] [IP: " + ClientIP() + "] [Client: " + ClientId() + "]";
        }

        std::string UserCode() const
        {
            if (userClaims.contains("sub") && userClaims.at("sub").is_string())
                return std::string(userClaims.at("sub").as_string());
            if (userClaims.contains("userCode") && userClaims.at("userCode").is_string())
                return std::string(userClaims.at("userCode").as_string());
            if (userClaims.contains("UserCode") && userClaims.at("UserCode").is_string())
                return std::string(userClaims.at("UserCode").as_string());
            return "";
        }

        std::string UserRole() const
        {
            if (userClaims.contains("role") && userClaims.at("role").is_string())
                return std::string(userClaims.at("role").as_string());
            if (userClaims.contains("RoleCode") && userClaims.at("RoleCode").is_string())
                return std::string(userClaims.at("RoleCode").as_string());
            if (userClaims.contains("roleCode") && userClaims.at("roleCode").is_string())
                return std::string(userClaims.at("roleCode").as_string());
            return "";
        }

        std::string Header(const std::string& key) const
        {
            auto it = headers.find(key);
            if (it != headers.end()) return it->second;

            for (const auto& [k, v] : headers)
            {
                if (k.size() == key.size())
                {
                    bool match = true;
                    for (size_t i = 0; i < key.size(); ++i)
                    {
                        if (std::tolower(static_cast<unsigned char>(k[i])) != std::tolower(static_cast<unsigned char>(key[i])))
                        {
                            match = false;
                            break;
                        }
                    }
                    if (match) return v;
                }
            }
            return "";
        }

        std::string Cookie(const std::string& name) const
        {
            std::string cookieHeader = Header("Cookie");
            if (cookieHeader.empty()) return "";

            size_t pos = 0;
            while (pos < cookieHeader.size())
            {
                while (pos < cookieHeader.size() && (cookieHeader[pos] == ' ' || cookieHeader[pos] == ';'))
                    ++pos;
                if (pos >= cookieHeader.size()) break;

                size_t eqPos = cookieHeader.find('=', pos);
                if (eqPos == std::string::npos) break;

                std::string k = cookieHeader.substr(pos, eqPos - pos);
                size_t semiPos = cookieHeader.find(';', eqPos);
                std::string v = (semiPos == std::string::npos) 
                    ? cookieHeader.substr(eqPos + 1) 
                    : cookieHeader.substr(eqPos + 1, semiPos - (eqPos + 1));

                if (k == name) return v;
                if (semiPos == std::string::npos) break;
                pos = semiPos + 1;
            }
            return "";
        }

        std::string Param(const std::string& key) const
        {
            auto it = pathParams.find(key);
            if (it != pathParams.end()) return it->second;
            return "";
        }

        std::string QueryParam(const std::string& key) const
        {
            auto it = queryParams.find(key);
            if (it != queryParams.end()) return it->second;
            return "";
        }

        boost::json::value Json() const
        {
            if (body.empty()) return nullptr;
            try {
                return boost::json::parse(body);
            } catch (...) {
                return nullptr;
            }
        }

    private:
        std::string method;
        std::string target;
        std::string body;
        std::map<std::string, std::string> headers;
        std::unordered_map<std::string, std::string> pathParams;
        std::unordered_map<std::string, std::string> queryParams;
        boost::json::object userClaims;
        bool isAuthenticated = false;
        mutable std::string generatedRequestId;
        std::string clientIp;
    };
} // namespace omnisphere::net
