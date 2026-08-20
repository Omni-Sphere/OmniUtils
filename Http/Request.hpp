#pragma once

#include <string>
#include <unordered_map>
#include <map>
#include <boost/json.hpp>

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

        std::string UserCode() const
        {
            if (userClaims.contains("code") && userClaims.at("code").is_string())
                return std::string(userClaims.at("code").as_string());
            if (userClaims.contains("userCode") && userClaims.at("userCode").is_string())
                return std::string(userClaims.at("userCode").as_string());
            if (userClaims.contains("sub") && userClaims.at("sub").is_string())
                return std::string(userClaims.at("sub").as_string());
            return "";
        }

        std::string UserRole() const
        {
            if (userClaims.contains("role") && userClaims.at("role").is_string())
                return std::string(userClaims.at("role").as_string());
            return "";
        }

        std::string Header(const std::string& key) const
        {
            auto it = headers.find(key);
            if (it != headers.end()) return it->second;
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
    };
} // namespace omnisphere::net
