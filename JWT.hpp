#pragma once

#include <string>
#include <map>
#include <cstdint>

#include "PayloadModel.hpp"

class JWT
{
public:
    static void SetJWTSecret(const std::string &);
    static PayloadModel ValidateToken(const std::string &);
    static std::string GenerateToken(const std::string&, const int &);
private:
    static inline std::string _secret{};
};
