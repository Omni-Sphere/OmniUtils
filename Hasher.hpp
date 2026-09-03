#pragma once

#include <sodium.h>
#include <vector>
#include <string>
#include <cstring>
#include <stdexcept>
#include <iostream>

namespace omnisphere::utils
{
    class Hasher
    {
        public:
        static void Initialize();
        static std::vector<uint8_t> HashPassword(const std::string& password);
        static bool VerifyPassword(const std::string& password, const std::vector<uint8_t>& hash);
        static std::vector<uint8_t> HashStringGeneric(const std::string& input);
        static std::string HmacSha256(const std::string& data, const std::string& key);
    };
}