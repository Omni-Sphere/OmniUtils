#pragma once

#include <sodium.h>
#include <vector>
#include <string>
#include <cstring>
#include <stdexcept>
#include <iostream>

class Hasher {
public:
    static void Initialize();
    static std::vector<uint8_t> HashPassword(const std::string& password);
    static bool VerifyPassword(const std::string& password, const std::vector<uint8_t>& hash);
    static std::vector<uint8_t> HashStringGeneric(const std::string& input);
};
