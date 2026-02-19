#pragma once

#include <iostream>

namespace omnisphere::utils::models {

struct PayloadModel
{
    uint64_t ExpiresAt;
    uint64_t IssuedAt;
    std::string SessionUUID;        
};
}