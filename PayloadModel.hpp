#pragma once

#include <iostream>

struct PayloadModel
{
    uint64_t ExpiresAt;
    uint64_t IssuedAt;
    std::string SessionUUID;        
};
