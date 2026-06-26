#include "DeviceRegistry.hpp"
#include "Base64.hpp"
#include <fstream>
#include <filesystem>
#include <cstdlib>
#include <iostream>

namespace omnisphere::utils
{
    std::string DeviceRegistry::GetRegistryPath()
    {
        std::string path;
        const char* home = std::getenv("HOME");
        if (home)
        {
            path = std::string(home) + "/.config/omnicafe";
        }
        else
        {
            path = "/var/lib/omnicafe";
        }
        
        // Ensure directory exists
        std::filesystem::create_directories(path);
        
        return path + "/registry.bin";
    }

    bool DeviceRegistry::GetRegistration(std::string& storeCode, std::string& nodeCode)
    {
        std::string path = GetRegistryPath();
        std::ifstream file(path);
        if (!file.is_open())
            return false;

        std::string encoded;
        std::getline(file, encoded);
        file.close();

        if (encoded.empty())
            return false;

        std::string decoded = Base64::Decode(encoded);
        size_t sep = decoded.find('|');
        if (sep == std::string::npos)
            return false;

        storeCode = decoded.substr(0, sep);
        nodeCode = decoded.substr(sep + 1);

        return true;
    }

    bool DeviceRegistry::SaveRegistration(const std::string& storeCode, const std::string& nodeCode)
    {
        std::string plain = storeCode + "|" + nodeCode;
        std::string encoded = Base64::Encode(plain);

        std::string path = GetRegistryPath();
        std::ofstream file(path);
        if (!file.is_open())
            return false;

        file << encoded;
        file.close();

        return true;
    }
}
