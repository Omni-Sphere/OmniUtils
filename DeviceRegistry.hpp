#pragma once

#include <string>

namespace omnisphere::utils
{
    class DeviceRegistry
    {
    public:
        // Reads the Store and Node codes from the system registry.
        // Returns true if both are found, false otherwise.
        static bool GetRegistration(std::string& storeCode, std::string& nodeCode);

        // Saves the Store and Node codes to the system registry.
        static bool SaveRegistration(const std::string& storeCode, const std::string& nodeCode);

    private:
        static std::string GetRegistryPath();
    };
}
