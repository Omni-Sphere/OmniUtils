#pragma once

#include <filesystem>
#include <string>

#if defined(_WIN32)
#include <windows.h>
#elif defined(__APPLE__)
#include <mach-o/dyld.h>
#elif defined(__linux__)
#include <unistd.h>
#include <limits.h>
#endif

namespace omnisphere::utils
{
    /**
     * @brief Returns the absolute path of the directory containing the running executable binary.
     * Fallback to current_path() if detection fails.
     */
    inline std::filesystem::path GetExecutableDir()
    {
        try
        {
#if defined(_WIN32)
            wchar_t path[MAX_PATH];
            DWORD count = GetModuleFileNameW(NULL, path, MAX_PATH);
            if (count > 0 && count < MAX_PATH)
            {
                return std::filesystem::path(path).parent_path();
            }
#elif defined(__linux__)
            char path[PATH_MAX];
            ssize_t count = ::readlink("/proc/self/exe", path, sizeof(path) - 1);
            if (count > 0)
            {
                path[count] = '\0';
                return std::filesystem::path(path).parent_path();
            }
            if (std::filesystem::exists("/proc/self/exe"))
            {
                return std::filesystem::canonical("/proc/self/exe").parent_path();
            }
#elif defined(__APPLE__)
            char path[1024];
            uint32_t size = sizeof(path);
            if (_NSGetExecutablePath(path, &size) == 0)
            {
                return std::filesystem::canonical(path).parent_path();
            }
#endif
        }
        catch (...)
        {
        }
        return std::filesystem::current_path();
    }
}
