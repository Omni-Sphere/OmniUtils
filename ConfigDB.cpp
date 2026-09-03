#include "ConfigDB.hpp"
#include "Base64.hpp"
#include "PathUtils.hpp"
#include <boost/filesystem.hpp>
#include <fstream>
#include <iostream>
#include "Logger.hpp"

namespace omnisphere::utils
{
    namespace fs = boost::filesystem;

    ConfigDB::ConfigDB()
    {
        std::filesystem::path exeDir = GetExecutableDir();
        _configDir = (exeDir / "Config").string();
        _configPath = (exeDir / "Config" / "ConfigDB.json").string();
    }

    void ConfigDB::Initialize()
    {
        try
        {
            if (!fs::exists(_configDir))
            {
                if (fs::create_directory(_configDir))
                {
                    Logger::LogSystem(LogType::INFO, "ConfigDB", "Created directory: " + _configDir);
                }
            }

            if (!fs::exists(_configPath))
            {
                createDefaultConfig();
                Logger::LogSystem(LogType::INFO, "ConfigDB", "Created default config file: " + _configPath);
            }
        }
        catch (const fs::filesystem_error &e)
        {
            Logger::LogSystem(LogType::ERROR, "ConfigDB", "Filesystem error: " + std::string(e.what()));
        }
        catch (const std::exception &e)
        {
            Logger::LogSystem(LogType::ERROR, "ConfigDB", "General error: " + std::string(e.what()));
        }
    }

    bool ConfigDB::Exists() const
    {
        std::lock_guard<std::mutex> lock(_mutex);

        if (_loaded)
            return true; // If loaded, it exists (even if empty)
        return fs::exists(_configPath);
    }

    void ConfigDB::SaveConfig(const std::string &server, const std::string &user,
                              const std::string &password,
                              const std::string &database, bool trustCertificate,
                              bool trustedConnection, int dbEngine, unsigned short apiPort)
    {
        std::lock_guard<std::mutex> lock(_mutex);
        try
        {
            boost::json::object config;
            config["Server"] = Base64::Encode(server);
            config["User"] = Base64::Encode(user);
            config["Password"] = Base64::Encode(password);
            config["Database"] = Base64::Encode(database);
            config["TrustCertificate"] = trustCertificate;
            config["TrustedConnection"] = trustedConnection;
            config["DatabaseEngine"] = dbEngine;
            config["APIPort"] = apiPort;

            std::ofstream ofs(_configPath);

            if (ofs.is_open())
            {
                ofs << boost::json::serialize(config);
                // Update cache
                _cache = config;
                _loaded = true;
            }
        }
        catch (const std::exception &e)
        {
            Logger::LogSystem(LogType::ERROR, "ConfigDB", "Error saving config: " + std::string(e.what()));
        }
    }

    void ConfigDB::createDefaultConfig()
    { 
        SaveConfig("", "", "", "OmniPOS", true, false, 1, 8080); 
    }

    boost::json::object ConfigDB::GetConfig() const
{
    std::lock_guard<std::mutex> lock(_mutex);

    if (_loaded)
    {
        return _cache;
    }

    try
    {
        std::ifstream ifs(_configPath);
        if (!ifs.is_open())
        {
            return {};
        }

        std::string content((std::istreambuf_iterator<char>(ifs)),
                            std::istreambuf_iterator<char>());

        auto value = boost::json::parse(content);
        boost::json::object rawConfig = value.as_object();


        boost::json::object cleanConfig = rawConfig;

        if (rawConfig.contains("Server") && rawConfig.at("Server").is_string())
            cleanConfig["Server"] = Base64::Decode(rawConfig.at("Server").as_string().c_str());
            
        if (rawConfig.contains("User") && rawConfig.at("User").is_string())
            cleanConfig["User"] = Base64::Decode(rawConfig.at("User").as_string().c_str());
            
        if (rawConfig.contains("Password") && rawConfig.at("Password").is_string())
            cleanConfig["Password"] = Base64::Decode(rawConfig.at("Password").as_string().c_str());
            
        if (rawConfig.contains("Database") && rawConfig.at("Database").is_string())
            cleanConfig["Database"] = Base64::Decode(rawConfig.at("Database").as_string().c_str());

        _cache = cleanConfig;
        _loaded = true;

        return _cache;
    }
    catch (const std::exception &e)
    {
        Logger::LogSystem(LogType::ERROR, "ConfigDB", "Error reading config: " + std::string(e.what()));
        return {};
    }
}

} // namespace omnisphere::utils
