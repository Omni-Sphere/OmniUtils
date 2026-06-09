#include <ConfigDB.hpp>
#include <Base64.hpp>
#include <boost/filesystem.hpp>
#include <fstream>
#include <iostream>
#include <Logger.hpp>

namespace omnisphere::utils
{
    namespace fs = boost::filesystem;

    ConfigDB::ConfigDB()
    {
        _configDir = "Config";
        _configPath = _configDir + "/ConfigDB.json";
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
            _cache = value.as_object();
            _loaded = true;

            return _cache;
        }
        catch (const std::exception &e)
        {
            Logger::LogSystem(LogType::ERROR, "ConfigDB", "Error reading config: " + std::string(e.what()));

            return {};
        }
    }

    void ConfigDB::SaveConfig(const std::string &server, const std::string &user,
                              const std::string &password,
                              const std::string &database, bool trustCertificate,
                              bool trustedConnection, int dbEngine)
    {
        std::lock_guard<std::mutex> lock(_mutex);
        try
        {
            boost::json::object config;
            config["Server"] = server;
            config["User"] = user;
            config["Password"] = password;
            config["Database"] = database;
            config["TrustCertificate"] = trustCertificate;
            config["TrustedConnection"] = trustedConnection;
            config["DatabaseEngine"] = dbEngine;

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

    { SaveConfig("", "", "", "OmniPOS", true, false, 1); }

    std::string ConfigDB::GetConnectionString() const
    {
        auto config = GetConfig();

        if (config.empty())
        {
            return "";
        }

        int engine = 1;

        if (config.contains("DatabaseEngine"))
        {
            engine = static_cast<int>(config.at("DatabaseEngine").as_int64());
        }

        auto safeDecode = [](const std::string& input) -> std::string
        {
            if (input.empty()) return "";
            try
            {
                return Base64::Decode(input);
            }
            catch (...)
            {
                // If it's not base64 or doesn't have our secret, it's probably plain text

                return input;
            }
        };

        std::string server = safeDecode(config.contains("Server") ? config.at("Server").as_string().c_str() : "");
        std::string user = safeDecode(config.contains("User") ? config.at("User").as_string().c_str() : "");
        std::string password = safeDecode(config.contains("Password") ? config.at("Password").as_string().c_str() : "");
        std::string database = config.contains("Database") ? config.at("Database").as_string().c_str() : "OmniPOS";

        if (database.empty()) database = "OmniPOS";
        bool trustCert = config.contains("TrustCertificate") ? config.at("TrustCertificate").as_bool() : true;
        bool trustedConn = config.contains("TrustedConnection") ? config.at("TrustedConnection").as_bool() : false;

        if (engine == 1)
        {
            std::string conn = "Driver={ODBC Driver 18 for SQL Server};Server=" + server + ";";

            if (!database.empty()) conn += "Database=" + database + ";";
            if (trustedConn)
            {
                conn += "Trusted_Connection=yes;";
            }
            else
            {
                conn += "Uid=" + user + ";Pwd=" + password + ";";
            }
            conn += "TrustServerCertificate=" + std::string(trustCert ? "yes" : "no") + ";";

            return conn;
        }
        else if (engine == 2)
        {
            std::string conn = "Driver={MySQL ODBC 9.4 Driver};Server=" + server + ";";

            if (!database.empty()) conn += "Database=" + database + ";";
            conn += "User=" + user + ";Password=" + password + ";";

            return conn;
        }

        return "";
    }

} // namespace omnisphere::utils
