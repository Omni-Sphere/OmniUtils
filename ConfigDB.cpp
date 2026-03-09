#include "ConfigDB.hpp"
#include <boost/filesystem.hpp>
#include <fstream>
#include <iostream>

namespace omnisphere::utils {

namespace fs = boost::filesystem;

ConfigDB::ConfigDB() {
  _configDir = "Config";
  _configPath = _configDir + "/ConfigDB.json";
}

void ConfigDB::Initialize() {
  try {
    if (!fs::exists(_configDir)) {
      if (fs::create_directory(_configDir)) {
        std::cout << "Created directory: " << _configDir << std::endl;
      }
    }

    if (!fs::exists(_configPath)) {
      createDefaultConfig();
      std::cout << "Created default config file: " << _configPath << std::endl;
    }
  } catch (const fs::filesystem_error &e) {
    std::cerr << "Filesystem error: " << e.what() << std::endl;
  } catch (const std::exception &e) {
    std::cerr << "General error: " << e.what() << std::endl;
  }
}

bool ConfigDB::Exists() const { return fs::exists(_configPath); }

boost::json::object ConfigDB::GetConfig() const {
  try {
    std::ifstream ifs(_configPath);
    if (!ifs.is_open()) {
      return {};
    }

    std::string content((std::istreambuf_iterator<char>(ifs)),
                        std::istreambuf_iterator<char>());

    auto value = boost::json::parse(content);
    return value.as_object();
  } catch (const std::exception &e) {
    std::cerr << "Error reading config: " << e.what() << std::endl;
    return {};
  }
}

void ConfigDB::SaveConfig(const std::string &server,
                          const std::string &user,
                          const std::string &password, bool trustCertificate,
                          bool trustedConnection) {
  try {
    boost::json::object config;
    config["Server"] = server;
    config["User"] = user;
    config["Password"] = password;
    config["TrustCertificate"] = trustCertificate;
    config["TrustedConnection"] = trustedConnection;

    std::ofstream ofs(_configPath);
    if (ofs.is_open()) {
      ofs << boost::json::serialize(config);
    }
  } catch (const std::exception &e) {
    std::cerr << "Error saving config: " << e.what() << std::endl;
  }
}

void ConfigDB::createDefaultConfig() {
  SaveConfig("", "", "", true, false);
}

} // namespace omnisphere::utils
