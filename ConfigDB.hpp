#pragma once

#include <boost/json.hpp>
#include <string>

namespace omnisphere::utils {

class ConfigDB {
public:
  ConfigDB();
  ~ConfigDB() = default;

  void Initialize();
  bool Exists() const;
  boost::json::object GetConfig() const;
  void SaveConfig(const std::string &server, const std::string &user,
                  const std::string &password, bool trustCertificate,
                  bool trustedConnection);

private:
  std::string _configPath;
  std::string _configDir;

  void createDefaultConfig();
};

} // namespace omnisphere::utils
