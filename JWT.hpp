#pragma once

#include <boost/json.hpp>
#include <string>


class JWT {
public:
  static void SetJWTSecret(const std::string &);
  static boost::json::object ValidateToken(const std::string &);
  static std::string GenerateToken(const boost::json::object &, const int &);

private:
  static inline std::string _secret{};
};
