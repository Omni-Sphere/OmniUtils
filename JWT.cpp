#include "JWT.hpp"
#include "Base64.hpp"
#include <boost/json.hpp>
#include <ctime>
#include <iostream>
#include <sodium.h>
#include <sstream>
#include <stdexcept>

namespace omnisphere::utils {
boost::json::object JWT::ValidateToken(const std::string &token) {
  try {
    // 1. Format Validation
    size_t pos1 = token.find('.');
    size_t pos2 = token.rfind('.');

    if (pos1 == std::string::npos || pos2 == std::string::npos || pos1 == pos2)
      throw std::runtime_error(
          "Invalid token format: expected header.payload.signature");

    std::string header_b64 = token.substr(0, pos1);
    std::string payload_b64 = token.substr(pos1 + 1, pos2 - pos1 - 1);
    std::string signature_b64 = token.substr(pos2 + 1);

    std::string header_json = Base64::DecodeUrl(header_b64);
    std::string payload_json = Base64::DecodeUrl(payload_b64);
    std::string signature = Base64::DecodeUrl(signature_b64);

    // 2. Header / Algorithm Validation
    boost::json::value hjv = boost::json::parse(header_json);
    boost::json::object hobj = hjv.as_object();

    if (!hobj.contains("alg") ||
        boost::json::value_to<std::string>(hobj.at("alg")) != "HS256")
      throw std::runtime_error(
          "Unsupported or missing algorithm in header (HS256 required)");

    // 3. Signature Validation
    std::string signing_input = header_b64 + "." + payload_b64;

    unsigned char mac[crypto_auth_BYTES];
    crypto_auth_hmacsha256_state state;
    crypto_auth_hmacsha256_init(&state, (const unsigned char *)_secret.data(),
                                _secret.size());
    crypto_auth_hmacsha256_update(&state,
                                  (const unsigned char *)signing_input.data(),
                                  signing_input.size());
    crypto_auth_hmacsha256_final(&state, mac);

    if (signature.size() != crypto_auth_BYTES ||
        sodium_memcmp(signature.data(), mac, crypto_auth_BYTES) != 0)
      throw std::runtime_error("Invalid signature: authentication failed");

    // 4. Payload Parsing and Temporal Validation
    boost::json::value jv = boost::json::parse(payload_json);
    boost::json::object obj = jv.as_object();

    uint64_t now = std::time(nullptr);

    // Check for expiration (exp claim)
    if (obj.contains("exp")) {
      if (boost::json::value_to<uint64_t>(obj.at("exp")) < now)
        throw std::runtime_error("Token has expired");
    }
    // Compatibility with old ExpiresAt claim
    else if (obj.contains("ExpiresAt")) {
      if (boost::json::value_to<uint64_t>(obj.at("ExpiresAt")) < now)
        throw std::runtime_error("Token has expired");
    }

    return obj;
  } catch (const std::exception &e) {
    throw std::runtime_error(std::string("[JWT Validation Error]: ") +
                             e.what());
  }
}

std::string JWT::GenerateToken(const boost::json::object &payload,
                               const int &expiresInSeconds) {
  try {
    // Header
    boost::json::object header;
    header["alg"] = "HS256";
    header["typ"] = "JWT";
    std::string header_b64 = Base64::EncodeUrl(boost::json::serialize(header));

    // Payload
    boost::json::object final_payload = payload;
    uint64_t now = std::time(nullptr);

    // Add standard claims if not present
    if (!final_payload.contains("iat")) {
      final_payload["iat"] = now;
    }
    if (!final_payload.contains("exp") && expiresInSeconds > 0) {
      final_payload["exp"] = now + expiresInSeconds;
    }

    std::string payload_b64 =
        Base64::EncodeUrl(boost::json::serialize(final_payload));

    // Signing
    std::string signing_input = header_b64 + "." + payload_b64;

    unsigned char mac[crypto_auth_BYTES];
    crypto_auth_hmacsha256_state state;
    crypto_auth_hmacsha256_init(
        &state, reinterpret_cast<const unsigned char *>(_secret.data()),
        _secret.size());
    crypto_auth_hmacsha256_update(
        &state, reinterpret_cast<const unsigned char *>(signing_input.data()),
        signing_input.size());
    crypto_auth_hmacsha256_final(&state, mac);

    std::string signature(reinterpret_cast<const char *>(mac),
                          crypto_auth_BYTES);
    return signing_input + "." + Base64::EncodeUrl(signature);
  } catch (const std::exception &e) {
    throw std::runtime_error(std::string("[JWT Generation Error]: ") +
                             e.what());
  }
};

void JWT::SetJWTSecret(const std::string &secret) {
  if (secret.size() < 32)
    throw std::runtime_error("JWT secret must be at least 32 characters long");
  JWT::_secret = secret;
};
}