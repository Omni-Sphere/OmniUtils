#include "JWT.hpp"
#include "Base64.hpp"
#include <sodium.h>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <boost/json.hpp>

PayloadModel JWT::ValidateToken(const std::string &token)
{
    try
    {
        std::cout << "Token recibido Longitud (" << token.size() << "): '" << token << "'\n";

        size_t pos1 = token.find('.');
        size_t pos2 = token.rfind('.');

        if (pos1 == std::string::npos || pos2 == std::string::npos || pos1 == pos2)
            throw std::runtime_error("Invalid token format");

        std::string header_b64 = token.substr(0, pos1);
        std::string payload_b64 = token.substr(pos1 + 1, pos2 - pos1 - 1);
        std::string signature_b64 = token.substr(pos2 + 1);

        std::string header_json = Base64::DecodeUrl(header_b64);
        std::string payload_json = Base64::DecodeUrl(payload_b64);
        std::string signature = Base64::DecodeUrl(signature_b64);

        std::string signing_input = header_b64 + "." + payload_b64;

        unsigned char mac[crypto_auth_BYTES];
        crypto_auth_hmacsha256_state state;
        crypto_auth_hmacsha256_init(&state, (const unsigned char *)_secret.data(), _secret.size());
        crypto_auth_hmacsha256_update(&state, (const unsigned char *)signing_input.data(), signing_input.size());
        crypto_auth_hmacsha256_final(&state, mac);

        if (signature.size() != crypto_auth_BYTES || sodium_memcmp(signature.data(), mac, crypto_auth_BYTES) != 0)
            throw std::runtime_error("Invalid signature");

        boost::json::value jv = boost::json::parse(payload_json);
        boost::json::object obj = jv.as_object();

        if (!obj.contains("IssuedAt") || !obj.contains("ExpiresAt") || !obj.contains("SessionUUID") /* || !obj.contains("apikey") */)
            throw std::runtime_error("Missing parameters in the header");

        uint64_t now = std::time(nullptr);

        if (obj["ExpiresAt"].as_int64() < now)
            throw std::runtime_error("Expired token");

        PayloadModel payload{
            static_cast<uint64_t>(obj["IssuedAt"].as_int64()),
            static_cast<uint64_t>(obj["ExpiresAt"].as_int64()),
            boost::json::value_to<std::string>(obj["SessionUUID"]),
        };

        return payload;
    }
    catch (const std::exception &e)
    {
        throw std::runtime_error(std::string("[ValidateToken Exception]: ") + e.what());
    }
}

std::string JWT::GenerateToken(const std::string &sessionUUID, const int &expiresInSeconds)
{
    try
    {
        boost::json::object header;
        header["alg"] = "HS256";
        header["typ"] = "JWT";
        std::string header_json = boost::json::serialize(header);
        std::string header_b64 = Base64::EncodeUrl(header_json);

        boost::json::object payload;
        std::cout << "Generate token: " << sessionUUID;

        payload["SessionUUID"] = sessionUUID;
        payload["IssuedAt"] = static_cast<int64_t>(std::time(nullptr));
        payload["ExpiresAt"] = static_cast<int64_t>(std::time(nullptr) + expiresInSeconds);

        std::string payload_json = boost::json::serialize(payload);
        std::string payload_b64 = Base64::EncodeUrl(payload_json);

        std::string signing_input = header_b64 + "." + payload_b64;

        unsigned char mac[crypto_auth_BYTES];
        crypto_auth_hmacsha256_state state;
        crypto_auth_hmacsha256_init(&state, reinterpret_cast<const unsigned char *>(_secret.data()), _secret.size());
        crypto_auth_hmacsha256_update(&state, reinterpret_cast<const unsigned char *>(signing_input.data()), signing_input.size());
        crypto_auth_hmacsha256_final(&state, mac);

        std::string signature(reinterpret_cast<const char *>(mac), crypto_auth_BYTES);
        std::string signature_b64 = Base64::EncodeUrl(signature);

        return signing_input + "." + signature_b64;
    }
    catch (const std::exception &e)
    {
        throw std::runtime_error(std::string("[GenerateToken Exception]: ") + e.what());
    }
};

void JWT::SetJWTSecret(const std::string &secret)
{
    JWT::_secret = secret;
};