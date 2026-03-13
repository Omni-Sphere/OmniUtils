#pragma once
#include <string>
#include <stdexcept>
#include <cctype>

namespace omnisphere::utils {
class Base64 {
public:
    static inline const std::string _secretString = "_.:._0mn15ph3r3_.:._";
    static inline const std::string _secretJWT = "_.:._0mn15ph3r3JWT_.:._";

    static std::string Encode(const std::string&);
    static std::string Decode(const std::string&);
    static std::string EncodeUrl(const std::string&);
    static std::string DecodeUrl(const std::string&);

private:
    static inline const std::string base64_chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";

    static inline const std::string base64url_chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789-_";

    static inline bool IsBase64(unsigned char c) {
        return (isalnum(c) || (c == '+') || (c == '/'));
    }
    static std::string EncodeBase64(const std::string&);
    static std::string DecodeBase64(const std::string&);

    static std::string EncodeBase64Url(const std::string&);
    static std::string DecodeBase64Url(const std::string&);
};
}