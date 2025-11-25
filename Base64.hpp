#pragma once
#include <string>
#include <stdexcept>
#include <cctype>

class Base64 {
public:
    static void SetSecret(const std::string&);
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

    static inline std::string _secret{};

    static inline bool IsBase64(unsigned char);
    static std::string EncodeBase64(const std::string&);
    static std::string DecodeBase64(const std::string&);

    static std::string EncodeBase64Url(const std::string&);
    static std::string DecodeBase64Url(const std::string&);
};
