#include "Base64.hpp"
#include <vector>

namespace omnisphere::utils {
void Base64::SetSecret(const std::string& secret) 
{
    _secret = secret;
}

bool Base64::IsBase64(unsigned char c) {
    return (std::isalnum(c) || (c == '+') || (c == '/'));
}

std::string Base64::Encode(const std::string& input) 
{
    if (_secret.empty()) {
        throw std::runtime_error("Base64 secret no inicializado");
    }
    std::string obscured = _secret + input + _secret;
    return EncodeBase64(obscured);
}

std::string Base64::Decode(const std::string& encoded) 
{
    if (_secret.empty()) {
        throw std::runtime_error("Base64 secret no inicializado");
    }
    std::string decoded = DecodeBase64(encoded);

    size_t secretLen = _secret.length();
    if (decoded.length() < secretLen * 2) {
        throw std::runtime_error("Cadena Base64 inválida o dañada");
    }
    if (decoded.substr(0, secretLen) != _secret ||
        decoded.substr(decoded.length() - secretLen) != _secret) {
        throw std::runtime_error("Secreto no coincide al decodificar");
    }
    return decoded.substr(secretLen, decoded.length() - 2 * secretLen);
}

std::string Base64::EncodeUrl(const std::string& input) 
{
    return EncodeBase64Url(input);
}

std::string Base64::DecodeUrl(const std::string& encoded) 
{
    return DecodeBase64Url(encoded);
}

std::string Base64::EncodeBase64(const std::string& input) {
    unsigned int in_len = static_cast<unsigned int>(input.size());
    const unsigned char* bytes_to_encode = reinterpret_cast<const unsigned char*>(input.c_str());
    std::string ret;
    int i = 0;
    int j = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];

    while (in_len--) {
        char_array_3[i++] = *(bytes_to_encode++);
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for(i = 0; i < 4 ; i++)
                ret += base64_chars[char_array_4[i]];
            i = 0;
        }
    }

    if (i)
    {
        for(j = i; j < 3; j++)
            char_array_3[j] = '\0';

        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
        char_array_4[3] = char_array_3[2] & 0x3f;

        for (j = 0; j < i + 1; j++)
            ret += base64_chars[char_array_4[j]];

        while((i++ < 3))
            ret += '=';
    }

    return ret;
}

std::string Base64::DecodeBase64(const std::string& encoded_string) 
{
    int in_len = static_cast<int>(encoded_string.size());
    int i = 0;
    int j = 0;
    int in_ = 0;
    unsigned char char_array_4[4], char_array_3[3];
    std::string ret;

    while (in_len-- && (encoded_string[in_] != '=') && IsBase64(encoded_string[in_])) {
        char_array_4[i++] = static_cast<unsigned char>(encoded_string[in_]); in_++;
        if (i ==4) {
            for (i = 0; i <4; i++)
                char_array_4[i] = static_cast<unsigned char>(base64_chars.find(char_array_4[i]));

            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

            for (i = 0; i < 3; i++)
                ret += static_cast<char>(char_array_3[i]);
            i = 0;
        }
    }

    if (i) {
        for (j = i; j <4; j++)
            char_array_4[j] = 0;

        for (j = 0; j <4; j++)
            char_array_4[j] = static_cast<unsigned char>(base64_chars.find(char_array_4[j]));

        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
        char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
        char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

        for (j = 0; j < i - 1; j++)
            ret += static_cast<char>(char_array_3[j]);
    }

    return ret;
}

std::string Base64::EncodeBase64Url(const std::string& input) 
{
    std::string b64 = EncodeBase64(input);

    std::string ret;
    for(char c : b64) {
        if(c == '+') ret += '-';
        else if(c == '/') ret += '_';
        else if(c == '=') ;
        else ret += c;
    }
    return ret;
}

std::string Base64::DecodeBase64Url(const std::string& encoded) 
{
    std::string b64;
    for(char c : encoded) {
        if(c == '-') b64 += '+';
        else if(c == '_') b64 += '/';
        else b64 += c;
    }
    
    while(b64.size() % 4 != 0) b64 += '=';

    return DecodeBase64(b64);
}
}