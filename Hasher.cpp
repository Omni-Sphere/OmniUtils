#include "Hasher.hpp"

namespace omnisphere::utils {
void Hasher::Initialize()
{
    if (sodium_init() < 0)
    {
        throw std::runtime_error("Error al inicializar libsodium");
    }
};

std::vector<uint8_t> Hasher::HashPassword(const std::string &password)
{
    std::vector<uint8_t> hash(crypto_pwhash_STRBYTES);

    if (crypto_pwhash_str(
            reinterpret_cast<char *>(hash.data()),
            password.c_str(),
            password.length(),
            crypto_pwhash_OPSLIMIT_INTERACTIVE,
            crypto_pwhash_MEMLIMIT_INTERACTIVE) != 0)
    {
        throw std::runtime_error("Error al generar hash de la contraseña");
    }

    return hash;
};

bool Hasher::VerifyPassword(const std::string &password, const std::vector<uint8_t> &hash)
{
    try
    {
        if (hash.size() != crypto_pwhash_STRBYTES)
            throw std::invalid_argument("Tamaño de hash inválido");

        try
        {           
            std::string hashStr(reinterpret_cast<const char *>(hash.data()), strnlen(reinterpret_cast<const char *>(hash.data()), hash.size()));

            return crypto_pwhash_str_verify(hashStr.c_str(), password.c_str(), password.length()) == 0;

        }
        catch(const std::exception& e)
        {
            throw std::runtime_error(std::string("[Verificación de contraseña] ") + e.what());
        }

    }
    catch (const std::exception &e)
    {
        throw std::runtime_error(std::string("[Hasher exception] ") + e.what());
    }
}

std::vector<uint8_t> Hasher::HashStringGeneric(const std::string &input)
{
    std::vector<uint8_t> hash(crypto_generichash_BYTES);

    if (crypto_generichash(hash.data(), hash.size(), reinterpret_cast<const unsigned char *>(input.data()), input.size(), nullptr, 0) != 0)
    {
        throw std::runtime_error("Error al generar hash genérico");
    }

    return hash;
};
}