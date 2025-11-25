#include <sodium.h>
#include <sstream>
#include <iomanip>

class UUIDv4
{
public:
    static std::string GenerateUUIDv4()
    {

        unsigned char uuid[16];

        randombytes_buf(uuid, sizeof(uuid));

        uuid[6] = (uuid[6] & 0x0F) | 0x40;
        uuid[8] = (uuid[8] & 0x3F) | 0x80;

        std::ostringstream oss;

        oss << std::hex << std::setfill('0');

        for (int i = 0; i < 16; ++i)
        {
            oss << std::setw(2) << static_cast<int>(uuid[i]);
            if (i == 3 || i == 5 || i == 7 || i == 9)
                oss << "-";
        };

        return oss.str();
    };
};