#include <cryptor/encrypt.h>

#include <iostream>
#include <sstream>
#include <string_view>

constexpr uint32_t g_encryptKey = 0xdeadbeef;

int main(int argc, char* argv[])
{
    if (argc != 2)
    {
        std::cerr << "Usage: ./encryptor <path>" << std::endl;
        return -1;
    }

    fn::Encryptor encryptor(g_encryptKey);
    encryptor.Encrypt(argv[1]);
    
    return 0;
}