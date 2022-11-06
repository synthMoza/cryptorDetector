#include <encrypt.h>

#include <iostream>
#include <sstream>
#include <string_view>

int main(int argc, char* argv[])
{
    if (argc != 3)
    {
        std::cerr << "Usage: ./encryptor <path> <key>" << std::endl;
        return -1;
    }

    // read key
    uint32_t key = 0;
    std::stringstream stringStream(argv[1]);
    stringStream >> key;

    if (stringStream.fail())
    {
        std::cerr << "Error converting " << argv[1] << " to integer value, check if it is valid" << std::endl;
        return -1;
    }

    fn::Encryptor encryptor(key);
    encryptor.Encrypt(argv[2]);
    
    return 0;
}