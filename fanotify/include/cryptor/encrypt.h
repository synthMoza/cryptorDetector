#ifndef ENCRYPT_HEADER
#define ENCRYPT_HEADER

#include <string>

namespace fn
{

/*
    Encryptor class allows to encrypt files or directories recursively
*/
class Encryptor final
{
    // block size to read/write file by blocks
    static const uint32_t m_blockSize = 1024;
    uint32_t m_key;

    /*
        Encrypt given file
        @param fileName file name (recursive or absolute path)
    */
    void EncryptFile(const std::string& fileName);

    /*
        Encrypt given directory recursively
        @param dirName directory name (recursive or absolute path)
    */
    void EncryptDirectory(const std::string& dirName);
public:
    /*
        Initialize encryptor with the given key. It will be used to encrypt/decrypt data
    */
    Encryptor(uint32_t key) :
        m_key(key) {}

    /*
        Encrypt given file/directory. Directories are encrypted recursively.
        Original files are deleted after the encryption, and they are replaced
        with file with the subfix ".ecnrypted".

        @param name path to the file/directory
    */
    void Encrypt(const std::string& name);
};

}

#endif // #define ENCRYPT_HEADER
