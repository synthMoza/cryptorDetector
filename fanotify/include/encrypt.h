#ifndef ENCRYPT_HEADER
#define ENCRYPT_HEADER

#include <vector>
#include <fstream>
#include <filesystem>

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
    void EncryptFile(std::string fileName)
    {
        std::vector<char> buffer(m_blockSize); 
        std::ifstream fileInput(fileName);
        std::ofstream fileOutput(fileName + ".encrypted");

        // read by block
        size_t readBytes = 0;
        while ((readBytes = fileInput.read(buffer.data(), m_blockSize).gcount()) > 0)
        {

            // encrypt
            for (size_t i = 0; i < readBytes; ++i)
                buffer[i] ^= m_key;
            
            // write
            fileOutput.write(buffer.data(), readBytes);
            if (fileOutput.bad())
            {
                std::string errorText("Error writing to file ");
                errorText += fileName.data();
                throw std::runtime_error(errorText);
            }
        }

        fileInput.close();
        fileOutput.close();

        // delete original file
        std::filesystem::remove(fileName.data());
    }

    /*
        Encrypt given directory recursively
        @param dirName directory name (recursive or absolute path)
    */
    void EncryptDirectory(std::string dirName)
    {
        using directory_iterator = std::filesystem::directory_iterator;
        for (auto& directoryEntry : directory_iterator(dirName))
        {
            if (directoryEntry.is_directory())
                EncryptDirectory(directoryEntry.path());
            else if (directoryEntry.is_regular_file())
                EncryptFile(directoryEntry.path());
        }
    }
public:
    /*
        Initialize encryptor with the given key. It will be used to encrypt/decrypt data
    */
    Encryptor(uint32_t key) :
        m_key(key) {}

    /*
        Encrypt given file/directory. DIrectories are encrypted recursively.
        Original files are deleted after the encryption, and they are replaced
        with file with the subfix ".ecnrypted".

        @param name path to the file/directory
    */
    void Encrypt(std::string name)
    {
        // check for existence, throw exception if doesn't exist
        if (!std::filesystem::exists(name))
        {
            std::string errorText("Can't access path: ");
            errorText += name;
            throw std::runtime_error(errorText);
        }

        if (std::filesystem::is_directory(name))
        {
            EncryptDirectory(name);
        }    
        else if (std::filesystem::is_regular_file(name))
        {
            EncryptFile(name);
        }
        else
        {
            std::string errorText("Given path is nor a file neither a directory: ");
            errorText += name;
            throw std::runtime_error(errorText);
        }
    }
};

}

#endif // #define ENCRYPT_HEADER
