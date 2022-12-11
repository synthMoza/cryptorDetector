#include <encrypt.h>

// c includes
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

// c++ includes
#include <array>
#include <vector>
#include <filesystem>
#include <stdexcept>

using namespace fn;

void Encryptor::EncryptFile(const std::string& fileName)
{
    /*
        Write & read operations on the same file are quite tricky in C++. WE write this program for linux, so
        to carefully encrypt file, use low-level C operations instead of file streams in C++
    */
    std::array<char, m_blockSize> buffer;    

    int inputFd = open(fileName.c_str(), O_RDONLY);
    if (inputFd < 0)
        throw std::runtime_error("Can't open requested file");
    
    int outputFd = open(fileName.c_str(), O_WRONLY);
    if (outputFd < 0)
        throw std::runtime_error("Can't open requested file");

    // read by block
    ssize_t readBytes = 0;
    while ((readBytes = read(inputFd, buffer.data(), m_blockSize)) > 0)
    {
        // encrypt
        for (ssize_t i = 0; i < readBytes; ++i)
            buffer[i] ^= m_key;
        
        ssize_t writtenBytes = write(outputFd, buffer.data(), readBytes);
        if (writtenBytes < 0)
            throw std::runtime_error("Error while encrypting - can't write to the file");
    }

    if (readBytes < 0)
        throw std::runtime_error("Error while encrypting - can't read from the file");

    close(inputFd);
    close(outputFd);
}

void Encryptor::EncryptDirectory(const std::string& dirName)
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

void Encryptor::Encrypt(const std::string& name)
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
