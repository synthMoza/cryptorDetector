#include <fanotify_helpers.h>

// c++ include
#include <sstream>
#include <stdexcept>

// c include
#include <unistd.h>

namespace fn
{

EventType FanotifyEventToIdx(size_t type)
{
    switch (type)
    {
        case FAN_ACCESS:
        case FAN_ACCESS_PERM:
            return EVENT_READ;
        case FAN_MODIFY:
            return EVENT_WRITE;
        case FAN_OPEN:
        case FAN_OPEN_PERM:
        case FAN_OPEN_EXEC:
            return EVENT_OPEN;
        case FAN_CLOSE:
        case FAN_CLOSE_NOWRITE:
        case FAN_CLOSE_WRITE:
            return EVENT_CLOSE;
        default:
            return EVENT_COUNT; // error
    }
}

std::string StringizeEventType(size_t type)
{
    switch (type)
    {
        case FAN_ACCESS:
            return "FAN_ACCESS";
        case FAN_MODIFY:
            return "FAN_MODIFY";
        case FAN_ACCESS_PERM:
            return "FAN_ACCESS_PERM";
        case FAN_OPEN:
            return "FAN_OPEN";
        case FAN_OPEN_PERM:
            return "FAN_OPEN_PERM";
        case FAN_CLOSE:
            return "FAN_CLOSE";
        case FAN_CLOSE_NOWRITE:
            return "FAN_CLOSE_NOWRITE";
        case FAN_CLOSE_WRITE:
            return "FAN_CLOSE_WRITE";
        default:
            return "";
    }
}

ssize_t StringToEventType(const std::string& str)
{
    if (str == "FAN_ACCESS")
        return FAN_ACCESS;
    if (str == "FAN_MODIFY") 
        return FAN_MODIFY;
    if (str == "FAN_ACCESS_PERM")
        return FAN_ACCESS_PERM;
    if (str == "FAN_OPEN")
        return FAN_OPEN;
    if (str == "FAN_OPEN_PERM")
        return FAN_OPEN_PERM;
    if (str == "FAN_CLOSE")
        return FAN_CLOSE;
    if (str == "FAN_CLOSE_NOWRITE")
        return FAN_CLOSE_NOWRITE;
    if (str == "FAN_CLOSE_WRITE")
        return FAN_CLOSE_WRITE;

    return -1;
}

ssize_t StringToFanotifyFlag(const std::string& str)
{
    if (str == "FAN_CLOEXEC")
        return FAN_CLOEXEC;
    if (str == "FAN_CLASS_CONTENT")
        return FAN_CLASS_CONTENT;
    if (str == "FAN_NONBLOCK")
        return FAN_NONBLOCK;
    
    return -1;
}

ssize_t StringToEventFlag(const std::string& str)
{
    if (str == "O_RDONLY")
        return O_RDONLY;
    if (str == "O_LARGEFILE")
        return O_LARGEFILE;
    
    return -1;  
}

ssize_t StringToMarkFlag(const std::string& str)
{
    if (str == "FAN_OPEN")
        return FAN_OPEN;
    if (str == "FAN_OPEN_PERM")
        return FAN_OPEN_PERM;
    if (str == "FAN_CLOSE")
        return FAN_CLOSE;
    if (str == "FAN_CLOSE_NOWRITE")
        return FAN_CLOSE_NOWRITE;
    if (str == "FAN_CLOSE_WRITE")
        return FAN_CLOSE_WRITE;
    if (str == "FAN_OPEN_EXEC")
        return FAN_OPEN_EXEC;
    
    return -1;
}

std::string GetFilenameByFd(int fd)
{
    std::stringstream filePath;

    filePath << "/proc/self/fd/" << fd;

    std::string fileName(PATH_MAX, ' ');
    auto pathLen = readlink(filePath.str().c_str(), fileName.data(), fileName.size());
    if (pathLen < 0)
        throw std::runtime_error("readlink error");
    
    fileName.resize(pathLen);
    return fileName;
}

std::string GetFilenameByPid(int pid)
{
    std::stringstream filePath;

    filePath << "/proc/" << pid << "/exe";

    std::string fileName(PATH_MAX, ' ');
    auto pathLen = readlink(filePath.str().c_str(), fileName.data(), fileName.size());
    if (pathLen < 0)
        throw std::runtime_error("readlink error");
    
    fileName.resize(pathLen);
    return fileName;
}

}
