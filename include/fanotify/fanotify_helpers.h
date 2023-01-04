#ifndef FANOTIFY_HELPERS_HEADER
#define FANOTIFY_HELPERS_HEADER

// c includes
#include <sys/fanotify.h>
#include <fcntl.h>
#include <limits.h>

// c++ includes
#include <string>

namespace fn
{

// Event type enum is required because fanotify has, for example, FAN_ACCESS_PERM and FAN_ACCESS that are both EVENT_READ
enum EventType
{
    EVENT_READ,
    EVENT_WRITE,
    EVENT_OPEN,
    EVENT_CLOSE,
    EVENT_COUNT
};

EventType FanotifyEventToIdx(size_t type);

std::string GetFilenameByPid(int pid);

std::string StringizeEventType(size_t type);

ssize_t StringToEventType(const std::string& str);

ssize_t StringToFanotifyFlag(const std::string& str);

ssize_t StringToEventFlag(const std::string& str);

ssize_t StringToMarkFlag(const std::string& str);

std::string GetFilenameByFd(int fd);

}

#endif // #define FANOTIFY_HELPERS_HEADER
