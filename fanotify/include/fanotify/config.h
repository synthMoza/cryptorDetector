#ifndef CONFIG_HEADER
#define CONFIG_HEADER

// c header
#include <sys/fanotify.h>
#include <fcntl.h>

// c++ header
#include <vector>
#include <string>
#include <fstream>
#include <filesystem>

#include <fanotify/fanotify_helpers.h>

namespace fn
{

struct Config
{
    unsigned fanotifyFlags;

    unsigned fanotifyEventFlags;
    // Flags that we pass to fanotify mark (events that we track)
    std::vector<ssize_t> markFlags;
    // Maximum amount of all kind of suspicious operations
    // If any of events count exceeds maximum, it is considered suspicious
    struct FileIOSuspect
    {
        unsigned reads;
        unsigned writes;
    } fileIOSuspect;
    
    // Maximum life time of each event stored (in millieseconds)
    int64_t fileIOMaxAge;
    std::string logPath;
    std::vector<std::string> whiteList;
};

Config GetConfig();
Config GetDaemonConfig();

};




#endif // #define CONFIG_HEADER
 