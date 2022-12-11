#ifndef DETECTOR_HEADER
#define DETECTOR_HEADER

#include <fanotify_wrapper.h>
#include <sqlite/filedb.h>

// c++ include
#include <iostream>
#include <sstream>
#include <map>
#include <array>
#include <queue>
#include <chrono>
#include <fstream>

// c include
#include <limits.h>
#include <sys/types.h>
#include <signal.h>

namespace fn
{

/*
    Encryptor Detector class finds suspicious processes running on OS and tracks their activity using fanotify
    to find encryption viruses and terminate them
*/
class EncryptorDetector
{
    // FAN_CLASS_CONTENT - get event before user gets data
    // FAN_NONBLOCK - non blocking read from file
    // FAN_CLOEXEC - set this flag to newly opened files
    static constexpr unsigned m_fanotifyFlags = FAN_CLOEXEC | FAN_CLASS_CONTENT | FAN_NONBLOCK;
    // O_RDONLY - we do not modify files
    // O_LARGEFILE - enable support for big files
    static constexpr unsigned m_fanotifyEventFlags = O_RDONLY | O_LARGEFILE;

    // Flags that we pass to fanotify mark (events that we track)
    static constexpr std::array<uint64_t, 8> m_markFlagsArray = {
        FAN_ACCESS, 
        FAN_ACCESS_PERM, 
        FAN_MODIFY,
        FAN_OPEN,
        FAN_OPEN_PERM,
        FAN_CLOSE,
        FAN_CLOSE_NOWRITE,
        FAN_CLOSE_WRITE,
    };
    static constexpr unsigned m_markFlags = FAN_MARK_ADD | FAN_MARK_MOUNT;

    // Fanotify wrapper class that will be used to interact with fanotify C API
    FanotifyWrapper m_fanotify;
    // Mount point for fanotify
    std::string_view m_mount;

    // Event type enum is required because fanotify has, for example, FAN_ACCESS_PERM and FAN_ACCESS that are both EVENT_READ
    enum EventType
    {
        EVENT_READ,
        EVENT_WRITE,
        EVENT_OPEN,
        EVENT_CLOSE,
        EVENT_COUNT
    };
    
    // Maximum amount of all kind of suspicious operations
    // If any of events count exceeds maximum, it is considered suspicious
    static constexpr std::array<size_t, EVENT_COUNT> m_fileIOSuspect = {
        300, // EVENT_READ
        300, // EVENT_WRITE
    };
    // Maximum life time of each event stored (in millieseconds)
    static constexpr int64_t m_fileIOMaxAge = 150;
    static constexpr const char* m_fileDbPath = "/etc/synthmoza/fileDb.sqlite3";

    using time_point = std::chrono::time_point<std::chrono::high_resolution_clock>;
    using clock = std::chrono::high_resolution_clock;
    using ms = std::chrono::milliseconds;

    /*
        Proc Event struct describes certain event - its type and relative time it was added
    */
    struct ProcEvent
    {
        int type;
        time_point birth;
    };

    /*
        Proc Info struct describes all events of the certain proc - number of "alive" events (not outdated) and a queue if these events
    */
    struct ProcInfo
    {
        std::array<size_t, EVENT_COUNT> eventsCount;
        std::queue<ProcEvent> eventsQueue;
    };

    /*
        Map takes proc pid as a key and its value if Proc Info struct (described above)
        So, working with this map will be as follows:
        - remove outdated events
        - add all events on current iteration map:
            - add all events to the process queue
            - increment counters of each event
        - check if any of processes is suspicious
    */
    std::map<int, ProcInfo> m_pidEventMap;
    
    // File Data Base contains copies of files that have been opened for writing
    sqlite::FileDB m_fileDb;

    constexpr EventType FanotifyEventToIdx(size_t type);
    std::string StringizeEventType(size_t type);

    std::string GetFilenameByFd(int fd);
    
    void ProcessEvent(fanotify_event_metadata& event);
public:
    EncryptorDetector(const char* mount);
    
    void Launch();
};

}

#endif // #define DETECTOR_HEADER
