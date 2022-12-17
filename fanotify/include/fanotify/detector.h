#ifndef DETECTOR_HEADER
#define DETECTOR_HEADER

#include <fanotify/fanotify_wrapper.h>
#include <fanotify/fanotify_helpers.h>
#include <fanotify/config.h>
#include <sqlite/filedb.h>
#include <tracer/tracer.h>

// c++ include
#include <iostream>
#include <sstream>
#include <map>
#include <array>
#include <queue>
#include <chrono>
#include <fstream>
#include <vector>

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
    using time_point = std::chrono::time_point<std::chrono::high_resolution_clock>;
    using clock = std::chrono::high_resolution_clock;
    using ms = std::chrono::milliseconds;

    static constexpr unsigned m_markFlags = FAN_MARK_ADD | FAN_MARK_MOUNT;

    Tracer m_tracer;
    // Current config of detector
    Config m_config;

    // Fanotify wrapper class that will be used to interact with fanotify C API
    FanotifyWrapper m_fanotify;
    // Mount point for fanotify
    std::string_view m_mount;

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
    // White list - list of paths to binaries that must not be considered as suspicious
    std::vector<std::string> m_whiteList;

    void ProcessEvent(fanotify_event_metadata& event);
    void CheckForOutdatedEvents();
    void ProcessEvents();
    void CheckForSuspiciousPids();
public:
    EncryptorDetector(const char* mount, const Config& cfg);
    void Launch();
    ~EncryptorDetector() {}
};

}

#endif // #define DETECTOR_HEADER
