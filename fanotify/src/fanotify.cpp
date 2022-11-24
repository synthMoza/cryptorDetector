#include <fanotify_wrapper.h>

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

using namespace fn;

#ifdef DEBUG
#include <tracer.h>
    // Use tracer for debug purposes only
    static Tracer g_tracer;

    #define TRACE(message) g_tracer.Trace(message, __PRETTY_FUNCTION__, __LINE__);
#else
    #define TRACE(message) // do nothing
#endif

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
    static constexpr std::array<uint64_t, 5> m_markFlagsArray = {FAN_ACCESS, FAN_ACCESS_PERM, FAN_MODIFY};
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
    
    constexpr EventType FanotifyEventToIdx(size_t type)
    {
        switch (type)
        {
            case FAN_ACCESS:
            case FAN_ACCESS_PERM:
                return EVENT_READ;
            case FAN_MODIFY:
                return EVENT_WRITE;
            default:
                return EVENT_COUNT; // error
        }
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
            default:
                return "";
        }
    }

    void ProcessEvent(fanotify_event_metadata& event)
    {
        #ifdef DEBUG
            std::stringstream stream;
            stream << "Event caught! info: ";
        #endif

        for (auto& id : m_markFlagsArray)
        {
            if (IsEvent(event, id))
            {
                // log event info into console
                if (id == FAN_OPEN_PERM || id == FAN_ACCESS_PERM)
                    m_fanotify.ResponseAllow(event);

                #ifdef DEBUG
                    stream << "type = " << StringizeEventType(id) << ": " << std::endl;
                    stream << "file = " << GetFilenameByFd(event.fd) << ", PID = " << event.pid << std::endl;

                    if (event.pid != getpid()) // do not generate infinite amount of logs
                        TRACE(stream.str().c_str());
                #endif

                // log this event into map
                auto& procInfo = m_pidEventMap[event.pid];
                procInfo.eventsCount[FanotifyEventToIdx(id)]++;
                procInfo.eventsQueue.push({FanotifyEventToIdx(id), clock::now()});
            }
        }

        close(event.fd);
    }
public:
    EncryptorDetector(const char* mount) :
        m_fanotify(m_fanotifyFlags, m_fanotifyEventFlags),
        m_mount(mount),
        m_pidEventMap() {}
    
    void Launch()
    {
        uint64_t markMask = 0;
        for (auto& flag : m_markFlagsArray)
            markMask |= flag;
        
        m_fanotify.Mark(m_markFlags, markMask, AT_FDCWD, m_mount.data());

        // set up main loop
        std::cout << "Starting the program... To finish the program, press enter." << std::endl;
        while (m_fanotify.WaitForEvent())
        {
            // check for outdated events
            for (auto& pair : m_pidEventMap)
            {
                auto& currentQueue = pair.second.eventsQueue;
                while (currentQueue.size() > 0)
                {
                    auto frontTimeAlive = std::chrono::duration_cast<ms>(clock::now() - currentQueue.front().birth).count();
                    if (frontTimeAlive < m_fileIOMaxAge)
                        break;
                    else
                    {
                        // TRACE("Remove element!");
                        pair.second.eventsCount[currentQueue.front().type]--;
                        currentQueue.pop();
                    }
                }
            }

            // proccess all events
            auto events = m_fanotify.GetEvents();
            if (events.IsEmpty())
                continue ; // all events for this iteration are processed

            for (auto& event : events)
            {
                if (event.vers != FANOTIFY_METADATA_VERSION)
                    throw std::runtime_error("mismatch of fanotify metadata version");
                
                if (event.fd == 0)
                {
                    TRACE("Overflow detected!");
                    throw std::overflow_error("Event queue overflow!");
                }

                ProcessEvent(event);
            }

            // check for suspicious pids
            std::vector<int> pidsToRemove;
            pidsToRemove.reserve(m_pidEventMap.size());
            for (auto& [pid, procInfo] : m_pidEventMap)
            {
                if (procInfo.eventsCount[EVENT_READ] >= m_fileIOSuspect[EVENT_READ] &&
                    procInfo.eventsCount[EVENT_WRITE] >= m_fileIOSuspect[EVENT_WRITE])
                {
                    TRACE("Suspicious pid has been found");

                    // kill this pid
                    TRACE("Killing suspicious pid...");
                    kill(pid, SIGKILL);

                    TRACE("Suspicious pid has been killed successfully");
                    std::cout << "Suspicious pid " << pid << " has been terminated" << std::endl;
                    pidsToRemove.push_back(pid);
                }
            }

            for (auto& pid : pidsToRemove)
                m_pidEventMap.erase(pid);
        }

        std::cout << "Finishing the program..." << std::endl;
    }
};


int main(int argc, char* argv[])
{
    if (argc != 2)
    {
        std::cerr << "Usage: ./fanotify <mount>" << std::endl;
        return -1;
    }

    try
    {
        EncryptorDetector detector(argv[1]);
        detector.Launch();
    }
    catch (const std::exception& e)
    {
        std::cerr << "Caught exception from EncryptorDetector: " << e.what() << std::endl;
        return -1;
    }
    
    return 0;
}
