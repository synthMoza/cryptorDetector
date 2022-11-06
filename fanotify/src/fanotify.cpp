#include <fanotify_wrapper.h>

// c++ include
#include <iostream>
#include <sstream>
#include <map>

// c include
#include <limits.h>
#include <sys/types.h>
#include <signal.h>

using namespace fn;

class EncryptorDetector
{
    // FAN_CLASS_CONTENT - get event before user gets data
    // FAN_NONBLOCK - non blocking read from file
    static constexpr unsigned m_fanotifyFlags = FAN_CLOEXEC | FAN_CLASS_CONTENT | FAN_NONBLOCK;
    // O_RDONLY - we do not modify files
    // O_LARGEFILE - enable support for big files
    static constexpr unsigned m_fanotifyEventFlags = O_RDONLY | O_LARGEFILE;

    static constexpr unsigned m_markFlags = FAN_MARK_ADD | FAN_MARK_MOUNT;
    static constexpr uint64_t m_markMask = FAN_OPEN | FAN_OPEN_PERM | FAN_ACCESS | FAN_ACCESS_PERM | FAN_MODIFY;    
    static constexpr std::array<uint64_t, 5> m_markFlagsArray = {FAN_OPEN, FAN_OPEN_PERM, FAN_ACCESS, FAN_ACCESS_PERM, FAN_MODIFY};

    // Value to monitor suspicious processes that open/read/write too much
    const unsigned m_fileIOSuspect = 25;

    FanotifyWrapper m_fanotify;
    std::string_view m_mount;

    /*
        Map layout is: PROCESS PID - vector<EVENT TYPE>
        Count read/write/open events of each process, terminate process if it is suspicious.
        P.S. Suspicious process: openEventCount >= fileIOSuspect && readEventCount >= fileIOSuspect && writeEventCount >= fileIOSuspect
    */
    
    enum EventType
    {
        EVENT_READ,
        EVENT_WRITE,
        EVENT_OPEN,
        EVENT_COUNT
    };

    constexpr EventType FanotifyEvenToIdx(size_t type)
    {
        switch (type)
        {
            case FAN_OPEN:
            case FAN_OPEN_PERM:
                return EVENT_OPEN;
            case FAN_ACCESS:
            case FAN_ACCESS_PERM:
                return EVENT_READ;
            case FAN_MODIFY:
                return EVENT_WRITE;
            default:
                return EVENT_COUNT; // error
        }
    }

    std::map<int, std::array<unsigned, EVENT_COUNT>> m_pidEventMap;

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
            case FAN_OPEN:
                return "FAN_OPEN";
            case FAN_ACCESS:
                return "FAN_ACCESS";
            case FAN_MODIFY:
                return "FAN_MODIFY";
            case FAN_OPEN_PERM:
                return "FAN_OPEN_PERM";
            case FAN_ACCESS_PERM:
                return "FAN_ACCESS_PERM";
            default:
                return "";
        }
    }

    void ProcessEvent(fanotify_event_metadata& event)
    {
        std::cout << "Event caught! info: ";

        for (auto& id : m_markFlagsArray)
        {
            if (IsEvent(event, id))
            {
                // log event info into console
                std::cout << "type = " << StringizeEventType(id) << ": " << std::endl;
                if (id == FAN_OPEN_PERM || id == FAN_ACCESS_PERM)
                    m_fanotify.ResponseAllow(event);

                std::cout << "file = " << GetFilenameByFd(event.fd) << ", PID = " << event.pid << std::endl;
                
                // log into map
                m_pidEventMap[event.pid][FanotifyEvenToIdx(id)]++;
            }        
        }

        // check for suspicious pids
        for (auto& [pid, events] : m_pidEventMap)
        {
            if (events[EVENT_OPEN] >= m_fileIOSuspect && events[EVENT_READ] >= m_fileIOSuspect && events[EVENT_WRITE])
            {
                LOG("suspicious pid " << pid << ", terminating it...");

                // kill this pid
                kill(pid, SIGKILL);

                LOG("suspicious pid " << pid << "has been terminated");
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
        
        m_fanotify.Mark(m_markFlags, m_markMask, AT_FDCWD, m_mount.data());

        // set up main loop
        std::cout << "Starting the program... To finish the program, press enter." << std::endl;
        while (m_fanotify.WaitForEvent())
        {
            while (m_fanotify.IsLeftEvents())
            {
                auto events = m_fanotify.GetEvents();
                for (auto& event : events)
                {
                    if(IsEmpty(event)) // TODO: return buffer with no zero blocks, so we do not have to check if event is zero
                        break;

                    if (event.vers != FANOTIFY_METADATA_VERSION)
                        throw std::runtime_error("mismatch of fanotify metadata version");
                    
                    if (event.fd != 0) // ignore overflow
                        ProcessEvent(event);
                }
            }
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
    catch(const std::exception& e)
    {
        std::cerr << "Caught exception from EncryptorDetector: " << e.what() << std::endl;
        return -1;
    }
    
    return 0;
}