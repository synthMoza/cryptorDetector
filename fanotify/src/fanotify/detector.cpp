#include <fanotify/detector.h>

using namespace fn;

EncryptorDetector::EncryptorDetector(const char* mount, const Config& cfg) :
    m_tracer(cfg.logPath),
    m_config(cfg),
    m_fanotify(cfg.fanotifyFlags, cfg.fanotifyEventFlags),
    m_mount(mount),
    m_pidEventMap()
{
    // initialize fanotify
    uint64_t markMask = 0;
    for (auto& flag : cfg.markFlags)
        markMask |= flag;
    
    m_fanotify.Mark(m_markFlags, markMask, AT_FDCWD, m_mount.data());
    // ignore log file
    m_fanotify.Mark(FAN_MARK_ADD | FAN_MARK_IGNORED_MASK | FAN_MARK_IGNORED_SURV_MODIFY,
        FAN_OPEN_PERM | FAN_CLOSE_WRITE, AT_FDCWD, cfg.logPath);
}

void EncryptorDetector::ProcessEvent(fanotify_event_metadata& event)
{
    // trace caught events only in debug
#ifdef DEBUG
    std::stringstream stream;
    stream << "Event caught! info: ";
#endif

    auto fileName = GetFilenameByFd(event.fd);
    auto isItself = (getpid() == event.pid);
    for (auto& id : m_config.markFlags)
    {
    #ifdef DEBUG
        stream.str(""); // flush stream
    #endif
        if (IsEvent(event, id))
        {
            if (id == FAN_OPEN_PERM || id == FAN_ACCESS_PERM)
                m_fanotify.ResponseAllow(event);

            // allowed event, no more interesting for itself
            if (isItself)
                continue;

        #ifdef DEBUG
            stream << "type = " << StringizeEventType(id) << ", ";
            stream << "file = " << GetFilenameByFd(event.fd) << ", PID = " << event.pid;
            if (!isItself) // do not generate infinite amount of logs
                TRACE(m_tracer, stream.str().c_str());
        #endif

            // log this event into map (only reads and writes)
            auto idx = FanotifyEventToIdx(id);
            if (idx == EVENT_READ || idx == EVENT_WRITE)
            {
                auto& procInfo = m_pidEventMap[event.pid];
                procInfo.eventsCount[idx]++;
                procInfo.eventsQueue.push({idx, clock::now()});
            }
        }
    }

    close(event.fd);
}

void EncryptorDetector::CheckForOutdatedEvents()
{
    for (auto& pair : m_pidEventMap)
    {
        auto& currentQueue = pair.second.eventsQueue;
        while (currentQueue.size() > 0)
        {
            auto frontTimeAlive = std::chrono::duration_cast<ms>(clock::now() - currentQueue.front().birth).count();
            if (frontTimeAlive < m_config.fileIOMaxAge)
                break;
            else
            {
            #ifdef DEBUG
                std::stringstream ss;
                ss << "Remove outdated event from proccess with pid = " << pair.first;
                TRACE(m_tracer, std::move(ss.str()));
            #endif
                pair.second.eventsCount[currentQueue.front().type]--;
                currentQueue.pop();
            }
        }
    }
}

void EncryptorDetector::ProcessEvents()
{
    auto events = m_fanotify.GetEvents();
    if (events.IsEmpty())
        return ; // all events for this iteration are processed

    for (auto& event : events)
    {
        if (event.vers != FANOTIFY_METADATA_VERSION)
        {
            TRACE(m_tracer, "Mismatch in fanotify metadata version");
            throw std::runtime_error("mismatch of fanotify metadata version");
        }
        
        if (event.fd == 0)
        {
            TRACE(m_tracer, "Overflow detected!");
            throw std::overflow_error("Event queue overflow!");
        }

        ProcessEvent(event);
    }
}

void EncryptorDetector::CheckForSuspiciousPids()
{
    // check for suspicious pids
    std::vector<int> pidsToRemove;
    pidsToRemove.reserve(m_pidEventMap.size());
    for (auto& [pid, procInfo] : m_pidEventMap)
    {
        if (procInfo.eventsCount[EVENT_READ] >= m_config.fileIOSuspect.reads &&
            procInfo.eventsCount[EVENT_WRITE] >= m_config.fileIOSuspect.writes)
        {
            // check whitelist here to save some resources
            auto execName = GetFilenameByPid(pid);
            bool isWhiteListed = false;
            for (auto& path : m_config.whiteList)
            {
                if (path == execName)
                {
                    // do nothing with white-listed binaries
                    pidsToRemove.push_back(pid);
                    isWhiteListed = true;
                    break;
                }
            }
     
            if (isWhiteListed)
                continue ;

            std::stringstream ss;
            ss << "Suspicious pid = " << pid << " has been found";
            TRACE(m_tracer, std::move(ss.str()));

            // kill this pid
            kill(pid, SIGKILL);

            ss.str("");
            ss << "Suspicious pid = " << pid << " has been killed successfully";
            TRACE(m_tracer, std::move(ss.str()));

            pidsToRemove.push_back(pid);
        }
    }

    for (auto& pid : pidsToRemove)
        m_pidEventMap.erase(pid);
}

void EncryptorDetector::Launch()
{
    TRACE(m_tracer, "Starting the program... To finish the program, press enter");

    // set up main loop
    while (m_fanotify.WaitForEvent())
    {
        CheckForOutdatedEvents();
        ProcessEvents();
        CheckForSuspiciousPids();
    }

    TRACE(m_tracer, "Finishing the program...");
}

