#include <detector.h>

#include <thread>

using namespace fn;

#ifdef DEBUG
#include <tracer.h>
    // Use tracer for debug purposes only
    static Tracer g_tracer;

    #define TRACE(message) g_tracer.Trace(message, __PRETTY_FUNCTION__, __LINE__);
#else
    #define TRACE(message) // do nothing
#endif

EncryptorDetector::EncryptorDetector(const char* mount) :
    m_fanotify(m_fanotifyFlags, m_fanotifyEventFlags),
    m_mount(mount),
    m_pidEventMap(),
    m_fileDb(m_fileDbPath)
{
    // initialize fanotify
    uint64_t markMask = 0;
    for (auto& flag : m_markFlagsArray)
        markMask |= flag;
    
    m_fanotify.Mark(m_markFlags, markMask, AT_FDCWD, m_mount.data());
}

constexpr EncryptorDetector::EventType EncryptorDetector::FanotifyEventToIdx(size_t type)
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
            return EVENT_OPEN;
        case FAN_CLOSE:
        case FAN_CLOSE_NOWRITE:
        case FAN_CLOSE_WRITE:
            return EVENT_CLOSE;
        default:
            return EVENT_COUNT; // error
    }
}

std::string EncryptorDetector::GetFilenameByFd(int fd)
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

std::string EncryptorDetector::StringizeEventType(size_t type)
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

void EncryptorDetector::ProcessEvent(fanotify_event_metadata& event)
{
    #ifdef DEBUG
        std::stringstream stream;
        stream << "Event caught! info: ";
    #endif

    auto fileName = GetFilenameByFd(event.fd);
    auto isItself = (getpid() == event.pid);
    for (auto& id : m_markFlagsArray)
    {
        if (IsEvent(event, id))
        {
            // Restrict access to database
            if (id == FAN_OPEN_PERM || id == FAN_ACCESS_PERM)
            {
                // do not let anyone edit file data base besides this process
                if (fileName.compare(m_fileDbPath) == 0 && !isItself)
                    m_fanotify.ResponseDeny(event);
                else
                    m_fanotify.ResponseAllow(event);
            }

            // allowed event, no more interesting for itself
            if (isItself)
                continue;

            if (id == FAN_OPEN || id == FAN_OPEN_PERM)
            {
                // add file to database
                std::thread thread([&](){
                    m_fileDb.AddFile(fileName.c_str(), event.pid);
                });

                thread.detach();
            }
            else if (id == FAN_CLOSE_NOWRITE)
            {
                // readonly file was closed, might delete it now
                std::thread thread([&](){
                    m_fileDb.DeleteFile(fileName.c_str());
                });

                thread.detach();
            }

            #ifdef DEBUG
                stream << "type = " << StringizeEventType(id) << ": " << std::endl;
                stream << "file = " << GetFilenameByFd(event.fd) << ", PID = " << event.pid << std::endl;

                if (event.pid != getpid()) // do not generate infinite amount of logs
                    TRACE(stream.str().c_str());
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

void EncryptorDetector::Launch()
    {
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

                    std::thread thread([&](int procPid){
                        // restore files that were opened by this pid
                        auto openedFiles = m_fileDb.GetFilesFromPid(procPid);
                        if (openedFiles.empty())
                        {
                            std::cout << "Encryptor didn't open any files or can't restore any encrypted file";
                        }
                        else
                        {
                            for (auto& file : openedFiles)
                            {
                                std::ofstream fileStream(file);
                                // find content in db
                                auto content = m_fileDb.GetFileContent(file.c_str());
                                fileStream.write((char*) content.data(), content.size());

                                std::cout << "Succesfully restored file: " << file << std::endl;
                            }
                        }
                    }, pid);

                    thread.detach();
                    
                }
            }

            for (auto& pid : pidsToRemove)
                m_pidEventMap.erase(pid);
        }

        std::cout << "Finishing the program..." << std::endl;
    }

