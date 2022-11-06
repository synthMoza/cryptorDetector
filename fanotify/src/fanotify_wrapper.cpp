#include <fanotify_wrapper.h>

#include <poll.h>
#include <unistd.h>

#include <algorithm>

using namespace fn;

FanotifyWrapper::FanotifyWrapper(unsigned flags, unsigned event_f_flags) :
    m_fds(),
    m_notificationGroupFd(fanotify_init(flags, event_f_flags)),
    m_eventBuffer(EVENTS_BUFFER_SIZE),
    m_isLeftEvents(false)
{
    LOG("start initialization");
    if (m_notificationGroupFd < 0)
        throw std::runtime_error("fanotify_init error");
    
    m_fds[STDIN_FD_IDX].fd = STDIN_FILENO;
    m_fds[STDIN_FD_IDX].events = POLLIN;
    
    m_fds[FANOTIFY_FD_IDX].fd = m_notificationGroupFd;
    m_fds[FANOTIFY_FD_IDX].events = POLLIN;
    LOG("initialization success");
}

void FanotifyWrapper::Mark(unsigned flags, uint64_t mask, int dfd, const std::string& pathName)
{
    LOG("enter");

    if (fanotify_mark(m_notificationGroupFd, flags, mask, dfd, pathName.c_str()) < 0)
        throw std::runtime_error("fanotify_mark error");
    
    LOG("success");
}

void FanotifyWrapper::ReadEvents()
{
    LOG("enter");

    // clear buffer
    fanotify_event_metadata empty{};
    std::fill(m_eventBuffer.begin(), m_eventBuffer.end(), empty);
    
    // read next block of events
    auto readBytes = read(m_notificationGroupFd, m_eventBuffer.data(), EVENTS_BUFFER_SIZE);
    if (readBytes < 0 && errno != EAGAIN)
        throw std::runtime_error("read error");
    
    m_isLeftEvents = (readBytes > 0);

    LOG("success");
}

bool FanotifyWrapper::WaitForEvent()
{
    LOG("enter");

    while (true)
    {
        auto pollNum = poll(m_fds, NFDS, -1);
        
        if (pollNum < 0 && errno != EINTR)
            throw std::runtime_error("poll error");

        if (pollNum > 0)
        {
            if (m_fds[STDIN_FD_IDX].revents & POLLIN)
            {
                LOG("got event from STDIN");

                char buf = 0;
                while (read(STDIN_FILENO, &buf, 1) > 0 && buf != '\n')
                    continue;

                LOG("success");                
                return false; // end
            }

            if (m_fds[FANOTIFY_FD_IDX].revents & POLLIN)
            {
                LOG("got fanotify event");

                // events are availible, read first portion
                ReadEvents();

                LOG("success");
                return true;
            }
        }    
    }

    LOG("unreachable code reached");
    return false; // unreachable code
}

void FanotifyWrapper::Response(fanotify_event_metadata& metadata, unsigned access) const
{
    LOG("enter");

    struct fanotify_response response;
        
    response.fd = metadata.fd;
    response.response = access;
    
    if (write(m_notificationGroupFd, &response, sizeof(response)) < 0)
        throw std::runtime_error("write error");

    LOG("success");
}

void FanotifyWrapper::ResponseAllow(fanotify_event_metadata& metadata) const
{
    LOG("enter");
    Response(metadata, FAN_ACCESS);
    LOG("success");
}

void FanotifyWrapper::ResponseDeny(fanotify_event_metadata& metadata) const
{
    LOG("enter");
    Response(metadata, FAN_DENY);
    LOG("success");
}

FanotifyWrapper::event_container FanotifyWrapper::GetEvents()
{
    LOG("enter");

    if (m_isLeftEvents)
    {
        // return current buffer, read new
        event_container oldBuffer(m_eventBuffer);
        
        ReadEvents();

        LOG("success");
        return oldBuffer;
    }
    
    LOG("success");
    return event_container{}; // empty events buffer
}

bool FanotifyWrapper::IsLeftEvents() const
{
    return m_isLeftEvents;
}
