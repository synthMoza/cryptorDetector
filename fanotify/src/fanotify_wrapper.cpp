#include <fanotify_wrapper.h>

#include <poll.h>
#include <unistd.h>

#include <algorithm>

using namespace fn;

FanotifyWrapper::FanotifyWrapper(unsigned flags, unsigned event_f_flags) :
    m_fds(),
    m_notificationGroupFd(fanotify_init(flags, event_f_flags))
{
    if (m_notificationGroupFd < 0)
        throw std::runtime_error("fanotify_init error");
    
    m_fds[STDIN_FD_IDX].fd = STDIN_FILENO;
    m_fds[STDIN_FD_IDX].events = POLLIN;
    
    m_fds[FANOTIFY_FD_IDX].fd = m_notificationGroupFd;
    m_fds[FANOTIFY_FD_IDX].events = POLLIN;
}

void FanotifyWrapper::Mark(unsigned flags, uint64_t mask, int dfd, const std::string& pathName)
{
    if (fanotify_mark(m_notificationGroupFd, flags, mask, dfd, pathName.c_str()) < 0)
        throw std::runtime_error("fanotify_mark error");
}

bool FanotifyWrapper::WaitForEvent()
{
    while (true)
    {
        auto pollNum = poll(m_fds, NFDS, -1);
        
        if (pollNum < 0 && errno != EINTR)
            throw std::runtime_error("poll error");

        if (pollNum > 0)
        {
            if (m_fds[STDIN_FD_IDX].revents & POLLIN)
            {
                char buf = 0;
                while (read(STDIN_FILENO, &buf, 1) > 0 && buf != '\n')
                    continue;

                return false; // end
            }

            if (m_fds[FANOTIFY_FD_IDX].revents & POLLIN)
            {
                return true;
            }
        }    
    }

    return false; // unreachable code
}

void FanotifyWrapper::Response(const fanotify_event_metadata& metadata, unsigned access) const
{
    struct fanotify_response response;
        
    response.fd = metadata.fd;
    response.response = access;
    
    if (write(m_notificationGroupFd, &response, sizeof(response)) < 0)
        throw std::runtime_error("write error");
}

void FanotifyWrapper::ResponseAllow(const fanotify_event_metadata& metadata) const
{
    Response(metadata, FAN_ACCESS);
}

void FanotifyWrapper::ResponseDeny(const fanotify_event_metadata& metadata) const
{
    Response(metadata, FAN_DENY);
}

EventContainer FanotifyWrapper::GetEvents()
{
    return EventContainer(m_notificationGroupFd);
}
