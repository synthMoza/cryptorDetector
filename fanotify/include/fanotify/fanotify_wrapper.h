#ifndef FANITIFY_WRAPPER
#define FANOTIFY_WRAPPER

// c includes/defines
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif // #define _GNU_SOURCE

#include <sys/fanotify.h>
#include <poll.h>
#include <unistd.h>
#include <fcntl.h>

// c++ includes
#include <stdexcept>
#include <iterator>
#include <cstddef>
#include <cstring>
#include <vector>
#include <iostream>

namespace fn
{

constexpr size_t EVENTS_BUFFER_SIZE = 200;

class EventContainer
{
    fanotify_event_metadata m_buffer[EVENTS_BUFFER_SIZE];
    ssize_t m_len;
    bool m_isEmpty;
public:
    struct Iterator
    {
        using iterator_category = std::forward_iterator_tag;
        using difference_type   = std::ptrdiff_t;
        using value_type        = fanotify_event_metadata;
        using pointer           = value_type*;
        using reference         = value_type&;

        Iterator(pointer bufferPtr, ssize_t len) :
            m_bufferPtr(bufferPtr),
            m_len(len) {}
        
        reference operator*() const 
        { 
            return *m_bufferPtr;
        }
        pointer operator->() 
        { 
            return m_bufferPtr;
        }

        // Prefix increment
        Iterator& operator++() 
        {
            m_bufferPtr = FAN_EVENT_NEXT(m_bufferPtr, m_len);

            if (!FAN_EVENT_OK(m_bufferPtr, m_len))
            {
                // invalidate iterator
                m_bufferPtr = nullptr;
                m_len = -1;
            }

            return *this;
        }  

        // Postfix increment
        Iterator operator++(int) 
        { 
            Iterator tmp = *this; 
            ++(*this); 
            return tmp;
        }

        friend bool operator== (const Iterator& a, const Iterator& b) 
        { 
            return (a.m_bufferPtr == b.m_bufferPtr) && (a.m_len == b.m_len);
        }

        friend bool operator!= (const Iterator& a, const Iterator& b) 
        { 
            return !(a == b); 
        }
    private:
        pointer m_bufferPtr;
        ssize_t m_len;
    };

    EventContainer(int fd)
    {
        // Read events from given descriptor
        m_len = read(fd, m_buffer, sizeof(m_buffer));
        if (m_len == -1 && errno != EAGAIN)
            throw std::runtime_error("Read error while reading events from fanotify notification group");
        
        m_isEmpty = (m_len == 0);
    }

    Iterator begin()
    {
        return {m_buffer, m_len};
    }

    Iterator end()
    {
        return {nullptr, -1};
    }

    bool IsEmpty()
    {
        return m_isEmpty;
    }
};

#ifndef DAEMON_FANOTIFY
constexpr nfds_t NFDS = 2; // number of file descriptors for poll
constexpr size_t STDIN_FD_IDX = 1;
#else
constexpr nfds_t NFDS = 1; // number of file descriptors for poll
#endif
constexpr size_t FANOTIFY_FD_IDX = 0;


/**
 * @brief Event Container incapsulates events on current bufferized read ans allows to iterate over them easily
 * 
 */
class EventContainer;

/**
 * @brief Check the mask of the given fanotify metadata for the certain type of event
 * 
 * @param type event type
 * @param metadata given metadata to check
 */
constexpr inline bool IsEvent(fanotify_event_metadata& metadata, size_t type) noexcept
{
    return metadata.mask & type;
}
/**
 * @brief Check if the fanotify event metadata is empty
 * 
 * @param metadata fanotify metadata to check
 */
constexpr inline bool IsEmpty(fanotify_event_metadata& metadata) noexcept
{
    fanotify_event_metadata empty{};
    return (std::memcmp(&metadata, &empty, sizeof(fanotify_event_metadata)) == 0);
}

/**
 * @brief Fanotify Wrapper gives C++ API for C functions related to fanotify
 */
class FanotifyWrapper final
{
    pollfd m_fds[NFDS]; // pollfd struct for futher polling between stdin and fanotify fd
    int m_notificationGroupFd; // file descriptor to access fanotify API

    /**
     * @brief Write given type of responce to fanotify notification group
     * 
     * @param metadata given fanotify metadata
     * @param access type of responce (FAN_ACCESS or FAN_DENY)
     */
    void Response(const fanotify_event_metadata& metadata, unsigned access) const;
public:
    FanotifyWrapper(unsigned flags, unsigned event_f_flags);
    
    /**
     * @brief Wrapper fanotify_mark() function
     * 
     * @param flags a bit mask describing the modification to perform
     * @param mask defines which events shall be listened for (or which shall be ignored)
     * @param dfd the filesystem object to be marked - file descriptor
     * @param pathName the filesystem object to be marked - path name (see man fanotify_mark)
     */
    void Mark(unsigned int flags, uint64_t mask, int dfd, const std::string& pathName);

   /**
    * @brief Wait for any event from notification group. In case of any error function will throw a corresponding exception. To exit the loop, press enter (send something to stdin).
    *    
    *    Typical usage might be as follows:
    *    // initialize FanotifyWrapper
    *    try
    *    {
    *        while (fanotify.WaitForEvent())
    *        {
    *            // handle event
    *        }
    *    }
    *    catch (const std::exception& e)
    *    {
    *        // handle exception
    *    }
    * 
    * @return return true if there is a valid event to handle, false if the loop was stopped.
    */
    bool WaitForEvent();

    /**
     * @brief Get the event container to iterate over
     * 
     * Example of usage:
     * while (m_fanotify.WaitForEvent())
     * {
     *       auto events = m_fanotify.GetEvents();
     *       if (events.IsEmpty())
     *           continue ;
     * 
     *       for (auto& event : events)
     *       {
     *           // process events
     *       }
     * }
     * 
     * @return event container
     */
    EventContainer GetEvents();

    /**
     * @brief Allow fanotify event
     * 
     * @param metadata given event metadata
     */
    void ResponseAllow(const fanotify_event_metadata& metadata) const;

    /**
     * @brief Deny fanotify event
     * 
     * @param metadata given event metadata
     */
    void ResponseDeny(const fanotify_event_metadata& metadata) const;

    ~FanotifyWrapper() {}
};

} // namespace fn

#endif // #define FANOTIFY_WRAPPER
 