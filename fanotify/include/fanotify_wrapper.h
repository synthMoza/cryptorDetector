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
#include <array>
#include <ranges>
#include <iostream>

namespace fn
{

#ifdef DEBUG
#define LOG(msg) std::cout << "[FANOTIFY " << __PRETTY_FUNCTION__ << ":" << __LINE__ << "]: " << msg << std::endl;
#else
#define LOG(msg)
#endif

constexpr nfds_t NFDS = 2; // number of file descriptors for poll
constexpr size_t STDIN_FD_IDX = 0;
constexpr size_t FANOTIFY_FD_IDX = 1;

constexpr size_t EVENTS_BUFFER_SIZE = 200;

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
    
    using event_container = std::vector<fanotify_event_metadata>;
    event_container m_eventBuffer; // buffer for accessing events
    bool m_isLeftEvents;

    /**
     * @brief Read events to the buffer, update bool flag m_isLeftEvents
     */
    void ReadEvents();

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

    /*
        Check if there are events to reads, buffer first part of events when they appear. It is required for bufferized read of events and easy iteration over them.
        Example:

        while (fanotify.WaitForEvent())
        {
            while (fanotify.IsLeftEvents())
                for (auto& event : fanotify.GetEvents())
                {
                    // handle events
                }
        }
    */

   /**
    * @brief Check if there are events to reads, buffer first part of events when they appear. It is required for bufferized read of events and easy iteration over them.
    * Example:
    * 
    *    while (fanotify.WaitForEvent())
    *    {
    *        while (fanotify.IsLeftEvents())
    *            for (auto& event : fanotify.GetEvents())
    *            {
    *                // handle events
    *            }
    *    }
    * 
    */
    bool IsLeftEvents() const;
    
    /**
     * @brief Get the Events object. Call IsLeftEvents() before getting this container, otherwise it might be empty
     * 
     * @return event container
     */
    event_container GetEvents();

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

}

#endif // #define FANOTIFY_WRAPPER
 