#ifndef TRACER_HEADER
#define TRACER_HEADER

#include <fstream>

namespace fn
{

#ifndef DAEMON_FANOTIFY

#define TRACE(tracer, message) tracer.Trace(message, __PRETTY_FUNCTION__, __LINE__);

class Tracer
{
    std::ofstream m_traceFile;
public:
    Tracer(const char* traceFileName) : m_traceFile(traceFileName) {}
    Tracer(const std::string& traceFileName) : m_traceFile(traceFileName) {}

    template <typename T>
    void Trace(T&& message, const char* func, unsigned line)
    {
        m_traceFile << "[" << func << ":" << line << "] " << std::forward<T>(message) << std::endl;
    }
};

#else

#include <syslog.h>

#define TRACE(tracer, message) tracer.Trace(message);

class Tracer
{
    static constexpr const int m_option = LOG_CONS | LOG_PID | LOG_NDELAY;
    static constexpr const int m_facility = LOG_LOCAL1;
    static constexpr const char* m_programName = "fanotify_detector";
public:
    Tracer() 
    {
        openlog(m_programName, m_option, m_facility);
    }
    
    Tracer(const char*) : Tracer() {}
    Tracer(const std::string&) : Tracer() {}

    void Trace(const std::string& message)
    {
        syslog(LOG_NOTICE, "%s", message.c_str());
    }

    void Trace(const char* message)
    {
        syslog(LOG_NOTICE, "%s", message);
    }

    ~Tracer()
    {
        closelog();
    }
};

#endif // #ifndef DAEMON_FANOTIFY

}

#endif // #define TRACER_HEADER
