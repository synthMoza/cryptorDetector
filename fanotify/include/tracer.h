#ifndef TRACER_HEADER
#define TRACER_HEADER

#include <fstream>
namespace fn
{

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

}

#endif // #define TRACER_HEADER
