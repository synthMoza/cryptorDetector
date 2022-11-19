#ifndef TRACER_HEADER
#define TRACER_HEADER

#include <fstream>
namespace fn
{

class Tracer
{
    static constexpr const char* traceFileName = "fanotify_trace.log";

    std::ofstream m_traceFile;
public:
    Tracer() : m_traceFile(traceFileName) {}
    
    void Trace(const char* message, const char* func, unsigned line)
    {
        m_traceFile << "[" << func << ":" << line << "]: " << message << std::endl;
    }
};

}

#endif // #define TRACER_HEADER
