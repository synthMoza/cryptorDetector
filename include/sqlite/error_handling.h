#ifndef ERROR_HANDLING_HEADER
#define ERROR_HANDLING_HEADER

#include "sqlite3.h"

#include <stdexcept>
#include <sstream>

namespace sqlite
{

#define CHECK_SQL(stm)                                                  \
do                                                                      \
{                                                                       \
    decltype(stm) __tmp = stm;                                          \
    if (__tmp != SQLITE_OK)                                             \
        throw sqlite::sql_error(__PRETTY_FUNCTION__, __LINE__, __tmp);  \
}                                                                       \
while (0);                                                              \

#define CHECK_SQL_MSG(stm, errmsg)                                      \
do                                                                      \
{                                                                       \
    decltype(stm) __tmp = stm;                                          \
    if (__tmp != SQLITE_OK)                                             \
        throw sqlite::sql_error(__PRETTY_FUNCTION__, __LINE__, errmsg); \
}                                                                       \
while (0);                                                              \


class sql_error : public std::exception
{
    std::string m_str;
public:
    // Note: msg will be freed with sqlite3_free after construction of the exception
    sql_error(const char* functionName, int line, char* msg)
    {
        std::stringstream stream;
        stream << "sql_exception: " << functionName << ", line " << line << " with error message: " << msg;
        m_str = std::move(stream.str());
        sqlite3_free(msg);
    }

    sql_error(const char* functionName, int line, int res)
    {
        std::stringstream stream;
        stream << "sql_exception: " << functionName << ", line " << line << " with result code " << res;
        m_str = std::move(stream.str());
    }

    sql_error(const char* str) : m_str(str) {}

    virtual const char* what() const noexcept
    {
        return m_str.c_str();
    }

    virtual ~sql_error() {}
};

}

#endif // #define ERROR_HANDLING_HEADER
 