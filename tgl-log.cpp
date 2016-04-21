#include "tgl-log.h"

log_function registered_logfunction = 0;
std::stringstream str_stream;
int g_severity = E_NOTICE;

void init_tgl_log(log_function log_f, int s)
{
    registered_logfunction = log_f;
    g_severity = s;
}

void tgl_log(std::string str, int severity)
{
    if (severity <= g_severity) {
        if (registered_logfunction) {
            registered_logfunction(str, severity);
        }
    }
}

#if defined(__SIZEOF_INT128__)
std::ostream& operator<<(std::ostream& s, __int128 i)
{
    int32_t *i32s = (int32_t*)&i;
    s << *i32s << *(i32s + 1) << *(i32s + 2) << *(i32s + 3);
    return s;
}
#endif
