#ifndef QUERY_METHODS
#define QUERY_METHODS
#include "auto.h"
#include <functional>
struct query;
struct query_methods {
    std::function<int(struct query *q, void *DS)> on_answer;
    std::function<int(struct query *q, int error_code, int len, const char *error)> on_error;
    std::function<int(struct query *q)> on_timeout;
    struct paramed_type type;
};
#endif // QUERY_METHODS

