#ifndef QUERY_METHODS
#define QUERY_METHODS
#include "auto.h"
#include <memory>
#include <functional>
struct query;
struct query_methods {
    std::function<int(std::shared_ptr<query> q, void *DS)> on_answer;
    std::function<int(std::shared_ptr<query> q, int error_code, const std::string &error)> on_error;
    std::function<int(std::shared_ptr<query> q)> on_timeout;
    struct paramed_type type;
};
#endif // QUERY_METHODS

