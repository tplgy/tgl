#ifndef __TGL_ONLINE_STATUS_OBSERVER_H__
#define __TGL_ONLINE_STATUS_OBSERVER_H__

#include "tgl_online_status.h"

class tgl_online_status_observer
{
public:
    virtual void on_online_status_changed(tgl_online_status status) = 0;
    virtual ~tgl_online_status_observer() { }
};

#endif
