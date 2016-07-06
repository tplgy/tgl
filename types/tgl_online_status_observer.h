#ifndef __TGL_ONLINE_STATUS_OBSERVER_H__
#define __TGL_ONLINE_STATUS_OBSERVER_H__

class tgl_online_status_observer
{
public:
    virtual void on_online_status_changed(bool online) = 0;
    virtual ~tgl_online_status_observer() { }
};

#endif
