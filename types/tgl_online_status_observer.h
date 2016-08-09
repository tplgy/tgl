/*
    This file is part of tgl-library

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License as published by the Free Software Foundation; either
    version 2.1 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

    Copyright Topology LP 2016
*/

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
