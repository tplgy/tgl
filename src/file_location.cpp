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

    Copyright Vitaly Valtman 2013-2015
    Copyright Topology LP 2016-2017
*/

#include "file_location.h"

#include "auto/auto.h"
#include "auto/auto-types.h"
#include "auto/constants.h"

namespace tgl {
namespace impl {

tgl_file_location create_file_location(const tl_ds_file_location* DS_FL)
{
    tgl_file_location location;

    if (!DS_FL) {
        return location;
    }

    location.set_dc(DS_LVAL(DS_FL->dc_id));
    location.set_volume(DS_LVAL(DS_FL->volume_id));
    location.set_local_id(DS_LVAL(DS_FL->local_id));
    location.set_secret(DS_LVAL(DS_FL->secret));

    return location;
}

}
}
