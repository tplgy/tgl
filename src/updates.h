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
    Copyright Topology LP 2016
*/

#ifndef __UPDATES_H__
#define __UPDATES_H__

#include <memory>

struct tl_ds_updates;
struct tl_ds_update;
struct tgl_in_buffer;

enum class tgl_update_mode {
   check_and_update_consistency,
   dont_check_and_update_consistency
};

bool tgl_check_pts_diff(int32_t pts, int32_t pts_count);

void tglu_work_update(const tl_ds_update* DS_U, const std::shared_ptr<void>& extra,
        tgl_update_mode mode = tgl_update_mode::check_and_update_consistency);

void tglu_work_updates(const tl_ds_updates* DS_U, const std::shared_ptr<void>& extra,
        tgl_update_mode mode = tgl_update_mode::check_and_update_consistency);

void tglu_work_any_updates(tgl_in_buffer* in);

void tglu_work_any_updates(const tl_ds_updates* DS_U, const std::shared_ptr<void>& extra,
        tgl_update_mode mode = tgl_update_mode::check_and_update_consistency);

#endif
