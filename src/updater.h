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

#pragma once

#include <memory>

struct tgl_peer_id_t;

namespace tgl {
namespace impl {

class message;
class user_agent;

struct tl_ds_encrypted_message;
struct tl_ds_updates;
struct tl_ds_update;
struct tgl_in_buffer;

enum class update_mode {
    check_and_update_consistency,
    dont_check_and_update_consistency
};

struct update_context
{
    update_context() { }
    explicit update_context(update_mode mode): mode(mode) { }
    explicit update_context(const std::shared_ptr<message>& old_message): old_message(old_message) { }
    update_mode mode = update_mode::check_and_update_consistency;
    std::shared_ptr<message> old_message;
};

class updater {
public:
    explicit updater(user_agent& ua)
        : m_user_agent(ua)
    { }

    bool check_pts_diff(int32_t pts, int32_t pts_count);
    void work_update(const tl_ds_update* DS_U, const update_context& = update_context());
    void work_any_updates(tgl_in_buffer* in, const update_context& = update_context());
    void work_any_updates(const tl_ds_updates* DS_U, const update_context& = update_context());
    void work_encrypted_message(const tl_ds_encrypted_message*, const update_context& = update_context());

private:
    bool check_qts_diff(int32_t qts, int32_t qts_count);
    bool check_channel_pts_diff(const tgl_peer_id_t& channel_id, int32_t pts, int32_t pts_count);
    bool check_seq_diff(int32_t seq);
    void work_updates(const tl_ds_updates* DS_U, const update_context& context);
    void work_updates_combined(const tl_ds_updates* DS_U, const update_context& context);
    void work_updates_too_long(const tl_ds_updates* DS_U, const update_context& context);
    void work_update_short(const tl_ds_updates* DS_U, const update_context& context);
    void work_update_short_message(const tl_ds_updates* DS_U, const update_context& context);
    void work_update_short_chat_message(const tl_ds_updates* DS_U, const update_context& context);
    void work_update_short_sent_message(const tl_ds_updates* DS_U, const update_context& context);

private:
    user_agent& m_user_agent;
};

}
}
