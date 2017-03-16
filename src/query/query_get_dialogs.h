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

#include "query.h"
#include "tgl/tgl_log.h"
#include "tgl/tgl_peer_id.h"
#include "user_agent.h"

#include <cstdint>
#include <memory>
#include <functional>
#include <string>
#include <vector>

namespace tgl {
namespace impl {

struct get_dialogs_state {
    std::vector<tgl_peer_id_t> peers;
    std::vector<int64_t> last_message_ids;
    std::vector<int> unread_count;
    std::vector<int> read_box_max_id;
    tgl_peer_id_t offset_peer;
    int limit = 0;
    int offset = 0;
    int offset_date;
    int max_id = 0;
    int channels = 0;
    std::weak_ptr<user_agent> weak_user_agent;
};

class query_get_dialogs: public query
{
public:
    query_get_dialogs(const std::shared_ptr<get_dialogs_state>& state,
            const std::function<void(bool, const std::vector<tgl_peer_id_t>&, const std::vector<int64_t>&, const std::vector<int>&)>& callback);
    virtual void on_answer(void* D) override;
    virtual int on_error(int error_code, const std::string& error_string) override;

private:
    std::shared_ptr<get_dialogs_state> m_state;
    std::function<void(bool, const std::vector<tgl_peer_id_t>&,
            const std::vector<int64_t>&, const std::vector<int>&)> m_callback;
};

// FIXME: better organize this.
void tgl_do_get_dialog_list(const std::shared_ptr<get_dialogs_state>& state,
        const std::function<void(bool, const std::vector<tgl_peer_id_t>&, const std::vector<int64_t>&, const std::vector<int>&)>& callback);

}
}
