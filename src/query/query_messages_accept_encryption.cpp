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

#include "query_messages_accept_encryption.h"

#include "auto/auto.h"
#include "structures.h"
#include "tgl_secret_chat_private.h"
#include "tgl/tgl_secret_chat.h"

query_messages_accept_encryption::query_messages_accept_encryption(const std::shared_ptr<tgl_secret_chat>& secret_chat,
        const std::function<void(bool, const std::shared_ptr<tgl_secret_chat>&)>& callback)
    : query("send encrypted (chat accept)", TYPE_TO_PARAM(encrypted_chat))
    , m_secret_chat(secret_chat)
    , m_callback(callback)
{
}

void query_messages_accept_encryption::on_answer(void* D)
{
    std::shared_ptr<tgl_secret_chat> secret_chat = tglf_fetch_alloc_encrypted_chat(
            static_cast<tl_ds_encrypted_chat*>(D));

    if (secret_chat && secret_chat->state() == tgl_secret_chat_state::ok) {
        secret_chat->private_facet()->send_layer();
    }

    if (secret_chat) {
        assert(m_secret_chat == secret_chat);
    }

    if (m_callback) {
        m_callback(secret_chat && secret_chat->state() == tgl_secret_chat_state::ok, secret_chat);
    }
}

int query_messages_accept_encryption::on_error(int error_code, const std::string& error_string)
{
    if (m_secret_chat && m_secret_chat->state() != tgl_secret_chat_state::deleted
        && error_code == 400 && error_string == "ENCRYPTION_DECLINED") {
        m_secret_chat->private_facet()->set_deleted();
    }

    if (m_callback) {
        m_callback(false, m_secret_chat);
    }
    return 0;
}
