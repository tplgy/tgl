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

#include "query_messages_send_encrypted_base.h"

void query_messages_send_encrypted_base::on_answer(void* D)
{
    m_message->set_pending(false);

    tl_ds_messages_sent_encrypted_message* DS_MSEM = static_cast<tl_ds_messages_sent_encrypted_message*>(D);

    if (DS_MSEM->date) {
        m_message->date = *DS_MSEM->date;
    }
    if(DS_MSEM->file) {
        tglf_fetch_encrypted_message_file(m_message->media, DS_MSEM->file);
    }
    tgl_state::instance()->callback()->new_messages({m_message});

    if (m_callback) {
        m_callback(true, m_message);
    }

    tgl_state::instance()->callback()->message_id_updated(m_message->permanent_id, m_message->permanent_id, m_message->to_id);
}

int query_messages_send_encrypted_base::on_error(int error_code, const std::string& error_string)
{
    TGL_ERROR("RPC_CALL_FAIL " <<  error_code << " " << error_string);

    if (m_secret_chat && m_secret_chat->state() != tgl_secret_chat_state::deleted && error_code == 400 && error_string == "ENCRYPTION_DECLINED") {
        tgl_secret_chat_deleted(m_secret_chat);
    }

    if (m_callback) {
        m_callback(false, m_message);
    }

    if (m_message) {
        m_message->set_pending(false).set_send_failed(true);
        tgl_state::instance()->callback()->new_messages({m_message});
    }
    return 0;
}

void query_messages_send_encrypted_base::will_send()
{
    if (m_assembled) {
        return;
    }

    m_assembled = true;

    auto depending_query_id = m_secret_chat->private_facet()->last_depending_query_id();
    if (depending_query_id) {
        out_i32(CODE_invoke_after_msg);
        out_i64(depending_query_id);
    }

    assemble();

    m_secret_chat->private_facet()->set_out_seq_no(m_secret_chat->out_seq_no() + 1);
    tgl_state::instance()->callback()->secret_chat_update(m_secret_chat);
}

void query_messages_send_encrypted_base::sent()
{
    m_secret_chat->private_facet()->set_last_depending_query_id(msg_id());
}
