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

#include "document.h"
#include "message.h"
#include "query_messages_send_encrypted_action.h"
#include "query_messages_send_encrypted_file.h"
#include "query_messages_send_encrypted_message.h"
#include "secret_chat.h"
#include "tgl/tgl_log.h"
#include "tgl/tgl_unconfirmed_secret_message_storage.h"

namespace tgl {
namespace impl {

void query_messages_send_encrypted_base::on_answer(void* D)
{
    assert(m_message);
    m_message->set_pending(false);

    tl_ds_messages_sent_encrypted_message* DS_MSEM = static_cast<tl_ds_messages_sent_encrypted_message*>(D);

    if (DS_MSEM->date) {
        m_message->set_date(*DS_MSEM->date);
    }

    if(DS_MSEM->file && DS_MSEM->file->magic == CODE_encrypted_file && m_message->media()->type() == tgl_message_media_type::document) {
        auto doc = std::static_pointer_cast<tgl_message_media_document>(m_message->media())->document;
        std::static_pointer_cast<document>(doc)->update(DS_MSEM->file);
    }

    m_user_agent.callback()->update_messages({m_message});

    if (m_callback) {
        m_callback(true, m_message);
    }

    m_user_agent.callback()->message_sent(m_message->id(), m_message->id(), m_message->date(), m_message->to_id());
}

int query_messages_send_encrypted_base::on_error(int error_code, const std::string& error_string)
{
    TGL_ERROR("RPC_CALL_FAIL " <<  error_code << " " << error_string);

    if (m_secret_chat->state() != tgl_secret_chat_state::deleted
            && (error_code == 400 && (error_string == "ENCRYPTION_DECLINED" || error_string == "ENCRYPTION_ID_INVALID"))) {
        m_secret_chat->set_deleted();
    }

    if (m_callback) {
        m_callback(false, m_message);
    }

    if (m_message) {
        m_message->set_pending(false).set_send_failed(true);
        m_user_agent.callback()->update_messages({m_message});
    }
    return 0;
}

void query_messages_send_encrypted_base::will_send()
{
    if (m_assembled) {
        return;
    }

    m_assembled = true;

    auto depending_query_id = m_secret_chat->last_depending_query_id();
    if (depending_query_id) {
        out_i32(CODE_invoke_after_msg);
        out_i64(depending_query_id);
    }

    assemble();

    if (m_unconfirmed_message) {
        m_secret_chat->queue_unconfirmed_outgoing_message(m_unconfirmed_message);
        m_unconfirmed_message = nullptr;
    }

    if (m_secret_chat->layer() >= 17) {
        m_message->set_sequence_number(m_secret_chat->out_seq_no());
        m_secret_chat->set_out_seq_no(m_secret_chat->out_seq_no() + 1);
        m_user_agent.callback()->secret_chat_update(m_secret_chat);
    }

    m_user_agent.callback()->update_messages({m_message});
}

void query_messages_send_encrypted_base::sent()
{
    m_secret_chat->set_last_depending_query_id(msg_id());
}

size_t query_messages_send_encrypted_base::begin_unconfirmed_message(uint32_t constructor_code)
{
    assert(!m_unconfirmed_message);
    assert(m_message);
    assert(m_secret_chat->layer() >= 17);
    m_unconfirmed_message = tgl_unconfirmed_secret_message::create_default_impl(
            m_message->id(),
            m_message->date(),
            m_secret_chat->id().peer_id,
            m_secret_chat->in_seq_no(),
            m_secret_chat->out_seq_no(),
            true,
            constructor_code);
    return serializer()->char_size();
}

void query_messages_send_encrypted_base::append_blob_to_unconfirmed_message(size_t start)
{
    assert(m_secret_chat->layer() >= 17);
    assert(serializer()->char_size() > start);
    const char* buffer = (serializer()->char_data()) + start;
    size_t size = serializer()->char_size() - start;
    TGL_DEBUG("adding blob of size " << size);
    m_unconfirmed_message->append_blob(std::string(buffer, size));
}

void query_messages_send_encrypted_base::construct_message(int64_t message_id, int64_t date,
        const std::string& layer_blob) throw(std::runtime_error)
{
    assert(m_secret_chat->layer() >= 17);
    m_message = m_secret_chat->construct_message(
            m_secret_chat->our_id(),
            message_id, date, layer_blob, std::string());
    if (!m_message) {
        throw std::runtime_error("failed to reconstruct message from blobs");
    }
    m_message->set_unread(true).set_pending(true);
}

std::vector<std::shared_ptr<query_messages_send_encrypted_base>>
query_messages_send_encrypted_base::create_by_out_seq_no(const std::shared_ptr<secret_chat>& sc,
            int32_t out_seq_no_start, int32_t out_seq_no_end)
{
    assert(sc->layer() >= 17);
    std::vector<std::shared_ptr<query_messages_send_encrypted_base>> queries;
    auto ua = sc->weak_user_agent().lock();
    if (!ua) {
        return queries;
    }

    auto storage = ua->unconfirmed_secret_message_storage();
    auto messages = storage->load_messages_by_out_seq_no(sc->id().peer_id, out_seq_no_start, out_seq_no_end, true);
    for (const auto& message: messages) {
        TGL_DEBUG("reconstructing query from unconfirmed secret messsage out_seq_no " << message->out_seq_no());
        try {
            switch (message->constructor_code()) {
                case CODE_messages_send_encrypted:
                    queries.push_back(std::make_shared<query_messages_send_encrypted_message>(*ua, sc, message, nullptr));
                    break;
                case CODE_messages_send_encrypted_service:
                    queries.push_back(std::make_shared<query_messages_send_encrypted_action>(*ua, sc, message, nullptr));
                    break;
                case CODE_messages_send_encrypted_file:
                    queries.push_back(std::make_shared<query_messages_send_encrypted_file>(*ua, sc, message, nullptr));
                    break;
                default:
                    TGL_WARNING("unknown constructor code 0x" << std::hex << message->constructor_code()
                            << " seen when loading query from storage");
                    break;
            }
        } catch (const std::exception& e) {
            TGL_ERROR("caught exception: " << e.what());
            continue;
        }
    }
    TGL_DEBUG("reconstructed " << queries.size() << " queries from unconfirmed secret messageis of range ["
            << out_seq_no_start << "," << out_seq_no_end << "]");
    return queries;
}

}
}
