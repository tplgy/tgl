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

#include "query_messages_get_dh_config.h"

#include "auto/auto.h"
#include "auto/auto-types.h"
#include "tgl_secret_chat_private.h"

query_messages_get_dh_config::query_messages_get_dh_config(const std::shared_ptr<tgl_secret_chat>& secret_chat,
        const std::function<void(const std::shared_ptr<tgl_secret_chat>&,
                std::array<unsigned char, 256>& random,
                const std::function<void(bool, const std::shared_ptr<tgl_secret_chat>&)>&)>& callback,
        const std::function<void(bool, const std::shared_ptr<tgl_secret_chat>&)>& final_callback)
    : query("get dh config", TYPE_TO_PARAM(messages_dh_config))
    , m_secret_chat(secret_chat)
    , m_callback(callback)
    , m_final_callback(final_callback)
{
}

void query_messages_get_dh_config::on_answer(void* D)
{
    tl_ds_messages_dh_config* DS_MDC = static_cast<tl_ds_messages_dh_config*>(D);

    bool fail = false;
    if (DS_MDC->magic == CODE_messages_dh_config) {
        if (DS_MDC->p->len == 256) {
            m_secret_chat->private_facet()->set_dh_params(DS_LVAL(DS_MDC->g),
                    reinterpret_cast<unsigned char*>(DS_MDC->p->data), DS_LVAL(DS_MDC->version));
        } else {
            TGL_WARNING("the prime got from the server is not of size 256");
            fail = true;
        }
    } else if (DS_MDC->magic == CODE_messages_dh_config_not_modified) {
        TGL_NOTICE("secret chat dh config version not modified");
        if (m_secret_chat->encr_param_version() != DS_LVAL(DS_MDC->version)) {
            TGL_WARNING("encryption parameter versions mismatch");
            fail = true;
        }
    } else {
        TGL_WARNING("the server sent us something wrong");
        fail = true;
    }

    if (DS_MDC->random->len != 256) {
        fail = true;
    }

    if (fail) {
        m_secret_chat->private_facet()->set_deleted();
        if (m_final_callback) {
            m_final_callback(false, m_secret_chat);
        }
        return;
    }

    if (m_callback) {
        std::array<unsigned char, 256> random;
        memcpy(random.data(), DS_MDC->random->data, 256);
        m_callback(m_secret_chat, random, m_final_callback);
    }
}

int query_messages_get_dh_config::on_error(int error_code, const std::string& error_string)
{
    TGL_ERROR("RPC_CALL_FAIL " << error_code << " " << error_string);
    m_secret_chat->private_facet()->set_deleted();
    if (m_final_callback) {
        m_final_callback(false, m_secret_chat);
    }
    return 0;
}
