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

#include "query_get_and_set_password.h"

#include "crypto/crypto_sha.h"
#include "query_update_password_settings.h"
#include "tgl/tgl_update_callback.h"

namespace tgl {
namespace impl {

struct change_password_state {
    std::string current_password;
    std::string new_password;
    std::string current_salt;
    std::string new_salt;
    std::string hint;
    std::function<void(bool)> callback;
    std::weak_ptr<user_agent> weak_user_agent;
};

static void tgl_do_act_set_password(const std::shared_ptr<user_agent>& ua,
        const std::string& current_password,
        const std::string& new_password,
        const std::string& current_salt,
        const std::string& new_salt,
        const std::string& hint,
        const std::function<void(bool success)>& callback)
{
    char s[512];
    unsigned char shab[32];
    memset(s, 0, sizeof(s));
    memset(shab, 0, sizeof(shab));

    if (current_salt.size() > 128 || current_password.size() > 128 || new_salt.size() > 128 || new_password.size() > 128) {
        if (callback) {
            callback(false);
        }
        return;
    }

    std::shared_ptr<query> q = std::make_shared<query_update_password_settings>(callback);
    q->out_i32(CODE_account_update_password_settings);

    if (current_password.size() && current_salt.size()) {
        memcpy(s, current_salt.data(), current_salt.size());
        memcpy(s + current_salt.size(), current_password.data(), current_password.size());
        memcpy(s + current_salt.size() + current_password.size(), current_salt.data(), current_salt.size());

        TGLC_sha256((const unsigned char *)s, 2 * current_salt.size() + current_password.size(), shab);
        q->out_string((const char *)shab, 32);
    } else {
        q->out_string("");
    }

    q->out_i32(CODE_account_password_input_settings);
    if (new_password.size()) {
        q->out_i32(1);

        char d[256];
        memset(d, 0, sizeof(d));
        memcpy(d, new_salt.data(), new_salt.size());

        int l = new_salt.size();
        tgl_secure_random((unsigned char*)d + l, 16);
        l += 16;
        memcpy(s, d, l);

        memcpy(s + l, new_password.data(), new_password.size());
        memcpy(s + l + new_password.size(), d, l);

        TGLC_sha256((const unsigned char *)s, 2 * l + new_password.size(), shab);

        q->out_string(d, l);
        q->out_string((const char *)shab, 32);
        q->out_std_string(hint);
    } else {
        q->out_i32(1);
        q->out_string("");
        q->out_string("");
        q->out_string("");
    }

    q->execute(ua->active_client());
}

static void tgl_on_new_pwd(const std::shared_ptr<change_password_state>& state,
        const std::string& new_password, const std::string& confirm_password, const std::string& new_hint)
{
    auto ua = state->weak_user_agent.lock();
    if (!ua) {
        if (state->callback) {
            state->callback(false);
        }
        return;
    }

    state->new_password = new_password;
    state->hint = new_hint;

    if (state->new_password != confirm_password) {
        TGL_ERROR("passwords do not match");
        ua->callback()->get_value(std::make_shared<tgl_value_new_password>(
                std::bind(tgl_on_new_pwd, state, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3)));
        return;
    }

    tgl_do_act_set_password(ua,
            state->current_password,
            state->new_password,
            state->current_salt,
            state->new_salt,
            state->hint,
            state->callback);
}

query_get_and_set_password::query_get_and_set_password(
        const std::function<void(bool)>& callback)
    : query("get and set password", TYPE_TO_PARAM(account_password))
    , m_callback(callback)
{ }

void query_get_and_set_password::on_answer(void* D)
{
    auto ua = get_user_agent();
    if (!ua) {
        TGL_ERROR("the user agent has gone");
        if (m_callback) {
            m_callback(false);
        }
        return;
    }

    tl_ds_account_password* DS_AP = static_cast<tl_ds_account_password*>(D);
    std::shared_ptr<change_password_state> state = std::make_shared<change_password_state>();

    state->current_salt = DS_STDSTR(DS_AP->current_salt);
    state->new_salt = DS_STDSTR(DS_AP->new_salt);
    state->hint = DS_STDSTR(DS_AP->hint);

    state->callback = m_callback;
    state->weak_user_agent = ua;

    if (DS_AP->magic == CODE_account_no_password) {
        ua->callback()->get_value(std::make_shared<tgl_value_new_password>(
                std::bind(tgl_on_new_pwd, state, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3)));
    } else {
        ua->callback()->get_value(std::make_shared<tgl_value_current_and_new_password>(
            [=](const std::string& current_password,
                    const std::string& new_password,
                    const std::string& confirm_password,
                    const std::string& new_hint) {
                state->current_password = current_password;
                tgl_on_new_pwd(state, new_password, confirm_password, new_hint);
            }, state->hint));
    }
}

int query_get_and_set_password::on_error(int error_code, const std::string& error_string)
{
    TGL_ERROR("RPC_CALL_FAIL " << error_code << " " << error_string);
    if (m_callback) {
        m_callback(false);
    }
    return 0;
}

}
}
