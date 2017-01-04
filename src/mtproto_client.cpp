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

    Copyright Nikolay Durov, Andrey Lopatin 2012-2013
              Vitaly Valtman 2013-2015
    Copyright Topology LP 2016
*/

#include "mtproto_client.h"

#include "auto/auto.h"
#include "auto/auto-skip.h"
#include "auto/auto-types.h"
#include "crypto/tgl_crypto_aes.h"
#include "crypto/tgl_crypto_bn.h"
#include "crypto/tgl_crypto_rand.h"
#include "crypto/tgl_crypto_rsa_pem.h"
#include "crypto/tgl_crypto_sha.h"
#include "mtproto-common.h"
#include "mtproto-utils.h"
#include "queries.h"
#include "structures.h"
#include "tgl_rsa_key.h"
#include "tools.h"
#include "tgl/tgl.h"
#include "tgl/tgl_log.h"
#include "tgl/tgl_net.h"
#include "tgl/tgl_timer.h"
#include "tgl/tgl_queries.h"
#include "tgl/tgl_update_callback.h"
#include "updates.h"

#include <algorithm>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <memory>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

static constexpr float SESSION_CLEANUP_TIMEOUT = 5.0;
static constexpr int MAX_MESSAGE_INTS = 1048576;
static constexpr int ACK_TIMEOUT = 1;

#pragma pack(push,4)
struct encrypted_message {
    // unencrypted header
    int64_t auth_key_id;
    unsigned char msg_key[16];
    // encrypted part, starts with encrypted header
    int64_t server_salt;
    int64_t session_id;
    // first message follows
    int64_t msg_id;
    int32_t seq_no;
    int32_t msg_len;   // divisible by 4
    int32_t message[1];
};
#pragma pack(pop)

static_assert(!(sizeof(encrypted_message) & 3), "the encrypted_message has to be 4 bytes alligned");

inline static std::string to_string(mtproto_client::state state)
{
    switch (state) {
    case mtproto_client::state::init:
        return "init";
    case mtproto_client::state::reqpq_sent:
        return "request pq sent";
    case mtproto_client::state::reqdh_sent:
        return "request dh sent";
    case mtproto_client::state::client_dh_sent:
        return "client_dh_sent";
    case mtproto_client::state::init_temp:
        return "init (temp)";
    case mtproto_client::state::reqpq_sent_temp:
        return "request pq sent (temp)";
    case mtproto_client::state::reqdh_sent_temp:
        return "request dh sent (temp)";
    case mtproto_client::state::client_dh_sent_temp:
        return "client_dh_sent (temp)";
    case mtproto_client::state::authorized:
        return "authorized";
    case mtproto_client::state::error:
        return "error";
    default:
        assert(false);
        return "unknown client state";
    }
}

inline static std::ostream& operator<<(std::ostream& os, mtproto_client::state state)
{
    os << to_string(state);
    return os;
}

mtproto_client::mtproto_client(int32_t id)
    : m_id(id)
    , m_state(state::init)
    , m_auth_key_id(0)
    , m_temp_auth_key_id(0)
    , m_temp_auth_key_bind_query_id(0)
    , m_server_salt(0)
    , m_server_time_delta(0)
    , m_server_time_udelta(0)
    , m_auth_transfer_in_process(false)
    , m_active_queries(0)
    , m_logout_query_id(0)
    , m_authorized(false)
    , m_logged_in(false)
    , m_configured(false)
    , m_bound(false)
    , m_session_cleanup_timer()
    , m_rsa_key()
{
    memset(m_auth_key.data(), 0, m_auth_key.size());
    memset(m_temp_auth_key.data(), 0, m_temp_auth_key.size());
    memset(m_nonce.data(), 0, m_nonce.size());
    memset(m_new_nonce.data(), 0, m_new_nonce.size());
    memset(m_server_nonce.data(), 0, m_server_nonce.size());
}

void mtproto_client::ping()
{
    if (!is_configured()) {
        return;
    }

    int32_t buffer[3];
    buffer[0] = CODE_ping;
    *reinterpret_cast<int64_t*>(buffer + 1) = tgl_random<int64_t>();
    send_message(buffer, 3);
}

bool mtproto_client::try_rpc_execute(const std::shared_ptr<tgl_connection>& c)
{
    if (!m_session) {
        restart_session();
        return true;
    }

    assert(c);
    assert(m_session->c == c);

    while (true) {
        if (c->available_bytes_for_read() < 1) {
            return true;
        }
        unsigned len = 0;
        ssize_t result = c->peek(&len, 1);
        TGL_ASSERT_UNUSED(result, result == 1);
        if (len >= 1 && len <= 0x7e) {
            if (c->available_bytes_for_read() < 1 + 4 * len) {
                return true;
            }
        } else {
            if (c->available_bytes_for_read() < 4) {
                return true;
            }
            result = c->peek(&len, 4);
            TGL_ASSERT_UNUSED(result, result == 4);
            len = (len >> 8);
            if (c->available_bytes_for_read() < 4 + 4 * len) {
                return true;
            }
            len = 0x7f;
        }

        if (len >= 1 && len <= 0x7e) {
            unsigned t = 0;
            result = c->read(&t, 1);
            TGL_ASSERT_UNUSED(result, result == 1);
            TGL_ASSERT(t == len);
            TGL_ASSERT(len >= 1);
        } else {
            TGL_ASSERT(len == 0x7f);
            result = c->read(&len, 4);
            TGL_ASSERT_UNUSED(result, result == 4);
            len = (len >> 8);
            TGL_ASSERT(len >= 1);
        }
        len *= 4;
        int op;
        result = c->peek(&op, 4);
        TGL_ASSERT_UNUSED(result, result == 4);
        if (!rpc_execute(op, len)) {
            return false;
        }
    }
}

#define MAX_RESPONSE_SIZE        (1L << 24)

/*
 *
 *        UNAUTHORIZED (DH KEY EXCHANGE) PROTOCOL PART
 *
 */

//
// Used in unauthorized part of protocol
//
void mtproto_client::rpc_send_packet(const char* data, size_t len)
{
    struct {
        int64_t auth_key_id;
        int64_t out_msg_id;
        int msg_len;
    } unenc_msg_header;

    memset(&unenc_msg_header, 0, sizeof(unenc_msg_header));

    unenc_msg_header.out_msg_id = generate_next_msg_id();
    unenc_msg_header.msg_len = len;

    int total_len = len + 20;
    assert(total_len > 0 && !(total_len & 0xfc000003));
    total_len >>= 2;
    TGL_DEBUG("writing packet: total_len = " << total_len << ", len = " << len);

    const std::shared_ptr<tgl_connection>& c = m_session->c;
    if (total_len < 0x7f) {
        int result = c->write(&total_len, 1);
        TGL_ASSERT_UNUSED(result, result == 1);
    } else {
        total_len = (total_len << 8) | 0x7f;
        int result = c->write(&total_len, 4);
        TGL_ASSERT_UNUSED(result, result == 4);
    }
    c->write(&unenc_msg_header, 20);
    c->write(data, len);
    c->flush();
}

static int rpc_send_message(const std::shared_ptr<tgl_connection>& c, void* data, int len)
{
    assert(len > 0 && !(len & 0xfc000003));

    int total_len = len >> 2;
    if (total_len < 0x7f) {
        int result = c->write(&total_len, 1);
        TGL_ASSERT_UNUSED(result, result == 1);
    } else {
        total_len = (total_len << 8) | 0x7f;
        int result = c->write(&total_len, 4);
        TGL_ASSERT_UNUSED(result, result == 4);
    }

    int result = c->write(data, len);
    TGL_ASSERT_UNUSED(result, result == len);
    c->flush();

    return 1;
}

//
// State machine. See description at
// https://core.telegram.org/mtproto/auth_key
//


static int check_unauthorized_header(tgl_in_buffer* in)
{
    if (in->end - in->ptr < 5) {
        TGL_ERROR("ERROR: the input buffer is small than 5 ints");
        return -1;
    }
    int64_t auth_key_id = fetch_i64(in);
    if (auth_key_id) {
        TGL_ERROR("ERROR: auth_key_id should be NULL");
        return -1;
    }
    fetch_i64(in); // msg_id
    int32_t len = fetch_i32(in);
    if (len != 4 * (in->end - in->ptr)) {
        TGL_ERROR("ERROR: length mismatch");
        return -1;
    }
    return 0;
}

/* {{{ REQ_PQ */
// req_pq#60469778 nonce:int128 = ResPQ
void mtproto_client::send_req_pq_packet()
{
    assert(m_state == state::init);
    assert(m_session);
    assert(m_session->c);

    tgl_secure_random(m_nonce.data(), 16);
    mtprotocol_serializer s;
    s.out_i32(CODE_req_pq);
    s.out_i32s(reinterpret_cast<int32_t*>(m_nonce.data()), 4);
    TGL_DEBUG("sending request pq to DC " << m_id);
    rpc_send_packet(s.char_data(), s.char_size());

    m_state = state::reqpq_sent;
}

// req_pq#60469778 nonce:int128 = ResPQ
void mtproto_client::send_req_pq_temp_packet()
{
    assert(m_state == state::authorized);

    tgl_secure_random(m_nonce.data(), 16);
    mtprotocol_serializer s;
    s.out_i32(CODE_req_pq);
    s.out_i32s(reinterpret_cast<int32_t*>(m_nonce.data()), 4);
    TGL_DEBUG("send request pq (temp) to DC " << m_id);
    rpc_send_packet(s.char_data(), s.char_size());

    m_state = state::reqpq_sent_temp;
}
/* }}} */

/* {{{ REQ DH */
// req_DH_params#d712e4be nonce:int128 server_nonce:int128 p:string q:string public_key_fingerprint:long encrypted_data:string = Server_DH_Params;
// p_q_inner_data#83c95aec pq:string p:string q:string nonce:int128 server_nonce:int128 new_nonce:int256 = P_Q_inner_data;
// p_q_inner_data_temp#3c6a84d4 pq:string p:string q:string nonce:int128 server_nonce:int128 new_nonce:int256 expires_in:int = P_Q_inner_data;
void mtproto_client::send_req_dh_packet(TGLC_bn* pq, bool temp_key)
{
    std::unique_ptr<TGLC_bn, TGLC_bn_deleter> p(TGLC_bn_new());
    std::unique_ptr<TGLC_bn, TGLC_bn_deleter> q(TGLC_bn_new());
    auto result = bn_factorize(pq, p.get(), q.get());
    TGL_ASSERT_UNUSED(result, result >= 0);

    mtprotocol_serializer s;
    size_t at = s.reserve_i32s(5);
    s.out_i32(temp_key ? CODE_p_q_inner_data_temp : CODE_p_q_inner_data);

    s.out_bignum(pq);
    s.out_bignum(p.get());
    s.out_bignum(q.get());

    s.out_i32s(reinterpret_cast<int32_t*>(m_nonce.data()), 4);
    s.out_i32s(reinterpret_cast<int32_t*>(m_server_nonce.data()), 4);
    tgl_secure_random(m_new_nonce.data(), 32);
    s.out_i32s(reinterpret_cast<int32_t*>(m_new_nonce.data()), 8);
    if (temp_key) {
        TGL_DEBUG("creating temp auth key expiring in " << tgl_state::instance()->temp_key_expire_time() << " seconds for DC " << m_id);
        s.out_i32(tgl_state::instance()->temp_key_expire_time());
    }

    unsigned char sha1_buffer[20];
    memset(sha1_buffer, 0, sizeof(sha1_buffer));
    TGLC_sha1(reinterpret_cast<const unsigned char*>(s.i32_data() + at + 5), (s.i32_size() - at - 5) * 4, sha1_buffer);
    s.out_i32s_at(at, reinterpret_cast<int32_t*>(sha1_buffer), 5);

    int encrypted_buffer_size = tgl_pad_rsa_encrypt_dest_buffer_size(s.char_size());
    assert(encrypted_buffer_size > 0);
    std::unique_ptr<char[]> encrypted_data(new char[encrypted_buffer_size]);
    const TGLC_rsa* key = m_rsa_key->public_key();
    size_t unpadded_size = s.ensure_char_size(encrypted_buffer_size);
    int encrypted_data_size = tgl_pad_rsa_encrypt(s.char_data(), unpadded_size, encrypted_data.get(), encrypted_buffer_size, TGLC_rsa_n(key), TGLC_rsa_e(key));

    s.clear();
    s.out_i32(CODE_req_DH_params);
    s.out_i32s(reinterpret_cast<int32_t*>(m_nonce.data()), 4);
    s.out_i32s(reinterpret_cast<int32_t*>(m_server_nonce.data()), 4);
    s.out_bignum(p.get());
    s.out_bignum(q.get());

    s.out_i64(m_rsa_key->fingerprint());
    s.out_string(encrypted_data.get(), encrypted_data_size);

    m_state = temp_key ? state::reqdh_sent_temp : state::reqdh_sent;
    TGL_DEBUG("sending request dh (temp_key=" << std::boolalpha << temp_key << ") to DC " << m_id);
    rpc_send_packet(s.char_data(), s.char_size());
}
/* }}} */

/* {{{ SEND DH PARAMS */
// set_client_DH_params#f5045f1f nonce:int128 server_nonce:int128 encrypted_data:string = Set_client_DH_params_answer;
// client_DH_inner_data#6643b654 nonce:int128 server_nonce:int128 retry_id:long g_b:string = Client_DH_Inner_Data
void mtproto_client::send_dh_params(TGLC_bn* dh_prime, TGLC_bn* g_a, int g, bool temp_key)
{
    mtprotocol_serializer s;
    size_t at = s.reserve_i32s(5);
    s.out_i32(CODE_client_DH_inner_data);
    s.out_i32s(reinterpret_cast<int32_t*>(m_nonce.data()), 4);
    s.out_i32s(reinterpret_cast<int32_t*>(m_server_nonce.data()), 4);
    s.out_i64(0);

    std::unique_ptr<TGLC_bn, TGLC_bn_deleter> dh_g(TGLC_bn_new());
    check_crypto_result(TGLC_bn_set_word(dh_g.get(), g));

    unsigned char s_power[256];
    tgl_secure_random(s_power, 256);
    std::unique_ptr<TGLC_bn, TGLC_bn_deleter> dh_power(TGLC_bn_bin2bn((unsigned char *)s_power, 256, 0));

    std::unique_ptr<TGLC_bn, TGLC_bn_deleter> y(TGLC_bn_new());
    check_crypto_result(TGLC_bn_mod_exp(y.get(), dh_g.get(), dh_power.get(), dh_prime, tgl_state::instance()->bn_ctx()->ctx));
    s.out_bignum(y.get());

    std::unique_ptr<TGLC_bn, TGLC_bn_deleter> auth_key_num(TGLC_bn_new());
    check_crypto_result(TGLC_bn_mod_exp(auth_key_num.get(), g_a, dh_power.get(), dh_prime, tgl_state::instance()->bn_ctx()->ctx));
    int l = TGLC_bn_num_bytes(auth_key_num.get());
    assert(l >= 250 && l <= 256);
    auto result = TGLC_bn_bn2bin(auth_key_num.get(), (temp_key ? m_temp_auth_key.data() : m_auth_key.data()));
    TGL_ASSERT_UNUSED(result, result);
    if (l < 256) {
        unsigned char* key = temp_key ? m_temp_auth_key.data() : m_auth_key.data();
        memmove(key + 256 - l, key, l);
        memset(key, 0, 256 - l);
    }

    unsigned char sha1_buffer[20];
    memset(sha1_buffer, 0, sizeof(sha1_buffer));
    TGLC_sha1(reinterpret_cast<const unsigned char*>(s.i32_data() + at + 5), (s.i32_size() - at - 5) * 4, sha1_buffer);
    s.out_i32s_at(at, reinterpret_cast<int32_t*>(sha1_buffer), 5);

    TGLC_aes_key aes_key;
    unsigned char aes_iv[32];
    tgl_init_aes_unauth(&aes_key, aes_iv, m_server_nonce.data(), m_new_nonce.data(), 1);
    int encrypted_buffer_size = tgl_pad_aes_encrypt_dest_buffer_size(s.char_size());
    std::unique_ptr<char[]> encrypted_data(new char[encrypted_buffer_size]);
    size_t unpadded_size = s.ensure_char_size(encrypted_buffer_size);
    int encrypted_data_size = tgl_pad_aes_encrypt(&aes_key, aes_iv, reinterpret_cast<const unsigned char*>(s.char_data()), unpadded_size,
            reinterpret_cast<unsigned char*>(encrypted_data.get()), encrypted_buffer_size);

    s.clear();
    s.out_i32(CODE_set_client_DH_params);
    s.out_i32s(reinterpret_cast<int32_t*>(m_nonce.data()), 4);
    s.out_i32s(reinterpret_cast<int32_t*>(m_server_nonce.data()), 4);
    s.out_string(encrypted_data.get(), encrypted_data_size);

    m_state = temp_key ? state::client_dh_sent_temp : state::client_dh_sent;;
    TGL_DEBUG("sending dh parameters (temp_key=" << std::boolalpha << temp_key << ") to DC " << m_id);
    rpc_send_packet(s.char_data(), s.char_size());
}
/* }}} */

/* {{{ RECV RESPQ */
// resPQ#05162463 nonce:int128 server_nonce:int128 pq:string server_public_key_fingerprints:Vector long = ResPQ
bool mtproto_client::process_respq_answer(const char* packet, int len, bool temp_key)
{
    assert(!(len & 3));
    tgl_in_buffer in;
    in.ptr = reinterpret_cast<const int*>(packet);
    in.end = in.ptr + (len / 4);
    if (check_unauthorized_header(&in) < 0) {
        return false;
    }

    tgl_in_buffer skip_in = in;
    struct paramed_type type = TYPE_TO_PARAM(res_p_q);
    if (skip_type_any(&skip_in, &type) < 0 || skip_in.ptr != skip_in.end) {
        TGL_ERROR("can not parse req_p_q answer");
        return false;
    }

    auto result = fetch_i32(&in);
    TGL_ASSERT_UNUSED(result, result == static_cast<int32_t>(CODE_res_pq));

    int tmp[4];
    fetch_i32s(&in, tmp, 4);
    if (memcmp(tmp, m_nonce.data(), 16)) {
        TGL_ERROR("nonce mismatch");
        return false;
    }
    fetch_i32s(&in, reinterpret_cast<int32_t*>(m_server_nonce.data()), 4);

    std::unique_ptr<TGLC_bn, TGLC_bn_deleter> pq(TGLC_bn_new());
    result = fetch_bignum(&in, pq.get());
    TGL_ASSERT_UNUSED(result, result >= 0);

    result = fetch_i32(&in);
    TGL_ASSERT_UNUSED(result, result == static_cast<int32_t>(CODE_vector));
    int32_t fingerprints_num = fetch_i32(&in);
    assert(fingerprints_num >= 0);
    m_rsa_key = nullptr;

    for (int i = 0; i < fingerprints_num; i++) {
        int64_t fingerprint = fetch_i64(&in);
        for (const auto& key : tgl_state::instance()->rsa_key_list()) {
            if (key->is_loaded() && fingerprint == key->fingerprint()) {
                m_rsa_key = key;
                break;
            }
        }
    }
    assert(in.ptr == in.end);
    if (!m_rsa_key) {
        TGL_ERROR("fatal: don't have any matching keys");
        return false;
    }

    send_req_dh_packet(pq.get(), temp_key);

    return true;
}
/* }}} */

/* {{{ RECV DH */
// server_DH_params_fail#79cb045d nonce:int128 server_nonce:int128 new_nonce_hash:int128 = Server_DH_Params;
// server_DH_params_ok#d0e8075c nonce:int128 server_nonce:int128 encrypted_answer:string = Server_DH_Params;
// server_DH_inner_data#b5890dba nonce:int128 server_nonce:int128 g:int dh_prime:string g_a:string server_time:int = Server_DH_inner_data;
bool mtproto_client::process_dh_answer(const char* packet, int len, bool temp_key)
{
    assert(!(len & 3));
    tgl_in_buffer in;
    in.ptr = reinterpret_cast<const int*>(packet);
    in.end = in.ptr + (len / 4);
    if (check_unauthorized_header(&in) < 0) {
        return false;
    }

    tgl_in_buffer skip_in = in;
    struct paramed_type type = TYPE_TO_PARAM(server_d_h_params);
    if (skip_type_any(&skip_in, &type) < 0 || skip_in.ptr != skip_in.end) {
        TGL_ERROR("can not parse server_DH_params answer");
        return false;
    }

    uint32_t op = fetch_i32(&in);
    assert(op == CODE_server__dh_params_ok || op == CODE_server__dh_params_fail);

    int tmp[4];
    fetch_i32s(&in, tmp, 4);
    if (memcmp(tmp, m_nonce.data(), 16)) {
        TGL_ERROR("nonce mismatch");
        return false;
    }
    fetch_i32s(&in, tmp, 4);
    if (memcmp(tmp, m_server_nonce.data(), 16)) {
        TGL_ERROR("server nonce mismatch");
        return false;
    }

    if (op == CODE_server__dh_params_fail) {
        TGL_ERROR("DH params fail");
        return false;
    }

    TGLC_aes_key aes_key;
    unsigned char aes_iv[32];
    tgl_init_aes_unauth(&aes_key, aes_iv, m_server_nonce.data(), m_new_nonce.data(), 0);

    ssize_t l = prefetch_strlen(&in);
    assert(l > 0);
    if (l <= 0) {
        TGL_ERROR("non-empty encrypted part expected");
        return false;
    }
    int decrypted_buffer_size = tgl_pad_aes_decrypt_dest_buffer_size(l);
    assert(decrypted_buffer_size > 0);
    if (decrypted_buffer_size <= 0) {
        TGL_ERROR("failed to get decrypted buffer size");
        return false;
    }

    std::unique_ptr<int[]> decrypted_buffer(new int[(decrypted_buffer_size + 3) / 4]);
    l = tgl_pad_aes_decrypt(&aes_key,
            aes_iv,
            reinterpret_cast<const unsigned char *>(fetch_str(&in, l)),
            l,
            reinterpret_cast<unsigned char*>(decrypted_buffer.get()), decrypted_buffer_size);
    assert(in.ptr == in.end);

    tgl_in_buffer skip = { decrypted_buffer.get() + 5, decrypted_buffer.get() + (decrypted_buffer_size >> 2) };
    struct paramed_type type2 = TYPE_TO_PARAM(server_d_h_inner_data);
    if (skip_type_any(&skip, &type2) < 0) {
        TGL_ERROR("can not parse server_DH_inner_data answer");
        return false;
    }
    in.ptr = decrypted_buffer.get() + 5;
    in.end = decrypted_buffer.get() + (decrypted_buffer_size >> 2);

    auto result = fetch_i32(&in);
    TGL_ASSERT_UNUSED(result, result == static_cast<int32_t>(CODE_server_DH_inner_data));
    fetch_i32s(&in, tmp, 4);
    if (memcmp(tmp, m_nonce.data(), 16)) {
        TGL_ERROR("inner nonce mismatch");
        return false;
    }
    fetch_i32s(&in, tmp, 4);
    if (memcmp(tmp, m_server_nonce.data(), 16)) {
        TGL_ERROR("inner server nonce mismatch");
        return false;
    }
    int32_t g = fetch_i32(&in);

    std::unique_ptr<TGLC_bn, TGLC_bn_deleter> dh_prime(TGLC_bn_new());
    std::unique_ptr<TGLC_bn, TGLC_bn_deleter> g_a(TGLC_bn_new());
    result = fetch_bignum(&in, dh_prime.get());
    TGL_ASSERT_UNUSED(result, result > 0);
    result = fetch_bignum(&in, g_a.get());
    TGL_ASSERT_UNUSED(result, result > 0);

    if (tglmp_check_DH_params(dh_prime.get(), g) < 0) {
        TGL_ERROR("bad DH params");
        return false;
    }
    if (tglmp_check_g_a(dh_prime.get(), g_a.get()) < 0) {
        TGL_ERROR("bad dh_prime");
        return false;
    }

    int32_t server_time = fetch_i32(&in);
    assert(in.ptr <= in.end);

    char sha1_buffer[20];
    memset(sha1_buffer, 0, sizeof(sha1_buffer));
    TGLC_sha1((unsigned char *) decrypted_buffer.get() + 20, (in.ptr - decrypted_buffer.get() - 5) * 4, (unsigned char *) sha1_buffer);
    if (memcmp(decrypted_buffer.get(), sha1_buffer, 20)) {
        TGL_ERROR("bad encrypted message SHA1");
        return false;
    }
    if ((char *) in.end - (char *) in.ptr >= 16) {
        TGL_ERROR("too much padding");
        return false;
    }

    m_server_time_delta = server_time - tgl_get_system_time();
    m_server_time_udelta = server_time - tgl_get_monotonic_time();

    send_dh_params(dh_prime.get(), g_a.get(), g, temp_key);

    return true;
}
/* }}} */

void mtproto_client::create_temp_auth_key()
{
    assert(tgl_state::instance()->pfs_enabled());
    send_req_pq_temp_packet();
}

void mtproto_client::restart_authorization(bool temp_key)
{
    if (temp_key) {
        restart_temp_authorization();
    } else {
        restart_authorization();
    }
}

/* {{{ RECV AUTH COMPLETE */

// dh_gen_ok#3bcbf734 nonce:int128 server_nonce:int128 new_nonce_hash1:int128 = Set_client_DH_params_answer;
// dh_gen_retry#46dc1fb9 nonce:int128 server_nonce:int128 new_nonce_hash2:int128 = Set_client_DH_params_answer;
// dh_gen_fail#a69dae02 nonce:int128 server_nonce:int128 new_nonce_hash3:int128 = Set_client_DH_params_answer;
bool mtproto_client::process_auth_complete(const char* packet, int len, bool temp_key)
{
    assert(!(len & 3));
    tgl_in_buffer in;
    in.ptr = reinterpret_cast<const int*>(packet);
    in.end = in.ptr + (len / 4);
    if (check_unauthorized_header(&in) < 0) {
        TGL_ERROR("check header failed");
        restart_authorization(temp_key);
        return true;
    }

    tgl_in_buffer skip_in = in;
    struct paramed_type type = TYPE_TO_PARAM(set_client_d_h_params_answer);
    if (skip_type_any(&skip_in, &type) < 0 || skip_in.ptr != skip_in.end) {
        TGL_ERROR("can not parse server_DH_params answer");
        restart_authorization(temp_key);
        return true;
    }

    uint32_t op = fetch_i32(&in);
    assert(op == CODE_dh_gen_ok || op == CODE_dh_gen_retry || op == CODE_dh_gen_fail);

    int tmp[4];
    fetch_i32s(&in, tmp, 4);
    if (memcmp(m_nonce.data(), tmp, 16)) {
        TGL_ERROR("nonce mismatch");
        restart_authorization(temp_key);
        return true;
    }
    fetch_i32s(&in, tmp, 4);
    if (memcmp(m_server_nonce.data(), tmp, 16)) {
        TGL_ERROR("server nonce mismatch");
        restart_authorization(temp_key);
        return true;
    }
    if (op != CODE_dh_gen_ok) {
        TGL_DEBUG("DH failed for DC " << m_id << ", retrying");
        restart_authorization(temp_key);
        return true;
    }

    fetch_i32s(&in, tmp, 4);

    unsigned char th[44], sha1_buffer[20];
    memset(th, 0, sizeof(th));
    memset(sha1_buffer, 0, sizeof(sha1_buffer));
    memcpy(th, m_new_nonce.data(), 32);
    th[32] = 1;
    if (!temp_key) {
        TGLC_sha1(m_auth_key.data(), 256, sha1_buffer);
    } else {
        TGLC_sha1(m_temp_auth_key.data(), 256, sha1_buffer);
    }
    memcpy(th + 33, sha1_buffer, 8);
    TGLC_sha1(th, 41, sha1_buffer);
    if (memcmp(tmp, sha1_buffer + 4, 16)) {
        TGL_ERROR("hash mismatch");
        restart_authorization(temp_key);
        return true;
    }

    calculate_auth_key_id(temp_key);
    if (!temp_key) {
        tgl_state::instance()->callback()->dc_updated(shared_from_this());
    }

    m_server_salt = *reinterpret_cast<int64_t*>(m_server_nonce.data()) ^ *reinterpret_cast<int64_t*>(m_new_nonce.data());

    m_state = state::authorized;

    TGL_DEBUG("auth success for DC " << m_id << " " << (temp_key ? "(temp)" : "") << " salt=" << m_server_salt);
    if (temp_key) {
        bind_temp_auth_key();
    } else {
        set_authorized();
        if (tgl_state::instance()->pfs_enabled()) {
            create_temp_auth_key();
        } else {
            m_temp_auth_key_id = m_auth_key_id;
            memcpy(m_temp_auth_key.data(), m_auth_key.data(), 256);
            set_bound();
            if (!is_configured()) {
                tgl_do_help_get_client_config(shared_from_this());
            } else {
                // To trigger sending pending queries if any.
                tgl_do_set_client_configured(shared_from_this(), true);
            }
        }
    }

    return true;
}
/* }}} */

void mtproto_client::bind_temp_auth_key()
{
    if (!m_session) {
        TGL_WARNING("no session created for DC " << m_id);
        return;
    }

    if (m_temp_auth_key_bind_query_id) {
        tglq_query_delete(m_temp_auth_key_bind_query_id);
    }
    int64_t msg_id = generate_next_msg_id();

    mtprotocol_serializer s;
    s.out_i32(CODE_bind_auth_key_inner);
    int64_t rand;
    tgl_secure_random(reinterpret_cast<unsigned char*>(&rand), 8);
    s.out_i64(rand);
    s.out_i64(m_temp_auth_key_id);
    s.out_i64(m_auth_key_id);

    while (!m_session->session_id) {
        tgl_secure_random(reinterpret_cast<unsigned char*>(&m_session->session_id), 8);
    }
    s.out_i64(m_session->session_id);
    int expires = tgl_get_system_time() + m_server_time_delta + tgl_state::instance()->temp_key_expire_time();
    s.out_i32(expires);

    int data[1000];
    memset(data, 0, sizeof(data));
    int len = encrypt_inner_temp(s.i32_data(), s.i32_size(), data, msg_id);
    m_temp_auth_key_bind_query_id = msg_id;
    tgl_do_bind_temp_key(shared_from_this(), rand, expires, data, len, msg_id);
}

/*
 *
 *                AUTHORIZED (MAIN) PROTOCOL PART
 *
 */

double mtproto_client::get_server_time()
{
    return tgl_get_monotonic_time() + m_server_time_udelta;
}

int64_t mtproto_client::generate_next_msg_id()
{
    int64_t next_id = static_cast<int64_t>(get_server_time()*(1LL << 32)) & -4;
    if (next_id <= m_session->last_msg_id) {
        next_id = m_session->last_msg_id += 4;
    } else {
        m_session->last_msg_id = next_id;
    }
    return next_id;
}

void mtproto_client::init_enc_msg(encrypted_message& enc_msg, bool useful)
{
    assert(m_state == state::authorized);
    assert(m_temp_auth_key_id);
    assert(m_session);

    enc_msg.auth_key_id = m_temp_auth_key_id;
    enc_msg.server_salt = m_server_salt;
    while (!m_session->session_id) {
        tgl_secure_random(reinterpret_cast<unsigned char*>(&m_session->session_id), 8);
    }
    enc_msg.session_id = m_session->session_id;
    if (!enc_msg.msg_id) {
        enc_msg.msg_id = generate_next_msg_id();
    }
    enc_msg.seq_no = m_session->seq_no;
    if (useful) {
        enc_msg.seq_no |= 1;
    }
    m_session->seq_no += 2;
};

void mtproto_client::init_enc_msg_inner_temp(encrypted_message& enc_msg, int64_t msg_id)
{
    enc_msg.auth_key_id = m_auth_key_id;
    tgl_secure_random((unsigned char*)&enc_msg.server_salt, 8);
    tgl_secure_random((unsigned char*)&enc_msg.session_id, 8);
    enc_msg.msg_id = msg_id;
    enc_msg.seq_no = 0;
};


static int aes_encrypt_message(unsigned char* key, struct encrypted_message* enc)
{
    unsigned char sha1_buffer[20];
    memset(sha1_buffer, 0, sizeof(sha1_buffer));
    const int MINSZ = offsetof(struct encrypted_message, message);
    const int UNENCSZ = offsetof(struct encrypted_message, server_salt);

    int enc_len = (MINSZ - UNENCSZ) + enc->msg_len;
    assert(enc->msg_len >= 0 && enc->msg_len <= MAX_MESSAGE_INTS * 4 - 16 && !(enc->msg_len & 3));
    TGLC_sha1((unsigned char *) &enc->server_salt, enc_len, sha1_buffer);
    memcpy(enc->msg_key, sha1_buffer + 4, 16);
    TGLC_aes_key aes_key;
    unsigned char aes_iv[32];
    tgl_init_aes_auth(&aes_key, aes_iv, key, enc->msg_key, AES_ENCRYPT);
    return tgl_pad_aes_encrypt(&aes_key, aes_iv, (unsigned char *) &enc->server_salt, enc_len,
            (unsigned char*)&enc->server_salt, tgl_pad_aes_encrypt_dest_buffer_size(enc_len));
}

static std::unique_ptr<char[]> allocate_encrypted_message_buffer(int msg_ints)
{
    // This will be slightly larger than the exactly needed.
    int buffer_size = sizeof(encrypted_message) + tgl_pad_aes_encrypt_dest_buffer_size(
            offsetof(encrypted_message, message) - offsetof(encrypted_message, server_salt) + msg_ints * 4);

    std::unique_ptr<char[]> buffer(new char[buffer_size]);
    memset(buffer.get(), 0, buffer_size);
    return buffer;
}

int64_t mtproto_client::send_message(
        const int32_t* msg, int msg_ints,
        int64_t msg_id_override, bool force_send, bool useful)
{
    if (!m_session || !m_session->c) {
        return -1;
    }

    assert(is_configured() || force_send);

    const int UNENCSZ = offsetof(struct encrypted_message, server_salt);
    if (msg_ints <= 0) {
        TGL_NOTICE("message length is zero or negative");
        return -1;
    }

    if (msg_ints > MAX_MESSAGE_INTS - 4) {
        TGL_NOTICE("message too long");
        return -1;
    }

    std::unique_ptr<char[]> buffer = allocate_encrypted_message_buffer(msg_ints);
    encrypted_message* enc_msg = reinterpret_cast<encrypted_message*>(buffer.get());

    memcpy(enc_msg->message, msg, msg_ints * 4);
    enc_msg->msg_len = msg_ints * 4;

    enc_msg->msg_id = msg_id_override;
    init_enc_msg(*enc_msg, useful);
    int64_t msg_id = enc_msg->msg_id;

    int l = aes_encrypt_message(m_temp_auth_key.data(), enc_msg);
    assert(l > 0);
    rpc_send_message(m_session->c, enc_msg, l + UNENCSZ);

    return msg_id;
}

int mtproto_client::encrypt_inner_temp(const int32_t* msg, int msg_ints, void* data, int64_t msg_id)
{
    const int UNENCSZ = offsetof(struct encrypted_message, server_salt);
    if (msg_ints <= 0 || msg_ints > MAX_MESSAGE_INTS - 4) {
        return -1;
    }

    std::unique_ptr<char[]> buffer = allocate_encrypted_message_buffer(msg_ints);
    encrypted_message* enc_msg = reinterpret_cast<encrypted_message*>(buffer.get());

    memcpy(enc_msg->message, msg, msg_ints * 4);
    enc_msg->msg_len = msg_ints * 4;

    init_enc_msg_inner_temp(*enc_msg, msg_id);

    int length = aes_encrypt_message(m_auth_key.data(), enc_msg);
    assert(length > 0);
    memcpy(data, enc_msg, length + UNENCSZ);

    return length + UNENCSZ;
}

int mtproto_client::work_container(tgl_in_buffer* in, int64_t msg_id)
{
    TGL_DEBUG("work_container: msg_id = " << msg_id);
    auto result = fetch_i32(in);
    TGL_ASSERT_UNUSED(result, result == static_cast<int32_t>(CODE_msg_container));
    int32_t n = fetch_i32(in);
    for (int32_t i = 0; i < n; i++) {
        int64_t id = fetch_i64(in);
        //int seqno = fetch_i32();
        fetch_i32(in); // seq_no
        if (id & 1) {
            if (!m_session) {
                return -1;
            }
            insert_msg_id(id);
        }
        int32_t bytes = fetch_i32(in);
        const int32_t* t = in->end;
        in->end = in->ptr + (bytes / 4);
        int r = rpc_execute_answer(in, id);
        if (r < 0) {
            return -1;
        }
        assert(in->ptr == in->end);
        in->end = t;
    }
    TGL_DEBUG("end work_container: msg_id = " << msg_id);
    return 0;
}

int mtproto_client::work_new_session_created(tgl_in_buffer* in, int64_t msg_id)
{
    if (!m_session) {
        return -1;
    }
    TGL_DEBUG("work_new_session_created: msg_id = " << msg_id << ", DC " << m_id);
    auto result = fetch_i32(in);
    TGL_ASSERT_UNUSED(result, result == static_cast<int32_t>(CODE_new_session_created));
    fetch_i64(in); // first message id
    fetch_i64(in); // unique_id
    m_server_salt = fetch_i64(in);

    if (tgl_state::instance()->is_started()
            && !tgl_state::instance()->is_diff_locked()
            && tgl_state::instance()->active_client()->is_logged_in()) {
        tgl_do_get_difference(false, nullptr);
    }
    return 0;
}

static int work_msgs_ack(tgl_in_buffer* in, int64_t msg_id)
{
    TGL_DEBUG("work_msgs_ack: msg_id = " << msg_id);
    auto result = fetch_i32(in);
    TGL_ASSERT_UNUSED(result, result == static_cast<int32_t>(CODE_msgs_ack));
    result = fetch_i32(in);
    TGL_ASSERT_UNUSED(result, result == static_cast<int32_t>(CODE_vector));
    int32_t n = fetch_i32(in);
    for (int32_t i = 0; i < n; i++) {
        int64_t id = fetch_i64(in);
        TGL_DEBUG("ack for " << id);
        tglq_query_ack(id);
    }
    return 0;
}

static int work_rpc_result(tgl_in_buffer* in, int64_t msg_id)
{
    TGL_DEBUG("work_rpc_result: msg_id = " << msg_id);
    auto result = fetch_i32(in);
    TGL_ASSERT_UNUSED(result, result == static_cast<int32_t>(CODE_rpc_result));
    int64_t id = fetch_i64(in);
    uint32_t op = prefetch_i32(in);
    if (op == CODE_rpc_error) {
        return tglq_query_error(in, id);
    } else {
        return tglq_query_result(in, id);
    }
}

int mtproto_client::work_packed(tgl_in_buffer* in, int64_t msg_id)
{
    auto result = fetch_i32(in);
    TGL_ASSERT_UNUSED(result, result == static_cast<int32_t>(CODE_gzip_packed));
    constexpr size_t MAX_PACKED_SIZE = 1 << 24;
    std::unique_ptr<int32_t[]> unzipped_buffer(new int32_t[MAX_PACKED_SIZE >> 2]);

    ssize_t l = prefetch_strlen(in);
    const char* s = fetch_str(in, l);

    int total_out = tgl_inflate(s, l, unzipped_buffer.get(), MAX_PACKED_SIZE);
    tgl_in_buffer new_in = { unzipped_buffer.get(), unzipped_buffer.get() + total_out / 4 };
    int r = rpc_execute_answer(&new_in, msg_id, true);
    return r;
}

int mtproto_client::work_bad_server_salt(tgl_in_buffer* in)
{
    auto result = fetch_i32(in);
    TGL_ASSERT_UNUSED(result, result == static_cast<int32_t>(CODE_bad_server_salt));
    int64_t id = fetch_i64(in);
    int32_t seq_no = fetch_i32(in); // seq_no
    int32_t error_code = fetch_i32(in); // error_code
    int64_t new_server_salt = fetch_i64(in);
    TGL_DEBUG(" DC " << m_id << " id = " << id << " seq_no = " << seq_no
            << " error_code = " << error_code << " new_server_salt =" << new_server_salt
            << " old_server_salt = " << m_server_salt);
    m_server_salt = new_server_salt;
    tglq_query_restart(id);
    return 0;
}

static int work_pong(tgl_in_buffer* in)
{
    auto result = fetch_i32(in);
    TGL_ASSERT_UNUSED(result, result == static_cast<int32_t>(CODE_pong));
    fetch_i64(in); // msg_id
    fetch_i64(in); // ping_id
    return 0;
}

static int work_detailed_info(tgl_in_buffer* in)
{
    auto result = fetch_i32(in);
    TGL_ASSERT_UNUSED(result, result == static_cast<int32_t>(CODE_msg_detailed_info));
    fetch_i64(in); // msg_id
    fetch_i64(in); // answer_msg_id
    fetch_i32(in); // bytes
    fetch_i32(in); // status
    return 0;
}

static int work_new_detailed_info(tgl_in_buffer* in)
{
    auto result = fetch_i32(in);
    TGL_ASSERT_UNUSED(result, result == static_cast<int32_t>(CODE_msg_new_detailed_info));
    fetch_i64(in); // answer_msg_id
    fetch_i32(in); // bytes
    fetch_i32(in); // status
    return 0;
}

static int work_bad_msg_notification(tgl_in_buffer* in)
{
    auto result = fetch_i32(in);
    TGL_ASSERT_UNUSED(result, result == static_cast<int32_t>(CODE_bad_msg_notification));
    int64_t m1 = fetch_i64(in);
    int32_t s = fetch_i32(in);
    int32_t e = fetch_i32(in);
    TGL_NOTICE("bad_msg_notification: msg_id = " << m1 << ", seq = " << s << ", error = " << e);
    switch (e) {
    // Too low msg id
    case 16:
      tglq_regen_query(m1);
      break;
    // Too high msg id
    case 17:
      tglq_regen_query(m1);
      break;
    // Bad container
    case 64:
      TGL_NOTICE("bad_msg_notification: msg_id = " << m1 << ", seq = " << s << ", error = " << e);
      tglq_regen_query(m1);
      break;
    default:
      TGL_NOTICE("bad_msg_notification: msg_id = " << m1 << ", seq = " << s << ", error = " << e);
      break;
    }

    return -1;
}

int mtproto_client::rpc_execute_answer(tgl_in_buffer* in, int64_t msg_id, bool in_gzip)
{
    uint32_t op = prefetch_i32(in);
    switch (op) {
    case CODE_msg_container:
        return work_container(in, msg_id);
    case CODE_new_session_created:
        return work_new_session_created(in, msg_id);
    case CODE_msgs_ack:
        return work_msgs_ack(in, msg_id);
    case CODE_rpc_result:
        return work_rpc_result(in, msg_id);
    case CODE_update_short:
    case CODE_updates:
    case CODE_update_short_message:
    case CODE_update_short_chat_message:
    case CODE_updates_too_long:
        tglu_work_any_updates(in);
        return 0;
    case CODE_gzip_packed:
        if (in_gzip) {
            TGL_ERROR("no netsted zip");
            TGL_CRASH();
        }
        return work_packed(in, msg_id);
    case CODE_bad_server_salt:
        return work_bad_server_salt(in);
    case CODE_pong:
        return work_pong(in);
    case CODE_msg_detailed_info:
        return work_detailed_info(in);
    case CODE_msg_new_detailed_info:
        return work_new_detailed_info(in);
    case CODE_bad_msg_notification:
        return work_bad_msg_notification(in);
    }
    TGL_WARNING("unknown message: " << op);
    in->ptr = in->end; // Will not fail due to assertion in->ptr == in->end
    return 0;
}

void mtproto_client::restart_session()
{
    if (m_session) {
        TGL_WARNING("failing session " << m_session->session_id);
        m_session->clear();
        m_session = nullptr;
    }
    create_session();
}

bool mtproto_client::process_rpc_message(encrypted_message* enc, int len)
{
    const int MINSZ = offsetof(struct encrypted_message, message);
    const int UNENCSZ = offsetof(struct encrypted_message, server_salt);
    TGL_DEBUG("process_rpc_message(), len=" << len);
    if (len < MINSZ || (len & 15) != (UNENCSZ & 15)) {
        TGL_WARNING("incorrect packet from server, closing connection");
        return false;
    }
    assert(len >= MINSZ && (len & 15) == (UNENCSZ & 15));

    if (enc->auth_key_id != m_temp_auth_key_id && enc->auth_key_id != m_auth_key_id) {
        TGL_WARNING("received msg from DC " << m_id << " with auth_key_id " << enc->auth_key_id <<
                " (perm_auth_key_id " << m_auth_key_id << " temp_auth_key_id "<< m_temp_auth_key_id << "), dropping");
        return true;
    }

    TGLC_aes_key aes_key;
    unsigned char aes_iv[32];
    if (enc->auth_key_id == m_temp_auth_key_id) {
        assert(enc->auth_key_id == m_temp_auth_key_id);
        assert(m_temp_auth_key_id);
        tgl_init_aes_auth(&aes_key, aes_iv, m_temp_auth_key.data() + 8, enc->msg_key, AES_DECRYPT);
    } else {
        assert(enc->auth_key_id == m_auth_key_id);
        assert(m_auth_key_id);
        tgl_init_aes_auth(&aes_key, aes_iv, m_auth_key.data() + 8, enc->msg_key, AES_DECRYPT);
    }

    int l = tgl_pad_aes_decrypt(&aes_key,
            aes_iv,
            reinterpret_cast<const unsigned char*>(&enc->server_salt),
            len - UNENCSZ,
            reinterpret_cast<unsigned char*>(&enc->server_salt), len - UNENCSZ);
    TGL_ASSERT_UNUSED(l, l == len - UNENCSZ);

    if (!(!(enc->msg_len & 3) && enc->msg_len > 0 && enc->msg_len <= len - MINSZ && len - MINSZ - enc->msg_len <= 12)) {
        TGL_WARNING("incorrect packet from server, closing connection");
        return false;
    }
    assert(!(enc->msg_len & 3) && enc->msg_len > 0 && enc->msg_len <= len - MINSZ && len - MINSZ - enc->msg_len <= 12);

    if (!m_session || m_session->session_id != enc->session_id) {
        TGL_WARNING("message to wrong session, dropping");
        return true;
    }

    unsigned char sha1_buffer[20];
    memset(sha1_buffer, 0, sizeof(sha1_buffer));
    TGLC_sha1((unsigned char *)&enc->server_salt, enc->msg_len + (MINSZ - UNENCSZ), sha1_buffer);
    if (memcmp(&enc->msg_key, sha1_buffer + 4, 16)) {
        TGL_WARNING("incorrect packet from server, closing connection");
        return false;
    }

    int32_t this_server_time = enc->msg_id >> 32LL;
    if (!m_session->received_messages) {
        m_server_time_delta = this_server_time - tgl_get_system_time();
        if (m_server_time_udelta) {
            TGL_WARNING("adjusting monotonic clock delta to " <<
                    m_server_time_udelta - this_server_time + tgl_get_monotonic_time());
        }
        m_server_time_udelta = this_server_time - tgl_get_monotonic_time();
    }

    int64_t server_time = get_server_time();
    if (this_server_time < server_time - 300 || this_server_time > server_time + 30) {
        TGL_WARNING("bad msg time: salt = " << enc->server_salt << ", session_id = " << enc->session_id
                << ", msg_id = " << enc->msg_id << ", seq_no = " << enc->seq_no
                << ", server_time = " << server_time << ", time from msg_id = " << this_server_time
                << ", now = " << static_cast<int64_t>(tgl_get_system_time()));
        restart_session();
        return true;
    }
    m_session->received_messages++;

    if (m_server_salt != enc->server_salt) {
        TGL_DEBUG("updating server salt from " << m_server_salt << " to " << enc->server_salt);
        m_server_salt = enc->server_salt;
    }

    //assert(enc->msg_id > server_last_msg_id && (enc->msg_id & 3) == 1);
    TGL_DEBUG("received mesage id " << enc->msg_id);
    //server_last_msg_id = enc->msg_id;

    assert(l >= (MINSZ - UNENCSZ) + 8);

    tgl_in_buffer in = { enc->message, enc->message + (enc->msg_len / 4) };

    if (enc->msg_id & 1) {
        insert_msg_id(enc->msg_id);
    }
    assert(m_session->session_id == enc->session_id);

    if (rpc_execute_answer(&in, enc->msg_id) < 0) {
        restart_session();
        return true;
    }

    assert(in.ptr == in.end);
    return true;
}

bool mtproto_client::rpc_execute(int op, int len)
{
    assert(m_session);
    assert(m_session->c);

    if (len >= MAX_RESPONSE_SIZE/* - 12*/ || len < 0/*12*/) {
        TGL_WARNING("answer too long, skipping. lengeth:" << len);
        return true;
    }

    std::unique_ptr<char[]> response(new char[len]);
    TGL_DEBUG("response of " << len << " bytes received from DC " << m_id);
    int result = m_session->c->read(response.get(), len);
    TGL_ASSERT_UNUSED(result, result == len);

#if !defined(__MACH__) && !defined(__FreeBSD__) && !defined(__OpenBSD__) && !defined(__CYGWIN__)
    //  setsockopt(c->fd, IPPROTO_TCP, TCP_QUICKACK, (int[]){0}, 4);
#endif
    state current_state = m_state;
    if (current_state != state::authorized) {
        TGL_DEBUG("state = " << current_state << " for DC " << m_id);
    }
    switch (current_state) {
    case state::reqpq_sent:
        return process_respq_answer(response.get()/* + 8*/, len/* - 12*/, false);
    case state::reqdh_sent:
        return process_dh_answer(response.get()/* + 8*/, len/* - 12*/, false);
    case state::client_dh_sent:
        return process_auth_complete(response.get()/* + 8*/, len/* - 12*/, false);
    case state::reqpq_sent_temp:
        return process_respq_answer(response.get()/* + 8*/, len/* - 12*/, true);
    case state::reqdh_sent_temp:
        return process_dh_answer(response.get()/* + 8*/, len/* - 12*/, true);
    case state::client_dh_sent_temp:
        return process_auth_complete(response.get()/* + 8*/, len/* - 12*/, true);
    case state::authorized:
        if (op < 0 && op >= -999) {
            if (tgl_state::instance()->pfs_enabled() && op == -404) {
                TGL_DEBUG("bind temp auth key failed with -404 error for DC "
                        << m_id << ", which is not unusual, requesting a new temp auth key and trying again");
                restart_temp_authorization();
                return true;
            } else {
                TGL_WARNING("server error " << op << " from DC " << m_id);
                return false;
            }
        } else {
            return process_rpc_message(reinterpret_cast<encrypted_message*>(response.get()/* + 8*/), len/* - 12*/);
        }
    default:
        TGL_ERROR("cannot receive answer in state " << m_state);
        return false;
    }
}

void mtproto_client::restart_temp_authorization()
{
    TGL_DEBUG("restarting temp authorization for DC " << m_id);
    reset_temp_authorization();
    assert(is_authorized());
    if (is_authorized()) {
        m_state = state::authorized;
    }
    if (!m_session) {
        create_session();
    } else {
        create_temp_auth_key();
    }
}

void mtproto_client::restart_authorization()
{
    TGL_DEBUG("restarting authorization for DC " << m_id);
    reset_authorization();
    if (!m_session) {
        create_session();
    } else {
        send_req_pq_packet();
    }
}

int mtproto_client::ready(const std::shared_ptr<tgl_connection>& c)
{
    if (!m_session || !m_session->c) {
        return -1;
    }

    assert(m_session->c == c);

    TGL_NOTICE("outbound rpc connection from DC " << m_id << " became ready");

    if (is_authorized()) {
        m_state = state::authorized;
    }

    state current_state = m_state;
    if (current_state == state::authorized && !tgl_state::instance()->pfs_enabled()) {
        m_temp_auth_key_id = m_auth_key_id;
        memcpy(m_temp_auth_key.data(), m_auth_key.data(), 256);
        set_bound();
    }
    switch (current_state) {
    case state::init:
        TGL_DEBUG("DC " << m_id << " is in init state");
        send_req_pq_packet();
        break;
    case state::authorized:
        TGL_DEBUG("DC " << m_id << " is in authorized state");
        if (!is_bound()) {
            TGL_DEBUG("DC " << m_id << " is not bond");
            assert(tgl_state::instance()->pfs_enabled());
            if (!m_temp_auth_key_id) {
                assert(tgl_state::instance()->pfs_enabled());
                create_temp_auth_key();
            } else {
                bind_temp_auth_key();
            }
        } else if (!is_configured()) {
            TGL_DEBUG("DC " << m_id << " is not configured");
            tgl_do_help_get_client_config(shared_from_this());
        } else {
            // To trigger sending pending queries if any.
            tgl_do_set_client_configured(shared_from_this(), true);
        }
        break;
    default:
        TGL_DEBUG("c_state = " << m_state);
        m_state = state::init; // previous connection was reset
        send_req_pq_packet();
        break;
    }
    return 0;
}

#define RANDSEED_PASSWORD_FILENAME     NULL
#define RANDSEED_PASSWORD_LENGTH       0
int tglmp_on_start()
{
    tgl_prng_seed(RANDSEED_PASSWORD_FILENAME, RANDSEED_PASSWORD_LENGTH);

    bool ok = false;
    for (const auto& key: tgl_state::instance()->rsa_key_list()) {
        if (key->load()) {
            ok = true;
        } else {
            TGL_WARNING("can not load key " << key->public_key_string());
        }
    }

    if (!ok) {
        TGL_ERROR("no public keys found");
        tgl_state::instance()->set_error("no public keys found", ENOTCONN);
        return -1;
    }
    return 0;
}

void mtproto_client::send_all_acks()
{
    if (!is_configured() || !m_session) {
        return;
    }

    mtprotocol_serializer s;
    s.out_i32(CODE_msgs_ack);
    s.out_i32(CODE_vector);
    s.out_i32(m_session->ack_set.size());
    for (int64_t id: m_session->ack_set) {
        s.out_i64(id);
    }
    m_session->ack_set.clear();
    send_message(s.i32_data(), s.i32_size());
}

void mtproto_client::insert_msg_id(int64_t id)
{
    if (!m_session || !m_session->ev) {
        // The session has been cleared.
        return;
    }

    if (m_session->ack_set.empty()) {
        m_session->ev->start(ACK_TIMEOUT);
    }
    m_session->ack_set.insert(id);
}

void mtproto_client::create_session()
{
    assert(!m_session);
    m_session = std::make_shared<tgl_session>();
    while (!m_session->session_id) {
        tgl_secure_random(reinterpret_cast<unsigned char*>(&m_session->session_id), 8);
    }
    m_session->c = tgl_state::instance()->connection_factory()->create_connection(
            m_ipv4_options, m_ipv6_options, shared_from_this());
    m_session->c->open();
    m_session->ev = tgl_state::instance()->timer_factory()->create_timer(
            std::bind(&mtproto_client::send_all_acks, shared_from_this()));
}

void mtproto_client::reset_authorization()
{
    reset_temp_authorization();
    m_state = state::init;
    memset(m_auth_key.data(), 0, m_auth_key.size());
    m_auth_key_id = 0;
    if (!m_pending_queries.empty()) {
        send_pending_queries();
    }
}

void mtproto_client::reset_temp_authorization()
{
    if (m_temp_auth_key_bind_query_id) {
        tglq_query_delete(m_temp_auth_key_bind_query_id);
        m_temp_auth_key_bind_query_id = 0;
    }
    m_rsa_key = nullptr;
    memset(m_temp_auth_key.data(), 0, m_temp_auth_key.size());
    memset(m_nonce.data(), 0, m_nonce.size());
    memset(m_new_nonce.data(), 0, m_new_nonce.size());
    memset(m_server_nonce.data(), 0, m_server_nonce.size());
    m_temp_auth_key_id = 0;
    m_server_salt = 0;
    set_configured(false);
    set_bound(false);
}

void mtproto_client::send_pending_queries()
{
    std::list<std::shared_ptr<query>> queries = m_pending_queries; // make a copy since queries can get re-enqueued
    for (std::shared_ptr<query> q : queries) {
        if (q->execute_after_pending()) {
            m_pending_queries.remove(q);
        } else {
            TGL_DEBUG("sending pending query failed for DC " << m_id);
        }
    }
}

void mtproto_client::increase_active_queries(size_t num)
{
    m_active_queries += num;
    if (m_session_cleanup_timer) {
        m_session_cleanup_timer->cancel();
    }
}

void mtproto_client::decrease_active_queries(size_t num)
{
    if (m_active_queries >= num) {
        m_active_queries -= num;
    }

    if (!m_active_queries && m_pending_queries.empty() && tgl_state::instance()->active_client().get() != this) {
        if (!m_session_cleanup_timer) {
            m_session_cleanup_timer = tgl_state::instance()->timer_factory()->create_timer(
                    std::bind(&mtproto_client::cleanup_timer_expired, shared_from_this()));
        }
        m_session_cleanup_timer->start(SESSION_CLEANUP_TIMEOUT);
    }
}

void mtproto_client::add_pending_query(const std::shared_ptr<query>& q)
{
    if (std::find(m_pending_queries.cbegin(), m_pending_queries.cend(), q) == m_pending_queries.cend()) {
        m_pending_queries.push_back(q);
    }
}

void mtproto_client::remove_pending_query(const std::shared_ptr<query>& q)
{
    m_pending_queries.remove(q);
}

void mtproto_client::cleanup_timer_expired()
{
    if (!m_active_queries && m_pending_queries.empty()) {
        TGL_DEBUG("cleanup timer expired for DC " << m_id << ", deleting session");
        clear_session();
    }
}

void mtproto_client::set_auth_key(const unsigned char* key, size_t length)
{
    assert(key);
    assert(length == 256);
    if (!key || length != 256) {
        return;
    }

    memcpy(m_auth_key.data(), key, 256);
    calculate_auth_key_id(false);
    set_authorized();
}

void mtproto_client::calculate_auth_key_id(bool temp_key)
{
    unsigned char sha1_buffer[20];
    memset(sha1_buffer, 0, sizeof(sha1_buffer));
    TGLC_sha1(temp_key ? m_temp_auth_key.data() : m_auth_key.data(), 256, sha1_buffer);
    memcpy(temp_key ? &m_temp_auth_key_id : &m_auth_key_id, sha1_buffer + 12, 8);
}

void mtproto_client::add_ipv6_option(const std::string& address, int port)
{
    m_ipv6_options.push_back(std::make_pair(address, port));
}

void mtproto_client::add_ipv4_option(const std::string& address, int port)
{
    m_ipv4_options.push_back(std::make_pair(address, port));
}
