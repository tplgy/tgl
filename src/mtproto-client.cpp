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

#include "mtproto-client.h"

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
#include "tgl_session.h"
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

constexpr int MAX_MESSAGE_INTS = 1048576;
constexpr int ACK_TIMEOUT = 1;

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

static int64_t generate_next_msg_id(const std::shared_ptr<tgl_dc>& DC, const std::shared_ptr<tgl_session>& S);
static double get_server_time(const std::shared_ptr<tgl_dc>& DC);

static mtproto_client::execute_result rpc_execute(const std::shared_ptr<tgl_connection>& c, int32_t op, int len);
static int rpc_becomes_ready(const std::shared_ptr<tgl_connection>& c);

int mtproto_client::ready(const std::shared_ptr<tgl_connection>& c)
{
    return rpc_becomes_ready(c);
}

mtproto_client::execute_result mtproto_client::try_rpc_execute(const std::shared_ptr<tgl_connection>& c)
{
    while (true) {
        if (c->available_bytes_for_read() < 1) {
            return execute_result::ok;
        }
        unsigned len = 0;
        ssize_t result = c->peek(&len, 1);
        TGL_ASSERT_UNUSED(result, result == 1);
        if (len >= 1 && len <= 0x7e) {
            if (c->available_bytes_for_read() < 1 + 4 * len) {
                return execute_result::ok;
            }
        } else {
            if (c->available_bytes_for_read() < 4) {
                return execute_result::ok;
            }
            result = c->peek(&len, 4);
            TGL_ASSERT_UNUSED(result, result == 4);
            len = (len >> 8);
            if (c->available_bytes_for_read() < 4 + 4 * len) {
                return execute_result::ok;
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
        auto exec_result = rpc_execute(c, op, len);
        if (exec_result != mtproto_client::execute_result::ok) {
            return exec_result;
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
static int rpc_send_packet(const std::shared_ptr<tgl_connection>& c, const char* data, size_t len)
{
    struct {
        int64_t auth_key_id;
        int64_t out_msg_id;
        int msg_len;
    } unenc_msg_header;

    memset(&unenc_msg_header, 0, sizeof(unenc_msg_header));

    std::shared_ptr<tgl_dc> DC = c->get_dc().lock();
    std::shared_ptr<tgl_session> S = c->get_session().lock();
    if (!DC || !S) {
        return -1;
    }

    unenc_msg_header.out_msg_id = generate_next_msg_id(DC, S);
    unenc_msg_header.msg_len = len;

    int total_len = len + 20;
    assert(total_len > 0 && !(total_len & 0xfc000003));
    total_len >>= 2;
    TGL_DEBUG("writing packet: total_len = " << total_len << ", len = " << len);
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

    return 1;
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
static int send_req_pq_packet(const std::shared_ptr<tgl_connection>& c)
{
    std::shared_ptr<tgl_dc> DC = c->get_dc().lock();
    if (!DC) {
        return -1;
    }

    assert(DC->state == tgl_dc_state::init);

    tgl_secure_random(DC->nonce, 16);
    mtprotocol_serializer s;
    s.out_i32(CODE_req_pq);
    s.out_i32s((int *)DC->nonce, 4);
    TGL_DEBUG("sending request pq to DC " << DC->id);
    rpc_send_packet(c, s.char_data(), s.char_size());

    DC->state = tgl_dc_state::reqpq_sent;
    return 1;
}

// req_pq#60469778 nonce:int128 = ResPQ
static int send_req_pq_temp_packet(const std::shared_ptr<tgl_connection>& c)
{
    std::shared_ptr<tgl_dc> DC = c->get_dc().lock();
    if (!DC) {
        return -1;
    }

    assert(DC->state == tgl_dc_state::authorized);

    tgl_secure_random(DC->nonce, 16);
    mtprotocol_serializer s;
    s.out_i32(CODE_req_pq);
    s.out_i32s((int *)DC->nonce, 4);
    TGL_DEBUG("send request pq (temp) to DC " << DC->id);
    rpc_send_packet(c, s.char_data(), s.char_size());

    DC->state = tgl_dc_state::reqpq_sent_temp;
    return 1;
}
/* }}} */

/* {{{ REQ DH */
// req_DH_params#d712e4be nonce:int128 server_nonce:int128 p:string q:string public_key_fingerprint:long encrypted_data:string = Server_DH_Params;
// p_q_inner_data#83c95aec pq:string p:string q:string nonce:int128 server_nonce:int128 new_nonce:int256 = P_Q_inner_data;
// p_q_inner_data_temp#3c6a84d4 pq:string p:string q:string nonce:int128 server_nonce:int128 new_nonce:int256 expires_in:int = P_Q_inner_data;
static void send_req_dh_packet(const std::shared_ptr<tgl_connection>& c, TGLC_bn* pq, bool temp_key)
{
    std::shared_ptr<tgl_dc> DC = c->get_dc().lock();
    if (!DC) {
        return;
    }

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

    s.out_i32s((int *)DC->nonce, 4);
    s.out_i32s((int *)DC->server_nonce, 4);
    tgl_secure_random(DC->new_nonce, 32);
    s.out_i32s((int *)DC->new_nonce, 8);
    if (temp_key) {
        TGL_DEBUG("creating temp auth key expiring in " << tgl_state::instance()->temp_key_expire_time() << " seconds for DC " << DC->id);
        s.out_i32(tgl_state::instance()->temp_key_expire_time());
    }

    unsigned char sha1_buffer[20];
    memset(sha1_buffer, 0, sizeof(sha1_buffer));
    TGLC_sha1(reinterpret_cast<const unsigned char*>(s.i32_data() + at + 5), (s.i32_size() - at - 5) * 4, sha1_buffer);
    s.out_i32s_at(at, reinterpret_cast<int32_t*>(sha1_buffer), 5);

    int encrypted_buffer_size = tgl_pad_rsa_encrypt_dest_buffer_size(s.char_size());
    assert(encrypted_buffer_size > 0);
    std::unique_ptr<char[]> encrypted_data(new char[encrypted_buffer_size]);
    const TGLC_rsa* key = DC->rsa_key()->public_key();
    size_t unpadded_size = s.ensure_char_size(encrypted_buffer_size);
    int encrypted_data_size = tgl_pad_rsa_encrypt(s.char_data(), unpadded_size, encrypted_data.get(), encrypted_buffer_size, TGLC_rsa_n(key), TGLC_rsa_e(key));

    s.clear();
    s.out_i32(CODE_req_DH_params);
    s.out_i32s((int *) DC->nonce, 4);
    s.out_i32s((int *) DC->server_nonce, 4);
    s.out_bignum(p.get());
    s.out_bignum(q.get());

    s.out_i64(DC->rsa_key()->fingerprint());
    s.out_string(encrypted_data.get(), encrypted_data_size);

    DC->state = temp_key ? tgl_dc_state::reqdh_sent_temp : tgl_dc_state::reqdh_sent;
    TGL_DEBUG("sending request dh (temp_key=" << std::boolalpha << temp_key << ") to DC " << DC->id);
    rpc_send_packet(c, s.char_data(), s.char_size());
}
/* }}} */

/* {{{ SEND DH PARAMS */
// set_client_DH_params#f5045f1f nonce:int128 server_nonce:int128 encrypted_data:string = Set_client_DH_params_answer;
// client_DH_inner_data#6643b654 nonce:int128 server_nonce:int128 retry_id:long g_b:string = Client_DH_Inner_Data
static void send_dh_params(const std::shared_ptr<tgl_connection>& c, TGLC_bn* dh_prime, TGLC_bn* g_a, int g, bool temp_key)
{
    std::shared_ptr<tgl_dc> DC = c->get_dc().lock();
    if (!DC) {
        return;
    }

    mtprotocol_serializer s;
    size_t at = s.reserve_i32s(5);
    s.out_i32(CODE_client_DH_inner_data);
    s.out_i32s((int *) DC->nonce, 4);
    s.out_i32s((int *) DC->server_nonce, 4);
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
    auto result = TGLC_bn_bn2bin(auth_key_num.get(), (unsigned char *)(temp_key ? DC->temp_auth_key : DC->auth_key));
    TGL_ASSERT_UNUSED(result, result);
    if (l < 256) {
        unsigned char* key = temp_key ? DC->temp_auth_key : DC->auth_key;
        memmove(key + 256 - l, key, l);
        memset(key, 0, 256 - l);
    }

    unsigned char sha1_buffer[20];
    memset(sha1_buffer, 0, sizeof(sha1_buffer));
    TGLC_sha1(reinterpret_cast<const unsigned char*>(s.i32_data() + at + 5), (s.i32_size() - at - 5) * 4, sha1_buffer);
    s.out_i32s_at(at, reinterpret_cast<int32_t*>(sha1_buffer), 5);

    TGLC_aes_key aes_key;
    unsigned char aes_iv[32];
    tgl_init_aes_unauth(&aes_key, aes_iv, DC->server_nonce, DC->new_nonce, 1);
    int encrypted_buffer_size = tgl_pad_aes_encrypt_dest_buffer_size(s.char_size());
    std::unique_ptr<char[]> encrypted_data(new char[encrypted_buffer_size]);
    size_t unpadded_size = s.ensure_char_size(encrypted_buffer_size);
    int encrypted_data_size = tgl_pad_aes_encrypt(&aes_key, aes_iv, reinterpret_cast<const unsigned char*>(s.char_data()), unpadded_size,
            reinterpret_cast<unsigned char*>(encrypted_data.get()), encrypted_buffer_size);

    s.clear();
    s.out_i32(CODE_set_client_DH_params);
    s.out_i32s((int *) DC->nonce, 4);
    s.out_i32s((int *) DC->server_nonce, 4);
    s.out_string(encrypted_data.get(), encrypted_data_size);

    DC->state = temp_key ? tgl_dc_state::client_dh_sent_temp : tgl_dc_state::client_dh_sent;;
    TGL_DEBUG("sending dh parameters (temp_key=" << std::boolalpha << temp_key << ") to DC " << DC->id);
    rpc_send_packet(c, s.char_data(), s.char_size());
}
/* }}} */

/* {{{ RECV RESPQ */
// resPQ#05162463 nonce:int128 server_nonce:int128 pq:string server_public_key_fingerprints:Vector long = ResPQ
static mtproto_client::execute_result process_respq_answer(const std::shared_ptr<tgl_connection>& c, char* packet, int len, bool temp_key)
{
    assert(!(len & 3));
    tgl_in_buffer in;
    in.ptr = reinterpret_cast<int*>(packet);
    in.end = in.ptr + (len / 4);
    if (check_unauthorized_header(&in) < 0) {
        return mtproto_client::execute_result::bad_connection;
    }

    tgl_in_buffer skip_in = in;
    struct paramed_type type = TYPE_TO_PARAM(res_p_q);
    if (skip_type_any(&skip_in, &type) < 0 || skip_in.ptr != skip_in.end) {
        TGL_ERROR("can not parse req_p_q answer");
        return mtproto_client::execute_result::bad_connection;
    }

    std::shared_ptr<tgl_dc> DC = c->get_dc().lock();
    if (!DC) {
        return mtproto_client::execute_result::bad_dc;
    }

    auto result = fetch_i32(&in);
    TGL_ASSERT_UNUSED(result, result == static_cast<int32_t>(CODE_res_pq));

    int tmp[4];
    fetch_i32s(&in, tmp, 4);
    if (memcmp(tmp, DC->nonce, 16)) {
        TGL_ERROR("nonce mismatch");
        return mtproto_client::execute_result::bad_connection;
    }
    fetch_i32s(&in, reinterpret_cast<int32_t*>(DC->server_nonce), 4);

    std::unique_ptr<TGLC_bn, TGLC_bn_deleter> pq(TGLC_bn_new());
    result = fetch_bignum(&in, pq.get());
    TGL_ASSERT_UNUSED(result, result >= 0);

    result = fetch_i32(&in);
    TGL_ASSERT_UNUSED(result, result == static_cast<int32_t>(CODE_vector));
    int32_t fingerprints_num = fetch_i32(&in);
    assert(fingerprints_num >= 0);
    DC->set_rsa_key(nullptr);

    for (int i = 0; i < fingerprints_num; i++) {
        int64_t fingerprint = fetch_i64(&in);
        for (const auto& key : tgl_state::instance()->rsa_key_list()) {
            if (key->is_loaded() && fingerprint == key->fingerprint()) {
                DC->set_rsa_key(key);
                break;
            }
        }
    }
    assert(in.ptr == in.end);
    if (!DC->rsa_key()) {
        TGL_ERROR("fatal: don't have any matching keys");
        return mtproto_client::execute_result::bad_connection;
    }

    send_req_dh_packet(c, pq.get(), temp_key);

    return mtproto_client::execute_result::ok;
}
/* }}} */

/* {{{ RECV DH */
// server_DH_params_fail#79cb045d nonce:int128 server_nonce:int128 new_nonce_hash:int128 = Server_DH_Params;
// server_DH_params_ok#d0e8075c nonce:int128 server_nonce:int128 encrypted_answer:string = Server_DH_Params;
// server_DH_inner_data#b5890dba nonce:int128 server_nonce:int128 g:int dh_prime:string g_a:string server_time:int = Server_DH_inner_data;
static mtproto_client::execute_result process_dh_answer(const std::shared_ptr<tgl_connection>& c, char* packet, int len, bool temp_key)
{
    assert(!(len & 3));
    tgl_in_buffer in;
    in.ptr = reinterpret_cast<int*>(packet);
    in.end = in.ptr + (len / 4);
    if (check_unauthorized_header(&in) < 0) {
        return mtproto_client::execute_result::bad_connection;
    }

    tgl_in_buffer skip_in = in;
    struct paramed_type type = TYPE_TO_PARAM(server_d_h_params);
    if (skip_type_any(&skip_in, &type) < 0 || skip_in.ptr != skip_in.end) {
        TGL_ERROR("can not parse server_DH_params answer");
        return mtproto_client::execute_result::bad_connection;
    }

    std::shared_ptr<tgl_dc> DC = c->get_dc().lock();
    if (!DC) {
        return mtproto_client::execute_result::bad_dc;
    }

    uint32_t op = fetch_i32(&in);
    assert(op == CODE_server__dh_params_ok || op == CODE_server__dh_params_fail);

    int tmp[4];
    fetch_i32s(&in, tmp, 4);
    if (memcmp(tmp, DC->nonce, 16)) {
        TGL_ERROR("nonce mismatch");
        return mtproto_client::execute_result::bad_connection;
    }
    fetch_i32s(&in, tmp, 4);
    if (memcmp(tmp, DC->server_nonce, 16)) {
        TGL_ERROR("server nonce mismatch");
        return mtproto_client::execute_result::bad_connection;
    }

    if (op == CODE_server__dh_params_fail) {
        TGL_ERROR("DH params fail");
        return mtproto_client::execute_result::bad_connection;
    }

    TGLC_aes_key aes_key;
    unsigned char aes_iv[32];
    tgl_init_aes_unauth(&aes_key, aes_iv, DC->server_nonce, DC->new_nonce, 0);

    ssize_t l = prefetch_strlen(&in);
    assert(l > 0);
    if (l <= 0) {
        TGL_ERROR("non-empty encrypted part expected");
        return mtproto_client::execute_result::bad_connection;
    }
    int decrypted_buffer_size = tgl_pad_aes_decrypt_dest_buffer_size(l);
    assert(decrypted_buffer_size > 0);
    if (decrypted_buffer_size <= 0) {
        TGL_ERROR("failed to get decrypted buffer size");
        return mtproto_client::execute_result::bad_connection;
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
        return mtproto_client::execute_result::bad_connection;
    }
    in.ptr = decrypted_buffer.get() + 5;
    in.end = decrypted_buffer.get() + (decrypted_buffer_size >> 2);

    auto result = fetch_i32(&in);
    TGL_ASSERT_UNUSED(result, result == static_cast<int32_t>(CODE_server_DH_inner_data));
    fetch_i32s(&in, tmp, 4);
    if (memcmp(tmp, DC->nonce, 16)) {
        TGL_ERROR("inner nonce mismatch");
        return mtproto_client::execute_result::bad_connection;
    }
    fetch_i32s(&in, tmp, 4);
    if (memcmp(tmp, DC->server_nonce, 16)) {
        TGL_ERROR("inner server nonce mismatch");
        return mtproto_client::execute_result::bad_connection;
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
        return mtproto_client::execute_result::bad_connection;
    }
    if (tglmp_check_g_a(dh_prime.get(), g_a.get()) < 0) {
        TGL_ERROR("bad dh_prime");
        return mtproto_client::execute_result::bad_connection;
    }

    int32_t server_time = fetch_i32(&in);
    assert(in.ptr <= in.end);

    char sha1_buffer[20];
    memset(sha1_buffer, 0, sizeof(sha1_buffer));
    TGLC_sha1((unsigned char *) decrypted_buffer.get() + 20, (in.ptr - decrypted_buffer.get() - 5) * 4, (unsigned char *) sha1_buffer);
    if (memcmp(decrypted_buffer.get(), sha1_buffer, 20)) {
        TGL_ERROR("bad encrypted message SHA1");
        return mtproto_client::execute_result::bad_connection;
    }
    if ((char *) in.end - (char *) in.ptr >= 16) {
        TGL_ERROR("too much padding");
        return mtproto_client::execute_result::bad_connection;
    }

    DC->server_time_delta = server_time - tgl_get_system_time();
    DC->server_time_udelta = server_time - tgl_get_monotonic_time();

    send_dh_params(c, dh_prime.get(), g_a.get(), g, temp_key);

    return mtproto_client::execute_result::ok;
}
/* }}} */

static void create_temp_auth_key(const std::shared_ptr<tgl_connection>& c)
{
    assert(tgl_state::instance()->pfs_enabled());
    send_req_pq_temp_packet(c);
}

static int tglmp_encrypt_inner_temp(const std::shared_ptr<tgl_connection>& c, const int32_t* msg, int msg_ints, void* data, int64_t msg_id);
static void bind_temp_auth_key(const std::shared_ptr<tgl_connection>& c);

static void restart_dc_authorization(const std::shared_ptr<tgl_dc>& dc, bool temp_key)
{
    if (temp_key) {
        dc->restart_temp_authorization();
    } else {
        dc->restart_authorization();
    }
}

/* {{{ RECV AUTH COMPLETE */

// dh_gen_ok#3bcbf734 nonce:int128 server_nonce:int128 new_nonce_hash1:int128 = Set_client_DH_params_answer;
// dh_gen_retry#46dc1fb9 nonce:int128 server_nonce:int128 new_nonce_hash2:int128 = Set_client_DH_params_answer;
// dh_gen_fail#a69dae02 nonce:int128 server_nonce:int128 new_nonce_hash3:int128 = Set_client_DH_params_answer;
static mtproto_client::execute_result process_auth_complete(const std::shared_ptr<tgl_connection>& c, char* packet, int len, bool temp_key)
{
    std::shared_ptr<tgl_dc> DC = c->get_dc().lock();
    if (!DC) {
        return mtproto_client::execute_result::bad_dc;
    }

    assert(!(len & 3));
    tgl_in_buffer in;
    in.ptr = reinterpret_cast<int*>(packet);
    in.end = in.ptr + (len / 4);
    if (check_unauthorized_header(&in) < 0) {
        TGL_ERROR("check header failed");
        restart_dc_authorization(DC, temp_key);
        return mtproto_client::execute_result::ok;
    }

    tgl_in_buffer skip_in = in;
    struct paramed_type type = TYPE_TO_PARAM(set_client_d_h_params_answer);
    if (skip_type_any(&skip_in, &type) < 0 || skip_in.ptr != skip_in.end) {
        TGL_ERROR("can not parse server_DH_params answer");
        restart_dc_authorization(DC, temp_key);
        return mtproto_client::execute_result::ok;
    }

    uint32_t op = fetch_i32(&in);
    assert(op == CODE_dh_gen_ok || op == CODE_dh_gen_retry || op == CODE_dh_gen_fail);

    int tmp[4];
    fetch_i32s(&in, tmp, 4);
    if (memcmp(DC->nonce, tmp, 16)) {
        TGL_ERROR("nonce mismatch");
        restart_dc_authorization(DC, temp_key);
        return mtproto_client::execute_result::ok;
    }
    fetch_i32s(&in, tmp, 4);
    if (memcmp(DC->server_nonce, tmp, 16)) {
        TGL_ERROR("server nonce mismatch");
        restart_dc_authorization(DC, temp_key);
        return mtproto_client::execute_result::ok;
    }
    if (op != CODE_dh_gen_ok) {
        TGL_DEBUG("DH failed for DC " << DC->id << ", retrying");
        restart_dc_authorization(DC, temp_key);
        return mtproto_client::execute_result::ok;
    }

    fetch_i32s(&in, tmp, 4);

    unsigned char th[44], sha1_buffer[20];
    memset(th, 0, sizeof(th));
    memset(sha1_buffer, 0, sizeof(sha1_buffer));
    memcpy(th, DC->new_nonce, 32);
    th[32] = 1;
    if (!temp_key) {
        TGLC_sha1(DC->auth_key, 256, sha1_buffer);
    } else {
        TGLC_sha1(DC->temp_auth_key, 256, sha1_buffer);
    }
    memcpy(th + 33, sha1_buffer, 8);
    TGLC_sha1(th, 41, sha1_buffer);
    if (memcmp(tmp, sha1_buffer + 4, 16)) {
        TGL_ERROR("hash mismatch");
        restart_dc_authorization(DC, temp_key);
        return mtproto_client::execute_result::ok;
    }

    if (!temp_key) {
        tgl_state::instance()->set_auth_key(DC->id, NULL);
    } else {
        memset(sha1_buffer, 0, sizeof(sha1_buffer));
        TGLC_sha1(DC->temp_auth_key, 256, sha1_buffer);
        DC->temp_auth_key_id = *reinterpret_cast<int64_t*>(sha1_buffer + 12);
    }

    DC->server_salt = *reinterpret_cast<int64_t*>(DC->server_nonce) ^ *reinterpret_cast<int64_t*>(DC->new_nonce);

    DC->state = tgl_dc_state::authorized;

    TGL_DEBUG("auth success for DC " << DC->id << " " << (temp_key ? "(temp)" : "") << " salt=" << DC->server_salt);
    if (temp_key) {
        bind_temp_auth_key(c);
    } else {
        DC->set_authorized();
        if (tgl_state::instance()->pfs_enabled()) {
            create_temp_auth_key(c);
        } else {
            DC->temp_auth_key_id = DC->auth_key_id;
            memcpy(DC->temp_auth_key, DC->auth_key, 256);
            DC->set_bound();
            if (!DC->is_configured()) {
                tgl_do_help_get_config_dc(DC);
            } else {
                // To trigger sending pending queries if any.
                tgl_do_set_dc_configured(DC, true);
            }
        }
    }

    return mtproto_client::execute_result::ok;
}
/* }}} */

static void bind_temp_auth_key(const std::shared_ptr<tgl_connection>& c)
{
    std::shared_ptr<tgl_dc> DC = c->get_dc().lock();
    std::shared_ptr<tgl_session> S = c->get_session().lock();
    if (!DC || !S) {
        return;
    }

    if (DC->temp_auth_key_bind_query_id) {
        tglq_query_delete(DC->temp_auth_key_bind_query_id);
    }
    int64_t msg_id = generate_next_msg_id(DC, S);

    mtprotocol_serializer s;
    s.out_i32(CODE_bind_auth_key_inner);
    int64_t rand;
    tgl_secure_random(reinterpret_cast<unsigned char*>(&rand), 8);
    s.out_i64(rand);
    s.out_i64(DC->temp_auth_key_id);
    s.out_i64(DC->auth_key_id);

    if (!S->session_id) {
        tgl_secure_random((unsigned char*)&S->session_id, 8);
    }
    s.out_i64(S->session_id);
    int expires = tgl_get_system_time() + DC->server_time_delta + tgl_state::instance()->temp_key_expire_time();
    s.out_i32(expires);

    int data[1000];
    memset(data, 0, sizeof(data));
    int len = tglmp_encrypt_inner_temp(c, s.i32_data(), s.i32_size(), data, msg_id);
    DC->temp_auth_key_bind_query_id = msg_id;
    tgl_do_bind_temp_key(DC, rand, expires, (void *)data, len, msg_id);
}

/*
 *
 *                AUTHORIZED (MAIN) PROTOCOL PART
 *
 */

static double get_server_time(const std::shared_ptr<tgl_dc>& DC)
{
    //if (!DC->server_time_udelta) {
    //  DC->server_time_udelta = tgl_get_system_time() - tgl_get_monotonic_time();
    //}
    return tgl_get_monotonic_time() + DC->server_time_udelta;
}

static int64_t generate_next_msg_id(const std::shared_ptr<tgl_dc>& DC, const std::shared_ptr<tgl_session>& S)
{
    int64_t next_id = static_cast<int64_t>(get_server_time(DC)*(1LL << 32)) & -4;
    if (next_id <= S->last_msg_id) {
        next_id = S->last_msg_id += 4;
    } else {
        S->last_msg_id = next_id;
    }
    return next_id;
}

static void init_enc_msg(encrypted_message& enc_msg, std::shared_ptr<tgl_session> S, bool useful)
{
    std::shared_ptr<tgl_dc> DC = S->dc.lock();
    if (!DC) {
        TGL_WARNING("no dc found for session");
        return;
    }

    assert(DC->state == tgl_dc_state::authorized);
    assert(DC->temp_auth_key_id);
    enc_msg.auth_key_id = DC->temp_auth_key_id;
    enc_msg.server_salt = DC->server_salt;
    if (!S->session_id) {
        tgl_secure_random((unsigned char*)&S->session_id, 8);
    }
    enc_msg.session_id = S->session_id;
    if (!enc_msg.msg_id) {
        enc_msg.msg_id = generate_next_msg_id(DC, S);
    }
    enc_msg.seq_no = S->seq_no;
    if (useful) {
        enc_msg.seq_no |= 1;
    }
    S->seq_no += 2;
};

static void init_enc_msg_inner_temp(encrypted_message& enc_msg, const std::shared_ptr<tgl_dc>& DC, int64_t msg_id)
{
    enc_msg.auth_key_id = DC->auth_key_id;
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

int64_t tglmp_encrypt_send_message(const std::shared_ptr<tgl_connection>& c,
        const int32_t* msg, int msg_ints,
        int64_t msg_id_override, bool force_send, bool useful)
{
    std::shared_ptr<tgl_dc> DC = c->get_dc().lock();
    std::shared_ptr<tgl_session> S = c->get_session().lock();
    if (!DC || !S) {
        return -1;
    }

    assert(DC->is_configured() || force_send);

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
    init_enc_msg(*enc_msg, S, useful);
    int64_t msg_id = enc_msg->msg_id;

    int l = aes_encrypt_message(DC->temp_auth_key, enc_msg);
    assert(l > 0);
    rpc_send_message(c, enc_msg, l + UNENCSZ);

    return msg_id;
}

static int tglmp_encrypt_inner_temp(const std::shared_ptr<tgl_connection>& c, const int32_t* msg, int msg_ints, void* data, int64_t msg_id)
{
    std::shared_ptr<tgl_dc> DC = c->get_dc().lock();
    std::shared_ptr<tgl_session> S = c->get_session().lock();
    if (!DC || !S) {
        return -1;
    }

    const int UNENCSZ = offsetof(struct encrypted_message, server_salt);
    if (msg_ints <= 0 || msg_ints > MAX_MESSAGE_INTS - 4) {
        return -1;
    }

    std::unique_ptr<char[]> buffer = allocate_encrypted_message_buffer(msg_ints);
    encrypted_message* enc_msg = reinterpret_cast<encrypted_message*>(buffer.get());

    memcpy(enc_msg->message, msg, msg_ints * 4);
    enc_msg->msg_len = msg_ints * 4;

    init_enc_msg_inner_temp(*enc_msg, DC, msg_id);

    int length = aes_encrypt_message(DC->auth_key, enc_msg);
    assert(length > 0);
    memcpy(data, enc_msg, length + UNENCSZ);

    return length + UNENCSZ;
}

static int rpc_execute_answer(const std::shared_ptr<tgl_connection>& c, tgl_in_buffer* in, int64_t msg_id, bool in_gzip = false);

static int work_container(const std::shared_ptr<tgl_connection>& c, tgl_in_buffer* in, int64_t msg_id)
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
            std::shared_ptr<tgl_session> S = c->get_session().lock();
            if (!S) {
                return -1;
            }
            tgln_insert_msg_id(S, id);
        }
        int32_t bytes = fetch_i32(in);
        const int32_t* t = in->end;
        in->end = in->ptr + (bytes / 4);
        int r = rpc_execute_answer(c, in, id);
        if (r < 0) {
            return -1;
        }
        assert(in->ptr == in->end);
        in->end = t;
    }
    TGL_DEBUG("end work_container: msg_id = " << msg_id);
    return 0;
}

static int work_new_session_created(const std::shared_ptr<tgl_connection>& c, tgl_in_buffer* in, int64_t msg_id)
{
    std::shared_ptr<tgl_session> S = c->get_session().lock();
    if (!S) {
        return -1;
    }
    std::shared_ptr<tgl_dc> DC = c->get_dc().lock();
    if (!DC) {
        return -1;
    }
    TGL_DEBUG("work_new_session_created: msg_id = " << msg_id << ", DC " << DC->id);
    auto result = fetch_i32(in);
    TGL_ASSERT_UNUSED(result, result == static_cast<int32_t>(CODE_new_session_created));
    fetch_i64(in); // first message id
    fetch_i64(in); // unique_id
    DC->server_salt = fetch_i64(in);

    //tglq_regen_queries_from_old_session(DC, S);

    if (tgl_state::instance()->is_started()
            && !tgl_state::instance()->is_diff_locked()
            && tgl_state::instance()->working_dc()->is_logged_in()) {
        tgl_do_get_difference(false, nullptr);
    }
    return 0;
}

static int work_msgs_ack(const std::shared_ptr<tgl_connection>& c, tgl_in_buffer* in, int64_t msg_id)
{
    TGL_UNUSED(c);
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

static int work_rpc_result(const std::shared_ptr<tgl_connection>& c, tgl_in_buffer* in, int64_t msg_id)
{
    TGL_UNUSED(c);
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

static int work_packed(const std::shared_ptr<tgl_connection>& c, tgl_in_buffer* in, int64_t msg_id)
{
    auto result = fetch_i32(in);
    TGL_ASSERT_UNUSED(result, result == static_cast<int32_t>(CODE_gzip_packed));
    constexpr size_t MAX_PACKED_SIZE = 1 << 24;
    std::unique_ptr<int32_t[]> unzipped_buffer(new int32_t[MAX_PACKED_SIZE >> 2]);

    ssize_t l = prefetch_strlen(in);
    const char* s = fetch_str(in, l);

    int total_out = tgl_inflate(s, l, unzipped_buffer.get(), MAX_PACKED_SIZE);
    tgl_in_buffer new_in = { unzipped_buffer.get(), unzipped_buffer.get() + total_out / 4 };
    int r = rpc_execute_answer(c, &new_in, msg_id, true);
    return r;
}

static int work_bad_server_salt(const std::shared_ptr<tgl_connection>& c, tgl_in_buffer* in, int64_t msg_id)
{
    TGL_UNUSED(msg_id);
    auto result = fetch_i32(in);
    TGL_ASSERT_UNUSED(result, result == static_cast<int32_t>(CODE_bad_server_salt));
    int64_t id = fetch_i64(in);
    int32_t seq_no = fetch_i32(in); // seq_no
    int32_t error_code = fetch_i32(in); // error_code
    int64_t new_server_salt = fetch_i64(in);
    std::shared_ptr<tgl_dc> DC = c->get_dc().lock();
    if (!DC) {
      return -1;
    }
    TGL_DEBUG(" DC " << DC->id << " id=" << id << " seq_no=" << seq_no << " error_code= " << error_code << " new_server_salt=" << new_server_salt << " (old_server_salt=" << DC->server_salt << ")");
    DC->server_salt = new_server_salt;
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

static int work_bad_msg_notification(const std::shared_ptr<tgl_connection>& c, tgl_in_buffer* in, int64_t msg_id)
{
    TGL_UNUSED(msg_id);
    TGL_UNUSED(c);
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

static int rpc_execute_answer(const std::shared_ptr<tgl_connection>& c, tgl_in_buffer* in, int64_t msg_id, bool in_gzip)
{
    uint32_t op = prefetch_i32(in);
    switch (op) {
    case CODE_msg_container:
        return work_container(c, in, msg_id);
    case CODE_new_session_created:
        return work_new_session_created(c, in, msg_id);
    case CODE_msgs_ack:
        return work_msgs_ack(c, in, msg_id);
    case CODE_rpc_result:
        return work_rpc_result(c, in, msg_id);
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
        return work_packed(c, in, msg_id);
    case CODE_bad_server_salt:
        return work_bad_server_salt(c, in, msg_id);
    case CODE_pong:
        return work_pong(in);
    case CODE_msg_detailed_info:
        return work_detailed_info(in);
    case CODE_msg_new_detailed_info:
        return work_new_detailed_info(in);
    case CODE_bad_msg_notification:
        return work_bad_msg_notification(c, in, msg_id);
    }
    TGL_WARNING("unknown message: " << op);
    in->ptr = in->end; // Will not fail due to assertion in->ptr == in->end
    return 0;
}

static void create_connection(const std::shared_ptr<tgl_session>& S)
{
    std::shared_ptr<tgl_dc> DC = S->dc.lock();
    if (!DC) {
        TGL_WARNING("no dc found for session");
        return;
    }

    static auto client = std::make_shared<mtproto_client>();

    S->c = tgl_state::instance()->connection_factory()->create_connection(
            std::weak_ptr<tgl_session>(S), std::weak_ptr<tgl_dc>(DC), client);
    S->c->open();
}

static void restart_session(const std::shared_ptr<tgl_dc>& dc)
{
    if (dc->session) {
        TGL_WARNING("failing session " << dc->session->session_id);
        dc->session->clear();
        dc->session = nullptr;
    }
    tglmp_dc_create_session(dc);
}

static mtproto_client::execute_result process_rpc_message(const std::shared_ptr<tgl_connection>& c, struct encrypted_message* enc, int len)
{
    const int MINSZ = offsetof(struct encrypted_message, message);
    const int UNENCSZ = offsetof(struct encrypted_message, server_salt);
    TGL_DEBUG("process_rpc_message(), len=" << len);
    if (len < MINSZ || (len & 15) != (UNENCSZ & 15)) {
        TGL_WARNING("incorrect packet from server, closing connection");
        return mtproto_client::execute_result::bad_connection;
    }
    assert(len >= MINSZ && (len & 15) == (UNENCSZ & 15));
    std::shared_ptr<tgl_dc> DC = c->get_dc().lock();
    if (!DC) {
        return mtproto_client::execute_result::bad_dc;
    }

    if (enc->auth_key_id != DC->temp_auth_key_id && enc->auth_key_id != DC->auth_key_id) {
        TGL_WARNING("received msg from dc " << DC->id << " with auth_key_id " << enc->auth_key_id <<
                " (perm_auth_key_id " << DC->auth_key_id << " temp_auth_key_id "<< DC->temp_auth_key_id << "), dropping");
        return mtproto_client::execute_result::ok;
    }

    TGLC_aes_key aes_key;
    unsigned char aes_iv[32];
    if (enc->auth_key_id == DC->temp_auth_key_id) {
        assert(enc->auth_key_id == DC->temp_auth_key_id);
        assert(DC->temp_auth_key_id);
        tgl_init_aes_auth(&aes_key, aes_iv, DC->temp_auth_key + 8, enc->msg_key, AES_DECRYPT);
    } else {
        assert(enc->auth_key_id == DC->auth_key_id);
        assert(DC->auth_key_id);
        tgl_init_aes_auth(&aes_key, aes_iv, DC->auth_key + 8, enc->msg_key, AES_DECRYPT);
    }

    int l = tgl_pad_aes_decrypt(&aes_key,
            aes_iv,
            reinterpret_cast<const unsigned char*>(&enc->server_salt),
            len - UNENCSZ,
            reinterpret_cast<unsigned char*>(&enc->server_salt), len - UNENCSZ);
    TGL_ASSERT_UNUSED(l, l == len - UNENCSZ);

    if (!(!(enc->msg_len & 3) && enc->msg_len > 0 && enc->msg_len <= len - MINSZ && len - MINSZ - enc->msg_len <= 12)) {
        TGL_WARNING("incorrect packet from server, closing connection");
        return mtproto_client::execute_result::bad_connection;
    }
    assert(!(enc->msg_len & 3) && enc->msg_len > 0 && enc->msg_len <= len - MINSZ && len - MINSZ - enc->msg_len <= 12);

    std::shared_ptr<tgl_session> S = c->get_session().lock();
    if (!S || S->session_id != enc->session_id) {
        TGL_WARNING("message to bad session, dropping");
        return mtproto_client::execute_result::ok;
    }

    unsigned char sha1_buffer[20];
    memset(sha1_buffer, 0, sizeof(sha1_buffer));
    TGLC_sha1((unsigned char *)&enc->server_salt, enc->msg_len + (MINSZ - UNENCSZ), sha1_buffer);
    if (memcmp(&enc->msg_key, sha1_buffer + 4, 16)) {
        TGL_WARNING("incorrect packet from server, closing connection");
        return mtproto_client::execute_result::bad_connection;
    }

    int32_t this_server_time = enc->msg_id >> 32LL;
    if (!S->received_messages) {
        DC->server_time_delta = this_server_time - tgl_get_system_time();
        if (DC->server_time_udelta) {
            TGL_WARNING("adjusting monotonic clock delta to " <<
                    DC->server_time_udelta - this_server_time + tgl_get_monotonic_time());
        }
        DC->server_time_udelta = this_server_time - tgl_get_monotonic_time();
    }

    int64_t server_time = get_server_time(DC);
    if (this_server_time < server_time - 300 || this_server_time > server_time + 30) {
        TGL_WARNING("bad msg time: salt = " << enc->server_salt << ", session_id = " << enc->session_id
                << ", msg_id = " << enc->msg_id << ", seq_no = " << enc->seq_no
                << ", server_time = " << server_time << ", time from msg_id = " << this_server_time
                << ", now = " << static_cast<int64_t>(tgl_get_system_time()));
        restart_session(DC);
        return mtproto_client::execute_result::bad_session;
    }
    S->received_messages++;

    if (DC->server_salt != enc->server_salt) {
        TGL_DEBUG("updating server salt from " << DC->server_salt << " to " << enc->server_salt);
        DC->server_salt = enc->server_salt;
    }

    //assert(enc->msg_id > server_last_msg_id && (enc->msg_id & 3) == 1);
    TGL_DEBUG("received mesage id " << enc->msg_id);
    //server_last_msg_id = enc->msg_id;

    assert(l >= (MINSZ - UNENCSZ) + 8);

    tgl_in_buffer in = { enc->message, enc->message + (enc->msg_len / 4) };

    if (enc->msg_id & 1) {
        tgln_insert_msg_id(S, enc->msg_id);
    }
    assert(S->session_id == enc->session_id);

    if (rpc_execute_answer(c, &in, enc->msg_id) < 0) {
        restart_session(DC);
        return mtproto_client::execute_result::bad_session;
    }
    assert(in.ptr == in.end);
    return mtproto_client::execute_result::ok;
}

static mtproto_client::execute_result rpc_execute(const std::shared_ptr<tgl_connection>& c, int op, int len)
{
    std::shared_ptr<tgl_dc> DC = c->get_dc().lock();
    if (!DC || !DC->session || DC->session->c != c) {
        return mtproto_client::execute_result::bad_dc;
    }

    if (len >= MAX_RESPONSE_SIZE/* - 12*/ || len < 0/*12*/) {
        TGL_WARNING("answer too long, skipping. lengeth:" << len);
        return mtproto_client::execute_result::ok;
    }

    std::unique_ptr<char[]> response(new char[len]);
    TGL_DEBUG("response of " << len << " bytes received from DC " << DC->id);
    int result = c->read(response.get(), len);
    TGL_ASSERT_UNUSED(result, result == len);

#if !defined(__MACH__) && !defined(__FreeBSD__) && !defined(__OpenBSD__) && !defined(__CYGWIN__)
    //  setsockopt(c->fd, IPPROTO_TCP, TCP_QUICKACK, (int[]){0}, 4);
#endif
    tgl_dc_state state = DC->state;
    if (state != tgl_dc_state::authorized) {
        TGL_DEBUG("state = " << state << " for DC " << DC->id);
    }
    switch (state) {
    case tgl_dc_state::reqpq_sent:
        return process_respq_answer(c, response.get()/* + 8*/, len/* - 12*/, false);
    case tgl_dc_state::reqdh_sent:
        return process_dh_answer(c, response.get()/* + 8*/, len/* - 12*/, false);
    case tgl_dc_state::client_dh_sent:
        return process_auth_complete(c, response.get()/* + 8*/, len/* - 12*/, false);
    case tgl_dc_state::reqpq_sent_temp:
        return process_respq_answer(c, response.get()/* + 8*/, len/* - 12*/, true);
    case tgl_dc_state::reqdh_sent_temp:
        return process_dh_answer(c, response.get()/* + 8*/, len/* - 12*/, true);
    case tgl_dc_state::client_dh_sent_temp:
        return process_auth_complete(c, response.get()/* + 8*/, len/* - 12*/, true);
    case tgl_dc_state::authorized:
        if (op < 0 && op >= -999) {
            if (tgl_state::instance()->pfs_enabled() && op == -404) {
                TGL_DEBUG("bind temp auth key failed with -404 error for DC "
                        << DC->id << ", which is not unusual, requesting a new temp auth key and trying again");
                DC->restart_temp_authorization();
                return mtproto_client::execute_result::ok;
            } else {
                TGL_WARNING("server error " << op << " from DC " << DC->id);
                return mtproto_client::execute_result::bad_connection;
            }
        } else {
            return process_rpc_message(c, (struct encrypted_message *)(response.get()/* + 8*/), len/* - 12*/);
        }
    default:
        TGL_ERROR("cannot receive answer in state " << DC->state);
        return mtproto_client::execute_result::bad_connection;
    }
}

void tgl_dc::restart_temp_authorization()
{
    TGL_DEBUG("restarting temp authorization for DC " << id);
    reset_temp_authorization();
    assert(is_authorized());
    if (is_authorized()) {
        state = tgl_dc_state::authorized;
    }
    if (!session) {
        tglmp_dc_create_session(shared_from_this());
    } else {
        create_temp_auth_key(session->c);
    }
}

void tgl_dc::restart_authorization()
{
    TGL_DEBUG("restarting authorization for DC " << id);
    reset_authorization();
    if (!session) {
        tglmp_dc_create_session(shared_from_this());
    } else {
        send_req_pq_packet(session->c);
    }
}

static int tc_becomes_ready(const std::shared_ptr<tgl_connection>& c)
{
    std::shared_ptr<tgl_dc> DC = c->get_dc().lock();
    if (!DC || !DC->session || DC->session->c != c) {
        return -1;
    }

    TGL_NOTICE("outbound rpc connection from DC " << DC->id << " became ready");
    //char byte = 0xef;
    //assert(c->write_out(&byte, 1) == 1);
    //c->flush();

    if (DC->is_authorized()) {
        DC->state = tgl_dc_state::authorized;
    }
    tgl_dc_state state = DC->state;
    if (state == tgl_dc_state::authorized && !tgl_state::instance()->pfs_enabled()) {
        DC->temp_auth_key_id = DC->auth_key_id;
        memcpy(DC->temp_auth_key, DC->auth_key, 256);
        DC->set_bound();
    }
    switch (state) {
    case tgl_dc_state::init:
        TGL_DEBUG("DC " << DC->id << " is in init state");
        send_req_pq_packet(c);
        break;
    case tgl_dc_state::authorized:
        TGL_DEBUG("DC " << DC->id << " is in authorized state");
        if (!DC->is_bound()) {
            TGL_DEBUG("DC " << DC->id << " is not bond");
            assert(tgl_state::instance()->pfs_enabled());
            if (!DC->temp_auth_key_id) {
                assert(tgl_state::instance()->pfs_enabled());
                create_temp_auth_key(c);
            } else {
                bind_temp_auth_key(c);
            }
        } else if (!DC->is_configured()) {
            TGL_DEBUG("DC " << DC->id << " is not configured");
            tgl_do_help_get_config_dc(DC);
        } else {
            // To trigger sending pending queries if any.
            tgl_do_set_dc_configured(DC, true);
        }
        break;
    default:
        TGL_DEBUG("c_state = " << DC->state);
        DC->state = tgl_dc_state::init; // previous connection was reset
        send_req_pq_packet(c);
        break;
    }
    return 0;
}

static int rpc_becomes_ready(const std::shared_ptr<tgl_connection>& c)
{
    return tc_becomes_ready(c);
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

static int send_all_acks(const std::shared_ptr<tgl_session>& session)
{
    auto dc = session->dc.lock();
    if (!dc) {
        return -1;
    }

    if (!dc->is_configured()) {
        return -1;
    }

    mtprotocol_serializer s;
    s.out_i32(CODE_msgs_ack);
    s.out_i32(CODE_vector);
    s.out_i32(session->ack_set.size());
    for (int64_t id: session->ack_set) {
        s.out_i64(id);
    }
    session->ack_set.clear();
    tglmp_encrypt_send_message(session->c, s.i32_data(), s.i32_size());
    return 0;
}

static void send_all_acks_gateway(const std::shared_ptr<tgl_session>& session)
{
    send_all_acks(session);
}

void tgln_insert_msg_id(const std::shared_ptr<tgl_session>& s, int64_t id)
{
    if (!s->ev) {
        // The session has been cleared.
        return;
    }

    if (s->ack_set.empty()) {
        s->ev->start(ACK_TIMEOUT);
    }
    s->ack_set.insert(id);
}

void tglmp_dc_create_session(const std::shared_ptr<tgl_dc>& dc)
{
    std::shared_ptr<tgl_session> S = std::make_shared<tgl_session>();
    tgl_secure_random((unsigned char *)&S->session_id, 8);
    S->dc = dc;

    create_connection(S);
    S->ev = tgl_state::instance()->timer_factory()->create_timer(std::bind(&send_all_acks_gateway, S));
    assert(!dc->session);

    if (S->c) {
        dc->session = S;
    } else {
        S->clear();
        S = nullptr;
    }
}

void tgl_do_send_ping(const std::shared_ptr<tgl_connection>& c)
{
    auto dc = c->get_dc().lock();
    if (!dc) {
        TGL_WARNING("no dc, can't send ping");
        return;
    }

    if (!dc->is_configured()) {
        return;
    }

    int32_t buffer[3];
    buffer[0] = CODE_ping;
    *reinterpret_cast<int64_t*>(buffer + 1) = tgl_random<int64_t>();
    tglmp_encrypt_send_message(c, buffer, 3);
}
