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

#include "tgl/tgl_secret_chat.h"

#include "crypto/tgl_crypto_bn.h"
#include "crypto/tgl_crypto_sha.h"

#include "mtproto-utils.h"
#include "tgl/tgl.h"
#include "tools.h"
#include "tgl/tgl_log.h"

tgl_secret_chat::tgl_secret_chat()
    : id()
    , access_hash(0)
    , temp_key_fingerprint(0)
    , exchange_id(0)
    , exchange_key_fingerprint(0)
    , user_id(0)
    , admin_id(0)
    , date(0)
    , ttl(0)
    , layer(0)
    , in_seq_no(0)
    , out_seq_no(0)
    , last_in_seq_no(0)
    , encr_root(0)
    , encr_param_version(0)
    , state(tgl_secret_chat_state::none)
    , exchange_state(tgl_secret_chat_exchange_state::none)
    , device_id(0)
    , g_key()
    , m_encr_prime()
    , m_encr_prime_bn(nullptr)
{
    memset(m_key, 0, sizeof(m_key));
    memset(m_key_sha, 0, sizeof(m_key_sha));
    memset(exchange_key, 0, sizeof(exchange_key));
}

tgl_secret_chat::~tgl_secret_chat()
{
}

void tgl_secret_chat::set_key(const unsigned char* key)
{
    TGLC_sha1(key, key_size(), m_key_sha);
    memcpy(m_key, key, key_size());
}

void tgl_secret_chat::set_encr_prime(const unsigned char* prime, size_t length)
{
    m_encr_prime.resize(length);
    m_encr_prime_bn.reset(new tgl_bn(TGLC_bn_new()));
    std::copy(prime, prime + length, m_encr_prime.begin());
    TGLC_bn_bin2bn(m_encr_prime.data(), length, m_encr_prime_bn->bn);
}

bool tgl_secret_chat::create_keys_end()
{
    assert(!this->encr_prime().empty());
    if (this->encr_prime().empty()) {
        return false;
    }

    std::unique_ptr<TGLC_bn, TGLC_bn_clear_deleter> g_b(TGLC_bn_bin2bn(this->g_key.data(), 256, 0));
    if (tglmp_check_g_a(this->encr_prime_bn()->bn, g_b.get()) < 0) {
        return false;
    }

    TGLC_bn* p = this->encr_prime_bn()->bn;
    std::unique_ptr<TGLC_bn, TGLC_bn_clear_deleter> r(TGLC_bn_new());
    std::unique_ptr<TGLC_bn, TGLC_bn_clear_deleter> a(TGLC_bn_bin2bn(this->key(), tgl_secret_chat::key_size(), 0));
    check_crypto_result(TGLC_bn_mod_exp(r.get(), g_b.get(), a.get(), p, tgl_state::instance()->bn_ctx()->ctx));

    std::vector<unsigned char> key(tgl_secret_chat::key_size(), 0);

    TGLC_bn_bn2bin(r.get(), (key.data() + (tgl_secret_chat::key_size() - TGLC_bn_num_bytes(r.get()))));
    this->set_key(key.data());

    if (this->key_fingerprint() != this->temp_key_fingerprint) {
        TGL_WARNING("key fingerprint mismatch (my 0x" << std::hex
                << (uint64_t)this->key_fingerprint()
                << "x 0x" << (uint64_t)this->temp_key_fingerprint << "x)");
        return false;
    }
    this->temp_key_fingerprint = 0;
    return true;
}

void tgl_secret_chat::do_set_dh_params(int root, unsigned char prime[], int version)
{
    this->encr_root = root;
    this->set_encr_prime(prime, 256);
    this->encr_param_version = version;

    auto res = tglmp_check_DH_params(this->encr_prime_bn()->bn, this->encr_root);
    TGL_ASSERT_UNUSED(res, res >= 0);
}


void tgl_secret_chat::update(const int64_t* access_hash,
        const int32_t* date,
        const int32_t* admin,
        const int32_t* user_id,
        const unsigned char* key,
        const unsigned char* g_key,
        const tgl_secret_chat_state& state,
        const int32_t* ttl,
        const int32_t* layer,
        const int32_t* in_seq_no)
{
    if (access_hash && *access_hash != this->access_hash) {
        this->access_hash = *access_hash;
        this->id.access_hash = *access_hash;
    }

    if (date) {
        this->date = *date;
    }

    if (admin) {
        this->admin_id = *admin;
    }

    if (user_id) {
        this->user_id = *user_id;
    }

    if (in_seq_no) {
        this->in_seq_no = *in_seq_no;
        TGL_DEBUG("in seq number " << *in_seq_no);
    }

    if (g_key) {
        this->g_key.resize(256);
        std::copy(g_key, g_key + 256, this->g_key.begin());
    }

    if (key) {
        this->set_key(key);
    }

    if (this->state == tgl_secret_chat_state::waiting && state == tgl_secret_chat_state::ok) {
        if (this->create_keys_end()) {
            this->state = state;
        } else {
            this->state = tgl_secret_chat_state::deleted;
        }
    } else {
        this->state = state;
    }
}
