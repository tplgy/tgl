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
