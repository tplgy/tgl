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

#include "secret_chat_encryptor.h"

#include "crypto/tgl_crypto_aes.h"
#include "crypto/tgl_crypto_sha.h"
#include "mtproto-common.h"
#include "tgl/tgl_secret_chat.h"

#include <string.h>

namespace tgl {
namespace impl {

static void encrypt_decrypted_message(const std::shared_ptr<tgl_secret_chat>& secret_chat,
        const unsigned char msg_sha[20], const int32_t* encr_ptr, const int32_t* encr_end, char* encrypted_data)
{
    unsigned char sha1a_buffer[20];
    unsigned char sha1b_buffer[20];
    unsigned char sha1c_buffer[20];
    unsigned char sha1d_buffer[20];
    memset(sha1a_buffer, 0, sizeof(sha1a_buffer));
    memset(sha1b_buffer, 0, sizeof(sha1b_buffer));
    memset(sha1c_buffer, 0, sizeof(sha1c_buffer));
    memset(sha1d_buffer, 0, sizeof(sha1d_buffer));

    const unsigned char* msg_key = msg_sha + 4;

    unsigned char buf[64];
    memset(buf, 0, sizeof(buf));
    const int* encryption_key = reinterpret_cast<const int*>(secret_chat->key());
    memcpy(buf, msg_key, 16);
    memcpy(buf + 16, encryption_key, 32);
    TGLC_sha1(buf, 48, sha1a_buffer);

    memcpy(buf, encryption_key + 8, 16);
    memcpy(buf + 16, msg_key, 16);
    memcpy(buf + 32, encryption_key + 12, 16);
    TGLC_sha1(buf, 48, sha1b_buffer);

    memcpy(buf, encryption_key + 16, 32);
    memcpy(buf + 32, msg_key, 16);
    TGLC_sha1(buf, 48, sha1c_buffer);

    memcpy(buf, msg_key, 16);
    memcpy(buf + 16, encryption_key + 24, 32);
    TGLC_sha1(buf, 48, sha1d_buffer);

    unsigned char key[32];
    memset(key, 0, sizeof(key));
    memcpy(key, sha1a_buffer + 0, 8);
    memcpy(key + 8, sha1b_buffer + 8, 12);
    memcpy(key + 20, sha1c_buffer + 4, 12);

    unsigned char iv[32];
    memset(iv, 0, sizeof(iv));
    memcpy(iv, sha1a_buffer + 8, 12);
    memcpy(iv + 12, sha1b_buffer + 0, 8);
    memcpy(iv + 20, sha1c_buffer + 16, 4);
    memcpy(iv + 24, sha1d_buffer + 0, 8);

    TGLC_aes_key aes_key;
    TGLC_aes_set_encrypt_key(key, 256, &aes_key);
    TGLC_aes_ige_encrypt(reinterpret_cast<const unsigned char*>(encr_ptr), reinterpret_cast<unsigned char*>(encrypted_data), 4 * (encr_end - encr_ptr), &aes_key, iv, 1);
    memset(&aes_key, 0, sizeof(aes_key));
}

void secret_chat_encryptor::start()
{
    m_encr_base = m_serializer->reserve_i32s(1/*str len*/ + 2/*fingerprint*/ + 4/*msg_key*/ + 1/*len*/);
}

void secret_chat_encryptor::end()
{
    size_t length = m_serializer->i32_size() - (m_encr_base + 8);
    while ((m_serializer->i32_size() - m_encr_base - 3) & 3) {
        int32_t i;
        tgl_secure_random(reinterpret_cast<unsigned char*>(&i), 4);
        m_serializer->out_i32(i);
    }

    m_serializer->out_i32_at(m_encr_base, (m_serializer->i32_size() - m_encr_base - 1) * 4 * 256 + 0xfe); // str len
    m_serializer->out_i64_at(m_encr_base + 1, m_secret_chat->key_fingerprint()); // fingerprint
    m_serializer->out_i32_at(m_encr_base + 1 + 2 + 4, length * 4); // len

    const int32_t* encr_ptr = m_serializer->i32_data() + m_encr_base + 1 + 2 + 4;
    const int32_t* encr_end = m_serializer->i32_data() + m_serializer->i32_size();

    unsigned char sha1_buffer[20];
    memset(sha1_buffer, 0, sizeof(sha1_buffer));
    TGLC_sha1(reinterpret_cast<const unsigned char*>(encr_ptr), (length + 1) * 4, sha1_buffer);
    m_serializer->out_i32s_at(m_encr_base + 1 + 2, reinterpret_cast<int32_t*>(sha1_buffer + 4), 4); // msg_key

    encrypt_decrypted_message(m_secret_chat, sha1_buffer, encr_ptr, encr_end, reinterpret_cast<char*>(const_cast<int32_t*>(encr_ptr)));
}

}
}
