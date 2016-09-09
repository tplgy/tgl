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
#ifndef __MTPROTO_CLIENT_H__
#define __MTPROTO_CLIENT_H__

#include <memory>

class tgl_connection;
struct tgl_dc;
struct tgl_session;

class mtproto_client
{
public:
    int ready(const std::shared_ptr<tgl_connection>& c);

    enum class execute_result {
        ok,
        bad_connection,
        bad_session,
        bad_dc,
    };
    execute_result execute(const std::shared_ptr<tgl_connection>& c, int op, int len);
};

int64_t tglmp_encrypt_send_message(const std::shared_ptr<tgl_connection>& c,
        const int32_t* msg, int msg_ints,
        int64_t msg_id_override = 0, bool force_send = false, bool useful = false);
void tglmp_dc_create_session(const std::shared_ptr<tgl_dc>& dc);
void tglmp_regenerate_temp_auth_key(const std::shared_ptr<tgl_dc>& dc);

void tgln_insert_msg_id(const std::shared_ptr<tgl_session>& s, int64_t id);
int tglmp_on_start();
void tgls_free_pubkey();
void tgl_do_send_ping(const std::shared_ptr<tgl_connection>& c);

#endif
