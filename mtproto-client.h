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
*/
#ifndef __MTPROTO_CLIENT_H__
#define __MTPROTO_CLIENT_H__
#include "crypto/bn.h"

#include "tgl.h"

class connection;
struct tgl_dc;
#define TG_APP_HASH "844584f2b1fd2daecee726166dcc1ef8"
#define TG_APP_ID 10534

#define ACK_TIMEOUT 1
#define MAX_DC_ID 10

long long tglmp_encrypt_send_message(std::shared_ptr<connection> c, int *msg, int msg_ints, int flags);
void tglmp_dc_create_session(std::shared_ptr<tgl_dc> DC);
//int tglmp_check_g (unsigned char p[256], BIGNUM *g);
//int tglmp_check_DH_params (BIGNUM *p, int g);
std::shared_ptr<tgl_dc> tglmp_alloc_dc(int flags, int id, const std::string &ip, int port);
void tglmp_regenerate_temp_auth_key(std::shared_ptr<tgl_dc> D);

void tgln_insert_msg_id(std::shared_ptr<tgl_session> S, long long id);
int tglmp_on_start ();
void tgl_dc_authorize(std::shared_ptr<tgl_dc>DC);
void tgls_free_dc(std::shared_ptr<tgl_dc> DC);
void tgls_free_pubkey();
void tgl_do_send_ping(std::shared_ptr<connection> c);
#endif
