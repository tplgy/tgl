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
*/
//#include "net.h"
#ifndef __QUERIES_H__
#define __QUERIES_H__
#include "tgl-structures.h"
#include "auto.h"
#include "tgl-layout.h"
#include "types/query_methods.h"

#define QUERY_ACK_RECEIVED 1
#define QUERY_FORCE_SEND 2

class tgl_timer;

struct query {
    long long msg_id;
    int data_len;
    int flags;
    int seq_no;
    long long session_id;
    void *data;
    struct query_methods *methods;
    std::shared_ptr<tgl_timer> ev;
    std::shared_ptr<tgl_dc> DC;
    std::shared_ptr<tgl_session> session;
    struct paramed_type *type;
    std::shared_ptr<void> extra;
    void *callback;
    std::shared_ptr<void> callback_extra;
};

void out_peer_id (tgl_peer_id_t id);

struct messages_send_extra {
  int multi = 0;
  tgl_message_id_t id;
  int count = 0;
  tgl_message_id_t *list = NULL;
};

std::shared_ptr<query> tglq_send_query (std::shared_ptr<tgl_dc> DC, int len, void *data, struct query_methods *methods, std::shared_ptr<void> extra, void *callback, std::shared_ptr<void> callback_extra);
void tglq_query_ack (long long id);
int tglq_query_error (long long id);
int tglq_query_result (long long id);
void tglq_query_restart (long long id);

//double next_timer_in (void);
//void work_timers (void);

//extern struct query_methods help_get_config_methods;

double get_double_time (void);

struct send_file;
void send_file_encrypted_end (std::shared_ptr<send_file> f, void *callback, std::shared_ptr<void> callback_extra);

void tgl_do_send_bind_temp_key (std::shared_ptr<tgl_dc> D, long long nonce, int expires_at, void *data, int len, long long msg_id);

void tgl_do_request_exchange (struct tgl_secret_chat *E);
void tgl_do_confirm_exchange ( struct tgl_secret_chat *E, int sen_nop);
void tgl_do_accept_exchange (struct tgl_secret_chat *E, long long exchange_id, unsigned char g_a[]);
void tgl_do_commit_exchange (struct tgl_secret_chat *E, unsigned char g_a[]);
void tgl_do_abort_exchange (struct tgl_secret_chat *E);

void tglq_regen_query (long long id);
void tglq_query_delete (long long id);
void tglq_query_free_all ();
void tglq_regen_queries_from_old_session (struct tgl_dc *DC, struct tgl_session *S);


#ifdef ENABLE_SECRET_CHAT
void tgl_do_encr_chat(const tgl_peer_id_t& id,
        long long* access_hash,
        int* date,
        int* admin,
        const int* user_id,
        void* key,
        unsigned char* g_key,
        void* first_key_id,
        tgl_secret_chat_state* state,
        int* ttl,
        int* layer,
        int* in_seq_no,
        int* last_in_seq_no,
        int* out_seq_no,
        long long* key_fingerprint,
        int flags,
        const char* print_name,
        int print_name_len);
#endif

// For binlog

//int get_dh_config_on_answer (struct query *q);
//void fetch_dc_option (void);
#endif
