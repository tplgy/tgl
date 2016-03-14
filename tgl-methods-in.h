// normally you should not use these methods 
// use them with caution


#ifndef __TGL_METHODS_IN_H__
#define __TGL_METHODS_IN_H__

/* {{{ AUTHORIZATION METHODS. NORMALLY YOU DON'T NEED THEM */

// send query to updated DCs' ips
// automatically renews data on update
void tgl_do_help_get_config (void (*callback)(void *callback_extra, int success), void *callback_extra);

// requests server to send code to specified phone number
// if user is logged in elsewhere message will first appear as telegram message
// and SMS will be sent some time after
void tgl_do_send_code (const char *phone, int phone_len, void (*callback)(void *callback_extra, int success, int registered, const char *hash), void *callback_extra);

// request server to send code via phone call
void tgl_do_phone_call (const char *phone, int phone_len, const char *hash, int hash_len, void (*callback)(void *callback_extra, int success), void *callback_extra);

// sends code from SMS to server. This step should end authorization, unless user have password
int tgl_do_send_code_result (const char *phone, int phone_len, const char *hash, int hash_len, const char *code, int code_len, void (*callback)(void *callback_extra, int success), void *callback_extra);


// sends code from SMS, username and lastname to server. This step should end new user registration
int tgl_do_send_code_result_auth (const char *phone, int phone_len, const char *hash, int hash_len, const char *code, int code_len, const char *first_name, int first_name_len, const char *last_name, int last_name_len, void (*callback)(void *callback_extra, int success, struct tgl_user *Self), void *callback_extra);

/* }}} */

void tgl_do_send_msg (struct tgl_message *M, void (*callback)(void *callback_extra, int success, struct tgl_message *M), void *callback_extra);

void tgl_do_check_password (void (*callback)(void *extra, int success), void *callback_extra);

void tgl_do_export_auth (int num, void (*callback) (void *callback_extra, int success), void *callback_extra);

void tgl_do_create_secret_chat (int user_id, void (*callback)(void *callback_extra, int success, struct tgl_secret_chat *E), void *callback_extra);

void tgl_do_get_difference (int sync_from_start, void (*callback)(void *callback_extra, int success), void *callback_extra);

void tgl_do_lookup_state ();

void tgl_do_help_get_config_dc (struct tgl_dc *D, void (*callback)(void *, int), void *callback_extra);

void tgl_do_request_exchange (struct tgl_secret_chat *E);

void tgl_do_create_keys_end (struct tgl_secret_chat *U);

void tgl_do_send_encr_chat_layer (struct tgl_secret_chat *E);
#endif
