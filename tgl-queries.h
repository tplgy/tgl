#ifndef __TGL_QUERIES_H__
#define __TGL_QUERIES_H__

#include "tgl.h"
#include "types/tgl_chat.h"
#include "types/tgl_user.h"
#include "types/tgl_typing_status.h"
#include "types/tgl_message.h"

#include <string>
#include <vector>

void tgl_do_get_terms_of_service(const std::function<void(bool success, const std::string&)>& callback);

// Registers the device for push notifications
void tgl_do_register_device(int token_type, const std::string& token, const std::string& device_model, const std::string& system_version, const std::string& app_version, bool app_sandbox, const std::string& lang_code,
        std::function<void(bool success)> callback);

/* {{{ WORK WITH ACCOUNT */
// sets account password
// user will be requested to type his current password and new password (twice)
void tgl_do_set_password(const std::string& hint, const std::function<void(bool success)>& callback);
/* }}} */

/* {{{ SENDING MESSAGES */

struct tl_ds_reply_markup;

// send plain text message to peer id
// flags is combination of TGL_SEND_MSG_FLAG_*
// reply markup can be NULL
void tgl_do_send_message (tgl_peer_id_t peer_id, const char *text, int text_len, unsigned long long flags, struct tl_ds_reply_markup *reply_markup, std::function<void(bool success, const std::shared_ptr<tgl_message>& M)> callback);

// sends plain text reply on message *reply_id*
// message *reply_id* should be cached
void tgl_do_reply_message (long long int reply_id, tgl_peer_id_t to_id, const char *text, std::function<void(bool success, const std::shared_ptr<tgl_message>& M)> callback);

// forward message *msg_id* to peer *id*
// message can not be encrypted and peer can not be secret chat
void tgl_do_forward_message (int id, int msg_id, unsigned long long flags, std::function<void(bool success, const std::shared_ptr<tgl_message>& M)> callback);

// forward messages *ids* to peer *id*
// messages can not be encrypted and peer can not be secret chat
void tgl_do_forward_messages(const tgl_peer_id_t& id, const std::vector<tgl_message_id_t>& ids, unsigned long long flags, std::function<void(bool success, const std::vector<std::shared_ptr<tgl_message>>& messages)> callback);

// sends contact to another user.
// This contact may be or may not be telegram user
void tgl_do_send_contact (tgl_peer_id_t id, const char *phone, const char *first_name, const char *last_name,
        unsigned long long flags, std::function<void(bool success, const std::shared_ptr<tgl_message>& M)> callback);

// reply on message *reply_id* with contact
void tgl_do_reply_contact (int reply_id, tgl_peer_id_t peer_id, const char *phone, const char *first_name, const char *last_name,
        unsigned long long flags, std::function<void(bool success, const std::shared_ptr<tgl_message>& M)> callback);

// sends media from message *msg_id* to another dialog
// a bit different from forwarding message with media
// secret message media can be forwarded to secret chats
// and non-secret - to non-secret chats and users
void tgl_do_forward_media (tgl_peer_id_t id, struct tgl_message_media *media, std::function<void(bool success, const std::shared_ptr<tgl_message>& M)> callback);

// sends location to chat *id*
void tgl_do_send_location (tgl_peer_id_t id, double latitude, double longitude, unsigned long long flags, std::function<void(bool success, const std::shared_ptr<tgl_message>& M)> callback);

// sends broadcast (i.e. message to several users at once)
// flags are same as in tgl_do_send_message
void tgl_do_send_broadcast (int num, tgl_peer_id_t peer_id[], const char *text, unsigned long long flags, std::function<void(bool success, const std::vector<std::shared_ptr<tgl_message>>& ML)> callback);
/* }}} */

/* {{{ EDITING SELF PROFILE */

// rename self account
void tgl_do_set_profile_name (const std::string& first_name, const std::string& last_name, std::function<void(bool success)> callback);

// sets self username
void tgl_do_set_username (const std::string& username, std::function<void(bool success)> callback);

// updates online/offline status
void tgl_do_update_status (bool online, std::function<void(bool success)> callback);

// exports card. This card can be later be used by another user to add you to dialog list.
void tgl_do_export_card(const std::function<void(bool success, const std::vector<int>& card)>& callback);
/* }}} */

/* {{{ WORKING WITH GROUP CHATS */

// sets chat title
void tgl_do_rename_chat (int id, const char *new_title, int new_title_len, std::function<void(bool success)> callback);

// requests full info about chat *id*.
// if *offline_mode* is set no actual query is sent
void tgl_do_get_chat_info (int id, int offline_mode, std::function<void(bool success, const std::shared_ptr<tgl_chat>& C)> callback);

// adds user *id* to chat *chat_id*
// sends *limit* last messages from this chat to user
void tgl_do_add_user_to_chat (int chat_id, int id, int limit, std::function<void(bool success)> callback);

// deleted user *id* from chat *chat_id*
// you can do it if you are admin (=creator) of chat or if you invited this user or if it is yourself
void tgl_do_del_user_from_chat(int chat_id, const tgl_peer_id_t& user_id, const std::function<void(bool success)>& callback);

// creates group chat with users ids
// there should be at least one user other then you in chat
void tgl_do_create_group_chat (std::vector<tgl_peer_id_t> user_ids, const std::string &chat_topic, std::function<void(bool success)> callback);

// receives invitation link to this chat
// only chat admin can create one
// prevoius link invalidated, if existed
void tgl_do_export_chat_link(const tgl_peer_id_t& id, const std::function<void(bool success, const std::string& link)>& callback);

// joins to secret chat by link (or hash of this link)
void tgl_do_import_chat_link (const char *link, int link_len, std::function<void(bool success)> callback);

/* }}} */

/* {{{ WORKING WITH USERS */

// requests full info about user *id*.
// if *offline_mode* is set no actual query is sent
void tgl_do_get_user_info(const tgl_peer_id_t& id, const std::function<void(bool success, const std::shared_ptr<tgl_user>& user)>& callback);

// adds contact to contact list by phone number
// user will be named  *first_name* *last_name* in contact list
// force should be set to 0
void tgl_do_add_contact (const std::string& phone, const std::string& first_name, const std::string& last_name, bool replace, std::function<void(bool success, const std::vector<int>& user_ids)> callback);

// deletes user *id* from contact listus
void tgl_do_del_contact (tgl_peer_id_t id, std::function<void(bool success)> callback);

// imports card exported by another user
void tgl_do_import_card (int size, int *card, std::function<void(bool success, const std::shared_ptr<tgl_user>& user)> callback);

// blocks user
void tgl_do_block_user (int user_id, long long int access_hash, std::function<void(bool success)> callback);

// unblocks blocked user
void tgl_do_unblock_user (int user_id, long long int access_hash, std::function<void(bool success)> callback);
/* }}} */

/* {{{ WORKING WITH SECRET CHATS */

// requests creation of secret chat with user *user_id*
//void tgl_do_create_encr_chat_request (int user_id, std::function<void(bool success, struct tgl_secret_chat *E)> callback);

// accepts secret chat request
// method can fail if another device will be first to accept it
void tgl_do_accept_encr_chat_request(const std::shared_ptr<tgl_secret_chat>& secret_chat,
        const std::function<void(bool success, const std::shared_ptr<tgl_secret_chat>&)>& callback);

// sets ttl of secret chat
void tgl_do_set_encr_chat_ttl(const std::shared_ptr<tgl_secret_chat>& secret_chat, int ttl);

void tgl_do_discard_secret_chat(const std::shared_ptr<tgl_secret_chat>& secret_chat,
        const std::function<void(bool success, const std::shared_ptr<tgl_secret_chat>&)>& callback);

// returns secret chat fingerprint
//int tgl_do_visualize_key (int id, unsigned char buf[16]);

// requests creation of secret chat with user id
void tgl_do_create_secret_chat(const tgl_peer_id_t& user_id,
        const std::function<void(bool success, const std::shared_ptr<tgl_secret_chat>& E)>& callback);
/* }}} */

/* {{{ WORKING WITH DIALOG LIST */

// receives all dialogs (except secret chats) from offset=*offset* with limit=*limit*
// dialogs are sorted by last message received
// if limit is > 100 there is a (small) chance of one dialog received twice
void tgl_do_get_dialog_list(int limit, int offset,
        const std::function<void(bool success,
                const std::vector<tgl_peer_id_t>& peers,
                const std::vector<tgl_message_id_t>& last_msg_ids,
                const std::vector<int>& unread_count)>& callback);

// resolves username
void tgl_do_contact_resolve_username(const std::string& name, std::function<void(bool success)> callback);

// requests contact list
void tgl_do_update_contact_list ();

/* }}} */

/* {{{ WORKING WITH ONE DIALOG */

// requests last *limit* from offset *offset* (offset = 0 means most recent) messages from dialog with peer id
// if offline_mode=1 then no actual query is sent
// only locally cached messages returned
// also marks messages from this chat as read
void tgl_do_get_history (tgl_peer_id_t id, int offset, int limit, std::function<void(bool success, int size, const std::vector<std::shared_ptr<tgl_message>>& list)> callback);

// sends typing event to chat
// set status=tgl_typing_typing for default typing event
void tgl_do_send_typing (tgl_peer_id_t id, enum tgl_typing_status status, std::function<void(bool success)> callback);

/* }}} */


/* {{{ ANOTHER MESSAGES FUNCTIONS */
// search messages with ids *from* .. *to* in dialog id
// id type of id is UNKNOWN uses global search (in all dialogs) instead
// if *from* or *to* is means *from*=0 and *to*=+INF
// return up to *limit* entries from offset=*offset*
void tgl_do_msg_search(const tgl_peer_id_t& id, int from, int to, int limit, int offset, const std::string& query,
        const std::function<void(bool success, const std::vector<std::shared_ptr<tgl_message>>& messages)>& callback);

// deletes message *id*
void tgl_do_delete_msg (long long msg_id, std::function<void(bool success)> callback);

// gets message by *id*
void tgl_do_get_message (long long id, std::function<void(bool success, const std::shared_ptr<tgl_message>& M)> callback);

/* }}} */

/* {{{ EXTENDED QUERIES USE WITH CAUTION */
// sends query with extended text syntax
// use only for debug or when you known what are you doing
// since answer is not interpretated by library in any way
//void tgl_do_send_extf (const char *data, int data_len, std::function<void(bool success, const char *data)> callback);
//int tglf_extf_autocomplete (const char *text, int text_len, int index, char **R, char *data, int data_len);
//struct paramed_type *tglf_extf_store (const char *data, int data_len);
//char *tglf_extf_fetch (struct paramed_type *T);
/* }}} */

/* {{{ BOT */
void tgl_do_start_bot (tgl_peer_id_t bot, tgl_peer_id_t chat, const char *str, int str_len, std::function<void(bool success)> callback);
/* }}} */

#endif
