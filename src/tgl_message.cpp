#include "tgl/tgl_message.h"
#include "tgl/tgl_secret_chat.h"
#include "structures.h"
#include "tgl/tgl_log.h"
#include "tgl_secret_chat_private.h"
#include "tgl_secret_chat_private.h"

tgl_message::tgl_message()
    : server_id(0)
    , random_id(0)
    , fwd_date(0)
    , date(0)
    , permanent_id(0)
    , reply_id(0)
    , seq_no(0)
    , fwd_from_id()
    , from_id()
    , to_id()
    , action(std::make_shared<tgl_message_action_none>())
    , media(std::make_shared<tgl_message_media_none>())
    , m_flags()
{ }

tgl_message::tgl_message(int64_t message_id,
        const tgl_peer_id_t& from_id,
        const tgl_input_peer_t& to_id,
        const tgl_peer_id_t* fwd_from_id,
        const int64_t* fwd_date,
        const int64_t* date,
        const std::string& message,
        const tl_ds_message_media* media,
        const tl_ds_message_action* action,
        int32_t reply_id,
        const tl_ds_reply_markup* reply_markup)
    : tgl_message()
{
    this->permanent_id = message_id;
    this->seq_no = message_id;
    this->from_id = from_id;
    this->to_id = to_id;
    assert(to_id.peer_type != tgl_peer_type::enc_chat);

    if (date) {
        this->date = *date;
    }

    if (fwd_from_id) {
        this->fwd_from_id = *fwd_from_id;
        this->fwd_date = *fwd_date;
    }

    if (action) {
        this->action = tglf_fetch_message_action(action);
        this->set_service(true);
    }

    this->message = message;

    if (media) {
        this->media = tglf_fetch_message_media(media);
        assert(!this->is_service());
    }

    this->reply_id = reply_id;

    if (reply_markup) {
        this->reply_markup = tglf_fetch_alloc_reply_markup(reply_markup);
    }
}

tgl_message::tgl_message(
        const std::shared_ptr<tgl_secret_chat>& secret_chat,
        int64_t message_id,
        const tgl_peer_id_t& from_id,
        const int64_t* date,
        const std::string& message,
        const tl_ds_decrypted_message_media* media,
        const tl_ds_decrypted_message_action* action,
        const tl_ds_encrypted_file* file)
    : tgl_message()
{
    this->permanent_id = message_id;
    this->from_id = from_id;
    this->to_id = secret_chat->id();

    if (date) {
        this->date = *date;
    }

    assert(secret_chat);

    if (action) {
        this->action = tglf_fetch_message_action_encrypted(action);
        this->set_service(true);
    }

    this->message = message;

    if (media) {
        this->media = tglf_fetch_message_media_encrypted(media);
        assert(!this->is_service());
    }

    if (file) {
        tglf_fetch_encrypted_message_file(this->media, file);
    }

    this->set_outgoing(from_id.peer_id == tgl_state::instance()->our_id().peer_id);

    if (action && !this->is_outgoing() && this->action && this->action->type() == tgl_message_action_type::notify_layer) {
        // FIXME is following right?
        secret_chat->private_facet()->update_layer(std::static_pointer_cast<tgl_message_action_notify_layer>(this->action)->layer);
    }

    if (this->is_outgoing()) {
        //secret_chat->out_seq_no++;
        secret_chat->private_facet()->message_sent(message_id);
        TGL_DEBUG("out seq number " << secret_chat->out_seq_no());
    }
}
