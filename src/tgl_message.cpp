#include "tgl/tgl_message.h"

#include "auto/constants.h"
#include "structures.h"
#include "tgl/tgl_log.h"
#include "tgl/tgl_secret_chat.h"
#include "tgl_secret_chat_private.h"

using namespace tgl::impl;

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
    this->from_id = from_id;
    this->to_id = to_id;

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

tgl_message::tgl_message(const std::shared_ptr<tgl_secret_chat>& secret_chat,
        int64_t message_id,
        const tgl_peer_id_t& from_id,
        const int64_t* date,
        const std::string& message,
        const tl_ds_decrypted_message_media* media,
        const tl_ds_decrypted_message_action* action,
        const tl_ds_encrypted_file* file)
    : tgl_message(message_id, from_id, secret_chat->id(), nullptr, nullptr, date, message, nullptr, nullptr, 0, nullptr)
{
    if (action) {
        if (action->magic == CODE_decrypted_message_action_opaque_message
                && !secret_chat->opaque_service_message_enabled()) {
            // ignore the action.
        } else {
            this->action = tglf_fetch_message_action_encrypted(action);
            this->set_service(true);
        }
    }

    if (media) {
        this->media = tglf_fetch_message_media_encrypted(media);
        assert(!this->is_service());
    }

    if (file) {
        tglf_fetch_encrypted_message_file(this->media, file);
    }

    this->set_outgoing(from_id.peer_id == secret_chat->private_facet()->our_id().peer_id);

    if (action && !this->is_outgoing() && this->action && this->action->type() == tgl_message_action_type::notify_layer) {
        // FIXME is following right?
        secret_chat->private_facet()->set_layer(std::static_pointer_cast<tgl_message_action_notify_layer>(this->action)->layer);
    }
}

void tgl_message::set_decrypted_message_media(const tl_ds_decrypted_message_media* media)
{
    if (media) {
        this->media = tglf_fetch_message_media_encrypted(media);
        assert(!is_service());
    } else {
        this->media = nullptr;
    }
}
