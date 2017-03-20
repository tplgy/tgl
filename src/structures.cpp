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

#include "structures.h"

#include "auto/auto.h"
#include "auto/auto-skip.h"
#include "auto/auto-types.h"
#include "auto/auto-free-ds.h"
#include "auto/auto-fetch-ds.h"
#include "chat.h"
#include "channel.h"
#include "crypto/tgl_crypto_aes.h"
#include "crypto/tgl_crypto_bn.h"
#include "crypto/tgl_crypto_sha.h"
#include "document.h"
#include "file_location.h"
#include "photo.h"
#include "mtproto_client.h"
#include "mtproto-common.h"
#include "tgl/tgl_bot.h"
#include "tgl/tgl_update_callback.h"
#include "tgl/tgl_user.h"
#include "updater.h"
#include "user.h"
#include "user_agent.h"

#include <algorithm>
#include <assert.h>
#include <ctype.h>
#include <string.h>
#include <strings.h>

namespace tgl {
namespace impl {

std::shared_ptr<tgl_photo> tglf_fetch_alloc_photo(const tl_ds_photo* DS_P)
{
    if (!DS_P) {
        return nullptr;
    }

    if (DS_P->magic == CODE_photo_empty) {
        return nullptr;
    }

    auto photo = std::make_shared<tgl_photo>();
    photo->id = DS_LVAL(DS_P->id);
    //photo->refcnt = 1;

    photo->access_hash = DS_LVAL(DS_P->access_hash);
    //photo->user_id = DS_LVAL(DS_P->user_id);
    photo->date = DS_LVAL(DS_P->date);
    //photo->caption = NULL;//DS_STR_DUP(DS_P->caption);
    /*if (DS_P->geo) {
      tglf_fetch_geo(&P->geo, DS_P->geo);
    }*/

    int sizes_num = DS_LVAL(DS_P->sizes->cnt);
    photo->sizes.resize(sizes_num);
    for (int i = 0; i < sizes_num; ++i) {
        photo->sizes[i] = create_photo_size(DS_P->sizes->data[i]);
    }

    return photo;
}

std::shared_ptr<tgl_webpage> tglf_fetch_alloc_webpage(const tl_ds_web_page* DS_W)
{
    if (!DS_W) {
        return nullptr;
    }

    auto webpage = std::make_shared<tgl_webpage>();
    webpage->id = DS_LVAL(DS_W->id);
    //webpage->refcnt = 1;

    webpage->url = DS_STDSTR(DS_W->url);
    webpage->display_url = DS_STDSTR(DS_W->display_url);
    webpage->type = DS_STDSTR(DS_W->type);
    webpage->title = DS_W->title ? DS_STDSTR(DS_W->title) : (DS_W->site_name ? DS_STDSTR(DS_W->site_name) : "");
    webpage->photo = tglf_fetch_alloc_photo(DS_W->photo);
    webpage->description = DS_STDSTR(DS_W->description);
    webpage->embed_url = DS_STDSTR(DS_W->embed_url);
    webpage->embed_type = DS_STDSTR(DS_W->embed_type);
    webpage->embed_width = DS_LVAL(DS_W->embed_width);
    webpage->embed_height = DS_LVAL(DS_W->embed_height);
    webpage->duration = DS_LVAL(DS_W->duration);
    webpage->author = DS_STDSTR(DS_W->author);

    return webpage;
}

}
}
