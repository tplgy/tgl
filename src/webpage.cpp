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

#include "webpage.h"

#include "auto/auto.h"
#include "auto/auto-types.h"
#include "auto/constants.h"
#include "photo.h"

namespace tgl {
namespace impl {

std::shared_ptr<webpage> webpage::create(const tl_ds_web_page* DS_W)
{
    if (!DS_W) {
        return nullptr;
    }

    std::shared_ptr<webpage> w(new webpage());

    w->m_id = DS_LVAL(DS_W->id);
    w->m_url = DS_STDSTR(DS_W->url);
    w->m_display_url = DS_STDSTR(DS_W->display_url);
    w->m_type = DS_STDSTR(DS_W->type);
    w->m_title = DS_W->title ? DS_STDSTR(DS_W->title) : DS_STDSTR(DS_W->site_name);
    w->m_photo = create_photo(DS_W->photo);
    w->m_description = DS_STDSTR(DS_W->description);
    w->m_embed_url = DS_STDSTR(DS_W->embed_url);
    w->m_embed_type = DS_STDSTR(DS_W->embed_type);
    w->m_embed_width = DS_LVAL(DS_W->embed_width);
    w->m_embed_height = DS_LVAL(DS_W->embed_height);
    w->m_duration = DS_LVAL(DS_W->duration);
    w->m_author = DS_STDSTR(DS_W->author);

    return w;
}

webpage::webpage()
    : m_id(0)
    , m_embed_width(0)
    , m_embed_height(0)
    , m_duration(0)
{
}

}
}
