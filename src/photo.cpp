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

#include "photo.h"

#include "auto/auto.h"
#include "auto/constants.h"
#include "auto/auto-types.h"
#include "file_location.h"

namespace tgl {
namespace impl {

std::shared_ptr<tgl_photo_size> create_photo_size(const tl_ds_photo_size* DS_PS)
{
    auto photo_size = std::make_shared<tgl_photo_size>();

    photo_size->type = DS_STDSTR(DS_PS->type);
    photo_size->width = DS_LVAL(DS_PS->w);
    photo_size->height = DS_LVAL(DS_PS->h);
    photo_size->size = DS_LVAL(DS_PS->size);
    if (DS_PS->bytes) {
        photo_size->size = DS_PS->bytes->len;
    }

    photo_size->loc = create_file_location(DS_PS->location);

    return photo_size;
}

std::shared_ptr<tgl_photo> create_photo(const tl_ds_photo* DS_P)
{
    if (!DS_P) {
        return nullptr;
    }

    if (DS_P->magic == CODE_photo_empty) {
        return nullptr;
    }

    auto photo = std::make_shared<tgl_photo>();
    photo->id = DS_LVAL(DS_P->id);

    photo->access_hash = DS_LVAL(DS_P->access_hash);
    photo->date = DS_LVAL(DS_P->date);

    int sizes_num = DS_LVAL(DS_P->sizes->cnt);
    photo->sizes.resize(sizes_num);
    for (int i = 0; i < sizes_num; ++i) {
        photo->sizes[i] = create_photo_size(DS_P->sizes->data[i]);
    }

    return photo;
}

}
}

