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

#include "tgl/tgl_mime_type.h"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <map>

#include "auto/tgl_mime_data.cpp"

static const std::string s_default_mime_type("application/octet-stream");

std::string tgl_extension_by_mime_type(const std::string& mime_type)
{
    std::string mime(mime_type.size(), 0);
    std::transform(mime_type.begin(), mime_type.end(), mime.begin(), ::tolower);
    auto it = s_mime_to_extension.find(mime.c_str());
    if (it != s_mime_to_extension.end()) {
        return it->second;
    }
    return std::string();
}

std::string tgl_mime_type_by_filename(const std::string& filename)
{
    auto dot_pos = filename.rfind('.');
    if (dot_pos == std::string::npos || dot_pos == filename.size() - 1) {
       return s_default_mime_type;
    }
    return tgl_mime_type_by_extension(filename.substr(dot_pos + 1));
}

std::string tgl_mime_type_by_extension(const std::string& extension)
{
    std::string ext(extension.size(), 0);
    std::transform(extension.begin(), extension.end(), ext.begin(), ::tolower);

    auto it = s_extension_to_mime.find(ext.c_str());
    if (it != s_extension_to_mime.end()) {
        return it->second;
    }

    return s_default_mime_type;
}
