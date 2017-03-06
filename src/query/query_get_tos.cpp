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

#include "query_get_tos.h"

query_get_tos::query_get_tos(const std::function<void(bool, const std::string&)>& callback)
    : query("get tos", TYPE_TO_PARAM(help_terms_of_service))
    , m_callback(callback)
{ }

void query_get_tos::on_answer(void* D)
{
    tl_ds_help_terms_of_service* DS_T = static_cast<tl_ds_help_terms_of_service*>(D);

    if (!DS_T->text || !DS_T->text->data) {
        if (m_callback) {
            m_callback(true, std::string());
        }
        return;
    }

    int l = DS_T->text->len;
    std::vector<char> buffer(l + 1);
    char* s = buffer.data();
    char* str = DS_T->text->data;
    int p = 0;
    int pp = 0;
    while (p < l) {
        if (*str == '\\' && p < l - 1) {
            str ++;
            p ++;
            switch (*str) {
            case 'n':
                s[pp ++] = '\n';
                break;
            case 't':
                s[pp ++] = '\t';
                break;
            case 'r':
                s[pp ++] = '\r';
                break;
            default:
                s[pp ++] = *str;
            }
            str ++;
            p ++;
        } else {
            s[pp ++] = *str;
            str ++;
            p ++;
        }
    }
    s[pp] = 0;

    if (m_callback) {
        m_callback(true, std::string(s, pp));
    }
}

int query_get_tos::on_error(int error_code, const std::string& error_string)
{
    TGL_ERROR("RPC_CALL_FAIL " << error_code << " " << error_string);
    if (m_callback) {
        m_callback(false, std::string());
    }
    return 0;
}
