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

#include "query_get_privacy_rules.h"

namespace tgl {
namespace impl {

query_get_privacy_rules::query_get_privacy_rules(const std::function<void(bool, const std::vector<std::pair<tgl_privacy_rule, const std::vector<int32_t>>>&)>& callback)
    : query("set phone", TYPE_TO_PARAM(account_privacy_rules))
    , m_callback(callback)
{ }

void query_get_privacy_rules::on_answer(void* D)
{
    tl_ds_account_privacy_rules* rules = static_cast<tl_ds_account_privacy_rules*>(D);
    std::vector<std::pair<tgl_privacy_rule, const std::vector<int32_t>>> privacy_rules;
    if (rules->rules) {
        for (int32_t i=0; i<DS_LVAL(rules->rules->cnt); ++i) {
            uint32_t rule = rules->rules->data[i]->magic;
            std::vector<int32_t> users;
            tgl_privacy_rule tgl_rule;
            switch (rule) {
            case(CODE_privacy_value_allow_contacts): tgl_rule = tgl_privacy_rule::allow_contacts; break;
            case(CODE_privacy_value_allow_all): tgl_rule = tgl_privacy_rule::allow_all; break;
            case(CODE_privacy_value_allow_users): {
                tgl_rule = tgl_privacy_rule::allow_users;
                if (rules->rules->data[i]->users) {
                    for (int32_t j=0; j<DS_LVAL(rules->rules->data[i]->users->cnt); ++j) {
                        users.push_back(DS_LVAL(rules->rules->data[i]->users->data[j]));
                    }
                }
                break;
            }
            case(CODE_privacy_value_disallow_contacts): tgl_rule = tgl_privacy_rule::disallow_contacts; break;
            case(CODE_privacy_value_disallow_all): tgl_rule = tgl_privacy_rule::disallow_all; break;
            case(CODE_privacy_value_disallow_users): {
                tgl_rule = tgl_privacy_rule::disallow_users;
                if (rules->rules->data[i]->users) {
                    for (int32_t j=0; j<DS_LVAL(rules->rules->data[i]->users->cnt); ++j) {
                        users.push_back(DS_LVAL(rules->rules->data[i]->users->data[j]));
                    }
                }
                break;
            }
            default:    tgl_rule = tgl_privacy_rule::unknown;
            }

            privacy_rules.push_back(std::make_pair(tgl_rule, users));
        }
    }
    if (m_callback) {
        m_callback(true, privacy_rules);
    }
}

int query_get_privacy_rules::on_error(int error_code, const std::string& error_string)
{
    TGL_ERROR("RPC_CALL_FAIL " << error_code << " " << error_string);
    if (m_callback) {
        m_callback(false, {});
    }
    return 0;
}

}
}
