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

    Copyright Vitaly Valtman 2014-2015
    Copyright Topology LP 2016-2017
*/

#ifndef __TGL_DOWNLOAD_TASDK_H__
#define __TGL_DOWNLOAD_TASDK_H__

#include "tgl/tgl_file_location.h"
#include "tgl/tgl_transfer_manager.h"

#include <cstdint>
#include <cstring>
#include <fstream>
#include <map>
#include <memory>
#include <string>
#include <unordered_set>
#include <vector>

class download_data {
public:
    download_data()
        : m_ref_data(nullptr)
        , m_length(0)
    { }

    download_data(char* data, size_t length, bool own_data)
        : m_length(length)
    {
        if (own_data) {
            m_ref_data = nullptr;
            m_owning_data.reset(new char[length]);
            memcpy(m_owning_data.get(), data, length);
        } else {
            m_ref_data = data;
        }
    }

    char* data() const { return m_owning_data ? m_owning_data.get() : m_ref_data; }
    size_t length() const { return m_length; }
    operator bool() const { return !!data() && !!length(); }

private:
    char* m_ref_data;
    std::unique_ptr<char[]> m_owning_data;
    size_t m_length;
};

class download_task {
public:
    int64_t id;
    int32_t offset;
    int32_t downloaded_bytes;
    int32_t size;
    int32_t type;
    std::unique_ptr<std::ofstream> file_stream;
    tgl_file_location location;
    std::string file_name;
    std::string ext;
    tgl_download_status status;
    tgl_download_callback callback;
    std::map<size_t, download_data> running_parts;
    //encrypted documents
    std::vector<unsigned char> iv;
    std::vector<unsigned char> key;
    int32_t decryption_offset;
    bool valid;
    // ---

    download_task(int64_t id, int32_t size, const tgl_file_location& location);
    download_task(int64_t id, const std::shared_ptr<tgl_document>& document);
    ~download_task();
    void set_status(tgl_download_status status);
    void request_cancel() { m_cancel_requested = true; }
    bool check_cancelled();

private:
    void init_from_document(const std::shared_ptr<tgl_document>& document);

private:
    bool m_cancel_requested;
};

#endif
