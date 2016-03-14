#ifndef TGL_DOWNLOAD_MANAGER_H
#define TGL_DOWNLOAD_MANAGER_H

#include <vector>
#include <string>
#include "types/tgl_file_location.h"

struct file_download {
    std::string path;
    tgl_file_location location;
};

class tgl_download_manager
{
public:
    bool download_file(file_download new_download);

private:
    std::vector<file_download> m_queued_downloads;
};

#endif // TGL_DOWNLOAD_MANAGER_H
