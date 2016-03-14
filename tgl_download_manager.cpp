#include "tgl_download_manager.h"
#include "queries.h"

bool tgl_download_manager::download_file(file_download new_download)
{
    tgl_do_load_file_location(&new_download.location, 0, 0);
    return true;
}
