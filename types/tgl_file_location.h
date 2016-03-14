#ifndef TGL_FILE_LOCATION
#define TGL_FILE_LOCATION

struct tgl_file_location {
  int dc;
  long long volume;
  int local_id;
  long long secret;
};

#endif // TGL_FILE_LOCATION

