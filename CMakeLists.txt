#
#    Copyright Topology LP 2016
#

cmake_minimum_required(VERSION 3.0.0)

project(tplgy_tgl)

set(TPLGY_TGL_LIBVERSION 0.1.0)

find_package(Boost REQUIRED COMPONENTS filesystem system)
find_package(OpenSSL REQUIRED)
find_package(ZLIB REQUIRED)

include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_BINARY_DIR}
    ${Boost_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIR}
    ${ZLIB_INCLUDE_DIRS}
)

option(ENABLE_ASAN "ASAN build" OFF)
option(ENABLE_TSAN "TSAN build" OFF)
option(ENABLE_UBSAN "UBSAN build" OFF)
option(ENABLE_VALGRIND_FIXES "Workaround Valgrind bugs" OFF)

if(NOT MSVC)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14 -Wall -Werror -Wno-deprecated-declarations -Wno-error=unused-variable")
endif()

add_definitions(-D_FILE_OFFSET_BITS=64)

if (ENABLE_VALGRIND_FIXES)
    add_definitions(-DVALGRIND_FIXES)
endif()

if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-error=strict-aliasing -fdiagnostics-color=always")
endif()

if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    if("${CMAKE_GENERATOR}" STREQUAL "Ninja")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fcolor-diagnostics")
    endif()
    if(ENABLE_ASAN)
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address")
        set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -fsanitize=address")
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=address")
    endif()
    if(ENABLE_TSAN)
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=thread")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=thread")
        set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -fsanitize=thread")
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=thread")
    endif()
    if(ENABLE_UBSAN)
        if(APPLE)
            set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=undefined-trap -fsanitize-undefined-trap-on-error")
            set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=undefined-trap -fsanitize-undefined-trap-on-error")
            set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -fsanitize=undefined-trap -fsanitize-undefined-trap-on-error")
            set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=undefined-trap -fsanitize-undefined-trap-on-error")
        else()
            set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=undefined")
            set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=undefined")
            set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -fsanitize=undefined")
            set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=undefined")
        endif()
    endif()
endif()

set(GENERATED_TGL_HEADERS
    ${CMAKE_BINARY_DIR}/auto/auto-fetch-ds.h
    ${CMAKE_BINARY_DIR}/auto/auto-free-ds.h
    ${CMAKE_BINARY_DIR}/auto/auto-skip.h
    ${CMAKE_BINARY_DIR}/auto/auto-types.h
    ${CMAKE_BINARY_DIR}/auto/constants.h
)

set(PUBLIC_HEADERS
    include/tgl/tgl.h
    include/tgl/tgl_bot.h
    include/tgl/tgl_channel.h
    include/tgl/tgl_chat.h
    include/tgl/tgl_connection_status.h
    include/tgl/tgl_dc.h
    include/tgl/tgl_file_location.h
    include/tgl/tgl_log.h
    include/tgl/tgl_message.h
    include/tgl/tgl_message_action.h
    include/tgl/tgl_message_entity.h
    include/tgl/tgl_message_media.h
    include/tgl/tgl_mime_type.h
    include/tgl/tgl_mtproto_client.h
    include/tgl/tgl_net.h
    include/tgl/tgl_online_status.h
    include/tgl/tgl_online_status_observer.h
    include/tgl/tgl_peer_id.h
    include/tgl/tgl_privacy_rule.h
    include/tgl/tgl_queries.h
    include/tgl/tgl_secret_chat.h
    include/tgl/tgl_secure_random.h
    include/tgl/tgl_timer.h
    include/tgl/tgl_transfer_manager.h
    include/tgl/tgl_typing_status.h
    include/tgl/tgl_update_callback.h
    include/tgl/tgl_unconfirmed_secret_message.h
    include/tgl/tgl_unconfirmed_secret_message_storage.h
    include/tgl/tgl_user.h
    include/tgl/tgl_value.h
)

set(PRIVATE_HEADERS
    ${GENERATED_TGL_HEADERS}
    src/auto/auto.h
    src/crypto/tgl_crypto_aes.h
    src/crypto/tgl_crypto_bn.h
    src/crypto/tgl_crypto_err.h
    src/crypto/tgl_crypto_md5.h
    src/crypto/tgl_crypto_rsa_pem.h
    src/crypto/tgl_crypto_sha.h
    src/crypto/tgl_crypto_rand.h
    src/download_task.h
    src/mtproto_client.h
    src/mtproto-common.h
    src/mtproto-utils.h
    src/query/queries.h
    src/query/query.h
    src/query/query_create_chat.h
    src/query/query_download_file_part.h
    src/query/query_export_auth.h
    src/query/query_help_get_config.h
    src/query/query_import_auth.h
    src/query/query_mark_read_encr.h
    src/query/query_messages_accept_encryption.h
    src/query/query_messages_discard_encryption.h
    src/query/query_messages_get_dh_config.h
    src/query/query_messages_request_encryption.h
    src/query/query_messages_send_encrypted_action.h
    src/query/query_messages_send_encrypted_base.h
    src/query/query_messages_send_encrypted_file.h
    src/query/query_messages_send_encrypted_message.h
    src/query/query_upload_file_part.h
    src/query/query_user_info.h
    src/secret_chat_encryptor.h
    src/structures.h
    src/tgl_rsa_key.h
    src/tgl_secret_chat_private.h
    src/tgl_session.h
    src/tools.h
    src/transfer_manager.h
    src/unconfirmed_secret_message.h
    src/updates.h
    src/upload_task.h
)

set(GENERATED_TGL_SOURCES
    ${CMAKE_BINARY_DIR}/auto/auto-fetch-ds.cpp
    ${CMAKE_BINARY_DIR}/auto/auto-free-ds.cpp
    ${CMAKE_BINARY_DIR}/auto/auto-skip.cpp
    ${CMAKE_BINARY_DIR}/auto/auto-types.cpp
)

set(SOURCES
    ${GENERATED_TGL_SOURCES}
    src/mtproto_client.cpp
    src/mtproto-common.cpp
    src/mtproto-utils.cpp
    src/download_task.cpp
    src/query/queries.cpp
    src/query/query.cpp
    src/query/query_create_chat.cpp
    src/query/query_download_file_part.cpp
    src/query/query_help_get_config.cpp
    src/query/query_messages_accept_encryption.cpp
    src/query/query_messages_get_dh_config.cpp
    src/query/query_messages_request_encryption.cpp
    src/query/query_messages_send_encrypted_action.cpp
    src/query/query_messages_send_encrypted_base.cpp
    src/query/query_messages_send_encrypted_file.cpp
    src/query/query_messages_send_encrypted_message.cpp
    src/query/query_upload_file_part.cpp
    src/secret_chat_encryptor.cpp
    src/structures.cpp
    src/tgl.cpp
    src/tgl_log.cpp
    src/tgl_mime_type.cpp
    src/tgl_message.cpp
    src/tgl_secret_chat.cpp
    src/tgl_session.cpp
    src/transfer_manager.cpp
    src/tools.cpp
    src/unconfirmed_secret_message.cpp
    src/updates.cpp
    src/upload_task.cpp
)

add_library(${PROJECT_NAME} SHARED ${SOURCES} ${PUBLIC_HEADERS} ${PRIVATE_HEADERS})

target_link_libraries(${PROJECT_NAME}
    ${Boost_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    ${ZLIB_LIBRARIES}
)

set(GENERATE_DEPENDS
    generator/generate.c
    generator/generate.h
    generator/tree.h
    scripts/generate.py
    scripts/build_lib.py
    src/auto/append.tl
    src/auto/encrypted_scheme.tl
    src/auto/mtproto.tl
    src/auto/scheme.tl
    src/auto/mime.types
)

add_custom_command(
    OUTPUT ${GENERATED_TGL_HEADERS} ${GENERATED_TGL_SOURCES}
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    DEPENDS ${GENERATE_DEPENDS}
    COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/scripts/generate.py ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_BINARY_DIR}
)

install(FILES ${PUBLIC_HEADERS} DESTINATION include/tgl)
install(TARGETS tplgy_tgl DESTINATION lib)
