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
    ${CMAKE_BINARY_DIR}/auto/auto_fetch_ds.h
    ${CMAKE_BINARY_DIR}/auto/auto_free_ds.h
    ${CMAKE_BINARY_DIR}/auto/auto_skip.h
    ${CMAKE_BINARY_DIR}/auto/auto_types.h
    ${CMAKE_BINARY_DIR}/auto/constants.h
)

set(PUBLIC_HEADERS
    include/tgl/tgl_bot.h
    include/tgl/tgl_channel.h
    include/tgl/tgl_chat.h
    include/tgl/tgl_connection_status.h
    include/tgl/tgl_dc.h
    include/tgl/tgl_document.h
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
    include/tgl/tgl_photo.h
    include/tgl/tgl_privacy_rule.h
    include/tgl/tgl_query_api.h
    include/tgl/tgl_secret_chat.h
    include/tgl/tgl_secure_random.h
    include/tgl/tgl_timer.h
    include/tgl/tgl_transfer_manager.h
    include/tgl/tgl_typing_status.h
    include/tgl/tgl_update_callback.h
    include/tgl/tgl_unconfirmed_secret_message.h
    include/tgl/tgl_unconfirmed_secret_message_storage.h
    include/tgl/tgl_user.h
    include/tgl/tgl_user_agent.h
    include/tgl/tgl_value.h
    include/tgl/tgl_webpage.h
)

set(PUBLIC_IMPL_HEADERS
    include/tgl/impl/tgl_net_base.h
)

set(PRIVATE_HEADERS
    ${GENERATED_TGL_HEADERS}
    src/auto/auto.h
    src/bot_info.h
    src/channel.h
    src/chat.h
    src/crypto/crypto_aes.h
    src/crypto/crypto_bn.h
    src/crypto/crypto_err.h
    src/crypto/crypto_md5.h
    src/crypto/crypto_rsa_pem.h
    src/crypto/crypto_sha.h
    src/crypto/crypto_rand.h
    src/document.h
    src/download_task.h
    src/file_location.h
    src/message.h
    src/mtproto_client.h
    src/mtproto_common.h
    src/mtproto_utils.h
    src/peer_id.h
    src/photo.h
    src/query/query.h
    src/query/query_add_contacts.h
    src/query/query_block_or_unblock_user.h
    src/query/query_bind_temp_auth_key.h
    src/query/query_channel_get_participant.h
    src/query/query_channels_get_participants.h
    src/query/query_channels_set_about.h
    src/query/query_check_password.h
    src/query/query_check_username.h
    src/query/query_create_chat.h
    src/query/query_delete_contact.h
    src/query/query_delete_message.h
    src/query/query_download_file_part.h
    src/query/query_export_auth.h
    src/query/query_export_card.h
    src/query/query_export_chat_link.h
    src/query/query_get_and_check_password.h
    src/query/query_get_and_set_password.h
    src/query/query_get_blocked_users.h
    src/query/query_get_channel_difference.h
    src/query/query_get_channel_info.h
    src/query/query_get_chat_info.h
    src/query/query_get_contacts.h
    src/query/query_get_dialogs.h
    src/query/query_get_difference.h
    src/query/query_get_history.h
    src/query/query_get_messages.h
    src/query/query_get_notify_settings.h
    src/query/query_get_privacy_rules.h
    src/query/query_get_state.h
    src/query/query_get_tos.h
    src/query/query_help_get_config.h
    src/query/query_import_auth.h
    src/query/query_import_card.h
    src/query/query_logout.h
    src/query/query_lookup_state.h
    src/query/query_mark_message_read.h
    src/query/query_mark_read_encr.h
    src/query/query_messages_accept_encryption.h
    src/query/query_messages_discard_encryption.h
    src/query/query_messages_get_dh_config.h
    src/query/query_messages_request_encryption.h
    src/query/query_messages_send_encrypted_action.h
    src/query/query_messages_send_encrypted_base.h
    src/query/query_messages_send_encrypted_file.h
    src/query/query_messages_send_encrypted_message.h
    src/query/query_msg_send.h
    src/query/query_phone_call.h
    src/query/query_register_device.h
    src/query/query_resolve_username.h
    src/query/query_search_contact.h
    src/query/query_search_message.h
    src/query/query_send_change_code.h
    src/query/query_send_code.h
    src/query/query_send_inline_query_to_bot.h
    src/query/query_send_messages.h
    src/query/query_send_typing.h
    src/query/query_set_phone.h
    src/query/query_set_profile_name.h
    src/query/query_sign_in.h
    src/query/query_unregister_device.h
    src/query/query_update_notify_settings.h
    src/query/query_update_password_settings.h
    src/query/query_update_status.h
    src/query/query_upload_file_part.h
    src/query/query_user_info.h
    src/rsa_public_key.h
    src/secret_chat.h
    src/secret_chat_encryptor.h
    src/session.h
    src/tools.h
    src/transfer_manager.h
    src/typing_status.h
    src/unconfirmed_secret_message.h
    src/updater.h
    src/upload_task.h
    src/user.h
    src/user_agent.h
    src/webpage.h
)

set(GENERATED_TGL_SOURCES
    ${CMAKE_BINARY_DIR}/auto/auto_fetch_ds.cpp
    ${CMAKE_BINARY_DIR}/auto/auto_free_ds.cpp
    ${CMAKE_BINARY_DIR}/auto/auto_skip.cpp
    ${CMAKE_BINARY_DIR}/auto/auto_types.cpp
)

set(SOURCES
    ${GENERATED_TGL_SOURCES}
    src/bot_info.cpp
    src/channel.cpp
    src/chat.cpp
    src/document.cpp
    src/download_task.cpp
    src/file_location.cpp
    src/log.cpp
    src/message.cpp
    src/mime_type.cpp
    src/mtproto_client.cpp
    src/mtproto_common.cpp
    src/mtproto_utils.cpp
    src/net/tgl_net_base.cpp
    src/peer_id.cpp
    src/photo.cpp
    src/query/query.cpp
    src/query/query_channel_get_participant.cpp
    src/query/query_channels_get_participants.cpp
    src/query/query_create_chat.cpp
    src/query/query_download_file_part.cpp
    src/query/query_get_and_check_password.cpp
    src/query/query_get_and_set_password.cpp
    src/query/query_get_blocked_users.cpp
    src/query/query_get_channel_difference.cpp
    src/query/query_get_channel_info.cpp
    src/query/query_get_chat_info.cpp
    src/query/query_get_dialogs.cpp
    src/query/query_get_difference.cpp
    src/query/query_get_history.cpp
    src/query/query_get_messages.cpp
    src/query/query_get_privacy_rules.cpp
    src/query/query_get_tos.cpp
    src/query/query_help_get_config.cpp
    src/query/query_messages_accept_encryption.cpp
    src/query/query_messages_get_dh_config.cpp
    src/query/query_messages_request_encryption.cpp
    src/query/query_messages_send_encrypted_action.cpp
    src/query/query_messages_send_encrypted_base.cpp
    src/query/query_messages_send_encrypted_file.cpp
    src/query/query_messages_send_encrypted_message.cpp
    src/query/query_search_message.cpp
    src/query/query_send_change_code.cpp
    src/query/query_send_inline_query_to_bot.cpp
    src/query/query_send_messages.cpp
    src/query/query_sign_in.cpp
    src/query/query_unregister_device.cpp
    src/query/query_upload_file_part.cpp
    src/secret_chat.cpp
    src/secret_chat_encryptor.cpp
    src/session.cpp
    src/tools.cpp
    src/transfer_manager.cpp
    src/typing_status.cpp
    src/unconfirmed_secret_message.cpp
    src/updater.cpp
    src/upload_task.cpp
    src/user.cpp
    src/user_agent.cpp
    src/webpage.cpp
)

add_library(${PROJECT_NAME} SHARED ${SOURCES} ${PUBLIC_HEADERS} ${PUBLIC_IMPL_HEADERS} ${PRIVATE_HEADERS})

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
install(FILES ${PUBLIC_IMPL_HEADERS} DESTINATION include/tgl/impl)
install(TARGETS tplgy_tgl DESTINATION lib)
