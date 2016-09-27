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
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_BINARY_DIR}
    ${Boost_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIR}
    ${ZLIB_INCLUDE_DIRS}
)

option(ENABLE_ASAN "ASAN build" OFF)
option(ENABLE_TSAN "TSAN build" OFF)
option(ENABLE_UBSAN "UBSAN build" OFF)
option(ENABLE_VALGRIND_FIXES "Workaround Valgrind bugs" OFF)

if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    set(CMAKE_CXX_FLAGS "-Wno-error=shorten-64-to-32 ${CMAKE_CXX_FLAGS}")
    if("${CMAKE_GENERATOR}" STREQUAL "Ninja")
        set(CMAKE_CXX_FLAGS "-fcolor-diagnostics ${CMAKE_CXX_FLAGS}")
    endif()
    if(ENABLE_ASAN)
        set(CMAKE_C_FLAGS "-fsanitize=address ${CMAKE_C_FLAGS}")
        set(CMAKE_CXX_FLAGS "-fsanitize=address ${CMAKE_CXX_FLAGS}")
        set(CMAKE_SHARED_LINKER_FLAGS "-fsanitize=address ${CMAKE_SHARED_LINKER_FLAGS}")
        set(CMAKE_EXE_LINKER_FLAGS "-fsanitize=address ${CMAKE_EXE_LINKER_FLAGS}")
    endif()
    if(ENABLE_TSAN)
        set(CMAKE_C_FLAGS "-fsanitize=thread ${CMAKE_C_FLAGS}")
        set(CMAKE_CXX_FLAGS "-fsanitize=thread ${CMAKE_CXX_FLAGS}")
        set(CMAKE_SHARED_LINKER_FLAGS "-fsanitize=thread ${CMAKE_SHARED_LINKER_FLAGS}")
        set(CMAKE_EXE_LINKER_FLAGS "-fsanitize=thread ${CMAKE_EXE_LINKER_FLAGS}")
    endif()
    if(ENABLE_UBSAN)
        if(APPLE)
            set(CMAKE_C_FLAGS "-fsanitize=undefined-trap -fsanitize-undefined-trap-on-error ${CMAKE_C_FLAGS}")
            set(CMAKE_CXX_FLAGS "-fsanitize=undefined-trap -fsanitize-undefined-trap-on-error ${CMAKE_CXX_FLAGS}")
            set(CMAKE_SHARED_LINKER_FLAGS "-fsanitize=undefined-trap -fsanitize-undefined-trap-on-error ${CMAKE_SHARED_LINKER_FLAGS}")
            set(CMAKE_EXE_LINKER_FLAGS "-fsanitize=undefined-trap -fsanitize-undefined-trap-on-error ${CMAKE_EXE_LINKER_FLAGS}")
        else()
            set(CMAKE_C_FLAGS "-fsanitize=undefined ${CMAKE_C_FLAGS}")
            set(CMAKE_CXX_FLAGS "-fsanitize=undefined ${CMAKE_CXX_FLAGS}")
            set(CMAKE_SHARED_LINKER_FLAGS "-fsanitize=undefined ${CMAKE_SHARED_LINKER_FLAGS}")
            set(CMAKE_EXE_LINKER_FLAGS "-fsanitize=undefined ${CMAKE_EXE_LINKER_FLAGS}")
        endif()
    endif()
endif()

if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
    set(CMAKE_CXX_FLAGS "-fdiagnostics-color=always -Wno-error=maybe-uninitialized -Wno-error=strict-aliasing ${CMAKE_CXX_FLAGS}")
endif()

if(NOT MSVC)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14 -Wall -Werror -Wno-deprecated-declarations -Wno-error=unused-variable")
endif()

# Workaround Android x86 link issue
if(ANDROID)
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,--no-warn-shared-textrel")
endif()

add_definitions(-D_FILE_OFFSET_BITS=64)

if (ENABLE_VALGRIND_FIXES)
    add_definitions(-DVALGRIND_FIXES)
endif()

set(GENERATED_TGL_HEADERS
    ${CMAKE_BINARY_DIR}/auto/auto-fetch-ds.h
    ${CMAKE_BINARY_DIR}/auto/auto-free-ds.h
    ${CMAKE_BINARY_DIR}/auto/auto-skip.h
    ${CMAKE_BINARY_DIR}/auto/auto-types.h
    ${CMAKE_BINARY_DIR}/auto/constants.h
)

set(AUTO_HEADERS
    ${GENERATED_TGL_HEADERS}
    auto/auto.h
)

set(TYPES_HEADERS
    types/tgl_file_location.h
    types/tgl_peer_id.h
    types/tgl_rsa_key.h
    types/tgl_update_callback.h
    types/tgl_message.h
    types/tgl_message_entity.h
    types/tgl_message_media.h
    types/tgl_message_action.h
    types/tgl_secret_chat.h
    types/tgl_typing_status.h
    types/tgl_online_status.h
    types/tgl_connection_status.h
    types/tgl_chat.h
    types/tgl_user.h
    types/tgl_bot.h
    types/tgl_online_status_observer.h
    types/tgl_channel.h
)

set(CRYPTO_HEADERS
    crypto/tgl_crypto_aes.h
    crypto/tgl_crypto_bn.h
    crypto/tgl_crypto_err.h
    crypto/tgl_crypto_md5.h
    crypto/tgl_crypto_rsa_pem.h
    crypto/tgl_crypto_sha.h
    crypto/tgl_crypto_rand.h
)

set(HEADERS
    mtproto-client.h
    mtproto-common.h
    mtproto-utils.h
    queries.h
    queries-encrypted.h
    structures.h
    tg-mime-types.h
    tgl.h
    tgl-dc.h
    tgl-log.h
    tgl-net.h
    tgl-net-asio.h
    tgl-queries.h
    tgl-timer.h
    tgl-timer-asio.h
    tgl_transfer_manager.h
    tools.h
    updates.h
)

set(GENERATED_TGL_SOURCES
    ${CMAKE_BINARY_DIR}/auto/auto-fetch-ds.cpp
    ${CMAKE_BINARY_DIR}/auto/auto-free-ds.cpp
    ${CMAKE_BINARY_DIR}/auto/auto-skip.cpp
    ${CMAKE_BINARY_DIR}/auto/auto-types.cpp
)

set(SOURCES
    ${GENERATED_TGL_SOURCES}
    mtproto-client.cpp
    mtproto-common.cpp
    mtproto-utils.cpp
    queries.cpp
    queries-encrypted.cpp
    structures.cpp
    tg-mime-types.cpp
    tgl.cpp
    tgl-dc.cpp
    tgl-log.cpp
    tgl-net-asio.cpp
    tgl_transfer_manager.cpp
    tools.cpp
    updates.cpp
)

add_library(${PROJECT_NAME} SHARED ${SOURCES} ${AUTO_HEADERS} ${CRYPTO_HEADERS} ${TYPES_HEADERS} ${HEADERS})

target_link_libraries(${PROJECT_NAME}
    ${Boost_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    ${ZLIB_LIBRARIES}
)

set(GENERATE_DEPENDS
    generate/generate.c
    generate/generate.h
    generate/tree.h
    scripts/generate.py
    scripts/build_lib.py
    auto/append.tl
    auto/encrypted_scheme.tl
    auto/mtproto.tl
    auto/scheme.tl
)

add_custom_command(
    OUTPUT ${GENERATED_TGL_HEADERS} ${GENERATED_TGL_SOURCES}
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    DEPENDS ${GENERATE_DEPENDS}
    COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/scripts/generate.py ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_BINARY_DIR}
)

install(FILES ${HEADERS} DESTINATION include/tgl)
install(FILES ${AUTO_HEADERS} DESTINATION include/tgl/auto)
install(FILES ${CRYPTO_HEADERS} DESTINATION include/tgl/crypto)
install(FILES ${TYPES_HEADERS} DESTINATION include/tgl/types)
install(TARGETS tplgy_tgl DESTINATION lib)
