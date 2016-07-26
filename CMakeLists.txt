#    This file is part of tgl-library
#
#    This library is free software; you can redistribute it and/or
#    modify it under the terms of the GNU Lesser General Public
#    License as published by the Free Software Foundation; either
#    version 2.1 of the License, or (at your option) any later version.
#
#    This library is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#    Lesser General Public License for more details.
#
#    You should have received a copy of the GNU Lesser General Public
#    License along with this library; if not, write to the Free Software
#    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
#
#    Copyright Topology LP 2016

cmake_minimum_required(VERSION 3.0.0)

project(tplgy_tgl)

set(TPLGY_TGL_LIBVERSION 0.1.0)

find_package(Boost REQUIRED COMPONENTS filesystem system)
find_package(OpenSSL REQUIRED)

include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_BINARY_DIR}
    ${CMAKE_BINARY_DIR}/auto
    ${Boost_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIR}
)

option(ENABLE_ASAN "ASAN build" OFF)
option(ENABLE_UBSAN "UBSAN build" OFF)

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
    set(CMAKE_CXX_FLAGS "-std=c++14 -Wall -Werror -Wno-deprecated-declarations -Wno-error=unused-variable ${CMAKE_CXX_FLAGS}")
endif()

if (APPLE)
    set(CMAKE_CXX_FLAGS "-fobjc-arc -fobjc-abi-version=2 ${CMAKE_CXX_FLAGS}")
elseif (ANDROID)
    set(CMAKE_CXX_FLAGS "-DTPLGY_USE_STRING_UTILS -Wno-sign-compare ${CMAKE_CXX_FLAGS}")
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
    crypto/aes.h
    crypto/bn.h
    crypto/err.h
    crypto/md5.h
    crypto/meta.h
    crypto/rsa_pem.h
    crypto/sha.h
    crypto/rand.h
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
    tgl-layout.h
    tgl-log.h
    tgl-net.h
    tgl-net-asio.h
    tgl-queries.h
    tgl-timer.h
    tgl-timer-asio.h
    tgl_download_manager.h
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
    crypto/aes_openssl.c
    crypto/bn_openssl.c
    crypto/err_openssl.c
    crypto/md5_openssl.c
    crypto/rand_openssl.c
    crypto/rsa_pem_openssl.c
    crypto/sha_openssl.c
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
    tgl_download_manager.cpp
    tools.cpp
    updates.cpp
    )

add_library(${PROJECT_NAME} SHARED ${SOURCES} ${AUTO_HEADERS} ${CRYPTO_HEADERS} ${TYPES_HEADERS} ${HEADERS})

target_link_libraries(${PROJECT_NAME}
    ${Boost_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    z
)

add_custom_command(
    OUTPUT ${GENERATED_TGL_HEADERS} ${GENERATED_TGL_SOURCES}
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/generate/generate.sh ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_BINARY_DIR}
)

install(FILES ${HEADERS} DESTINATION include/tgl)
install(FILES ${AUTO_HEADERS} DESTINATION include/tgl/auto)
install(FILES ${CRYPTO_HEADERS} DESTINATION include/tgl/crypto)
install(FILES ${TYPES_HEADERS} DESTINATION include/tgl/types)
install(TARGETS tplgy_tgl DESTINATION lib)

if (APPLE)
    # Generate Info.plist for the framework
    configure_file("${CMAKE_CURRENT_SOURCE_DIR}/objc/Info.plist.in"
            "${CMAKE_CURRENT_BINARY_DIR}/Info.plist")
endif()
