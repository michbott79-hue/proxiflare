cmake_minimum_required(VERSION 3.16)
project(proxiflare-daemon C)

# ── Language standard ────────────────────────────────────────────────────────
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# ── Compiler flags ───────────────────────────────────────────────────────────
add_compile_options(-Wall -Wextra)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_compile_options(-g -O0)
else()
    add_compile_options(-O2)
endif()

# ── pkg-config dependencies ──────────────────────────────────────────────────
find_package(PkgConfig REQUIRED)

pkg_check_modules(SQLITE3    REQUIRED sqlite3)
pkg_check_modules(OPENSSL    REQUIRED openssl)
pkg_check_modules(NFQ        REQUIRED libnetfilter_queue)
pkg_check_modules(NFNETLINK  REQUIRED libnfnetlink)
pkg_check_modules(LIBSSH2    REQUIRED libssh2)

# ── libargon2 (no pkg-config — manual search) ───────────────────────────────
find_library(ARGON2_LIB NAMES argon2 REQUIRED)
find_path(ARGON2_INCLUDE_DIR NAMES argon2.h REQUIRED)

if(NOT ARGON2_LIB)
    message(FATAL_ERROR "libargon2 not found. Install libargon2-dev.")
endif()
if(NOT ARGON2_INCLUDE_DIR)
    message(FATAL_ERROR "argon2.h not found. Install libargon2-dev.")
endif()

# ── Sources ──────────────────────────────────────────────────────────────────
set(DAEMON_SOURCES
    src/main.c
    src/config.c
    src/crypto.c
    src/ipc.c
    src/dns.c
    src/sni.c
    src/rules.c
    src/proxy_socks.c
    src/proxy_http.c
    src/proxy_ssh.c
    src/chain.c
    src/tproxy.c
    src/cgroup.c
    src/nft.c
    src/monitor.c
    src/logger.c
    src/stats.c
    vendor/cJSON/cJSON.c
)

# ── Executable ───────────────────────────────────────────────────────────────
add_executable(proxiflare-daemon ${DAEMON_SOURCES})

# ── Include directories ──────────────────────────────────────────────────────
target_include_directories(proxiflare-daemon PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/vendor/cJSON
    ${SQLITE3_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIRS}
    ${NFQ_INCLUDE_DIRS}
    ${NFNETLINK_INCLUDE_DIRS}
    ${LIBSSH2_INCLUDE_DIRS}
    ${ARGON2_INCLUDE_DIR}
)

# ── Link directories ─────────────────────────────────────────────────────────
target_link_directories(proxiflare-daemon PRIVATE
    ${SQLITE3_LIBRARY_DIRS}
    ${OPENSSL_LIBRARY_DIRS}
    ${NFQ_LIBRARY_DIRS}
    ${NFNETLINK_LIBRARY_DIRS}
    ${LIBSSH2_LIBRARY_DIRS}
)

# ── Link libraries ───────────────────────────────────────────────────────────
target_link_libraries(proxiflare-daemon PRIVATE
    ${SQLITE3_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    ${NFQ_LIBRARIES}
    ${NFNETLINK_LIBRARIES}
    ${LIBSSH2_LIBRARIES}
    ${ARGON2_LIB}
    pthread
)

# ── Compile definitions ──────────────────────────────────────────────────────
target_compile_options(proxiflare-daemon PRIVATE
    ${SQLITE3_CFLAGS_OTHER}
    ${OPENSSL_CFLAGS_OTHER}
    ${NFQ_CFLAGS_OTHER}
    ${NFNETLINK_CFLAGS_OTHER}
    ${LIBSSH2_CFLAGS_OTHER}
)

# ── Test executable ──────────────────────────────────────────────────────────
add_executable(pf-test-config tests/test_config.c src/config.c vendor/cJSON/cJSON.c)
target_include_directories(pf-test-config PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/vendor/cJSON
    ${SQLITE3_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIRS}
    ${ARGON2_INCLUDE_DIR}
)
target_link_directories(pf-test-config PRIVATE
    ${SQLITE3_LIBRARY_DIRS}
    ${OPENSSL_LIBRARY_DIRS}
)
target_link_libraries(pf-test-config PRIVATE
    ${SQLITE3_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    ${ARGON2_LIB}
)
