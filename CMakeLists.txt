cmake_minimum_required(VERSION 3.10)
project(AegisVPN CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# FIX: добавлены базовые флаги хардненинга сборки — их не было вообще.
# -D_FORTIFY_SOURCE=2 требует включённой оптимизации, поэтому идёт вместе с -O2.
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O2 -Wall -Wextra -fstack-protector-strong -D_FORTIFY_SOURCE=2")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -pie -Wl,-z,relro,-z,now")

set(CMAKE_THREAD_LIBS_INIT "-lpthread")
set(CMAKE_HAVE_THREADS_LIBRARY 1)
set(CMAKE_USE_WIN32_THREADS_INIT 0)
set(CMAKE_USE_PTHREADS_INIT 1)
find_package(Threads REQUIRED)

find_package(OpenSSL REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(SQLITE3 REQUIRED sqlite3)

add_executable(aegis_server server.cpp)
target_include_directories(aegis_server PRIVATE ${SQLITE3_INCLUDE_DIRS})
target_link_libraries(aegis_server PRIVATE OpenSSL::Crypto ${SQLITE3_LIBRARIES} Threads::Threads)

add_executable(aegis_client client.cpp)
target_link_libraries(aegis_client PRIVATE OpenSSL::Crypto Threads::Threads)
