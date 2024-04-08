cmake_minimum_required(VERSION 3.29)
project(tls13 LANGUAGES C VERSION 1.0)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED True)

# Find the OpenSSL package
find_package(OpenSSL REQUIRED)

# Include the OpenSSL headers
include_directories(${OPENSSL_INCLUDE_DIR})

# Define the server executable
add_executable(server server.c)
target_link_libraries(server OpenSSL::SSL OpenSSL::Crypto)

# Define the client executable
add_executable(client client.c)
target_link_libraries(client OpenSSL::SSL OpenSSL::Crypto)



#add_executable(tls13 main.c)

# If your OpenSSL version is not correctly found, specify the path manually, e.g.,
# set(OPENSSL_ROOT_DIR "/usr/local/opt/openssl/")
