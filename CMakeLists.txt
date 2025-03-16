cmake_minimum_required(VERSION 3.10)
project(vanet_secure_routing)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find required packages
find_package(OpenSSL REQUIRED)
find_package(ns3 REQUIRED)

# Add source files
set(SOURCES
    src/crypto/crypto-module.cpp
    src/routing/secure-routing.cpp
)

# Add header files
set(HEADERS
    src/crypto/crypto-module.h
    src/routing/secure-routing.h
)

# Create library
add_library(vanet_secure_routing SHARED ${SOURCES} ${HEADERS})

# Link dependencies
target_link_libraries(vanet_secure_routing
    PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    ${NS3_LIBRARIES}
)

# Include directories
target_include_directories(vanet_secure_routing
    PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${OPENSSL_INCLUDE_DIR}
    ${NS3_INCLUDE_DIRS}
)

# Add compile definitions
target_compile_definitions(vanet_secure_routing
    PRIVATE
    NS3_LOG_ENABLE
)

# Create test executable
add_executable(vanet_test tests/main.cpp)
target_link_libraries(vanet_test PRIVATE vanet_secure_routing)

# Installation
install(TARGETS vanet_secure_routing
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
)

install(FILES ${HEADERS}
    DESTINATION include/vanet
) 