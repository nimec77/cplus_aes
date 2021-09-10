cmake_minimum_required(VERSION 3.20)
project(cplus_aes)

set(CMAKE_CXX_STANDARD 20)

set(SET_SRC
        ptr_helper.cpp
        aes_encode.cpp
        main.cpp
        )

find_library(BCRYPT bcrypt.lib)

add_executable(${PROJECT_NAME} ${SET_SRC})

target_link_libraries(${PROJECT_NAME} ${BCRYPT})
