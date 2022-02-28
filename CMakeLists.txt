# sources: https://stackoverflow.com/questions/50877135/cmake-specify-linux-kernel-module-output-build-directory
# https://gitlab.com/christophacham/cmake-kernel-module/-/blob/master/CMakeLists.txt
# https://musteresel.github.io/posts/2020/02/cmake-template-linux-kernel-module.html

cmake_minimum_required(VERSION 3.0.0 FATAL_ERROR)
project(fred-buffctl VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# default installation path
if (CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
    set (CMAKE_INSTALL_PREFIX "/opt/fredsys/"
           CACHE PATH "default install path" FORCE)
endif()

# Find kernel headers
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/../../cmake")
find_package(KernelHeaders REQUIRED)
include_directories(${KERNELHEADERS_INCLUDE_DIRS})

set(DRIVER_FILE ${PROJECT_NAME}.ko)
set(KBUILD_CMD ${CMAKE_MAKE_PROGRAM} -C ${KERNELHEADERS_DIR} modules M=${CMAKE_CURRENT_BINARY_DIR} src=${CMAKE_CURRENT_SOURCE_DIR})

# Generate the Kbuild file through cmake.
file(WRITE ${CMAKE_CURRENT_SOURCE_DIR}/Kbuild "obj-m := ${PROJECT_NAME}.o")

add_custom_command(OUTPUT ${DRIVER_FILE}
        COMMAND ${KBUILD_CMD}
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        DEPENDS ${PROJECT_NAME}.c VERBATIM)

add_custom_target(${PROJECT_NAME} ALL DEPENDS ${DRIVER_FILE} ${CMAKE_CURRENT_SOURCE_DIR}/Kbuild) 

install(FILES "${CMAKE_CURRENT_BINARY_DIR}/${DRIVER_FILE}"
         DESTINATION modules
)
