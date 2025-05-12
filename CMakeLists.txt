cmake_minimum_required(VERSION 3.10)
project(eBpfPcap C)

set(CMAKE_C_STANDARD 11)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBBPF REQUIRED libbpf)

include_directories(${LIBBPF_INCLUDE_DIRS})
link_directories(${LIBBPF_LIBRARY_DIRS})

# Generate BPF object file
add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/xdp_prog_kern.o
    COMMAND clang -g -O2 -target bpf -c ${CMAKE_CURRENT_SOURCE_DIR}/xdp_prog_kern.c -o ${CMAKE_CURRENT_BINARY_DIR}/xdp_prog_kern.o -D__TARGET_ARCH_x86
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/xdp_prog_kern.c
    COMMENT "Building BPF object file"
    VERBATIM
)

add_custom_target(bpf_programs DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/xdp_prog_kern.o)

add_executable(eBpfPcap main.c)
add_dependencies(eBpfPcap bpf_programs)

target_link_libraries(eBpfPcap ${LIBBPF_LIBRARIES})

# Copy BPF object file to the same directory as the executable
add_custom_command(
    TARGET eBpfPcap
    POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_BINARY_DIR}/xdp_prog_kern.o ${CMAKE_CURRENT_BINARY_DIR}
    COMMENT "Copying BPF object file to executable directory"
)
