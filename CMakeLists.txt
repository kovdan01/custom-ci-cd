cmake_minimum_required(VERSION 3.2)


if(DEFINED ENV{TRAVIS_BUILD_NUMBER})
    project(custom-ci-cd VERSION 0.0.$ENV{TRAVIS_BUILD_NUMBER})
else()
    project(custom-ci-cd VERSION 0.0.1)
endif()

configure_file(version.h.in version.h)
find_package(Boost COMPONENTS COMPONENTS program_options system REQUIRED)

set(HEADERS
    src/include/network/server.h
    src/include/network/session.h

    src/include/utils/thread_pool.h
    src/include/utils/json.hpp)

set(NETWORK
    src/network/server.cpp
    src/network/session.cpp)

set(UTILS
    src/utils/thread_pool.cpp)

SET(SOURCES  ${NETWORK} ${UTILS})

add_executable(ci-cd-server src/server.cpp ${SOURCES} ${HEADERS})
add_executable(ci-cd-client src/client.cpp)

set_target_properties(ci-cd-server ci-cd-client PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
    CXX_EXTENSIONS OFF
)

target_include_directories(ci-cd-server PRIVATE "${CMAKE_BINARY_DIR}" "src/include")
target_link_libraries(ci-cd-server PRIVATE crypto ssl Boost::boost Boost::program_options Boost::system pthread stdc++fs)

target_include_directories(ci-cd-client PRIVATE "${CMAKE_BINARY_DIR}" "src/include" ${Boost_INCLUDE_DIRS})
target_link_libraries(ci-cd-client PRIVATE Boost::boost Boost::program_options Boost::system pthread)

if(MSVC)
    target_compile_options(ci-cd-server PRIVATE
        /W4
    )
    target_compile_options(ci-cd-client PRIVATE
        /W4
    )
else()
    target_compile_options(ci-cd-server PRIVATE
        -Werror -Wall -Wimplicit-fallthrough -pedantic-errors
    )
    target_compile_options(ci-cd-client PRIVATE
        -Werror -Wall -Wimplicit-fallthrough -pedantic-errors
    )
endif()

install(TARGETS ci-cd-server ci-cd-client DESTINATION bin)

set(CPACK_GENERATOR DEB)

set(CPACK_PACKAGE_VERSION_MAJOR "${PROJECT_VERSION_MAJOR}")
set(CPACK_PACKAGE_VERSION_MINOR "${PROJECT_VERSION_MINOR}")
set(CPACK_PACKAGE_VERSION_PATCH "${PROJECT_VERSION_PATCH}")

set(CPACK_PACKAGE_CONTACT example@example.com)

include(CPack)
