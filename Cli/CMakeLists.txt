cmake_minimum_required (VERSION 3.8)

include_directories(${PUBLIC_DIR}/include)

file(GLOB HEAD_FILES *.h)
file(GLOB SRC_FILES *.c *.cpp)

SET(TargetName trustsql_cli)

find_package(Threads)

add_executable(${TargetName} ${SRC_FILES} ${HEAD_FILES})
target_link_libraries(${TargetName} ${OPENSSL_LIBRARIES} ${CURL_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})

target_link_libraries(${TargetName} trustsql_sdk_v1.2)
target_include_directories(${TargetName} PRIVATE ${CMAKE_CURRENT_LIST_DIR}/include)

install (TARGETS ${TargetName} EXPORT ${PACKAGE_NAME} LIBRARY DESTINATION "lib${IsWow64}" ARCHIVE DESTINATION "lib${IsWow64}")
install (FILES ${LINK_DEPEND_LIBS} DESTINATION ${CMAKE_INSTALL_RPATH} PERMISSIONS OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE)