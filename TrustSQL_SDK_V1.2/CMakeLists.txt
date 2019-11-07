cmake_minimum_required (VERSION 3.8)

include_directories(${PUBLIC_DIR}/include)

file(GLOB HEAD_FILES *.h)
file(GLOB SRC_FILES *.c *.cpp)

SET(TargetName trustsql_sdk_v1.2)
add_library(${TargetName} SHARED ${SRC_FILES} ${HEAD_FILES})
target_link_libraries(${TargetName} ${OPENSSL_LIBRARIES} -static-libstdc++ -static-libgcc -Wl,--wrap=memcpy)

install (TARGETS ${TargetName} EXPORT ${PACKAGE_NAME} LIBRARY DESTINATION "lib${IsWow64}" ARCHIVE DESTINATION "lib${IsWow64}")