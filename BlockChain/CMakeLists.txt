cmake_minimum_required (VERSION 3.8)

SET(TargetName block_chain)

add_executable (${TargetName} "BlockChain.cpp" "BlockChain.h")

install (TARGETS ${TargetName} EXPORT ${PACKAGE_NAME} RUNTIME DESTINATION bin)