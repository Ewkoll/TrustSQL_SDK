cmake_minimum_required (VERSION 3.8)

if (UNIX)
	SET(CMAKE_C_COMPILER "/opt/rh/devtoolset-7/root/usr/bin/gcc")
	SET(CMAKE_CXX_COMPILER "/opt/rh/devtoolset-7/root/usr/bin/g++")
endif()

project ("BlockChain")
set(CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/CMake" "${CMAKE_MODULE_PATH}")

if (MINGW)
	set(CMAKE_INSTALL_PREFIX "C:/${PROJECT_NAME}")
else()
	set(CMAKE_INSTALL_PREFIX "/home/${PROJECT_NAME}")
endif()

include(GNUInstallDirs)
include(MacroDisableWarning)
include(CMakeDependentOption)
include(CMakePackageConfigHelpers)

message(STATUS "CMAKE_INSTALL_PREFIX: ${CMAKE_INSTALL_PREFIX}")
message(STATUS "CMAKE_ROOT: ${CMAKE_ROOT}")
message(STATUS "PROJECT_NAME: ${PROJECT_NAME}")
message(STATUS "CMAKE_SYSROOT: ${CMAKE_SYSROOT}")
message(STATUS "CMAKE_MODULE_PATH: ${CMAKE_MODULE_PATH}")
message(STATUS "CMAKE_STAGING_PREFIX: ${CMAKE_STAGING_PREFIX}")
message(STATUS "CMAKE_FIND_ROOT_PATH: ${CMAKE_FIND_ROOT_PATH}")
message(STATUS "CMAKE_BINARY_DIR: ${CMAKE_BINARY_DIR}")
message(STATUS "PROJECT_BINARY_DIR: ${PROJECT_BINARY_DIR}")

set(DEPENDENT_LIBRARIES "" CACHE STRING "" FORCE)

set(IsWow64 64)

set(CMAKE_SKIP_BUILD_RPATH FALSE)									# 编译时加上RPATH。
set(CMAKE_BUILD_WITH_INSTALL_RPATH FALSE)							# 编译时RPATH不使用安装的RPATH。
set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)							# 安装的执行文件加上RPATH。
set(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/lib${IsWow64}")    # 安装RPATH为程序目录下的lib64目录。

set(CMAKE_CXX_STANDARD_REQUIRED ON)
include(CheckCXXCompilerFlag)
if (MINGW)
	CHECK_CXX_COMPILER_FLAG("-std=c++17" COMPILER_SUPPORTS_CXX17)
	if (COMPILER_SUPPORTS_CXX17)
		add_compile_options("-std=c++17")
	else()
		message(SEND_ERROR "编译器需要支持C++17特性！")
	endif()
else()
	if (MSVC_VERSION GREATER_EQUAL "1900")
		CHECK_CXX_COMPILER_FLAG("/std:c++latest" COMPILER_SUPPORTS_LATEST)
		if (COMPILER_SUPPORTS_LATEST)
			add_compile_options("/std:c++latest")
		else()
			message(SEND_ERROR "编译器需要支持C++17特性！")
		endif()
	endif()
endif()

set(PUBLIC_DIR ${PROJECT_SOURCE_DIR}/Public)
set(THIRD_PARTY_DIR ${PROJECT_SOURCE_DIR}/ThirdParty)

if (POLICY CMP0074)
	cmake_policy(SET CMP0074 NEW)
	message(STATUS "CMake3.12版本以上开启基于环境变量查找库功能！")	
endif()

if (MINGW)
	set(ENV{OPENSSL_ROOT_DIR} "D:/msys64/home/openssl")
else()
	set(ENV{OPENSSL_ROOT_DIR} "/home/openssl/")
endif()
find_package(OpenSSL REQUIRED COMPONENTS Crypto SSL)
if (OPENSSL_FOUND)
	include_directories(${OPENSSL_INCLUDE_DIR})
	list(APPEND DEPENDENT_LIBRARIES ${OPENSSL_LIBRARIES})
	message(STATUS "OPENSSL_INCLUDE_DIR: ${OPENSSL_INCLUDE_DIR}")
	message(STATUS "OPENSSL_CRYPTO_LIBRARY: ${OPENSSL_LIBRARIES} ${OPENSSL_VERSION}")
endif()

if (MINGW)
	set(ZLIB_ROOT "D:/msys64/home/zlib")
else()
	set(ZLIB_ROOT "/home/zlib/")
endif()
find_package(ZLIB REQUIRED)
if (ZLIB_FOUND)
	include_directories(${ZLIB_INCLUDE_DIRS})
	list(APPEND DEPENDENT_LIBRARIES ${ZLIB_LIBRARIES})
	message(STATUS "ZLIB_INCLUDE_DIRS: ${ZLIB_INCLUDE_DIRS}")
	message(STATUS "ZLIB_LIBRARIES: ${ZLIB_LIBRARIES} ${ZLIB_VERSION_STRING}")
endif()

if (MINGW)	
	set(CURL_INCLUDE_DIR "D:/mysys64/home/curl/include")
	set(CURL_LIBRARY "D:/mysys64/home/curl/lib")
else()
	set(CURL_INCLUDE_DIR "/home/curl/include")
	set(CURL_LIBRARY "/home/curl/lib")
endif()
find_package(CURL REQUIRED)
if (CURL_FOUND)
	include_directories(${CURL_INCLUDE_DIRS})
	if (UNIX)
		set(CURL_LIBRARIES ${CURL_LIBRARIES}/libcurl.so)
	else()
		set(CURL_LIBRARIES ${CURL_LIBRARIES}/curl.dll)
	endif()
	list(APPEND DEPENDENT_LIBRARIES ${CURL_LIBRARIES})
	message(STATUS "CURL_INCLUDE_DIRS: ${CURL_INCLUDE_DIRS}")
	message(STATUS "CURL_LIBRARIES: ${CURL_LIBRARIES} ${CURL_VERSION_STRING}")
endif()

if (UNIX)
	list(REMOVE_DUPLICATES DEPENDENT_LIBRARIES)
	foreach(DEPENDENT_LIBS ${DEPENDENT_LIBRARIES})
		execute_process(COMMAND readlink -f ${DEPENDENT_LIBS}
						RESULT_VARIABLE Flag
						OUTPUT_VARIABLE LINK_LIBS)
		if (${Flag} STREQUAL "0")
			list(APPEND LINK_DEPEND_LIBS ${LINK_LIBS})
		else()
			list(APPEND LINK_DEPEND_LIBS ${DEPENDENT_LIBS})
		endif()
	endforeach()
	message(STATUS "公共依赖的库列表：" ${LINK_DEPEND_LIBS})
endif()

DisableWarning()

add_subdirectory ("BlockChain")

add_subdirectory ("TrustSQL_SDK_V1.2")

add_subdirectory ("Cli")

add_subdirectory ("Test")

if (MINGW)
	file(GLOB MINGW_DLL_FILES $ENV{MINGW64}/bin/*.dll)
	install (FILES ${MINGW_DLL_FILES} DESTINATION "./")
	
	add_custom_command(OUTPUT COPY_RES
		COMMAND ${CMAKE_COMMAND} -E copy $ENV{MINGW64}/bin/libgcc_s_seh-1.dll ${CMAKE_BINARY_DIR}/${PROJECT_NAME}/
		COMMAND ${CMAKE_COMMAND} -E copy $ENV{MINGW64}/bin/libatomic-1.dll ${CMAKE_BINARY_DIR}/${PROJECT_NAME}/
		COMMAND ${CMAKE_COMMAND} -E copy $ENV{MINGW64}/bin/libgomp-1.dll ${CMAKE_BINARY_DIR}/${PROJECT_NAME}/
		COMMAND ${CMAKE_COMMAND} -E copy $ENV{MINGW64}/bin/libquadmath-0.dll ${CMAKE_BINARY_DIR}/${PROJECT_NAME}/
		COMMAND ${CMAKE_COMMAND} -E copy $ENV{MINGW64}/bin/libssp-0.dll ${CMAKE_BINARY_DIR}/${PROJECT_NAME}/
		COMMAND ${CMAKE_COMMAND} -E copy $ENV{MINGW64}/bin/libstdc++-6.dll ${CMAKE_BINARY_DIR}/${PROJECT_NAME}/
		COMMAND ${CMAKE_COMMAND} -E copy $ENV{MINGW64}/bin/libwinpthread-1.dll ${CMAKE_BINARY_DIR}/${PROJECT_NAME}/
	)
	add_custom_target(CopyTask ALL DEPENDS COPY_RES)
endif()