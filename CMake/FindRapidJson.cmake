if (NOT RapidJson_LOAD_FROM_CACHE)
	message(STATUS "--------------------------------------------")
	message(STATUS "使用FindRapidJson.cmake查找Json解析库！")
	set(RapidJson_LOAD_FROM_CACHE TRUE)
endif()

if (WIN32)
	set(RapidJson_ROOT_PATH ${THIRD_PARTY_DIR}/win32/${PLATFROM}/rapidjson)
endif()

if (UNIX)
	set(RapidJson_ROOT_PATH ${THIRD_PARTY_DIR}/unix/rapidjson)

	find_path(RapidJson_INCLUDE_DIR
		NAMES rapidjson.h
		PATHS ${RapidJson_ROOT_PATH}/include/rapidjson
		NO_SYSTEM_ENVIRONMENT_PATH
		CACHE STRING "RapidJson头文件" FORCE)
endif()

if (RapidJson_INCLUDE_DIR)
	set(RapidJson_INCLUDE_DIR ${RapidJson_INCLUDE_DIR}/../)
	set(RapidJson_FOUND TRUE)
	message(STATUS "通过RapidJson_ROOT_PATH查找到RapidJson库 RapidJson_INCLUDE_DIR:${RapidJson_INCLUDE_DIR}")

	# 添加头文件和库依赖
	include_directories(${RapidJson_INCLUDE_DIR})
	message(STATUS "--------------------------------------------")
endif()