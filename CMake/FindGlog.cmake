if(NOT GLOG_LOAD_FROM_CACHE)
	message(STATUS "--------------------------------------------")
	message(STATUS "使用FindGlog.cmake查找日志库-不从全局环境变量查找，MinGW库引用的头文件和VS的头文件冲突！")
	set(GLOG_LOAD_FROM_CACHE TRUE)
endif()

if (UNIX)
	set(Glog_ROOT_PATH ${THIRD_PARTY_DIR}/unix/glog)

	find_path(Glog_INCLUDE_DIR
		NAMES logging.h
		PATHS ${Glog_ROOT_PATH}/include/glog
		NO_SYSTEM_ENVIRONMENT_PATH
		CACHE STRING "GLog头文件" FORCE)
	
	message(STATUS ${Glog_INCLUDE_DIR})
	find_library(Glog_LIBRARY
		NAMES libglog.a
		PATHS ${Glog_ROOT_PATH}/lib
		NO_SYSTEM_ENVIRONMENT_PATH
		CACHE STRING "GLog静态库目录" FORCE)

		message(STATUS "Glog_LIBRARY" ${Glog_LIBRARY})
endif(UNIX)

if(Glog_INCLUDE_DIR AND Glog_LIBRARY)
	set(Glog_INCLUDE_DIR ${Glog_INCLUDE_DIR}/../)
	set(Glog_FOUND TRUE)
	message(STATUS "通过Glog_ROOT_PATH查找到Glog库 Glog_INCLUDE_DIR:${Glog_INCLUDE_DIR} Glog_LIBRARY：${Glog_LIBRARY}")
	
	# 添加头文件和库依赖
	include_directories(${Glog_INCLUDE_DIR})
	list(APPEND DEPENDENT_LIBRARIES ${Glog_LIBRARY})
	message(STATUS "--------------------------------------------")
endif()