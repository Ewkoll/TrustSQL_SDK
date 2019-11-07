﻿macro(DisableWarning)
    if(MSVC)
		message(STATUS "---------B-MSVC-Warning-------------")
		add_compile_options(/wd4355)
		add_compile_options(/wd4112)
		add_compile_options(/wd4996)
		message(STATUS "---------E-MSVC-Warning-------------")
    endif()

	if(UNIX)
		message(STATUS "---------B-UNIX-Warning-------------")
		add_definitions(-Wall)
		add_definitions(-Wextra)
		add_definitions(-Wunused-variable)
		add_definitions(-Wno-unused-parameter)
		add_definitions(-Wno-unused-function)
		add_definitions(-Wunused-value)
		add_definitions(-Wcast-align)
		add_definitions(-Wno-write-strings)
		add_definitions(-Wsign-compare)
		add_definitions(-fms-extensions)
		add_definitions(-Wno-float-equal)
		add_definitions(-Wnonnull)
		message(STATUS "---------E-UNIX-Warning-------------")
	endif()
endmacro()