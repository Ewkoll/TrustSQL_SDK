macro(Configure_MSVC_Runtime)
    if(MSVC)
		message(STATUS "CMAKE_BUILD_TYPE:" ${CMAKE_BUILD_TYPE})
		message(STATUS "CMAKE_CXX_FLAGS: " ${CMAKE_CXX_FLAGS})
		message(STATUS "CMAKE_C_FLAGS_DEBUG: " ${CMAKE_C_FLAGS_DEBUG})
		message(STATUS "CMAKE_C_FLAGS_MINSIZEREL: " ${CMAKE_C_FLAGS_MINSIZEREL})
		message(STATUS "CMAKE_C_FLAGS_RELEASE: " ${CMAKE_C_FLAGS_RELEASE})
		message(STATUS "CMAKE_C_FLAGS_RELWITHDEBINFO: " ${CMAKE_C_FLAGS_RELWITHDEBINFO})
		message(STATUS "CMAKE_CXX_FLAGS_DEBUG: " ${CMAKE_CXX_FLAGS_DEBUG})
		message(STATUS "CMAKE_CXX_FLAGS_MINSIZEREL: " ${CMAKE_CXX_FLAGS_MINSIZEREL})
		message(STATUS "CMAKE_CXX_FLAGS_RELEASE: " ${CMAKE_CXX_FLAGS_RELEASE})
		message(STATUS "CMAKE_CXX_FLAGS_RELWITHDEBINFO: " ${CMAKE_CXX_FLAGS_RELWITHDEBINFO})
		message(STATUS "MSVC_RUNTIME: " ${MSVC_RUNTIME})

        if ("${MSVC_RUNTIME}" STREQUAL "")
            set(MSVC_RUNTIME "Static")
        endif()
        
		set (VAR_FLAG_DEBUG
			CMAKE_C_FLAGS_DEBUG
            CMAKE_CXX_FLAGS_DEBUG
		)

		set (VAR_FLAG_RELEASE
			CMAKE_C_FLAGS_RELEASE
            CMAKE_C_FLAGS_RELWITHDEBINFO
            CMAKE_CXX_FLAGS_MINSIZEREL
			CMAKE_C_FLAGS_MINSIZEREL
            CMAKE_CXX_FLAGS_RELEASE
            CMAKE_CXX_FLAGS_RELWITHDEBINFO
		)
		
        if(${MSVC_RUNTIME} STREQUAL "Static")
            message(STATUS "MSVC -> 使用MT的静态运行库")
            foreach(Variable ${VAR_FLAG_DEBUG})
                if(${Variable} MATCHES "/MDd")
					string(REGEX REPLACE "/MDd" "/MTd" ${Variable} "${${Variable}}")
                endif()
            endforeach()
			foreach(Variable ${VAR_FLAG_RELEASE})
                if(${Variable} MATCHES "/MD")
                    string(REGEX REPLACE "/MD" "/MT" ${Variable} "${${Variable}}")
                endif()
            endforeach()
        else()
            message(STATUS "MSVC -> 使用MD的动态运行库")
            foreach(Variable ${VAR_FLAG_DEBUG})
                if(${Variable} MATCHES "/MTd")
					string(REGEX REPLACE "/MTd" "/MDd" ${Variable} "${${Variable}}")
                endif()
            endforeach()
			foreach(Variable ${VAR_FLAG_RELEASE})
                if(${Variable} MATCHES "/MT")
                    string(REGEX REPLACE "/MT" "/MD" ${Variable} "${${Variable}}")
                endif()
            endforeach()
        endif()
    endif()
endmacro()
