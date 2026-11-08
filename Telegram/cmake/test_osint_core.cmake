# This file is part of OsintGram Desktop,
# based on Forkgram and Telegram Desktop.
#
# For license and copyright information please follow this link:
# https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL

add_executable(test_osint_core)
init_non_host_target(test_osint_core "(tests)")

target_precompile_headers(test_osint_core PRIVATE ${src_loc}/tests/test_osint_core_pch.h)
nice_target_sources(test_osint_core ${src_loc}
PRIVATE
    tests/test_osint_core.cpp
    tests/test_osint_core_pch.h
    menu/menu_osint_core.cpp
    menu/menu_osint_core.h
)

target_include_directories(test_osint_core
PRIVATE
    ${src_loc}
)

target_link_libraries(test_osint_core
PRIVATE
    desktop-app::lib_base
)

set_target_properties(test_osint_core PROPERTIES
    EXCLUDE_FROM_ALL TRUE
    EXCLUDE_FROM_DEFAULT_BUILD TRUE
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/test_osint_core
)
