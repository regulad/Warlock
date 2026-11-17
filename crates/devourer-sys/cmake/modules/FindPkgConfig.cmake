# SPDX-License-Identifier: GPL-2.0-or-later
#
# Stand-in for CMake's FindPkgConfig, found first through CMAKE_MODULE_PATH.
#
# devourer locates libusb with find_package(PkgConfig REQUIRED) and
# pkg_check_modules(libusb REQUIRED IMPORTED_TARGET libusb-1.0), then links
# PkgConfig::libusb. Warlock builds libusb itself (the libusb1-sys crate, which
# also links it into the final Rust binary), so all this module has to do is
# produce that imported target carrying the header directory.

set(PKG_CONFIG_FOUND TRUE)
set(PkgConfig_FOUND TRUE)
set(PKG_CONFIG_EXECUTABLE "warlock-pkg-config-stub")

macro(pkg_check_modules _prefix)
  if(NOT TARGET PkgConfig::${_prefix})
    add_library(PkgConfig::${_prefix} INTERFACE IMPORTED GLOBAL)
    set_target_properties(PkgConfig::${_prefix} PROPERTIES
      INTERFACE_INCLUDE_DIRECTORIES "${WARLOCK_LIBUSB_INCLUDE_DIRS}")
  endif()
  set(${_prefix}_FOUND TRUE)
endmacro()
