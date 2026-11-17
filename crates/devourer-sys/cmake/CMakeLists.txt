# SPDX-License-Identifier: GPL-2.0-or-later
#
# Builds devourer (only the RTL8822BU "Jaguar2" backend used by the TP-Link
# Archer T3U) plus Warlock's C shim over it. Driven by devourer-sys/build.rs.

cmake_minimum_required(VERSION 3.15)
project(warlock_devourer LANGUAGES C CXX)

list(PREPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/modules")

if(NOT DEVOURER_SOURCE_DIR)
  message(FATAL_ERROR "DEVOURER_SOURCE_DIR must point at the devourer checkout")
endif()

add_subdirectory("${DEVOURER_SOURCE_DIR}" devourer EXCLUDE_FROM_ALL)

add_library(warlock_dvr_shim STATIC
  "${CMAKE_CURRENT_SOURCE_DIR}/../shim/dvr_shim.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/../shim/dvr_shim.h")
target_compile_features(warlock_dvr_shim PRIVATE cxx_std_20)
target_link_libraries(warlock_dvr_shim PRIVATE devourer)
