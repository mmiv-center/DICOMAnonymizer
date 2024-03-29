cmake_minimum_required (VERSION 3.10)

project (anonymize)

# set (CMAKE_CXX_STANDARD 11)
IF("${CMAKE_SYSTEM}" MATCHES "Linux")
   set (CMAKE_CXX_STANDARD 20)
   SET(CMAKE_CXX_FLAGS "-std=c++20 -I/usr/local/include -I/usr/include")
ELSE()
   # find the correct path for isysroot with `xcrun --show-sdk-path`
   SET(CMAKE_CXX_FLAGS "-std=c++20 -isysroot /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk -I/usr/local/include")
ENDIF()

# add a date stamp to the version string
string(TIMESTAMP TODAY "%Y%m%d")
set(VERSION_DATE "${TODAY}")
configure_file(anonymize.cxx anonymize_versioned.cxx)

FIND_LIBRARY(LIBXML2_LIBRARY NAMES xml2)
FIND_LIBRARY(JPEG_LIBRARY NAMES jpeg)
FIND_LIBRARY(ZLIB_LIBRARY NAMES z)
FIND_LIBRARY(XLST_LIBRARY NAMES exslt)

message(STATUS LIBXML2_LIBRARY = ${LIBXML2_LIBRARY})
message(STATUS JPEG_LIBRARY = ${JPEG_LIBRARY})
message(STATUS ZLIB_LIBRARY = ${ZLIB_LIBRARY})
message(STATUS XLST_LIBRARY = ${XLST_LIBRARY})

add_executable (anonymize anonymize_versioned.cxx ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories (anonymize PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/gdcm-build/Source/DataStructureAndEncodingDefinition ${CMAKE_CURRENT_SOURCE_DIR}/gdcm-build/Source/Common ${CMAKE_CURRENT_SOURCE_DIR}/GDCM-3.0.20/Source/Common ${CMAKE_CURRENT_SOURCE_DIR}/GDCM-3.0.20/Source/MediaStorageAndFileFormat/ ${CMAKE_CURRENT_SOURCE_DIR}/GDCM-3.0.20/Source/InformationObjectDefinition/ ${CMAKE_CURRENT_SOURCE_DIR}/GDCM-3.0.20/Source/DataDictionary/ ${CMAKE_CURRENT_SOURCE_DIR}/GDCM-3.0.20/bin/Source/Common ${CMAKE_CURRENT_SOURCE_DIR}/GDCM-3.0.20/Source/DataStructureAndEncodingDefinition ${LIBXML2_INCLUDE_DIR})

SET(GDCM_LIB_PATH ${CMAKE_CURRENT_SOURCE_DIR}/gdcm-build/bin)
link_directories(anonymize ${CMAKE_CURRENT_SOURCE_DIR}/gdcm-build/bin)
FIND_LIBRARY(COMMON_LIBRARY     NAMES gdcmCommon     PATHS ${GDCM_LIB_PATH} NO_DEFAULT_PATH)
FIND_LIBRARY(IOD_LIBRARY        NAMES gdcmIOD        PATHS ${GDCM_LIB_PATH} NO_DEFAULT_PATH)
FIND_LIBRARY(MSFF_LIBRARY       NAMES gdcmMSFF       PATHS ${GDCM_LIB_PATH} NO_DEFAULT_PATH)
FIND_LIBRARY(DSED_LIBRARY       NAMES gdcmDSED       PATHS ${GDCM_LIB_PATH} NO_DEFAULT_PATH)
FIND_LIBRARY(DICT_LIBRARY       NAMES gdcmDICT       PATHS ${GDCM_LIB_PATH} NO_DEFAULT_PATH)
FIND_LIBRARY(MEXD_LIBRARY       NAMES gdcmMEXD       PATHS ${GDCM_LIB_PATH} NO_DEFAULT_PATH)


#message(AUTHOR_WARNING ${COMMON_LIBRARY})
#message(AUTHOR_WARNING ${IOD_LIBRARY})
message(STATUS COMMON_LIBRARY = ${COMMON_LIBRARY})
message(STATUS IOD_LIBRARY = ${IOD_LIBRARY})
message(STATUS DICT_LIBRARY = ${DICT_LIBRARY})
message(STATUS DSED_LIBRARY = ${DSED_LIBRARY})
message(STATUS MSFF_LIBRARY = ${MSFF_LIBRARY})
message(STATUS MEXD_LIBRARY = ${MEXD_LIBRARY})

target_link_libraries(anonymize ${COMMON_LIBRARY} ${IOD_LIBRARY} ${MEXD_LIBRARY} ${MSFF_LIBRARY} ${DICT_LIBRARY} ${DSED_LIBRARY} ${LIBXML2_LIBRARY} ${JPEG_LIBRARY} ${ZLIB_LIBRARY} ${XLST_LIBRARY} pthread)
