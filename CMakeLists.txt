cmake_minimum_required (VERSION 2.8.11)

project (anonymize)

# set (CMAKE_CXX_STANDARD 11)
set (CMAKE_CXX_STANDARD 11)

add_executable (anonymize anonymize.cxx ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories (anonymize PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/gdcm-build/Source/DataStructureAndEncodingDefinition ${CMAKE_CURRENT_SOURCE_DIR}/gdcm-build/bin/Source/Common ${CMAKE_CURRENT_SOURCE_DIR}/gdcm-build/Source/Common ${CMAKE_CURRENT_SOURCE_DIR}/gdcm-build/Source/MediaStorageAndFileFormat/ ${CMAKE_CURRENT_SOURCE_DIR}/gdcm-build/Source/InformationObjectDefinition/ ${CMAKE_CURRENT_SOURCE_DIR}/gdcm-build/Source/DataDictionary/)

SET(GDCM_LIB_PATH ${CMAKE_CURRENT_SOURCE_DIR}/gdcm-build/bin/)
link_directories(anonymize ${CMAKE_CURRENT_SOURCE_DIR}/gdcm-build/bin/)
FIND_LIBRARY(COMMON_LIBRARY       NAMES gdcmCommon       PATHS ${GDCM_LIB_PATH} NO_DEFAULT_PATH)
FIND_LIBRARY(IOD_LIBRARY       NAMES gdcmIOD       PATHS ${GDCM_LIB_PATH} NO_DEFAULT_PATH)
FIND_LIBRARY(MSFF_LIBRARY       NAMES gdcmMSFF       PATHS ${GDCM_LIB_PATH} NO_DEFAULT_PATH)
FIND_LIBRARY(DSED_LIBRARY       NAMES gdcmDSED       PATHS ${GDCM_LIB_PATH} NO_DEFAULT_PATH)
FIND_LIBRARY(DICT_LIBRARY       NAMES gdcmDICT       PATHS ${GDCM_LIB_PATH} NO_DEFAULT_PATH)


message(AUTHOR_WARNING ${COMMON_LIBRARY})
message(AUTHOR_WARNING ${IOD_LIBRARY})


target_link_libraries(anonymize ${COMMON_LIBRARY} ${IOD_LIBRARY} ${MSFF_LIBRARY} ${DICT_LIBRARY} ${DSED_LIBRARY} pthread)
