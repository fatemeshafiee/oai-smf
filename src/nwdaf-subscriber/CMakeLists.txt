set(SMF_NWDAF_SUBSCRIBER_DIR "${SRC_TOP_DIR}/nwdaf-subscriber")

#
#include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/logger)
#include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/model/common_model)
#include(${SRC_TOP_DIR}/${MOUNTED_COMMON}/config/config.cmake)
#include(${SRC_TOP_DIR}/${MOUNTED_COMMON}/utils/utils.cmake)
#include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/utils)
#

include_directories(${SRC_TOP_DIR}/common/msg)
include_directories(${SRC_TOP_DIR}/common/utils)
include_directories(${SRC_TOP_DIR}/common/utils/bstr)
include_directories(${SRC_TOP_DIR}/common/nas)
include_directories(${SRC_TOP_DIR}/common)
include_directories(${SRC_TOP_DIR}/itti)
include_directories(${SRC_TOP_DIR}/smf_app)
include_directories(${SRC_TOP_DIR}/pfcp)
include_directories(${SRC_TOP_DIR}/smf)
include_directories(${SRC_TOP_DIR}/ngap)
include_directories(${SRC_TOP_DIR}/ngap/asn1c)
include_directories(${SRC_TOP_DIR}/ngap/ies)
include_directories(${SRC_TOP_DIR}/nas/ies)
include_directories(${SRC_TOP_DIR}/nas/sm/msg)
include_directories(${SRC_TOP_DIR}/nas/mm)
include_directories(${SRC_TOP_DIR}/nas/mm/msg)
include_directories(${SRC_TOP_DIR}/nas/sm)
include_directories(${SRC_TOP_DIR}/nas/sm/msg)
include_directories(${SRC_TOP_DIR}/nas/security)
include_directories(${SRC_TOP_DIR}/nas)
include_directories(${SRC_TOP_DIR}/udp)
include_directories(${SRC_TOP_DIR}/api-server/api)
include_directories(${SRC_TOP_DIR}/api-server/impl)
include_directories(${SRC_TOP_DIR}/api-server/model)
include_directories(${SRC_TOP_DIR}/api-server/)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/logger)
include(${SRC_TOP_DIR}/${MOUNTED_COMMON}/config/config.cmake)
include(${SRC_TOP_DIR}/${MOUNTED_COMMON}/utils/utils.cmake)
# TODO Stefan: Why do I need include_directories here if it is already in utils.cmake?
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/utils)
include(${BUILD_TOP_DIR}/smf/used_models.cmake)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/logger)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/model/common_model)
include(${SRC_TOP_DIR}/${MOUNTED_COMMON}/config/config.cmake)
include(${SRC_TOP_DIR}/${MOUNTED_COMMON}/utils/utils.cmake)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/utils)




file(GLOB SMF_NWDAF_SUBSCRIBER_src_files
        ${SMF_NWDAF_SUBSCRIBER_DIR}/*.h
        ${SMF_NWDAF_SUBSCRIBER_DIR}/*.cpp
)

add_library(SMF_NWDAF_SUBSCRIBER STATIC
        ${SMF_NWDAF_SUBSCRIBER_src_files})

#add_executable(nghttp2_starter ${SOURCES})

# Just an example of how to put log in CMakeLists
# message(LOG="${Boost_LIBRARIES}")

#target_include_directories(nghttp2_starter PRIVATE
#        ${Boost_INCLUDE_DIRS}
#        ${OPENSSL_INCLUDE_DIR}
#        /usr/local/include/nghttp2
#)
#
#target_link_libraries(nghttp2_starter
#        ${Boost_LIBRARIES}
#        /usr/local/lib/libnghttp2_asio.a /usr/local/lib/libnghttp2.a
#        ${OPENSSL_LIBRARIES}
#        nlohmann_json::nlohmann_json
#)
