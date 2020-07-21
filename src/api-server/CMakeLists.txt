set(SMF_API_SERVER_DIR "${SRC_TOP_DIR}/api-server")

include_directories(${SMF_API_SERVER_DIR}/api)
include_directories(${SMF_API_SERVER_DIR}/impl)
include_directories(${SMF_API_SERVER_DIR}/model)
include_directories(${SMF_API_SERVER_DIR}/)
include_directories(${SRC_TOP_DIR}/utils/bstr)
include_directories(${SRC_TOP_DIR}/smf_app)
include_directories(${SRC_TOP_DIR}/itti)
include_directories(${SRC_TOP_DIR}/common)
include_directories(${SRC_TOP_DIR}/common/msg)
include_directories(${SRC_TOP_DIR}/common/utils)
include_directories(${SRC_TOP_DIR}/common/nas)
include_directories(${SRC_TOP_DIR}/common/ngap)
include_directories(${SRC_TOP_DIR}/pfcp)
include_directories(${SRC_TOP_DIR}/nas/ies)
include_directories(${SRC_TOP_DIR}/nas/sm/msg)
include_directories(${SRC_TOP_DIR}/ngap/asn1c)
include_directories(${SRC_TOP_DIR}/ngap/ies)
include_directories(${SRC_TOP_DIR}/udp)
include_directories(${SRC_TOP_DIR}/gtpv2c)
include_directories(${SRC_TOP_DIR}/../build/ext/spdlog/include)

file(GLOB SMF_API_SERVER_src_files
    ${SMF_API_SERVER_DIR}/smf-http2-server.cpp
    ${SMF_API_SERVER_DIR}/smf-api-server.cpp
    ${SMF_API_SERVER_DIR}/model/*.cpp
    ${SMF_API_SERVER_DIR}/api/*.cpp
    ${SMF_API_SERVER_DIR}/impl/*.cpp
)
 
add_library(SMF_API STATIC
           ${SMF_API_SERVER_src_files})