################################################################################
# Licensed to the OpenAirInterface (OAI) Software Alliance under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The OpenAirInterface Software Alliance licenses this file to You under
# the OAI Public License, Version 1.1  (the "License"); you may not use this file
# except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.openairinterface.org/?page_id=698
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#-------------------------------------------------------------------------------
# For more information about the OpenAirInterface (OAI) Software Alliance:
#      contact@openairinterface.org
################################################################################
#for NAS
set(NAS_DIR "${CMAKE_CURRENT_SOURCE_DIR}")

include_directories(${NAS_DIR})
include_directories(${NAS_DIR}/ies)
include_directories(${NAS_DIR}/network)
include_directories(${NAS_DIR}/mm/msg)
include_directories(${NAS_DIR}/mm)
include_directories(${NAS_DIR}/sm)
include_directories(${NAS_DIR}/sm/msg)
include_directories(${SRC_TOP_DIR}/utils)
include_directories(${SRC_TOP_DIR}/utils/bstr)
include_directories(${SRC_TOP_DIR}/nas/security)
include_directories(${SRC_TOP_DIR}/common)
include_directories(${SRC_TOP_DIR}/ngap/asn1c)
include_directories(${SRC_TOP_DIR}/ngap/ies)

file(GLOB NAS_src_files
    ${NAS_DIR}/*.c
    ${NAS_DIR}/ies/*.c
    ${NAS_DIR}/network/*.c
    ${NAS_DIR}/mm/msg/*.c
    ${NAS_DIR}/mm/*.c
    ${NAS_DIR}/sm/*.c
    ${NAS_DIR}/sm/msg/*.c
    ${SRC_TOP_DIR}/utils/conversions.c
    ${SRC_TOP_DIR}/utils/pid_file.c
    ${SRC_TOP_DIR}/utils/hashtable.c
    ${SRC_TOP_DIR}/utils/obj_hashtable.c
    ${SRC_TOP_DIR}/utils/TLVDecoder.c
    ${SRC_TOP_DIR}/utils/TLVEncoder.c
    ${SRC_TOP_DIR}/utils/bstr/*.c
    ${SRC_TOP_DIR}/nas/security/*.c
    ${SRC_TOP_DIR}/common/dynamic_memory_check.c
    ${SRC_TOP_DIR}/common/backtrace.c
    ${SRC_TOP_DIR}/common/*.c
)   

add_library(NAS ${NAS_DIR}/nas_message.c  ${NAS_src_files} ${NETTLE_LIBRARIES} ${CRYPTO_LIBRARIES})
