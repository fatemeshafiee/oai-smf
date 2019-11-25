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
include_directories(${SRC_TOP_DIR}/common)
include_directories(${SRC_TOP_DIR}/common/msg)
include_directories(${SRC_TOP_DIR}/common/utils)
include_directories(${SRC_TOP_DIR}/common/ngap)
include_directories(${SRC_TOP_DIR}/itti)
include_directories(${SRC_TOP_DIR}/gtpv2c)
include_directories(${SRC_TOP_DIR}/pfcp)
include_directories(${SRC_TOP_DIR}/smf)
include_directories(${SRC_TOP_DIR}/ngap)
include_directories(${SRC_TOP_DIR}/NgapSmfLayer)
include_directories(${SRC_TOP_DIR}/udp)
include_directories(${SRC_TOP_DIR}/../build/ext/spdlog/include)


add_library (SMF STATIC
  ${SRC_TOP_DIR}/common/ngap/ngap_common.c
  ${SRC_TOP_DIR}/NgapSmfLayer/ng_pdu_session_resource_setup_request.c
  ${SRC_TOP_DIR}/NgapSmfLayer/ng_pdu_session_resource_setup_response.c
  ${SRC_TOP_DIR}/NgapSmfLayer/ng_pdu_session_resource_release_command.c
  ${SRC_TOP_DIR}/NgapSmfLayer/ng_pdu_session_resource_release_response.c
  ${SRC_TOP_DIR}/NgapSmfLayer/ng_pdu_session_resource_modify_request.c
  ${SRC_TOP_DIR}/NgapSmfLayer/ng_pdu_session_resource_modify_response.c
  ${SRC_TOP_DIR}/NgapSmfLayer/ng_pdu_session_resource_notify.c
  ${SRC_TOP_DIR}/NgapSmfLayer/ng_pdu_session_resource_modify_indication.c
  ${SRC_TOP_DIR}/NgapSmfLayer/ng_pdu_session_resource_modify_confirm.c
  ${SRC_TOP_DIR}/NgapSmfLayer/ng_pdu_handover_required.c
  ${SRC_TOP_DIR}/NgapSmfLayer/ng_pdu_handover_command.c
  ${SRC_TOP_DIR}/NgapSmfLayer/ng_pdu_handover_preparation_failure.c
  ${SRC_TOP_DIR}/NgapSmfLayer/ng_pdu_handover_request_acknowledge.c
  ${SRC_TOP_DIR}/NgapSmfLayer/ng_pdu_handover_failure.c
  ${SRC_TOP_DIR}/NgapSmfLayer/ng_pdu_handover_notify.c
  ${SRC_TOP_DIR}/NgapSmfLayer/ng_pdu_path_switch_request.c
  ${SRC_TOP_DIR}/NgapSmfLayer/ng_pdu_path_switch_request_acknowledge.c
  ${SRC_TOP_DIR}/NgapSmfLayer/ng_pdu_path_switch_request_failure.c
  ${SRC_TOP_DIR}/NgapSmfLayer/ng_pdu_handover_cancel.c
  ${SRC_TOP_DIR}/NgapSmfLayer/ng_pdu_handover_cancel_acknowledge.c
  ${SRC_TOP_DIR}/NgapSmfLayer/ng_pdu_uplink_ran_status_transfer.c
  ${SRC_TOP_DIR}/NgapSmfLayer/ng_pdu_downlink_ran_status_transfer.c
  smf_app.cpp
  smf_config.cpp
  smf_context.cpp
  smf_pfcp_association.cpp
  smf_pco.cpp
  smf_procedure.cpp
  smf_n4.cpp
  smf_n10.cpp
  smf_n11.cpp
  smf_msg.cpp
)

