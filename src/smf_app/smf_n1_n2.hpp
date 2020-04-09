/*
 * Licensed to the OpenAirInterface (OAI) Software Alliance under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The OpenAirInterface Software Alliance licenses this file to You under
 * the OAI Public License, Version 1.1  (the "License"); you may not use this file
 * except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.openairinterface.org/?page_id=698
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *-------------------------------------------------------------------------------
 * For more information about the OpenAirInterface (OAI) Software Alliance:
 *      contact@openairinterface.org
 */

/*! \file smf_n1_n2.hpp
 * \brief
  \author  Tien-Thinh NGUYEN
  \company Eurecom
  \date 2019
  \email: tien-thinh.nguyen@eurecom.fr
 */

#ifndef FILE_SMF_N1_N2_HPP_SEEN
#define FILE_SMF_N1_N2_HPP_SEEN

#include <map>
#include <set>
#include <shared_mutex>
#include <string>
#include <thread>

#include "pistache/endpoint.h"
#include "pistache/http.h"
#include "pistache/router.h"
#include "smf.h"
#include "3gpp_29.274.h"
#include "itti_msg_n4.hpp"
#include "itti_msg_n11.hpp"
#include "smf_context.hpp"
#include "smf_pco.hpp"
#include "smf_msg.hpp"
#include "smf_app.hpp"
#include "3gpp_29.502.h"
#include "SmContextCreateData.h"
#include "SmContextCreateError.h"

extern "C"{
#include "nas_message.h"
#include "Ngap_NGAP-PDU.h"
#include "Ngap_PDUSessionResourceSetupResponseTransfer.h"
#include "Ngap_PDUSessionResourceModifyResponseTransfer.h"
}

namespace smf {

class smf_n1_n2 {
private:

public:
  smf_n1_n2(){};
  smf_n1_n2(smf_n1_n2 const&)    = delete;
  void operator=(smf_n1_n2 const&)     = delete;

  /*
   * Create N1 SM Container to send to AMF (using NAS lib)
   * @param [pdu_session_msg&] msg
   * @param [uint8_t] msg_type Type of N1 message
   * @param [std::string&] nas_msg_str store NAS message in form of string
   * @param [uint8_t] sm_cause store NAS Cause
   *
   */
  void create_n1_sm_container(pdu_session_msg& msg, uint8_t msg_type, std::string& nas_msg_str, cause_value_5gsm_e sm_cause);

  /*
   * Create N2 SM Information to send to AMF (using NAS lib)
   * @param [std::shared_ptr<itti_n11_create_sm_context_response>] sm_context_res
   * @param [uint8_t] msg_type Type of N2 message
   * @param [std::string&] ngap_msg_str store NGAP message in form of string
   *
   */
  void create_n2_sm_information(pdu_session_msg& msg, uint8_t ngap_msg_type, n2_sm_info_type_e ngap_ie_type, std::string& ngap_msg_str);

  /*
   * Decode N1 SM Container into the NAS mesasge (using NAS lib)
   * @param [nas_message_t&] nas_msg Store NAS message after decoded
   * @param [std::string&] n1_sm_msg N1 SM Container from AMF
   * @return status of the decode process
   */
  int decode_n1_sm_container(nas_message_t& nas_msg, std::string& n1_sm_msg);

  /*
   * Decode N2 SM Information Ngap_PDUSessionResourceSetupResponseTransfer
   * @param [std::shared_ptr<Ngap_PDUSessionResourceSetupResponseTransfer_t>&] ngap_IE Store decoded NGAP message
   * @param [std::string&] n2_sm_info N2 SM Information
   * @return status of the decode process
   */
  int decode_n2_sm_information(std::shared_ptr<Ngap_PDUSessionResourceSetupResponseTransfer_t>& ngap_IE, std::string& n2_sm_info);

  /*
   * Decode N2 SM Information Ngap_PDUSessionResourceModifyResponseTransfer_t
   * @param [std::shared_ptr<Ngap_PDUSessionResourceModifyResponseTransfer_t>&] ngap_IE Store decoded NGAP message
   * @param [std::string&] n2_sm_info N2 SM Information
   * @return status of the decode process
   */
  int decode_n2_sm_information(std::shared_ptr<Ngap_PDUSessionResourceModifyResponseTransfer_t>& ngap_IE, std::string& n2_sm_info);

};

} // namespace smf


#endif /* FILE_SMF_N1_N2_HPP_SEEN */
