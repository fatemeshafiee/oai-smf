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

/*! \file smf_n1.hpp
 * \brief
 \author  Tien-Thinh NGUYEN
 \company Eurecom
 \date 2019
 \email: tien-thinh.nguyen@eurecom.fr
 */

#ifndef FILE_SMF_N1_HPP_SEEN
#define FILE_SMF_N1_HPP_SEEN

#include <string>

#include "smf.h"
#include "smf_context.hpp"
#include "smf_msg.hpp"
#include "3gpp_29.502.h"

extern "C" {
#include "nas_message.h"
}

namespace smf {

class smf_n1 {
 private:

 public:
  smf_n1() {
  }
  ;
  smf_n1(smf_n1 const&) = delete;
  void operator=(smf_n1 const&) = delete;

  /*
   * Create N1 SM Container to send to AMF (using NAS lib)
   * @param [pdu_session_msg&] msg
   * @param [uint8_t] msg_type Type of N1 message
   * @param [std::string&] nas_msg_str store NAS message in form of string
   * @param [uint8_t] sm_cause store NAS Cause
   * @return boolean: True if the NAS message has been created successfully, otherwise return false
   */
  bool create_n1_sm_container(pdu_session_msg &msg, uint8_t msg_type,
                              std::string &nas_msg_str,
                              cause_value_5gsm_e sm_cause);

  /*
   * Decode N1 SM Container into the NAS mesasge (using NAS lib)
   * @param [nas_message_t&] nas_msg Store NAS message after decoded
   * @param [const std::string&] n1_sm_msg N1 SM Container
   * @return status of the decode process
   */
  int decode_n1_sm_container(nas_message_t &nas_msg, const std::string &n1_sm_msg);

  /*
   * Decode N2 SM Information Ngap_PDUSessionResourceSetupResponseTransfer
   * @param [std::shared_ptr<Ngap_PDUSessionResourceSetupResponseTransfer_t>&] ngap_IE Store decoded NGAP message
   * @param [const std::string&] n2_sm_info N2 SM Information
   * @return status of the decode process
   */


};

}  // namespace smf

#endif /* FILE_SMF_N1_HPP_SEEN */
