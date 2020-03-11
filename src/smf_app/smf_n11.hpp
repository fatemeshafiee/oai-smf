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

/*! \file smf_n11.hpp
  \author  Lionel GAUTHIER, Tien-Thinh NGUYEN
  \company Eurecom
  \date 2019
  \email: lionel.gauthier@eurecom.fr, tien-thinh.nguyen@eurecom.fr
 */

#ifndef FILE_SMF_N11_HPP_SEEN
#define FILE_SMF_N11_HPP_SEEN

#include "smf.h"
#include "3gpp_29.503.h"
#include "smf_context.hpp"
#include "SmContextCreatedData.h"
#include "SmContextUpdateError.h"
#include <thread>
#include <map>

namespace smf {

class smf_n11 {
private:
  std::thread::id thread_id;
  std::thread thread;

  void handle_receive_sm_data_notification();

public:
  smf_n11();
  smf_n11(smf_n11 const&)    = delete;
  void operator=(smf_n11 const&)     = delete;
  void send_n1n2_message_transfer_request(std::shared_ptr<itti_n11_create_sm_context_response> sm_context_res);
  void send_pdu_session_update_sm_context_response(std::shared_ptr<itti_n11_update_sm_context_response> sm_context_res);
  void send_n1n2_message_transfer_request(std::shared_ptr<itti_n11_modify_session_request_smf_requested> sm_context_mod);
  void send_pdu_session_update_sm_context_response(Pistache::Http::ResponseWriter& httpResponse, oai::smf_server::model::SmContextUpdateError& smContextUpdateError, Pistache::Http::Code code);
  //void send_pdu_session_update_sm_context_response(Pistache::Http::ResponseWriter& httpResponse, oai::smf_server::model::SmContextUpdateError& smContextUpdateError, Pistache::Http::Code code, std::string& n1_sm_msg );


  /*
   * Send create session response to AMF
   * @param [Pistache::Http::ResponseWriter] httpResponse
   * @param [ oai::smf_server::model::SmContextCreateError] smContextCreateError
   * @param [Pistache::Http::Code] code, response code
   *
   */
  void send_pdu_session_create_sm_context_response(Pistache::Http::ResponseWriter& httpResponse, oai::smf_server::model::SmContextCreateError& smContextCreateError, Pistache::Http::Code code);

  /*
   * Send create session response to AMF
   * @param [Pistache::Http::ResponseWriter] httpResponse
   * @param [ oai::smf_server::model::SmContextCreateError] smContextCreateError
   * @param [Pistache::Http::Code] code, response code
   * @param [std::string] n1_sm_msg, N1 SM message content
   *
   */
  void send_pdu_session_create_sm_context_response(Pistache::Http::ResponseWriter& httpResponse, oai::smf_server::model::SmContextCreateError& smContextCreateError, Pistache::Http::Code code, std::string& n1_sm_msg );

  /*
    * Send update session response to AMF
    * @param [Pistache::Http::ResponseWriter] httpResponse
    * @param [ oai::smf_server::model::SmContextUpdateError] smContextUpdateError
    * @param [Pistache::Http::Code] code, response code
    * @param [std::string] n1_sm_msg, N1 SM message content
    *
    */
   void send_pdu_session_update_sm_context_response(Pistache::Http::ResponseWriter& httpResponse, oai::smf_server::model::SmContextUpdateError& smContextUpdateError, Pistache::Http::Code code, std::string& n1_sm_msg );



  /*
   * Send create session response to AMF
   * @param [Pistache::Http::ResponseWriter] httpResponse
   * @param [ oai::smf_server::model::SmContextCreatedData] smContextCreatedData
   * @param [Pistache::Http::Code] code, response code
   *
   */
  void send_pdu_session_create_sm_context_response(Pistache::Http::ResponseWriter& httpResponse, oai::smf_server::model::SmContextCreatedData& smContextCreatedData, Pistache::Http::Code code);


};


}
#endif /* FILE_SMF_N11_HPP_SEEN */
