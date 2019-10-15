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

/*! \file pgw_app.hpp
   \author  Lionel GAUTHIER
   \date 2018
   \email: lionel.gauthier@eurecom.fr
*/

#ifndef FILE_PGW_APP_HPP_SEEN
#define FILE_PGW_APP_HPP_SEEN

#include "smf.h"
#include "3gpp_29.274.h"
#include "itti_msg_n4.hpp"
#include "itti_msg_n11.hpp"
#include "pgw_context.hpp"
#include "smf_pco.hpp"
#include "SmContextCreateData.h"
#include "SmContextCreateError.h"
#include "pistache/endpoint.h"
#include "pistache/http.h"
#include "pistache/router.h"
#include "smf_msg.hpp"

extern "C"{
#include "nas_message.h"
#include "mmData.h"
}

#include <map>
#include <set>
#include <shared_mutex>
#include <string>
#include <thread>

namespace pgwc {

class   smf_config; // same namespace

class pgw_app {
private:
  std::thread::id                     thread_id;
  std::thread                         thread;

  //seid generator
  uint64_t                        seid_n4_generator;
  std::mutex                      m_seid_n4_generator;
  std::set<uint64_t>              set_seid_n4;

  std::map<imsi64_t, std::shared_ptr<pgw_context>>  imsi2pgw_context;
  std::map<seid_t, std::shared_ptr<pgw_context>>    seid2pgw_context;

  mutable std::shared_mutex           m_imsi2pgw_context;
  mutable std::shared_mutex           m_seid2pgw_context;

  //for SMF
  std::map<supi64_t, std::shared_ptr<pgw_context>>  supi2pgw_context;
  mutable std::shared_mutex           m_supi2smf_context;


  int apply_config(const smf_config& cfg);

  bool is_imsi64_2_pgw_context(const imsi64_t& imsi64) const;
  std::shared_ptr<pgw_context> imsi64_2_pgw_context(const imsi64_t& imsi64) const;
  void set_imsi64_2_pgw_context(const imsi64_t& imsi64, std::shared_ptr<pgw_context> pc);


  int pco_push_protocol_or_container_id(protocol_configuration_options_t& pco, pco_protocol_or_container_id_t * const poc_id /* STOLEN_REF poc_id->contents*/);
  int process_pco_request_ipcp(protocol_configuration_options_t& pco_resp, const pco_protocol_or_container_id_t * const poc_id);
  int process_pco_dns_server_request(protocol_configuration_options_t& pco_resp, const pco_protocol_or_container_id_t * const poc_id);
  int process_pco_link_mtu_request(protocol_configuration_options_t& pco_resp, const pco_protocol_or_container_id_t * const poc_id);


public:
  explicit pgw_app(const std::string& config_file);
  pgw_app(pgw_app const&)    = delete;
  void operator=(pgw_app const&)     = delete;

  void set_seid_2_pgw_context(const seid_t& seid, std::shared_ptr<pgw_context>& pc);
  bool seid_2_pgw_context(const seid_t& seid, std::shared_ptr<pgw_context>& pc) const;

  void delete_pgw_context(std::shared_ptr<pgw_context> spc);

  int static_paa_get_free_paa (const std::string& apn, paa_t& paa);
  int static_paa_release_address (const std::string& apn, struct in_addr& addr);
  int static_paa_get_num_ipv4_pool(void);
  int static_paa_get_ipv4_pool(const int pool_id, struct in_addr * const range_low, struct in_addr * const range_high, struct in_addr * const netaddr, struct in_addr * const netmask, std::vector<struct in_addr>::iterator& it_out_of_nw);
  int static_paa_get_pool_id(const struct in_addr& ue_addr);

  int process_pco_request(
    const protocol_configuration_options_t& pco_req,
    protocol_configuration_options_t& pco_resp,
    protocol_configuration_options_ids_t & pco_ids);

  void handle_itti_msg (itti_n4_session_establishment_response& m);
  void handle_itti_msg (itti_n4_session_modification_response& m);
  void handle_itti_msg (itti_n4_session_deletion_response& m);
  void handle_itti_msg (std::shared_ptr<itti_n4_session_report_request> snr);
  void handle_itti_msg (itti_n4_association_setup_request& m);

  void restore_sx_sessions(const seid_t& seid) const;

  uint64_t generate_seid();
  bool is_seid_n4_exist(const uint64_t& s) const;
  void free_seid_n4(const uint64_t& seid);

  /*
   * Handle PDUSession_CreateSMContextRequest from AMF
   * @param [std::shared_ptr<itti_n11_create_sm_context_request>&] Request message
   * @return void
   */
   void handle_amf_msg (std::shared_ptr<itti_n11_create_sm_context_request> smreq);
  /*
   * Verify if SM Context is existed for this Supi
   * @param [supi_t] supi
   * @return True if existed, otherwise false
   */
  bool is_supi_2_smf_context(const supi64_t& supi) const;

  /*
   * Create/Update SMF context with the corresponding supi
   * @param [supi_t] supi
   * @param [std::shared_ptr<pgw_context>] sc Shared_ptr Pointer to an SMF context
   * @return True if existed, otherwise false
   */
  void set_supi_2_smf_context(const supi64_t& supi, std::shared_ptr<pgw_context> sc);

  /*
   * Get SM Context
   * @param [supi_t] Supi
   * @return Shared pointer to SM context
   */
  std::shared_ptr<pgw_context>  supi_2_smf_context(const supi64_t& supi) const;

  /*
   * Check whether SMF uses local configuration instead of retrieving Session Management Data from UDM
   * @param [std::string] dnn_selection_mode
   * @return True if SMF uses the local configuration to check the validity of the UE request, False otherwise
   */
  bool use_local_configuration_subscription_data(const std::string& dnn_selection_mode);

  /*
   * Verify whether the Session Management Data is existed
   * @param [supi_t] SUPI
   * @param [std::string] DNN
   * @param [snssai_t] S-NSSAI
   * @return True if SMF uses the local configuration to check the validity of the UE request, False otherwise
   */
  bool is_supi_dnn_snssai_subscription_data(supi_t& supi, std::string& dnn, snssai_t& snssai);

  /*
   * Verify whether the UE request is valid according to the user subscription and with local policies
   * @param [..]
   * @return True if the request is valid, otherwise False
   */
  bool is_create_sm_context_request_valid();

  /*
   * Send create session response to AMF
   * @param [Pistache::Http::ResponseWriter] httpResponse
   * @param [ oai::smf::model::SmContextCreateError] smContextCreateError
   *
   */
  void send_create_session_response(Pistache::Http::ResponseWriter& httpResponse, oai::smf::model::SmContextCreateError& smContextCreateError, Pistache::Http::Code code);

  /*
   * Create N1 SM Container to send to AMF (using NAS lib)
   * @param [std::shared_ptr<itti_n11_create_sm_context_response>] sm_context_res
   * @param [uint8_t] msg_type Type of N1 message
   * @param [std::string&] nas_msg_str store NAS message in form of string
   *
   */
  void create_n1_sm_container(std::shared_ptr<itti_n11_create_sm_context_response> sm_context_res, uint8_t msg_type, std::string& nas_msg_str, uint8_t sm_cause = 0);

  //for testing purpose!!
  void create_n1_sm_container(uint8_t msg_type, std::string& nas_msg_str, uint8_t sm_cause = 0);


  /*
    * Create N1 SM Container to send to AMF (using NAS lib)
    * @param [std::shared_ptr<itti_n11_create_sm_context_request>] sm_context_req
    * @param [uint8_t] msg_type Type of N1 message
    * @param [std::string&] nas_msg_str store NAS message in form of string
    *
    */
   void create_n1_sm_container(std::shared_ptr<itti_n11_create_sm_context_request> sm_context_req, uint8_t msg_type, std::string& nas_msg_str,  uint8_t sm_cause = 0);

  /*
    * Create N2 SM Information to send to AMF (using NAS lib)
    * @param [std::shared_ptr<itti_n11_create_sm_context_response>] sm_context_res
    * @param [uint8_t] msg_type Type of N2 message
    * @param [std::string&] ngap_msg_str store NGAP message in form of string
    *
    */
   void create_n2_sm_information(std::shared_ptr<itti_n11_create_sm_context_response> sm_context_res, uint8_t ngap_msg_type, uint8_t ngap_ie_type, std::string& ngap_msg_str);

   /*
     * Decode N1 SM Container into the NAS mesasge (using NAS lib)
     * @param [nas_message_t&] nas_msg Store NAS message after decoded
     * @param [std::string&] n1_sm_msg N1 SM Container from AMF
     * @return status of the decode process
     */
   uint8_t decode_nas_message_n1_sm_container(nas_message_t& nas_msg, std::string& n1_sm_msg);

};
}
#include "smf_config.hpp"

#endif /* FILE_PGW_APP_HPP_SEEN */
