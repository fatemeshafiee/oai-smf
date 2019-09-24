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
#include "itti_msg_s5s8.hpp"
#include "itti_msg_sxab.hpp"
#include "pgw_context.hpp"
#include "pgw_pco.hpp"
#include "SmContextCreateData.h"
#include "SmContextCreateError.h"
#include "pistache/endpoint.h"
#include "pistache/http.h"
#include "pistache/router.h"
#include "smf_msg.hpp"

extern "C" {
#include "sm_msg.h"
}

#include <map>
#include <set>
#include <shared_mutex>
#include <string>
#include <thread>

namespace pgwc {

//typedef std::pair<shared_ptr<pgw_context>,shared_ptr<pgw_pdn_connection>> zzz;
class   pgw_config; // same namespace

class pgw_app {
private:
  std::thread::id                     thread_id;
  std::thread                         thread;
  // teid generators (linear)
  teid_t                        teid_s5s8_cp_generator;

  std::map<imsi64_t, std::shared_ptr<pgw_context>>  imsi2pgw_context;
  std::map<teid_t, std::shared_ptr<pgw_context>>    s5s8lteid2pgw_context;
  std::map<seid_t, std::shared_ptr<pgw_context>>    seid2pgw_context;

  std::set<teid_t>              s5s8cplteid;

  std::mutex                          m_s5s8_cp_teid_generator;

  mutable std::shared_mutex           m_imsi2pgw_context;
  mutable std::shared_mutex           m_s5s8lteid2pgw_context;
  mutable std::shared_mutex           m_seid2pgw_context;

  //for SMF
  std::map<supi64_t, std::shared_ptr<pgw_context>>  supi2pgw_context;
  mutable std::shared_mutex           m_supi2smf_context;


  int apply_config(const pgw_config& cfg);

  teid_t generate_s5s8_cp_teid();
  void free_s5s8c_teid(const teid_t& teid_s5s8_cp);
  bool is_s5s8c_teid_exist(const teid_t& teid_s5s8_cp) const;
  //teid_t generate_s5s8_up_teid();
  //void free_s5s8u_teid(const teid_t& teid_s5s8_up);
  //bool is_s5s8u_teid_exist(teid_t& teid_s5s8_up);

  // s5s8crteid2pgw_eps_bearer_context collection
  bool is_s5s8cpgw_fteid_2_pgw_context(const fteid_t& ls5s8_fteid) const;
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

  void send_create_session_response_cause (const uint64_t gtpc_tx_id, const teid_t teid, const endpoint& r_endpoint, const cause_t &cause) const;
  void send_delete_session_response_cause_request_accepted (const uint64_t gtpc_tx_id, const teid_t teid, const endpoint& r_endpoint) const;
  void send_delete_session_response_cause_context_not_found (const uint64_t gtpc_tx_id, const teid_t teid, const endpoint& r_endpoint) const;
  void send_modify_bearer_response_cause_context_not_found (const uint64_t gtpc_tx_id, const teid_t teid, const endpoint& r_endpoint) const;
  void send_release_access_bearers_response_cause_context_not_found(const uint64_t gtpc_tx_id, const teid_t teid, const endpoint& r_endpoint) const;
  void send_release_access_bearers_response_cause_request_accepted(const uint64_t gtpc_tx_id, const teid_t teid, const endpoint& r_endpoint) const;

  fteid_t build_s5s8_cp_fteid(const struct in_addr ipv4_address, const teid_t teid);
  fteid_t generate_s5s8_cp_fteid(const struct in_addr ipv4_address);
  void free_s5s8_cp_fteid(const fteid_t& fteid);
  void set_s5s8cpgw_fteid_2_pgw_context(fteid_t& rs5s8_fteid, std::shared_ptr<pgw_context> spc);
  std::shared_ptr<pgw_context> s5s8cpgw_fteid_2_pgw_context(fteid_t& ls5s8_fteid);

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

  void handle_itti_msg (std::shared_ptr<itti_s5s8_create_session_request> m);
  void handle_itti_msg (std::shared_ptr<itti_s5s8_delete_session_request> m);
  void handle_itti_msg (std::shared_ptr<itti_s5s8_modify_bearer_request> m);
  void handle_itti_msg (std::shared_ptr<itti_s5s8_release_access_bearers_request> m);
  void handle_itti_msg (itti_s5s8_downlink_data_notification_acknowledge& m);
  void handle_itti_msg (itti_sxab_session_establishment_response& m);
  void handle_itti_msg (itti_sxab_session_modification_response& m);
  void handle_itti_msg (itti_sxab_session_deletion_response& m);
  void handle_itti_msg (std::shared_ptr<itti_sxab_session_report_request> snr);
  void handle_itti_msg (itti_sxab_association_setup_request& m);

  void restore_sx_sessions(const seid_t& seid) const;

  /*
   * Handle PDUSession_CreateSMContextRequest from AMF
   * @param [std::shared_ptr<pdu_session_create_sm_context_request>&] sm_context_req_msg Request message
   * @param [Pistache::Http::ResponseWriter& ] httpResponse To send a response to AMF
   * @return void
   */
  void handle_amf_msg(std::shared_ptr<pdu_session_create_sm_context_request>& sm_context_req_msg, Pistache::Http::ResponseWriter &httpResponse);

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
  bool is_use_local_configuration_subscription_data(const std::string& dnn_selection_mode);

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

};
}
#include "pgw_config.hpp"

#endif /* FILE_PGW_APP_HPP_SEEN */
