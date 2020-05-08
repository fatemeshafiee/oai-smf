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

/*! \file smf_app.hpp
 \brief
 \author  Lionel GAUTHIER, Tien-Thinh NGUYEN
 \company Eurecom
 \date 2019
 \email: lionel.gauthier@eurecom.fr, tien-thinh.nguyen@eurecom.fr
 */

#ifndef FILE_SMF_APP_HPP_SEEN
#define FILE_SMF_APP_HPP_SEEN

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
#include "3gpp_29.502.h"
#include "itti_msg_n4.hpp"
#include "itti_msg_n11.hpp"
#include "smf_context.hpp"
#include "smf_pco.hpp"
#include "smf_msg.hpp"
#include "SmContextCreateData.h"
#include "SmContextUpdateData.h"
#include "SmContextCreateError.h"
#include "SmContextUpdateError.h"

namespace smf {

#define TASK_SMF_APP_TRIGGER_T3591     (0)
#define TASK_SMF_APP_TIMEOUT_T3591     (1)
#define TASK_SMF_APP_TRIGGER_T3592     (2)
#define TASK_SMF_APP_TIMEOUT_T3592     (3)

//Table 10.3.2 @3GPP TS 24.501 V16.1.0 (2019-06)
#define T3591_TIMER_VALUE_SEC 16
#define T3591_TIMER_MAX_RETRIES 4
#define T3592_TIMER_VALUE_SEC 16
#define T3592_TIMER_MAX_RETRIES 4


typedef enum {
  PDU_SESSION_ESTABLISHMENT = 1,
  PDU_SESSION_MODIFICATION = 2,
  PDU_SESSION_RELEASE = 3
} pdu_session_procedure_t;

class smf_config;
// same namespace

class smf_context_ref {
 public:
  smf_context_ref() {
    clear();
  }

  void clear() {
    supi = { };
    nssai = { };
    dnn = "";
    pdu_session_id = 0;
  }

  //	std::string toString() const;

  supi_t supi;
  std::string dnn;
  pdu_session_id_t pdu_session_id;
  snssai_t nssai;

};

class smf_app {
 private:
  std::thread::id thread_id;
  std::thread thread;

  //seid generator
  uint64_t seid_n4_generator;
  std::mutex m_seid_n4_generator;
  std::set<uint64_t> set_seid_n4;

  std::map<seid_t, std::shared_ptr<smf_context>> seid2smf_context;
  mutable std::shared_mutex m_seid2smf_context;

  std::map<supi64_t, std::shared_ptr<smf_context>> supi2smf_context;
  mutable std::shared_mutex m_supi2smf_context;

  util::uint_generator<uint32_t> sm_context_ref_generator;

  std::map<scid_t, std::shared_ptr<smf_context_ref>> scid2smf_context;
  mutable std::shared_mutex m_scid2smf_context;

  int apply_config(const smf_config &cfg);

  int pco_push_protocol_or_container_id(
      protocol_configuration_options_t &pco,
      pco_protocol_or_container_id_t *const poc_id /* STOLEN_REF poc_id->contents*/);
  int process_pco_request_ipcp(
      protocol_configuration_options_t &pco_resp,
      const pco_protocol_or_container_id_t *const poc_id);
  int process_pco_dns_server_request(
      protocol_configuration_options_t &pco_resp,
      const pco_protocol_or_container_id_t *const poc_id);
  int process_pco_link_mtu_request(
      protocol_configuration_options_t &pco_resp,
      const pco_protocol_or_container_id_t *const poc_id);

 public:
  explicit smf_app(const std::string &config_file);
  smf_app(smf_app const&) = delete;
  void operator=(smf_app const&) = delete;

  void set_seid_2_smf_context(const seid_t &seid,
                              std::shared_ptr<smf_context> &pc);
  bool seid_2_smf_context(const seid_t &seid,
                          std::shared_ptr<smf_context> &pc) const;

  void delete_smf_context(std::shared_ptr<smf_context> spc);

  int static_paa_get_free_paa(const std::string &apn, paa_t &paa);
  int static_paa_release_address(const std::string &apn, struct in_addr &addr);
  int static_paa_get_num_ipv4_pool(void);
  int static_paa_get_ipv4_pool(
      const int pool_id, struct in_addr *const range_low,
      struct in_addr *const range_high, struct in_addr *const netaddr,
      struct in_addr *const netmask,
      std::vector<struct in_addr>::iterator &it_out_of_nw);
  int static_paa_get_pool_id(const struct in_addr &ue_addr);

  int process_pco_request(const protocol_configuration_options_t &pco_req,
                          protocol_configuration_options_t &pco_resp,
                          protocol_configuration_options_ids_t &pco_ids);

  void handle_itti_msg(itti_n4_session_establishment_response &m);
  void handle_itti_msg(itti_n4_session_modification_response &m);
  void handle_itti_msg(itti_n4_session_deletion_response &m);
  void handle_itti_msg(std::shared_ptr<itti_n4_session_report_request> snr);
  void handle_itti_msg(itti_n4_association_setup_request &m);

  /*
   * Handle ITTI message from N11 to update PDU session status
   * @param [itti_n11_update_pdu_session_status&] itti_n11_update_pdu_session_status
   * @return void
   */
  void handle_itti_msg(itti_n11_update_pdu_session_status &m);

  /*
   * Handle ITTI message from N11 (N1N2MessageTransfer Response)
   * @param [itti_n11_n1n2_message_transfer_response_status&] itti_n11_n1n2_message_transfer_response_status
   * @return void
   */
  void handle_itti_msg(itti_n11_n1n2_message_transfer_response_status &m);

  void restore_n4_sessions(const seid_t &seid) const;

  uint64_t generate_seid();
  bool is_seid_n4_exist(const uint64_t &s) const;
  void free_seid_n4(const uint64_t &seid);

  void generate_smf_context_ref(std::string &smf_ref);
  scid_t generate_smf_context_ref();

  void set_scid_2_smf_context(const scid_t &id,
                              std::shared_ptr<smf_context_ref> scf);
  std::shared_ptr<smf_context_ref> scid_2_smf_context(const scid_t &scid) const;
  bool is_scid_2_smf_context(const scid_t &scid) const;

  /*
   * Handle PDUSession_CreateSMContextRequest from AMF
   * @param [std::shared_ptr<itti_n11_create_sm_context_request>&] Request message
   * @return void
   */
  void handle_pdu_session_create_sm_context_request(
      std::shared_ptr<itti_n11_create_sm_context_request> smreq);

  /*
   * Handle PDUSession_UpdateSMContextRequest from AMF
   * @param [std::shared_ptr<itti_n11_update_sm_context_request>&] Request message
   * @return void
   */
  void handle_pdu_session_update_sm_context_request(
      std::shared_ptr<itti_n11_update_sm_context_request> smreq);

  /*
   * Handle PDUSession_ReleaseSMContextRequest from AMF
   * @param [std::shared_ptr<itti_n11_release_sm_context_request>&] Request message
   * @return void
   */
  void handle_pdu_session_release_sm_context_request(
      std::shared_ptr<itti_n11_release_sm_context_request> smreq);

  /*
   * Trigger pdu session modification
   * @param should be updated
   * @return void
   */
  void trigger_pdu_session_modification();

  /*
   * Verify if SM Context is existed for this Supi
   * @param [supi_t] supi
   * @return True if existed, otherwise false
   */
  bool is_supi_2_smf_context(const supi64_t &supi) const;

  /*
   * Create/Update SMF context with the corresponding supi
   * @param [supi_t] supi
   * @param [std::shared_ptr<smf_context>] sc Shared_ptr Pointer to an SMF context
   * @return True if existed, otherwise false
   */
  void set_supi_2_smf_context(const supi64_t &supi,
                              std::shared_ptr<smf_context> sc);

  /*
   * Get SM Context
   * @param [supi_t] Supi
   * @return Shared pointer to SM context
   */
  std::shared_ptr<smf_context> supi_2_smf_context(const supi64_t &supi) const;

  /*
   * Check whether SMF uses local configuration instead of retrieving Session Management Data from UDM
   * @param [std::string] dnn_selection_mode
   * @return True if SMF uses the local configuration to check the validity of the UE request, False otherwise
   */
  bool use_local_configuration_subscription_data(
      const std::string &dnn_selection_mode);

  /*
   * Verify whether the Session Management Data is existed
   * @param [supi_t] SUPI
   * @param [std::string] DNN
   * @param [snssai_t] S-NSSAI
   * @return True if SMF uses the local configuration to check the validity of the UE request, False otherwise
   */
  bool is_supi_dnn_snssai_subscription_data(supi_t &supi, std::string &dnn,
                                            snssai_t &snssai);

  /*
   * Verify whether the UE request is valid according to the user subscription and with local policies
   * @param [..]
   * @return True if the request is valid, otherwise False
   */
  bool is_create_sm_context_request_valid();

  /*
   * Convert a string to hex representing this string
   * @param [std::string&] input_str Input string
   * @param [std::string&] output_str String represents string in hex format
   * @return void
   */
  void convert_string_2_hex(std::string &input_str, std::string &output_str);

  unsigned char* format_string_as_hex(std::string str);

  void start_upf_association(const pfcp::node_id_t &node_id);

  /*
   * Update PDU session status
   * @param [const scid_t] id SM Context ID
   * @param [const pdu_session_status_e] status PDU Session Status
   * @return void
   */
  void update_pdu_session_status(const scid_t id,
                                 const pdu_session_status_e status);

  /*
   * Update PDU session UpCnxState
   * @param [const scid_t] id SM Context ID
   * @param [const upCnx_state_e] status PDU Session UpCnxState
   * @return void
   */
  void update_pdu_session_upCnx_state(const scid_t scid,
                                          const upCnx_state_e state);

  void timer_t3591_timeout(timer_id_t timer_id, uint64_t arg2_user);
  n2_sm_info_type_e n2_sm_info_type_str2e(std::string n2_info_type);

};
}
#include "smf_config.hpp"

#endif /* FILE_SMF_APP_HPP_SEEN */
