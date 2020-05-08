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

/*! \file smf_context.hpp
 \brief
 \author  Lionel GAUTHIER, Tien-Thinh NGUYEN
 \company Eurecom
 \date 2019
 \email: lionel.gauthier@eurecom.fr, tien-thinh.nguyen@eurecom.fr
 */

#ifndef FILE_SMF_CONTEXT_HPP_SEEN
#define FILE_SMF_CONTEXT_HPP_SEEN

#include <map>
//#include <mutex>
#include <shared_mutex>
#include <memory>
#include <utility>
#include <vector>

#include "pistache/endpoint.h"
#include "pistache/http.h"
#include "pistache/router.h"
#include "3gpp_24.008.h"
#include "3gpp_29.274.h"
#include "3gpp_29.244.h"
#include "3gpp_29.503.h"
#include "3gpp_29.502.h"
#include "common_root_types.h"
#include "itti.hpp"
#include "msg_pfcp.hpp"
#include "smf_procedure.hpp"
#include "uint_generator.hpp"
#include "SmContextCreateData.h"
#include "SmContextCreateError.h"

extern "C" {
#include "QOSRules.h"
#include "QOSFlowDescriptions.h"
#include "PDUSessionEstablishmentAccept.h"
#include "Ngap_PDUSessionAggregateMaximumBitRate.h"

}

namespace smf {

class smf_qos_flow {
 public:
  smf_qos_flow() {
    clear();
  }

  void clear() {
    ul_fteid = { };
    dl_fteid = { };
    pdr_id_ul = { };
    pdr_id_dl = { };
    precedence = { };
    far_id_ul = { };
    far_id_dl = { };
    released = false;
    qos_profile = {};
  }

  void deallocate_ressources();
  void release_qos_flow();
  std::string toString() const;

  pfcp::qfi_t qfi;  //QoS Flow Identifier

  fteid_t ul_fteid;  //fteid of UPF
  fteid_t dl_fteid;  //fteid of AN

  // PFCP
  // Packet Detection Rule ID
  pfcp::pdr_id_t pdr_id_ul;
  pfcp::pdr_id_t pdr_id_dl;
  pfcp::precedence_t precedence;
  std::pair<bool, pfcp::far_id_t> far_id_ul;
  std::pair<bool, pfcp::far_id_t> far_id_dl;

  bool released;  // finally seems necessary, TODO try to find heuristic ?

  pdu_session_id_t pdu_session_id;
  qos_profile_t qos_profile;   //QoS profile
  uint8_t cause_value;   //cause

};

class smf_pdu_session : public std::enable_shared_from_this<smf_pdu_session> {
 public:
  smf_pdu_session() {
    clear();
  }

  void clear() {
    ipv4 = false;
    ipv6 = false;
    ipv4_address.s_addr = INADDR_ANY;
    ipv6_address = in6addr_any;
    pdn_type = { };
    default_bearer.ebi = EPS_BEARER_IDENTITY_UNASSIGNED;
    seid = 0;
    up_fseid = { };
    qos_flows.clear();
    released = false;
    default_qfi.qfi = NO_QOS_FLOW_IDENTIFIER_ASSIGNED ;
    pdu_session_status = pdu_session_status_e::PDU_SESSION_INACTIVE;
    timer_T3590 = ITTI_INVALID_TIMER_ID;
    timer_T3591 = ITTI_INVALID_TIMER_ID;
    timer_T3592 = ITTI_INVALID_TIMER_ID;
  }

  smf_pdu_session(smf_pdu_session &b) = delete;

  void set(const paa_t &paa);
  void get_paa(paa_t &paa);

  bool get_qos_flow(const pfcp::pdr_id_t &pdr_id, smf_qos_flow &q);
  bool get_qos_flow(const pfcp::far_id_t &far_id, smf_qos_flow &q);
  bool get_qos_flow(const pfcp::qfi_t &qfi, smf_qos_flow &q);
  void add_qos_flow(smf_qos_flow &flow);
  void get_qos_flows(std::vector<smf_qos_flow> &flows);
  void set_default_qos_flow(const pfcp::qfi_t &qfi);

  bool find_qos_flow(const pfcp::pdr_id_t &pdr_id, smf_qos_flow &flow);
  bool has_qos_flow(const pfcp::pdr_id_t &pdr_id, pfcp::qfi_t &qfi);
  void remove_qos_flow(const pfcp::qfi_t &qfi);
  void remove_qos_flow(smf_qos_flow &flow);

  void set_pdu_session_status(const pdu_session_status_e &status);
  pdu_session_status_e get_pdu_session_status() const;

  /*
   * Set upCnxState for a N3 Tunnel
   * @param [upCnx_state_e&] state: new state of the N3 tunnel
   * @return void
   */
  void set_upCnx_state(const upCnx_state_e &state);

  /*
   * Get upCnxState of a N3 Tunnel
   * @param void
   * @return upCnx_state_e: current state of this N3 tunnel
   */
  upCnx_state_e get_upCnx_state() const;

  // Called by GTPV2-C DELETE_SESSION_REQUEST
  // deallocate_ressources is for releasing LTE resources prior to the deletion of objects
  // since shared_ptr is actually heavy used for handling objects, deletion of object instances cannot be always guaranteed
  // when removing them from a collection, so that is why actually the deallocation of resources is not done in the destructor of objects.
  void deallocate_ressources(const std::string &apn);

  std::string toString() const;

  void generate_seid();
  void set_seid(const uint64_t &seid);
  void generate_pdr_id(pfcp::pdr_id_t &pdr_id);
  void release_pdr_id(const pfcp::pdr_id_t &pdr_id);
  void generate_far_id(pfcp::far_id_t &far_id);
  void release_far_id(const pfcp::far_id_t &far_id);
  void insert_procedure(smf_procedure *proc);

  void generate_qos_rule_id(uint8_t &rule_id);
  void release_qos_rule_id(const uint8_t &rule_id);
  void get_qos_rules_to_be_synchronised(std::vector<QOSRulesIE> &qos_rules) const;

  /*
   * Get list of QoS rules associated with a given QFI
   * @param [pfcp::qfi_t] qfi
   * @param [std::vector<QOSRulesIE> &] rules
   * @void
   */
  void get_qos_rules(pfcp::qfi_t qfi,
      std::vector<QOSRulesIE> &rules) const;

  /*
   * Get default QoS Rule associated with this PDU Session
   * @param [QOSRulesIE &] qos_rule
   * @void
   */
  bool get_default_qos_rule(QOSRulesIE &qos_rule) const;
  bool get_qos_rule(uint8_t rule_id, QOSRulesIE &qos_rule) const;
  void update_qos_rule(QOSRulesIE qos_rule);
  void add_qos_rule(QOSRulesIE qos_rule);

  pdn_type_t get_pdn_type() const;

  bool ipv4;                  // IP Address(es): IPv4 address and/or IPv6 prefix
  bool ipv6;                  // IP Address(es): IPv4 address and/or IPv6 prefix
  struct in_addr ipv4_address;  // IP Address(es): IPv4 address and/or IPv6 prefix
  struct in6_addr ipv6_address;  // IP Address(es): IPv4 address and/or IPv6 prefix
  pdn_type_t pdn_type;            // IPv4, IPv6, IPv4v6 or Non-IP
  ebi_t default_bearer;  //Default Bearer: Identifies the default bearer within the PDN connection by its EPS Bearer Id.

  bool released;  //(release access bearers request)

  //----------------------------------------------------------------------------
  // PFCP related members
  //----------------------------------------------------------------------------
  // PFCP Session
  uint64_t seid;
  pfcp::fseid_t up_fseid;
  //
  util::uint_generator<uint16_t> pdr_id_generator;
  util::uint_generator<uint32_t> far_id_generator;

  uint32_t pdu_session_id;
  std::string amf_id;
  // QFI <-> QoS Flow
  std::map<uint8_t, smf_qos_flow> qos_flows;
  pfcp::qfi_t default_qfi;
  // QFI <-> QoS Rules
  std::map<uint8_t, QOSRulesIE> qos_rules;
  std::vector<uint8_t> qos_rules_to_be_synchronised;
  std::vector<uint8_t> qos_rules_to_be_removed;
  pdu_session_status_e pdu_session_status;
  timer_id_t timer_T3590;
  timer_id_t timer_T3591;
  timer_id_t timer_T3592;
  //N3 tunnel status (ACTIVATED, DEACTIVATED, ACTIVATING)
  upCnx_state_e upCnx_state;
  //5GSM parameters and capabilities
  uint8_t maximum_number_of_supported_packet_filters;
  //TODO: 5GSM Capability (section 9.11.4.1@3GPP TS 24.501 V16.1.0)
  //TODO: Integrity protection maximum data rate (section 9.11.4.7@@3GPP TS 24.501 V16.1.0)
  //number_of_supported_packet_filters
  uint8_t number_of_supported_packet_filters;
  util::uint_generator<uint32_t> qos_rule_id_generator;

};

class session_management_subscription {
 public:
  session_management_subscription(snssai_t snssai)
      :
      single_nssai(snssai),
      dnn_configurations() {
  }
  void insert_dnn_configuration(
      std::string dnn, std::shared_ptr<dnn_configuration_t> &dnn_configuration);
  void find_dnn_configuration(
      std::string dnn, std::shared_ptr<dnn_configuration_t> &dnn_configuration);
 private:
  snssai_t single_nssai;
  //dnn <->dnn_configuration
  std::map<std::string, std::shared_ptr<dnn_configuration_t>> dnn_configurations;
};

/*
 * Manage the DNN context
 */
class dnn_context {

 public:
  dnn_context()
      :
      m_context(),
      in_use(false),
      pdu_sessions(),
      nssai() {
  }

  dnn_context(std::string dnn)
      :
      m_context(),
      in_use(false),
      pdu_sessions(),
      nssai(),
      dnn_in_use(dnn) {
    // apn_ambr = {0};
  }
  dnn_context(dnn_context &b) = delete;

  /* Find the PDU Session */
  bool find_pdu_session(const uint32_t pdu_session_id,
                        std::shared_ptr<smf_pdu_session> &pdu_session);

  //void create_or_update_qos_rule(QOSRulesIE &qos_rule, pfcp::qfi_t qfi,
  //                                            pdu_session_id_t pdu_id);

  /* Insert a PDU Session into the DNN context */
  void insert_pdu_session(std::shared_ptr<smf_pdu_session> &sp);
  /* get number of pdu sessions associated with this context (dnn and Nssai) */
  size_t get_number_pdu_sessions();

  std::string toString() const;

  bool in_use;
  std::string dnn_in_use;   // The APN currently used, as received from the SGW.
  //ambr_t  apn_ambr;                 // APN AMBR: The maximum aggregated uplink and downlink MBR values to be shared across all Non-GBR bearers, which are established for this APN.
  snssai_t nssai;
  /* Store all PDU Sessions associated with this DNN context */
  std::vector<std::shared_ptr<smf_pdu_session>> pdu_sessions;
  mutable std::recursive_mutex m_context;
};

class smf_context;

class smf_context : public std::enable_shared_from_this<smf_context> {

 public:
  smf_context()
      :
      m_context(),
      imsi(),
      imsi_unauthenticated_indicator(false),
      pending_procedures(),
      msisdn(),
      dnn_subscriptions(),
      scid(0) {
  }

  smf_context(smf_context &b) = delete;

  void insert_procedure(std::shared_ptr<smf_procedure> &sproc);
  bool find_procedure(const uint64_t &trxn_id,
                      std::shared_ptr<smf_procedure> &proc);
  void remove_procedure(smf_procedure *proc);

#define IS_FIND_PDN_WITH_LOCAL_TEID true
#define IS_FIND_PDN_WITH_PEER_TEID  false

  bool find_pdu_session(const pfcp::pdr_id_t &pdr_id,
                        std::shared_ptr<smf_pdu_session> &pdn, ebi_t &ebi);

  void handle_itti_msg(itti_n4_session_establishment_response&);
  void handle_itti_msg(itti_n4_session_modification_response&);
  void handle_itti_msg(itti_n4_session_deletion_response&);
  void handle_itti_msg(std::shared_ptr<itti_n4_session_report_request>&);

  /*
   * Handle messages from AMF (e.g., PDU_SESSION_CreateSMContextRequest)
   * @param [std::shared_ptr<itti_n11_create_sm_context_request] smreq Request message
   * @return void
   */
  void handle_pdu_session_create_sm_context_request(
      std::shared_ptr<itti_n11_create_sm_context_request> smreq);

  /*
   * Handle messages from AMF (e.g., PDU_SESSION_UpdateSMContextRequest)
   * @param [std::shared_ptr<itti_n11_update_sm_context_request] smreq Request message
   * @return void
   */
  void handle_pdu_session_update_sm_context_request(
      std::shared_ptr<itti_n11_update_sm_context_request> smreq);

  /*
   * Handle messages from AMF (e.g., PDU_SESSION_ReleaseSMContextRequest)
   * @param [std::shared_ptr<itti_n11_release_sm_context_request] smreq Request message
   * @return void
   */
  void handle_pdu_session_release_sm_context_request(
      std::shared_ptr<itti_n11_release_sm_context_request> smreq);

  void handle_pdu_session_modification_network_requested(
      std::shared_ptr<itti_nx_trigger_pdu_session_modification> msg);

  /*
   * Find DNN context with name
   * @param [const std::string&] dnn
   * @param [std::shared_ptr<dnn_context>&] dnn_context dnn context to be found
   * @return void
   */
  bool find_dnn_context(const snssai_t &nssai, const std::string &dnn,
                        std::shared_ptr<dnn_context> &dnn_context);

  /*
   * Insert a DNN context into SMF context
   * @param [std::shared_ptr<dnn_context>&] sd Shared_ptr pointer to a DNN context
   * @return void
   */
  void insert_dnn(std::shared_ptr<dnn_context> &sd);

  /*
   * Check the validity of the request according to user subscription and local policies
   * @param [std::shared_ptr<itti_n11_create_sm_context_request>] smreq
   * @return true if the request is valid, otherwise return false
   *
   */
  bool verify_sm_context_request(
      std::shared_ptr<itti_n11_create_sm_context_request> smreq);

  /*
   * Insert a session management subscription into the SMF context
   * @param [const snssai_t&] snssai
   * @param [std::shared_ptr<session_management_subscription>&] ss: pointer to the subscription
   * @return void
   */
  void insert_dnn_subscription(
      const snssai_t &snssai,
      std::shared_ptr<session_management_subscription> &ss);

  /*
   * Find a session management subscription from a SMF context
   * @param [const snssai_t&] snssai
   * @param [std::shared_ptr<session_management_subscription>&] ss: pointer to the subscription
   * @return void
   */
  bool find_dnn_subscription(
      const snssai_t &snssai,
      std::shared_ptr<session_management_subscription> &ss);

  /*
   * Convert all members of this class to string for logging
   * @return std::string
   */
  std::string toString() const;

  /*
   * Get the default QoS from the subscription
   * @param [const snssai_t&] snssai
   * @param [const std::string&] dnn
   * @param [subscribed_default_qos_t] default_qos
   * @return void
   */
  void get_default_qos(const snssai_t &snssai, const std::string &dnn,
                       subscribed_default_qos_t &default_qos);

  /*
   * Set the value for Supi
   * @param [const supi_t&] s
   * @return void
   */
  void set_supi(const supi_t &s);

  /*
   * Get Supi member
   * @param
   * @return supi_t
   */
  supi_t get_supi() const;

  /*
   * Get the number of dnn contexts
   * @param
   * @return std::size_t: the number of contexts
   */
  std::size_t get_number_dnn_contexts();
  void set_scid(scid_t const &id);
  scid_t get_scid() const;

  /*
   * Get the default QoS Rule for all QFIs
   * @param [QOSRulesIE] qos_rule
   * @return void
   */
  void get_default_qos_rule(QOSRulesIE &qos_rule, uint8_t pdu_session_type);

  void get_default_qos_flow_description(
      QOSFlowDescriptionsContents &qos_flow_description,
      uint8_t pdu_session_type,
      const pfcp::qfi_t &qfi);

  void get_session_ambr(SessionAMBR &session_ambr, const snssai_t &snssai,
                        const std::string &dnn);
  void get_session_ambr(Ngap_PDUSessionAggregateMaximumBitRate_t &session_ambr,
                        const snssai_t &snssai, const std::string &dnn);

 private:

  std::vector<std::shared_ptr<dnn_context>> dnns;
  imsi_t imsi;  // IMSI (International Mobile Subscriber Identity) is the subscriber permanent identity.
  bool imsi_unauthenticated_indicator;  // This is an IMSI indicator to show the IMSI is unauthenticated.
  // TO BE CHECKED me_identity_t    me_identity;       // Mobile Equipment Identity (e.g. IMEI/IMEISV).
  msisdn_t msisdn;  // The basic MSISDN of the UE. The presence is dictated by its storage in the HSS.
  //  selected_cn_operator_id                          // Selected core network operator identity (to support networksharing as defined in TS 23.251
  // NOT IMPLEMENTED RAT type  Current RAT (implicit)
  // NOT IMPLEMENTED Trace reference                        // Identifies a record or a collection of records for a particular trace.
  // NOT IMPLEMENTED Trace type                             // Indicates the type of trace
  // NOT IMPLEMENTED Trigger id                             // Identifies the entity that initiated the trace
  // NOT IMPLEMENTED OMC identity                           // Identifies the OMC that shall receive the trace record(s).

  //--------------------------------------------
  // internals
  std::vector<std::shared_ptr<smf_procedure>> pending_procedures;

  // Big recursive lock
  mutable std::recursive_mutex m_context;

  // snssai-sst <-> session management subscription
  std::map<uint8_t, std::shared_ptr<session_management_subscription>> dnn_subscriptions;

  supi_t supi;
  scid_t scid;

};
}

#endif
