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

/*! \file smf_msg.cpp
 \brief
 \author  Tien-Thinh NGUYEN
 \company Eurecom
 \date 2019
 \email: tien-thinh.nguyen@eurecom.fr
 */
#include "smf_msg.hpp"

using namespace smf;

//-----------------------------------------------------------------------------
void qos_flow_context_updated::set_cause(const uint8_t cause) {
  cause_value = cause;
}

//-----------------------------------------------------------------------------
void qos_flow_context_updated::set_qfi(const pfcp::qfi_t &q) {
  qfi = q;
}

//-----------------------------------------------------------------------------
void qos_flow_context_updated::set_ul_fteid(const fteid_t &teid) {
  ul_fteid = teid;
}

//-----------------------------------------------------------------------------
void qos_flow_context_updated::set_dl_fteid(const fteid_t &teid) {
  dl_fteid = teid;
}

//-----------------------------------------------------------------------------
void qos_flow_context_updated::add_qos_rule(const QOSRulesIE &rule) {
  uint8_t rule_id = rule.qosruleidentifer;
  if ((rule_id >= QOS_RULE_IDENTIFIER_FIRST )
      and (rule_id <= QOS_RULE_IDENTIFIER_LAST )) {
    qos_rules.erase(rule_id);
    qos_rules.insert(std::pair<uint8_t, QOSRulesIE>(rule_id, rule));
    Logger::smf_app().trace(
        "qos_flow_context_updated::add_qos_rule(%d) success", rule_id);
  }
}

void qos_flow_context_updated::set_qos_profile(const qos_profile_t &profile) {
  qos_profile = profile;
}

//-----------------------------------------------------------------------------
void qos_flow_context_updated::set_priority_level(uint8_t p) {
  //priority_level = p;
  qos_profile.priority_level = p;
}

//-----------------------------------------------------------------------------
pdu_session_msg_type_t pdu_session_msg::get_msg_type() const {
  return m_msg_type;
}

//-----------------------------------------------------------------------------
void pdu_session_msg::set_msg_type(pdu_session_msg_type_t const &msg_type) {
  m_msg_type = msg_type;
}

//-----------------------------------------------------------------------------
supi_t pdu_session_msg::get_supi() const {
  return m_supi;
}

//-----------------------------------------------------------------------------
void pdu_session_msg::set_supi(supi_t const &supi) {
  m_supi = supi;
}

//-----------------------------------------------------------------------------
std::string pdu_session_msg::get_supi_prefix() const {
  return m_supi_prefix;
}

//-----------------------------------------------------------------------------
void pdu_session_msg::set_supi_prefix(std::string const &prefix) {
  m_supi_prefix = prefix;
}

//-----------------------------------------------------------------------------
pdu_session_id_t pdu_session_msg::get_pdu_session_id() const {
  return m_pdu_session_id;
}

//-----------------------------------------------------------------------------
void pdu_session_msg::set_pdu_session_id(
    pdu_session_id_t const pdu_session_id) {
  m_pdu_session_id = pdu_session_id;
}

//-----------------------------------------------------------------------------
std::string pdu_session_msg::get_dnn() const {
  return m_dnn;
}

//-----------------------------------------------------------------------------
void pdu_session_msg::set_dnn(std::string const &dnn) {
  m_dnn = dnn;
}

//-----------------------------------------------------------------------------
snssai_t pdu_session_msg::get_snssai() const {
  return m_snssai;
}

//-----------------------------------------------------------------------------
void pdu_session_msg::set_snssai(snssai_t const &snssai) {
  m_snssai = snssai;
}

//-----------------------------------------------------------------------------
void pdu_session_msg::set_api_root(std::string const &value) {
  m_api_root = value;
}

std::string pdu_session_msg::get_api_root() const {
  return m_api_root;
}

//-----------------------------------------------------------------------------
uint8_t pdu_session_msg::get_pdu_session_type() const {
  return m_pdu_session_type;
}

//-----------------------------------------------------------------------------
void pdu_session_msg::set_pdu_session_type(uint8_t const &pdu_session_type) {
  m_pdu_session_type = pdu_session_type;
}

//-----------------------------------------------------------------------------
procedure_transaction_id_t pdu_session_msg::get_pti() const {
  return m_pti;
}

//-----------------------------------------------------------------------------
void pdu_session_msg::set_pti(procedure_transaction_id_t const &pti) {
  m_pti = pti;
}

//-----------------------------------------------------------------------------
extended_protocol_discriminator_t pdu_session_create_sm_context::get_epd() const {
  return m_epd;
}

//-----------------------------------------------------------------------------
void pdu_session_create_sm_context::set_epd(
    extended_protocol_discriminator_t const &epd) {
  m_epd = epd;
}

//-----------------------------------------------------------------------------
uint8_t pdu_session_create_sm_context::get_message_type() const {
  return m_message_type;
}

//-----------------------------------------------------------------------------
void pdu_session_create_sm_context::set_message_type(
    uint8_t const &message_type) {
  m_message_type = message_type;
}

//-----------------------------------------------------------------------------
std::string pdu_session_create_sm_context_request::get_n1_sm_message() const {
  return m_n1_sm_message;
}

//-----------------------------------------------------------------------------
void pdu_session_create_sm_context_request::set_n1_sm_message(
    std::string const &value) {
  m_n1_sm_message = value;
}

//-----------------------------------------------------------------------------
std::string pdu_session_create_sm_context_request::get_serving_nf_id() const {
  return m_serving_nf_id;
}

//-----------------------------------------------------------------------------
void pdu_session_create_sm_context_request::set_serving_nf_id(
    std::string const &serving_nf_id) {
  m_serving_nf_id = serving_nf_id;
}

//-----------------------------------------------------------------------------
std::string pdu_session_create_sm_context_request::get_request_type() const {
  return m_request_type;
}

//-----------------------------------------------------------------------------
void pdu_session_create_sm_context_request::set_request_type(
    std::string const &request_type) {
  m_request_type = request_type;
}

//-----------------------------------------------------------------------------
void pdu_session_create_sm_context_request::set_dnn_selection_mode(
    std::string const &dnn_selection_mode) {
  m_dnn_selection_mode = dnn_selection_mode;
}

//-----------------------------------------------------------------------------
std::string pdu_session_create_sm_context_request::get_dnn_selection_mode() const {
  return m_dnn_selection_mode;
}

//-----------------------------------------------------------------------------
void pdu_session_create_sm_context_response::set_cause(uint8_t cause) {
  m_cause = cause;
}

//-----------------------------------------------------------------------------
uint8_t pdu_session_create_sm_context_response::get_cause() {
  return m_cause;
}

//-----------------------------------------------------------------------------
void pdu_session_create_sm_context_response::set_paa(paa_t paa) {
  m_paa = paa;
}

//-----------------------------------------------------------------------------
paa_t pdu_session_create_sm_context_response::get_paa() {
  return m_paa;
}

//-----------------------------------------------------------------------------
void pdu_session_create_sm_context_response::set_http_code(
    Pistache::Http::Code code) {
  m_code = code;
}

//-----------------------------------------------------------------------------
Pistache::Http::Code pdu_session_create_sm_context_response::get_http_code() {
  return m_code;
}

//-----------------------------------------------------------------------------
void pdu_session_create_sm_context_response::set_qos_flow_context(
    const qos_flow_context_updated &qos_flow) {
  qos_flow_context = qos_flow;
}

//-----------------------------------------------------------------------------
qos_flow_context_updated pdu_session_create_sm_context_response::get_qos_flow_context() const {
  return qos_flow_context;
}

//-----------------------------------------------------------------------------
std::string pdu_session_create_sm_context_response::get_n2_sm_information() const {
  return m_n2_sm_information;
}

//-----------------------------------------------------------------------------
void pdu_session_create_sm_context_response::set_n2_sm_information(
    std::string const &value) {
  m_n2_sm_information = value;
  m_n2_sm_info_is_set = true;
}

//-----------------------------------------------------------------------------
std::string pdu_session_create_sm_context_response::get_n1_sm_message() const {
  return m_n1_sm_message;
}

//-----------------------------------------------------------------------------
void pdu_session_create_sm_context_response::set_n1_sm_message(
    std::string const &value) {
  m_n1_sm_message = value;
  m_n1_sm_msg_is_set = true;
}

//-----------------------------------------------------------------------------
bool pdu_session_create_sm_context_response::n1_sm_msg_is_set() const {
  return m_n1_sm_msg_is_set;
}

//-----------------------------------------------------------------------------
bool pdu_session_create_sm_context_response::n2_sm_info_is_set() const {
  return m_n2_sm_info_is_set;
}

//-----------------------------------------------------------------------------
void pdu_session_create_sm_context_response::set_amf_url(
    std::string const &value) {
  amf_url = value;
}

//-----------------------------------------------------------------------------
std::string pdu_session_create_sm_context_response::get_amf_url() const {
  return amf_url;
}

//-----------------------------------------------------------------------------
std::string pdu_session_update_sm_context::get_n2_sm_information() const {
  return m_n2_sm_information;
}

//-----------------------------------------------------------------------------
void pdu_session_update_sm_context::set_n2_sm_information(
    std::string const &value) {
  m_n2_sm_information = value;
  m_n2_sm_info_is_set = true;
}

//-----------------------------------------------------------------------------
std::string pdu_session_update_sm_context::get_n2_sm_info_type() const {
  return m_n2_sm_info_type;
}

//-----------------------------------------------------------------------------
void pdu_session_update_sm_context::set_n2_sm_info_type(
    std::string const &value) {
  m_n2_sm_info_type = value;
  m_n2_sm_info_is_set = true;
}

//-----------------------------------------------------------------------------
std::string pdu_session_update_sm_context::get_n1_sm_message() const {
  return m_n1_sm_message;
}

//-----------------------------------------------------------------------------
void pdu_session_update_sm_context::set_n1_sm_message(
    std::string const &value) {
  m_n1_sm_message = value;
  m_n1_sm_msg_is_set = true;
}

//-----------------------------------------------------------------------------
bool pdu_session_update_sm_context::n1_sm_msg_is_set() const {
  return m_n1_sm_msg_is_set;
}

//-----------------------------------------------------------------------------
bool pdu_session_update_sm_context::n2_sm_info_is_set() const {
  return m_n2_sm_info_is_set;
}

//-----------------------------------------------------------------------------
void pdu_session_update_sm_context_request::add_qfi(pfcp::qfi_t const &qfi) {
  qfis.push_back(qfi);
}

//-----------------------------------------------------------------------------
void pdu_session_update_sm_context_request::add_qfi(uint8_t const &q) {
  pfcp::qfi_t qfi(q);
  qfis.push_back(qfi);
}

//-----------------------------------------------------------------------------
void pdu_session_update_sm_context_request::get_qfis(
    std::vector<pfcp::qfi_t> &q) {
  for (auto qfi : qfis) {
    q.push_back(qfi);
  }
}

//-----------------------------------------------------------------------------
void pdu_session_update_sm_context_request::set_dl_fteid(fteid_t const &t) {
  dl_fteid = t;
}

//-----------------------------------------------------------------------------
void pdu_session_update_sm_context_request::get_dl_fteid(fteid_t &t) {
  t = dl_fteid;
}

//-----------------------------------------------------------------------------
void pdu_session_update_sm_context_request::set_upCnx_state(
    std::string const &value) {
  m_upCnx_state = value;
  m_upCnx_state_is_set = true;
}

//-----------------------------------------------------------------------------
bool pdu_session_update_sm_context_request::upCnx_state_is_set() const {
  return m_upCnx_state_is_set;
}

//-----------------------------------------------------------------------------
void pdu_session_update_sm_context_request::set_rat_type(
    std::string const &value) {
  m_rat_type = value;
  m_rat_type_is_set = true;
}

//-----------------------------------------------------------------------------
bool pdu_session_update_sm_context_request::rat_type_is_set() const {
  return m_rat_type_is_set;
}

//-----------------------------------------------------------------------------
void pdu_session_update_sm_context_request::set_an_type(
    std::string const &value) {
  m_an_type = value;
  m_an_type_is_set = true;
}

//-----------------------------------------------------------------------------
bool pdu_session_update_sm_context_request::an_type_is_set() const {
  return m_an_type_is_set;
}

//-----------------------------------------------------------------------------
bool pdu_session_update_sm_context_request::release_is_set() const {
  return m_release_is_set;
}

//-----------------------------------------------------------------------------
void pdu_session_update_sm_context_request::set_release(bool const value) {
  m_release = value;
  m_release_is_set = true;
}

//-----------------------------------------------------------------------------
void pdu_session_update_sm_context_response::set_cause(uint8_t cause) {
  m_cause = cause;
}

//-----------------------------------------------------------------------------
uint8_t pdu_session_update_sm_context_response::get_cause() {
  return m_cause;
}

//-----------------------------------------------------------------------------
void pdu_session_update_sm_context_response::add_qos_flow_context_updated(
    const qos_flow_context_updated &flow) {
  if ((flow.qfi.qfi >= QOS_FLOW_IDENTIFIER_FIRST )
      and (flow.qfi.qfi <= QOS_FLOW_IDENTIFIER_LAST )) {
    qos_flow_context_updateds.erase(flow.qfi.qfi);
    qos_flow_context_updateds.insert(
        std::pair<uint8_t, qos_flow_context_updated>((uint8_t) flow.qfi.qfi,
                                                     flow));
    Logger::smf_app().trace(
        "pdu_session_update_sm_context_response::add_qos_flow_context(%d) success",
        flow.qfi.qfi);
  } else {
    Logger::smf_app().error(
        "pdu_session_update_sm_context_response::add_qos_flow_context(%d) failed, invalid QFI",
        flow.qfi.qfi);
  }
}

//-----------------------------------------------------------------------------
bool pdu_session_update_sm_context_response::get_qos_flow_context_updated(
    const pfcp::qfi_t &qfi, qos_flow_context_updated &flow) {
  for (auto it : qos_flow_context_updateds) {
    if (it.second.qfi == qfi) {
      flow = it.second;
      return true;
    }
  }
  return false;
}

//-----------------------------------------------------------------------------
void pdu_session_update_sm_context_response::get_all_qos_flow_context_updateds(
    std::map<uint8_t, qos_flow_context_updated> &all_flows) {
  for (auto it : qos_flow_context_updateds) {
    all_flows.insert(
        std::pair<uint8_t, qos_flow_context_updated>((uint8_t) it.first,
                                                     it.second));
  }
}

//-----------------------------------------------------------------------------
void pdu_session_update_sm_context_response::remove_all_qos_flow_context_updateds() {
  qos_flow_context_updateds.clear();
}

//-----------------------------------------------------------------------------
void pdu_session_release_sm_context_response::set_cause(uint8_t cause) {
  m_cause = cause;
}

//-----------------------------------------------------------------------------
uint8_t pdu_session_release_sm_context_response::get_cause() {
  return m_cause;
}

//-----------------------------------------------------------------------------
void pdu_session_modification_network_requested::set_http_code(
    Pistache::Http::Code code) {
  m_code = code;
}

//-----------------------------------------------------------------------------
Pistache::Http::Code pdu_session_modification_network_requested::get_http_code() {
  return m_code;
}

//-----------------------------------------------------------------------------
void pdu_session_modification_network_requested::set_amf_url(
    std::string const &value) {
  amf_url = value;
}

//-----------------------------------------------------------------------------
std::string pdu_session_modification_network_requested::get_amf_url() const {
  return amf_url;
}

//-----------------------------------------------------------------------------
void pdu_session_modification_network_requested::add_qfi(
    pfcp::qfi_t const &qfi) {
  qfis.push_back(qfi);
}

//-----------------------------------------------------------------------------
void pdu_session_modification_network_requested::add_qfi(uint8_t const &q) {
  pfcp::qfi_t qfi(q);
  qfis.push_back(qfi);
}

//-----------------------------------------------------------------------------
void pdu_session_modification_network_requested::get_qfis(
    std::vector<pfcp::qfi_t> &q) {
  for (auto qfi : qfis) {
    q.push_back(qfi);
  }
}

