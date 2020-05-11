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

/*! \file smf_context.cpp
 \brief
 \author  Lionel GAUTHIER, Tien-Thinh NGUYEN
 \company Eurecom
 \date 2019
 \email: lionel.gauthier@eurecom.fr, tien-thinh.nguyen@eurecom.fr
 */

#include "smf_context.hpp"

#include <algorithm>

#include "itti.hpp"
#include "logger.hpp"
#include "smf_app.hpp"
#include "smf_n11.hpp"
#include "smf_config.hpp"
#include "smf_n1_n2.hpp"
#include "smf_paa_dynamic.hpp"
#include "smf_procedure.hpp"
#include "ProblemDetails.h"
#include "3gpp_29.502.h"
#include "3gpp_24.501.h"
#include "SmContextCreatedData.h"

extern "C" {
#include "Ngap_PDUSessionResourceSetupResponseTransfer.h"
#include "Ngap_PDUSessionResourceModifyResponseTransfer.h"
#include "Ngap_PDUSessionResourceReleaseResponseTransfer.h"
#include "Ngap_GTPTunnel.h"
#include "Ngap_AssociatedQosFlowItem.h"
#include "Ngap_QosFlowAddOrModifyResponseList.h"
#include "Ngap_QosFlowAddOrModifyResponseItem.h"
#include "dynamic_memory_check.h"
}

using namespace smf;

extern itti_mw *itti_inst;
extern smf::smf_app *smf_app_inst;
extern smf::smf_n11 *smf_n11_inst;
extern smf::smf_config smf_cfg;

//------------------------------------------------------------------------------
void smf_qos_flow::mark_as_released() {
  released = true;
}

//------------------------------------------------------------------------------
std::string smf_qos_flow::toString() const {
  std::string s = { };
  s.append("QoS Flow:\n");
  s.append("\tFQI:\t\t\t\t").append(std::to_string((uint8_t) qfi.qfi)).append(
      "\n");
  s.append("\tUL FTEID:\t\t").append(ul_fteid.toString()).append("\n");
  s.append("\tPDR ID UL:\t\t\t").append(std::to_string(pdr_id_ul.rule_id))
      .append("\n");
  s.append("\tPDR ID DL:\t\t\t").append(std::to_string(pdr_id_dl.rule_id))
      .append("\n");
  s.append("\tPrecedence:\t\t\t").append(std::to_string(precedence.precedence))
      .append("\n");
  if (far_id_ul.first) {
    s.append("\tFAR ID UL:\t\t\t").append(
        std::to_string(far_id_ul.second.far_id)).append("\n");
  }
  if (far_id_dl.first) {
    s.append("\tFAR ID DL:\t\t\t").append(
        std::to_string(far_id_dl.second.far_id)).append("\n");
  }
  return s;
}
//------------------------------------------------------------------------------
void smf_qos_flow::deallocate_ressources() {
  clear();
  Logger::smf_app().info(
      "Resources associated with this QoS Flow (%d) have been released",
      (uint8_t) qfi.qfi);
}

//------------------------------------------------------------------------------
void smf_pdu_session::set(const paa_t &paa) {
  switch (paa.pdn_type.pdn_type) {
    case PDN_TYPE_E_IPV4:
      ipv4 = true;
      ipv6 = false;
      ipv4_address = paa.ipv4_address;
      pdn_type.pdn_type = paa.pdn_type.pdn_type;
      break;
    case PDN_TYPE_E_IPV6:
      ipv4 = false;
      ipv6 = true;
      ipv6_address = paa.ipv6_address;
      pdn_type.pdn_type = paa.pdn_type.pdn_type;
      break;
    case PDN_TYPE_E_IPV4V6:
      ipv4 = true;
      ipv6 = true;
      ipv4_address = paa.ipv4_address;
      ipv6_address = paa.ipv6_address;
      pdn_type.pdn_type = paa.pdn_type.pdn_type;
      break;
    case PDN_TYPE_E_NON_IP:
      ipv4 = false;
      ipv6 = false;
      pdn_type.pdn_type = paa.pdn_type.pdn_type;
      break;
    default:
      Logger::smf_app().error("smf_pdu_session::set(paa_t) Unknown PDN type %d",
                              paa.pdn_type.pdn_type);
  }
}

//------------------------------------------------------------------------------
void smf_pdu_session::get_paa(paa_t &paa) {
  switch (pdn_type.pdn_type) {
    case PDN_TYPE_E_IPV4:
      ipv4 = true;
      ipv6 = false;
      paa.ipv4_address = ipv4_address;
      break;
    case PDN_TYPE_E_IPV6:
      ipv4 = false;
      ipv6 = true;
      paa.ipv6_address = ipv6_address;
      break;
    case PDN_TYPE_E_IPV4V6:
      ipv4 = true;
      ipv6 = true;
      paa.ipv4_address = ipv4_address;
      paa.ipv6_address = ipv6_address;
      break;
    case PDN_TYPE_E_NON_IP:
      ipv4 = false;
      ipv6 = false;
      break;
    default:
      Logger::smf_app().error(
          "smf_pdu_session::get_paa (paa_t) Unknown PDN type %d",
          pdn_type.pdn_type);
  }
  paa.pdn_type.pdn_type = pdn_type.pdn_type;
}

//------------------------------------------------------------------------------
void smf_pdu_session::add_qos_flow(const smf_qos_flow &flow) {
  if ((flow.qfi.qfi >= QOS_FLOW_IDENTIFIER_FIRST )
      and (flow.qfi.qfi <= QOS_FLOW_IDENTIFIER_LAST )) {
    qos_flows.erase(flow.qfi.qfi);
    qos_flows.insert(
        std::pair<uint8_t, smf_qos_flow>((uint8_t) flow.qfi.qfi, flow));
    Logger::smf_app().trace("QoS Flow (flow Id %d) has been added successfully",
                            flow.qfi.qfi);
  } else {
    Logger::smf_app().error("Failed to add QoS flow (flow Id %d), invalid QFI",
                            flow.qfi.qfi);
  }
}

//------------------------------------------------------------------------------
bool smf_pdu_session::get_qos_flow(const pfcp::pdr_id_t &pdr_id,
                                   smf_qos_flow &q) {
  for (auto it : qos_flows) {
    if (it.second.pdr_id_ul.rule_id == pdr_id.rule_id) {
      q = it.second;
      return true;
    }
    if (it.second.pdr_id_dl.rule_id == pdr_id.rule_id) {
      q = it.second;
      return true;
    }
  }
  return false;
}

//------------------------------------------------------------------------------
bool smf_pdu_session::get_qos_flow(const pfcp::far_id_t &far_id,
                                   smf_qos_flow &q) {
  for (auto it : qos_flows) {
    if ((it.second.far_id_ul.first)
        && (it.second.far_id_ul.second.far_id == far_id.far_id)) {
      q = it.second;
      return true;
    }
    if ((it.second.far_id_dl.first)
        && (it.second.far_id_dl.second.far_id == far_id.far_id)) {
      q = it.second;
      return true;
    }
  }
  return false;
}

//------------------------------------------------------------------------------
bool smf_pdu_session::get_qos_flow(const pfcp::qfi_t &qfi, smf_qos_flow &q) {
  for (auto it : qos_flows) {
    if (it.second.qfi == qfi) {
      q = it.second;
      return true;
    }
  }
  return false;
}

//------------------------------------------------------------------------------
void smf_pdu_session::set_default_qos_flow(const pfcp::qfi_t &qfi) {
  default_qfi.qfi = qfi.qfi;
}

//------------------------------------------------------------------------------
bool smf_pdu_session::get_default_qos_flow(smf_qos_flow &flow) {
  Logger::smf_app().debug("Get default QoS Flow of this PDU session.");
  return get_qos_flow(default_qfi, flow);
}

//------------------------------------------------------------------------------
void smf_pdu_session::get_qos_flows(std::vector<smf_qos_flow> &flows) {
  flows.clear();
  for (auto it : qos_flows) {
    flows.push_back(it.second);
  }
}

//------------------------------------------------------------------------------
bool smf_pdu_session::find_qos_flow(const pfcp::pdr_id_t &pdr_id,
                                    smf_qos_flow &flow) {
  for (std::map<uint8_t, smf_qos_flow>::iterator it = qos_flows.begin();
      it != qos_flows.end(); ++it) {
    if ((it->second.pdr_id_ul == pdr_id) || (it->second.pdr_id_dl == pdr_id)) {
      flow = it->second;
      return true;
    }
  }
  return false;
}

//------------------------------------------------------------------------------
void smf_pdu_session::remove_qos_flow(const pfcp::qfi_t &qfi) {
  smf_qos_flow &flow = qos_flows[qfi.qfi];
  flow.deallocate_ressources();
  qos_flows.erase(qfi.qfi);
}

//------------------------------------------------------------------------------
void smf_pdu_session::remove_qos_flow(smf_qos_flow &flow) {
  pfcp::qfi_t qfi = { .qfi = flow.qfi.qfi };
  flow.deallocate_ressources();
  qos_flows.erase(qfi.qfi);
}

//------------------------------------------------------------------------------
void smf_pdu_session::deallocate_ressources(const std::string &apn) {

  for (std::map<uint8_t, smf_qos_flow>::iterator it = qos_flows.begin();
      it != qos_flows.end(); ++it) {
    //TODO: release FAR_ID, PDR_ID
    //release_pdr_id(it->second.pdr_id_dl);
    //release_pdr_id(it->second.pdr_id_ul);
    //release_far_id(it->second.far_id_dl.second);
    //release_far_id(it->second.far_id_ul.second);
    it->second.deallocate_ressources();
  }
  if (ipv4) {
    paa_dynamic::get_instance().release_paa(apn, ipv4_address);
  }
  clear();  //including qos_flows.clear()
  Logger::smf_app().info(
      "Resources associated with this PDU Session have been released");
}

//------------------------------------------------------------------------------
void smf_pdu_session::generate_seid() {
  // DO it simple now:
  // seid = pgw_fteid_s5_s8_cp.teid_gre_key | (((uint64_t)smf_cfg.instance) << 32);
}

void smf_pdu_session::set_seid(const uint64_t &s) {
  seid = s;
}

//------------------------------------------------------------------------------
// TODO check if prd_id should be uniq in the UPF or in the context of a pdn connection
void smf_pdu_session::generate_far_id(pfcp::far_id_t &far_id) {
  far_id.far_id = far_id_generator.get_uid();
}

//------------------------------------------------------------------------------
// TODO check if prd_id should be uniq in the UPF or in the context of a pdn connection
void smf_pdu_session::release_far_id(const pfcp::far_id_t &far_id) {
  far_id_generator.free_uid(far_id.far_id);
}

//------------------------------------------------------------------------------
// TODO check if prd_id should be uniq in the UPF or in the context of a pdn connection
void smf_pdu_session::generate_pdr_id(pfcp::pdr_id_t &pdr_id) {
  pdr_id.rule_id = pdr_id_generator.get_uid();
}

//------------------------------------------------------------------------------
// TODO check if prd_id should be uniq in the UPF or in the context of a pdn connection
void smf_pdu_session::release_pdr_id(const pfcp::pdr_id_t &pdr_id) {
  pdr_id_generator.free_uid(pdr_id.rule_id);
}

//------------------------------------------------------------------------------
void smf_pdu_session::generate_qos_rule_id(uint8_t &rule_id) {
  rule_id = qos_rule_id_generator.get_uid();
}

//------------------------------------------------------------------------------
void smf_pdu_session::release_qos_rule_id(const uint8_t &rule_id) {
  qos_rule_id_generator.free_uid(rule_id);
}

//------------------------------------------------------------------------------
std::string smf_pdu_session::toString() const {
  std::string s = { };
  s.append("PDN CONNECTION:\n");
  s.append("\tPDN type:\t\t\t").append(pdn_type.toString()).append("\n");
  if (ipv4)
    s.append("\tPAA IPv4:\t\t\t").append(conv::toString(ipv4_address)).append(
        "\n");
  if (ipv6)
    s.append("\tPAA IPv6:\t\t\t").append(conv::toString(ipv6_address)).append(
        "\n");
  s.append("\tDefault QFI:\t\t\t").append(std::to_string(default_qfi.qfi))
      .append("\n");
  s.append("\tSEID:\t\t\t\t").append(std::to_string(seid)).append("\n");
  return s;
}

//------------------------------------------------------------------------------
void smf_pdu_session::set_pdu_session_status(
    const pdu_session_status_e &status) {
  //TODO: Should consider congestion handling
  Logger::smf_app().info(
      "Set PDU Session Status to %s",
      pdu_session_status_e2str[static_cast<int>(status)].c_str());
  pdu_session_status = status;
}

//------------------------------------------------------------------------------
pdu_session_status_e smf_pdu_session::get_pdu_session_status() const {
  return pdu_session_status;
}

//------------------------------------------------------------------------------
void smf_pdu_session::set_upCnx_state(const upCnx_state_e &state) {
  Logger::smf_app().info("Set upCnxState to %s",
                         upCnx_state_e2str[static_cast<int>(state)].c_str());
  upCnx_state = state;
}

//------------------------------------------------------------------------------
upCnx_state_e smf_pdu_session::get_upCnx_state() const {
  return upCnx_state;
}

//------------------------------------------------------------------------------
pdn_type_t smf_pdu_session::get_pdn_type() const {
  return pdn_type;
}

//------------------------------------------------------------------------------
void smf_pdu_session::get_qos_rules_to_be_synchronised(
    std::vector<QOSRulesIE> &rules) const {
  for (auto it : qos_rules_to_be_synchronised) {
    if (qos_rules.count(it) > 0)
      rules.push_back(qos_rules.at(it));
  }
}

//------------------------------------------------------------------------------
void smf_pdu_session::get_qos_rules(const pfcp::qfi_t &qfi,
                                    std::vector<QOSRulesIE> &rules) const {
  Logger::smf_app().info("Get QoS Rules associated with Flow with QFI %d",
                         qfi.qfi);
  for (auto it : qos_rules) {
    if (it.second.qosflowidentifer == qfi.qfi)
      rules.push_back(qos_rules.at(it.first));
  }
}

//------------------------------------------------------------------------------
bool smf_pdu_session::get_default_qos_rule(QOSRulesIE &qos_rule) const {
  Logger::smf_app().info("Get default QoS Rule this PDU Session (ID %d)",
                         pdu_session_id);
  for (auto it : qos_rules) {
    if (it.second.dqrbit == THE_QOS_RULE_IS_DEFAULT_QOS_RULE) {
      qos_rule = it.second;
      return true;
    }
  }
  return false;
}

//------------------------------------------------------------------------------
bool smf_pdu_session::get_qos_rule(uint8_t rule_id,
                                   QOSRulesIE &qos_rule) const {
  Logger::smf_app().info("Find QoS Rule with Rule Id %d", (uint8_t) rule_id);
  if (qos_rules.count(rule_id) > 0) {
    qos_rule = qos_rules.at(rule_id);
  }
  return false;
}

//------------------------------------------------------------------------------
void smf_pdu_session::update_qos_rule(const QOSRulesIE &qos_rule) {
  Logger::smf_app().info("Update QoS Rule with Rule Id %d",
                         (uint8_t) qos_rule.qosruleidentifer);
  uint8_t rule_id = qos_rule.qosruleidentifer;
  if ((rule_id >= QOS_RULE_IDENTIFIER_FIRST )
      and (rule_id <= QOS_RULE_IDENTIFIER_LAST )) {

    if (qos_rules.count(rule_id) > 0) {
      qos_rules.erase(rule_id);
      qos_rules.insert(std::pair<uint8_t, QOSRulesIE>(rule_id, qos_rule));
      //marked to be synchronised with UE
      qos_rules_to_be_synchronised.push_back(rule_id);
      Logger::smf_app().trace("smf_pdu_session::update_qos_rule(%d) success",
                              rule_id);
    } else {
      Logger::smf_app().error(
          "smf_pdu_session::update_qos_rule(%d) failed, rule does not existed",
          rule_id);
    }

  } else {
    Logger::smf_app().error(
        "smf_pdu_session::update_qos_rule(%d) failed, invalid Rule Id",
        rule_id);
  }
}

//------------------------------------------------------------------------------
void smf_pdu_session::mark_qos_rule_to_be_synchronised(uint8_t rule_id) {

  if ((rule_id >= QOS_RULE_IDENTIFIER_FIRST )
      and (rule_id <= QOS_RULE_IDENTIFIER_LAST )) {
    if (qos_rules.count(rule_id) > 0) {
      qos_rules_to_be_synchronised.push_back(rule_id);
      Logger::smf_app().trace(
          "smf_pdu_session::mark_qos_rule_to_be_synchronised(%d) success",
          rule_id);
    } else {
      Logger::smf_app().error(
          "smf_pdu_session::mark_qos_rule_to_be_synchronised(%d) failed, rule does not existed",
          rule_id);
    }

  } else {
    Logger::smf_app().error(
        "smf_pdu_session::mark_qos_rule_to_be_synchronised(%d) failed, invalid Rule Id",
        rule_id);
  }
}

//------------------------------------------------------------------------------
void smf_pdu_session::add_qos_rule(const QOSRulesIE &qos_rule) {
  Logger::smf_app().info("Add QoS Rule with Rule Id %d",
                         (uint8_t) qos_rule.qosruleidentifer);
  uint8_t rule_id = qos_rule.qosruleidentifer;

  if ((rule_id >= QOS_RULE_IDENTIFIER_FIRST )
      and (rule_id <= QOS_RULE_IDENTIFIER_LAST )) {
    if (qos_rules.count(rule_id) > 0) {
      Logger::smf_app().error("Failed to add rule (Id %d), rule existed",
                              rule_id);
    } else {
      qos_rules.insert(std::pair<uint8_t, QOSRulesIE>(rule_id, qos_rule));
      Logger::smf_app().trace("Rule (Id %d) has been added successfully",
                              rule_id);
    }

  } else {
    Logger::smf_app().error(
        "Failed to add rule (Id %d) failed: invalid rule Id", rule_id);
  }

}

//------------------------------------------------------------------------------
void session_management_subscription::insert_dnn_configuration(
    std::string dnn, std::shared_ptr<dnn_configuration_t> &dnn_configuration) {
  dnn_configurations.insert(
      std::pair<std::string, std::shared_ptr<dnn_configuration_t>>(
          dnn, dnn_configuration));
}

//------------------------------------------------------------------------------
void session_management_subscription::find_dnn_configuration(
    std::string dnn, std::shared_ptr<dnn_configuration_t> &dnn_configuration) {
  Logger::smf_app().info("Find DNN configuration with DNN %s", dnn.c_str());
  if (dnn_configurations.count(dnn) > 0) {
    dnn_configuration = dnn_configurations.at(dnn);
  }
}

//------------------------------------------------------------------------------
void smf_context::insert_procedure(std::shared_ptr<smf_procedure> &sproc) {
  std::unique_lock<std::recursive_mutex> lock(m_context);
  pending_procedures.push_back(sproc);
}

//------------------------------------------------------------------------------
bool smf_context::find_procedure(const uint64_t &trxn_id,
                                 std::shared_ptr<smf_procedure> &proc) {
  std::unique_lock<std::recursive_mutex> lock(m_context);
  auto found = std::find_if(
      pending_procedures.begin(), pending_procedures.end(),
      [trxn_id](const std::shared_ptr<smf_procedure> &i) -> bool {
        return i->trxn_id == trxn_id;
      });
  if (found != pending_procedures.end()) {
    proc = *found;
    return true;
  }
  return false;
}

//------------------------------------------------------------------------------
void smf_context::remove_procedure(smf_procedure *proc) {
  std::unique_lock<std::recursive_mutex> lock(m_context);
  auto found = std::find_if(pending_procedures.begin(),
                            pending_procedures.end(),
                            [proc](const std::shared_ptr<smf_procedure> &i) {
                              return i.get() == proc;
                            });
  if (found != pending_procedures.end()) {
    pending_procedures.erase(found);
  }
}

//------------------------------------------------------------------------------
void smf_context::handle_itti_msg(
    itti_n4_session_establishment_response &seresp) {
  std::shared_ptr<smf_procedure> proc = { };
  if (find_procedure(seresp.trxn_id, proc)) {
    Logger::smf_app().debug(
        "Received N4 SESSION ESTABLISHMENT RESPONSE sender teid " TEID_FMT "  pfcp_tx_id %" PRIX64"",
        seresp.seid, seresp.trxn_id);
    proc->handle_itti_msg(seresp, shared_from_this());
    remove_procedure(proc.get());
  } else {
    Logger::smf_app().debug(
        "Received N4 SESSION ESTABLISHMENT RESPONSE sender teid " TEID_FMT "  pfcp_tx_id %" PRIX64", smf_procedure not found, discarded!",
        seresp.seid, seresp.trxn_id);
  }
}

//------------------------------------------------------------------------------
void smf_context::handle_itti_msg(
    itti_n4_session_modification_response &smresp) {
  std::shared_ptr<smf_procedure> proc = { };
  if (find_procedure(smresp.trxn_id, proc)) {
    Logger::smf_app().debug(
        "Received N4 SESSION MODIFICATION RESPONSE sender teid " TEID_FMT "  pfcp_tx_id %" PRIX64" ",
        smresp.seid, smresp.trxn_id);
    proc->handle_itti_msg(smresp, shared_from_this());
    remove_procedure(proc.get());
  } else {
    Logger::smf_app().debug(
        "Received N4 SESSION MODIFICATION RESPONSE sender teid " TEID_FMT "  pfcp_tx_id %" PRIX64", smf_procedure not found, discarded!",
        smresp.seid, smresp.trxn_id);
  }
  Logger::smf_app().info(
      "Handle N4 SESSION MODIFICATION RESPONSE with SMF context %s",
      toString().c_str());
}

//------------------------------------------------------------------------------
void smf_context::handle_itti_msg(itti_n4_session_deletion_response &sdresp) {
  std::shared_ptr<smf_procedure> proc = { };
  if (find_procedure(sdresp.trxn_id, proc)) {
    Logger::smf_app().debug(
        "Received N4 SESSION DELETION RESPONSE sender teid " TEID_FMT "  pfcp_tx_id %" PRIX64" ",
        sdresp.seid, sdresp.trxn_id);
    proc->handle_itti_msg(sdresp, shared_from_this());
    remove_procedure(proc.get());
  } else {
    Logger::smf_app().debug(
        "Received N4 SESSION DELETION RESPONSE sender teid " TEID_FMT "  pfcp_tx_id %" PRIX64", smf_procedure not found, discarded!",
        sdresp.seid, sdresp.trxn_id);
  }

  Logger::smf_app().info(
      "Handle N4 SESSION DELETION RESPONSE with SMF context %s",
      toString().c_str());

}

//------------------------------------------------------------------------------
void smf_context::handle_itti_msg(
    std::shared_ptr<itti_n4_session_report_request> &req) {
}

//------------------------------------------------------------------------------
std::string smf_context::toString() const {
  std::unique_lock<std::recursive_mutex> lock(m_context);
  std::string s = { };
  s.append("\n");
  s.append("SMF CONTEXT:\n");
  s.append("\tSUPI:\t\t\t\t").append(smf_supi_to_string(supi).c_str()).append(
      "\n");
  for (auto it : dnns) {
    s.append(it->toString());
  }
//  s.append("\n");
  return s;
}

//------------------------------------------------------------------------------
void smf_context::get_default_qos(const snssai_t &snssai,
                                  const std::string &dnn,
                                  subscribed_default_qos_t &default_qos) {
  Logger::smf_app().info("Get default QoS for a PDU Session, key %d",
                         (uint8_t) snssai.sST);
  //get the default QoS profile
  std::shared_ptr<session_management_subscription> ss = { };
  std::shared_ptr<dnn_configuration_t> sdc = { };
  find_dnn_subscription(snssai, ss);

  if (nullptr != ss.get()) {
    ss.get()->find_dnn_configuration(dnn, sdc);
    if (nullptr != sdc.get()) {
      default_qos = sdc.get()->_5g_qos_profile;
    }
  }

}

//------------------------------------------------------------------------------
void smf_context::get_default_qos_rule(QOSRulesIE &qos_rule,
                                       uint8_t pdu_session_type) {
  //TODO, update according to PDU Session type
  Logger::smf_app().info(
      "Get default QoS rule for a PDU Session (PDU session type %d)",
      pdu_session_type);
  //see section 9.11.4.13 @ 3GPP TS 24.501 and section 5.7.1.4 @ 3GPP TS 23.501
  qos_rule.qosruleidentifer = 0x01;  //be updated later on
  qos_rule.ruleoperationcode = CREATE_NEW_QOS_RULE;
  qos_rule.dqrbit = THE_QOS_RULE_IS_DEFAULT_QOS_RULE;
  if ((pdu_session_type == PDU_SESSION_TYPE_E_IPV4)
      or (pdu_session_type == PDU_SESSION_TYPE_E_IPV4V6)
      or (pdu_session_type == PDU_SESSION_TYPE_E_IPV6)
      or (pdu_session_type == PDU_SESSION_TYPE_E_ETHERNET)) {
    qos_rule.numberofpacketfilters = 1;
    qos_rule.packetfilterlist.create_modifyandadd_modifyandreplace =
        (Create_ModifyAndAdd_ModifyAndReplace*) calloc(
            1, sizeof(Create_ModifyAndAdd_ModifyAndReplace));
    qos_rule.packetfilterlist.create_modifyandadd_modifyandreplace[0]
        .packetfilterdirection = 0b11;  //bi-directional
    qos_rule.packetfilterlist.create_modifyandadd_modifyandreplace[0]
        .packetfilteridentifier = 1;
    qos_rule.packetfilterlist.create_modifyandadd_modifyandreplace[0]
        .packetfiltercontents.component_type = QOS_RULE_MATCHALL_TYPE;
    //qos_rule.packetfilterlist.create_modifyandadd_modifyandreplace[0].packetfiltercontents.component_value = bfromcstralloc(2, "\0");
    qos_rule.qosruleprecedence = 0xff;
  }

  if (pdu_session_type == PDU_SESSION_TYPE_E_UNSTRUCTURED) {
    qos_rule.numberofpacketfilters = 0;
    qos_rule.qosruleprecedence = 0xff;
  }

  qos_rule.segregation = SEGREGATION_NOT_REQUESTED;
  qos_rule.qosflowidentifer = 6;  //TODO: default value

  Logger::smf_app().debug(
      "Default QoSRules: %x %x %x %x %x %x %x %x %x",
      qos_rule.qosruleidentifer,
      qos_rule.ruleoperationcode,
      qos_rule.dqrbit,
      qos_rule.numberofpacketfilters,
      qos_rule.packetfilterlist.create_modifyandadd_modifyandreplace
          ->packetfilterdirection,
      qos_rule.packetfilterlist.create_modifyandadd_modifyandreplace
          ->packetfilteridentifier,
      qos_rule.packetfilterlist.create_modifyandadd_modifyandreplace
          ->packetfiltercontents.component_type,
      qos_rule.qosruleprecedence, qos_rule.segregation,
      qos_rule.qosflowidentifer);
}

//------------------------------------------------------------------------------
void smf_context::get_default_qos_flow_description(
    QOSFlowDescriptionsContents &qos_flow_description, uint8_t pdu_session_type,
    const pfcp::qfi_t &qfi) {
  //TODO, update according to PDU Session type
  Logger::smf_app().info(
      "Get default QoS Flow Description (PDU session type %d)",
      pdu_session_type);
  qos_flow_description.qfi = qfi.qfi;
  qos_flow_description.operationcode = CREATE_NEW_QOS_FLOW_DESCRIPTION;
  qos_flow_description.e = PARAMETERS_LIST_IS_INCLUDED;
  qos_flow_description.numberofparameters = 1;
  qos_flow_description.parameterslist = (ParametersList*) calloc(
      3, sizeof(ParametersList));
  qos_flow_description.parameterslist[0].parameteridentifier =
  PARAMETER_IDENTIFIER_5QI;
  qos_flow_description.parameterslist[0].parametercontents._5qi = qfi.qfi;
  /*
   qos_flow_description.parameterslist[1].parameteridentifier =
   PARAMETER_IDENTIFIER_GFBR_UPLINK;
   qos_flow_description.parameterslist[1].parametercontents
   .gfbrormfbr_uplinkordownlink.uint =
   GFBRORMFBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_1MBPS;
   qos_flow_description.parameterslist[1].parametercontents
   .gfbrormfbr_uplinkordownlink.value = 0x10;
   qos_flow_description.parameterslist[2].parameteridentifier =
   PARAMETER_IDENTIFIER_GFBR_DOWNLINK;
   qos_flow_description.parameterslist[2].parametercontents
   .gfbrormfbr_uplinkordownlink.uint =
   GFBRORMFBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_1MBPS;
   qos_flow_description.parameterslist[2].parametercontents
   .gfbrormfbr_uplinkordownlink.value = 0x10;
   */

  Logger::smf_app().debug(
      "Default Qos Flow Description: %x %x %x %x %x %x",
      qos_flow_description.qfi, qos_flow_description.operationcode,
      qos_flow_description.e, qos_flow_description.numberofparameters,
      qos_flow_description.parameterslist[0].parameteridentifier,
      qos_flow_description.parameterslist[0].parametercontents._5qi
      /*      qos_flow_description.parameterslist[1].parameteridentifier,
       qos_flow_description.parameterslist[1].parametercontents
       .gfbrormfbr_uplinkordownlink.uint,
       qos_flow_description.parameterslist[1].parametercontents
       .gfbrormfbr_uplinkordownlink.value,
       qos_flow_description.parameterslist[2].parameteridentifier,
       qos_flow_description.parameterslist[2].parametercontents
       .gfbrormfbr_uplinkordownlink.uint,
       qos_flow_description.parameterslist[2].parametercontents
       .gfbrormfbr_uplinkordownlink.value
       */);
}

//------------------------------------------------------------------------------
void smf_context::get_session_ambr(SessionAMBR &session_ambr,
                                   const snssai_t &snssai,
                                   const std::string &dnn) {
  Logger::smf_app().debug(
      "Get AMBR info from the subscription information (DNN %s)", dnn.c_str());

  std::shared_ptr<session_management_subscription> ss = { };
  std::shared_ptr<dnn_configuration_t> sdc = { };
  find_dnn_subscription(snssai, ss);
  if (nullptr != ss.get()) {

    ss.get()->find_dnn_configuration(dnn, sdc);
    if (nullptr != sdc.get()) {
      Logger::smf_app().debug(
          "Default AMBR info from the subscription information, downlink %s, uplink %s",
          (sdc.get()->session_ambr).downlink.c_str(),
          (sdc.get()->session_ambr).uplink.c_str());

      //Downlink
      size_t leng_of_session_ambr_dl =
          (sdc.get()->session_ambr).downlink.length();
      try {
        std::string session_ambr_dl_unit = (sdc.get()->session_ambr).downlink
            .substr(leng_of_session_ambr_dl - 4);  //4 last characters stand for mbps, kbps, ..
        if (session_ambr_dl_unit.compare("Kbps") == 0)
          session_ambr.uint_for_session_ambr_for_downlink =
          AMBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_1KBPS;
        if (session_ambr_dl_unit.compare("Mbps") == 0)
          session_ambr.uint_for_session_ambr_for_downlink =
          AMBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_1MBPS;
        if (session_ambr_dl_unit.compare("Gbps") == 0)
          session_ambr.uint_for_session_ambr_for_downlink =
          AMBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_1GBPS;
        if (session_ambr_dl_unit.compare("Tbps") == 0)
          session_ambr.uint_for_session_ambr_for_downlink =
          AMBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_1TBPS;
        if (session_ambr_dl_unit.compare("Pbps") == 0)
          session_ambr.uint_for_session_ambr_for_downlink =
          AMBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_1PBPS;

        session_ambr.session_ambr_for_downlink = std::stoi(
            (sdc.get()->session_ambr).downlink.substr(
                0, leng_of_session_ambr_dl - 4));
      } catch (const std::exception &e) {
        Logger::smf_app().warn("Undefined error: %s", e.what());
        //assign default value
        session_ambr.session_ambr_for_downlink = 1;
        session_ambr.uint_for_session_ambr_for_downlink =
        AMBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_1MBPS;
      }

      //Uplink
      size_t leng_of_session_ambr_ul =
          (sdc.get()->session_ambr).uplink.length();
      try {
        std::string session_ambr_ul_unit = (sdc.get()->session_ambr).uplink
            .substr(leng_of_session_ambr_ul - 4);  //4 last characters stand for mbps, kbps, ..
        if (session_ambr_ul_unit.compare("Kbps") == 0)
          session_ambr.uint_for_session_ambr_for_uplink =
          AMBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_1KBPS;
        if (session_ambr_ul_unit.compare("Mbps") == 0)
          session_ambr.uint_for_session_ambr_for_uplink =
          AMBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_1MBPS;
        if (session_ambr_ul_unit.compare("Gbps") == 0)
          session_ambr.uint_for_session_ambr_for_uplink =
          AMBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_1GBPS;
        if (session_ambr_ul_unit.compare("Tbps") == 0)
          session_ambr.uint_for_session_ambr_for_uplink =
          AMBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_1TBPS;
        if (session_ambr_ul_unit.compare("Pbps") == 0)
          session_ambr.uint_for_session_ambr_for_uplink =
          AMBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_1PBPS;

        session_ambr.session_ambr_for_uplink = std::stoi(
            (sdc.get()->session_ambr).uplink.substr(
                0, leng_of_session_ambr_ul - 4));
      } catch (const std::exception &e) {
        Logger::smf_app().warn("Undefined error: %s", e.what());
        //assign default value
        session_ambr.session_ambr_for_uplink = 1;
        session_ambr.uint_for_session_ambr_for_uplink =
        AMBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_1MBPS;
      }
    }
  } else {

    Logger::smf_app().debug(
        "Could not get default info from the subscription information, use default value instead.");
    //use default value
    session_ambr.session_ambr_for_downlink = 1;
    session_ambr.uint_for_session_ambr_for_downlink =
    AMBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_1MBPS;
    session_ambr.session_ambr_for_uplink = 1;
    session_ambr.uint_for_session_ambr_for_uplink =
    AMBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_1MBPS;
  }

}

//------------------------------------------------------------------------------
void smf_context::get_session_ambr(
    Ngap_PDUSessionAggregateMaximumBitRate_t &session_ambr,
    const snssai_t &snssai, const std::string &dnn) {
  Logger::smf_app().debug(
      "Get AMBR info from the subscription information (DNN %s)", dnn.c_str());

  std::shared_ptr<session_management_subscription> ss = { };
  std::shared_ptr<dnn_configuration_t> sdc = { };
  find_dnn_subscription(snssai, ss);

  uint32_t bit_rate_dl = { 1 };
  uint32_t bit_rate_ul = { 1 };

  session_ambr.pDUSessionAggregateMaximumBitRateDL.size = 4;
  session_ambr.pDUSessionAggregateMaximumBitRateDL.buf = (uint8_t*) calloc(
      4, sizeof(uint8_t));
  session_ambr.pDUSessionAggregateMaximumBitRateUL.size = 4;
  session_ambr.pDUSessionAggregateMaximumBitRateUL.buf = (uint8_t*) calloc(
      4, sizeof(uint8_t));

  if (nullptr != ss.get()) {
    ss.get()->find_dnn_configuration(dnn, sdc);

    if (nullptr != sdc.get()) {
      Logger::smf_app().debug(
          "Default AMBR info from the DNN configuration, downlink %s, uplink %s",
          (sdc.get()->session_ambr).downlink.c_str(),
          (sdc.get()->session_ambr).uplink.c_str());
      //Downlink
      size_t leng_of_session_ambr_dl =
          (sdc.get()->session_ambr).downlink.length();
      try {
        bit_rate_dl = std::stoi(
            (sdc.get()->session_ambr).downlink.substr(
                0, leng_of_session_ambr_dl - 4));
        std::string session_ambr_dl_unit = (sdc.get()->session_ambr).downlink
            .substr(leng_of_session_ambr_dl - 4);  //4 last characters stand for mbps, kbps, ..
        if (session_ambr_dl_unit.compare("Kbps") == 0)
          bit_rate_dl *= 1000;
        if (session_ambr_dl_unit.compare("Mbps") == 0)
          bit_rate_dl *= 1000000;
        if (session_ambr_dl_unit.compare("Gbps") == 0)
          bit_rate_dl *= 1000000000;
        INT32_TO_BUFFER(bit_rate_dl,
                        session_ambr.pDUSessionAggregateMaximumBitRateDL.buf);
      } catch (const std::exception &e) {
        Logger::smf_app().warn("Undefined error: %s", e.what());
        //assign default value
        bit_rate_dl = 1;
        INT32_TO_BUFFER(bit_rate_dl,
                        session_ambr.pDUSessionAggregateMaximumBitRateDL.buf);
      }

      //Uplink
      size_t leng_of_session_ambr_ul =
          (sdc.get()->session_ambr).uplink.length();
      try {
        bit_rate_ul = std::stoi(
            (sdc.get()->session_ambr).uplink.substr(
                0, leng_of_session_ambr_ul - 4));
        std::string session_ambr_ul_unit = (sdc.get()->session_ambr).uplink
            .substr(leng_of_session_ambr_ul - 4);  //4 last characters stand for mbps, kbps, ..
        if (session_ambr_ul_unit.compare("Kbps") == 0)
          bit_rate_ul *= 1000;
        if (session_ambr_ul_unit.compare("Mbps") == 0)
          bit_rate_ul *= 1000000;
        if (session_ambr_ul_unit.compare("Gbps") == 0)
          bit_rate_ul *= 1000000000;
        INT32_TO_BUFFER(bit_rate_ul,
                        session_ambr.pDUSessionAggregateMaximumBitRateUL.buf);
      } catch (const std::exception &e) {
        Logger::smf_app().warn("Undefined error: %s", e.what());
        //assign default value
        bit_rate_ul = 1;
        INT32_TO_BUFFER(bit_rate_ul,
                        session_ambr.pDUSessionAggregateMaximumBitRateUL.buf);
      }
    }
  } else {
    INT32_TO_BUFFER(bit_rate_dl,
                    session_ambr.pDUSessionAggregateMaximumBitRateDL.buf);
    INT32_TO_BUFFER(bit_rate_ul,
                    session_ambr.pDUSessionAggregateMaximumBitRateUL.buf);
  }

}

//------------------------------------------------------------------------------
void smf_context::handle_pdu_session_create_sm_context_request(
    std::shared_ptr<itti_n11_create_sm_context_request> smreq) {
  Logger::smf_app().info(
      "Handle a PDU Session Create SM Context Request message from AMF");

  oai::smf_server::model::SmContextCreateError smContextCreateError = { };
  oai::smf_server::model::ProblemDetails problem_details = { };
  oai::smf_server::model::RefToBinaryData refToBinaryData = { };
  std::string n1_sm_message, n1_sm_msg_hex;
  smf_n1_n2 smf_n1_n2_inst = { };
  bool request_accepted = true;

  //Step 1. get necessary information
  std::string dnn = smreq->req.get_dnn();
  snssai_t snssai = smreq->req.get_snssai();
  std::string request_type = smreq->req.get_request_type();
  supi_t supi = smreq->req.get_supi();
  supi64_t supi64 = smf_supi_to_u64(supi);
  uint32_t pdu_session_id = smreq->req.get_pdu_session_id();

  //Step 2. check the validity of the UE request, if valid send PDU Session Accept, otherwise send PDU Session Reject to AMF
  if (!verify_sm_context_request(smreq)) {
    // Not a valid request...
    Logger::smf_app().warn(
        "Received PDU_SESSION_CREATESMCONTEXT_REQUEST, the request is not valid!");
    problem_details.setCause(
        pdu_session_application_error_e2str[PDU_SESSION_APPLICATION_ERROR_SUBSCRIPTION_DENIED]);
    smContextCreateError.setError(problem_details);
    refToBinaryData.setContentId(N1_SM_CONTENT_ID);
    smContextCreateError.setN1SmMsg(refToBinaryData);
    smf_n1_n2_inst.create_n1_sm_container(
        smreq->req,
        PDU_SESSION_ESTABLISHMENT_REJECT,
        n1_sm_message,
        cause_value_5gsm_e::CAUSE_29_USER_AUTHENTICATION_OR_AUTHORIZATION_FAILED);
    smf_app_inst->convert_string_2_hex(n1_sm_message, n1_sm_msg_hex);
    smf_n11_inst->send_pdu_session_create_sm_context_response(
        smreq->http_response, smContextCreateError,
        Pistache::Http::Code::Forbidden, n1_sm_msg_hex);
    //TODO:
    //SMF unsubscribes to the modifications of Session Management Subscription data for (SUPI, DNN, S-NSSAI)
    //using Nudm_SDM_Unsubscribe()
    return;
  }

  //store HttpResponse and session-related information to be used when receiving the response from UPF
  itti_n11_create_sm_context_response *sm_context_resp =
      new itti_n11_create_sm_context_response(TASK_SMF_APP, TASK_SMF_N11,
                                              smreq->http_response);
  std::shared_ptr<itti_n11_create_sm_context_response> sm_context_resp_pending =
      std::shared_ptr<itti_n11_create_sm_context_response>(sm_context_resp);
  sm_context_resp->res.set_supi(supi);
  sm_context_resp->res.set_supi_prefix(smreq->req.get_supi_prefix());
  sm_context_resp->res.set_cause(REQUEST_ACCEPTED);
  sm_context_resp->res.set_pdu_session_id(pdu_session_id);
  sm_context_resp->res.set_snssai(snssai);
  sm_context_resp->res.set_dnn(dnn);
  sm_context_resp->res.set_pdu_session_type(smreq->req.get_pdu_session_type());
  sm_context_resp->res.set_pti(smreq->req.get_pti());
  sm_context_resp->set_scid(smreq->scid);

  //Step 3. find pdu_session
  std::shared_ptr<dnn_context> sd = { };
  bool find_dnn = find_dnn_context(snssai, dnn, sd);

  //step 3.1. create dnn context if not exist
  //At this step, this context should be existed
  if (nullptr == sd.get()) {
    Logger::smf_app().debug("DNN context (dnn_in_use %s) is not existed yet!",
                            dnn.c_str());
    sd = std::shared_ptr<dnn_context>(new dnn_context());
    sd.get()->in_use = true;
    sd.get()->dnn_in_use = dnn;
    sd.get()->nssai = snssai;
    insert_dnn(sd);
  } else {
    sd.get()->dnn_in_use = dnn;
    Logger::smf_app().debug("DNN context (dnn_in_use %s) is already existed",
                            dnn.c_str());
  }

  //step 3.2. create pdu session if not exist
  std::shared_ptr<smf_pdu_session> sp = { };
  bool find_pdu = sd.get()->find_pdu_session(pdu_session_id, sp);

  if (nullptr == sp.get()) {
    Logger::smf_app().debug("Create a new PDN connection");
    sp = std::shared_ptr<smf_pdu_session>(new smf_pdu_session());
    sp.get()->pdn_type.pdn_type = smreq->req.get_pdu_session_type();
    sp.get()->pdu_session_id = pdu_session_id;
    sp.get()->amf_id = smreq->req.get_serving_nf_id();  //amf id
    sd->insert_pdu_session(sp);
  } else {
    Logger::smf_app().debug("PDN connection is already existed!");
    //TODO:
  }

  //pending session??
  //Step 4. check if supi is authenticated

  //TODO: if "Integrity Protection is required", check UE Integrity Protection Maximum Data Rate
  //TODO: (Optional) Secondary authentication/authorization

  //TODO: Step 5. PCF selection
  //TODO: Step 5.1. SM Policy Association Establishment to get default PCC rules for this PDU session from PCF
  //For the moment, SMF uses the local policy (e.g., default QoS rule)

  //address allocation based on PDN type
  //Step 6. paa
  bool set_paa = false;
  paa_t paa = { };

  //Step 6. pco
  //section 6.2.4.2, TS 24.501
  //If the UE wants to use DHCPv4 for IPv4 address assignment, it shall indicate that to the network within the Extended
  //protocol configuration options IE in the PDU SESSION ESTABLISHMENT REQUEST
  //Extended protocol configuration options: See subclause 10.5.6.3A in 3GPP TS 24.008.

  //ExtendedProtocolConfigurationOptions extended_protocol_options = (sm_context_req_msg.get_nas_msg()).extendedprotocolconfigurationoptions;
  //TODO: PCO
  protocol_configuration_options_t pco_resp = { };
  protocol_configuration_options_ids_t pco_ids =
      { .pi_ipcp = 0, .ci_dns_server_ipv4_address_request = 0,
          .ci_ip_address_allocation_via_nas_signalling = 0,
          .ci_ipv4_address_allocation_via_dhcpv4 = 0,
          .ci_ipv4_link_mtu_request = 0 };
  //smf_app_inst->process_pco_request(extended_protocol_options, pco_resp, pco_ids);

  //Step 7. Address allocation based on PDN type
  Logger::smf_app().debug("UE address allocation");
  switch (sp->pdn_type.pdn_type) {
    case PDN_TYPE_E_IPV4: {
      if (!pco_ids.ci_ipv4_address_allocation_via_dhcpv4) {  //use SM NAS signalling
        //static or dynamic address allocation
        bool paa_res = false;  //how to define static or dynamic
        //depend of subscription information: staticIpAddress in DNN Configuration
        //TODO: check static IP address is available in the subscription information (SessionManagementSubscription) or in DHCP/DN-AAA

        std::shared_ptr<session_management_subscription> ss = { };
        std::shared_ptr<dnn_configuration_t> sdc = { };
        find_dnn_subscription(snssai, ss);
        if (nullptr != ss.get()) {
          ss.get()->find_dnn_configuration(sd->dnn_in_use, sdc);
          if (nullptr != sdc.get()) {
            paa.pdn_type.pdn_type = sdc.get()->pdu_session_types
                .default_session_type.pdu_session_type;
            //TODO: static ip address
          }
        }

        if ((not paa_res) || (not paa.is_ip_assigned())) {
          bool success = paa_dynamic::get_instance().get_free_paa(
              sd->dnn_in_use, paa);
          if (success) {
            set_paa = true;
          } else {
            //cause: ALL_DYNAMIC_ADDRESSES_ARE_OCCUPIED; //check for 5G?
          }
          // Static IP address allocation
        } else if ((paa_res) && (paa.is_ip_assigned())) {
          set_paa = true;
        }
        Logger::smf_app().info(
            "PAA, Ipv4 Address: %s",
            inet_ntoa(*((struct in_addr*) &paa.ipv4_address)));
      } else {  //use DHCP
        //TODO: DHCP
      }

    }
      break;

    case PDN_TYPE_E_IPV6: {
      //TODO:
    }
      break;

    case PDN_TYPE_E_IPV4V6: {
      //TODO:
    }
      break;

    default:
      Logger::smf_app().error("Unknown PDN type %d", sp->pdn_type.pdn_type);
      problem_details.setCause(
          pdu_session_application_error_e2str[PDU_SESSION_APPLICATION_ERROR_PDUTYPE_DENIED]);
      smContextCreateError.setError(problem_details);
      refToBinaryData.setContentId(N1_SM_CONTENT_ID);
      smContextCreateError.setN1SmMsg(refToBinaryData);
      //PDU Session Establishment Reject
      smf_n1_n2_inst.create_n1_sm_container(
          smreq->req, PDU_SESSION_ESTABLISHMENT_REJECT, n1_sm_message,
          cause_value_5gsm_e::CAUSE_28_UNKNOWN_PDU_SESSION_TYPE);
      smf_app_inst->convert_string_2_hex(n1_sm_message, n1_sm_msg_hex);
      smf_n11_inst->send_pdu_session_create_sm_context_response(
          sm_context_resp->http_response, smContextCreateError,
          Pistache::Http::Code::Forbidden, n1_sm_msg_hex);
      request_accepted = false;
      break;
  }

  //TODO: Step 8. SMF-initiated SM Policy Modification (with PCF)

  //Step 9. Create session establishment procedure and run the procedure
  //if request is accepted
  if (request_accepted) {
    if (set_paa) {
      sm_context_resp_pending->res.set_paa(paa);  //will be used when procedure is running
      sp->set(paa);
    } else {
      // Valid PAA sent in CSR ?
      //bool paa_res = csreq->gtp_ies.get(paa);
      //if ((paa_res) && ( paa.is_ip_assigned())) {
      //	sp->set(paa);
      //}
    }

    //(step 5 (4.3.2.2.1 TS 23.502)) Send reply to AMF (PDUSession_CreateSMContextResponse including Cause, SMContextId)
    //location header contains the URI of the created resource
    oai::smf_server::model::SmContextCreatedData smContextCreatedData;
    //TODO: assign values for smContextCreatedData

    //include only SmfServiceInstanceId (See section 6.1.6.2.3, 3GPP TS 29.502 v16.0.0)
    //Enable to test with tester
    //	std::string smContextRef = sm_context_req_msg.get_supi_prefix() + "-" + smf_supi_to_string(sm_context_req_msg.get_supi());
    std::string smContextRef = std::to_string(smreq->scid);
    //headers: Location: contains the URI of the newly created resource, according to the structure: {apiRoot}/nsmf-pdusession/{apiVersion}/sm-contexts/{smContextRef}
    std::string uri = smreq->req.get_api_root() + "/" + smContextRef.c_str();

    sm_context_resp->http_response.headers()
        .add<Pistache::Http::Header::Location>(uri);
    smf_n11_inst->send_pdu_session_create_sm_context_response(
        sm_context_resp->http_response, smContextCreatedData,
        Pistache::Http::Code::Created);

    //TODO: PDU Session authentication/authorization (Optional)
    //see section 4.3.2.3@3GPP TS 23.502 and section 6.3.1@3GPP TS 24.501

    Logger::smf_app().info("Create a procedure to process this message.");
    session_create_sm_context_procedure *proc =
        new session_create_sm_context_procedure(sp);
    std::shared_ptr<smf_procedure> sproc = std::shared_ptr<smf_procedure>(proc);

    insert_procedure(sproc);
    if (proc->run(smreq, sm_context_resp_pending, shared_from_this())) {
      // error !
      Logger::smf_app().info(
          "PDU Session Establishment Request: Create SM Context Request procedure failed");
      remove_procedure(proc);
      //Set cause to error to trigger PDU session establishment reject (step 10)
      sm_context_resp->res.set_cause(REMOTE_PEER_NOT_RESPONDING);  //TODO: check cause
    }

  } else {  //if request is rejected
    //TODO:
    //un-subscribe to the modifications of Session Management Subscription data for (SUPI, DNN, S-NSSAI)
  }

  //step 10. if error when establishing the pdu session,
  //send ITTI message to APP to trigger N1N2MessageTransfer towards AMFs (PDU Session Establishment Reject)
  if (sm_context_resp->res.get_cause() != REQUEST_ACCEPTED) {
    //clear pco, ambr
    //TODO:
    //free paa
    paa_t free_paa = { };
    free_paa = sm_context_resp->res.get_paa();
    if (free_paa.is_ip_assigned()) {
      switch (sp->pdn_type.pdn_type) {
        case PDN_TYPE_E_IPV4:
        case PDN_TYPE_E_IPV4V6:
          paa_dynamic::get_instance().release_paa(sd->dnn_in_use,
                                                  free_paa.ipv4_address);
          break;

        case PDN_TYPE_E_IPV6:
        case PDN_TYPE_E_NON_IP:
        default:
          ;
      }
      //sm_context_resp->res.clear_paa(); //TODO:
    }
    //clear the created context??
    //TODO:

    //Create PDU Session Establishment Reject and embedded in Namf_Communication_N1N2MessageTransfer Request
    Logger::smf_app().debug("Create PDU Session Establishment Reject");
    //TODO: Should check Cause for other cases
    cause_value_5gsm_e cause_n1 =
        { cause_value_5gsm_e::CAUSE_38_NETWORK_FAILURE };
    if (sm_context_resp->res.get_cause() == NO_RESOURCES_AVAILABLE) {
      cause_n1 = cause_value_5gsm_e::CAUSE_26_INSUFFICIENT_RESOURCES;
    }
    smf_n1_n2_inst.create_n1_sm_container(sm_context_resp_pending->res,
    PDU_SESSION_ESTABLISHMENT_REJECT,
                                          n1_sm_message, cause_n1);
    smf_app_inst->convert_string_2_hex(n1_sm_message, n1_sm_msg_hex);
    sm_context_resp_pending->res.set_n1_sm_message(n1_sm_msg_hex);

    //get supi and put into URL
    std::string supi_str;
    supi_t supi = sm_context_resp_pending->res.get_supi();
    supi_str = sm_context_resp_pending->res.get_supi_prefix() + "-"
        + smf_supi_to_string(supi);
    std::string url = std::string(
        inet_ntoa(*((struct in_addr*) &smf_cfg.amf_addr.ipv4_addr))) + ":"
        + std::to_string(smf_cfg.amf_addr.port)
        + fmt::format(NAMF_COMMUNICATION_N1N2_MESSAGE_TRANSFER_URL,
                      supi_str.c_str());
    sm_context_resp_pending->res.set_amf_url(url);

    //Fill the json part
    sm_context_resp_pending->res.n1n2_message_transfer_data["n1MessageContainer"]["n1MessageClass"] =
    N1N2_MESSAGE_CLASS;
    sm_context_resp_pending->res.n1n2_message_transfer_data["n1MessageContainer"]["n1MessageContent"]["contentId"] =
    N1_SM_CONTENT_ID;
    //sm_context_resp_pending->res.n1n2_message_transfer_data["ppi"] = 1; //Don't need this info for the moment
    sm_context_resp_pending->res.n1n2_message_transfer_data["pduSessionId"] =
        sm_context_resp_pending->res.get_pdu_session_id();

    //send ITTI message to N11 interface to trigger N1N2MessageTransfer towards AMFs
    Logger::smf_app().info("Sending ITTI message %s to task TASK_SMF_N11",
                           sm_context_resp_pending->get_msg_name());
    int ret = itti_inst->send_msg(sm_context_resp_pending);
    if (RETURNok != ret) {
      Logger::smf_app().error(
          "Could not send ITTI message %s to task TASK_SMF_N11",
          sm_context_resp_pending->get_msg_name());
    }
  }

}

//-------------------------------------------------------------------------------------
void smf_context::handle_pdu_session_update_sm_context_request(
    std::shared_ptr<itti_n11_update_sm_context_request> smreq) {
  Logger::smf_app().info(
      "Handle a PDU Session Update SM Context Request message from an AMF");
  pdu_session_update_sm_context_request sm_context_req_msg = smreq->req;
  smf_n1_n2 smf_n1_n2_inst = { };
  oai::smf_server::model::SmContextUpdateError smContextUpdateError = { };
  oai::smf_server::model::SmContextUpdatedData smContextUpdatedData = { };

  oai::smf_server::model::ProblemDetails problem_details = { };
  oai::smf_server::model::RefToBinaryData refToBinaryData = { };
  std::string n1_sm_msg, n1_sm_msg_hex;
  std::string n2_sm_info, n2_sm_info_hex;
  bool update_upf = false;
  session_management_procedures_type_e procedure_type(
      session_management_procedures_type_e::PDU_SESSION_ESTABLISHMENT_UE_REQUESTED);

  //Step 1. get DNN, SMF PDU session context. At this stage, dnn_context and pdu_session must be existed
  std::shared_ptr<dnn_context> sd = { };
  std::shared_ptr<smf_pdu_session> sp = { };
  bool find_dnn = find_dnn_context(sm_context_req_msg.get_snssai(),
                                   sm_context_req_msg.get_dnn(), sd);
  bool find_pdu = false;
  if (find_dnn) {
    find_pdu = sd.get()->find_pdu_session(
        sm_context_req_msg.get_pdu_session_id(), sp);
  }
  if (!find_dnn or !find_pdu) {
    //error, send reply to AMF with error code "Context Not Found"
    Logger::smf_app().warn("DNN or PDU session context does not exist!");
    problem_details.setCause(
        pdu_session_application_error_e2str[PDU_SESSION_APPLICATION_ERROR_CONTEXT_NOT_FOUND]);
    smContextUpdateError.setError(problem_details);
    smf_n11_inst->send_pdu_session_update_sm_context_response(
        smreq->http_response, smContextUpdateError,
        Pistache::Http::Code::Not_Found);
    return;
  }

  //we need to store HttpResponse and session-related information to be used when receiving the response from UPF
  itti_n11_update_sm_context_response *n11_sm_context_resp =
      new itti_n11_update_sm_context_response(TASK_SMF_APP, TASK_SMF_N11,
                                              smreq->http_response);
  std::shared_ptr<itti_n11_update_sm_context_response> sm_context_resp_pending =
      std::shared_ptr<itti_n11_update_sm_context_response>(n11_sm_context_resp);

  n11_sm_context_resp->res.set_supi(sm_context_req_msg.get_supi());
  n11_sm_context_resp->res.set_supi_prefix(
      sm_context_req_msg.get_supi_prefix());
  n11_sm_context_resp->res.set_cause(REQUEST_ACCEPTED);
  n11_sm_context_resp->res.set_pdu_session_id(
      sm_context_req_msg.get_pdu_session_id());
  n11_sm_context_resp->res.set_snssai(sm_context_req_msg.get_snssai());
  n11_sm_context_resp->res.set_dnn(sm_context_req_msg.get_dnn());

  //Step 2.1. Decode N1 (if content is available)
  if (sm_context_req_msg.n1_sm_msg_is_set()) {
    nas_message_t decoded_nas_msg = { };

    //Decode NAS and get the necessary information
    n1_sm_msg = sm_context_req_msg.get_n1_sm_message();
    memset(&decoded_nas_msg, 0, sizeof(nas_message_t));

    int decoder_rc = smf_n1_n2_inst.decode_n1_sm_container(decoded_nas_msg,
                                                           n1_sm_msg);
    if (decoder_rc != RETURNok) {
      //error, send reply to AMF with error code!!
      Logger::smf_app().warn("N1 SM container cannot be decoded correctly!");
      problem_details.setCause(
          pdu_session_application_error_e2str[PDU_SESSION_APPLICATION_ERROR_N1_SM_ERROR]);
      smContextUpdateError.setError(problem_details);
      smf_n11_inst->send_pdu_session_update_sm_context_response(
          smreq->http_response, smContextUpdateError,
          Pistache::Http::Code::Forbidden);
      return;
    }

    Logger::smf_app().debug(
        "NAS header information, extended_protocol_discriminator %d, security_header_type:%d",
        decoded_nas_msg.header.extended_protocol_discriminator,
        decoded_nas_msg.header.security_header_type);
    Logger::smf_app().debug("NAS header information, Message Type %d",
                            decoded_nas_msg.plain.sm.header.message_type);

    uint8_t message_type = decoded_nas_msg.plain.sm.header.message_type;
    switch (message_type) {

      case PDU_SESSION_MODIFICATION_REQUEST: {
        //PDU Session Modification procedure (UE-initiated, step 1.a, Section 4.3.3.2@3GPP TS 23.502)
        //UE initiated PDU session modification request (Step 1)
        Logger::smf_app().debug("PDU_SESSION_MODIFICATION_REQUEST");

        procedure_type =
            session_management_procedures_type_e::PDU_SESSION_MODIFICATION_UE_INITIATED_STEP1;
        sm_context_resp_pending->session_procedure_type =
            session_management_procedures_type_e::PDU_SESSION_MODIFICATION_UE_INITIATED_STEP1;

        //check if the PDU Session Release Command is already sent for this message (see section 6.3.3.5 @3GPP TS 24.501)
        if (sp.get()->get_pdu_session_status()
            == pdu_session_status_e::PDU_SESSION_INACTIVE_PENDING) {
          //Ignore the message
          Logger::smf_app().info(
              "A PDU Session Release Command has been sent for this session (session ID %d), ignore the message!",
              decoded_nas_msg.plain.sm.header.pdu_session_identity);
          return;
        }

        //check if the session is in state Modification pending, SMF will ignore this message (see section 6.3.2.5 @3GPP TS 24.501)
        if (sp.get()->get_pdu_session_status()
            == pdu_session_status_e::PDU_SESSION_MODIFICATION_PENDING) {
          //Ignore the message
          Logger::smf_app().info(
              "This PDU session is in MODIFICATION_PENDING State (session ID %d), ignore the message!",
              decoded_nas_msg.plain.sm.header.pdu_session_identity);
          return;
        }

        //See section 6.4.2 - UE-requested PDU Session modification procedure@ 3GPP TS 24.501
        //Verify PDU Session Identity
        if (sm_context_req_msg.get_pdu_session_id()
            != decoded_nas_msg.plain.sm.header.pdu_session_identity) {
          //TODO: PDU Session ID mismatch
        }

        //PTI
        Logger::smf_app().info(
            "PTI %d",
            decoded_nas_msg.plain.sm.header.procedure_transaction_identity);
        procedure_transaction_id_t pti = { .procedure_transaction_id =
            decoded_nas_msg.plain.sm.header.procedure_transaction_identity };
        n11_sm_context_resp->res.set_pti(pti);

        // Message Type

        //TODO: _5GSMCapability _5gsmcapability = decoded_nas_msg.plain.sm.pdu_session_modification_request._5gsmcapability;
        //
        //TODO: Cause
        //TODO: uint8_t maximum_number_of_supported_packet_filters = decoded_nas_msg.plain.sm.pdu_session_modification_request.maximumnumberofsupportedpacketfilters;
        //sp.get()->set_number_of_supported_packet_filters(maximum_number_of_supported_packet_filters);

        //TODO: AlwaysonPDUSessionRequested
        //TODO: IntergrityProtectionMaximumDataRate

        //Process QoS rules and Qos Flow descriptions
        uint16_t length_of_rule_ie = decoded_nas_msg.plain.sm
            .pdu_session_modification_request.qosrules.lengthofqosrulesie;

        pfcp::qfi_t generated_qfi = { .qfi = 0 };

        //QOSFlowDescriptions
        uint8_t number_of_flow_descriptions = decoded_nas_msg.plain.sm
            .pdu_session_modification_request.qosflowdescriptions
            .qosflowdescriptionsnumber;
        QOSFlowDescriptionsContents qos_flow_description_content = { };

        //Only one flow description for new requested QoS Flow
        QOSFlowDescriptionsContents *qos_flow_description =
            (QOSFlowDescriptionsContents*) calloc(
                1, sizeof(QOSFlowDescriptionsContents));

        if (number_of_flow_descriptions > 0) {
          qos_flow_description = decoded_nas_msg.plain.sm
              .pdu_session_modification_request.qosflowdescriptions
              .qosflowdescriptionscontents;

          for (int i = 0; i < number_of_flow_descriptions; i++) {
            if (qos_flow_description[i].qfi == NO_QOS_FLOW_IDENTIFIER_ASSIGNED) {
              //TODO: generate new QFI
              generated_qfi.qfi = (uint8_t) 77;        //hardcoded for now
              qos_flow_description_content = qos_flow_description[i];
              qos_flow_description_content.qfi = generated_qfi.qfi;
              break;
            }
          }
        }

        int i = 0;
        int length_of_rule = 0;
        while (length_of_rule_ie > 0) {
          QOSRulesIE qos_rules_ie = { };
          qos_rules_ie = decoded_nas_msg.plain.sm
              .pdu_session_modification_request.qosrules.qosrulesie[i];

          uint8_t rule_id = { 0 };
          pfcp::qfi_t qfi = { };
          smf_qos_flow qos_flow = { };

          length_of_rule = qos_rules_ie.LengthofQoSrule;

          //If UE requested a new GBR flow
          if ((qos_rules_ie.ruleoperationcode == CREATE_NEW_QOS_RULE)
              and (qos_rules_ie.segregation == SEGREGATION_REQUESTED)) {
            //Add a new QoS Flow
            if (qos_rules_ie.qosruleidentifer == NO_QOS_RULE_IDENTIFIER_ASSIGNED) {
              //Generate a new QoS rule
              sp.get()->generate_qos_rule_id(rule_id);
              Logger::smf_app().info("Create a new QoS rule (rule Id %d)",
                                     rule_id);
              qos_rules_ie.qosruleidentifer = rule_id;
            }

            sp.get()->add_qos_rule(qos_rules_ie);

            qfi.qfi = generated_qfi.qfi;
            qos_flow.qfi = generated_qfi.qfi;

            //set qos_profile from qos_flow_description_content
            qos_flow.qos_profile = { };

            for (int j = 0; j < qos_flow_description_content.numberofparameters;
                j++) {
              if (qos_flow_description_content.parameterslist[j]
                  .parameteridentifier == PARAMETER_IDENTIFIER_5QI) {
                qos_flow.qos_profile._5qi = qos_flow_description_content
                    .parameterslist[j].parametercontents._5qi;
              } else if (qos_flow_description_content.parameterslist[j]
                  .parameteridentifier == PARAMETER_IDENTIFIER_GFBR_UPLINK) {
                qos_flow.qos_profile.parameter.qos_profile_gbr.gfbr.uplink.unit =
                    qos_flow_description_content.parameterslist[j]
                        .parametercontents.gfbrormfbr_uplinkordownlink.uint;
                qos_flow.qos_profile.parameter.qos_profile_gbr.gfbr.uplink.value =
                    qos_flow_description_content.parameterslist[j]
                        .parametercontents.gfbrormfbr_uplinkordownlink.value;
              } else if (qos_flow_description_content.parameterslist[j]
                  .parameteridentifier == PARAMETER_IDENTIFIER_GFBR_DOWNLINK) {
                qos_flow.qos_profile.parameter.qos_profile_gbr.gfbr.donwlink
                    .unit = qos_flow_description_content.parameterslist[j]
                    .parametercontents.gfbrormfbr_uplinkordownlink.uint;
                qos_flow.qos_profile.parameter.qos_profile_gbr.gfbr.donwlink
                    .value = qos_flow_description_content.parameterslist[j]
                    .parametercontents.gfbrormfbr_uplinkordownlink.value;
              } else if (qos_flow_description_content.parameterslist[j]
                  .parameteridentifier == PARAMETER_IDENTIFIER_MFBR_UPLINK) {
                qos_flow.qos_profile.parameter.qos_profile_gbr.mfbr.uplink.unit =
                    qos_flow_description_content.parameterslist[j]
                        .parametercontents.gfbrormfbr_uplinkordownlink.uint;
                qos_flow.qos_profile.parameter.qos_profile_gbr.mfbr.uplink.value =
                    qos_flow_description_content.parameterslist[j]
                        .parametercontents.gfbrormfbr_uplinkordownlink.value;
              } else if (qos_flow_description_content.parameterslist[j]
                  .parameteridentifier == PARAMETER_IDENTIFIER_MFBR_DOWNLINK) {
                qos_flow.qos_profile.parameter.qos_profile_gbr.mfbr.donwlink
                    .unit = qos_flow_description_content.parameterslist[j]
                    .parametercontents.gfbrormfbr_uplinkordownlink.uint;
                qos_flow.qos_profile.parameter.qos_profile_gbr.mfbr.donwlink
                    .value = qos_flow_description_content.parameterslist[j]
                    .parametercontents.gfbrormfbr_uplinkordownlink.value;
              }
            }

            Logger::smf_app().debug("Add new QoS Flow with new QRI");
            //mark this rule to be synchronised with the UE
            sp.get()->update_qos_rule(qos_rules_ie);
            //Add new QoS flow
            sp.get()->add_qos_flow(qos_flow);

            //ADD QoS Flow to be updated
            qos_flow_context_updated qcu = { };
            qcu.set_qfi(pfcp::qfi_t(qos_flow.qfi));
            //qcu.set_ul_fteid(flow.ul_fteid);
            //qcu.set_dl_fteid(flow.dl_fteid);
            qcu.set_qos_profile(qos_flow.qos_profile);
            sm_context_resp_pending->res.add_qos_flow_context_updated(qcu);

          } else {  //update existing QRI
            Logger::smf_app().debug("Update existing QRI");
            qfi.qfi = qos_rules_ie.qosflowidentifer;
            if (sp.get()->get_qos_flow(qfi, qos_flow)) {
              sp.get()->update_qos_rule(qos_rules_ie);
              //update QoS flow
              sp.get()->add_qos_flow(qos_flow);

              //ADD QoS Flow to be updated
              qos_flow_context_updated qcu = { };
              qcu.set_qfi(pfcp::qfi_t(qos_flow.qfi));
              qcu.set_ul_fteid(qos_flow.ul_fteid);
              qcu.set_dl_fteid(qos_flow.dl_fteid);
              qcu.set_qos_profile(qos_flow.qos_profile);
              sm_context_resp_pending->res.add_qos_flow_context_updated(qcu);
            }
          }
          length_of_rule_ie -= (length_of_rule + 3);  // 2 for Length of QoS rules IE and 1 for QoS rule identifier

          i++;
        }

        //TODO: MappedEPSBearerContexts
        //TODO: ExtendedProtocolConfigurationOptions

        //section 6.3.2. Network-requested PDU Session modification procedure @ 3GPP TS 24.501
        //requested QoS rules (including packet filters) and/or requested QoS flow descriptions
        //session-AMBR, session TMBR
        // PTI
        //or UE capability

        //Create a N1 SM (PDU Session Modification Command) and N2 SM (PDU Session Resource Modify Request Transfer IE)
        std::string n1_sm_msg_to_be_created, n1_sm_msg_hex_to_be_created;
        std::string n2_sm_info_to_be_created, n2_sm_info_hex_to_be_created;
        //N1 SM (PDU Session Modification Command)
        smf_n1_n2_inst.create_n1_sm_container(
            n11_sm_context_resp->res, PDU_SESSION_MODIFICATION_COMMAND,
            n1_sm_msg_to_be_created, cause_value_5gsm_e::CAUSE_0_UNKNOWN);  //TODO: need cause?
        //N2 SM (PDU Session Resource Modify Request Transfer IE)
        smf_n1_n2_inst.create_n2_sm_information(
            n11_sm_context_resp->res, 1, n2_sm_info_type_e::PDU_RES_MOD_REQ,
            n2_sm_info_to_be_created);
        smf_app_inst->convert_string_2_hex(n1_sm_msg_to_be_created,
                                           n1_sm_msg_hex_to_be_created);
        smf_app_inst->convert_string_2_hex(n2_sm_info_to_be_created,
                                           n2_sm_info_hex_to_be_created);

        n11_sm_context_resp->res.set_n1_sm_message(n1_sm_msg_hex_to_be_created);
        n11_sm_context_resp->res.set_n2_sm_information(
            n2_sm_info_hex_to_be_created);
        n11_sm_context_resp->res.set_n2_sm_info_type("PDU_RES_MOD_REQ");

        //Fill the json part
        //N1SM
        n11_sm_context_resp->res.sm_context_updated_data["n1MessageContainer"]["n1MessageClass"] =
        N1N2_MESSAGE_CLASS;
        n11_sm_context_resp->res.sm_context_updated_data["n1MessageContainer"]["n1MessageContent"]["contentId"] =
        N1_SM_CONTENT_ID;  //part 2
        n11_sm_context_resp->res.sm_context_updated_data["n2InfoContainer"]["n2InformationClass"] =
        N1N2_MESSAGE_CLASS;
        n11_sm_context_resp->res.sm_context_updated_data["n2InfoContainer"]["smInfo"]["n2InfoContent"]["ngapIeType"] =
            "PDU_RES_MOD_REQ";  //NGAP message
        n11_sm_context_resp->res.sm_context_updated_data["n2InfoContainer"]["smInfo"]["n2InfoContent"]["ngapData"]["contentId"] =
        N2_SM_CONTENT_ID;  //part 3
        n11_sm_context_resp->res.sm_context_updated_data["n2InfoContainer"]["smInfo"]["PduSessionId"] =
            n11_sm_context_resp->res.get_pdu_session_id();

        //Update PDU Session status
        sp.get()->set_pdu_session_status(
            pdu_session_status_e::PDU_SESSION_MODIFICATION_PENDING);
        //start timer T3591
        //get smf_pdu_session and set the corresponding timer
        sp.get()->timer_T3591 = itti_inst->timer_setup(
            T3591_TIMER_VALUE_SEC, 0, TASK_SMF_APP, TASK_SMF_APP_TRIGGER_T3591,
            sm_context_req_msg.get_pdu_session_id());

        sm_context_resp_pending->session_procedure_type = procedure_type;
        //don't need to create a procedure to update UPF

        free_wrapper((void**) &qos_flow_description);
      }
        break;

        //PDU_SESSION_MODIFICATION_COMPLETE - PDU Session Modification procedure (UE-initiated/Network-requested) (step 3)
        //PDU Session Modification Command Complete
      case PDU_SESSION_MODIFICATION_COMPLETE: {
        //PDU Session Modification procedure (Section 4.3.3.2@3GPP TS 23.502)
        Logger::smf_app().debug("PDU_SESSION_MODIFICATION_COMPLETE");

        procedure_type =
            session_management_procedures_type_e::PDU_SESSION_MODIFICATION_UE_INITIATED_STEP3;

        /* see section 6.3.2.3@3GPP TS 24.501 V16.1.0
         Upon receipt of a PDU SESSION MODIFICATION COMPLETE message, the SMF shall stop timer T3591 and shall
         consider the PDU session as modified. If the selected SSC mode of the PDU session is "SSC mode 3" and the PDU
         SESSION MODIFICATION COMMAND message included 5GSM cause #39 "reactivation requested", the SMF shall
         start timer T3593. If the PDU Session Address Lifetime value is sent to the UE in the PDU SESSION
         MODIFICATION COMMAND message then timer T3593 shall be started with the same value, otherwise it shall use a
         default value.
         */
        //Update PDU Session status -> ACTIVE
        sp.get()->set_pdu_session_status(
            pdu_session_status_e::PDU_SESSION_ACTIVE);
        //stop T3591
        itti_inst->timer_remove(sp.get()->timer_T3591);

        sm_context_resp_pending->session_procedure_type = procedure_type;
        //don't need to create a procedure to update UPF
      }
        break;

        //PDU_SESSION_MODIFICATION_COMMAND_REJECT - PDU Session Modification Procedure
      case PDU_SESSION_MODIFICATION_COMMAND_REJECT: {
        //PDU Session Modification procedure (Section 4.3.3.2@3GPP TS 23.502)
        Logger::smf_app().debug("PDU_SESSION_MODIFICATION_COMMAND_REJECT");

        procedure_type =
            session_management_procedures_type_e::PDU_SESSION_MODIFICATION_UE_INITIATED_STEP3;

        //Verify PDU Session Identity
        if (sm_context_req_msg.get_pdu_session_id()
            != decoded_nas_msg.plain.sm.header.pdu_session_identity) {
          //TODO: PDU Session ID mismatch
        }

        //PTI
        Logger::smf_app().info(
            "PTI %d",
            decoded_nas_msg.plain.sm.header.procedure_transaction_identity);
        procedure_transaction_id_t pti = { .procedure_transaction_id =
            decoded_nas_msg.plain.sm.header.procedure_transaction_identity };
        n11_sm_context_resp->res.set_pti(pti);

        // Message Type
        //_5GSMCause
        //presence
        //ExtendedProtocolConfigurationOptions

        if (decoded_nas_msg.plain.sm.pdu_session_modification_command_reject
            ._5gsmcause
            == static_cast<uint8_t>(cause_value_5gsm_e::CAUSE_43_INVALID_PDU_SESSION_IDENTITY)) {
          //Update PDU Session status -> INACTIVE
          sp.get()->set_pdu_session_status(
              pdu_session_status_e::PDU_SESSION_INACTIVE);
          //TODO: Release locally the existing PDU Session (see section 6.3.2.5@3GPP TS 24.501)
        } else if (sp.get()->get_pdu_session_status()
            == pdu_session_status_e::PDU_SESSION_MODIFICATION_PENDING) {
          //Update PDU Session status -> ACTIVE
          sp.get()->set_pdu_session_status(
              pdu_session_status_e::PDU_SESSION_ACTIVE);
        }

        //stop T3591
        itti_inst->timer_remove(sp.get()->timer_T3591);

        sm_context_resp_pending->session_procedure_type = procedure_type;
        //don't need to create a procedure to update UPF
      }
        break;

        //PDU Session Release UE-Initiated (Step 1)
      case PDU_SESSION_RELEASE_REQUEST: {
        //PDU Session Release procedure (Section 4.3.4@3GPP TS 23.502)
        Logger::smf_app().debug("PDU_SESSION_RELEASE_REQUEST");
        Logger::smf_app().info(
            "PDU Session Release (UE-Initiated), processing N1 SM Information");
        procedure_type =
            session_management_procedures_type_e::PDU_SESSION_RELEASE_UE_REQUESTED_STEP1;
        //verify PDU Session ID
        if (sm_context_req_msg.get_pdu_session_id()
            != decoded_nas_msg.plain.sm.header.pdu_session_identity) {
          //TODO: PDU Session ID mismatch
        }

        //Abnormal cases in network side (see section 6.4.3.6 @3GPP TS 24.501)
        if (sp.get()->get_pdu_session_status()
            == pdu_session_status_e::PDU_SESSION_INACTIVE) {
          Logger::smf_app().warn(
              "PDU Session status: INACTIVE, send PDU Session Release Reject to UE!");
          problem_details.setCause(
              pdu_session_application_error_e2str[PDU_SESSION_APPLICATION_ERROR_NETWORK_FAILURE]);  //TODO: which cause?
          smContextUpdateError.setError(problem_details);
          refToBinaryData.setContentId(N1_SM_CONTENT_ID);
          smContextUpdateError.setN1SmMsg(refToBinaryData);
          smf_n1_n2_inst.create_n1_sm_container(
              sm_context_req_msg, PDU_SESSION_RELEASE_REJECT, n1_sm_msg,
              cause_value_5gsm_e::CAUSE_43_INVALID_PDU_SESSION_IDENTITY);
          smf_app_inst->convert_string_2_hex(n1_sm_msg, n1_sm_msg_hex);
          smf_n11_inst->send_pdu_session_update_sm_context_response(
              smreq->http_response, smContextUpdateError,
              Pistache::Http::Code::Forbidden, n1_sm_msg_hex);
        }
        //Abnormal cases in network side (see section 6.3.3.5 @3GPP TS 24.501)
        if (sp.get()->get_pdu_session_status()
            == pdu_session_status_e::PDU_SESSION_INACTIVE_PENDING) {
          //Ignore the message
          Logger::smf_app().info(
              "A PDU Session Release Command has been sent for this session (session ID %d), ignore the message!",
              decoded_nas_msg.plain.sm.header.pdu_session_identity);
          return;
        }

        //PTI
        Logger::smf_app().info(
            "PTI %d",
            decoded_nas_msg.plain.sm.header.procedure_transaction_identity);
        procedure_transaction_id_t pti = { .procedure_transaction_id =
            decoded_nas_msg.plain.sm.header.procedure_transaction_identity };
        n11_sm_context_resp->res.set_pti(pti);

        //Message Type
        //Presence
        //5GSM Cause
        //Extended Protocol Configuration Options

        //Release the resources related to this PDU Session (in Procedure)

        //get the associated QoS flows: to be used for PFCP Session Modification procedure
        std::vector<smf_qos_flow> qos_flows;
        sp.get()->get_qos_flows(qos_flows);
        for (auto i : qos_flows) {
          smreq->req.add_qfi(i.qfi.qfi);
        }

        //need to update UPF accordingly
        update_upf = true;
      }
        break;

        //PDU Session Release UE-Initiated (Step 3)
      case PDU_SESSION_RELEASE_COMPLETE: {
        //PDU Session Release procedure
        Logger::smf_app().debug("PDU_SESSION_RELEASE_COMPLETE");
        Logger::smf_app().info(
            "PDU Session Release Complete (UE-Initiated), processing N1 SM Information");
        procedure_type =
            session_management_procedures_type_e::PDU_SESSION_RELEASE_UE_REQUESTED_STEP3;
        //verify PDU Session ID
        if (sm_context_req_msg.get_pdu_session_id()
            != decoded_nas_msg.plain.sm.header.pdu_session_identity) {
          //TODO: PDU Session ID mismatch
        }
        //PTI
        Logger::smf_app().info(
            "PTI %d",
            decoded_nas_msg.plain.sm.header.procedure_transaction_identity);
        procedure_transaction_id_t pti = { .procedure_transaction_id =
            decoded_nas_msg.plain.sm.header.procedure_transaction_identity };

        //Message Type
        if (decoded_nas_msg.plain.sm.header.message_type
            != PDU_SESSION_RELEASE_COMPLETE) {
          //TODO: Message Type mismatch
        }
        //5GSM Cause
        //Extended Protocol Configuration Options

        //Update PDU Session status -> INACTIVE
        sp.get()->set_pdu_session_status(
            pdu_session_status_e::PDU_SESSION_INACTIVE);
        //Stop timer T3592
        itti_inst->timer_remove(sp.get()->timer_T3592);

        sm_context_resp_pending->session_procedure_type = procedure_type;
        //don't need to create a procedure to update UPF

        //TODO: SMF invokes Nsmf_PDUSession_SMContextStatusNotify to notify AMF that the SM context for this PDU Session is released
        //TODO: if dynamic PCC applied, SMF invokes an SM Policy Association Termination
        //TODO: SMF unsubscribes from Session Management Subscription data changes notification from UDM by invoking Numd_SDM_Unsubscribe
        if (sd.get()->get_number_pdu_sessions() == 0) {
          Logger::smf_app().debug(
              "Unsubscribe from Session Management Subscription data changes notification from UDM");
          //TODO: unsubscribes from Session Management Subscription data changes notification from UDM
        }
        //TODO: Invoke Nudm_UECM_Deregistration
      }
        break;

        //To be verified
      case PDU_SESSION_RELEASE_COMMAND: {
        //PDU Session Release procedure (Section 4.3.4@3GPP TS 23.502)
        //TODO:

      }
        break;

      default: {
        Logger::smf_app().warn("Unknown message type %d", message_type);
        //TODO:
      }
    }  //end switch

  }

  //Step 2.2. Decode N2 (if content is available)
  if (sm_context_req_msg.n2_sm_info_is_set()) {

    //get necessary information (N2 SM information)
    std::string n2_sm_info_type_str = smreq->req.get_n2_sm_info_type();
    std::string n2_sm_information = smreq->req.get_n2_sm_information();
    n2_sm_info_type_e n2_sm_info_type = smf_app_inst->n2_sm_info_type_str2e(
        n2_sm_info_type_str);

    //decode N2 SM Info
    switch (n2_sm_info_type) {

      case n2_sm_info_type_e::PDU_RES_SETUP_RSP: {
        //PDU Session Resource Setup Response Transfer is included in the following procedures:
        //1 - UE-Requested PDU Session Establishment procedure (Section 4.3.2.2.1@3GPP TS 23.502)
        //2 - UE Triggered Service Request Procedure (step 2)

        Logger::smf_app().info("PDU Session Resource Setup Response Transfer");
        if (sm_context_req_msg.rat_type_is_set()
            and sm_context_req_msg.an_type_is_set()) {
          procedure_type =
              session_management_procedures_type_e::SERVICE_REQUEST_UE_TRIGGERED_STEP2;
          Logger::smf_app().info(
              "UE-Triggered Service Request, processing N2 SM Information");
        } else {
          procedure_type =
              session_management_procedures_type_e::PDU_SESSION_ESTABLISHMENT_UE_REQUESTED;
          Logger::smf_app().info(
              "PDU Session Establishment Request, processing N2 SM Information");
        }

        //Ngap_PDUSessionResourceSetupResponseTransfer
        std::shared_ptr<Ngap_PDUSessionResourceSetupResponseTransfer_t> decoded_msg =
            std::make_shared<Ngap_PDUSessionResourceSetupResponseTransfer_t>();
        int decode_status = smf_n1_n2_inst.decode_n2_sm_information(
            decoded_msg, n2_sm_information);
        if (decode_status == RETURNerror) {
          //error, send error to AMF
          Logger::smf_app().warn(
              "Decode N2 SM (Ngap_PDUSessionResourceSetupResponseTransfer) failed!");
          problem_details.setCause(
              pdu_session_application_error_e2str[PDU_SESSION_APPLICATION_ERROR_N2_SM_ERROR]);
          smContextUpdateError.setError(problem_details);
          refToBinaryData.setContentId(N1_SM_CONTENT_ID);
          smContextUpdateError.setN1SmMsg(refToBinaryData);
          //PDU Session Establishment Reject
          //24.501: response with a 5GSM STATUS message including cause "#95 Semantically incorrect message"
          smf_n1_n2_inst.create_n1_sm_container(
              sm_context_req_msg, PDU_SESSION_ESTABLISHMENT_REJECT, n1_sm_msg,
              cause_value_5gsm_e::CAUSE_95_SEMANTICALLY_INCORRECT_MESSAGE);
          smf_app_inst->convert_string_2_hex(n1_sm_msg, n1_sm_msg_hex);
          smf_n11_inst->send_pdu_session_update_sm_context_response(
              smreq->http_response, smContextUpdateError,
              Pistache::Http::Code::Forbidden);
          return;
        }

        //store AN Tunnel Info + list of accepted QFIs
        fteid_t dl_teid;
        memcpy(
            &dl_teid.teid_gre_key,
            decoded_msg->dLQosFlowPerTNLInformation.uPTransportLayerInformation
                .choice.gTPTunnel->gTP_TEID.buf,
            sizeof(struct in_addr));
        memcpy(
            &dl_teid.ipv4_address,
            decoded_msg->dLQosFlowPerTNLInformation.uPTransportLayerInformation
                .choice.gTPTunnel->transportLayerAddress.buf,
            4);
        Logger::smf_app().debug("DL GTP_F-TEID (AN F-TEID) " "0x%" PRIx32 " ",
                                htonl(dl_teid.teid_gre_key));
        Logger::smf_app().debug("uPTransportLayerInformation (AN IP Addr) %s",
                                conv::toString(dl_teid.ipv4_address).c_str());

        smreq->req.set_dl_fteid(dl_teid);

        for (int i = 0;
            i
                < decoded_msg->dLQosFlowPerTNLInformation.associatedQosFlowList
                    .list.count; i++) {
          pfcp::qfi_t qfi(
              (uint8_t) (decoded_msg->dLQosFlowPerTNLInformation
                  .associatedQosFlowList.list.array[i])->qosFlowIdentifier);
          smreq->req.add_qfi(qfi);
          Logger::smf_app().debug(
              "QoSFlowPerTNLInformation, AssociatedQosFlowList, QFI %d",
              (decoded_msg->dLQosFlowPerTNLInformation.associatedQosFlowList
                  .list.array[i])->qosFlowIdentifier);
        }

        //need to update UPF accordingly
        update_upf = true;
      }
        break;

        //PDU Session Modification procedure (UE-initiated, Section 4.3.3.2@3GPP TS 23.502 or SMF-Requested)(Step 2)
      case n2_sm_info_type_e::PDU_RES_MOD_RSP: {
        Logger::smf_app().info("PDU_RES_MOD_RSP");
        Logger::smf_app().info(
            "PDU Session Modification Procedure, processing N2 SM Information");

        procedure_type =
            session_management_procedures_type_e::PDU_SESSION_MODIFICATION_UE_INITIATED_STEP2;

        //Ngap_PDUSessionResourceModifyResponseTransfer
        std::shared_ptr<Ngap_PDUSessionResourceModifyResponseTransfer_t> decoded_msg =
            std::make_shared<Ngap_PDUSessionResourceModifyResponseTransfer_t>();
        int decode_status = smf_n1_n2_inst.decode_n2_sm_information(
            decoded_msg, n2_sm_information);

        if (decode_status == RETURNerror) {
          Logger::smf_app().warn(
              "Decode N2 SM (Ngap_PDUSessionResourceModifyResponseTransfer) failed!");
          problem_details.setCause(
              pdu_session_application_error_e2str[PDU_SESSION_APPLICATION_ERROR_N2_SM_ERROR]);
          smContextUpdateError.setError(problem_details);
          smf_n11_inst->send_pdu_session_update_sm_context_response(
              smreq->http_response, smContextUpdateError,
              Pistache::Http::Code::Forbidden);
          return;
        }

        //see section 8.2.3 (PDU Session Resource Modify) @3GPP TS 38.413
        //if dL_NGU_UP_TNLInformation is included, it shall be considered as the new DL transport layer addr for the PDU session (should be verified)
        //TODO: may include uL_NGU_UP_TNLInformation (mapping between each new DL transport layer address and the corresponding UL transport layer address)
        fteid_t dl_teid;
        memcpy(
            &dl_teid.teid_gre_key,
            decoded_msg->dL_NGU_UP_TNLInformation->choice.gTPTunnel->gTP_TEID
                .buf,
            sizeof(struct in_addr));
        memcpy(
            &dl_teid.ipv4_address,
            decoded_msg->dL_NGU_UP_TNLInformation->choice.gTPTunnel
                ->transportLayerAddress.buf,
            4);
        smreq->req.set_dl_fteid(dl_teid);

        Logger::smf_app().debug("gTP_TEID " "0x%" PRIx32 " ",
                                htonl(dl_teid.teid_gre_key));
        Logger::smf_app().debug("uPTransportLayerInformation IP Addr %s",
                                conv::toString(dl_teid.ipv4_address).c_str());

        //list of Qos Flows which have been successfully setup or modified
        if (decoded_msg->qosFlowAddOrModifyResponseList) {
          for (int i = 0;
              i < decoded_msg->qosFlowAddOrModifyResponseList->list.count;
              i++) {
            smreq->req.add_qfi(
                (decoded_msg->qosFlowAddOrModifyResponseList->list.array[i])
                    ->qosFlowIdentifier);
          }
        }

        //TODO: list of QoS Flows which have failed to be modified, qosFlowFailedToAddOrModifyList
        //TODO: additionalDLQosFlowPerTNLInformation

        //need to update UPF accordingly
        update_upf = true;
      }
        break;

        //PDU Session Modification procedure
      case n2_sm_info_type_e::PDU_RES_MOD_FAIL: {
        Logger::smf_app().info("PDU_RES_MOD_FAIL");
        //TODO: To be completed
      }
        break;

        //PDU Session Release procedure (UE-initiated, Section 4.3.4.2@3GPP TS 23.502 or SMF-Requested)(Step 2)
      case n2_sm_info_type_e::PDU_RES_REL_RSP: {
        Logger::smf_app().info("PDU_RES_REL_RSP");
        Logger::smf_app().info(
            "PDU Session Release (UE-initiated), processing N2 SM Information");

        procedure_type =
            session_management_procedures_type_e::PDU_SESSION_RELEASE_UE_REQUESTED_STEP2;
        //TODO: SMF does nothing (Step 7, section 4.3.4.2@3GPP TS 23.502)
        //Ngap_PDUSessionResourceReleaseResponseTransfer
        std::shared_ptr<Ngap_PDUSessionResourceReleaseResponseTransfer_t> decoded_msg =
            std::make_shared<Ngap_PDUSessionResourceReleaseResponseTransfer_t>();
        int decode_status = smf_n1_n2_inst.decode_n2_sm_information(
            decoded_msg, n2_sm_information);
        if (decode_status == RETURNerror) {
          Logger::smf_app().warn(
              "Decode N2 SM (Ngap_PDUSessionResourceReleaseResponseTransfer) failed!");
          problem_details.setCause(
              pdu_session_application_error_e2str[PDU_SESSION_APPLICATION_ERROR_N2_SM_ERROR]);
          smContextUpdateError.setError(problem_details);
          smf_n11_inst->send_pdu_session_update_sm_context_response(
              smreq->http_response, smContextUpdateError,
              Pistache::Http::Code::Forbidden);
          return;
        }

        sm_context_resp_pending->session_procedure_type = procedure_type;
        //don't need to create a procedure to update UPF
      }
        break;

      default: {
        Logger::smf_app().warn("Unknown N2 SM info type %d", n2_sm_info_type);
      }

    }  //end switch
  }

  //Step 3. For Service Request
  if (!sm_context_req_msg.n1_sm_msg_is_set()
      and !sm_context_req_msg.n2_sm_info_is_set()
      and sm_context_req_msg.upCnx_state_is_set()) {
    Logger::smf_app().info("Service Request (UE-triggered, step 1)");

    procedure_type =
        session_management_procedures_type_e::SERVICE_REQUEST_UE_TRIGGERED_STEP1;
    //Update upCnxState
    sp.get()->set_upCnx_state(upCnx_state_e::UPCNX_STATE_ACTIVATING);

    //get QFIs associated with PDU session ID
    std::vector<smf_qos_flow> qos_flows = { };
    sp.get()->get_qos_flows(qos_flows);
    for (auto i : qos_flows) {
      smreq->req.add_qfi(i.qfi.qfi);

      qos_flow_context_updated qcu = { };
      qcu.set_cause(REQUEST_ACCEPTED);
      qcu.set_qfi(i.qfi);
      qcu.set_ul_fteid(i.ul_fteid);
      qcu.set_qos_profile(i.qos_profile);
      sm_context_resp_pending->res.add_qos_flow_context_updated(qcu);

    }

    sm_context_resp_pending->session_procedure_type = procedure_type;

    // Create N2 SM Information: PDU Session Resource Setup Request Transfer IE
    //N2 SM Information
    smf_n1_n2_inst.create_n2_sm_information(
        sm_context_resp_pending->res, 1, n2_sm_info_type_e::PDU_RES_SETUP_REQ,
        n2_sm_info);
    smf_app_inst->convert_string_2_hex(n2_sm_info, n2_sm_info_hex);
    sm_context_resp_pending->res.set_n2_sm_information(n2_sm_info_hex);

    //fill the content of SmContextUpdatedData
    sm_context_resp_pending->res.sm_context_updated_data = { };
    sm_context_resp_pending->res.sm_context_updated_data["n2InfoContainer"]["n2InformationClass"] =
    N1N2_MESSAGE_CLASS;
    sm_context_resp_pending->res.sm_context_updated_data["n2InfoContainer"]["smInfo"]["PduSessionId"] =
        sm_context_resp_pending->res.get_pdu_session_id();
    sm_context_resp_pending->res.sm_context_updated_data["n2InfoContainer"]["smInfo"]["n2InfoContent"]["ngapData"]["contentId"] =
    N2_SM_CONTENT_ID;
    sm_context_resp_pending->res.sm_context_updated_data["n2InfoContainer"]["smInfo"]["n2InfoContent"]["ngapIeType"] =
        "PDU_RES_SETUP_REQ";  //NGAP message
    sm_context_resp_pending->res.sm_context_updated_data["upCnxState"] =
        "ACTIVATING";

    //Update upCnxState to ACTIVATING
    sp.get()->set_upCnx_state(upCnx_state_e::UPCNX_STATE_ACTIVATING);

    //do not need update UPF
    update_upf = false;
    //TODO: If new UPF is used, need to send N4 Session Modification Request/Response to new/old UPF

    //Accept the activation of UP connection and continue to using the current UPF
    //TODO: Accept the activation of UP connection and select a new UPF
    //Reject the activation of UP connection
    //SMF fails to find a suitable I-UPF: i) trigger re-establishment of PDU Session;
    //or ii) keep PDU session but reject the activation of UP connection;
    //or iii) release PDU session

  }

  //Step 4. For AMF-initiated Session Release (with release indication)
  if (sm_context_req_msg.release_is_set()) {
    procedure_type =
        session_management_procedures_type_e::PDU_SESSION_RELEASE_AMF_INITIATED;
    //get QFIs associated with PDU session ID
    std::vector<smf_qos_flow> qos_flows = { };
    sp.get()->get_qos_flows(qos_flows);
    for (auto i : qos_flows) {
      smreq->req.add_qfi(i.qfi.qfi);
    }
    //need update UPF
    update_upf = true;
  }

  //Step 5. Create a procedure for update sm context and let the procedure handle the request if necessary
  if (update_upf) {
    session_update_sm_context_procedure *proc =
        new session_update_sm_context_procedure(sp);
    std::shared_ptr<smf_procedure> sproc = std::shared_ptr<smf_procedure>(proc);
    proc->session_procedure_type = procedure_type;

    insert_procedure(sproc);
    if (proc->run(smreq, sm_context_resp_pending, shared_from_this())) {
      // error !
      Logger::smf_app().info(
          "PDU Update SM Context Request procedure failed (session procedure type %s)",
          session_management_procedures_type_e2str[static_cast<int>(procedure_type)]
              .c_str());
      remove_procedure(proc);

      //send error to AMF according to the procedure
      switch (procedure_type) {
        case session_management_procedures_type_e::PDU_SESSION_ESTABLISHMENT_UE_REQUESTED: {
          problem_details.setCause(
              pdu_session_application_error_e2str[PDU_SESSION_APPLICATION_ERROR_PEER_NOT_RESPONDING]);
          smContextUpdateError.setError(problem_details);
          //TODO: need to verify with/without N1 SM
          refToBinaryData.setContentId(N1_SM_CONTENT_ID);
          smContextUpdateError.setN1SmMsg(refToBinaryData);
          //PDU Session Establishment Reject
          smf_n1_n2_inst.create_n1_sm_container(
              sm_context_req_msg, PDU_SESSION_ESTABLISHMENT_REJECT, n1_sm_msg,
              cause_value_5gsm_e::CAUSE_38_NETWORK_FAILURE);
          smf_app_inst->convert_string_2_hex(n1_sm_msg, n1_sm_msg_hex);
          smf_n11_inst->send_pdu_session_update_sm_context_response(
              smreq->http_response, smContextUpdateError,
              Pistache::Http::Code::Forbidden);
        }
          break;

        case session_management_procedures_type_e::SERVICE_REQUEST_UE_TRIGGERED_STEP1:
        case session_management_procedures_type_e::PDU_SESSION_MODIFICATION_SMF_REQUESTED:
        case session_management_procedures_type_e::PDU_SESSION_MODIFICATION_AN_REQUESTED:
        case session_management_procedures_type_e::PDU_SESSION_MODIFICATION_UE_INITIATED_STEP2:
        case session_management_procedures_type_e::PDU_SESSION_RELEASE_AMF_INITIATED:
        case session_management_procedures_type_e::PDU_SESSION_RELEASE_UE_REQUESTED_STEP1: {
          problem_details.setCause(
              pdu_session_application_error_e2str[PDU_SESSION_APPLICATION_ERROR_PEER_NOT_RESPONDING]);
          smContextUpdateError.setError(problem_details);
          smf_n11_inst->send_pdu_session_update_sm_context_response(
              smreq->http_response, smContextUpdateError,
              Pistache::Http::Code::Forbidden);
        }
          break;

        default: {
          //TODO: to be updated
          problem_details.setCause(
              pdu_session_application_error_e2str[PDU_SESSION_APPLICATION_ERROR_PEER_NOT_RESPONDING]);
          smContextUpdateError.setError(problem_details);
          smf_n11_inst->send_pdu_session_update_sm_context_response(
              smreq->http_response, smContextUpdateError,
              Pistache::Http::Code::Forbidden);
        }
      }

      return;

    }
  } else {
    Logger::smf_app().info("Sending ITTI message %s to task TASK_SMF_N11",
                           sm_context_resp_pending->get_msg_name());
    int ret = itti_inst->send_msg(sm_context_resp_pending);
    if (RETURNok != ret) {
      Logger::smf_app().error(
          "Could not send ITTI message %s to task TASK_SMF_N11",
          sm_context_resp_pending->get_msg_name());
    }
  }

  //TODO, Step 6
  /*  If the PDU Session establishment is not successful, the SMF informs the AMF by invoking Nsmf_PDUSession_SMContextStatusNotify (Release). The SMF also releases any N4
   session(s) created, any PDU Session address if allocated (e.g. IP address) and releases the association with PCF,
   if any. In this case, step 19 is skipped.
   see step 18, section 4.3.2.2.1@3GPP TS 23.502)
   */

}

//-------------------------------------------------------------------------------------
void smf_context::handle_pdu_session_release_sm_context_request(
    std::shared_ptr<itti_n11_release_sm_context_request> smreq) {
  Logger::smf_app().info(
      "Handle a PDU Session Release SM Context Request message from AMF");

  bool update_upf = false;

  //Step 1. get DNN, SMF PDU session context. At this stage, dnn_context and pdu_session must be existed
  std::shared_ptr<dnn_context> sd = { };
  std::shared_ptr<smf_pdu_session> sp = { };
  bool find_dnn = find_dnn_context(smreq->req.get_snssai(),
                                   smreq->req.get_dnn(), sd);
  bool find_pdu = false;
  if (find_dnn) {
    find_pdu = sd.get()->find_pdu_session(smreq->req.get_pdu_session_id(), sp);
  }
  if (!find_dnn or !find_pdu) {
    //error, send reply to AMF with error code "Context Not Found"
    Logger::smf_app().warn("DNN or PDU session context does not exist!");
    smf_n11_inst->send_pdu_session_release_sm_context_response(
        smreq->http_response, Pistache::Http::Code::Not_Found);
    return;
  }

  //we need to store HttpResponse and session-related information to be used when receiving the response from UPF
  itti_n11_release_sm_context_response *n11_sm_context_resp =
      new itti_n11_release_sm_context_response(TASK_SMF_APP, TASK_SMF_N11,
                                               smreq->http_response);

  std::shared_ptr<itti_n11_release_sm_context_response> sm_context_resp_pending =
      std::shared_ptr<itti_n11_release_sm_context_response>(
          n11_sm_context_resp);

  n11_sm_context_resp->res.set_supi(smreq->req.get_supi());
  n11_sm_context_resp->res.set_supi_prefix(smreq->req.get_supi_prefix());
  n11_sm_context_resp->res.set_cause(REQUEST_ACCEPTED);
  n11_sm_context_resp->res.set_pdu_session_id(smreq->req.get_pdu_session_id());
  n11_sm_context_resp->res.set_snssai(smreq->req.get_snssai());
  n11_sm_context_resp->res.set_dnn(smreq->req.get_dnn());

  session_release_sm_context_procedure *proc =
      new session_release_sm_context_procedure(sp);
  std::shared_ptr<smf_procedure> sproc = std::shared_ptr<smf_procedure>(proc);

  insert_procedure(sproc);
  if (proc->run(smreq, sm_context_resp_pending, shared_from_this())) {
    // error !
    Logger::smf_app().info("PDU Release SM Context Request procedure failed");
  }

}

//------------------------------------------------------------------------------
void smf_context::handle_pdu_session_modification_network_requested(
    std::shared_ptr<itti_nx_trigger_pdu_session_modification> itti_msg) {
  Logger::smf_app().info(
      "Handle a PDU Session Modification Request (SMF-Requested)");

  smf_n1_n2 smf_n1_n2_inst = { };
  oai::smf_server::model::SmContextUpdateError smContextUpdateError = { };
  oai::smf_server::model::SmContextUpdatedData smContextUpdatedData = { };

  oai::smf_server::model::ProblemDetails problem_details = { };
  oai::smf_server::model::RefToBinaryData refToBinaryData = { };
  std::string n1_sm_msg, n1_sm_msg_hex;
  std::string n2_sm_info, n2_sm_info_hex;

  //Step 1. get DNN, SMF PDU session context. At this stage, dnn_context and pdu_session must be existed
  std::shared_ptr<dnn_context> sd = { };
  std::shared_ptr<smf_pdu_session> sp = { };
  bool find_dnn = find_dnn_context(itti_msg->msg.get_snssai(),
                                   itti_msg->msg.get_dnn(), sd);
  bool find_pdu = false;
  if (find_dnn) {
    find_pdu = sd.get()->find_pdu_session(itti_msg->msg.get_pdu_session_id(),
                                          sp);
  }
  if (!find_dnn or !find_pdu) {
    Logger::smf_app().warn("DNN or PDU session context does not exist!");
    return;
  }

  std::vector<pfcp::qfi_t> list_qfis_to_be_updated;
  itti_msg->msg.get_qfis(list_qfis_to_be_updated);

  //add QFI(s), QoS Profile(s), QoS Rules
  for (auto it : list_qfis_to_be_updated) {
    Logger::smf_app().debug("QFI to be updated: %d", it.qfi);

    std::vector<QOSRulesIE> qos_rules;
    sp.get()->get_qos_rules(it, qos_rules);
    //mark QoS rule to be updated for all rules associated with the QFIs
    for (auto r : qos_rules) {
      sp.get()->mark_qos_rule_to_be_synchronised(r.qosruleidentifer);
    }

    //list of QFIs and QoS profiles
    smf_qos_flow flow = { };
    if (sp.get()->get_qos_flow(it, flow)) {
      qos_flow_context_updated qcu = { };
      qcu.set_qfi(flow.qfi);
      qcu.set_qos_profile(flow.qos_profile);
      qcu.set_ul_fteid(flow.ul_fteid);
      qcu.set_dl_fteid(flow.dl_fteid);
      itti_msg->msg.add_qos_flow_context_updated(qcu);
    }
  }

  // Step 2. prepare information for N1N2MessageTransfer to send to AMF
  Logger::smf_app().debug(
      "Prepare N1N2MessageTransfer message and send to AMF");

  //N1: PDU_SESSION_MODIFICATION_COMMAND
  smf_n1_n2_inst.create_n1_sm_container(itti_msg->msg,
  PDU_SESSION_MODIFICATION_COMMAND,
                                        n1_sm_msg,
                                        cause_value_5gsm_e::CAUSE_0_UNKNOWN);
  smf_app_inst->convert_string_2_hex(n1_sm_msg, n1_sm_msg_hex);
  itti_msg->msg.set_n1_sm_message(n1_sm_msg_hex);

  //N2: PDU Session Resource Modify Response Transfer
  smf_n1_n2_inst.create_n2_sm_information(itti_msg->msg, 1,
                                          n2_sm_info_type_e::PDU_RES_MOD_REQ,
                                          n2_sm_info);
  smf_app_inst->convert_string_2_hex(n2_sm_info, n2_sm_info_hex);
  itti_msg->msg.set_n2_sm_information(n2_sm_info_hex);

  //Fill N1N2MesasgeTransferRequestData
  //get supi and put into URL
  supi_t supi = itti_msg->msg.get_supi();
  std::string supi_str = itti_msg->msg.get_supi_prefix() + "-"
      + smf_supi_to_string(supi);
  std::string url = std::string(
      inet_ntoa(*((struct in_addr*) &smf_cfg.amf_addr.ipv4_addr))) + ":"
      + std::to_string(smf_cfg.amf_addr.port)
      + fmt::format(NAMF_COMMUNICATION_N1N2_MESSAGE_TRANSFER_URL,
                    supi_str.c_str());
  itti_msg->msg.set_amf_url(url);
  Logger::smf_n11().debug(
      "N1N2MessageTransfer will be sent to AMF with URL: %s", url.c_str());

  //Fill the json part
  //N1SM
  itti_msg->msg.n1n2_message_transfer_data["n1MessageContainer"]["n1MessageClass"] =
  N1N2_MESSAGE_CLASS;
  itti_msg->msg.n1n2_message_transfer_data["n1MessageContainer"]["n1MessageContent"]["contentId"] =
  N1_SM_CONTENT_ID;  //NAS part
  //N2SM
  itti_msg->msg.n1n2_message_transfer_data["n2InfoContainer"]["n2InformationClass"] =
  N1N2_MESSAGE_CLASS;
  itti_msg->msg.n1n2_message_transfer_data["n2InfoContainer"]["smInfo"]["PduSessionId"] =
      itti_msg->msg.get_pdu_session_id();
  //N2InfoContent (section 6.1.6.2.27@3GPP TS 29.518)
  itti_msg->msg.n1n2_message_transfer_data["n2InfoContainer"]["smInfo"]["n2InfoContent"]["ngapIeType"] =
      "PDU_RES_MOD_REQ";  //NGAP message type
  itti_msg->msg.n1n2_message_transfer_data["n2InfoContainer"]["smInfo"]["n2InfoContent"]["ngapData"]["contentId"] =
  N2_SM_CONTENT_ID;  //NGAP part
  itti_msg->msg.n1n2_message_transfer_data["n2InfoContainer"]["smInfo"]["sNssai"]["sst"] =
      itti_msg->msg.get_snssai().sST;
  itti_msg->msg.n1n2_message_transfer_data["n2InfoContainer"]["smInfo"]["sNssai"]["sd"] =
      itti_msg->msg.get_snssai().sD;
  itti_msg->msg.n1n2_message_transfer_data["n2InfoContainer"]["ranInfo"] = "SM";

  itti_msg->msg.n1n2_message_transfer_data["pduSessionId"] = itti_msg->msg
      .get_pdu_session_id();

  //Step 3. Send ITTI message to N11 interface to trigger N1N2MessageTransfer towards AMFs
  Logger::smf_app().info("Sending ITTI message %s to task TASK_SMF_N11",
                         itti_msg->get_msg_name());

  int ret = itti_inst->send_msg(itti_msg);
  if (RETURNok != ret) {
    Logger::smf_app().error(
        "Could not send ITTI message %s to task TASK_SMF_N11",
        itti_msg->get_msg_name());
  }

}

//------------------------------------------------------------------------------
void smf_context::insert_dnn_subscription(
    const snssai_t &snssai,
    std::shared_ptr<session_management_subscription> &ss) {
  //std::unique_lock<std::recursive_mutex> lock(m_context);
  //dnn_subscriptions.insert (std::make_pair <const uint8_t, std::shared_ptr<session_management_subscription> >((uint8_t)snssai.sST, ss));
  dnn_subscriptions[(uint8_t) snssai.sST] = ss;
  Logger::smf_app().info("Inserted DNN Subscription, key: %d",
                         (uint8_t) snssai.sST);
}

//------------------------------------------------------------------------------
bool smf_context::find_dnn_subscription(
    const snssai_t &snssai,
    std::shared_ptr<session_management_subscription> &ss) {
  Logger::smf_app().info("Find a DNN Subscription with key: %d, map size %d",
                         (uint8_t) snssai.sST, dnn_subscriptions.size());
  //std::unique_lock<std::recursive_mutex> lock(m_context);
  if (dnn_subscriptions.count((uint8_t) snssai.sST) > 0) {
    ss = dnn_subscriptions.at((uint8_t) snssai.sST);
    return true;
  }

  Logger::smf_app().info("DNN subscription (SNSSAI %d) not found",
                         (uint8_t) snssai.sST);
  return false;
}

//------------------------------------------------------------------------------
bool smf_context::find_dnn_context(const snssai_t &nssai,
                                   const std::string &dnn,
                                   std::shared_ptr<dnn_context> &dnn_context) {
  std::unique_lock<std::recursive_mutex> lock(m_context);
  for (auto it : dnns) {
    if ((0 == dnn.compare(it->dnn_in_use))
        and ((uint8_t) nssai.sST) == (uint8_t) (it->nssai.sST)) {
      dnn_context = it;
      return true;
    }
  }
  return false;
}

//------------------------------------------------------------------------------
void smf_context::insert_dnn(std::shared_ptr<dnn_context> &sd) {
  std::unique_lock<std::recursive_mutex> lock(m_context);
  dnns.push_back(sd);
}

//------------------------------------------------------------------------------
bool smf_context::verify_sm_context_request(
    std::shared_ptr<itti_n11_create_sm_context_request> smreq) {
  //check the validity of the UE request according to the user subscription or local policies
  //TODO: need to be implemented
  return true;
}

//-----------------------------------------------------------------------------
supi_t smf_context::get_supi() const {
  return supi;
}

//-----------------------------------------------------------------------------
void smf_context::set_supi(const supi_t &s) {
  supi = s;
}

//-----------------------------------------------------------------------------
std::size_t smf_context::get_number_dnn_contexts() {
  return dnns.size();
}

//-----------------------------------------------------------------------------
void smf_context::set_scid(const scid_t &id) {
  scid = id;
}

//-----------------------------------------------------------------------------
scid_t smf_context::get_scid() const {
  return scid;
}

//------------------------------------------------------------------------------
bool dnn_context::find_pdu_session(
    const uint32_t pdu_session_id,
    std::shared_ptr<smf_pdu_session> &pdu_session) {
  pdu_session = { };

  std::unique_lock<std::recursive_mutex> lock(m_context);
  for (auto it : pdu_sessions) {
    if (pdu_session_id == it->pdu_session_id) {
      pdu_session = it;
      return true;
    }
  }
  return false;
}

//------------------------------------------------------------------------------
void dnn_context::insert_pdu_session(std::shared_ptr<smf_pdu_session> &sp) {
  std::unique_lock<std::recursive_mutex> lock(m_context);
  pdu_sessions.push_back(sp);
}

size_t dnn_context::get_number_pdu_sessions() {
  return pdu_sessions.size();
}

//------------------------------------------------------------------------------
std::string dnn_context::toString() const {
  std::string s = { };
  s.append("DNN CONTEXT:\n");
  s.append("\tIn use:\t\t\t\t").append(std::to_string(in_use)).append("\n");
  s.append("\tDNN:\t\t\t\t").append(dnn_in_use).append("\n");
  //s.append("\tAPN AMBR Bitrate Uplink:\t").append(std::to_string(apn_ambr.br_ul)).append("\n");
  //s.append("\tAPN AMBR Bitrate Downlink:\t").append(std::to_string(apn_ambr.br_dl)).append("\n");
  for (auto it : pdu_sessions) {
    s.append(it->toString());
  }
  return s;
}

