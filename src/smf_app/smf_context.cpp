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
void smf_qos_flow::release_qos_flow() {
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
  s.append("\tPRECEDENCE:\t\t\t").append(std::to_string(precedence.precedence))
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
void smf_pdu_session::add_qos_flow(smf_qos_flow &flow) {
  if ((flow.qfi.qfi >= QOS_FLOW_IDENTIFIER_FIRST )
      and (flow.qfi.qfi <= QOS_FLOW_IDENTIFIER_LAST )) {
    qos_flows.erase(flow.qfi.qfi);
    qos_flows.insert(
        std::pair<uint8_t, smf_qos_flow>((uint8_t) flow.qfi.qfi, flow));
    Logger::smf_app().trace("smf_pdu_session::add_qos_flow(%d) success",
                            flow.qfi.qfi);
  } else {
    Logger::smf_app().error(
        "smf_pdu_session::add_qos_flow(%d) failed, invalid QFI", flow.qfi.qfi);
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
smf_qos_flow& smf_pdu_session::get_qos_flow(const pfcp::qfi_t &qfi) {
  return qos_flows[qfi.qfi];
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
bool smf_pdu_session::has_qos_flow(const pfcp::pdr_id_t &pdr_id,
                                   pfcp::qfi_t &qfi) {
  for (std::map<uint8_t, smf_qos_flow>::iterator it = qos_flows.begin();
      it != qos_flows.end(); ++it) {
    if ((it->second.pdr_id_ul == pdr_id) || (it->second.pdr_id_dl == pdr_id)) {
      qfi = it->second.qfi;
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
  s.append("\tDefault EBI:\t\t\t").append(std::to_string(default_bearer.ebi))
      .append("\n");
  s.append("\tSEID:\t\t\t").append(std::to_string(seid)).append("\n");

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
void session_management_subscription::insert_dnn_configuration(
    std::string dnn, std::shared_ptr<dnn_configuration_t> &dnn_configuration) {
  dnn_configurations.insert(
      std::pair<std::string, std::shared_ptr<dnn_configuration_t>>(
          dnn, dnn_configuration));
}

//------------------------------------------------------------------------------
void session_management_subscription::find_dnn_configuration(
    std::string dnn, std::shared_ptr<dnn_configuration_t> &dnn_configuration) {
  Logger::smf_app().info("find_dnn_configuration with dnn %s", dnn.c_str());
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
  std::cout << toString() << std::endl;
}

//------------------------------------------------------------------------------
void smf_context::handle_itti_msg(
    std::shared_ptr<itti_n4_session_report_request> &req) {
}

//------------------------------------------------------------------------------
std::string smf_context::toString() const {
  std::unique_lock<std::recursive_mutex> lock(m_context);
  std::string s = { };
  s.append("SMF CONTEXT:\n");
  s.append("\tIMSI:\t\t\t\t").append(imsi.toString()).append("\n");
  s.append("\tIMSI UNAUTHENTICATED:\t\t").append(
      std::to_string(imsi_unauthenticated_indicator)).append("\n");
  for (auto it : dnns) {
    s.append(it->toString());
  }
  s.append("\tSUPI:\t\t\t\t").append(smf_supi_to_string(supi)).append("\n");

  //s.append("\tIMSI:\t"+toString(p.msisdn));
  //apns.reserve(MAX_APN_PER_UE);
  return s;
}

//------------------------------------------------------------------------------
void smf_context::get_default_qos(const snssai_t &snssai,
                                  const std::string &dnn,
                                  subscribed_default_qos_t &default_qos) {
  Logger::smf_app().info("get_default_qos, key %d", (uint8_t) snssai.sST);
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
  Logger::smf_app().info("Get default QoS rule (PDU session type %d)",
                         pdu_session_type);
  //see section 9.11.4.13 @ 3GPP TS 24.501 and section 5.7.1.4 @ 3GPP TS 23.501
  qos_rule.qosruleidentifer = 0x01;
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
    qos_rule.qosruleprecedence = 1;
  }

  if (pdu_session_type == PDU_SESSION_TYPE_E_UNSTRUCTURED) {
    qos_rule.numberofpacketfilters = 0;
    qos_rule.qosruleprecedence = 1;
  }

  qos_rule.segregation = SEGREGATION_NOT_REQUESTED;
  qos_rule.qosflowidentifer = 60;  //TODO: default value

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
    QOSFlowDescriptionsContents &qos_flow_description,
    uint8_t pdu_session_type) {
  //TODO, update according to PDU Session type
  Logger::smf_app().info(
      "Get default QoS Flow Description (PDU session type %d)",
      pdu_session_type);
  qos_flow_description.qfi = 60;
  qos_flow_description.operationcode = CREATE_NEW_QOS_FLOW_DESCRIPTION;
  qos_flow_description.e = PARAMETERS_LIST_IS_INCLUDED;
  qos_flow_description.numberofparameters = 3;
  qos_flow_description.parameterslist = (ParametersList*) calloc(
      3, sizeof(ParametersList));
  qos_flow_description.parameterslist[0].parameteridentifier =
  PARAMETER_IDENTIFIER_5QI;
  qos_flow_description.parameterslist[0].parametercontents._5qi = 60;  //TODO: ??
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

  Logger::smf_app().debug(
      "Default Qos Flow Description: %x %x %x %x %x %x %x %x %x %x %x %x",
      qos_flow_description.qfi,
      qos_flow_description.operationcode,
      qos_flow_description.e,
      qos_flow_description.numberofparameters,
      qos_flow_description.parameterslist[0].parameteridentifier,
      qos_flow_description.parameterslist[0].parametercontents._5qi,
      qos_flow_description.parameterslist[1].parameteridentifier,
      qos_flow_description.parameterslist[1].parametercontents
          .gfbrormfbr_uplinkordownlink.uint,
      qos_flow_description.parameterslist[1].parametercontents
          .gfbrormfbr_uplinkordownlink.value,
      qos_flow_description.parameterslist[2].parameteridentifier,
      qos_flow_description.parameterslist[2].parametercontents
          .gfbrormfbr_uplinkordownlink.uint,
      qos_flow_description.parameterslist[2].parametercontents
          .gfbrormfbr_uplinkordownlink.value);
}

//------------------------------------------------------------------------------
void smf_context::get_session_ambr(SessionAMBR &session_ambr,
                                   const snssai_t &snssai,
                                   const std::string &dnn) {
  Logger::smf_app().debug("Get AMBR info from the DNN configuration");

  std::shared_ptr<session_management_subscription> ss = { };
  std::shared_ptr<dnn_configuration_t> sdc = { };
  find_dnn_subscription(snssai, ss);
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
  Logger::smf_app().debug("Get AMBR info from the DNN configuration");

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
    Logger::smf_app().debug("Create a new PDN connection!");
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
  switch (sp->pdn_type.pdn_type) {
    case PDN_TYPE_E_IPV4: {
      if (!pco_ids.ci_ipv4_address_allocation_via_dhcpv4) {  //use SM NAS signalling
        //use NAS signalling
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

    Logger::smf_app().info("Create a procedure to process this message!");
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
      //sm_context_resp->res.set_cause(UNKNOWN_ERROR);
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

    /*
     for (auto it : sm_context_resp->res.bearer_contexts_to_be_created) {
     gtpv2c::bearer_context_created_within_create_session_response bcc = {};
     cause_t bcc_cause = {.cause_value = NO_RESOURCES_AVAILABLE, .pce = 0, .bce = 0, .cs = 0};
     bcc.set(it.eps_bearer_id);
     bcc.set(bcc_cause);
     //sm_context_resp->res.add_bearer_context_created(bcc);
     }
     */

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
      "Handle a PDU Session Update SM Context Request message from AMF");
  pdu_session_update_sm_context_request sm_context_req_msg = smreq->req;
  smf_n1_n2 smf_n1_n2_inst = { };
  oai::smf_server::model::SmContextUpdateError smContextUpdateError = { };
  oai::smf_server::model::ProblemDetails problem_details = { };
  oai::smf_server::model::RefToBinaryData refToBinaryData = { };
  std::string n1_sm_msg, n1_sm_msg_hex;
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
  itti_n11_update_sm_context_response *n1_sm_context_resp =
      new itti_n11_update_sm_context_response(TASK_SMF_APP, TASK_SMF_N11,
                                              smreq->http_response);
  std::shared_ptr<itti_n11_update_sm_context_response> sm_context_resp_pending =
      std::shared_ptr<itti_n11_update_sm_context_response>(n1_sm_context_resp);

  n1_sm_context_resp->res.set_supi(sm_context_req_msg.get_supi());
  n1_sm_context_resp->res.set_supi_prefix(sm_context_req_msg.get_supi_prefix());
  n1_sm_context_resp->res.set_cause(REQUEST_ACCEPTED);
  n1_sm_context_resp->res.set_pdu_session_id(
      sm_context_req_msg.get_pdu_session_id());
  n1_sm_context_resp->res.set_snssai(sm_context_req_msg.get_snssai());
  n1_sm_context_resp->res.set_dnn(sm_context_req_msg.get_dnn());

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
      //PDU_SESSION_MODIFICATION_REQUEST - UE initiated PDU session modification request (Step 1)
      case PDU_SESSION_MODIFICATION_REQUEST: {
        //TODO: to be finished
        Logger::smf_app().debug("PDU_SESSION_MODIFICATION_REQUEST");
        //PDU Session Modification procedure (UE-initiated, step 1.a, Section 4.3.3.2@3GPP TS 23.502)
        procedure_type =
            session_management_procedures_type_e::PDU_SESSION_MODIFICATION_UE_INITIATED_STEP1;
        sm_context_resp_pending->session_procedure_type =
            session_management_procedures_type_e::PDU_SESSION_MODIFICATION_UE_INITIATED_STEP1;

        //step 1. assign the necessary information from pdu_session_modification_request to sm_context_req_msg to be used to create N1 SM, N2 SM information
        //decoded_nas_msg.plain.sm.pdu_session_modification_request;
        //needs the following IEs
        // PTI,
        /* ExtendedProtocolDiscriminator extendedprotocoldiscriminator;
         PDUSessionIdentity pdusessionidentity;
         ProcedureTransactionIdentity proceduretransactionidentity;
         MessageType messagetype;

         uint16_t presence;
         _5GSMCapability _5gsmcapability;
         _5GSMCause _5gsmcause;
         MaximumNumberOfSupportedPacketFilters maximumnumberofsupportedpacketfilters;
         AlwaysonPDUSessionRequested alwaysonpdusessionrequested;
         IntergrityProtectionMaximumDataRate intergrityprotectionmaximumdatarate;
         QOSRules qosrules;
         QOSFlowDescriptions qosflowdescriptions;
         MappedEPSBearerContexts mappedepsbearercontexts;
         ExtendedProtocolConfigurationOptions extendedprotocolconfigurationoptions;
         */

        //See section 6.4.2 - UE-requested PDU Session modification procedure@ 3GPP TS 24.501
        //PDU Session Identity
        //check if the PDU Session Release Command is already sent for this message (see section 6.3.3.5 @3GPP TS 24.501)
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
        n1_sm_context_resp->res.set_pti(pti);

        //TODO: _5GSMCapability _5gsmcapability = decoded_nas_msg.plain.sm.pdu_session_modification_request._5gsmcapability;
        //
        //TODO: Cause
        //TODO: uint8_t maximum_number_of_supported_packet_filters = decoded_nas_msg.plain.sm.pdu_session_modification_request.maximumnumberofsupportedpacketfilters;
        //sp.get()->set_number_of_supported_packet_filters(maximum_number_of_supported_packet_filters);

        //TODO: AlwaysonPDUSessionRequested
        //TODO: IntergrityProtectionMaximumDataRate intergrityprotectionmaximumdatarate;

        //TODO: process QoS rules and Qos Flow descriptions
        uint8_t number_of_rules = decoded_nas_msg.plain.sm
            .pdu_session_modification_request.qosrules.lengthofqosrulesie;
        QOSRulesIE *qos_rules_ie = (QOSRulesIE*) calloc(1, sizeof(QOSRulesIE));
        qos_rules_ie = decoded_nas_msg.plain.sm.pdu_session_modification_request
            .qosrules.qosrulesie;
        for (int i = 0; i < number_of_rules; i++) {
          //qos_rules_ie[0].qosruleidentifer
          if ((qos_rules_ie[i].ruleoperationcode == CREATE_NEW_QOS_RULE)
              and (qos_rules_ie[i].segregation == SEGREGATION_REQUESTED)) {
            //Request to bind specific SDF to a dedicated QoS flow
            if (qos_rules_ie[i].qosruleidentifer == 0) {
              //new QoS rule
            } else {
              //existing QoS rule
            }
          }
          //qos_rules_ie[0].ruleoperationcode
          //qos_rules_ie[0].dqrbit
          //qos_rules_ie[0].numberofpacketfilters
          //1st rule
          // qos_rules_ie[0].packetfilterlist.create_modifyandadd_modifyandreplace->packetfilterdirection
          // qos_rules_ie[0].packetfilterlist.create_modifyandadd_modifyandreplace->packetfilteridentifier
          // qos_rules_ie[0].packetfilterlist.create_modifyandadd_modifyandreplace->packetfiltercontents.component_type
          // qos_rules_ie[0].qosruleprecedence ;
          // qos_rules_ie[0].segregation ;
          // qos_rules_ie[0].qosflowidentifer ;
        }
        free_wrapper((void**) &qos_rules_ie);

        //verify the PDU session ID
        if (smreq->req.get_pdu_session_id()
            != decoded_nas_msg.plain.sm.pdu_session_modification_request
                .pdusessionidentity) {
          //TODO: error
        }

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
            n1_sm_context_resp->res, PDU_SESSION_MODIFICATION_COMMAND,
            n1_sm_msg_to_be_created, cause_value_5gsm_e::CAUSE_0_UNKNOWN);  //TODO: need cause?
        //N2 SM (PDU Session Resource Modify Request Transfer IE)
        smf_n1_n2_inst.create_n2_sm_information(
            n1_sm_context_resp->res, 1, n2_sm_info_type_e::PDU_RES_MOD_REQ,
            n2_sm_info_to_be_created);
        smf_app_inst->convert_string_2_hex(n1_sm_msg_to_be_created,
                                           n1_sm_msg_hex_to_be_created);
        smf_app_inst->convert_string_2_hex(n2_sm_info_to_be_created,
                                           n2_sm_info_hex_to_be_created);

        n1_sm_context_resp->res.set_n1_sm_message(n1_sm_msg_hex_to_be_created);
        n1_sm_context_resp->res.set_n1_sm_msg_type(
            "PDU_SESSION_MODIFICATION_COMMAND");
        n1_sm_context_resp->res.set_n2_sm_information(
            n2_sm_info_hex_to_be_created);
        n1_sm_context_resp->res.set_n2_sm_info_type("PDU_RES_MOD_REQ");

        //Fill the json part
        //N1SM
        n1_sm_context_resp->res.sm_context_updated_data["n1SmMsg"]["n1MessageClass"] =
        N1N2_MESSAGE_CLASS;
        n1_sm_context_resp->res.sm_context_updated_data["n1SmMsg"]["n1MessageContent"]["contentId"] =
        N1_SM_CONTENT_ID;  //part 2
        n1_sm_context_resp->res.sm_context_updated_data["n2SmInfo"]["n2InformationClass"] =
        N1N2_MESSAGE_CLASS;
        n1_sm_context_resp->res.sm_context_updated_data["n2SmInfo"]["n2InfoContent"]["ngapIeType"] =
            "PDU_RES_MOD_REQ";  //NGAP message
        n1_sm_context_resp->res.sm_context_updated_data["n2SmInfo"]["n2InfoContent"]["ngapData"]["contentId"] =
        N2_SM_CONTENT_ID;  //part 3

        //Store pdu_session_modification_request in itti_n11_update_sm_context_response
        Logger::smf_app().info("Sending ITTI message %s to task TASK_SMF_N11",
                               sm_context_resp_pending->get_msg_name());

        //Update PDU Session status
        sp.get()->set_pdu_session_status(
            pdu_session_status_e::PDU_SESSION_MODIFICATION_PENDING);
        //start timer T3591
        //get smf_pdu_session and set the corresponding timer
        sp.get()->timer_T3591 = itti_inst->timer_setup(
            T3591_TIMER_VALUE_SEC, 0, TASK_SMF_APP, TASK_SMF_APP_TRIGGER_T3591,
            sm_context_req_msg.get_pdu_session_id());

        int ret = itti_inst->send_msg(sm_context_resp_pending);
        if (RETURNok != ret) {
          Logger::smf_app().error(
              "Could not send ITTI message %s to task TASK_SMF_N11",
              sm_context_resp_pending->get_msg_name());
        }
        //don't need to create a procedure to update UPF
      }
        break;

        //PDU_SESSION_MODIFICATION_COMPLETE - PDU Session Modification procedure (UE-initiated/Network-requested) (step 3)
        //PDU Session Modification Command Complete
      case PDU_SESSION_MODIFICATION_COMPLETE: {
        //PDU Session Modification procedure (Section 4.3.3.2@3GPP TS 23.502)
        //TODO: should be verified since mentioned PDU_SESSION_MODIFICATION_COMMAND ACK in spec (see Step 11, section 4.3.3.2@3GPP TS 23.502)
        Logger::smf_app().debug("PDU_SESSION_MODIFICATION_COMPLETE");
        procedure_type =
            session_management_procedures_type_e::PDU_SESSION_MODIFICATION_UE_INITIATED_STEP3;

        //send response

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
        n1_sm_context_resp->res.set_pti(pti);

        //Message Type
        //Presence
        //5GSM Cause
        //Extended Protocol Configuration Options

        //Release the resources related to this PDU Session (in Procedure)

        //find DNN context
        std::shared_ptr<dnn_context> sd = { };
        if ((!find_dnn_context(sm_context_req_msg.get_snssai(),
                               sm_context_req_msg.get_dnn(), sd))
            or (nullptr == sd.get())) {
          Logger::smf_app().warn(
              "Could not find the context for this PDU session");
          //create PDU Session Release Reject and send to UE
          problem_details.setCause(
              pdu_session_application_error_e2str[PDU_SESSION_APPLICATION_ERROR_CONTEXT_NOT_FOUND]);
          smContextUpdateError.setError(problem_details);
          refToBinaryData.setContentId(N1_SM_CONTENT_ID);
          smContextUpdateError.setN1SmMsg(refToBinaryData);
          smf_n1_n2_inst.create_n1_sm_container(
              sm_context_req_msg, PDU_SESSION_RELEASE_REJECT, n1_sm_msg,
              cause_value_5gsm_e::CAUSE_111_PROTOCOL_ERROR_UNSPECIFIED);
          smf_app_inst->convert_string_2_hex(n1_sm_msg, n1_sm_msg_hex);
          smf_n11_inst->send_pdu_session_update_sm_context_response(
              smreq->http_response, smContextUpdateError,
              Pistache::Http::Code::Not_Found, n1_sm_msg_hex);
          return;
        }

        //find PDU Session
        std::shared_ptr<smf_pdu_session> ss;
        if ((!sd.get()->find_pdu_session(
            sm_context_req_msg.get_pdu_session_id(), ss))
            or (nullptr == ss.get())) {
          Logger::smf_app().warn(
              "Could not find the context for this PDU session");
          //create PDU Session Release Reject and send to UE
          problem_details.setCause(
              pdu_session_application_error_e2str[PDU_SESSION_APPLICATION_ERROR_CONTEXT_NOT_FOUND]);
          smContextUpdateError.setError(problem_details);
          refToBinaryData.setContentId(N1_SM_CONTENT_ID);
          smContextUpdateError.setN1SmMsg(refToBinaryData);
          smf_n1_n2_inst.create_n1_sm_container(
              sm_context_req_msg, PDU_SESSION_RELEASE_REJECT, n1_sm_msg,
              cause_value_5gsm_e::CAUSE_43_INVALID_PDU_SESSION_IDENTITY);
          smf_app_inst->convert_string_2_hex(n1_sm_msg, n1_sm_msg_hex);
          smf_n11_inst->send_pdu_session_update_sm_context_response(
              smreq->http_response, smContextUpdateError,
              Pistache::Http::Code::Not_Found, n1_sm_msg_hex);
          return;
        }

        //get the associated QoS flows: to be used for PFCP Session Modification procedure
        std::vector<smf_qos_flow> qos_flows;
        ss.get()->get_qos_flows(qos_flows);
        for (auto i : qos_flows) {
          sm_context_req_msg.add_qfi(i.qfi.qfi);
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

        //send response to AMF
        oai::smf_server::model::SmContextCreatedData smContextCreatedData;  //Verify, do we need this?
        smf_n11_inst->send_pdu_session_create_sm_context_response(
            smreq->http_response, smContextCreatedData,
            Pistache::Http::Code::Ok);

        //TODO: SMF invokes Nsmf_PDUSession_SMContextStatusNotify to notify AMF that the SM context for this PDU Session is released
        //TODO: if dynamic PCC applied, SMF invokes an SM Policy Association Termination
        //TODO: SMF unsubscribes from Session Management Subscription data changes notification from UDM by invoking Numd_SDM_Unsubscribe
        //find dnn context
        std::shared_ptr<dnn_context> sd = { };
        bool find_dnn = find_dnn_context(sm_context_req_msg.get_snssai(),
                                         sm_context_req_msg.get_dnn(), sd);
        //At this step, this context should be existed
        if (nullptr == sd.get()) {
          Logger::smf_app().debug(
              "DNN context (dnn_in_use %s) is not existed yet!",
              sm_context_req_msg.get_dnn().c_str());
          //TODO:
        }
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

        Logger::smf_app().info("PDU_RES_SETUP_RSP");
        Logger::smf_app().info(
            "PDU Session Establishment Request, processing N2 SM Information");

        procedure_type =
            session_management_procedures_type_e::PDU_SESSION_ESTABLISHMENT_UE_REQUESTED;

        if (sm_context_req_msg.rat_type_is_set()
            and sm_context_req_msg.an_type_is_set()) {
          procedure_type =
              session_management_procedures_type_e::SERVICE_REQUEST_UE_TRIGGERED_STEP2;
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
          //TODO: need to verify with/without N1 SM
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
        printf("gTP_TEID:");
        printf(
            "%02x ",
            decoded_msg->dLQosFlowPerTNLInformation.uPTransportLayerInformation
                .choice.gTPTunnel->gTP_TEID.buf[0]);
        printf(
            "%02x ",
            decoded_msg->dLQosFlowPerTNLInformation.uPTransportLayerInformation
                .choice.gTPTunnel->gTP_TEID.buf[1]);
        printf(
            "%02x ",
            decoded_msg->dLQosFlowPerTNLInformation.uPTransportLayerInformation
                .choice.gTPTunnel->gTP_TEID.buf[2]);
        printf(
            "%02x \n",
            decoded_msg->dLQosFlowPerTNLInformation.uPTransportLayerInformation
                .choice.gTPTunnel->gTP_TEID.buf[3]);
        Logger::smf_app().debug("gTP_TEID " "0x%" PRIx32 " ",
                                htonl(dl_teid.teid_gre_key));
        Logger::smf_app().debug("uPTransportLayerInformation IP Addr %s",
                                conv::toString(dl_teid.ipv4_address).c_str());

        sm_context_req_msg.set_dl_fteid(dl_teid);

        for (int i = 0;
            i
                < decoded_msg->dLQosFlowPerTNLInformation.associatedQosFlowList
                    .list.count; i++) {
          pfcp::qfi_t qfi(
              (uint8_t) (decoded_msg->dLQosFlowPerTNLInformation
                  .associatedQosFlowList.list.array[i])->qosFlowIdentifier);
          sm_context_req_msg.add_qfi(qfi);
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
            "PDU Session Modification, processing N2 SM Information");

        procedure_type =
            session_management_procedures_type_e::PDU_SESSION_MODIFICATION_UE_INITIATED_STEP2;

        //Ngap_PDUSessionResourceModifyResponseTransfer
        std::shared_ptr<Ngap_PDUSessionResourceModifyResponseTransfer_t> decoded_msg =
            std::make_shared<Ngap_PDUSessionResourceModifyResponseTransfer_t>();
        int decode_status = smf_n1_n2_inst.decode_n2_sm_information(
            decoded_msg, n2_sm_information);
        if (decode_status == RETURNerror) {
          Logger::smf_api_server().warn("asn_decode failed");
          //send error to AMF
          Logger::smf_app().warn(
              "Decode N2 SM (Ngap_PDUSessionResourceModifyResponseTransfer) failed!");
          problem_details.setCause(
              pdu_session_application_error_e2str[PDU_SESSION_APPLICATION_ERROR_N2_SM_ERROR]);
          smContextUpdateError.setError(problem_details);
          //TODO: need to verify with/without N1 SM
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
              Pistache::Http::Code::Forbidden, n1_sm_msg_hex);
          return;

        }

        //if dL_NGU_UP_TNLInformation is included, it shall be considered as the new DL transfort layer addr for the PDU session (should be verified)
        fteid_t dl_teid;
        memcpy(
            &dl_teid.ipv4_address,
            decoded_msg->dL_NGU_UP_TNLInformation->choice.gTPTunnel->gTP_TEID
                .buf,
            sizeof(struct in_addr));
        memcpy(
            &dl_teid.teid_gre_key,
            decoded_msg->dL_NGU_UP_TNLInformation->choice.gTPTunnel
                ->transportLayerAddress.buf,
            4);
        sm_context_req_msg.set_dl_fteid(dl_teid);
        //list of Qos Flows which have been successfully setup or modified
        for (int i = 0;
            i < decoded_msg->qosFlowAddOrModifyResponseList->list.count; i++) {
          sm_context_req_msg.add_qfi(
              (decoded_msg->qosFlowAddOrModifyResponseList->list.array[i])
                  ->qosFlowIdentifier);
        }
        //TODO:
        //list of QoS Flows which have failed to be modified
        //qosFlowFailedToAddOrModifyList

        //need to update UPF accordingly
        update_upf = true;
      }
        break;

        //PDU Session Modification procedure
      case n2_sm_info_type_e::PDU_RES_MOD_FAIL: {
        Logger::smf_app().info("PDU_RES_MOD_FAIL");
        //TODO:
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
          Logger::smf_api_server().warn("asn_decode failed");
          //send error to AMF
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

        //SMF send response to AMF
        oai::smf_server::model::SmContextCreatedData smContextCreatedData;  //Verify, do we need this?
        smf_n11_inst->send_pdu_session_create_sm_context_response(
            smreq->http_response, smContextCreatedData,
            Pistache::Http::Code::Ok);
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
    Logger::smf_app().info("SERVICE_REQUEST_UE_TRIGGERED_STEP1");
    Logger::smf_app().info("Service Request (UE-triggered)");

    procedure_type =
        session_management_procedures_type_e::SERVICE_REQUEST_UE_TRIGGERED_STEP1;
    //if request accepted-> set unCnxState to ACTIVATING
    //Update upCnxState
    sp.get()->set_upCnx_state(upCnx_state_e::UPCNX_STATE_ACTIVATING);

    //get QFIs associated with PDU session ID
    std::vector<smf_qos_flow> qos_flows = { };
    sp.get()->get_qos_flows(qos_flows);
    for (auto i : qos_flows) {
      sm_context_req_msg.add_qfi(i.qfi.qfi);
    }
    //need update UPF
    update_upf = true;

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
      sm_context_req_msg.add_qfi(i.qfi.qfi);
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

    smreq->req = sm_context_req_msg;
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
  }

  //TODO, Step 6
  /*  If the PDU Session establishment is not successful, the SMF informs the AMF by invoking Nsmf_PDUSession_SMContextStatusNotify (Release). The SMF also releases any N4
   session(s) created, any PDU Session address if allocated (e.g. IP address) and releases the association with PCF,
   if any. In this case, step 19 is skipped.
   see step 18, section 4.3.2.2.1@3GPP TS 23.502)
   */

}

//------------------------------------------------------------------------------
void smf_context::insert_dnn_subscription(
    const snssai_t &snssai,
    std::shared_ptr<session_management_subscription> &ss) {
  Logger::smf_app().info("Insert dnn subscription, key: %d",
                         (uint8_t) snssai.sST);
  //std::unique_lock<std::recursive_mutex> lock(m_context);
  //dnn_subscriptions.insert (std::make_pair <const uint8_t, std::shared_ptr<session_management_subscription> >((uint8_t)snssai.sST, ss));
  dnn_subscriptions[(uint8_t) snssai.sST] = ss;

}

//------------------------------------------------------------------------------
bool smf_context::find_dnn_subscription(
    const snssai_t &snssai,
    std::shared_ptr<session_management_subscription> &ss) {
  Logger::smf_app().info("find_dnn_subscription: %d, map size %d",
                         (uint8_t) snssai.sST, dnn_subscriptions.size());
  //std::unique_lock<std::recursive_mutex> lock(m_context);
  if (dnn_subscriptions.count((uint8_t) snssai.sST) > 0) {
    ss = dnn_subscriptions.at((uint8_t) snssai.sST);
    return true;
  }

  Logger::smf_app().info(
      "find_dnn_subscription: cannot find DNN subscription for SNSSAI %d",
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
bool dnn_context::find_pdu_session(const uint32_t pdu_session_id,
                                   std::shared_ptr<smf_pdu_session> &pdn) {
  pdn = { };

  std::unique_lock<std::recursive_mutex> lock(m_context);
  for (auto it : pdu_sessions) {
    if (pdu_session_id == it->pdu_session_id) {
      pdn = it;
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

