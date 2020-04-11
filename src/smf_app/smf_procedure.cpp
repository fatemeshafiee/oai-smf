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

/*! \file smf_procedure.cpp
 \author  Lionel GAUTHIER, Tien-Thinh NGUYEN
 \company Eurecom
 \date 2019
 \email: lionel.gauthier@eurecom.fr, tien-thinh.nguyen@eurecom.fr
 */

#include "smf_procedure.hpp"

#include <algorithm>    // std::search

#include "3gpp_29.244.h"
#include "3gpp_29.274.h"
#include "common_defs.h"
#include "3gpp_conversions.hpp"
#include "conversions.hpp"
#include "itti.hpp"
#include "itti_msg_n4_restore.hpp"
#include "logger.hpp"
#include "msg_gtpv2c.hpp"
#include "smf_app.hpp"
#include "smf_config.hpp"
#include "smf_pfcp_association.hpp"
#include "smf_context.hpp"
#include "smf_n1_n2.hpp"
#include "SmContextCreatedData.h"

using namespace pfcp;
using namespace smf;
using namespace std;

extern itti_mw *itti_inst;
extern smf::smf_app *smf_app_inst;
extern smf::smf_config smf_cfg;

//------------------------------------------------------------------------------
int n4_session_restore_procedure::run() {
  if (pending_sessions.size()) {
    itti_n4_restore *itti_msg = nullptr;
    for (std::set<pfcp::fseid_t>::iterator it = pending_sessions.begin(); it != pending_sessions.end(); ++it) {
      if (!itti_msg) {
        itti_msg = new itti_n4_restore(TASK_SMF_N4, TASK_SMF_APP);
      }
      itti_msg->sessions.insert(*it);
      if (itti_msg->sessions.size() >= 64) {
        std::shared_ptr<itti_n4_restore> i = std::shared_ptr<itti_n4_restore>(itti_msg);
        int ret = itti_inst->send_msg(i);
        if (RETURNok != ret) {
          Logger::smf_n4().error("Could not send ITTI message %s to task TASK_SMF_APP", i->get_msg_name());
        }
        itti_msg = nullptr;
      }
    }
    if (itti_msg) {
      std::shared_ptr<itti_n4_restore> i = std::shared_ptr<itti_n4_restore>(itti_msg);
      int ret = itti_inst->send_msg(i);
      if (RETURNok != ret) {
        Logger::smf_n4().error("Could not send ITTI message %s to task TASK_SMF_APP", i->get_msg_name());
        return RETURNerror ;
      }
    }
  }
  return RETURNok ;
}

//------------------------------------------------------------------------------
int session_create_sm_context_procedure::run(std::shared_ptr<itti_n11_create_sm_context_request> sm_context_req, std::shared_ptr<itti_n11_create_sm_context_response> sm_context_resp,
                                             std::shared_ptr<smf::smf_context> pc) {

  Logger::smf_app().info("[SMF Procedure] Create SM Context Request");
  // TODO check if compatible with ongoing procedures if any
  pfcp::node_id_t up_node_id = { };
  if (not pfcp_associations::get_instance().select_up_node(up_node_id, NODE_SELECTION_CRITERIA_MIN_PFCP_SESSIONS)) {
    // TODO
    sm_context_resp->res.set_cause(REMOTE_PEER_NOT_RESPONDING);  //verify for 5G??
    return RETURNerror ;
  }

  //-------------------
  n11_trigger = sm_context_req;
  n11_triggered_pending = sm_context_resp;
  //ppc->generate_seid();
  uint64_t seid = smf_app_inst->generate_seid();
  ppc->set_seid(seid);
  itti_n4_session_establishment_request *n4_ser = new itti_n4_session_establishment_request(TASK_SMF_APP, TASK_SMF_N4);
  n4_ser->seid = 0;
  n4_ser->trxn_id = this->trxn_id;
  n4_ser->r_endpoint = endpoint(up_node_id.u1.ipv4_address, pfcp::default_port);
  n4_triggered = std::shared_ptr<itti_n4_session_establishment_request>(n4_ser);

  //-------------------
  // IE node_id_t
  //-------------------
  pfcp::node_id_t node_id = { };
  smf_cfg.get_pfcp_node_id(node_id);
  n4_ser->pfcp_ies.set(node_id);

  //-------------------
  // IE fseid_t
  //-------------------
  pfcp::fseid_t cp_fseid = { };
  smf_cfg.get_pfcp_fseid(cp_fseid);
  cp_fseid.seid = ppc->seid;
  n4_ser->pfcp_ies.set(cp_fseid);

  //*******************
  // UPLINK
  //*******************
  //-------------------
  // IE create_far (Forwarding Action Rules)
  //-------------------
  pfcp::create_far create_far = { };
  pfcp::far_id_t far_id = { };  //rule ID
  pfcp::apply_action_t apply_action = { };
  pfcp::forwarding_parameters forwarding_parameters = { };

  // forwarding_parameters IEs
  pfcp::destination_interface_t destination_interface = { };

  ppc->generate_far_id(far_id);
  apply_action.forw = 1;

  //wys-test-add
  pfcp::outer_header_creation_t outer_header_creation = { };

  if (smf_cfg.test_upf_cfg.is_test) {
    //wys-test-add
    destination_interface.interface_value = pfcp::INTERFACE_VALUE_ACCESS;  // ACCESS is for downlink, CORE for uplink
    outer_header_creation.teid = 1;
    //inet_aton("192.168.20.136", &outer_header_creation.ipv4_address);
    outer_header_creation.ipv4_address = smf_cfg.test_upf_cfg.gnb_addr4;
    outer_header_creation.outer_header_creation_description = pfcp::OUTER_HEADER_CREATION_GTPU_UDP_IPV4;

    forwarding_parameters.set(outer_header_creation);
    forwarding_parameters.set(destination_interface);
  } else {
    destination_interface.interface_value = pfcp::INTERFACE_VALUE_CORE;  // ACCESS is for downlink, CORE for uplink
    forwarding_parameters.set(destination_interface);
  }

  //destination_interface.interface_value = pfcp::INTERFACE_VALUE_CORE; // ACCESS is for downlink, CORE for uplink
  //forwarding_parameters.set(destination_interface);
  //TODO
  //Network instance

  create_far.set(far_id);
  create_far.set(apply_action);
  create_far.set(forwarding_parameters);  //should check since destination interface is directly set to FAR (as described in Table 5.8.2.11.6-1)

  //-------------------
  // IE create_pdr (section 5.8.2.11.3@TS 23.501)
  //-------------------
  pfcp::create_pdr create_pdr = { };
  pfcp::pdr_id_t pdr_id = { };  //rule ID?
  pfcp::precedence_t precedence = { };
  pfcp::pdi pdi = { };  //packet detection information
  pfcp::outer_header_removal_t outer_header_removal = { };
  // pdi IEs
  pfcp::source_interface_t source_interface = { };
  pfcp::fteid_t local_fteid = { };
  pfcp::ue_ip_address_t ue_ip_address = { };
  pfcp::sdf_filter_t sdf_filter = { };
  pfcp::application_id_t application_id = { };
  pfcp::qfi_t qfi = { };

  source_interface.interface_value = pfcp::INTERFACE_VALUE_ACCESS;
  local_fteid.ch = 1;
  //local_fteid.chid = 1;

  xgpp_conv::paa_to_pfcp_ue_ip_address(sm_context_resp->res.get_paa(), ue_ip_address);

  // DOIT simple
  // shall uniquely identify the PDR among all the PDRs configured for that PFCP session.
  ppc->generate_pdr_id(pdr_id);
  //precedence.precedence = it.bearer_level_qos.pl; //TODO

  //get the default QoS profile
  subscribed_default_qos_t default_qos = { };
  std::shared_ptr<session_management_subscription> ss = { };
  pc.get()->get_default_qos(sm_context_req->req.get_snssai(), sm_context_req->req.get_dnn(), default_qos);
  qfi.qfi = default_qos._5qi;
  Logger::smf_app().info("session_create_sm_context_procedure default qfi %d", qfi.qfi);

  //packet detection information
  pdi.set(source_interface);  //source interface
  pdi.set(local_fteid);  // CN tunnel info
  pdi.set(ue_ip_address);  //UE IP address
  pdi.set(qfi);  //QoS Flow ID
  //TODO:
  //Network Instance (no need in this version)
  //Packet Filter Set
  //Application ID
  //QoS Flow ID
  //Ethernet PDU Session Information
  //Framed Route Information

  outer_header_removal.outer_header_removal_description = OUTER_HEADER_REMOVAL_GTPU_UDP_IPV4;

  create_pdr.set(pdr_id);
  create_pdr.set(precedence);
  create_pdr.set(pdi);

  //wys-add-test
  if (smf_cfg.test_upf_cfg.is_test)
    create_pdr.set(outer_header_removal);
  //create_pdr.set(outer_header_removal);

  create_pdr.set(far_id);
  //TODO: list of Usage reporting Rule IDs
  //TODO: list of QoS Enforcement Rule IDs

  //-------------------
  // ADD IEs to message
  //-------------------
  n4_ser->pfcp_ies.set(create_pdr);
  n4_ser->pfcp_ies.set(create_far);

  //TODO: verify whether N4 SessionID should be included in PDR and FAR (Section 5.8.2.11@3GPP TS 23.501)

  // Have to backup far id and pdr id
  smf_qos_flow q = { };
  q.far_id_ul.first = true;
  q.far_id_ul.second = far_id;
  q.pdr_id_ul = pdr_id;
  q.pdu_session_id = sm_context_req->req.get_pdu_session_id();
  //default QoS profile
  q.qfi = default_qos._5qi;
  q.qos_profile._5qi = default_qos._5qi;
  q.qos_profile.arp = default_qos.arp;
  q.qos_profile.priority_level = default_qos.priority_level;

  //assign default QoS rule for this
  QOSRulesIE qos_rule = { };
  pc.get()->get_default_qos_rule(qos_rule, sm_context_req->req.get_pdu_session_type());
  q.qos_rules.push_back(qos_rule);
  ppc->generate_qos_rule_id(q.qos_rules[0].qosruleidentifer);
  q.qos_rules[0].qosflowidentifer = q.qfi.qfi;

  smf_qos_flow q2 = q;
  ppc->add_qos_flow(q2);

  // for finding procedure when receiving response
  smf_app_inst->set_seid_2_smf_context(cp_fseid.seid, pc);

  Logger::smf_app().info("Sending ITTI message %s to task TASK_SMF_N4", n4_ser->get_msg_name());
  int ret = itti_inst->send_msg(n4_triggered);
  if (RETURNok != ret) {
    Logger::smf_app().error("Could not send ITTI message %s to task TASK_SMF_N4", n4_ser->get_msg_name());
    return RETURNerror ;
  }

  return RETURNok ;
}

//------------------------------------------------------------------------------
void session_create_sm_context_procedure::handle_itti_msg(itti_n4_session_establishment_response &resp, std::shared_ptr<smf::smf_context> sc) {
  Logger::smf_app().info("session_create_sm_context_procedure handle itti_n4_session_establishment_response: pdu-session-id %d", n11_trigger.get()->req.get_pdu_session_id());

  pfcp::cause_t cause = { };
  resp.pfcp_ies.get(cause);
  if (cause.cause_value == pfcp::CAUSE_VALUE_REQUEST_ACCEPTED) {
    resp.pfcp_ies.get(ppc->up_fseid);
    n11_triggered_pending->res.set_cause(REQUEST_ACCEPTED);
  }

  for (auto it : resp.pfcp_ies.created_pdrs) {
    pfcp::pdr_id_t pdr_id = { };
    pfcp::far_id_t far_id = { };
    if (it.get(pdr_id)) {
      smf_qos_flow q = { };
      if (ppc->get_qos_flow(pdr_id, q)) {
        pfcp::fteid_t local_up_fteid = { };
        if (it.get(local_up_fteid)) {
          //b.pgw_fteid_s5_s8_up.interface_type = S5_S8_PGW_GTP_U;
          //set tunnel id
          xgpp_conv::pfcp_to_core_fteid(local_up_fteid, q.ul_fteid);
          //TODO: should be updated to 5G N3/N9 interface
          q.ul_fteid.interface_type = S1_U_SGW_GTP_U;  //UPF's N3 interface
          //Update Qos Flow
          smf_qos_flow q2 = q;
          ppc->add_qos_flow(q2);
        }
      } else {
        Logger::smf_app().error("Could not get QoS Flow for created_pdr %d", pdr_id.rule_id);
      }
    } else {
      Logger::smf_app().error("Could not get pdr_id for created_pdr in %s", resp.pfcp_ies.get_msg_name());
    }
  }

  //get the default QoS profile
  pfcp::qfi_t qfi = { };
  subscribed_default_qos_t default_qos = { };
  sc.get()->get_default_qos(n11_triggered_pending->res.get_snssai(), n11_triggered_pending->res.get_dnn(), default_qos);
  qfi.qfi = default_qos._5qi;

  //TODO:	how about pdu_session_id??
  smf_qos_flow q = { };
  qos_flow_context_updated qos_flow = { };  //default flow, so Non-GBR, TODO: //we can use smf_qos_flow instead!
  qos_flow.set_cause(REQUEST_ACCEPTED);
  if (not ppc->get_qos_flow(qfi, q)) {
    qos_flow.set_cause(SYSTEM_FAILURE);
  } else {
    if (q.ul_fteid.is_zero()) {
      qos_flow.set_cause(SYSTEM_FAILURE);
    } else {
      qos_flow.set_ul_fteid(q.ul_fteid);  //tunnel info
    }
    qos_flow.set_qos_rule(q.qos_rules[0]);  //set default QoS rule
  }
  qos_flow.set_qfi(qfi);
  qos_profile_t profile = { };
  profile.arp = default_qos.arp;
  qos_flow.set_qos_profile(profile);
  //qos_flow.set_arp(default_qos.arp);
  qos_flow.set_priority_level(default_qos.priority_level);
  //TODO: Set RQA (optional)

  n11_triggered_pending->res.set_qos_flow_context(qos_flow);

  //fill content for N1N2MessageTransfer (including N1, N2 SM)

  // Create N1 SM container & N2 SM Information
  smf_n1_n2 smf_n1_n2_inst = { };
  std::string n1_sm_msg, n1_sm_msg_hex;
  std::string n2_sm_info, n2_sm_info_hex;

  //TODO: should uncomment this line when including UPF in the test
  n11_triggered_pending->res.set_cause(REQUEST_ACCEPTED);  //for testing purpose

  if (n11_triggered_pending->res.get_cause() != REQUEST_ACCEPTED) {  //PDU Session Establishment Reject
    Logger::smf_app().debug("PDU Session Establishment Reject");
    smf_n1_n2_inst.create_n1_sm_container(n11_triggered_pending->res, PDU_SESSION_ESTABLISHMENT_REJECT, n1_sm_msg, cause_value_5gsm_e::CAUSE_0_UNKNOWN);  //TODO: need cause?
    smf_app_inst->convert_string_2_hex(n1_sm_msg, n1_sm_msg_hex);
    n11_triggered_pending->res.set_n1_sm_message(n1_sm_msg_hex);
  } else {  //PDU Session Establishment Accept
    Logger::smf_app().debug("Prepare a PDU Session Establishment Accept message and send to UE");
    smf_n1_n2_inst.create_n1_sm_container(n11_triggered_pending->res, PDU_SESSION_ESTABLISHMENT_ACCEPT, n1_sm_msg, cause_value_5gsm_e::CAUSE_0_UNKNOWN);  //TODO: need cause?
    smf_app_inst->convert_string_2_hex(n1_sm_msg, n1_sm_msg_hex);
    n11_triggered_pending->res.set_n1_sm_message(n1_sm_msg_hex);
    //TODO: N2 SM Information (Step 11, section 4.3.2.2.1 @ 3GPP TS 23.502)
    smf_n1_n2_inst.create_n2_sm_information(n11_triggered_pending->res, 1, n2_sm_info_type_e::PDU_RES_SETUP_REQ, n2_sm_info);
    smf_app_inst->convert_string_2_hex(n2_sm_info, n2_sm_info_hex);
    n11_triggered_pending->res.set_n2_sm_information(n2_sm_info_hex);
  }

  //Fill N1N2MesasgeTransferRequestData
  //get supi and put into URL
  supi_t supi = n11_triggered_pending->res.get_supi();
  std::string supi_str = n11_triggered_pending->res.get_supi_prefix() + "-" + smf_supi_to_string(supi);
  //std::string url = std::string(inet_ntoa (*((struct in_addr *)&smf_cfg.amf_addr.ipv4_addr)))  + ":" + std::to_string(smf_cfg.amf_addr.port) + "/namf-comm/v2/ue-contexts/" + supi_str.c_str() +"/n1-n2-messages";
  std::string url = std::string(inet_ntoa(*((struct in_addr*) &smf_cfg.amf_addr.ipv4_addr))) + ":" + std::to_string(smf_cfg.amf_addr.port)
      + fmt::format(NAMF_COMMUNICATION_N1N2_MESSAGE_TRANSFER_URL, supi_str.c_str());
  n11_triggered_pending->res.set_amf_url(url);
  Logger::smf_n11().debug("N1N2MessageTransfer will be sent to AMF with URL: %s", url.c_str());

  //Fill the json part
  //N1SM
  n11_triggered_pending->res.n1n2_message_transfer_data["n1MessageContainer"]["n1MessageClass"] = N1N2_MESSAGE_CLASS;
  n11_triggered_pending->res.n1n2_message_transfer_data["n1MessageContainer"]["n1MessageContent"]["contentId"] = N1_SM_CONTENT_ID;  //part 2

  //N2SM
  if (n11_triggered_pending->res.get_cause() == REQUEST_ACCEPTED) {
    //TODO: fill the content of N1N2MessageTransferReqData
    n11_triggered_pending->res.n1n2_message_transfer_data["n2InfoContainer"]["n2InformationClass"] = N1N2_MESSAGE_CLASS;
    n11_triggered_pending->res.n1n2_message_transfer_data["n2InfoContainer"]["smInfo"]["PduSessionId"] = n11_triggered_pending->res.get_pdu_session_id();
    //N2InfoContent (section 6.1.6.2.27@3GPP TS 29.518)
    //n11_triggered_pending->res.n1n2_message_transfer_data["n2InfoContainer"]["smInfo"]["n2InfoContent"]["ngapMessageType"] = 123; //NGAP message -to be verified: doesn't exist in tester (not required!!)
    n11_triggered_pending->res.n1n2_message_transfer_data["n2InfoContainer"]["smInfo"]["n2InfoContent"]["ngapIeType"] = "PDU_RES_SETUP_REQ";  //NGAP message
    n11_triggered_pending->res.n1n2_message_transfer_data["n2InfoContainer"]["smInfo"]["n2InfoContent"]["ngapData"]["contentId"] = N2_SM_CONTENT_ID;  //part 3
    n11_triggered_pending->res.n1n2_message_transfer_data["n2InfoContainer"]["smInfo"]["sNssai"]["sst"] = n11_triggered_pending->res.get_snssai().sST;
    n11_triggered_pending->res.n1n2_message_transfer_data["n2InfoContainer"]["smInfo"]["sNssai"]["sd"] = n11_triggered_pending->res.get_snssai().sD;
    n11_triggered_pending->res.n1n2_message_transfer_data["n2InfoContainer"]["ranInfo"] = "SM";
  }
  //Others information
  n11_triggered_pending->res.n1n2_message_transfer_data["ppi"] = 1;  //Don't need this info for the moment
  n11_triggered_pending->res.n1n2_message_transfer_data["pduSessionId"] = n11_triggered_pending->res.get_pdu_session_id();
  //n11_triggered_pending->res.n1n2_message_transfer_data["arp"]["priorityLevel"] = 1;
  //n11_triggered_pending->res.n1n2_message_transfer_data["arp"]["preemptCap"] = "NOT_PREEMPT";
  //n11_triggered_pending->res.n1n2_message_transfer_data["arp"]["preemptVuln"] = "NOT_PREEMPTABLE";
  //n11_triggered_pending->res.n1n2_message_transfer_data["5qi"] = ;

  //send ITTI message to N11 interface to trigger N1N2MessageTransfer towards AMFs
  Logger::smf_app().info("Sending ITTI message %s to task TASK_SMF_N11", n11_triggered_pending->get_msg_name());

  int ret = itti_inst->send_msg(n11_triggered_pending);
  if (RETURNok != ret) {
    Logger::smf_app().error("Could not send ITTI message %s to task TASK_SMF_N11", n11_triggered_pending->get_msg_name());
  }

}

//------------------------------------------------------------------------------
int session_update_sm_context_procedure::run(std::shared_ptr<itti_n11_update_sm_context_request> sm_context_req, std::shared_ptr<itti_n11_update_sm_context_response> sm_context_resp,
                                             std::shared_ptr<smf::smf_context> pc) {
  //Handle SM update sm context request
  //first try to reuse from CUPS....
  //The SMF initiates an N4 Session Modification procedure with the UPF. The SMF provides AN Tunnel Info to the UPF as well as the corresponding forwarding rules

  bool send_n4 = false;

  Logger::smf_app().info("[SMF Procedure] Update SM Context Request");
  // TODO check if compatible with ongoing procedures if any
  pfcp::node_id_t up_node_id = { };
  if (not pfcp_associations::get_instance().select_up_node(up_node_id, NODE_SELECTION_CRITERIA_MIN_PFCP_SESSIONS)) {
    // TODO
    sm_context_resp->res.set_cause(REMOTE_PEER_NOT_RESPONDING);  //verify for 5G??
    Logger::smf_app().info("[SMF Procedure] REMOTE_PEER_NOT_RESPONDING");
    return RETURNerror ;
  }

  //-------------------
  n11_trigger = sm_context_req;
  n11_triggered_pending = sm_context_resp;
  uint64_t seid = smf_app_inst->generate_seid();
  ppc->set_seid(seid);
  itti_n4_session_modification_request *n4_ser = new itti_n4_session_modification_request(TASK_SMF_APP, TASK_SMF_N4);
  n4_ser->seid = ppc->up_fseid.seid;
  n4_ser->trxn_id = this->trxn_id;
  n4_ser->r_endpoint = endpoint(up_node_id.u1.ipv4_address, pfcp::default_port);
  n4_triggered = std::shared_ptr<itti_n4_session_modification_request>(n4_ser);

  //TODO: To be completed
  //qos Flow to be modified
  pdu_session_update_sm_context_request sm_context_req_msg = sm_context_req->req;
  std::vector<pfcp::qfi_t> list_of_qfis_to_be_modified = { };
  sm_context_req_msg.get_qfis(list_of_qfis_to_be_modified);

  for (auto i : list_of_qfis_to_be_modified) {
    Logger::smf_app().debug("qfi to be modified: %d", i.qfi);
  }

  ::fteid_t dl_fteid = { };
  sm_context_req_msg.get_dl_fteid(dl_fteid);  //eNB's fteid

  for (auto qfi : list_of_qfis_to_be_modified) {
    smf_qos_flow qos_flow = { };
    if (!ppc->get_qos_flow(qfi, qos_flow)) {  //no QoS flow found
      Logger::smf_app().error("Update SM Context procedure: could not found QoS flow with QFI %d", qfi.qfi);
      //Set cause to SYSTEM_FAILURE and send response
      qos_flow_context_updated qcu = { };
      qcu.set_cause(SYSTEM_FAILURE);
      qcu.set_qfi(qfi);
      n11_triggered_pending->res.add_qos_flow_context_updated(qcu);
      continue;
    }
    pfcp::far_id_t far_id = { };
    pfcp::pdr_id_t pdr_id = { };
    if ((dl_fteid == qos_flow.dl_fteid) and (not qos_flow.released)) {
      Logger::smf_app().debug("Update SM Context procedure: QFI %d dl_fteid unchanged", qfi.qfi);
      qos_flow_context_updated qcu = { };
      qcu.set_cause(REQUEST_ACCEPTED);
      qcu.set_qfi(qfi);
      n11_triggered_pending->res.add_qos_flow_context_updated(qcu);
      continue;
    } else if ((qos_flow.far_id_dl.first) && (qos_flow.far_id_dl.second.far_id)) {
      Logger::smf_app().debug("Update SM Context procedure: Update FAR DL");
      // Update FAR
      far_id.far_id = qos_flow.far_id_dl.second.far_id;
      pfcp::update_far update_far = { };
      pfcp::apply_action_t apply_action = { };
      pfcp::outer_header_creation_t outer_header_creation = { };
      pfcp::update_forwarding_parameters update_forwarding_parameters = { };

      update_far.set(qos_flow.far_id_dl.second);
      outer_header_creation.outer_header_creation_description = OUTER_HEADER_CREATION_GTPU_UDP_IPV4;
      outer_header_creation.teid = dl_fteid.teid_gre_key;
      outer_header_creation.ipv4_address.s_addr = dl_fteid.ipv4_address.s_addr;
      update_forwarding_parameters.set(outer_header_creation);
      update_far.set(update_forwarding_parameters);
      apply_action.forw = 1;
      update_far.set(apply_action);

      n4_ser->pfcp_ies.set(update_far);

      send_n4 = true;
      qos_flow.far_id_dl.first = true;

    } else {
      Logger::smf_app().debug("Update SM Context procedure: Create FAR DL");
      //Create FAR
      pfcp::create_far create_far = { };
      pfcp::apply_action_t apply_action = { };
      pfcp::forwarding_parameters forwarding_parameters = { };
      //pfcp::duplicating_parameters      duplicating_parameters = {};
      //pfcp::bar_id_t                    bar_id = {};

      // forwarding_parameters IEs
      pfcp::destination_interface_t destination_interface = { };
      //pfcp::network_instance_t          network_instance = {};
      //pfcp::redirect_information_t      redirect_information = {};
      pfcp::outer_header_creation_t outer_header_creation = { };
      //pfcp::transport_level_marking_t   transport_level_marking = {};
      //pfcp::forwarding_policy_t         forwarding_policy = {};
      //pfcp::header_enrichment_t         header_enrichment = {};
      //pfcp::traffic_endpoint_id_t       linked_traffic_endpoint_id_t = {};
      //pfcp::proxying_t                  proxying = {};

      ppc->generate_far_id(far_id);
      apply_action.forw = 1;

      destination_interface.interface_value = pfcp::INTERFACE_VALUE_ACCESS;  // ACCESS is for downlink, CORE for uplink
      forwarding_parameters.set(destination_interface);
      outer_header_creation.outer_header_creation_description = OUTER_HEADER_CREATION_GTPU_UDP_IPV4;
      outer_header_creation.teid = dl_fteid.teid_gre_key;
      outer_header_creation.ipv4_address.s_addr = dl_fteid.ipv4_address.s_addr;
      forwarding_parameters.set(outer_header_creation);

      create_far.set(far_id);
      create_far.set(apply_action);
      create_far.set(forwarding_parameters);
      //-------------------
      // ADD IEs to message
      //-------------------
      n4_ser->pfcp_ies.set(create_far);

      send_n4 = true;

      qos_flow.far_id_dl.first = true;
      qos_flow.far_id_dl.second = far_id;
    }

    if (not qos_flow.pdr_id_dl.rule_id) {
      Logger::smf_app().debug("Update SM Context procedure, Create PDR DL");
      //-------------------
      // IE create_pdr
      //-------------------
      pfcp::create_pdr create_pdr = { };
      pfcp::precedence_t precedence = { };
      pfcp::pdi pdi = { };
      //    pfcp::far_id_t                    far_id;
      //    pfcp::urr_id_t                    urr_id;
      //    pfcp::qer_id_t                    qer_id;
      //    pfcp::activate_predefined_rules_t activate_predefined_rules;
      // pdi IEs
      pfcp::source_interface_t source_interface = { };
      //pfcp::fteid_t                    local_fteid = {};
      //pfcp::network_instance_t         network_instance = {};
      pfcp::ue_ip_address_t ue_ip_address = { };
      //pfcp::traffic_endpoint_id_t      traffic_endpoint_id = {};
      pfcp::sdf_filter_t sdf_filter = { };
      pfcp::application_id_t application_id = { };
      //pfcp::ethernet_packet_filter     ethernet_packet_filter = {};
      pfcp::qfi_t qfi = { };
      //pfcp::framed_route_t             framed_route = {};
      //pfcp::framed_routing_t           framed_routing = {};
      //pfcp::framed_ipv6_route_t        framed_ipv6_route = {};
      source_interface.interface_value = pfcp::INTERFACE_VALUE_CORE;

      //local_fteid.from_core_fteid(peb.sgw_fteid_s5_s8_up);
      if (ppc->ipv4) {
        ue_ip_address.v4 = 1;
        ue_ip_address.ipv4_address.s_addr = ppc->ipv4_address.s_addr;
      }
      if (ppc->ipv6) {
        ue_ip_address.v6 = 1;
        ue_ip_address.ipv6_address = ppc->ipv6_address;
      }

      // DOIT simple
      // shall uniquely identify the PDR among all the PDRs configured for that PFCP session.
      ppc->generate_pdr_id(pdr_id);
      precedence.precedence = qos_flow.precedence.precedence;      //TODO: should be verified

      pdi.set(source_interface);
      //pdi.set(local_fteid);
      pdi.set(ue_ip_address);

      create_pdr.set(pdr_id);
      create_pdr.set(precedence);
      create_pdr.set(pdi);
      create_pdr.set(far_id);
      //-------------------
      // ADD IEs to message
      //-------------------
      n4_ser->pfcp_ies.set(create_pdr);

      send_n4 = true;

      qos_flow.pdr_id_dl = pdr_id;
    } else {
      Logger::smf_app().debug("Update SM Context procedure: Update FAR, qos_flow.pdr_id_dl.rule_id %d", qos_flow.pdr_id_dl.rule_id);
      // Update FAR
      far_id.far_id = qos_flow.far_id_ul.second.far_id;
      pfcp::update_far update_far = { };
      pfcp::apply_action_t apply_action = { };

      update_far.set(qos_flow.far_id_ul.second);
      apply_action.forw = 1;
      update_far.set(apply_action);

      n4_ser->pfcp_ies.set(update_far);

      send_n4 = true;

      qos_flow.far_id_dl.first = true;
    }
    // after a release flows
    if (not qos_flow.ul_fteid.is_zero()) {

    }
    // may be modified
    smf_qos_flow qos_flow2 = qos_flow;
    ppc->add_qos_flow(qos_flow2);

    qos_flow_context_updated qcu = { };
    qcu.set_cause(REQUEST_ACCEPTED);
    qcu.set_qfi(qfi);
    n11_triggered_pending->res.add_qos_flow_context_updated(qcu);
  }

  if (send_n4) {
    Logger::smf_app().info("Sending ITTI message %s to task TASK_SMF_N4", n4_ser->get_msg_name());
    int ret = itti_inst->send_msg(n4_triggered);
    if (RETURNok != ret) {
      Logger::smf_app().error("Could not send ITTI message %s to task TASK_SMF_N4", n4_ser->get_msg_name());
      return RETURNerror ;
    }
  } else {
    // send to AMF, update response
    //TODO: to be completed
    Logger::smf_app().info("Sending ITTI message %s to task TASK_SMF_N11", n11_triggered_pending->get_msg_name());
    int ret = itti_inst->send_msg(n11_triggered_pending);
    if (RETURNok != ret) {
      Logger::smf_app().error("Could not send ITTI message %s to task TASK_SMF_N11", n11_triggered_pending->get_msg_name());
    }
    return RETURNclear ;
  }
  return RETURNok ;

}

//------------------------------------------------------------------------------
void session_update_sm_context_procedure::handle_itti_msg(itti_n4_session_modification_response &resp, std::shared_ptr<smf::smf_context> sc) {

  smf_n1_n2 smf_n1_n2_inst = { };
  std::string n1_sm_msg, n1_sm_msg_hex;
  std::string n2_sm_info, n2_sm_info_hex;

  Logger::smf_app().info("Handle itti_n4_session_modification_response: pdu-session-id %d", n11_trigger.get()->req.get_pdu_session_id());
  //TODO: to be completed

  pfcp::cause_t cause = { };
  ::cause_t cause_gtp = { .cause_value = REQUEST_ACCEPTED };

  // must be there
  if (resp.pfcp_ies.get(cause)) {
    xgpp_conv::pfcp_cause_to_core_cause(cause, cause_gtp);
  }

  //list of accepted QFI(s) and AN Tunnel Info corresponding to the PDU Session
  std::vector<pfcp::qfi_t> list_of_qfis_to_be_modified = { };
  n11_trigger->req.get_qfis(list_of_qfis_to_be_modified);
  ::fteid_t dl_fteid = { };
  n11_trigger->req.get_dl_fteid(dl_fteid);

  std::map<uint8_t, qos_flow_context_updated> qos_flow_context_to_be_updateds = { };
  n11_triggered_pending->res.get_all_qos_flow_context_updateds(qos_flow_context_to_be_updateds);
  n11_triggered_pending->res.remove_all_qos_flow_context_updateds();

  for (std::map<uint8_t, qos_flow_context_updated>::iterator it = qos_flow_context_to_be_updateds.begin(); it != qos_flow_context_to_be_updateds.end(); ++it)
    Logger::smf_app().debug("qos_flow_context_to_be_modifieds qfi %d", it->first);

  for (auto it_created_pdr : resp.pfcp_ies.created_pdrs) {
    pfcp::pdr_id_t pdr_id = { };
    if (it_created_pdr.get(pdr_id)) {
      smf_qos_flow flow = { };
      if (ppc->get_qos_flow(pdr_id, flow)) {
        Logger::smf_app().debug("QoS Flow,  qfi %d", flow.qfi.qfi);
        for (auto it : qos_flow_context_to_be_updateds) {
          flow.dl_fteid = dl_fteid;
          flow.dl_fteid.interface_type = S1_U_ENODEB_GTP_U;  //eNB's N3 interface

          // flow.ul_fteid = it.second.ul_fteid;

          pfcp::fteid_t local_up_fteid = { };
          if (it_created_pdr.get(local_up_fteid)) {
            xgpp_conv::pfcp_to_core_fteid(local_up_fteid, flow.ul_fteid);
            flow.ul_fteid.interface_type = S1_U_SGW_GTP_U;  //UPF's N3 interface, TODO: should be modified
            Logger::smf_app().warn("got local_up_fteid from created_pdr %s", flow.ul_fteid.toString().c_str());
          } else {
            //UPF doesn't include its fteid in the response
            Logger::smf_app().warn("Could not get local_up_fteid from created_pdr");
          }

          flow.released = false;
          smf_qos_flow flow2 = flow;
          ppc->add_qos_flow(flow2);

          qos_flow_context_updated qcu = { };
          qcu.set_cause(REQUEST_ACCEPTED);
          qcu.set_qfi(pfcp::qfi_t(it.first));
          qcu.set_ul_fteid(flow.ul_fteid);
          qcu.set_dl_fteid(flow.dl_fteid);
          qcu.set_qos_profile(flow.qos_profile);
          n11_triggered_pending->res.add_qos_flow_context_updated(qcu);
          //TODO: remove this QFI from the list (as well as in n11_trigger->req)
          break;

        }
        /*
         for (auto qfi: list_of_qfis_to_be_modified){
         pfcp::fteid_t local_up_fteid = {};
         if (it_created_pdr.get(local_up_fteid)) {
         xgpp_conv::pfcp_to_core_fteid(local_up_fteid, flow.ul_fteid);
         flow.ul_fteid.interface_type = S5_S8_PGW_GTP_U; //TODO: should be modified

         Logger::smf_app().error( "got local_up_fteid from created_pdr %s", flow.ul_fteid.toString().c_str());
         } else {
         Logger::smf_app().error( "Could not get local_up_fteid from created_pdr");
         }

         flow.released = false;
         smf_qos_flow flow2 = flow;
         ppc->add_qos_flow(flow2);

         qos_flow_context_updated qcu = {};
         qcu.set_cause(REQUEST_ACCEPTED);
         qcu.set_qfi(qfi);
         qcu.set_ul_fteid(flow.ul_fteid);
         n11_triggered_pending->res.add_qos_flow_context_updated(qcu);
         //TODO: remove this QFI from the list (as well as in n11_trigger->req)
         break;

         }
         */
      }
    } else {
      Logger::smf_app().error("Could not get pdr_id for created_pdr in %s", resp.pfcp_ies.get_msg_name());
    }
  }

  if (cause.cause_value == CAUSE_VALUE_REQUEST_ACCEPTED) {
    // TODO failed rule id
    for (auto it_update_far : n4_triggered->pfcp_ies.update_fars) {
      pfcp::far_id_t far_id = { };
      if (it_update_far.get(far_id)) {
        smf_qos_flow flow = { };
        if (ppc->get_qos_flow(far_id, flow)) {
          //for (auto qfi: list_of_qfis_to_be_modified){
          for (auto it : qos_flow_context_to_be_updateds) {
            if (it.first == flow.qfi.qfi) {
              flow.dl_fteid = dl_fteid;
              smf_qos_flow flow2 = flow;
              ppc->add_qos_flow(flow2);

              qos_flow_context_updated qcu = { };
              qcu.set_cause(REQUEST_ACCEPTED);
              qcu.set_qfi(pfcp::qfi_t(it.first));
              qcu.set_ul_fteid(flow.ul_fteid);
              qcu.set_dl_fteid(flow.dl_fteid);
              qcu.set_qos_profile(flow.qos_profile);
              n11_triggered_pending->res.add_qos_flow_context_updated(qcu);
              break;
            }
          }
        } else {
          Logger::smf_app().error("Could not get qos flow for far_id for update_far in %s", resp.pfcp_ies.get_msg_name());
        }
      } else {
        Logger::smf_app().error("Could not get far_id for update_far in %s", resp.pfcp_ies.get_msg_name());
      }
    }
  }

  n11_triggered_pending->res.set_cause(cause_gtp.cause_value);

  // TODO
  // check we got all responses vs n11_triggered_pending->res.flow_context_modified

  //TODO: Optional: send ITTI message to N10 to trigger UDM registration (Nudm_UECM_Registration)
  //see TS29503_Nudm_UECM.yaml ( /{ueId}/registrations/smf-registrations/{pduSessionId}:)
  /* std::shared_ptr<itti_n10_create_smf_registration_request> itti_msg = std::make_shared<itti_n10_create_smf_registration_request>(TASK_SMF_APP, TASK_SMF_N10, response);
   int ret = itti_inst->send_msg(itti_msg);
   */

  //SHOULD BE REMOVED, FOR TESTING PURPOSE
  //change value here to test the corresponding message
  session_procedure_type = session_management_procedures_type_e::PDU_SESSION_TEST;

  nlohmann::json sm_context_updated_data = { };
  sm_context_updated_data["n1MessageContainer"]["n1MessageClass"] = N1N2_MESSAGE_CLASS;
  sm_context_updated_data["n1MessageContainer"]["n1MessageContent"]["contentId"] = N1_SM_CONTENT_ID;
  sm_context_updated_data["n2InfoContainer"]["n2InformationClass"] = N1N2_MESSAGE_CLASS;
  sm_context_updated_data["n2InfoContainer"]["smInfo"]["PduSessionId"] = n11_triggered_pending->res.get_pdu_session_id();
  sm_context_updated_data["n2InfoContainer"]["smInfo"]["n2InfoContent"]["ngapData"]["contentId"] = N2_SM_CONTENT_ID;

  switch (session_procedure_type) {

    //FOR TESTING PURPOSE
    case session_management_procedures_type_e::PDU_SESSION_TEST: {

      //N1 SM: PDU Session Modification Command​
      //N2 SM: PDU Session Resource Modify Request Transfer IE

      //N1 SM
      smf_n1_n2_inst.create_n1_sm_container(n11_triggered_pending->res, PDU_SESSION_MODIFICATION_COMMAND, n1_sm_msg, cause_value_5gsm_e::CAUSE_0_UNKNOWN);  //TODO: need cause?
      smf_app_inst->convert_string_2_hex(n1_sm_msg, n1_sm_msg_hex);
      n11_triggered_pending->res.set_n1_sm_message(n1_sm_msg_hex);
      //N2 SM Information
      smf_n1_n2_inst.create_n2_sm_information(n11_triggered_pending->res, 1, n2_sm_info_type_e::PDU_RES_MOD_REQ, n2_sm_info);
      smf_app_inst->convert_string_2_hex(n2_sm_info, n2_sm_info_hex);
      n11_triggered_pending->res.set_n2_sm_information(n2_sm_info_hex);

      //fill the content of SmContextUpdatedData
      n11_triggered_pending->res.sm_context_updated_data = sm_context_updated_data;
      n11_triggered_pending->res.sm_context_updated_data["n2InfoContainer"]["smInfo"]["n2InfoContent"]["ngapIeType"] = "PDU_RES_MOD_REQ";  //NGAP message
    }
      break;

      //PDU Session Establishment UE-Requested
    case session_management_procedures_type_e::PDU_SESSION_ESTABLISHMENT_UE_REQUESTED: {
      //No need to create N1/N2 Container, just Cause
      Logger::smf_app().info("PDU Session Establishment Request (UE-Initiated)");
      n11_triggered_pending->res.sm_context_updated_data["cause"] = n11_triggered_pending->res.get_cause();
    }
      break;

      //UE-Triggered Service Request Procedure (Step 1)
    case session_management_procedures_type_e::SERVICE_REQUEST_UE_TRIGGERED_STEP1: {
      // Create N2 SM Information: PDU Session Resource Setup Request Transfer IE

      //N2 SM Information
      smf_n1_n2_inst.create_n2_sm_information(n11_triggered_pending->res, 1, n2_sm_info_type_e::PDU_RES_SETUP_REQ, n2_sm_info);
      smf_app_inst->convert_string_2_hex(n2_sm_info, n2_sm_info_hex);
      n11_triggered_pending->res.set_n2_sm_information(n2_sm_info_hex);

      //fill the content of SmContextUpdatedData
      n11_triggered_pending->res.sm_context_updated_data = sm_context_updated_data;
      n11_triggered_pending->res.sm_context_updated_data["n2InfoContainer"]["smInfo"]["n2InfoContent"]["ngapIeType"] = "PDU_RES_SETUP_REQ";  //NGAP message
    }
      break;

      //UE-triggered Service Request (Step 2)
    case session_management_procedures_type_e::SERVICE_REQUEST_UE_TRIGGERED_STEP2: {
      //No need to create N1/N2 Container, just Cause
      Logger::smf_app().info("UE Triggered Service Request (Step 2)");
      n11_triggered_pending->res.sm_context_updated_data["cause"] = n11_triggered_pending->res.get_cause();
    }
      break;

      //PDU Session Modification UE-initiated (Step 1)
    case session_management_procedures_type_e::PDU_SESSION_MODIFICATION_UE_INITIATED_STEP1: {
      //N1 SM: PDU Session Modification Command​
      //N2 SM: PDU Session Resource Modify Request Transfer IE

      //N1 SM
      smf_n1_n2_inst.create_n1_sm_container(n11_triggered_pending->res, PDU_SESSION_MODIFICATION_COMMAND, n1_sm_msg, cause_value_5gsm_e::CAUSE_0_UNKNOWN);  //TODO: need cause?
      smf_app_inst->convert_string_2_hex(n1_sm_msg, n1_sm_msg_hex);
      n11_triggered_pending->res.set_n1_sm_message(n1_sm_msg_hex);
      //N2 SM Information
      smf_n1_n2_inst.create_n2_sm_information(n11_triggered_pending->res, 1, n2_sm_info_type_e::PDU_RES_MOD_REQ, n2_sm_info);
      smf_app_inst->convert_string_2_hex(n2_sm_info, n2_sm_info_hex);
      n11_triggered_pending->res.set_n2_sm_information(n2_sm_info_hex);

      //fill the content of SmContextUpdatedData
      n11_triggered_pending->res.sm_context_updated_data = sm_context_updated_data;
      n11_triggered_pending->res.sm_context_updated_data["n2InfoContainer"]["smInfo"]["n2InfoContent"]["ngapIeType"] = "PDU_RES_MOD_REQ";  //NGAP message
    }
      break;

      //PDU Session Modification UE-initiated (Step 2)
    case session_management_procedures_type_e::PDU_SESSION_MODIFICATION_UE_INITIATED_STEP2: {
      //No need to create N1/N2 Container
      Logger::smf_app().info("PDU Session Modification UE-initiated (Step 2)");
      //TODO:
    }
      break;

      //PDU Session Modification UE-initiated (Step 3)
    case session_management_procedures_type_e::PDU_SESSION_MODIFICATION_UE_INITIATED_STEP3: {
      //No need to create N1/N2 Container
      Logger::smf_app().info("PDU Session Modification UE-initiated (Step 3)");
      //TODO:
    }
      break;

      //PDU Session Release UE-initiated (Step 1)
    case session_management_procedures_type_e::PDU_SESSION_RELEASE_UE_REQUESTED_STEP1: {
      //N1 SM: PDU Session Release Command​
      //N2 SM: PDU Session Resource Release Command Transfer
      Logger::smf_app().info("PDU Session Release UE-initiated (Step 1))");

      //N1 SM
      smf_n1_n2_inst.create_n1_sm_container(n11_triggered_pending->res, PDU_SESSION_RELEASE_COMMAND, n1_sm_msg, cause_value_5gsm_e::CAUSE_0_UNKNOWN);  //TODO: need cause?
      smf_app_inst->convert_string_2_hex(n1_sm_msg, n1_sm_msg_hex);
      n11_triggered_pending->res.set_n1_sm_message(n1_sm_msg_hex);
      //N2 SM Information
      smf_n1_n2_inst.create_n2_sm_information(n11_triggered_pending->res, 1, n2_sm_info_type_e::PDU_RES_REL_CMD, n2_sm_info);
      smf_app_inst->convert_string_2_hex(n2_sm_info, n2_sm_info_hex);
      n11_triggered_pending->res.set_n2_sm_information(n2_sm_info_hex);

      //fill the content of SmContextUpdatedData
      n11_triggered_pending->res.sm_context_updated_data = sm_context_updated_data;
      n11_triggered_pending->res.sm_context_updated_data["n2InfoContainer"]["smInfo"]["n2InfoContent"]["ngapIeType"] = "PDU_RES_REL_CMD";  //NGAP message

    }
      break;

      //PDU Session Release UE-initiated (Step 2)
    case session_management_procedures_type_e::PDU_SESSION_RELEASE_UE_REQUESTED_STEP2: {
      //No need to create N1/N2 Container
      Logger::smf_app().info("PDU Session Release UE-initiated (Step 2)");
      //TODO:
    }
      break;

      //PDU Session Release UE-initiated (Step 3)
    case session_management_procedures_type_e::PDU_SESSION_RELEASE_UE_REQUESTED_STEP3: {
      //No need to create N1/N2 Container
      Logger::smf_app().info("PDU Session Release UE-initiated (Step 3)");
      //TODO:
    }
      break;

    default: {
      Logger::smf_app().info("Unknown session procedure type %d", session_procedure_type);

    }
  }

  //send ITTI message to N11 interface to trigger SessionUpdateSMContextResponse towards AMFs
  Logger::smf_app().info("Sending ITTI message %s to task TASK_SMF_N11", n11_triggered_pending->get_msg_name());
  n11_triggered_pending->session_procedure_type = session_procedure_type;  //session_management_procedures_type_e::PDU_SESSION_ESTABLISHMENT_UE_REQUESTED;
  int ret = itti_inst->send_msg(n11_triggered_pending);
  if (RETURNok != ret) {
    Logger::smf_app().error("Could not send ITTI message %s to task TASK_SMF_N11", n11_triggered_pending->get_msg_name());
  }

  //The SMF may subscribe to the UE mobility event notification from the AMF (e.g. location reporting, UE
  //moving into or out of Area Of Interest), by invoking Namf_EventExposure_Subscribe service operation
  // For LADN, the SMF subscribes to the UE moving into or out of LADN service area event notification by providing the LADN DNN as an indicator for the Area Of Interest
  //see step 17@section 4.3.2.2.1@3GPP TS 23.502

  if (cause.cause_value != CAUSE_VALUE_REQUEST_ACCEPTED) {
    //TODO: Nsmf_PDUSession_SMContextStatusNotify
    /*  If the PDU Session establishment is not successful, the SMF informs the AMF by invoking Nsmf_PDUSession_SMContextStatusNotify (Release). The SMF also releases any N4
     session(s) created, any PDU Session address if allocated (e.g. IP address) and releases the association with PCF, if any.
     see step 18, section 4.3.2.2.1@3GPP TS 23.502)
     */
  }

}

