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

/*! \file smf_app.cpp
 \brief
 \author  Lionel GAUTHIER, Tien-Thinh NGUYEN
 \company Eurecom
 \date 2019
 \email: lionel.gauthier@eurecom.fr, tien-thinh.nguyen@eurecom.fr
 */

#include "smf_app.hpp"

#include <stdexcept>
#include <iostream>
#include <cstdlib>

#include "async_shell_cmd.hpp"
#include "common_defs.h"
#include "conversions.hpp"
#include "itti.hpp"
#include "logger.hpp"
#include "string.hpp"
#include "3gpp_29.502.h"
#include "3gpp_24.007.h"
#include "smf.h"
#include "3gpp_24.501.h"
#include "smf_n1_n2.hpp"
#include "smf_paa_dynamic.hpp"
#include "smf_n4.hpp"
#include "smf_n10.hpp"
#include "smf_n11.hpp"
#include "pfcp.hpp"
#include "itti_msg_nx.hpp"
#include "SmContextCreatedData.h"
#include "RefToBinaryData.h"
#include "SmContextCreateError.h"
#include "SmContextUpdateError.h"
#include "SmContextMessage.h"
#include "ProblemDetails.h"

extern "C" {
#include "nas_message.h"
#include "dynamic_memory_check.h"
}

using namespace smf;

#define SYSTEM_CMD_MAX_STR_SIZE 512
extern util::async_shell_cmd *async_shell_cmd_inst;
extern smf_app *smf_app_inst;
extern smf_config smf_cfg;
smf_n4 *smf_n4_inst = nullptr;
smf_n10 *smf_n10_inst = nullptr;
smf_n11 *smf_n11_inst = nullptr;
extern itti_mw *itti_inst;

void smf_app_task(void*);

//------------------------------------------------------------------------------
int smf_app::apply_config(const smf_config &cfg) {
  Logger::smf_app().info("Apply config...");

  for (int ia = 0; ia < cfg.num_apn; ia++) {
    if (cfg.apn[ia].pool_id_iv4 >= 0) {
      int pool_id = cfg.apn[ia].pool_id_iv4;
      int range =
          be32toh(
              cfg.ue_pool_range_high[pool_id].s_addr) - be32toh(cfg.ue_pool_range_low[pool_id].s_addr);
      paa_dynamic::get_instance().add_pool(cfg.apn[ia].apn, pool_id,
                                           cfg.ue_pool_range_low[pool_id],
                                           range);
      //TODO: check with apn_label
      Logger::smf_app().info("Applied config %s", cfg.apn[ia].apn.c_str());
    }
    if (cfg.apn[ia].pool_id_iv6 >= 0) {
      int pool_id = cfg.apn[ia].pool_id_iv6;
      paa_dynamic::get_instance().add_pool(cfg.apn[ia].apn, pool_id,
                                           cfg.paa_pool6_prefix[pool_id],
                                           cfg.paa_pool6_prefix_len[pool_id]);
      //TODO: check with apn_label
    }
  }

  Logger::smf_app().info("Applied config");
  return RETURNok ;
}

//------------------------------------------------------------------------------
uint64_t smf_app::generate_seid() {
  std::unique_lock<std::mutex> ls(m_seid_n4_generator);
  uint64_t seid = ++seid_n4_generator;
  while ((is_seid_n4_exist(seid)) || (seid == UNASSIGNED_SEID)) {
    seid = ++seid_n4_generator;
  }
  set_seid_n4.insert(seid);
  ls.unlock();
  return seid;
}

//------------------------------------------------------------------------------
void smf_app::generate_smf_context_ref(std::string &smf_ref) {
  smf_ref = std::to_string(sm_context_ref_generator.get_uid());
}

//------------------------------------------------------------------------------
scid_t smf_app::generate_smf_context_ref() {
  return sm_context_ref_generator.get_uid();
}

//------------------------------------------------------------------------------
bool smf_app::is_seid_n4_exist(const uint64_t &seid) const {
  return bool { set_seid_n4.count(seid) > 0 };
}

//------------------------------------------------------------------------------
void smf_app::free_seid_n4(const uint64_t &seid) {
  std::unique_lock<std::mutex> ls(m_seid_n4_generator);
  set_seid_n4.erase(seid);
  ls.unlock();
}

//------------------------------------------------------------------------------
void smf_app::set_seid_2_smf_context(const seid_t &seid,
                                     std::shared_ptr<smf_context> &pc) {
  std::unique_lock lock(m_seid2smf_context);
  seid2smf_context[seid] = pc;
}

//------------------------------------------------------------------------------
bool smf_app::seid_2_smf_context(const seid_t &seid,
                                 std::shared_ptr<smf_context> &pc) const {
  std::shared_lock lock(m_seid2smf_context);
  std::map<seid_t, std::shared_ptr<smf_context>>::const_iterator it =
      seid2smf_context.find(seid);
  if (it != seid2smf_context.end()) {
    pc = it->second;
    return true;
  }
  return false;
}

//------------------------------------------------------------------------------
void smf_app::delete_smf_context(std::shared_ptr<smf_context> spc) {
  supi64_t supi64 = smf_supi_to_u64(spc.get()->get_supi());
  std::unique_lock lock(m_supi2smf_context);
  supi2smf_context.erase(supi64);
}

//------------------------------------------------------------------------------
void smf_app::restore_n4_sessions(const seid_t &seid) const {
  std::shared_lock lock(m_seid2smf_context);
  //TODO
}

//------------------------------------------------------------------------------
void smf_app_task(void*) {
  const task_id_t task_id = TASK_SMF_APP;
  itti_inst->notify_task_ready(task_id);

  do {
    std::shared_ptr<itti_msg> shared_msg = itti_inst->receive_msg(task_id);
    auto *msg = shared_msg.get();
    switch (msg->msg_type) {

      case N4_SESSION_ESTABLISHMENT_RESPONSE:
        if (itti_n4_session_establishment_response *m =
            dynamic_cast<itti_n4_session_establishment_response*>(msg)) {
          smf_app_inst->handle_itti_msg(std::ref(*m));
        }
        break;

      case N4_SESSION_MODIFICATION_RESPONSE:
        if (itti_n4_session_modification_response *m =
            dynamic_cast<itti_n4_session_modification_response*>(msg)) {
          smf_app_inst->handle_itti_msg(std::ref(*m));
        }
        break;

      case N4_SESSION_DELETION_RESPONSE:
        if (itti_n4_session_deletion_response *m =
            dynamic_cast<itti_n4_session_deletion_response*>(msg)) {
          smf_app_inst->handle_itti_msg(std::ref(*m));
        }
        break;

      case N11_SESSION_N1N2_MESSAGE_TRANSFER_RESPONSE_STATUS:
        if (itti_n11_n1n2_message_transfer_response_status *m =
            dynamic_cast<itti_n11_n1n2_message_transfer_response_status*>(msg)) {
          smf_app_inst->handle_itti_msg(std::ref(*m));
        }
        break;

      case N11_SESSION_UPDATE_PDU_SESSION_STATUS:
        if (itti_n11_update_pdu_session_status *m =
            dynamic_cast<itti_n11_update_pdu_session_status*>(msg)) {
          smf_app_inst->handle_itti_msg(std::ref(*m));
        }
        break;

      case N4_SESSION_REPORT_REQUEST:
        smf_app_inst->handle_itti_msg(
            std::static_pointer_cast<itti_n4_session_report_request>(
                shared_msg));
        break;

      case TIME_OUT:
        if (itti_msg_timeout *to = dynamic_cast<itti_msg_timeout*>(msg)) {
          Logger::smf_app().info("TIME-OUT event timer id %d", to->timer_id);
          switch (to->arg1_user) {
            case TASK_SMF_APP_TRIGGER_T3591:
              smf_app_inst->timer_t3591_timeout(to->timer_id, to->arg2_user);
              break;
            default:
              ;
          }
        }

        break;
      case TERMINATE:
        if (itti_msg_terminate *terminate =
            dynamic_cast<itti_msg_terminate*>(msg)) {
          Logger::smf_app().info("Received terminate message");
          return;
        }
      case HEALTH_PING:
        break;
      default:
        Logger::smf_app().info("no handler for msg type %d", msg->msg_type);
    }
  } while (true);
}

//------------------------------------------------------------------------------
smf_app::smf_app(const std::string &config_file)
    :
    m_seid2smf_context() {
  Logger::smf_app().startup("Starting...");

  supi2smf_context = { };
  set_seid_n4 = { };
  seid_n4_generator = 0;

  apply_config(smf_cfg);

  if (itti_inst->create_task(TASK_SMF_APP, smf_app_task, nullptr)) {
    Logger::smf_app().error("Cannot create task TASK_SMF_APP");
    throw std::runtime_error("Cannot create task TASK_SMF_APP");
  }

  try {
    smf_n4_inst = new smf_n4();
    smf_n10_inst = new smf_n10();
    smf_n11_inst = new smf_n11();
  } catch (std::exception &e) {
    Logger::smf_app().error("Cannot create SMF_APP: %s", e.what());
    throw;
  }

  //TODO: should be done when SMF select UPF for a particular UE (should be verified)
  for (std::vector<pfcp::node_id_t>::const_iterator it = smf_cfg.upfs.begin();
      it != smf_cfg.upfs.end(); ++it) {
    start_upf_association(*it);
  }

  Logger::smf_app().startup("Started");
}

//------------------------------------------------------------------------------
//From SPGWU
void smf_app::start_upf_association(const pfcp::node_id_t &node_id) {
  // TODO  refine this, look at RFC5905
  std::tm tm_epoch = { 0 };  // Feb 8th, 2036
  tm_epoch.tm_year = 2036 - 1900;  // years count from 1900
  tm_epoch.tm_mon = 2 - 1;    // months count from January=0
  tm_epoch.tm_mday = 8 - 1;         // days count from 1
  std::time_t time_epoch = std::mktime(&tm_epoch);
  std::chrono::time_point<std::chrono::system_clock> now =
      std::chrono::system_clock::now();
  std::time_t now_c = std::chrono::system_clock::to_time_t(now);
  std::time_t ellapsed = now_c - time_epoch;
  uint64_t recovery_time_stamp = ellapsed;

  //char* dt = ctime(&now_c);
  //Logger::smf_app().info( "Current time %s", dt);
  // convert now to tm struct for UTC
  tm *gmtm = gmtime(&now_c);
  char *dt = asctime(gmtm);
  Logger::smf_app().info("Current time (UTC) %s", dt);

  pfcp_associations::get_instance().add_peer_candidate_node(node_id);
  std::shared_ptr<itti_n4_association_setup_request> n4_asc = std::shared_ptr<
      itti_n4_association_setup_request>(
      new itti_n4_association_setup_request(TASK_SMF_APP, TASK_SMF_N4));

  //n4_asc->trxn_id = smf_n4_inst->generate_trxn_id();
  pfcp::cp_function_features_s cp_function_features;
  cp_function_features = { };
  cp_function_features.load = 1;
  cp_function_features.ovrl = 1;

  /*
   pfcp::up_function_features_s   up_function_features;
   // TODO load from config when features available ?
   up_function_features = {};
   up_function_features.bucp = 0;
   up_function_features.ddnd = 0;
   up_function_features.dlbd = 0;
   up_function_features.trst = 0;
   up_function_features.ftup = 1;
   up_function_features.pfdm = 0;
   up_function_features.heeu = 0;
   up_function_features.treu = 0;
   up_function_features.empu = 0;
   up_function_features.pdiu = 0;
   up_function_features.udbc = 0;
   up_function_features.quoac = 0;
   up_function_features.trace = 0;
   up_function_features.frrt = 0;
   */

  pfcp::node_id_t this_node_id = { };
  if (smf_cfg.get_pfcp_node_id(this_node_id) == RETURNok) {
    n4_asc->pfcp_ies.set(this_node_id);
    pfcp::recovery_time_stamp_t r = { .recovery_time_stamp =
        (uint32_t) recovery_time_stamp };
    n4_asc->pfcp_ies.set(r);

    //n4_asc->pfcp_ies.set(up_function_features);
    n4_asc->pfcp_ies.set(cp_function_features);
    if (node_id.node_id_type == pfcp::NODE_ID_TYPE_IPV4_ADDRESS) {
      n4_asc->r_endpoint = endpoint(node_id.u1.ipv4_address,
                                    pfcp::default_port);
      int ret = itti_inst->send_msg(n4_asc);
      if (RETURNok != ret) {
        Logger::smf_app().error(
            "Could not send ITTI message %s to task TASK_SMF_N4",
            n4_asc.get()->get_msg_name());
      }
    } else {
      Logger::smf_app().warn("TODO start_association() node_id IPV6, FQDN!");
    }
  }
}

//------------------------------------------------------------------------------
void smf_app::handle_itti_msg(itti_n4_session_establishment_response &seresp) {
  std::shared_ptr<smf_context> pc = { };
  if (seid_2_smf_context(seresp.seid, pc)) {
    pc.get()->handle_itti_msg(seresp);
  } else {
    Logger::smf_app().debug(
        "Received N4 SESSION ESTABLISHMENT RESPONSE seid" TEID_FMT "  pfcp_tx_id %" PRIX64", smf_context not found, discarded!",
        seresp.seid, seresp.trxn_id);
  }
}

//------------------------------------------------------------------------------
void smf_app::handle_itti_msg(itti_n4_session_modification_response &smresp) {
  std::shared_ptr<smf_context> pc = { };
  if (seid_2_smf_context(smresp.seid, pc)) {
    pc.get()->handle_itti_msg(smresp);
  } else {
    Logger::smf_app().debug(
        "Received N4 SESSION MODIFICATION RESPONSE seid" TEID_FMT "  pfcp_tx_id %" PRIX64", smf_context not found, discarded!",
        smresp.seid, smresp.trxn_id);
  }
}

//------------------------------------------------------------------------------
void smf_app::handle_itti_msg(itti_n4_session_deletion_response &smresp) {
  std::shared_ptr<smf_context> pc = { };
  if (seid_2_smf_context(smresp.seid, pc)) {
    pc.get()->handle_itti_msg(smresp);

    if (pc->get_number_dnn_contexts() == 0) {
      delete_smf_context(pc);
    }
  } else {
    Logger::smf_app().debug(
        "Received N4 SESSION DELETION RESPONSE seid" TEID_FMT "  pfcp_tx_id %" PRIX64", smf_context not found, discarded!",
        smresp.seid, smresp.trxn_id);
  }
}

//------------------------------------------------------------------------------
void smf_app::handle_itti_msg(
    std::shared_ptr<itti_n4_session_report_request> snr) {
  std::shared_ptr<smf_context> pc = { };
  if (seid_2_smf_context(snr->seid, pc)) {
    pc.get()->handle_itti_msg(snr);
  } else {
    Logger::smf_app().debug(
        "Received N4 SESSION REPORT REQUEST seid" TEID_FMT "  pfcp_tx_id %" PRIX64", smf_context not found, discarded!",
        snr->seid, snr->trxn_id);
  }
}

//------------------------------------------------------------------------------
void smf_app::handle_itti_msg(
    itti_n11_n1n2_message_transfer_response_status &m) {
  Logger::smf_app().info("Process N1N2MessageTransfer Response");
  //Update PDU Session accordingly
  //TODO: to be completed (process cause)
  pdu_session_status_e status = { pdu_session_status_e::PDU_SESSION_INACTIVE };
  upCnx_state_e state = { upCnx_state_e::UPCNX_STATE_DEACTIVATED };
  if ((static_cast<http_response_codes_e>(m.response_code)
      == http_response_codes_e::HTTP_RESPONSE_CODE_OK)
      or (static_cast<http_response_codes_e>(m.response_code)
          == http_response_codes_e::HTTP_RESPONSE_CODE_ACCEPTED)) {
    if (m.msg_type == PDU_SESSION_ESTABLISHMENT_REJECT) {
      status = pdu_session_status_e::PDU_SESSION_INACTIVE;
    } else if (m.msg_type == PDU_SESSION_ESTABLISHMENT_ACCEPT) {
      status = pdu_session_status_e::PDU_SESSION_ESTABLISHMENT_PENDING;
      state = upCnx_state_e::UPCNX_STATE_ACTIVATING;
    }
    update_pdu_session_status(m.scid, status);
    update_pdu_session_upCnx_state(m.scid, state);
    Logger::smf_app().debug(
        "Got successful response from AMF (Response code %d), set session status to %s",
        m.response_code,
        pdu_session_status_e2str[static_cast<int>(status)].c_str());
  } else {
    //TODO:
    Logger::smf_app().debug("Got response from AMF (Response code %d)",
                            m.response_code);
  }

}

//------------------------------------------------------------------------------
void smf_app::handle_itti_msg(itti_n11_update_pdu_session_status &m) {
  Logger::smf_app().info(
      "Set PDU Session Status to %s",
      pdu_session_status_e2str[static_cast<int>(m.pdu_session_status)].c_str());
  update_pdu_session_status(m.scid, m.pdu_session_status);
}

//------------------------------------------------------------------------------
void smf_app::handle_pdu_session_create_sm_context_request(
    std::shared_ptr<itti_n11_create_sm_context_request> smreq) {
  Logger::smf_app().info(
      "Handle a PDU Session Create SM Context Request from an AMF");
  //handle PDU Session Create SM Context Request as specified in section 4.3.2 3GPP TS 23.502
  oai::smf_server::model::SmContextCreateError smContextCreateError = { };
  oai::smf_server::model::ProblemDetails problem_details = { };
  oai::smf_server::model::RefToBinaryData refToBinaryData = { };
  std::string n1_sm_message, n1_sm_message_hex;
  smf_n1_n2 smf_n1_n2_inst = { };
  nas_message_t decoded_nas_msg = { };
  cause_value_5gsm_e cause_n1 = { cause_value_5gsm_e::CAUSE_0_UNKNOWN };
  pdu_session_type_t pdu_session_type = { .pdu_session_type =
      PDU_SESSION_TYPE_E_IPV4 };

  //Step 1. Decode NAS and get the necessary information
  std::string n1_sm_msg = smreq->req.get_n1_sm_message();
  memset(&decoded_nas_msg, 0, sizeof(nas_message_t));

  int decoder_rc = smf_n1_n2_inst.decode_n1_sm_container(decoded_nas_msg,
                                                         n1_sm_msg);
  if (decoder_rc != RETURNok) {
    //error, send reply to AMF with PDU Session Establishment Reject
    Logger::smf_app().warn("N1 SM container cannot be decoded correctly!");
    problem_details.setCause(
        pdu_session_application_error_e2str[PDU_SESSION_APPLICATION_ERROR_N1_SM_ERROR]);
    smContextCreateError.setError(problem_details);
    refToBinaryData.setContentId(N1_SM_CONTENT_ID);
    smContextCreateError.setN1SmMsg(refToBinaryData);
    smf_n1_n2_inst.create_n1_sm_container(
        smreq->req, PDU_SESSION_ESTABLISHMENT_REJECT, n1_sm_message,
        cause_value_5gsm_e::CAUSE_95_SEMANTICALLY_INCORRECT_MESSAGE);
    smf_app_inst->convert_string_2_hex(n1_sm_message, n1_sm_message_hex);
    smf_n11_inst->send_pdu_session_create_sm_context_response(
        smreq->http_response, smContextCreateError,
        Pistache::Http::Code::Forbidden, n1_sm_message_hex);
    return;
  }

  Logger::smf_app().debug(
      "NAS information: Extended Protocol Discriminator %d, Security Header Type %d, Message Type %d",
      decoded_nas_msg.header.extended_protocol_discriminator,
      decoded_nas_msg.header.security_header_type,
      decoded_nas_msg.plain.sm.header.message_type);

  //Extended protocol discriminator (Mandatory)
  smreq->req.set_epd(decoded_nas_msg.header.extended_protocol_discriminator);
  //PDUSessionIdentity
  pdu_session_id_t pdu_session_id = decoded_nas_msg.plain.sm.header
      .pdu_session_identity;
  //ProcedureTransactionIdentity
  procedure_transaction_id_t pti = { .procedure_transaction_id = decoded_nas_msg
      .plain.sm.header.procedure_transaction_identity };
  //Message type (Mandatory)
  smreq->req.set_message_type(decoded_nas_msg.plain.sm.header.message_type);
  //TODO: Integrity protection maximum data rate (Mandatory)

  //PDU session type (Optional)
  if (decoded_nas_msg.plain.sm.header.message_type
      == PDU_SESSION_ESTABLISHMENT_REQUEST) {
    //TODO: Disable this command temporarily since can't get this info from tester
    Logger::smf_app().debug(
        "NAS, pdu_session_type %d",
        decoded_nas_msg.plain.sm.pdu_session_establishment_request
            ._pdusessiontype.pdu_session_type_value);
    pdu_session_type.pdu_session_type = decoded_nas_msg.plain.sm
        .pdu_session_establishment_request._pdusessiontype
        .pdu_session_type_value;
  }

  smreq->req.set_pdu_session_type(pdu_session_type.pdu_session_type);

  //TODO: Support IPv4 only for now
  if (pdu_session_type.pdu_session_type == PDU_SESSION_TYPE_E_IPV6) {
    cause_n1 = cause_value_5gsm_e::CAUSE_50_PDU_SESSION_TYPE_IPV4_ONLY_ALLOWED;
  } else if ((pdu_session_type.pdu_session_type == PDU_SESSION_TYPE_E_ETHERNET)
      or (pdu_session_type.pdu_session_type == PDU_SESSION_TYPE_E_UNSTRUCTURED)) {
    cause_n1 = cause_value_5gsm_e::CAUSE_28_UNKNOWN_PDU_SESSION_TYPE;
  }
  if (pdu_session_type.pdu_session_type != PDU_SESSION_TYPE_E_IPV4) {
    problem_details.setCause(
        pdu_session_application_error_e2str[PDU_SESSION_APPLICATION_ERROR_PDUTYPE_DENIED]);
    smContextCreateError.setError(problem_details);
    refToBinaryData.setContentId(N1_SM_CONTENT_ID);
    smContextCreateError.setN1SmMsg(refToBinaryData);
    //PDU Session Establishment Reject
    smf_n1_n2_inst.create_n1_sm_container(smreq->req,
    PDU_SESSION_ESTABLISHMENT_REJECT,
                                          n1_sm_message, cause_n1);
    smf_app_inst->convert_string_2_hex(n1_sm_message, n1_sm_message_hex);
    smf_n11_inst->send_pdu_session_create_sm_context_response(
        smreq->http_response, smContextCreateError,
        Pistache::Http::Code::Forbidden, n1_sm_message_hex);
  }

  //TODO: SSCMode
  //TODO: store UE 5GSM Capability
  //TODO: MaximumNumberOfSupportedPacketFilters
  //TODO: AlwaysonPDUSessionRequested
  //TODO: SMPDUDNRequestContainer
  //TODO: ExtendedProtocolConfigurationOptions

  //Get necessary information
  supi_t supi = smreq->req.get_supi();
  supi64_t supi64 = smf_supi_to_u64(supi);
  std::string dnn = smreq->req.get_dnn();
  snssai_t snssai = smreq->req.get_snssai();
  uint8_t message_type = decoded_nas_msg.plain.sm.header.message_type;
  std::string request_type = smreq->req.get_request_type();
  Logger::smf_app().info(
      "Handle a PDU Session Create SM Context Request message from AMF, supi " SUPI_64_FMT ", dnn %s, snssai_sst %d, snssai_sd %s",
      supi64, dnn.c_str(), snssai.sST, snssai.sD.c_str());

  //If no DNN information from UE, set to default value
  if (dnn.length() == 0) {
    dnn == smf_cfg.get_default_dnn();
  }

  //Step 2. Verify Procedure transaction id, pdu session id, message type, request type, etc.
  //check pti
  if ((pti.procedure_transaction_id == PROCEDURE_TRANSACTION_IDENTITY_UNASSIGNED )
      || (pti.procedure_transaction_id > PROCEDURE_TRANSACTION_IDENTITY_LAST )) {
    Logger::smf_app().warn(" Invalid PTI value (pti = %d)",
                           pti.procedure_transaction_id);
    problem_details.setCause(
        pdu_session_application_error_e2str[PDU_SESSION_APPLICATION_ERROR_N1_SM_ERROR]);
    smContextCreateError.setError(problem_details);
    refToBinaryData.setContentId(N1_SM_CONTENT_ID);
    smContextCreateError.setN1SmMsg(refToBinaryData);
    //PDU Session Establishment Reject including cause "#81 Invalid PTI value" (section 7.3.1 @3GPP TS 24.501)
    smf_n1_n2_inst.create_n1_sm_container(
        smreq->req, PDU_SESSION_ESTABLISHMENT_REJECT, n1_sm_message,
        cause_value_5gsm_e::CAUSE_81_INVALID_PTI_VALUE);
    smf_app_inst->convert_string_2_hex(n1_sm_message, n1_sm_message_hex);
    smf_n11_inst->send_pdu_session_create_sm_context_response(
        smreq->http_response, smContextCreateError,
        Pistache::Http::Code::Forbidden, n1_sm_message_hex);
    return;
  }
  smreq->req.set_pti(pti);

  //check pdu session id
  if ((pdu_session_id == PDU_SESSION_IDENTITY_UNASSIGNED )
      || (pdu_session_id > PDU_SESSION_IDENTITY_LAST )) {
    Logger::smf_app().warn(" Invalid PDU Session ID value (psi = %d)",
                           pdu_session_id);
    //section 7.3.2@3GPP TS 24.501; NAS N1 SM message: ignore the message
    return;
  }

  //check message type
  if (message_type != PDU_SESSION_ESTABLISHMENT_REQUEST) {
    Logger::smf_app().warn("Invalid message type (message type = %d)",
                           message_type);
    problem_details.setCause(
        pdu_session_application_error_e2str[PDU_SESSION_APPLICATION_ERROR_N1_SM_ERROR]);
    smContextCreateError.setError(problem_details);
    refToBinaryData.setContentId(N1_SM_CONTENT_ID);
    smContextCreateError.setN1SmMsg(refToBinaryData);
    //PDU Session Establishment Reject
    //(24.501 (section 7.4)) implementation dependent->do similar to UE: response with a 5GSM STATUS message including cause "#98 message type not compatible with protocol state."
    smf_n1_n2_inst.create_n1_sm_container(
        smreq->req,
        PDU_SESSION_ESTABLISHMENT_REJECT,
        n1_sm_message,
        cause_value_5gsm_e::CAUSE_98_MESSAGE_TYPE_NOT_COMPATIBLE_WITH_PROTOCOL_STATE);
    smf_app_inst->convert_string_2_hex(n1_sm_message, n1_sm_message_hex);
    smf_n11_inst->send_pdu_session_create_sm_context_response(
        smreq->http_response, smContextCreateError,
        Pistache::Http::Code::Forbidden, n1_sm_message_hex);
  }

  //check request type
  if (request_type.compare("INITIAL_REQUEST") != 0) {
    Logger::smf_app().warn("Invalid request type (request type = %s)",
                           "INITIAL_REQUEST");
    //TODO:
    //return
  }

  //TODO: For the moment, not support PDU session authentication and authorization by the external DN

  //Step 3. check if the DNN requested is valid
  if (not smf_cfg.is_dotted_dnn_handled(dnn, pdu_session_type)) {
    // Not a valid request...
    Logger::smf_app().warn(
        "Received PDU_SESSION_CREATESMCONTEXT_REQUEST unknown requested DNN %s, ignore message!",
        dnn.c_str());
    problem_details.setCause(
        pdu_session_application_error_e2str[PDU_SESSION_APPLICATION_ERROR_DNN_DENIED]);
    smContextCreateError.setError(problem_details);
    refToBinaryData.setContentId(N1_SM_CONTENT_ID);
    smContextCreateError.setN1SmMsg(refToBinaryData);
    //PDU Session Establishment Reject, 24.501 cause "#27 Missing or unknown DNN"
    smf_n1_n2_inst.create_n1_sm_container(
        smreq->req, PDU_SESSION_ESTABLISHMENT_REJECT, n1_sm_message,
        cause_value_5gsm_e::CAUSE_27_MISSING_OR_UNKNOWN_DNN);
    smf_app_inst->convert_string_2_hex(n1_sm_message, n1_sm_message_hex);
    smf_n11_inst->send_pdu_session_create_sm_context_response(
        smreq->http_response, smContextCreateError,
        Pistache::Http::Code::Forbidden, n1_sm_message_hex);
    return;
  }

  //Step 4. create a context for this supi if not existed, otherwise update
  std::shared_ptr<smf_context> sc = { };
  if (is_supi_2_smf_context(supi64)) {
    Logger::smf_app().debug("Update SMF context with SUPI " SUPI_64_FMT "",
                            supi64);
    sc = supi_2_smf_context(supi64);
    sc.get()->set_supi(supi);
  } else {
    Logger::smf_app().debug(
        "Create a new SMF context with SUPI " SUPI_64_FMT "", supi64);
    sc = std::shared_ptr<smf_context>(new smf_context());
    sc.get()->set_supi(supi);
    set_supi_2_smf_context(supi64, sc);
  }

  //Step 5. Create/update context with dnn information
  std::shared_ptr<dnn_context> sd = { };

  if (!sc.get()->find_dnn_context(snssai, dnn, sd)) {
    if (nullptr == sd.get()) {
      //create a new one and insert to the list
      Logger::smf_app().debug(
          "Create a DNN context and add to the SMF context");
      sd = std::shared_ptr<dnn_context>(new dnn_context(dnn));
      sd.get()->in_use = true;
      sd.get()->dnn_in_use = dnn;
      sd.get()->nssai = snssai;
      sc.get()->insert_dnn(sd);
    }
  }

  //Step 6. retrieve Session Management Subscription data from UDM if not available (step 4, section 4.3.2 3GPP TS 23.502)
  //TODO: Test with UDM (TESTER)
  std::string dnn_selection_mode = smreq->req.get_dnn_selection_mode();
  if (not use_local_configuration_subscription_data(dnn_selection_mode)
      && not is_supi_dnn_snssai_subscription_data(supi, dnn, snssai)) {
    //uses a dummy UDM to test this part
    Logger::smf_app().debug(
        "Retrieve Session Management Subscription data from an UDM");
    session_management_subscription *s = new session_management_subscription(
        snssai);
    std::shared_ptr<session_management_subscription> subscription =
        std::shared_ptr<session_management_subscription>(s);
    if (smf_n10_inst->get_sm_data(supi64, dnn, snssai, subscription)) {
      Logger::smf_app().debug("Update DNN subscription info");
      //update dnn_context with subscription info
      sc.get()->insert_dnn_subscription(snssai, subscription);
    } else {
      // Cannot retrieve information from UDM, reject PDU session establishment
      Logger::smf_app().warn(
          "Received PDU_SESSION_CREATESMCONTEXT_REQUEST, couldn't retrieve the Session Management Subscription from UDM, ignore message!");
      problem_details.setCause(
          pdu_session_application_error_e2str[PDU_SESSION_APPLICATION_ERROR_SUBSCRIPTION_DENIED]);
      smContextCreateError.setError(problem_details);
      refToBinaryData.setContentId(N1_SM_CONTENT_ID);
      smContextCreateError.setN1SmMsg(refToBinaryData);
      //PDU Session Establishment Reject, with cause "29 User authentication or authorization failed"
      smf_n1_n2_inst.create_n1_sm_container(
          smreq->req,
          PDU_SESSION_ESTABLISHMENT_REJECT,
          n1_sm_message,
          cause_value_5gsm_e::CAUSE_29_USER_AUTHENTICATION_OR_AUTHORIZATION_FAILED);
      smf_app_inst->convert_string_2_hex(n1_sm_message, n1_sm_message_hex);
      //Send response (PDU Session Establishment Reject) to AMF
      smf_n11_inst->send_pdu_session_create_sm_context_response(
          smreq->http_response, smContextCreateError,
          Pistache::Http::Code::Forbidden, n1_sm_message_hex);
      return;
    }
  }

  // Step 7. generate a SMF context Id and store the corresponding information in a map (SM_Context_ID, (supi, dnn, nssai, pdu_session_id))
  scid_t scid = generate_smf_context_ref();
  std::shared_ptr<smf_context_ref> scf = std::shared_ptr<smf_context_ref>(
      new smf_context_ref());
  scf.get()->supi = supi;
  scf.get()->dnn = dnn;
  scf.get()->nssai = snssai;
  scf.get()->pdu_session_id = pdu_session_id;
  set_scid_2_smf_context(scid, scf);
  smreq->set_scid(scid);
  //store scid in the context itself
  sc.get()->set_scid(scid);

  Logger::smf_app().debug("Generated a SCID " SCID_FMT " ", scid);

  //Step 8. let the context handle the message
  sc.get()->handle_pdu_session_create_sm_context_request(smreq);

}

//------------------------------------------------------------------------------
void smf_app::handle_pdu_session_update_sm_context_request(
    std::shared_ptr<itti_n11_update_sm_context_request> smreq) {
  //handle PDU Session Update SM Context Request as specified in section 4.3.2 3GPP TS 23.502
  Logger::smf_app().info(
      "Handle a PDU Session Update SM Context Request from an AMF");
  oai::smf_server::model::SmContextUpdateError smContextUpdateError = { };
  oai::smf_server::model::ProblemDetails problem_details = { };

  //Step 1. get supi, dnn, nssai, pdu_session id from sm_context
  //SM Context ID - uint32_t in our case
  scid_t scid = { };
  try {
    scid = std::stoi(smreq->scid);
  } catch (const std::exception &err) {
    Logger::smf_app().warn(
        "Received a PDU Session Update SM Context Request, couldn't retrieve the corresponding SMF context, ignore message!");
    problem_details.setCause(
        pdu_session_application_error_e2str[PDU_SESSION_APPLICATION_ERROR_CONTEXT_NOT_FOUND]);
    smContextUpdateError.setError(problem_details);
    smf_n11_inst->send_pdu_session_update_sm_context_response(
        smreq->http_response, smContextUpdateError,
        Pistache::Http::Code::Not_Found);
    return;
  }

  std::shared_ptr<smf_context_ref> scf = { };

  if (is_scid_2_smf_context(scid)) {
    scf = scid_2_smf_context(scid);
  } else {
    Logger::smf_app().warn(
        "Context associated with this id " SCID_FMT " does not exit!", scid);
    problem_details.setCause(
        pdu_session_application_error_e2str[PDU_SESSION_APPLICATION_ERROR_CONTEXT_NOT_FOUND]);
    smContextUpdateError.setError(problem_details);
    smf_n11_inst->send_pdu_session_update_sm_context_response(
        smreq->http_response, smContextUpdateError,
        Pistache::Http::Code::Not_Found);
    return;
  }

  //Step 2. store supi, dnn, nssai  in itti_n11_update_sm_context_request to be processed later on
  supi64_t supi64 = smf_supi_to_u64(scf.get()->supi);
  smreq->req.set_supi(scf.get()->supi);
  smreq->req.set_dnn(scf.get()->dnn);
  smreq->req.set_snssai(scf.get()->nssai);
  smreq->req.set_pdu_session_id(scf.get()->pdu_session_id);

  //Step 2. find the smf context
  std::shared_ptr<smf_context> sc = { };
  if (is_supi_2_smf_context(supi64)) {
    sc = supi_2_smf_context(supi64);
    Logger::smf_app().debug("Retrieve SMF context with SUPI " SUPI_64_FMT "",
                            supi64);
  } else {
    //send PDUSession_SMUpdateContext Response to AMF
    Logger::smf_app().warn(
        "Received PDU Session Update SM Context Request with Supi " SUPI_64_FMT "couldn't retrieve the corresponding SMF context, ignore message!",
        supi64);
    problem_details.setCause(
        pdu_session_application_error_e2str[PDU_SESSION_APPLICATION_ERROR_CONTEXT_NOT_FOUND]);
    smContextUpdateError.setError(problem_details);
    smf_n11_inst->send_pdu_session_update_sm_context_response(
        smreq->http_response, smContextUpdateError,
        Pistache::Http::Code::Not_Found);
    return;
  }

  //get dnn context
  std::shared_ptr<dnn_context> sd = { };

  if (!sc.get()->find_dnn_context(scf.get()->nssai, scf.get()->dnn, sd)) {
    if (nullptr == sd.get()) {
      //Error, DNN context doesn't exist, send PDUSession_SMUpdateContext Response to AMF
      Logger::smf_app().warn(
          "Received PDU Session Update SM Context Request, couldn't retrieve the corresponding SMF context, ignore message!");
      problem_details.setCause(
          pdu_session_application_error_e2str[PDU_SESSION_APPLICATION_ERROR_CONTEXT_NOT_FOUND]);
      smContextUpdateError.setError(problem_details);
      smf_n11_inst->send_pdu_session_update_sm_context_response(
          smreq->http_response, smContextUpdateError,
          Pistache::Http::Code::Not_Found);
      return;
    }
  }

  //Step 3. Verify AMF??

  //Step 4. handle the message in smf_context
  sc.get()->handle_pdu_session_update_sm_context_request(smreq);

}

//------------------------------------------------------------------------------
void smf_app::handle_pdu_session_release_sm_context_request(
    std::shared_ptr<itti_n11_release_sm_context_request> smreq) {
  //TODO:

  //handle PDU Session Release SM Context Request
  Logger::smf_app().info(
      "Handle a PDU Session Release SM Context Request from an AMF");

  //Step 1. get supi, dnn, nssai, pdu_session id from sm_context
  //SM Context ID - uint32_t in our case
  scid_t scid = { };
  try {
    scid = std::stoi(smreq->scid);
  } catch (const std::exception &err) {
    Logger::smf_app().warn(
        "Received a PDU Session Release SM Context Request, couldn't retrieve the corresponding SMF context, ignore message!");

    smf_n11_inst->send_pdu_session_release_sm_context_response(
        smreq->http_response, Pistache::Http::Code::Not_Found);
    return;
  }

  std::shared_ptr<smf_context_ref> scf = { };

  if (is_scid_2_smf_context(scid)) {
    scf = scid_2_smf_context(scid);
  } else {
    Logger::smf_app().warn(
        "Context associated with this id " SCID_FMT " does not exit!", scid);
    smf_n11_inst->send_pdu_session_release_sm_context_response(
        smreq->http_response, Pistache::Http::Code::Not_Found);
    return;
  }

  //Step 2. store supi, dnn, nssai  in itti_n11_update_sm_context_request to be processed later on
  supi64_t supi64 = smf_supi_to_u64(scf.get()->supi);
  smreq->req.set_supi(scf.get()->supi);
  smreq->req.set_dnn(scf.get()->dnn);
  smreq->req.set_snssai(scf.get()->nssai);
  smreq->req.set_pdu_session_id(scf.get()->pdu_session_id);

  //Step 2. find the smf context
  std::shared_ptr<smf_context> sc = { };
  if (is_supi_2_smf_context(supi64)) {
    sc = supi_2_smf_context(supi64);
    Logger::smf_app().debug("Retrieve SMF context with SUPI " SUPI_64_FMT "",
                            supi64);
  } else {
    //send PDUSession_SMReleaseContext Response to AMF
    Logger::smf_app().warn(
        "Received PDU Session Release SM Context Request with Supi " SUPI_64_FMT "couldn't retrieve the corresponding SMF context, ignore message!",
        supi64);

    smf_n11_inst->send_pdu_session_release_sm_context_response(
        smreq->http_response, Pistache::Http::Code::Not_Found);
    return;
  }

  //get dnn context
  std::shared_ptr<dnn_context> sd = { };

  if (!sc.get()->find_dnn_context(scf.get()->nssai, scf.get()->dnn, sd)) {
    if (nullptr == sd.get()) {
      //Error, DNN context doesn't exist, send PDUSession_SMUpdateContext Response to AMF
      Logger::smf_app().warn(
          "Received PDU Session Release SM Context Request, couldn't retrieve the corresponding SMF context, ignore message!");

      smf_n11_inst->send_pdu_session_release_sm_context_response(
          smreq->http_response, Pistache::Http::Code::Not_Found);
      return;
    }
  }

  //Step 3. handle the message in smf_context
  sc.get()->handle_pdu_session_release_sm_context_request(smreq);

}

//------------------------------------------------------------------------------
void smf_app::trigger_pdu_session_modification () {
  //SMF-requested session modification, see section 4.3.3.2@3GPP TS 23.502
  //The SMF may decide to modify PDU Session. This procedure also may be
  //triggered based on locally configured policy or triggered from the (R)AN (see clause 4.2.6 and clause 4.9.1).
  //It may also be triggered if the UP connection is activated (as described in Service Request procedure) and the
  //SMF has marked that the status of one or more QoS Flows are deleted in the 5GC but not synchronized with
  //the UE yet.


  std::shared_ptr<itti_nx_trigger_pdu_session_modification> itti_msg =
      std::make_shared<itti_nx_trigger_pdu_session_modification>(
          TASK_SMF_N11, TASK_SMF_APP);

  //step 1. collect the necessary information
  supi_t supi = { };
  std::string dnn;
  pdu_session_id_t pdu_session_id = { 0 };
  snssai_t snssai = { };

  itti_msg->msg.set_supi(supi);
  itti_msg->msg.set_dnn(dnn);
  itti_msg->msg.set_pdu_session_id(pdu_session_id);
  itti_msg->msg.set_snssai(snssai);

  supi64_t supi64 = smf_supi_to_u64(supi);

  //Step 2. find the smf context
  std::shared_ptr<smf_context> sc = { };

  if (is_supi_2_smf_context(supi64)) {
    sc = supi_2_smf_context(supi64);
    Logger::smf_app().debug("Retrieve SMF context with SUPI " SUPI_64_FMT "",
                            supi64);
  } else {
    Logger::smf_app().debug("SMF context with SUPI " SUPI_64_FMT "does not exist",
                                supi64);
    return;
  }

  // handle the message in smf_context
    sc.get()->handle_pdu_session_modification_network_requested(itti_msg);

}

//------------------------------------------------------------------------------
bool smf_app::is_supi_2_smf_context(const supi64_t &supi) const {
  std::shared_lock lock(m_supi2smf_context);
  return bool { supi2smf_context.count(supi) > 0 };
}

//------------------------------------------------------------------------------
std::shared_ptr<smf_context> smf_app::supi_2_smf_context(
    const supi64_t &supi) const {
  std::shared_lock lock(m_supi2smf_context);
  return supi2smf_context.at(supi);
}

//------------------------------------------------------------------------------
void smf_app::set_supi_2_smf_context(const supi64_t &supi,
                                     std::shared_ptr<smf_context> sc) {
  std::shared_lock lock(m_supi2smf_context);
  supi2smf_context[supi] = sc;
}

//------------------------------------------------------------------------------
void smf_app::set_scid_2_smf_context(const scid_t &id,
                                     std::shared_ptr<smf_context_ref> scf) {
  std::shared_lock lock(m_scid2smf_context);
  scid2smf_context[id] = scf;
}

//------------------------------------------------------------------------------
std::shared_ptr<smf_context_ref> smf_app::scid_2_smf_context(
    const scid_t &scid) const {
  std::shared_lock lock(m_scid2smf_context);
  return scid2smf_context.at(scid);
}

//------------------------------------------------------------------------------
bool smf_app::is_scid_2_smf_context(const scid_t &scid) const {
  std::shared_lock lock(m_scid2smf_context);
  return bool { scid2smf_context.count(scid) > 0 };
}

//------------------------------------------------------------------------------
bool smf_app::use_local_configuration_subscription_data(
    const std::string &dnn_selection_mode) {
  //TODO: should be implemented
  return false;  //get Session Management Subscription from UDM
}

//------------------------------------------------------------------------------
bool smf_app::is_supi_dnn_snssai_subscription_data(supi_t &supi,
                                                   std::string &dnn,
                                                   snssai_t &snssai) {
  //TODO: should be implemented
  return false;  //Session Management Subscription from UDM isn't available
}

//------------------------------------------------------------------------------
bool smf_app::is_create_sm_context_request_valid() {
  //TODO: should be implemented
  return true;

}

//---------------------------------------------------------------------------------------------
void smf_app::convert_string_2_hex(std::string &input_str,
                                   std::string &output_str) {
  Logger::smf_app().debug("Convert string to Hex");
  unsigned char *data = (unsigned char*) malloc(input_str.length() + 1);
  memset(data, 0, input_str.length() + 1);
  memcpy((void*) data, (void*) input_str.c_str(), input_str.length());

  Logger::smf_app().debug("Input: ");
  for (int i = 0; i < input_str.length(); i++) {
    printf("%02x ", data[i]);
  }
  printf("\n");
  char *datahex = (char*) malloc(input_str.length() * 2 + 1);
  memset(datahex, 0, input_str.length() * 2 + 1);

  for (int i = 0; i < input_str.length(); i++)
    sprintf(datahex + i * 2, "%02x", data[i]);

  output_str = reinterpret_cast<char*>(datahex);
  Logger::smf_app().debug("Output: \n %s ", output_str.c_str());

  //free memory
  free_wrapper((void**) &data);
  free_wrapper((void**) &datahex);

}

//---------------------------------------------------------------------------------------------
unsigned char* smf_app::format_string_as_hex(std::string str) {
  unsigned int str_len = str.length();
  char *data = (char*) malloc(str_len + 1);
  memset(data, 0, str_len + 1);
  memcpy((void*) data, (void*) str.c_str(), str_len);

  unsigned char *data_hex = (uint8_t*) malloc(str_len / 2 + 1);
  conv::ascii_to_hex(data_hex, (const char*) data);

  Logger::smf_app().debug("[Format string as Hex] Input string (%d bytes): %s ",
                          str_len, str.c_str());
  Logger::smf_app().debug("Data (formatted):");

  for (int i = 0; i < str_len / 2; i++)
    printf(" %02x ", data_hex[i]);
  printf("\n");

  //free memory
  free_wrapper((void**) &data);

  return data_hex;

}

//---------------------------------------------------------------------------------------------
void smf_app::update_pdu_session_status(const scid_t scid,
                                        const pdu_session_status_e status) {
  Logger::smf_app().info("Update PDU Session Status");

  //get the smf context
  std::shared_ptr<smf_context_ref> scf = { };

  if (is_scid_2_smf_context(scid)) {
    scf = scid_2_smf_context(scid);
  } else {
    Logger::smf_app().warn(
        "Context associated with this id " SCID_FMT " does not exit!", scid);
  }

  supi_t supi = scf.get()->supi;
  supi64_t supi64 = smf_supi_to_u64(supi);
  pdu_session_id_t pdu_session_id = scf.get()->pdu_session_id;

  std::shared_ptr<smf_context> sc = { };

  if (is_supi_2_smf_context(supi64)) {
    sc = supi_2_smf_context(supi64);
    Logger::smf_app().debug("Retrieve SMF context with SUPI " SUPI_64_FMT "",
                            supi64);
  } else {
    Logger::smf_app().error(
        "Could not retrieve the corresponding SMF context with Supi " SUPI_64_FMT "!",
        supi64);
    //TODO:
  }

  //get dnn context
  std::shared_ptr<dnn_context> sd = { };

  if (!sc.get()->find_dnn_context(scf.get()->nssai, scf.get()->dnn, sd)) {
    if (nullptr == sd.get()) {
      //Error, DNN context doesn't exist
      Logger::smf_app().warn(
          "Could not retrieve the corresponding DNN context!");
    }
  }
  //get smd_pdu_session
  std::shared_ptr<smf_pdu_session> sp = { };
  bool find_pdn = sd.get()->find_pdu_session(pdu_session_id, sp);

  if (nullptr == sp.get()) {
    Logger::smf_app().warn(
        "Could not retrieve the corresponding SMF PDU Session context!");
  }
  sp.get()->set_pdu_session_status(status);
  Logger::smf_app().info(
      "Set PDU Session Status to %s",
      pdu_session_status_e2str[static_cast<int>(status)].c_str());
}

//---------------------------------------------------------------------------------------------
void smf_app::update_pdu_session_upCnx_state(const scid_t scid,
                                             const upCnx_state_e state) {
  Logger::smf_app().info("Update UpCnx_State");

  //get the smf context
  std::shared_ptr<smf_context_ref> scf = { };

  if (is_scid_2_smf_context(scid)) {
    scf = scid_2_smf_context(scid);
  } else {
    Logger::smf_app().warn(
        "Context associated with this id " SCID_FMT " does not exit!", scid);
  }

  supi_t supi = scf.get()->supi;
  supi64_t supi64 = smf_supi_to_u64(supi);
  pdu_session_id_t pdu_session_id = scf.get()->pdu_session_id;

  std::shared_ptr<smf_context> sc = { };

  if (is_supi_2_smf_context(supi64)) {
    sc = supi_2_smf_context(supi64);
    Logger::smf_app().debug("Retrieve SMF context with SUPI " SUPI_64_FMT "",
                            supi64);
  } else {
    Logger::smf_app().error(
        "Could not retrieve the corresponding SMF context with Supi " SUPI_64_FMT "!",
        supi64);
    //TODO:
  }

  //get dnn context
  std::shared_ptr<dnn_context> sd = { };

  if (!sc.get()->find_dnn_context(scf.get()->nssai, scf.get()->dnn, sd)) {
    if (nullptr == sd.get()) {
      //Error, DNN context doesn't exist
      Logger::smf_app().warn(
          "Could not retrieve the corresponding DNN context!");
    }
  }
  //get smd_pdu_session
  std::shared_ptr<smf_pdu_session> sp = { };
  bool find_pdn = sd.get()->find_pdu_session(pdu_session_id, sp);

  if (nullptr == sp.get()) {
    Logger::smf_app().warn(
        "Could not retrieve the corresponding SMF PDU Session context!");
  }
  sp.get()->set_upCnx_state(state);
  Logger::smf_app().info("Set PDU Session UpCnxState to %s",
                         upCnx_state_e2str[static_cast<int>(state)].c_str());
}
//---------------------------------------------------------------------------------------------
void smf_app::timer_t3591_timeout(timer_id_t timer_id, uint64_t arg2_user) {
  //TODO: send session modification request again...
}

//---------------------------------------------------------------------------------------------
n2_sm_info_type_e smf_app::n2_sm_info_type_str2e(std::string n2_info_type) {
  std::size_t number_of_types = n2_sm_info_type_e2str.size();
  for (auto i = 0; i < number_of_types; ++i) {
    if (n2_info_type.compare(n2_sm_info_type_e2str[i]) == 0) {
      return static_cast<n2_sm_info_type_e>(i);
    }
  }
}

