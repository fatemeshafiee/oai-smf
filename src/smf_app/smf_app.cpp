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
#include "3gpp_29.500.h"
#include "3gpp_29.502.h"
#include "3gpp_24.007.h"
#include "smf.h"
#include "3gpp_24.501.h"
#include "smf_n1.hpp"
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

  for (int ia = 0; ia < cfg.num_dnn; ia++) {
    if (cfg.dnn[ia].pool_id_iv4 >= 0) {
      int pool_id = cfg.dnn[ia].pool_id_iv4;
      int range =
          be32toh(
              cfg.ue_pool_range_high[pool_id].s_addr) - be32toh(cfg.ue_pool_range_low[pool_id].s_addr);
      paa_dynamic::get_instance().add_pool(cfg.dnn[ia].dnn, pool_id,
                                           cfg.ue_pool_range_low[pool_id],
                                           range);
      //TODO: check with dnn_label
      Logger::smf_app().info("Applied config %s", cfg.dnn[ia].dnn.c_str());
    }
    if (cfg.dnn[ia].pool_id_iv6 >= 0) {
      int pool_id = cfg.dnn[ia].pool_id_iv6;
      paa_dynamic::get_instance().add_pool(cfg.dnn[ia].dnn, pool_id,
                                           cfg.paa_pool6_prefix[pool_id],
                                           cfg.paa_pool6_prefix_len[pool_id]);
      //TODO: check with dnn_label
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

      case N11_SESSION_CREATE_SM_CONTEXT_RESPONSE:
        if (itti_n11_create_sm_context_response *m =
            dynamic_cast<itti_n11_create_sm_context_response*>(msg)) {
          smf_app_inst->handle_itti_msg(std::ref(*m));
        }
        break;

      case N11_SESSION_UPDATE_SM_CONTEXT_RESPONSE:
        if (itti_n11_update_sm_context_response *m =
            dynamic_cast<itti_n11_update_sm_context_response*>(msg)) {
          smf_app_inst->handle_itti_msg(std::ref(*m));
        }
        break;

      case N11_SESSION_RELEASE_SM_CONTEXT_RESPONSE:
        if (itti_n11_release_sm_context_response *m =
            dynamic_cast<itti_n11_release_sm_context_response*>(msg)) {
          smf_app_inst->handle_itti_msg(std::ref(*m));
        }
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
        break;

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
    m_seid2smf_context(),
    m_supi2smf_context(),
    m_scid2smf_context(),
    m_sm_context_create_promises(),
    m_sm_context_update_promises(),
    m_sm_context_release_promises() {
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

  std::time_t time_epoch = std::time(nullptr);
  uint64_t tv_ntp = time_epoch + SECONDS_SINCE_FIRST_EPOCH;

  pfcp_associations::get_instance().add_peer_candidate_node(node_id);
  std::shared_ptr<itti_n4_association_setup_request> n4_asc = std::shared_ptr<
      itti_n4_association_setup_request>(
      new itti_n4_association_setup_request(TASK_SMF_APP, TASK_SMF_N4));

  //n4_asc->trxn_id = smf_n4_inst->generate_trxn_id();
  pfcp::cp_function_features_s cp_function_features;
  cp_function_features = { };
  cp_function_features.load = 1;
  cp_function_features.ovrl = 1;

  pfcp::node_id_t this_node_id = { };
  if (smf_cfg.get_pfcp_node_id(this_node_id) == RETURNok) {
    n4_asc->pfcp_ies.set(this_node_id);
    pfcp::recovery_time_stamp_t r = { .recovery_time_stamp = (uint32_t) tv_ntp };
    n4_asc->pfcp_ies.set(r);

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
        "Received N4 Session Establishment Response seid" TEID_FMT "  pfcp_tx_id %" PRIX64", smf_context not found, discarded!",
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
        "Received N4 Session Modification Response seid" TEID_FMT "  pfcp_tx_id %" PRIX64", smf_context not found, discarded!",
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
        "Received N4 Session Deletion Response seid" TEID_FMT "  pfcp_tx_id %" PRIX64", smf_context not found, discarded!",
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
        "Received N4 Session Report Request seid" TEID_FMT "  pfcp_tx_id %" PRIX64", smf_context not found, discarded!",
        snr->seid, snr->trxn_id);
  }
}

//------------------------------------------------------------------------------
void smf_app::handle_itti_msg(
    itti_n11_n1n2_message_transfer_response_status &m) {
  //see TS29518_Namf_Communication.yaml
  Logger::smf_app().info("Process N1N2MessageTransfer Response");

  switch (m.procedure_type) {
    case session_management_procedures_type_e::PDU_SESSION_ESTABLISHMENT_UE_REQUESTED: {
      //Update PDU Session accordingly
      Logger::smf_app().info("PDU_SESSION_ESTABLISHMENT_UE_REQUESTED");
      pdu_session_status_e status =
          { pdu_session_status_e::PDU_SESSION_INACTIVE };
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
            "Got successful response from AMF (response code %d), set session status to %s",
            m.response_code,
            pdu_session_status_e2str[static_cast<int>(status)].c_str());
      } else {
        //TODO:
        Logger::smf_app().debug("Got response from AMF (response code %d)",
                                m.response_code);
      }
    }
      break;
    case session_management_procedures_type_e::SERVICE_REQUEST_NETWORK_TRIGGERED: {
      Logger::smf_app().debug(
          "Got response from AMF (response code %d) with cause %s",
          m.response_code, m.cause.c_str());
      if ((static_cast<http_response_codes_e>(m.response_code)
          != http_response_codes_e::HTTP_RESPONSE_CODE_OK)
          and (static_cast<http_response_codes_e>(m.response_code)
              != http_response_codes_e::HTTP_RESPONSE_CODE_ACCEPTED)) {
        //send failure indication to UPF
        Logger::smf_app().debug("Send failure indication to UPF");
        //TODO: to be completed
        pfcp::node_id_t up_node_id = { };
        if (not pfcp_associations::get_instance().select_up_node(
            up_node_id, NODE_SELECTION_CRITERIA_MIN_PFCP_SESSIONS)) {
          Logger::smf_app().info("REMOTE_PEER_NOT_RESPONDING");
          return;
        }

        itti_n4_session_failure_indication *itti_n4 =
            new itti_n4_session_failure_indication(TASK_SMF_APP, TASK_SMF_N4);
        itti_n4->seid = m.seid;
        itti_n4->trxn_id = m.trxn_id;
        itti_n4->r_endpoint = endpoint(up_node_id.u1.ipv4_address,
                                       pfcp::default_port);
        std::shared_ptr<itti_n4_session_failure_indication> itti_n4_failure_indication =
            std::shared_ptr<itti_n4_session_failure_indication>(itti_n4);

        Logger::smf_app().info("Sending ITTI message %s to task TASK_SMF_N4",
                               itti_n4->get_msg_name());
        int ret = itti_inst->send_msg(itti_n4_failure_indication);
        if (RETURNok != ret) {
          Logger::smf_app().error(
              "Could not send ITTI message %s to task TASK_SMF_N4",
              itti_n4->get_msg_name());
          return;
        }
      }
    }
      break;
    default: {
      //TODO:

    }
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
void smf_app::handle_itti_msg(itti_n11_create_sm_context_response &m) {
  Logger::smf_app().debug(
      "PDU Session Create SM Context: Set promise with ID %d to ready", m.pid);
  pdu_session_create_sm_context_response sm_context_response = { };
  std::unique_lock lock(m_sm_context_create_promises);
  if (sm_context_create_promises.count(m.pid) > 0 ){
    sm_context_create_promises[m.pid]->set_value(m.res);
    //Remove this promise from list
    sm_context_create_promises.erase(m.pid);
  }
}

//------------------------------------------------------------------------------
void smf_app::handle_itti_msg(itti_n11_update_sm_context_response &m) {
  Logger::smf_app().debug(
      "PDU Session Update SM Context: Set promise with ID %d to ready", m.pid);
  pdu_session_update_sm_context_response sm_context_response = { };
  std::unique_lock lock(m_sm_context_update_promises);
  if (sm_context_update_promises.count(m.pid) > 0 ){
    sm_context_update_promises[m.pid]->set_value(m.res);
    //Remove this promise from list
    sm_context_update_promises.erase(m.pid);
  }
}

//------------------------------------------------------------------------------
void smf_app::handle_itti_msg(itti_n11_release_sm_context_response &m) {
  Logger::smf_app().debug(
      "PDU Session Release SM Context: Set promise with ID %d to ready", m.pid);
  pdu_session_release_sm_context_response sm_context_response = { };
  std::unique_lock lock(m_sm_context_release_promises);
  if (sm_context_release_promises.count(m.pid) > 0 ){
    sm_context_release_promises[m.pid]->set_value(m.res);
    //Remove this promise from list
    sm_context_release_promises.erase(m.pid);
  }
}

//------------------------------------------------------------------------------
void smf_app::handle_pdu_session_create_sm_context_request(
    std::shared_ptr<itti_n11_create_sm_context_request> smreq) {
  Logger::smf_app().info(
      "Handle a PDU Session Create SM Context Request from an AMF (HTTP version %d)",
      smreq->http_version);
  //handle PDU Session Create SM Context Request as specified in section 4.3.2 3GPP TS 23.502
  oai::smf_server::model::SmContextCreateError smContextCreateError = { };
  oai::smf_server::model::ProblemDetails problem_details = { };
  oai::smf_server::model::RefToBinaryData refToBinaryData = { };
  std::string n1_sm_message, n1_sm_message_hex;
  smf_n1 smf_n1_inst = { };
  nas_message_t decoded_nas_msg = { };
  cause_value_5gsm_e cause_n1 = { cause_value_5gsm_e::CAUSE_0_UNKNOWN };
  pdu_session_type_t pdu_session_type = { .pdu_session_type =
      PDU_SESSION_TYPE_E_IPV4 };

  //Step 1. Decode NAS and get the necessary information
  std::string n1_sm_msg = smreq->req.get_n1_sm_message();

  int decoder_rc = smf_n1_inst.decode_n1_sm_container(decoded_nas_msg,
                                                         n1_sm_msg);

  //Failed to decode, send reply to AMF with PDU Session Establishment Reject
  if (decoder_rc != RETURNok) {
    Logger::smf_app().warn("N1 SM container cannot be decoded correctly!");
    problem_details.setCause(
        pdu_session_application_error_e2str[PDU_SESSION_APPLICATION_ERROR_N1_SM_ERROR]);
    smContextCreateError.setError(problem_details);
    refToBinaryData.setContentId(N1_SM_CONTENT_ID);
    smContextCreateError.setN1SmMsg(refToBinaryData);
    if (smf_n1_inst.create_n1_pdu_session_establishment_reject(
          smreq->req, n1_sm_message,
          cause_value_5gsm_e::CAUSE_95_SEMANTICALLY_INCORRECT_MESSAGE)) {
      smf_app_inst->convert_string_2_hex(n1_sm_message, n1_sm_message_hex);
      //trigger to send reply to AMF
      trigger_http_response(http_status_code_e::HTTP_STATUS_CODE_403_FORBIDDEN,
                            smContextCreateError, n1_sm_message_hex,
                            smreq->pid);
    } else {
      //trigger to send reply to AMF
      trigger_http_response(
          http_status_code_e::HTTP_STATUS_CODE_500_INTERNAL_SERVER_ERROR,
          smreq->pid, N11_SESSION_CREATE_SM_CONTEXT_RESPONSE);
    }
    return;
  }

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
    Logger::smf_app().debug(
        "PDU Session Type %d",
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
    if (smf_n1_inst.create_n1_pdu_session_establishment_reject(smreq->req,
                                                 n1_sm_message, cause_n1)) {
      smf_app_inst->convert_string_2_hex(n1_sm_message, n1_sm_message_hex);
      //trigger to send reply to AMF
      trigger_http_response(http_status_code_e::HTTP_STATUS_CODE_403_FORBIDDEN,
                            smContextCreateError, n1_sm_message_hex,
                            smreq->pid);
    } else {
      trigger_http_response(
          http_status_code_e::HTTP_STATUS_CODE_500_INTERNAL_SERVER_ERROR,
          smreq->pid, N11_SESSION_CREATE_SM_CONTEXT_RESPONSE);
    }
    return;
  }

  //TODO: SSCMode
  //TODO: store UE 5GSM Capability
  //TODO: MaximumNumberOfSupportedPacketFilters
  //TODO: AlwaysonPDUSessionRequested
  //TODO: SMPDUDNRequestContainer
  //TODO: ExtendedProtocolConfigurationOptions

  //Get necessary information
  supi_t supi = smreq->req.get_supi();
  std::string supi_prefix = smreq->req.get_supi_prefix();
  supi64_t supi64 = smf_supi_to_u64(supi);
  std::string dnn = smreq->req.get_dnn();
  snssai_t snssai = smreq->req.get_snssai();
  uint8_t message_type = decoded_nas_msg.plain.sm.header.message_type;
  std::string request_type = smreq->req.get_request_type();
  Logger::smf_app().info(
      "Handle a PDU Session Create SM Context Request message from AMF, SUPI " SUPI_64_FMT ", DNN %s, SNSSAI SST %d, SD %s",
      supi64, dnn.c_str(), snssai.sST, snssai.sD.c_str());

  //If no DNN information from UE, set to default value
  if (dnn.length() == 0) {
    dnn == smf_cfg.get_default_dnn();
  }

  //Step 2. Verify Procedure transaction id, pdu session id, message type, request type, etc.
  //check pti
  if ((pti.procedure_transaction_id == PROCEDURE_TRANSACTION_IDENTITY_UNASSIGNED )
      || (pti.procedure_transaction_id > PROCEDURE_TRANSACTION_IDENTITY_LAST )) {
    Logger::smf_app().warn("Invalid PTI value (pti = %d)",
                           pti.procedure_transaction_id);
    problem_details.setCause(
        pdu_session_application_error_e2str[PDU_SESSION_APPLICATION_ERROR_N1_SM_ERROR]);
    smContextCreateError.setError(problem_details);
    refToBinaryData.setContentId(N1_SM_CONTENT_ID);
    smContextCreateError.setN1SmMsg(refToBinaryData);
    //PDU Session Establishment Reject including cause "#81 Invalid PTI value" (section 7.3.1 @3GPP TS 24.501)
    if (smf_n1_inst.create_n1_pdu_session_establishment_reject(
          smreq->req, n1_sm_message,
          cause_value_5gsm_e::CAUSE_81_INVALID_PTI_VALUE)) {
      smf_app_inst->convert_string_2_hex(n1_sm_message, n1_sm_message_hex);
      //trigger to send reply to AMF
      trigger_http_response(http_status_code_e::HTTP_STATUS_CODE_403_FORBIDDEN,
                            smContextCreateError, n1_sm_message_hex,
                            smreq->pid);
    } else {
      trigger_http_response(
          http_status_code_e::HTTP_STATUS_CODE_500_INTERNAL_SERVER_ERROR,
          smreq->pid, N11_SESSION_CREATE_SM_CONTEXT_RESPONSE);
    }
    return;
  }
  smreq->req.set_pti(pti);

  //check pdu session id
  if ((pdu_session_id == PDU_SESSION_IDENTITY_UNASSIGNED )
      || (pdu_session_id > PDU_SESSION_IDENTITY_LAST )) {
    Logger::smf_app().warn("Invalid PDU Session ID value (%d)", pdu_session_id);
    //section 7.3.2@3GPP TS 24.501; NAS N1 SM message: ignore the message
    //trigger to send reply to AMF
    trigger_http_response(
        http_status_code_e::HTTP_STATUS_CODE_406_NOT_ACCEPTABLE, smreq->pid,
        N11_SESSION_CREATE_SM_CONTEXT_RESPONSE);
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
    if (smf_n1_inst.create_n1_pdu_session_establishment_reject(
          smreq->req,
          n1_sm_message,
          cause_value_5gsm_e::CAUSE_98_MESSAGE_TYPE_NOT_COMPATIBLE_WITH_PROTOCOL_STATE)) {
      smf_app_inst->convert_string_2_hex(n1_sm_message, n1_sm_message_hex);
      //trigger to send reply to AMF
      trigger_http_response(http_status_code_e::HTTP_STATUS_CODE_403_FORBIDDEN,
                            smContextCreateError, n1_sm_message_hex,
                            smreq->pid);
    } else {
      trigger_http_response(
          http_status_code_e::HTTP_STATUS_CODE_500_INTERNAL_SERVER_ERROR,
          smreq->pid, N11_SESSION_CREATE_SM_CONTEXT_RESPONSE);
    }
    return;
  }

  //check request type
  if (request_type.compare("INITIAL_REQUEST") != 0) {
    Logger::smf_app().warn("Invalid request type (request type = %s)",
                           request_type.c_str());
    //"Existing PDU Session", AMF should use PDUSession_UpdateSMContext instead (see step 3, section 4.3.2.2.1 @ 3GPP TS 23.502 v16.0.0)
    //ignore the message
    return;
  }

  //TODO: For the moment, not support PDU session authentication and authorization by the external DN

  //Step 3. check if the DNN requested is valid
  if (not smf_cfg.is_dotted_dnn_handled(dnn, pdu_session_type)) {
    // Not a valid request...
    Logger::smf_app().warn(
        "Received a PDU Session Create SM Context Request: unknown requested DNN %s, ignore message!",
        dnn.c_str());
    problem_details.setCause(
        pdu_session_application_error_e2str[PDU_SESSION_APPLICATION_ERROR_DNN_DENIED]);
    smContextCreateError.setError(problem_details);
    refToBinaryData.setContentId(N1_SM_CONTENT_ID);
    smContextCreateError.setN1SmMsg(refToBinaryData);
    //PDU Session Establishment Reject, 24.501 cause "#27 Missing or unknown DNN"
    if (smf_n1_inst.create_n1_pdu_session_establishment_reject(
          smreq->req, n1_sm_message,
          cause_value_5gsm_e::CAUSE_27_MISSING_OR_UNKNOWN_DNN)) {
      smf_app_inst->convert_string_2_hex(n1_sm_message, n1_sm_message_hex);
      //trigger to send reply to AMF
      trigger_http_response(http_status_code_e::HTTP_STATUS_CODE_403_FORBIDDEN,
                            smContextCreateError, n1_sm_message_hex,
                            smreq->pid);
    } else {
      trigger_http_response(
          http_status_code_e::HTTP_STATUS_CODE_500_INTERNAL_SERVER_ERROR,
          smreq->pid, N11_SESSION_CREATE_SM_CONTEXT_RESPONSE);
    }
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
    sc.get()->set_supi_prefix(supi_prefix);
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

  //Step 6. if colliding with an existing SM context (session is already existed and request type is INITIAL_REQUEST)
  //Delete the local context (including and any associated resources in the UPF and PCF) and create a new one
  if (is_scid_2_smf_context(supi64, dnn, snssai, pdu_session_id) && (request_type.compare("INITIAL_REQUEST") == 0)) {
    //remove smf_pdu_session (including all flows associated to this session)
    sd.get()->remove_pdu_session(pdu_session_id);
    Logger::smf_app().warn(
        "PDU Session already existed (SUPI " SUPI_64_FMT ", DNN %s, NSSAI (sst %d, sd %s), PDU Session ID %d)",
        supi64, dnn.c_str(), snssai.sST, snssai.sD.c_str(), pdu_session_id);
  }

  //Step 7. retrieve Session Management Subscription data from UDM if not available (step 4, section 4.3.2 3GPP TS 23.502)
  std::string dnn_selection_mode = smreq->req.get_dnn_selection_mode();
  //if the Session Management Subscription data is not available, get from configuration file or UDM
  if (not sc.get()->is_dnn_snssai_subscription_data(dnn, snssai)) {
    Logger::smf_app().debug(
        "The Session Management Subscription data is not available");

    session_management_subscription *s = new session_management_subscription(
        snssai);
    std::shared_ptr<session_management_subscription> subscription =
        std::shared_ptr<session_management_subscription>(s);

    if (not use_local_configuration_subscription_data(dnn_selection_mode)) {
      Logger::smf_app().debug(
          "Retrieve Session Management Subscription data from the UDM");
      if (smf_n10_inst->get_sm_data(supi64, dnn, snssai, subscription)) {
        //update dnn_context with subscription info
        sc.get()->insert_dnn_subscription(snssai, subscription);
      } else {
        // Cannot retrieve information from UDM, reject PDU session establishment
        Logger::smf_app().warn(
            "Received a PDU Session Create SM Context Request, couldn't retrieve the Session Management Subscription from UDM, ignore message!");
        problem_details.setCause(
            pdu_session_application_error_e2str[PDU_SESSION_APPLICATION_ERROR_SUBSCRIPTION_DENIED]);
        smContextCreateError.setError(problem_details);
        refToBinaryData.setContentId(N1_SM_CONTENT_ID);
        smContextCreateError.setN1SmMsg(refToBinaryData);
        //PDU Session Establishment Reject, with cause "29 User authentication or authorization failed"
        if (smf_n1_inst.create_n1_pdu_session_establishment_reject(
            smreq->req,
            n1_sm_message,
            cause_value_5gsm_e::CAUSE_29_USER_AUTHENTICATION_OR_AUTHORIZATION_FAILED)) {
        smf_app_inst->convert_string_2_hex(n1_sm_message, n1_sm_message_hex);
          //trigger to send reply to AMF
          trigger_http_response(
              http_status_code_e::HTTP_STATUS_CODE_403_FORBIDDEN,
              smContextCreateError, n1_sm_message_hex, smreq->pid);
        } else {
          trigger_http_response(
              http_status_code_e::HTTP_STATUS_CODE_500_INTERNAL_SERVER_ERROR,
              smreq->pid, N11_SESSION_CREATE_SM_CONTEXT_RESPONSE);
        }
        return;
      }
    } else {
      //use local configuration
      Logger::smf_app().debug(
          "Retrieve Session Management Subscription data from local configuration");
      if (get_session_management_subscription_data(supi64, dnn, snssai,
                                                   subscription)) {
        //update dnn_context with subscription info
        sc.get()->insert_dnn_subscription(snssai, subscription);
      }
    }
  }

  // Step 8. generate a SMF context Id and store the corresponding information in a map (SM_Context_ID, (supi, dnn, nssai, pdu_session_id))
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

  Logger::smf_app().debug("Generated a SMF Context ID " SCID_FMT " ", scid);

  //Step 9. Let the context handle the message
  sc.get()->handle_pdu_session_create_sm_context_request(smreq);

}

//------------------------------------------------------------------------------
void smf_app::handle_pdu_session_update_sm_context_request(
    std::shared_ptr<itti_n11_update_sm_context_request> smreq) {

  //handle PDU Session Update SM Context Request as specified in section 4.3.2 3GPP TS 23.502
  Logger::smf_app().info(
      "Handle a PDU Session Update SM Context Request from an AMF (HTTP version %d)",
      smreq->http_version);
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
    //trigger to send reply to AMF
    trigger_http_response(http_status_code_e::HTTP_STATUS_CODE_404_NOT_FOUND,
                          smContextUpdateError, smreq->pid);
    return;
  }

  std::shared_ptr<smf_context_ref> scf = { };

  if (is_scid_2_smf_context(scid)) {
    scf = scid_2_smf_context(scid);
  } else {
    Logger::smf_app().warn(
        "SM Context associated with this id " SCID_FMT " does not exit!", scid);
    problem_details.setCause(
        pdu_session_application_error_e2str[PDU_SESSION_APPLICATION_ERROR_CONTEXT_NOT_FOUND]);
    smContextUpdateError.setError(problem_details);
    //trigger to send reply to AMF
    trigger_http_response(http_status_code_e::HTTP_STATUS_CODE_404_NOT_FOUND,
                          smContextUpdateError, smreq->pid);
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
    //trigger to send reply to AMF
    trigger_http_response(http_status_code_e::HTTP_STATUS_CODE_404_NOT_FOUND,
                          smContextUpdateError, smreq->pid);
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
      //trigger to send reply to AMF
      trigger_http_response(http_status_code_e::HTTP_STATUS_CODE_404_NOT_FOUND,
                            smContextUpdateError, smreq->pid);
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
    //trigger to send reply to AMF
    trigger_http_response(http_status_code_e::HTTP_STATUS_CODE_404_NOT_FOUND,
                          smreq->pid, N11_SESSION_RELEASE_SM_CONTEXT_RESPONSE);
    return;
  }

  std::shared_ptr<smf_context_ref> scf = { };

  if (is_scid_2_smf_context(scid)) {
    scf = scid_2_smf_context(scid);
  } else {
    Logger::smf_app().warn(
        "Context associated with this id " SCID_FMT " does not exit!", scid);
    //trigger to send reply to AMF
    trigger_http_response(http_status_code_e::HTTP_STATUS_CODE_404_NOT_FOUND,
                          smreq->pid, N11_SESSION_RELEASE_SM_CONTEXT_RESPONSE);
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
    //trigger to send reply to AMF
    trigger_http_response(http_status_code_e::HTTP_STATUS_CODE_404_NOT_FOUND,
                          smreq->pid, N11_SESSION_RELEASE_SM_CONTEXT_RESPONSE);
    return;
  }

  //get dnn context
  std::shared_ptr<dnn_context> sd = { };

  if (!sc.get()->find_dnn_context(scf.get()->nssai, scf.get()->dnn, sd)) {
    if (nullptr == sd.get()) {
      //Error, DNN context doesn't exist, send PDUSession_SMUpdateContext Response to AMF
      Logger::smf_app().warn(
          "Received PDU Session Release SM Context Request, couldn't retrieve the corresponding SMF context, ignore message!");
      //trigger to send reply to AMF
      trigger_http_response(http_status_code_e::HTTP_STATUS_CODE_404_NOT_FOUND,
                            smreq->pid,
                            N11_SESSION_RELEASE_SM_CONTEXT_RESPONSE);
      return;
    }
  }

  //Step 3. handle the message in smf_context
  sc.get()->handle_pdu_session_release_sm_context_request(smreq);
}

//------------------------------------------------------------------------------
void smf_app::trigger_pdu_session_modification(
    const supi_t &supi, const std::string &dnn,
    const pdu_session_id_t pdu_session_id, const snssai_t &snssai,
    const pfcp::qfi_t &qfi, const uint8_t &http_version) {
  //SMF-requested session modification, see section 4.3.3.2@3GPP TS 23.502
  //The SMF may decide to modify PDU Session. This procedure also may be
  //triggered based on locally configured policy or triggered from the (R)AN (see clause 4.2.6 and clause 4.9.1).
  //It may also be triggered if the UP connection is activated (as described in Service Request procedure) and the
  //SMF has marked that the status of one or more QoS Flows are deleted in the 5GC but not synchronized with
  //the UE yet.

  std::shared_ptr<itti_nx_trigger_pdu_session_modification> itti_msg =
      std::make_shared<itti_nx_trigger_pdu_session_modification>(TASK_SMF_APP,
                                                                 TASK_SMF_N11);
  itti_msg->http_version = http_version;

  //step 1. collect the necessary information
  /*
   //For testing purpose
   supi_t supi = { };
   std::string dnn("default");
   pdu_session_id_t pdu_session_id = { 1 };
   snssai_t snssai = { };
   pfcp::qfi_t qfi = { };
   qfi.qfi = 7;
   std::string supi_str("200000000000001");
   smf_string_to_supi(&supi, supi_str.c_str());
   snssai.sST = 222;
   snssai.sD = "0000D4";
   */

  itti_msg->msg.set_supi(supi);
  itti_msg->msg.set_dnn(dnn);
  itti_msg->msg.set_pdu_session_id(pdu_session_id);
  itti_msg->msg.set_snssai(snssai);
  itti_msg->msg.add_qfi(qfi);
  supi64_t supi64 = smf_supi_to_u64(supi);

  //Step 2. find the smf context
  std::shared_ptr<smf_context> sc = { };

  if (is_supi_2_smf_context(supi64)) {
    sc = supi_2_smf_context(supi64);
    Logger::smf_app().debug("Retrieve SMF context with SUPI " SUPI_64_FMT "",
                            supi64);
  } else {
    Logger::smf_app().debug(
        "SMF context with SUPI " SUPI_64_FMT "does not exist", supi64);
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
  std::unique_lock lock(m_supi2smf_context);
  supi2smf_context[supi] = sc;
}

//------------------------------------------------------------------------------
void smf_app::set_scid_2_smf_context(const scid_t &id,
                                     std::shared_ptr<smf_context_ref> scf) {
  std::unique_lock lock(m_scid2smf_context);
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
bool smf_app::is_scid_2_smf_context(const supi64_t &supi,
                                    const std::string &dnn,
                                    const snssai_t &snssai,
                                    const pdu_session_id_t &pid) const {
  std::shared_lock lock(m_scid2smf_context);
  for (auto it : scid2smf_context) {
    supi64_t supi64 = smf_supi_to_u64(it.second->supi);
    if ((supi64 == supi) and (it.second->dnn.compare(dnn) == 0)
        and (it.second->nssai == snssai) and (it.second->pdu_session_id == pid))
      return true;
  }
  return false;
}

//------------------------------------------------------------------------------
bool smf_app::scid_2_smf_context(const scid_t &scid,
                                 std::shared_ptr<smf_context_ref> &scf) const {
  std::shared_lock lock(m_scid2smf_context);
  if (scid2smf_context.count(scid) > 0) {
    scf = scid2smf_context.at(scid);
    return true;
  }
  return false;
}

//------------------------------------------------------------------------------
bool smf_app::use_local_configuration_subscription_data(
    const std::string &dnn_selection_mode) {
  //TODO: should be implemented
  return smf_cfg.local_configuration;
}

//------------------------------------------------------------------------------
bool smf_app::is_supi_dnn_snssai_subscription_data(
    const supi_t &supi, const std::string &dnn, const snssai_t &snssai) const {
  //TODO: should be implemented
  return false;  //Session Management Subscription from UDM isn't available
}

//------------------------------------------------------------------------------
bool smf_app::is_create_sm_context_request_valid() const {
  //TODO: should be implemented
  return true;
}

//---------------------------------------------------------------------------------------------
void smf_app::convert_string_2_hex(const std::string &input_str,
                                   std::string &output_str) {
  Logger::smf_app().debug("Convert string to Hex");
  unsigned char *data = (unsigned char*) malloc(input_str.length() + 1);
  memset(data, 0, input_str.length() + 1);
  memcpy((void*) data, (void*) input_str.c_str(), input_str.length());

#if DEBUG_IS_ON
  Logger::smf_app().debug("Input: ");
  for (int i = 0; i < input_str.length(); i++) {
    printf("%02x ", data[i]);
  }
  printf("\n");
#endif
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
unsigned char* smf_app::format_string_as_hex(const std::string &str) {
  unsigned int str_len = str.length();
  char *data = (char*) malloc(str_len + 1);
  memset(data, 0, str_len + 1);
  memcpy((void*) data, (void*) str.c_str(), str_len);

  unsigned char *data_hex = (uint8_t*) malloc(str_len / 2 + 1);
  conv::ascii_to_hex(data_hex, (const char*) data);

  Logger::smf_app().debug("[Format string as Hex] Input string (%d bytes): %s ",
                          str_len, str.c_str());
  Logger::smf_app().debug("Data (formatted):");
#if DEBUG_IS_ON
  for (int i = 0; i < str_len / 2; i++)
    printf(" %02x ", data_hex[i]);
  printf("\n");
#endif
  //free memory
  free_wrapper((void**) &data);

  return data_hex;
}

//---------------------------------------------------------------------------------------------
void smf_app::update_pdu_session_status(const scid_t &scid,
                                        const pdu_session_status_e &status) {
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
void smf_app::update_pdu_session_upCnx_state(const scid_t &scid,
                                             const upCnx_state_e &state) {
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
n2_sm_info_type_e smf_app::n2_sm_info_type_str2e(
    const std::string &n2_info_type) const {
  std::size_t number_of_types = n2_sm_info_type_e2str.size();
  for (auto i = 0; i < number_of_types; ++i) {
    if (n2_info_type.compare(n2_sm_info_type_e2str[i]) == 0) {
      return static_cast<n2_sm_info_type_e>(i);
    }
  }
}

//---------------------------------------------------------------------------------------------
bool smf_app::get_session_management_subscription_data(
    const supi64_t &supi, const std::string &dnn, const snssai_t &snssai,
    std::shared_ptr<session_management_subscription> subscription) {

  Logger::smf_app().debug(
      "Get Session Management Subscription from configuration file");

  for (int i = 0; i < smf_cfg.num_session_management_subscription; i++) {
    if ((0 == dnn.compare(smf_cfg.session_management_subscription[i].dnn))
        and (snssai.sST
            == smf_cfg.session_management_subscription[i].single_nssai.sST)) {

      std::shared_ptr<dnn_configuration_t> dnn_configuration = std::make_shared<
          dnn_configuration_t>();

      //PDU Session Type
      pdu_session_type_t pdu_session_type(
          pdu_session_type_e::PDU_SESSION_TYPE_E_IPV4);
      Logger::smf_app().debug(
          "Default session type %s",
          smf_cfg.session_management_subscription[i].session_type.c_str());
      if (smf_cfg.session_management_subscription[i].session_type.compare(
          "IPV4") == 0) {
        pdu_session_type.pdu_session_type =
            pdu_session_type_e::PDU_SESSION_TYPE_E_IPV4;
      } else if (smf_cfg.session_management_subscription[i].session_type.compare(
          "IPV6") == 0) {
        pdu_session_type.pdu_session_type =
            pdu_session_type_e::PDU_SESSION_TYPE_E_IPV6;
      } else if (smf_cfg.session_management_subscription[i].session_type.compare(
          "IPV4V6") == 0) {
        pdu_session_type.pdu_session_type =
            pdu_session_type_e::PDU_SESSION_TYPE_E_IPV4V6;
      }
      dnn_configuration->pdu_session_types.default_session_type =
          pdu_session_type;

      //Ssc_Mode
      dnn_configuration->ssc_modes.default_ssc_mode.ssc_mode = smf_cfg
          .session_management_subscription[i].ssc_mode;

      //5gQosProfile
      dnn_configuration->_5g_qos_profile._5qi = smf_cfg
          .session_management_subscription[i].default_qos._5qi;
      dnn_configuration->_5g_qos_profile.arp.priority_level = smf_cfg
          .session_management_subscription[i].default_qos.priority_level;
      dnn_configuration->_5g_qos_profile.arp.preempt_cap = smf_cfg
          .session_management_subscription[i].default_qos.arp.preempt_cap;
      dnn_configuration->_5g_qos_profile.arp.preempt_vuln = smf_cfg
          .session_management_subscription[i].default_qos.arp.preempt_vuln;
      dnn_configuration->_5g_qos_profile.priority_level = 1;  //TODO: hardcoded

      //session_ambr
      dnn_configuration->session_ambr.uplink = smf_cfg
          .session_management_subscription[i].session_ambr.uplink;
      dnn_configuration->session_ambr.downlink = smf_cfg
          .session_management_subscription[i].session_ambr.downlink;
      Logger::smf_app().debug("Session AMBR Uplink %s, Downlink %s",
                              dnn_configuration->session_ambr.uplink.c_str(),
                              dnn_configuration->session_ambr.downlink.c_str());

      subscription->insert_dnn_configuration(dnn, dnn_configuration);
      return true;
    }
  }
  return false;
}

//---------------------------------------------------------------------------------------------
void smf_app::add_promise(
    uint32_t id,
    boost::shared_ptr<boost::promise<pdu_session_create_sm_context_response> > &p) {
  std::unique_lock lock(m_sm_context_create_promises);
  sm_context_create_promises.emplace(id, p);
}

//---------------------------------------------------------------------------------------------
void smf_app::add_promise(
    uint32_t id,
    boost::shared_ptr<boost::promise<pdu_session_update_sm_context_response> > &p) {
  std::unique_lock lock(m_sm_context_update_promises);
  sm_context_update_promises.emplace(id, p);
}

//---------------------------------------------------------------------------------------------
void smf_app::add_promise(
    uint32_t id,
    boost::shared_ptr<boost::promise<pdu_session_release_sm_context_response> > &p) {
  std::unique_lock lock(m_sm_context_release_promises);
  sm_context_release_promises.emplace(id, p);
}

//---------------------------------------------------------------------------------------------
void smf_app::trigger_http_response(
    const uint32_t &http_code,
    const oai::smf_server::model::SmContextCreateError &smContextCreateError,
    const std::string &n1_sm_msg, uint32_t &promise_id) {
  Logger::smf_app().debug(
      "Send ITTI msg to SMF APP to trigger the response of Server");
  std::shared_ptr<itti_n11_create_sm_context_response> itti_msg =
      std::make_shared<itti_n11_create_sm_context_response>(TASK_SMF_N11,
                                                            TASK_SMF_APP,
                                                            promise_id);
  pdu_session_create_sm_context_response sm_context_response = { };
  nlohmann::json json_data = { };
  to_json(json_data, smContextCreateError);
  sm_context_response.set_json_data(json_data);
  sm_context_response.set_json_format("application/problem+json");
  sm_context_response.set_n1_sm_message(n1_sm_msg);
  sm_context_response.set_http_code(http_code);
  itti_msg->res = sm_context_response;
  int ret = itti_inst->send_msg(itti_msg);
  if (RETURNok != ret) {
    Logger::smf_app().error(
        "Could not send ITTI message %s to task TASK_SMF_APP",
        itti_msg->get_msg_name());
  }
}

//---------------------------------------------------------------------------------------------
void smf_app::trigger_http_response(
    const uint32_t &http_code,
    const oai::smf_server::model::SmContextUpdateError &smContextUpdateError,
    uint32_t &promise_id) {
  Logger::smf_app().debug(
      "Send ITTI msg to SMF APP to trigger the response of API Server");

  std::shared_ptr<itti_n11_update_sm_context_response> itti_msg =
      std::make_shared<itti_n11_update_sm_context_response>(TASK_SMF_N11,
                                                            TASK_SMF_APP,
                                                            promise_id);
  pdu_session_update_sm_context_response sm_context_response = { };
  nlohmann::json json_data = { };
  to_json(json_data, smContextUpdateError);
  sm_context_response.set_json_data(json_data);
  sm_context_response.set_json_format("application/problem+json");
  sm_context_response.set_http_code(http_code);
  itti_msg->res = sm_context_response;
  int ret = itti_inst->send_msg(itti_msg);
  if (RETURNok != ret) {
    Logger::smf_app().error(
        "Could not send ITTI message %s to task TASK_SMF_APP",
        itti_msg->get_msg_name());
  }

}

//---------------------------------------------------------------------------------------------
void smf_app::trigger_http_response(
    const uint32_t &http_code,
    const oai::smf_server::model::SmContextUpdateError &smContextUpdateError,
    const std::string &n1_sm_msg, uint32_t &promise_id) {

  Logger::smf_app().debug(
      "Send ITTI msg to SMF APP to trigger the response of HTTP Server");

  std::shared_ptr<itti_n11_update_sm_context_response> itti_msg =
      std::make_shared<itti_n11_update_sm_context_response>(TASK_SMF_N11,
                                                            TASK_SMF_APP,
                                                            promise_id);
  pdu_session_update_sm_context_response sm_context_response = { };
  nlohmann::json json_data = { };
  to_json(json_data, smContextUpdateError);
  sm_context_response.set_json_data(json_data);
  sm_context_response.set_json_format("application/problem+json");
  sm_context_response.set_n1_sm_message(n1_sm_msg);
  sm_context_response.set_http_code(http_code);
  itti_msg->res = sm_context_response;
  int ret = itti_inst->send_msg(itti_msg);
  if (RETURNok != ret) {
    Logger::smf_app().error(
        "Could not send ITTI message %s to task TASK_SMF_APP",
        itti_msg->get_msg_name());
  }

}

//---------------------------------------------------------------------------------------------
void smf_app::trigger_http_response(const uint32_t &http_code,
                                    uint32_t &promise_id, uint8_t msg_type) {

  Logger::smf_app().debug(
      "Send ITTI msg to SMF APP to trigger the response of HTTP Server");
  switch (msg_type) {
    case N11_SESSION_RELEASE_SM_CONTEXT_RESPONSE: {
      std::shared_ptr<itti_n11_release_sm_context_response> itti_msg =
          std::make_shared<itti_n11_release_sm_context_response>(TASK_SMF_N11,
                                                                 TASK_SMF_APP,
                                                                 promise_id);
      pdu_session_release_sm_context_response sm_context_response = { };
      sm_context_response.set_http_code(http_code);
      itti_msg->res = sm_context_response;
      int ret = itti_inst->send_msg(itti_msg);
      if (RETURNok != ret) {
        Logger::smf_app().error(
            "Could not send ITTI message %s to task TASK_SMF_APP",
            itti_msg->get_msg_name());
      }
    }
      break;

    case N11_SESSION_CREATE_SM_CONTEXT_RESPONSE: {

      std::shared_ptr<itti_n11_create_sm_context_response> itti_msg =
          std::make_shared<itti_n11_create_sm_context_response>(TASK_SMF_N11,
                                                                TASK_SMF_APP,
                                                                promise_id);
      pdu_session_create_sm_context_response sm_context_response = { };
      sm_context_response.set_http_code(http_code);
      itti_msg->res = sm_context_response;
      int ret = itti_inst->send_msg(itti_msg);
      if (RETURNok != ret) {
        Logger::smf_app().error(
            "Could not send ITTI message %s to task TASK_SMF_APP",
            itti_msg->get_msg_name());
      }
    }
      break;

    case N11_SESSION_UPDATE_SM_CONTEXT_RESPONSE: {

      std::shared_ptr<itti_n11_update_sm_context_response> itti_msg =
          std::make_shared<itti_n11_update_sm_context_response>(TASK_SMF_N11,
                                                                TASK_SMF_APP,
                                                                promise_id);
      pdu_session_update_sm_context_response sm_context_response = { };
      sm_context_response.set_http_code(http_code);
      itti_msg->res = sm_context_response;
      int ret = itti_inst->send_msg(itti_msg);
      if (RETURNok != ret) {
        Logger::smf_app().error(
            "Could not send ITTI message %s to task TASK_SMF_APP",
            itti_msg->get_msg_name());
      }
    }
      break;

    default: {
      //TODO:
    }
  }

}
