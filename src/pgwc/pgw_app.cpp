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

/*! \file pgw_app.cpp
   \brief
   \author  Lionel GAUTHIER
   \date 2018
   \email: lionel.gauthier@eurecom.fr
*/
#include "pgw_app.hpp"
#include "async_shell_cmd.hpp"
#include "common_defs.h"
#include "conversions.hpp"
#include "itti.hpp"
#include "logger.hpp"
#include "smf_paa_dynamic.hpp"
#include "smf_n4.hpp"
#include "smf_n10.hpp"
#include "smf_n11.hpp"
#include "string.hpp"
#include "SmContextCreateError.h"
#include "3gpp_29.502.h"
#include "3gpp_24.007.h"
#include "smf.h"
#include "3gpp_24.501.h"

#include <stdexcept>
#include <iostream>
#include <cstdlib>

using namespace pgwc;

#define SYSTEM_CMD_MAX_STR_SIZE 512
extern util::async_shell_cmd *async_shell_cmd_inst;
extern pgw_app *pgw_app_inst;
extern smf_config smf_cfg;
smf_n4 *smf_n4_inst = nullptr;
smf_n10 *smf_n10_inst = nullptr;
smf_n11 *smf_n11_inst = nullptr;
extern itti_mw *itti_inst;

void pgw_app_task (void*);

//------------------------------------------------------------------------------
int pgw_app::apply_config (const smf_config& cfg)
{
  Logger::pgwc_app().info("Apply config...");

  for (int ia = 0; ia < cfg.num_apn; ia++) {
    if (cfg.apn[ia].pool_id_iv4 >= 0) {
      int pool_id = cfg.apn[ia].pool_id_iv4;
      int range = be32toh(cfg.ue_pool_range_high[pool_id].s_addr) - be32toh(cfg.ue_pool_range_low[pool_id].s_addr) ;
      paa_dynamic::get_instance().add_pool(cfg.apn[ia].apn, pool_id, cfg.ue_pool_range_low[pool_id], range);
      //TODO: check with apn_label
      Logger::pgwc_app().info("Applied config %s", cfg.apn[ia].apn.c_str());
    }
    if (cfg.apn[ia].pool_id_iv6 >= 0) {
      int pool_id = cfg.apn[ia].pool_id_iv6;
      paa_dynamic::get_instance().add_pool(cfg.apn[ia].apn, pool_id, cfg.paa_pool6_prefix[pool_id], cfg.paa_pool6_prefix_len[pool_id]);
      //TODO: check with apn_label
    }
  }

  Logger::pgwc_app().info("Applied config");
  return RETURNok;
}

//------------------------------------------------------------------------------
teid_t pgw_app::generate_s5s8_cp_teid() {
  std::unique_lock<std::mutex> ls(m_s5s8_cp_teid_generator);
  teid_t teid =  ++teid_s5s8_cp_generator;
  while ((is_s5s8c_teid_exist(teid)) || (teid == UNASSIGNED_TEID)) {
    teid =  ++teid_s5s8_cp_generator;
  }
  s5s8cplteid.insert(teid);
  ls.unlock();
  return teid;
}

//------------------------------------------------------------------------------
bool pgw_app::is_s5s8c_teid_exist(const teid_t& teid_s5s8_cp) const
{
  return bool{s5s8cplteid.count(teid_s5s8_cp) > 0};
}

//------------------------------------------------------------------------------
void pgw_app::free_s5s8c_teid(const teid_t& teid_s5s8_cp)
{
  s5s8cplteid.erase (teid_s5s8_cp); // can return value of erase
}

//------------------------------------------------------------------------------
bool pgw_app::is_imsi64_2_pgw_context(const imsi64_t& imsi64) const
{
  std::shared_lock lock(m_imsi2pgw_context);
  return bool{imsi2pgw_context.count(imsi64) > 0};
}
//------------------------------------------------------------------------------
std::shared_ptr<pgw_context> pgw_app::imsi64_2_pgw_context(const imsi64_t& imsi64) const
{
  std::shared_lock lock(m_imsi2pgw_context);
  return imsi2pgw_context.at(imsi64);
}
//------------------------------------------------------------------------------
void pgw_app::set_imsi64_2_pgw_context(const imsi64_t& imsi64, std::shared_ptr<pgw_context> pc)
{
  std::unique_lock lock(m_imsi2pgw_context);
  imsi2pgw_context[imsi64] = pc;
}
//------------------------------------------------------------------------------
void pgw_app::set_seid_2_pgw_context(const seid_t& seid, std::shared_ptr<pgw_context>& pc)
{
  std::unique_lock lock(m_seid2pgw_context);
  seid2pgw_context[seid] = pc;
}
//------------------------------------------------------------------------------
bool pgw_app::seid_2_pgw_context(const seid_t& seid, std::shared_ptr<pgw_context>& pc) const
{
  std::shared_lock lock(m_seid2pgw_context);
  std::map<seid_t, std::shared_ptr<pgw_context>>::const_iterator it = seid2pgw_context.find(seid);
  if (it != seid2pgw_context.end()) {
    pc = it->second;
    return true;
  }
  return false;
}

//------------------------------------------------------------------------------
fteid_t pgw_app::build_s5s8_cp_fteid(const struct in_addr ipv4_address, const teid_t teid)
{
  fteid_t fteid = {};
  fteid.interface_type = S5_S8_PGW_GTP_C;
  fteid.v4 = 1;
  fteid.ipv4_address = ipv4_address;
  fteid.v6 = 0;
  fteid.ipv6_address = in6addr_any;
  fteid.teid_gre_key = teid;
  return fteid;
}
//------------------------------------------------------------------------------
fteid_t pgw_app::generate_s5s8_cp_fteid(const struct in_addr ipv4_address)
{
  teid_t teid = generate_s5s8_cp_teid();
  return build_s5s8_cp_fteid(ipv4_address, teid);
}
//------------------------------------------------------------------------------
void  pgw_app::free_s5s8_cp_fteid(const fteid_t& fteid)
{
  std::unique_lock lock(m_s5s8lteid2pgw_context);
  s5s8lteid2pgw_context.erase(fteid.teid_gre_key);
  free_s5s8c_teid(fteid.teid_gre_key);
}
//------------------------------------------------------------------------------
bool pgw_app::is_s5s8cpgw_fteid_2_pgw_context(const fteid_t& ls5s8_fteid) const
{
  std::shared_lock lock(m_s5s8lteid2pgw_context);
  return bool{s5s8lteid2pgw_context.count(ls5s8_fteid.teid_gre_key) > 0};
}
//------------------------------------------------------------------------------
std::shared_ptr<pgw_context> pgw_app::s5s8cpgw_fteid_2_pgw_context(fteid_t& ls5s8_fteid)
{
  if (is_s5s8cpgw_fteid_2_pgw_context(ls5s8_fteid)) {
    return s5s8lteid2pgw_context.at(ls5s8_fteid.teid_gre_key);
  } else {
    return std::shared_ptr<pgw_context>(nullptr);
  }

}
//------------------------------------------------------------------------------
void pgw_app::set_s5s8cpgw_fteid_2_pgw_context(fteid_t& ls5s8_fteid, std::shared_ptr<pgw_context> spc)
{
  std::unique_lock lock(m_s5s8lteid2pgw_context);
  s5s8lteid2pgw_context[ls5s8_fteid.teid_gre_key] = spc;
}

//------------------------------------------------------------------------------
void pgw_app::delete_pgw_context(std::shared_ptr<pgw_context> spc)
{
  imsi64_t imsi64 = spc.get()->imsi.to_imsi64();
  std::unique_lock lock(m_imsi2pgw_context);
  imsi2pgw_context.erase(imsi64);
}
//------------------------------------------------------------------------------
void pgw_app::restore_sx_sessions(const seid_t& seid) const
{
  std::shared_lock lock(m_seid2pgw_context);
  //TODO
}

//------------------------------------------------------------------------------
void pgw_app_task (void*)
{
  const task_id_t task_id = TASK_PGWC_APP;
  itti_inst->notify_task_ready(task_id);

  do {
    std::shared_ptr<itti_msg> shared_msg = itti_inst->receive_msg(task_id);
    auto *msg = shared_msg.get();
    switch (msg->msg_type) {

    case N4_SESSION_ESTABLISHMENT_RESPONSE:
      if (itti_n4_session_establishment_response* m = dynamic_cast<itti_n4_session_establishment_response*>(msg)) {
        pgw_app_inst->handle_itti_msg(std::ref(*m));
      }
      break;

    case N4_SESSION_MODIFICATION_RESPONSE:
      if (itti_n4_session_modification_response* m = dynamic_cast<itti_n4_session_modification_response*>(msg)) {
        pgw_app_inst->handle_itti_msg(std::ref(*m));
      }
      break;

    case N4_SESSION_DELETION_RESPONSE:
      if (itti_n4_session_deletion_response* m = dynamic_cast<itti_n4_session_deletion_response*>(msg)) {
        pgw_app_inst->handle_itti_msg(std::ref(*m));
      }
      break;

    case N4_SESSION_REPORT_REQUEST:
      pgw_app_inst->handle_itti_msg(std::static_pointer_cast<itti_n4_session_report_request>(shared_msg));
      break;

    case TIME_OUT:
      if (itti_msg_timeout* to = dynamic_cast<itti_msg_timeout*>(msg)) {
        Logger::pgwc_app().info( "TIME-OUT event timer id %d", to->timer_id);
      }
      break;
    case TERMINATE:
      if (itti_msg_terminate *terminate = dynamic_cast<itti_msg_terminate*>(msg)) {
        Logger::pgwc_app().info( "Received terminate message");
        return;
      }
    case HEALTH_PING:
      break;
    default:
      Logger::pgwc_app().info( "no handler for msg type %d", msg->msg_type);
    }
  } while (true);
}

//------------------------------------------------------------------------------
pgw_app::pgw_app (const std::string& config_file) : m_s5s8_cp_teid_generator(), m_imsi2pgw_context(), m_s5s8lteid2pgw_context(), m_seid2pgw_context()
{
  Logger::pgwc_app().startup("Starting...");

  teid_s5s8_cp_generator = 0;
  imsi2pgw_context = {};
  s5s8lteid2pgw_context = {};
  s5s8cplteid = {};

  apply_config (smf_cfg);

  if (itti_inst->create_task(TASK_PGWC_APP, pgw_app_task, nullptr) ) {
    Logger::pgwc_app().error( "Cannot create task TASK_PGWC_APP" );
    throw std::runtime_error( "Cannot create task TASK_PGWC_APP" );
  }

  try {
    smf_n4_inst = new smf_n4();
    smf_n10_inst = new smf_n10();
    smf_n11_inst = new smf_n11();
  } catch (std::exception& e) {
    Logger::pgwc_app().error( "Cannot create PGW_APP: %s", e.what() );
    throw;
  }

  Logger::pgwc_app().startup( "Started" );
}


//------------------------------------------------------------------------------
void pgw_app::handle_itti_msg (itti_n4_session_establishment_response& seresp)
{
  std::shared_ptr<pgw_context> pc = {};
  if (seid_2_pgw_context(seresp.seid, pc)) {
    pc.get()->handle_itti_msg(seresp);
  } else {
    Logger::pgwc_app().debug("Received N4 SESSION ESTABLISHMENT RESPONSE seid" TEID_FMT "  pfcp_tx_id %" PRIX64", pgw_context not found, discarded!", seresp.seid, seresp.trxn_id);
  }
}
//------------------------------------------------------------------------------
void pgw_app::handle_itti_msg (itti_n4_session_modification_response& smresp)
{
  std::shared_ptr<pgw_context> pc = {};
  if (seid_2_pgw_context(smresp.seid, pc)) {
    pc.get()->handle_itti_msg(smresp);
  } else {
    Logger::pgwc_app().debug("Received N4 SESSION MODIFICATION RESPONSE seid" TEID_FMT "  pfcp_tx_id %" PRIX64", pgw_context not found, discarded!", smresp.seid, smresp.trxn_id);
  }
}
//------------------------------------------------------------------------------
void pgw_app::handle_itti_msg (itti_n4_session_deletion_response& smresp)
{
  std::shared_ptr<pgw_context> pc = {};
  if (seid_2_pgw_context(smresp.seid, pc)) {
    pc.get()->handle_itti_msg(smresp);

    if (pc->dnns.size() == 0) {
      delete_pgw_context(pc);
    }
  } else {
    Logger::pgwc_app().debug("Received N4 SESSION DELETION RESPONSE seid" TEID_FMT "  pfcp_tx_id %" PRIX64", pgw_context not found, discarded!", smresp.seid, smresp.trxn_id);
  }
}

//------------------------------------------------------------------------------
void pgw_app::handle_itti_msg (std::shared_ptr<itti_n4_session_report_request> snr)
{
  std::shared_ptr<pgw_context> pc = {};
  if (seid_2_pgw_context(snr->seid, pc)) {
    pc.get()->handle_itti_msg(snr);
  } else {
    Logger::pgwc_app().debug("Received N4 SESSION REPORT REQUEST seid" TEID_FMT "  pfcp_tx_id %" PRIX64", pgw_context not found, discarded!", snr->seid, snr->trxn_id);
  }
}


//------------------------------------------------------------------------------
void pgw_app::handle_amf_msg (std::shared_ptr<itti_n11_create_sm_context_request> smreq)
{
	//handle PDU Session Create SM Context Request as specified in section 4.3.2 3GPP TS 23.502
	oai::smf::model::SmContextCreateError smContextCreateError;
	oai::smf::model::ProblemDetails problem_details;

	//Step 1. get necessary information
	supi_t supi =  smreq->req.get_supi();
	supi64_t supi64 = smf_supi_to_u64(supi);
	std::string dnn = smreq->req.get_dnn();
	snssai_t snssai  =  smreq->req.get_snssai();
	procedure_transaction_id_t pti = smreq->req.get_pti();
	pdu_session_type_t pdu_session_type = {.pdu_session_type = smreq->req.get_pdu_session_type()};
	pdu_session_id_t pdu_session_id = smreq->req.get_pdu_session_id();
	uint8_t message_type = smreq->req.get_message_type();
	request_type_t request_type = smreq->req.get_request_type();

	Logger::pgwc_app().info("Handle a PDU Session Create SM Context Request message from AMF, supi " SUPI_64_FMT ", dnn %s, snssai_sst %d", supi64, dnn.c_str(), snssai.sST );

	//check pti
	if ((pti.procedure_transaction_id == PROCEDURE_TRANSACTION_IDENTITY_UNASSIGNED) || (pti.procedure_transaction_id > PROCEDURE_TRANSACTION_IDENTITY_LAST)){
		Logger::pgwc_app().warn(" Invalid PTI value (pti = %d)\n", pti.procedure_transaction_id);
		problem_details.setCause(pdu_session_application_error_e2str[PDU_SESSION_APPLICATION_ERROR_N1_SM_ERROR]);
		smContextCreateError.setError(problem_details);
		//TODO: to be completed when finishing NAS implementation
		//create a PDU Session Establishment Response by relying on NAS and assign to smContextCeateError.m_N1SmMsg
		//TODO: (24.501 (section 7.3.1)) NAS N1 SM message: response with a 5GSM STATUS message including cause "#81 Invalid PTI value"
		//Send response to AMF
		send_create_session_response(smreq->http_response, smContextCreateError, Pistache::Http::Code::Forbidden);
	}

	//check pdu session id
	if ((pdu_session_id == PDU_SESSION_IDENTITY_UNASSIGNED) || (pdu_session_id > PDU_SESSION_IDENTITY_LAST)){
		Logger::pgwc_app().warn(" Invalid PDU Session ID value (psi = %d)\n", pdu_session_id);
		//TODO: (24.501 (section 7.3.2)) NAS N1 SM message: ignore the message
		//return;
	}

	//check message type
	if (message_type != PDU_SESSION_ESTABLISHMENT_REQUEST) {
		Logger::pgwc_app().warn("Invalid message type (message type = %d)\n", message_type);
		//TODO:
		problem_details.setCause(pdu_session_application_error_e2str[PDU_SESSION_APPLICATION_ERROR_N1_SM_ERROR]);
		smContextCreateError.setError(problem_details);
		//TODO: to be completed when finishing NAS implementation
		//create a PDU Session Establishment Response by relying on NAS and assign to smContextCeateError.m_N1SmMsg
		//TODO: (24.501 (section 7.4)) implementation dependent->do similar to UE: response with a 5GSM STATUS message including cause "#98 message type not compatible with protocol state."
		//Send response to AMF
		send_create_session_response(smreq->http_response, smContextCreateError, Pistache::Http::Code::Forbidden);
	}

	//check request type
	if ((request_type & 0x07) != INITIAL_REQUEST){
		Logger::pgwc_app().warn("Invalid request type (request type = %s)\n", request_type_e2str[request_type & 0x07]);
		//TODO:
		//return
	}

	//Step 2. check if the DNN requested is valid
	if (not smf_cfg.is_dotted_dnn_handled(dnn, pdu_session_type)) {
		// Not a valid request...
		Logger::pgwc_app().warn("Received PDU_SESSION_CREATESMCONTEXT_REQUEST unknown requested APN %s, ignore message!", dnn.c_str());
		problem_details.setCause(pdu_session_application_error_e2str[PDU_SESSION_APPLICATION_ERROR_DNN_DENIED]);
		smContextCreateError.setError(problem_details);
		//TODO: to be completed when finishing NAS implementation
		//create a PDU Session Establishment Response by relying on NAS and assign to smContextCeateError.m_N1SmMsg
		//Send response to AMF
		send_create_session_response(smreq->http_response, smContextCreateError, Pistache::Http::Code::Forbidden);
		return;
	}

	//Step 3. create a context for this supi if not existed, otherwise update
	std::shared_ptr<pgw_context> sc;
	if (is_supi_2_smf_context(supi64)) {
		Logger::pgwc_app().debug("Update SMF context with SUPI " SUPI_64_FMT "", supi64);
		sc = supi_2_smf_context(supi64);
	} else {
		Logger::pgwc_app().debug("Create a new SMF context with SUPI " SUPI_64_FMT "", supi64);
		sc = std::shared_ptr<pgw_context>(new pgw_context());
		set_supi_2_smf_context(supi64, sc);
	}

	//update context with dnn information
	std::shared_ptr<dnn_context> sd;

	if (!sc.get()->find_dnn_context(dnn, sd)) {
		if (nullptr == sd.get()){
			//create a new one and insert to the list
			Logger::pgwc_app().debug("Create a DNN context and add to the SMF context\n");
			sd = std::shared_ptr<dnn_context>(new dnn_context(dnn));
			//sd.get()->in_use = true;
			sc.get()->insert_dnn(sd);
		}
	}

	// step 4. retrieve Session Management Subscription data from UDM if not available (step 4, section 4.3.2 3GPP TS 23.502)
	std::string dnn_selection_mode = smreq->req.get_dnn_selection_mode();
	if (not use_local_configuration_subscription_data(dnn_selection_mode) && not is_supi_dnn_snssai_subscription_data(supi, dnn, snssai))
	{
		//uses a dummy UDM to test this part
		Logger::pgwc_app().debug("Retrieve Session Management Subscription data from UDM");
		std::shared_ptr<session_management_subscription> subscription = std::shared_ptr<session_management_subscription>(new session_management_subscription (snssai));
		if (smf_n10_inst->get_sm_data(supi64, dnn, snssai, subscription)) {
			//update dnn_context with subscription info
			sc.get()->insert_dnn_subscription(snssai, subscription);
		} else {
			// Not accept to establish a PDU session
			Logger::pgwc_app().warn("Received PDU_SESSION_CREATESMCONTEXT_REQUEST, couldn't retrieve the Session Management Subscription from UDM, ignore message!");
			problem_details.setCause(pdu_session_application_error_e2str[PDU_SESSION_APPLICATION_ERROR_SUBSCRIPTION_DENIED]);
			smContextCreateError.setError(problem_details);
			//TODO: to be completed when finishing NAS implementation
			//create a PDU Session Establishment Response by relying on NAS and assign to smContextCeateError.m_N1SmMsg
			//Send response to AMF
			send_create_session_response(smreq->http_response, smContextCreateError, Pistache::Http::Code::Forbidden);
			return;
		}
	}

	//Step 5. let the context handle the message
	//in this step, SMF will send N4 Session Establishment/Modification to UPF (step 10a, section 4.3.2 3GPP 23.502)
	//SMF, then, sends response to AMF
	sc.get()->handle_amf_msg(smreq);

}


//------------------------------------------------------------------------------
bool pgw_app::is_supi_2_smf_context(const supi64_t& supi) const
{
	//TODO
	//context doesn't exist
	return false;
}

//------------------------------------------------------------------------------
std::shared_ptr<pgw_context>  pgw_app::supi_2_smf_context(const supi64_t& supi) const
{
	std::shared_lock lock(m_supi2smf_context);
	return supi2pgw_context.at(supi);
}

//------------------------------------------------------------------------------
void pgw_app::set_supi_2_smf_context(const supi64_t& supi, std::shared_ptr<pgw_context> sc)
{
	//TODO: from set_imsi64_2_pgw_context
}

//------------------------------------------------------------------------------
bool pgw_app::use_local_configuration_subscription_data(const std::string& dnn_selection_mode)
{
	//TODO: should be implemented
	return false; //get Session Management Subscription from UDM
}

//------------------------------------------------------------------------------
bool pgw_app::is_supi_dnn_snssai_subscription_data(supi_t& supi, std::string& dnn, snssai_t& snssai)
{
	//TODO: should be implemented
	return false; //Session Management Subscription from UDM isn't available
}

//------------------------------------------------------------------------------
bool pgw_app::is_create_sm_context_request_valid()
{
	//TODO: should be implemented
	return true;

}

//------------------------------------------------------------------------------
void pgw_app::send_create_session_response(Pistache::Http::ResponseWriter& httpResponse, oai::smf::model::SmContextCreateError& smContextCreateError, Pistache::Http::Code code)
{
	//Send reply to AMF
	nlohmann::json jsonData;
	to_json(jsonData, smContextCreateError);
	std::string resBody = jsonData.dump();

	//httpResponse.headers().add<Pistache::Http::Header::Location>(url);
	httpResponse.send(code, resBody);
}

