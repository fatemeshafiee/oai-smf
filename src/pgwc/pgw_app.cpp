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
#include "RefToBinaryData.h"

extern "C"{
#include "nas_message.h"
#include "mmData.h"
}

#include <stdexcept>
#include <iostream>
#include <cstdlib>

#define BUF_LEN 512

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
uint64_t pgw_app::generate_seid() {
  std::unique_lock<std::mutex> ls(m_seid_n4_generator);
  uint64_t seid =  ++seid_n4_generator;
  while ((is_seid_n4_exist(seid)) || (seid == UNASSIGNED_SEID)) {
    seid =  ++seid_n4_generator;
  }
  set_seid_n4.insert(seid);
  ls.unlock();
  return seid;
}


//------------------------------------------------------------------------------
bool pgw_app::is_seid_n4_exist(const uint64_t& seid) const
{
  return bool{set_seid_n4.count(seid) > 0};
}

//------------------------------------------------------------------------------
void pgw_app::free_seid_n4(const uint64_t& seid)
{
	std::unique_lock<std::mutex> ls(m_seid_n4_generator);
	set_seid_n4.erase (seid);
	ls.unlock();
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
pgw_app::pgw_app (const std::string& config_file) : m_imsi2pgw_context(), m_seid2pgw_context()
{
  Logger::pgwc_app().startup("Starting...");

  imsi2pgw_context = {};
  set_seid_n4 = {};

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
	oai::smf::model::RefToBinaryData binary_data;
	std::string n1_container; //N1 SM container

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

		//PDU Session Establishment Reject
		//(24.501 (section 7.3.1)) NAS N1 SM message: response with a 5GSM STATUS message including cause "#81 Invalid PTI value"
		pgw_app_inst->create_n1_sm_container(smreq, PDU_SESSION_ESTABLISHMENT_REJECT, n1_container, 81); //TODO: should define 5GSM cause in 24.501
		binary_data.setContentId(n1_container);
		smContextCreateError.setN1SmMsg(binary_data);
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

		//PDU Session Establishment Reject
		//(24.501 (section 7.4)) implementation dependent->do similar to UE: response with a 5GSM STATUS message including cause "#98 message type not compatible with protocol state."
		pgw_app_inst->create_n1_sm_container(smreq, PDU_SESSION_ESTABLISHMENT_REJECT, n1_container, 98); //TODO: should define 5GSM cause in 24.501
		binary_data.setContentId(n1_container);
		smContextCreateError.setN1SmMsg(binary_data);
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
		//PDU Session Establishment Reject
		//(24.501 cause "#27 Missing or unknown DNN"
		pgw_app_inst->create_n1_sm_container(smreq, PDU_SESSION_ESTABLISHMENT_REJECT, n1_container, 27); //TODO: should define 5GSM cause in 24.501
		binary_data.setContentId(n1_container);
		smContextCreateError.setN1SmMsg(binary_data);
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
			//PDU Session Establishment Reject
			//24.501 which cause should be use "29 User authentication or authorization failed"?
			pgw_app_inst->create_n1_sm_container(smreq, PDU_SESSION_ESTABLISHMENT_REJECT, n1_container, 29); //TODO: should define 5GSM cause in 24.501
			binary_data.setContentId(n1_container);
			smContextCreateError.setN1SmMsg(binary_data);
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

//------------------------------------------------------------------------------
void pgw_app::create_n1_sm_container(std::shared_ptr<itti_n11_create_sm_context_response> sm_context_res, uint8_t msg_type, std::string& nas_msg_str, uint8_t sm_cause)
{
	//TODO: should work with BUPT to finish this function
	Logger::pgwc_app().info("Create N1 SM Container, message type %d \n", msg_type);
	//To be updated according to NAS implementation
	int size = NAS_MESSAGE_SECURITY_HEADER_SIZE;
	int bytes = 0;
	int length = BUF_LEN;
	unsigned char data[BUF_LEN] = {'\0'};
	memset(data,0,sizeof(data));


	nas_message_t nas_msg;
	memset(&nas_msg, 0, sizeof(nas_message_t));
	nas_msg.header.extended_protocol_discriminator = EPD_5GS_SESSION_MANAGEMENT_MESSAGES;
	nas_msg.header.security_header_type = SECURITY_HEADER_TYPE_INTEGRITY_PROTECTED_CYPHERED;
	uint8_t sequencenumber = 0xfe;
	//uint32_t mac = 0xffffeeee;
	uint32_t mac = 0xffee;
	nas_msg.header.sequence_number = sequencenumber;
	nas_msg.header.message_authentication_code= mac;
	nas_msg.security_protected.header = nas_msg.header;


	//nas_msg.header.sequence_number = 0xfe;
	//nas_msg.security_protected.header = nas_msg.header;
	SM_msg *sm_msg;
	sm_msg = &nas_msg.security_protected.plain.sm;
	sm_msg->header.extended_protocol_discriminator  = EPD_5GS_SESSION_MANAGEMENT_MESSAGES;

	sm_msg->header.pdu_session_identity = sm_context_res->res.get_pdu_session_id();
	sm_msg->header.procedure_transaction_identity = 1; //TODO: to be updated

	switch (msg_type){

	case PDU_SESSION_ESTABLISHMENT_ACCPET: {
		//TODO:
		sm_msg->header.message_type = PDU_SESSION_ESTABLISHMENT_ACCPET;
	}
	break;

	case PDU_SESSION_ESTABLISHMENT_REJECT: {
		sm_msg->header.message_type = PDU_SESSION_ESTABLISHMENT_REJECT;
		sm_msg->specific_msg.pdu_session_establishment_reject.extendedprotocoldiscriminator = 0X2E;

		bstring pdusessionidentity_tmp = bfromcstralloc(10, "\0");
		uint8_t bitStream_pdusessionidentity = 0X01;
		pdusessionidentity_tmp->data = (unsigned char *)(&bitStream_pdusessionidentity);
		pdusessionidentity_tmp->slen = 1;
		sm_msg->specific_msg.pdu_session_establishment_reject.pdusessionidentity = pdusessionidentity_tmp;

		bstring proceduretransactionidentity_tmp = bfromcstralloc(10, "\0");
		uint8_t bitStream_proceduretransactionidentity = 0X01;
		proceduretransactionidentity_tmp->data = (unsigned char *)(&bitStream_proceduretransactionidentity);
		proceduretransactionidentity_tmp->slen = 1;
		sm_msg->specific_msg.pdu_session_establishment_reject.proceduretransactionidentity = proceduretransactionidentity_tmp;
		sm_msg->specific_msg.pdu_session_establishment_reject.messagetype = 0XC1;

		sm_msg->specific_msg.pdu_session_establishment_reject._5gsmcause = sm_cause;
		sm_msg->specific_msg.pdu_session_establishment_reject.presence = 0x1f;

		sm_msg->specific_msg.pdu_session_establishment_reject.gprstimer3.unit = VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_1_HOUR;
		sm_msg->specific_msg.pdu_session_establishment_reject.gprstimer3.timeValue = 0;

		sm_msg->specific_msg.pdu_session_establishment_reject.allowedsscmode.is_ssc1_allowed = SSC_MODE1_ALLOWED;
		sm_msg->specific_msg.pdu_session_establishment_reject.allowedsscmode.is_ssc2_allowed = SSC_MODE2_NOT_ALLOWED;
		sm_msg->specific_msg.pdu_session_establishment_reject.allowedsscmode.is_ssc3_allowed = SSC_MODE3_ALLOWED;

		unsigned char bitStream_eapmessage[2] = {0x01,0x02};
		bstring eapmessage_tmp = bfromcstralloc(2, "\0");
		eapmessage_tmp->slen = 2;
		memcpy(eapmessage_tmp->data,bitStream_eapmessage,sizeof(bitStream_eapmessage));
		sm_msg->specific_msg.pdu_session_establishment_reject.eapmessage = eapmessage_tmp;

		unsigned char bitStream_extendedprotocolconfigurationoptions[4];
		bitStream_extendedprotocolconfigurationoptions[0] = 0x12;
		bitStream_extendedprotocolconfigurationoptions[1] = 0x13;
		bitStream_extendedprotocolconfigurationoptions[2] = 0x14;
		bitStream_extendedprotocolconfigurationoptions[3] = 0x15;
		bstring extendedprotocolconfigurationoptions_tmp = bfromcstralloc(4, "\0");
		//extendedprotocolconfigurationoptions_tmp->data = bitStream_extendedprotocolconfigurationoptions;
		extendedprotocolconfigurationoptions_tmp->slen = 4;
		memcpy(extendedprotocolconfigurationoptions_tmp->data,bitStream_extendedprotocolconfigurationoptions,sizeof(bitStream_extendedprotocolconfigurationoptions));
		sm_msg->specific_msg.pdu_session_establishment_reject.extendedprotocolconfigurationoptions = extendedprotocolconfigurationoptions_tmp;

		sm_msg->specific_msg.pdu_session_establishment_reject._5gsmcongestionreattemptindicator.abo = THE_BACKOFF_TIMER_IS_APPLIED_IN_ALL_PLMNS;



		//encode message
		size += MESSAGE_TYPE_MAXIMUM_LENGTH;

		Logger::smf_n11().debug("Size of nas_msg.security_protected.plain.sm: %d\n ", sizeof(nas_msg.security_protected.plain.sm));
		nas_msg.plain.sm = *sm_msg;

		//construct security context
		fivegmm_security_context_t * security = (fivegmm_security_context_t *)calloc(1,sizeof(fivegmm_security_context_t));
		security->selected_algorithms.encryption = NAS_SECURITY_ALGORITHMS_NEA0;
		security->dl_count.overflow = 0xffff;
		security->dl_count.seq_num =  0x23;
		security->knas_enc[0] = 0x14;
		security->selected_algorithms.integrity = NAS_SECURITY_ALGORITHMS_NIA0;
		security->knas_int[0] = 0x41;
		//complete sercurity context


		bstring  info = bfromcstralloc(length, "\0");//info the nas_message_encode result

#ifdef DEBUG

		printf("nas header encode extended_protocol_discriminator:0x%x\n, security_header_type:0x%x\n,sequence_number:0x%x\n,message_authentication_code:0x%x\n",
				nas_msg.header.extended_protocol_discriminator,
				nas_msg.header.security_header_type,
				nas_msg.header.sequence_number,
				nas_msg.header.message_authentication_code);

		printf("sm header,extended_protocol_discriminator:0x%x,pdu_session_identity:0x%x,procedure_transaction_identity:0x%x, message type:0x%x\n",
				sm_msg->header.extended_protocol_discriminator,
				sm_msg->header.pdu_session_identity,
				sm_msg->header.procedure_transaction_identity,
				sm_msg->header.message_type);

		printf("_5gsmcause: 0x%x\n",sm_msg->specific_msg.pdu_session_establishment_reject._5gsmcause);
#endif

		bytes = nas_message_encode (data, &nas_msg, sizeof(data)/*don't know the size*/, security);

		//nas_msg_str = reinterpret_cast<char*> (data);
		std::string n1Message ((char*) data,  60);
		nas_msg_str = n1Message;
		Logger::pgwc_app().debug("n1MessageContent: %d, %s\n ", bytes, nas_msg_str.c_str());

		//printf("start nas_message_decode bytes:%d\n", bytes);
		bstring plain_msg = bstrcpy(info);
		nas_message_security_header_t header = {EPD_5GS_SESSION_MANAGEMENT_MESSAGES};
		//fivegmm_security_context_t  * security = NULL;
		nas_message_decode_status_t   decode_status = {0};

		nas_message_t	decoded_nas_msg;
		memset (&decoded_nas_msg,		 0, sizeof (nas_message_t));

		int decoder_rc = RETURNok;
		printf("calling nas_message_decode-----------\n");
		decoder_rc = nas_message_decode (data, &decoded_nas_msg, sizeof(data) /*blength(info)*/, security, &decode_status);


		printf("nas header  decode extended_protocol_discriminator:0x%x\n, security_header_type:0x%x\n,sequence_number:0x%x\n,message_authentication_code:0x%x\n",
				decoded_nas_msg.header.extended_protocol_discriminator,
				decoded_nas_msg.header.security_header_type,
				decoded_nas_msg.header.sequence_number,
				decoded_nas_msg.header.message_authentication_code);

		SM_msg * decoded_sm_msg = &decoded_nas_msg.plain.sm;

		printf("sm header,extended_protocol_discriminator:0x%x,pdu_session_identity:0x%x,procedure_transaction_identity:0x%x, message type:0x%x\n", decoded_sm_msg->header.extended_protocol_discriminator,
				decoded_sm_msg->header.pdu_session_identity,
				decoded_sm_msg->header.procedure_transaction_identity,
				decoded_sm_msg->header.message_type);

		printf("decoded_nas_msg.security_protected.plain.sm = %d\n",sizeof(decoded_nas_msg.security_protected.plain.sm));


		printf("_5gsmcause: 0x%x\n",decoded_sm_msg->specific_msg.pdu_session_establishment_reject._5gsmcause);
		printf("gprstimer3 --- unit_bits_H3: 0x%x,timeValue_bits_L5: 0x%x\n",decoded_sm_msg->specific_msg.pdu_session_establishment_reject.gprstimer3.unit,decoded_sm_msg->specific_msg.pdu_session_establishment_reject.gprstimer3.timeValue);
		printf("allowedsscmode --- is_ssc1_allowed: 0x%x, is_ssc2_allowed: 0x%x, is_ssc3_allowed: 0x%x\n",decoded_sm_msg->specific_msg.pdu_session_establishment_reject.allowedsscmode.is_ssc1_allowed,decoded_sm_msg->specific_msg.pdu_session_establishment_reject.allowedsscmode.is_ssc2_allowed,decoded_sm_msg->specific_msg.pdu_session_establishment_reject.allowedsscmode.is_ssc3_allowed);
		printf("eapmessage buffer:0x%x 0x%x\n",(unsigned char)(decoded_sm_msg->specific_msg.pdu_session_establishment_reject.eapmessage->data[0]),(unsigned char )(decoded_sm_msg->specific_msg.pdu_session_establishment_reject.eapmessage->data[1]));
		printf("extend_options buffer:0x%x 0x%x 0x%x 0x%x\n",(unsigned char)((decoded_sm_msg->specific_msg.pdu_session_establishment_reject.extendedprotocolconfigurationoptions)->data[0]),(unsigned char)((decoded_sm_msg->specific_msg.pdu_session_establishment_reject.extendedprotocolconfigurationoptions)->data[1]),(unsigned char)((decoded_sm_msg->specific_msg.pdu_session_establishment_reject.extendedprotocolconfigurationoptions)->data[2]),(unsigned char)((decoded_sm_msg->specific_msg.pdu_session_establishment_reject.extendedprotocolconfigurationoptions)->data[3]));
		printf("_5gsmcongestionreattemptindicator bits_1 --- abo:0x%x\n",decoded_sm_msg->specific_msg.pdu_session_establishment_reject._5gsmcongestionreattemptindicator.abo);

		printf("PDU_SESSION_ESTABLISHMENT_REJECT------------ end\n");

	}

	break;

	default:
		Logger::pgwc_app().debug("Unknown message type: %d \n", msg_type);
	}
}


void pgw_app::create_n1_sm_container(uint8_t msg_type, std::string& nas_msg_str, uint8_t sm_cause)
{
	Logger::pgwc_app().info("Create N1 SM Container, message type %d \n", msg_type);
	//To be updated according to NAS implementation
	int size = NAS_MESSAGE_SECURITY_HEADER_SIZE;
	int bytes = 0;
	int length = BUF_LEN;
	unsigned char data[BUF_LEN] = {'\0'};
	memset(data,0,sizeof(data));


	nas_message_t nas_msg;
	memset(&nas_msg, 0, sizeof(nas_message_t));
	nas_msg.header.extended_protocol_discriminator = EPD_5GS_SESSION_MANAGEMENT_MESSAGES;
	nas_msg.header.security_header_type = SECURITY_HEADER_TYPE_INTEGRITY_PROTECTED_CYPHERED;
	uint8_t sequencenumber = 0xfe;
	//uint32_t mac = 0xffffeeee;
	uint32_t mac = 0xffee;
	nas_msg.header.sequence_number = sequencenumber;
	nas_msg.header.message_authentication_code= mac;
	nas_msg.security_protected.header = nas_msg.header;


	//nas_msg.header.sequence_number = 0xfe;
	//nas_msg.security_protected.header = nas_msg.header;
	SM_msg *sm_msg;
	sm_msg = &nas_msg.security_protected.plain.sm;
	sm_msg->header.extended_protocol_discriminator  = EPD_5GS_SESSION_MANAGEMENT_MESSAGES;

	sm_msg->header.pdu_session_identity = 1;
	sm_msg->header.procedure_transaction_identity = 1; //TODO: to be updated

	switch (msg_type){
	case PDU_SESSION_ESTABLISHMENT_REQUEST: {
		//TODO:
		sm_msg->header.message_type = PDU_SESSION_ESTABLISHMENT_REQUEST;
		sm_msg->specific_msg.pdu_session_establishment_request.extendedprotocoldiscriminator = 0X2E;

		bstring pdusessionidentity_tmp = bfromcstralloc(10, "\0");
		uint8_t bitStream_pdusessionidentity = 0X01;
		pdusessionidentity_tmp->data = (unsigned char *)(&bitStream_pdusessionidentity);
		pdusessionidentity_tmp->slen = 1;
		sm_msg->specific_msg.pdu_session_establishment_request.pdusessionidentity = pdusessionidentity_tmp;

		bstring proceduretransactionidentity_tmp = bfromcstralloc(10, "\0");
		uint8_t bitStream_proceduretransactionidentity = 0X01;
		proceduretransactionidentity_tmp->data = (unsigned char *)(&bitStream_proceduretransactionidentity);
		proceduretransactionidentity_tmp->slen = 1;
		sm_msg->specific_msg.pdu_session_establishment_request.proceduretransactionidentity = proceduretransactionidentity_tmp;

		sm_msg->specific_msg.pdu_session_establishment_request.messagetype = 0XC1;


		unsigned char bitStream_intergrityprotectionmaximumdatarate[2] = {0x01,0x02};
		bstring intergrityprotectionmaximumdatarate_tmp = bfromcstralloc(2, "\0");
		//intergrityprotectionmaximumdatarate_tmp->data = bitStream_intergrityprotectionmaximumdatarate;
		intergrityprotectionmaximumdatarate_tmp->slen = 2;
		memcpy(intergrityprotectionmaximumdatarate_tmp->data,bitStream_intergrityprotectionmaximumdatarate,sizeof(bitStream_intergrityprotectionmaximumdatarate));
		sm_msg->specific_msg.pdu_session_establishment_request.intergrityprotectionmaximumdatarate = intergrityprotectionmaximumdatarate_tmp;

		sm_msg->specific_msg.pdu_session_establishment_request.presence = 0x7f;

		sm_msg->specific_msg.pdu_session_establishment_request._pdusessiontype.pdu_session_type_value = 0x01;

		sm_msg->specific_msg.pdu_session_establishment_request.sscmode.ssc_mode_value = 0x01;

		sm_msg->specific_msg.pdu_session_establishment_request._5gsmcapability.is_MPTCP_supported = MPTCP_FUNCTIONALITY_SUPPORTED;
		sm_msg->specific_msg.pdu_session_establishment_request._5gsmcapability.is_ATSLL_supported = EATSSS_LOW_LAYER_FUNCTIONALITY_NOT_SUPPORTED;
		sm_msg->specific_msg.pdu_session_establishment_request._5gsmcapability.is_EPTS1_supported = ETHERNET_PDN_TYPE_IN_S1_MODE_SUPPORTED;
		sm_msg->specific_msg.pdu_session_establishment_request._5gsmcapability.is_MH6PDU_supported = MULTI_HOMED_IPV6_PDU_SESSION_SUPPORTED;
		sm_msg->specific_msg.pdu_session_establishment_request._5gsmcapability.is_Rqos_supported = REFLECTIVE_QOS_NOT_SUPPORTED;


		sm_msg->specific_msg.pdu_session_establishment_request.maximumnumberofsupportedpacketfilters = 0x3ff;


		sm_msg->specific_msg.pdu_session_establishment_request.alwaysonpdusessionrequested.apsr_requested = ALWAYSON_PDU_SESSION_REQUESTED;

		unsigned char bitStream_smpdudnrequestcontainer[3];
		bitStream_smpdudnrequestcontainer[0] = 0x11;
		bitStream_smpdudnrequestcontainer[1] = 0x22;
		bitStream_smpdudnrequestcontainer[2] = 0x33;
		bstring smpdudnrequestcontainer_tmp = bfromcstralloc(3, "\0");
		//smpdudnrequestcontainer_tmp->data = bitStream_smpdudnrequestcontainer;
		smpdudnrequestcontainer_tmp->slen = 3;
		memcpy(smpdudnrequestcontainer_tmp->data,bitStream_smpdudnrequestcontainer,sizeof(bitStream_smpdudnrequestcontainer));
		sm_msg->specific_msg.pdu_session_establishment_request.smpdudnrequestcontainer = smpdudnrequestcontainer_tmp;

		unsigned char bitStream_extendedprotocolconfigurationoptions[4];
		bitStream_extendedprotocolconfigurationoptions[0] = 0x12;
		bitStream_extendedprotocolconfigurationoptions[1] = 0x13;
		bitStream_extendedprotocolconfigurationoptions[2] = 0x14;
		bitStream_extendedprotocolconfigurationoptions[3] = 0x15;
		bstring extendedprotocolconfigurationoptions_tmp = bfromcstralloc(4, "\0");
		//extendedprotocolconfigurationoptions_tmp->data = bitStream_extendedprotocolconfigurationoptions;
		extendedprotocolconfigurationoptions_tmp->slen = 4;
		memcpy(extendedprotocolconfigurationoptions_tmp->data,bitStream_extendedprotocolconfigurationoptions,sizeof(bitStream_extendedprotocolconfigurationoptions));
		sm_msg->specific_msg.pdu_session_establishment_request.extendedprotocolconfigurationoptions = extendedprotocolconfigurationoptions_tmp;

		/*********************sm_msg->specific_msg.pdu_session_establishment_request end******************************/

		size += MESSAGE_TYPE_MAXIMUM_LENGTH;

		//memcpy(&nas_msg.plain.sm,&nas_msg.security_protected.plain.sm,sizeof(nas_msg.security_protected.plain.sm));
		printf("nas_msg.security_protected.plain.sm = %d\n",sizeof(nas_msg.security_protected.plain.sm));
		nas_msg.plain.sm = *sm_msg;

		//complete sm msg content
		if(size <= 0){
		//	return -1;
		}

		//construct security context
		fivegmm_security_context_t * security = (fivegmm_security_context_t *)calloc(1,sizeof(fivegmm_security_context_t));
		security->selected_algorithms.encryption = NAS_SECURITY_ALGORITHMS_NEA1;
		security->dl_count.overflow = 0xffff;
		security->dl_count.seq_num =  0x23;
		security->knas_enc[0] = 0x14;
		security->selected_algorithms.integrity = NAS_SECURITY_ALGORITHMS_NIA1;
		security->knas_int[0] = 0x41;
		//complete sercurity context



		bstring  info = bfromcstralloc(length, "\0");//info the nas_message_encode result

#if 0
		printf("1 start nas_message_encode \n");
		printf("security %p\n",security);
		printf("info %p\n",info);
#endif

		printf("nas header encode extended_protocol_discriminator:0x%x\n, security_header_type:0x%x\n,sequence_number:0x%x\n,message_authentication_code:0x%x\n",
				nas_msg.header.extended_protocol_discriminator,
				nas_msg.header.security_header_type,
				nas_msg.header.sequence_number,
				nas_msg.header.message_authentication_code);



		printf("sm header,extended_protocol_discriminator:0x%x,pdu_session_identity:0x%x,procedure_transaction_identity:0x%x, message type:0x%x\n",
				sm_msg->header.extended_protocol_discriminator,
				sm_msg->header.pdu_session_identity,
				sm_msg->header.procedure_transaction_identity,
				sm_msg->header.message_type);

		//printf("message type:0x%x\n",sm_msg->specific_msg.pdu_session_establishment_request.messagetype);
		//printf("extendedprotocoldiscriminator:0x%x\n",sm_msg->specific_msg.pdu_session_establishment_request.extendedprotocoldiscriminator);
		//printf("pdu identity buffer:0x%x\n",*(unsigned char *)((sm_msg->specific_msg.pdu_session_establishment_request.pdusessionidentity)->data));
		//printf("PTI buffer:0x%x\n",*(unsigned char *)((sm_msg->specific_msg.pdu_session_establishment_request.proceduretransactionidentity)->data));

		printf("intergrity buffer:0x%x 0x%x\n",(unsigned char)((sm_msg->specific_msg.pdu_session_establishment_request.intergrityprotectionmaximumdatarate)->data[0]),(unsigned char )((sm_msg->specific_msg.pdu_session_establishment_request.intergrityprotectionmaximumdatarate)->data[1]));
		printf("_pdusessiontype bits_3:0x%x\n",sm_msg->specific_msg.pdu_session_establishment_request._pdusessiontype.pdu_session_type_value);
		printf("sscmode bits_3:0x%x\n",sm_msg->specific_msg.pdu_session_establishment_request.sscmode.ssc_mode_value);
		printf("_5gsmcapability bits_5 --- MPTCP:0x%x ATS-LL:0x%x EPT-S1:0x%x MH6-PDU:0x%x RqoS:0x%x\n",sm_msg->specific_msg.pdu_session_establishment_request._5gsmcapability.is_MPTCP_supported,sm_msg->specific_msg.pdu_session_establishment_request._5gsmcapability.is_ATSLL_supported,sm_msg->specific_msg.pdu_session_establishment_request._5gsmcapability.is_EPTS1_supported,sm_msg->specific_msg.pdu_session_establishment_request._5gsmcapability.is_MH6PDU_supported,sm_msg->specific_msg.pdu_session_establishment_request._5gsmcapability.is_Rqos_supported);
		printf("maximum bits_11:0x%x\n",sm_msg->specific_msg.pdu_session_establishment_request.maximumnumberofsupportedpacketfilters);
		printf("Always-on bits_1 --- APSR:0x%x\n",sm_msg->specific_msg.pdu_session_establishment_request.alwaysonpdusessionrequested.apsr_requested);
		printf("sm_pdu_dn buffer:0x%x 0x%x 0x%x\n",(unsigned char)((sm_msg->specific_msg.pdu_session_establishment_request.smpdudnrequestcontainer)->data[0]),(unsigned char)((sm_msg->specific_msg.pdu_session_establishment_request.smpdudnrequestcontainer)->data[1]),(unsigned char)((sm_msg->specific_msg.pdu_session_establishment_request.smpdudnrequestcontainer)->data[2]));
		printf("extend_options buffer:0x%x 0x%x 0x%x 0x%x\n",(unsigned char)((sm_msg->specific_msg.pdu_session_establishment_request.extendedprotocolconfigurationoptions)->data[0]),(unsigned char)((sm_msg->specific_msg.pdu_session_establishment_request.extendedprotocolconfigurationoptions)->data[1]),(unsigned char)((sm_msg->specific_msg.pdu_session_establishment_request.extendedprotocolconfigurationoptions)->data[2]),(unsigned char)((sm_msg->specific_msg.pdu_session_establishment_request.extendedprotocolconfigurationoptions)->data[3]));

		//bytes = nas_message_encode (data, &nas_msg, 60/*don't know the size*/, security);
		bytes = nas_message_encode (data, &nas_msg, sizeof(data)/*don't know the size*/, security);

		//nas_msg_str = reinterpret_cast<char*> (data);
		printf("Data = %s\n",data);
		std::string n1Message ((char*) data,  bytes);
		nas_msg_str = n1Message;
		Logger::pgwc_app().debug("n1MessageContent: %d, %s\n ", bytes, nas_msg_str.c_str());

	}
	break;


	case PDU_SESSION_ESTABLISHMENT_ACCPET: {
		//TODO:
		sm_msg->header.message_type = PDU_SESSION_ESTABLISHMENT_ACCPET;
	}
	break;

	case PDU_SESSION_ESTABLISHMENT_REJECT: {}
	break;

	default:
		Logger::pgwc_app().debug("Unknown message type: %d \n", msg_type);
	}
}


//------------------------------------------------------------------------------
void pgw_app::create_n1_sm_container(std::shared_ptr<itti_n11_create_sm_context_request> sm_context_req, uint8_t msg_type, std::string& nas_msg_str,  uint8_t sm_cause)
{
	//TODO: should work with BUPT to finish this function
}

//------------------------------------------------------------------------------
void pgw_app::create_n2_sm_information(std::shared_ptr<itti_n11_create_sm_context_response> sm_context_res, uint8_t ngap_msg_type, uint8_t ngap_ie_type, std::string& ngap_msg_str)
{
	//TODO: should work with BUPT to finish this function
	Logger::pgwc_app().info("Create N2 SM Information, ngap message type %d, ie type %d\n", ngap_msg_type, ngap_ie_type);
}

//------------------------------------------------------------------------------
uint8_t pgw_app::decode_nas_message_n1_sm_container(nas_message_t& nas_msg, std::string& n1_sm_msg)
{
	//TODO: should work with BUPT to finish this function
	Logger::pgwc_app().info("Decode NAS message from N1 SM Container\n");

	//step 1. Decode NAS  message (for instance, ... only served as an example)
	nas_message_decode_status_t   decode_status = {0};
	int decoder_rc = RETURNok;

	unsigned int n1SmMsgLen = strlen(n1_sm_msg.c_str());
	unsigned char *data = (unsigned char *)malloc(n1SmMsgLen + 1);//hardcoded for the moment
	unsigned char datavalue[512]  = {'\0'}; // = (unsigned char *)malloc(n1SmMsgLen/2 + 1);
	memset(data,0,n1SmMsgLen + 1);

	memcpy ((void *)data, (void *)n1_sm_msg.c_str(),n1SmMsgLen);

	printf("Data = %s\n",data);
	printf("Data value = ");
	for(int i=0;i<n1SmMsgLen;i++)
	{
		char datatmp[3] = {0};
		memcpy(datatmp,&data[i],2);
		// Ensure both characters are hexadecimal
		bool bBothDigits = true;

		for(int j = 0; j < 2; ++j)
		{
			if(!isxdigit(datatmp[j]))
				bBothDigits = false;
		}
		if(!bBothDigits)
			break;
		// Convert two hexadecimal characters into one character
		unsigned int nAsciiCharacter;
		sscanf(datatmp, "%x", &nAsciiCharacter);
		printf("%x ",nAsciiCharacter);
		// Concatenate this character onto the output
		datavalue[i/2] = (unsigned char)nAsciiCharacter;

		// Skip the next character
		i++;
	}
	printf("\n");
	free(data);
	data = NULL;

	//use a temporary security mechanism
	fivegmm_security_context_t * security = ( fivegmm_security_context_t *) std::calloc(1,sizeof(fivegmm_security_context_t));
	security->selected_algorithms.encryption = NAS_SECURITY_ALGORITHMS_NEA1;
	security->dl_count.overflow = 0xffff;
	security->dl_count.seq_num =  0x23;
	security->knas_enc[0] = 0x14;
	security->selected_algorithms.integrity = NAS_SECURITY_ALGORITHMS_NIA1;
	security->knas_int[0] = 0x41;

	//decode the NAS message (using NAS lib)
	decoder_rc = nas_message_decode (datavalue, &nas_msg, sizeof(datavalue), security, &decode_status);

	Logger::pgwc_app().debug("NAS header decode, extended_protocol_discriminator %d, security_header_type:%d,sequence_number:%d,message_authentication_code:%d\n",
			nas_msg.header.extended_protocol_discriminator,
			nas_msg.header.security_header_type,
			nas_msg.header.sequence_number,
			nas_msg.header.message_authentication_code);

	Logger::pgwc_app().debug("NAS msg type %d ", nas_msg.plain.sm.header.message_type);

	//nas_message_decode test
	switch(nas_msg.plain.sm.header.message_type)
	{
	case PDU_SESSION_ESTABLISHMENT_REQUEST:
		printf("PDU_SESSION_ESTABLISHMENT_REQUEST------------ start\n");
		printf("sm header,extended_protocol_discriminator:0x%x,pdu_session_identity:0x%x,procedure_transaction_identity:0x%x, message type:0x%x\n", nas_msg.plain.sm.header.extended_protocol_discriminator,nas_msg.plain.sm.header.pdu_session_identity,nas_msg.plain.sm.header.procedure_transaction_identity,nas_msg.plain.sm.header.message_type);
		printf("intergrity buffer:0x%x 0x%x\n",(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_establishment_request.intergrityprotectionmaximumdatarate)->data[0]),(unsigned char )((nas_msg.plain.sm.specific_msg.pdu_session_establishment_request.intergrityprotectionmaximumdatarate)->data[1]));
		printf("_pdusessiontype bits_3:0x%x\n",nas_msg.plain.sm.specific_msg.pdu_session_establishment_request._pdusessiontype.pdu_session_type_value);
		printf("sscmode bits_3:0x%x\n",nas_msg.plain.sm.specific_msg.pdu_session_establishment_request.sscmode.ssc_mode_value);
		printf("_5gsmcapability bits_5 --- MPTCP:0x%x ATS-LL:0x%x EPT-S1:0x%x MH6-PDU:0x%x RqoS:0x%x\n",nas_msg.plain.sm.specific_msg.pdu_session_establishment_request._5gsmcapability.is_MPTCP_supported,nas_msg.plain.sm.specific_msg.pdu_session_establishment_request._5gsmcapability.is_ATSLL_supported,nas_msg.plain.sm.specific_msg.pdu_session_establishment_request._5gsmcapability.is_EPTS1_supported,nas_msg.plain.sm.specific_msg.pdu_session_establishment_request._5gsmcapability.is_MH6PDU_supported,nas_msg.plain.sm.specific_msg.pdu_session_establishment_request._5gsmcapability.is_Rqos_supported);
		printf("maximum bits_11:0x%x\n",nas_msg.plain.sm.specific_msg.pdu_session_establishment_request.maximumnumberofsupportedpacketfilters);
		printf("Always-on bits_1 --- APSR:0x%x\n",nas_msg.plain.sm.specific_msg.pdu_session_establishment_request.alwaysonpdusessionrequested.apsr_requested);
		printf("sm_pdu_dn buffer:0x%x 0x%x 0x%x\n",(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_establishment_request.smpdudnrequestcontainer)->data[0]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_establishment_request.smpdudnrequestcontainer)->data[1]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_establishment_request.smpdudnrequestcontainer)->data[2]));
		printf("extend_options buffer:0x%x 0x%x 0x%x 0x%x\n",(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_establishment_request.extendedprotocolconfigurationoptions)->data[0]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_establishment_request.extendedprotocolconfigurationoptions)->data[1]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_establishment_request.extendedprotocolconfigurationoptions)->data[2]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_establishment_request.extendedprotocolconfigurationoptions)->data[3]));
		printf("PDU_SESSION_ESTABLISHMENT_REQUEST------------ end\n");
		break;
	case PDU_SESSION_ESTABLISHMENT_ACCPET:
		printf("PDU_SESSION_ESTABLISHMENT_ACCPET------------ start\n");
		printf("sm header,extended_protocol_discriminator:0x%x,pdu_session_identity:0x%x,procedure_transaction_identity:0x%x, message type:0x%x\n", nas_msg.plain.sm.header.extended_protocol_discriminator,nas_msg.plain.sm.header.pdu_session_identity,nas_msg.plain.sm.header.procedure_transaction_identity,nas_msg.plain.sm.header.message_type);
		printf("PDU_SESSION_ESTABLISHMENT_ACCPET------------ end\n");
		break;
	case PDU_SESSION_ESTABLISHMENT_REJECT:
		printf("PDU_SESSION_ESTABLISHMENT_REJECT------------ start\n");
		printf("sm header,extended_protocol_discriminator:0x%x,pdu_session_identity:0x%x,procedure_transaction_identity:0x%x, message type:0x%x\n", nas_msg.plain.sm.header.extended_protocol_discriminator,nas_msg.plain.sm.header.pdu_session_identity,nas_msg.plain.sm.header.procedure_transaction_identity,nas_msg.plain.sm.header.message_type);
		printf("_5gsmcause: 0x%x\n",nas_msg.plain.sm.specific_msg.pdu_session_establishment_reject._5gsmcause);
		printf("gprstimer3 --- unit_bits_H3: 0x%x,timeValue_bits_L5: 0x%x\n",nas_msg.plain.sm.specific_msg.pdu_session_establishment_reject.gprstimer3.unit,nas_msg.plain.sm.specific_msg.pdu_session_establishment_reject.gprstimer3.timeValue);
		printf("allowedsscmode --- is_ssc1_allowed: 0x%x, is_ssc2_allowed: 0x%x, is_ssc3_allowed: 0x%x\n",nas_msg.plain.sm.specific_msg.pdu_session_establishment_reject.allowedsscmode.is_ssc1_allowed,nas_msg.plain.sm.specific_msg.pdu_session_establishment_reject.allowedsscmode.is_ssc2_allowed,nas_msg.plain.sm.specific_msg.pdu_session_establishment_reject.allowedsscmode.is_ssc3_allowed);
		printf("eapmessage buffer:0x%x 0x%x\n",(unsigned char)(nas_msg.plain.sm.specific_msg.pdu_session_establishment_reject.eapmessage->data[0]),(unsigned char )(nas_msg.plain.sm.specific_msg.pdu_session_establishment_reject.eapmessage->data[1]));
		printf("extend_options buffer:0x%x 0x%x 0x%x 0x%x\n",(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_establishment_reject.extendedprotocolconfigurationoptions)->data[0]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_establishment_reject.extendedprotocolconfigurationoptions)->data[1]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_establishment_reject.extendedprotocolconfigurationoptions)->data[2]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_establishment_reject.extendedprotocolconfigurationoptions)->data[3]));
		printf("_5gsmcongestionreattemptindicator bits_1 --- abo:0x%x\n",nas_msg.plain.sm.specific_msg.pdu_session_establishment_reject._5gsmcongestionreattemptindicator.abo);
		printf("PDU_SESSION_ESTABLISHMENT_REJECT------------ end\n");
		break;
	case PDU_SESSION_AUTHENTICATION_COMMAND:
		printf("PDU_SESSION_AUTHENTICATION_COMMAND------------ start\n");
		printf("sm header,extended_protocol_discriminator:0x%x,pdu_session_identity:0x%x,procedure_transaction_identity:0x%x, message type:0x%x\n", nas_msg.plain.sm.header.extended_protocol_discriminator,nas_msg.plain.sm.header.pdu_session_identity,nas_msg.plain.sm.header.procedure_transaction_identity,nas_msg.plain.sm.header.message_type);
		printf("eapmessage buffer:0x%x 0x%x\n",(unsigned char)(nas_msg.plain.sm.specific_msg.pdu_session_authentication_command.eapmessage->data[0]),(unsigned char )(nas_msg.plain.sm.specific_msg.pdu_session_authentication_command.eapmessage->data[1]));
		printf("extend_options buffer:0x%x 0x%x 0x%x 0x%x\n",(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_authentication_command.extendedprotocolconfigurationoptions)->data[0]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_authentication_command.extendedprotocolconfigurationoptions)->data[1]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_authentication_command.extendedprotocolconfigurationoptions)->data[2]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_authentication_command.extendedprotocolconfigurationoptions)->data[3]));
		printf("PDU_SESSION_AUTHENTICATION_COMMAND------------ end\n");
		break;
	case PDU_SESSION_AUTHENTICATION_COMPLETE:
		printf("PDU_SESSION_AUTHENTICATION_COMPLETE------------ start\n");
		printf("sm header,extended_protocol_discriminator:0x%x,pdu_session_identity:0x%x,procedure_transaction_identity:0x%x, message type:0x%x\n", nas_msg.plain.sm.header.extended_protocol_discriminator,nas_msg.plain.sm.header.pdu_session_identity,nas_msg.plain.sm.header.procedure_transaction_identity,nas_msg.plain.sm.header.message_type);
		printf("eapmessage buffer:0x%x 0x%x\n",(unsigned char)(nas_msg.plain.sm.specific_msg.pdu_session_authentication_complete.eapmessage->data[0]),(unsigned char )(nas_msg.plain.sm.specific_msg.pdu_session_authentication_complete.eapmessage->data[1]));
		printf("extend_options buffer:0x%x 0x%x 0x%x 0x%x\n",(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_authentication_complete.extendedprotocolconfigurationoptions)->data[0]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_authentication_complete.extendedprotocolconfigurationoptions)->data[1]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_authentication_complete.extendedprotocolconfigurationoptions)->data[2]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_authentication_complete.extendedprotocolconfigurationoptions)->data[3]));
		printf("PDU_SESSION_AUTHENTICATION_COMPLETE------------ end\n");
		break;
	case PDU_SESSION_AUTHENTICATION_RESULT:
		printf("PDU_SESSION_AUTHENTICATION_RESULT------------ start\n");
		printf("sm header,extended_protocol_discriminator:0x%x,pdu_session_identity:0x%x,procedure_transaction_identity:0x%x, message type:0x%x\n", nas_msg.plain.sm.header.extended_protocol_discriminator,nas_msg.plain.sm.header.pdu_session_identity,nas_msg.plain.sm.header.procedure_transaction_identity,nas_msg.plain.sm.header.message_type);
		printf("eapmessage buffer:0x%x 0x%x\n",(unsigned char)(nas_msg.plain.sm.specific_msg.pdu_session_authentication_result.eapmessage->data[0]),(unsigned char )(nas_msg.plain.sm.specific_msg.pdu_session_authentication_result.eapmessage->data[1]));
		printf("extend_options buffer:0x%x 0x%x 0x%x 0x%x\n",(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_authentication_result.extendedprotocolconfigurationoptions)->data[0]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_authentication_result.extendedprotocolconfigurationoptions)->data[1]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_authentication_result.extendedprotocolconfigurationoptions)->data[2]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_authentication_result.extendedprotocolconfigurationoptions)->data[3]));
		printf("PDU_SESSION_AUTHENTICATION_RESULT------------ end\n");
		break;
	case PDU_SESSION_MODIFICATION_REQUEST:
		printf("PDU_SESSION_MODIFICATION_REQUEST------------ start\n");
		printf("sm header,extended_protocol_discriminator:0x%x,pdu_session_identity:0x%x,procedure_transaction_identity:0x%x, message type:0x%x\n", nas_msg.plain.sm.header.extended_protocol_discriminator,nas_msg.plain.sm.header.pdu_session_identity,nas_msg.plain.sm.header.procedure_transaction_identity,nas_msg.plain.sm.header.message_type);

		printf("PDU_SESSION_MODIFICATION_REQUEST------------ end\n");
		break;
	case PDU_SESSION_MODIFICATION_REJECT:
		printf("PDU_SESSION_MODIFICATION_REJECT------------ start\n");
		printf("sm header,extended_protocol_discriminator:0x%x,pdu_session_identity:0x%x,procedure_transaction_identity:0x%x, message type:0x%x\n", nas_msg.plain.sm.header.extended_protocol_discriminator,nas_msg.plain.sm.header.pdu_session_identity,nas_msg.plain.sm.header.procedure_transaction_identity,nas_msg.plain.sm.header.message_type);
		printf("_5gsmcause: 0x%x\n",nas_msg.plain.sm.specific_msg.pdu_session_modification_reject._5gsmcause);
		printf("gprstimer3 --- unit_bits_H3: 0x%x,timeValue_bits_L5: 0x%x\n",nas_msg.plain.sm.specific_msg.pdu_session_modification_reject.gprstimer3.unit,nas_msg.plain.sm.specific_msg.pdu_session_modification_reject.gprstimer3.timeValue);
		printf("extend_options buffer:0x%x 0x%x 0x%x 0x%x\n",(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_modification_reject.extendedprotocolconfigurationoptions)->data[0]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_modification_reject.extendedprotocolconfigurationoptions)->data[1]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_modification_reject.extendedprotocolconfigurationoptions)->data[2]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_modification_reject.extendedprotocolconfigurationoptions)->data[3]));
		printf("_5gsmcongestionreattemptindicator bits_1 --- abo:0x%x\n",nas_msg.plain.sm.specific_msg.pdu_session_modification_reject._5gsmcongestionreattemptindicator.abo);
		printf("PDU_SESSION_MODIFICATION_REJECT------------ end\n");
		break;
	case PDU_SESSION_MODIFICATION_COMMAND:
		printf("PDU_SESSION_MODIFICATION_COMMAND------------ start\n");
		printf("sm header,extended_protocol_discriminator:0x%x,pdu_session_identity:0x%x,procedure_transaction_identity:0x%x, message type:0x%x\n", nas_msg.plain.sm.header.extended_protocol_discriminator,nas_msg.plain.sm.header.pdu_session_identity,nas_msg.plain.sm.header.procedure_transaction_identity,nas_msg.plain.sm.header.message_type);

		printf("PDU_SESSION_MODIFICATION_COMMAND------------ end\n");
		break;
	case PDU_SESSION_MODIFICATION_COMPLETE:
		printf("PDU_SESSION_MODIFICATION_COMPLETE------------ start\n");
		printf("sm header,extended_protocol_discriminator:0x%x,pdu_session_identity:0x%x,procedure_transaction_identity:0x%x, message type:0x%x\n", nas_msg.plain.sm.header.extended_protocol_discriminator,nas_msg.plain.sm.header.pdu_session_identity,nas_msg.plain.sm.header.procedure_transaction_identity,nas_msg.plain.sm.header.message_type);
		printf("extend_options buffer:0x%x 0x%x 0x%x 0x%x\n",(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_modification_complete.extendedprotocolconfigurationoptions)->data[0]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_modification_complete.extendedprotocolconfigurationoptions)->data[1]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_modification_complete.extendedprotocolconfigurationoptions)->data[2]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_modification_complete.extendedprotocolconfigurationoptions)->data[3]));
		printf("PDU_SESSION_MODIFICATION_COMPLETE------------ end\n");
		break;
	case PDU_SESSION_MODIFICATION_COMMANDREJECT:
		printf("PDU_SESSION_MODIFICATION_COMMANDREJECT------------ start\n");
		printf("sm header,extended_protocol_discriminator:0x%x,pdu_session_identity:0x%x,procedure_transaction_identity:0x%x, message type:0x%x\n", nas_msg.plain.sm.header.extended_protocol_discriminator,nas_msg.plain.sm.header.pdu_session_identity,nas_msg.plain.sm.header.procedure_transaction_identity,nas_msg.plain.sm.header.message_type);
		printf("_5gsmcause: 0x%x\n",nas_msg.plain.sm.specific_msg.pdu_session_modification_command_reject._5gsmcause);
		printf("extend_options buffer:0x%x 0x%x 0x%x 0x%x\n",(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_modification_command_reject.extendedprotocolconfigurationoptions)->data[0]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_modification_command_reject.extendedprotocolconfigurationoptions)->data[1]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_modification_command_reject.extendedprotocolconfigurationoptions)->data[2]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_modification_command_reject.extendedprotocolconfigurationoptions)->data[3]));
		printf("PDU_SESSION_MODIFICATION_COMMANDREJECT------------ end\n");
		break;
	case PDU_SESSION_RELEASE_REQUEST:
		printf("PDU_SESSION_RELEASE_REQUEST------------ start\n");
		printf("sm header,extended_protocol_discriminator:0x%x,pdu_session_identity:0x%x,procedure_transaction_identity:0x%x, message type:0x%x\n", nas_msg.plain.sm.header.extended_protocol_discriminator,nas_msg.plain.sm.header.pdu_session_identity,nas_msg.plain.sm.header.procedure_transaction_identity,nas_msg.plain.sm.header.message_type);
		printf("_5gsmcause: 0x%x\n",nas_msg.plain.sm.specific_msg.pdu_session_release_request._5gsmcause);
		printf("extend_options buffer:0x%x 0x%x 0x%x 0x%x\n",(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_release_request.extendedprotocolconfigurationoptions)->data[0]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_release_request.extendedprotocolconfigurationoptions)->data[1]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_release_request.extendedprotocolconfigurationoptions)->data[2]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_release_request.extendedprotocolconfigurationoptions)->data[3]));
		printf("PDU_SESSION_RELEASE_REQUEST------------ end\n");
		break;
	case PDU_SESSION_RELEASE_REJECT:
		printf("PDU_SESSION_RELEASE_REJECT------------ start\n");
		printf("sm header,extended_protocol_discriminator:0x%x,pdu_session_identity:0x%x,procedure_transaction_identity:0x%x, message type:0x%x\n", nas_msg.plain.sm.header.extended_protocol_discriminator,nas_msg.plain.sm.header.pdu_session_identity,nas_msg.plain.sm.header.procedure_transaction_identity,nas_msg.plain.sm.header.message_type);
		printf("_5gsmcause: 0x%x\n",nas_msg.plain.sm.specific_msg.pdu_session_release_reject._5gsmcause);
		printf("extend_options buffer:0x%x 0x%x 0x%x 0x%x\n",(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_release_reject.extendedprotocolconfigurationoptions)->data[0]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_release_reject.extendedprotocolconfigurationoptions)->data[1]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_release_reject.extendedprotocolconfigurationoptions)->data[2]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_release_reject.extendedprotocolconfigurationoptions)->data[3]));
		printf("PDU_SESSION_RELEASE_REJECT------------ end\n");
		break;
	case PDU_SESSION_RELEASE_COMMAND:
		printf("PDU_SESSION_RELEASE_COMMAND------------ start\n");
		printf("sm header,extended_protocol_discriminator:0x%x,pdu_session_identity:0x%x,procedure_transaction_identity:0x%x, message type:0x%x\n", nas_msg.plain.sm.header.extended_protocol_discriminator,nas_msg.plain.sm.header.pdu_session_identity,nas_msg.plain.sm.header.procedure_transaction_identity,nas_msg.plain.sm.header.message_type);
		printf("_5gsmcause: 0x%x\n",nas_msg.plain.sm.specific_msg.pdu_session_release_command._5gsmcause);
		printf("gprstimer3 --- unit_bits_H3: 0x%x,timeValue_bits_L5: 0x%x\n",nas_msg.plain.sm.specific_msg.pdu_session_release_command.gprstimer3.unit,nas_msg.plain.sm.specific_msg.pdu_session_release_command.gprstimer3.timeValue);
		printf("eapmessage buffer:0x%x 0x%x\n",(unsigned char)(nas_msg.plain.sm.specific_msg.pdu_session_release_command.eapmessage->data[0]),(unsigned char )(nas_msg.plain.sm.specific_msg.pdu_session_release_command.eapmessage->data[1]));
		printf("_5gsmcongestionreattemptindicator bits_1 --- abo:0x%x\n",nas_msg.plain.sm.specific_msg.pdu_session_release_command._5gsmcongestionreattemptindicator.abo);
		printf("extend_options buffer:0x%x 0x%x 0x%x 0x%x\n",(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_release_command.extendedprotocolconfigurationoptions)->data[0]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_release_command.extendedprotocolconfigurationoptions)->data[1]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_release_command.extendedprotocolconfigurationoptions)->data[2]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_release_command.extendedprotocolconfigurationoptions)->data[3]));
		printf("PDU_SESSION_RELEASE_COMMAND------------ end\n");
		break;
	case PDU_SESSION_RELEASE_COMPLETE:
		printf("PDU_SESSION_RELEASE_COMPLETE------------ start\n");
		printf("sm header,extended_protocol_discriminator:0x%x,pdu_session_identity:0x%x,procedure_transaction_identity:0x%x, message type:0x%x\n", nas_msg.plain.sm.header.extended_protocol_discriminator,nas_msg.plain.sm.header.pdu_session_identity,nas_msg.plain.sm.header.procedure_transaction_identity,nas_msg.plain.sm.header.message_type);
		printf("_5gsmcause: 0x%x\n",nas_msg.plain.sm.specific_msg.pdu_session_release_complete._5gsmcause);
		printf("extend_options buffer:0x%x 0x%x 0x%x 0x%x\n",(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_release_complete.extendedprotocolconfigurationoptions)->data[0]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_release_complete.extendedprotocolconfigurationoptions)->data[1]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_release_complete.extendedprotocolconfigurationoptions)->data[2]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_release_complete.extendedprotocolconfigurationoptions)->data[3]));
		printf("PDU_SESSION_RELEASE_COMPLETE------------ end\n");
		break;
	case _5GSM_STATUS:
		printf("_5GSM_STAUS------------ start\n");
		printf("sm header,extended_protocol_discriminator:0x%x,pdu_session_identity:0x%x,procedure_transaction_identity:0x%x, message type:0x%x\n", nas_msg.plain.sm.header.extended_protocol_discriminator,nas_msg.plain.sm.header.pdu_session_identity,nas_msg.plain.sm.header.procedure_transaction_identity,nas_msg.plain.sm.header.message_type);
		printf("_5gsmcause: 0x%x\n",nas_msg.plain.sm.specific_msg._5gsm_status._5gsmcause);
		printf("_5GSM_STAUS------------ end\n");
		break;

	}



	return decoder_rc;
}
