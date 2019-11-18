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
   \date 2018
   \email: lionel.gauthier@eurecom.fr, tien-thinh.nguyen@eurecom.fr
*/
#include "smf_app.hpp"
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
#include "../NgapSmfLayer/ng_pdu_session_resource_setup_request.h"
#include "../NgapSmfLayer/ng_pdu_session_resource_setup_response.h"
#include "../NgapSmfLayer/ng_pdu_session_resource_release_command.h"
#include "../NgapSmfLayer/ng_pdu_session_resource_release_response.h"
#include "../NgapSmfLayer/ng_pdu_session_resource_modify_request.h"
#include "../NgapSmfLayer/ng_pdu_session_resource_modify_response.h"
#include "../NgapSmfLayer/ng_pdu_session_resource_notify.h"
#include "../NgapSmfLayer/ng_pdu_session_resource_modify_indication.h"
#include "../NgapSmfLayer/ng_pdu_session_resource_modify_confirm.h"
#include "../NgapSmfLayer/ng_pdu_handover_required.h"
#include "../NgapSmfLayer/ng_pdu_handover_command.h"
#include "../NgapSmfLayer/ng_pdu_handover_preparation_failure.h"
#include "../NgapSmfLayer/ng_pdu_handover_request_acknowledge.h"
#include "../NgapSmfLayer/ng_pdu_handover_failure.h"
#include "../NgapSmfLayer/ng_pdu_handover_notify.h"
}

#include <stdexcept>
#include <iostream>
#include <cstdlib>

#define BUF_LEN 512

using namespace smf;

#define SYSTEM_CMD_MAX_STR_SIZE 512
extern util::async_shell_cmd *async_shell_cmd_inst;
extern smf_app *smf_app_inst;
extern smf_config smf_cfg;
smf_n4 *smf_n4_inst = nullptr;
smf_n10 *smf_n10_inst = nullptr;
smf_n11 *smf_n11_inst = nullptr;
extern itti_mw *itti_inst;

void smf_app_task (void*);

//------------------------------------------------------------------------------
int smf_app::apply_config (const smf_config& cfg)
{
  Logger::smf_app().info("Apply config...");

  for (int ia = 0; ia < cfg.num_apn; ia++) {
    if (cfg.apn[ia].pool_id_iv4 >= 0) {
      int pool_id = cfg.apn[ia].pool_id_iv4;
      int range = be32toh(cfg.ue_pool_range_high[pool_id].s_addr) - be32toh(cfg.ue_pool_range_low[pool_id].s_addr) ;
      paa_dynamic::get_instance().add_pool(cfg.apn[ia].apn, pool_id, cfg.ue_pool_range_low[pool_id], range);
      //TODO: check with apn_label
      Logger::smf_app().info("Applied config %s", cfg.apn[ia].apn.c_str());
    }
    if (cfg.apn[ia].pool_id_iv6 >= 0) {
      int pool_id = cfg.apn[ia].pool_id_iv6;
      paa_dynamic::get_instance().add_pool(cfg.apn[ia].apn, pool_id, cfg.paa_pool6_prefix[pool_id], cfg.paa_pool6_prefix_len[pool_id]);
      //TODO: check with apn_label
    }
  }

  Logger::smf_app().info("Applied config");
  return RETURNok;
}

//------------------------------------------------------------------------------
uint64_t smf_app::generate_seid() {
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
bool smf_app::is_seid_n4_exist(const uint64_t& seid) const
{
  return bool{set_seid_n4.count(seid) > 0};
}

//------------------------------------------------------------------------------
void smf_app::free_seid_n4(const uint64_t& seid)
{
	std::unique_lock<std::mutex> ls(m_seid_n4_generator);
	set_seid_n4.erase (seid);
	ls.unlock();
}

//------------------------------------------------------------------------------
void smf_app::set_seid_2_smf_context(const seid_t& seid, std::shared_ptr<smf_context>& pc)
{
  std::unique_lock lock(m_seid2smf_context);
  seid2smf_context[seid] = pc;
}

//------------------------------------------------------------------------------
bool smf_app::seid_2_smf_context(const seid_t& seid, std::shared_ptr<smf_context>& pc) const
{
  std::shared_lock lock(m_seid2smf_context);
  std::map<seid_t, std::shared_ptr<smf_context>>::const_iterator it = seid2smf_context.find(seid);
  if (it != seid2smf_context.end()) {
    pc = it->second;
    return true;
  }
  return false;
}

//------------------------------------------------------------------------------
void smf_app::delete_smf_context(std::shared_ptr<smf_context> spc)
{
  supi64_t supi64 = smf_supi_to_u64(spc.get()->supi);
  std::unique_lock lock(m_supi2smf_context);
  supi2smf_context.erase(supi64);
}

//------------------------------------------------------------------------------
void smf_app::restore_sx_sessions(const seid_t& seid) const
{
  std::shared_lock lock(m_seid2smf_context);
  //TODO
}

//------------------------------------------------------------------------------
void smf_app_task (void*)
{
  const task_id_t task_id = TASK_SMF_APP;
  itti_inst->notify_task_ready(task_id);

  do {
    std::shared_ptr<itti_msg> shared_msg = itti_inst->receive_msg(task_id);
    auto *msg = shared_msg.get();
    switch (msg->msg_type) {

    case N4_SESSION_ESTABLISHMENT_RESPONSE:
      if (itti_n4_session_establishment_response* m = dynamic_cast<itti_n4_session_establishment_response*>(msg)) {
        smf_app_inst->handle_itti_msg(std::ref(*m));
      }
      break;

    case N4_SESSION_MODIFICATION_RESPONSE:
      if (itti_n4_session_modification_response* m = dynamic_cast<itti_n4_session_modification_response*>(msg)) {
        smf_app_inst->handle_itti_msg(std::ref(*m));
      }
      break;

    case N4_SESSION_DELETION_RESPONSE:
      if (itti_n4_session_deletion_response* m = dynamic_cast<itti_n4_session_deletion_response*>(msg)) {
        smf_app_inst->handle_itti_msg(std::ref(*m));
      }
      break;

    case N4_SESSION_REPORT_REQUEST:
      smf_app_inst->handle_itti_msg(std::static_pointer_cast<itti_n4_session_report_request>(shared_msg));
      break;

    case TIME_OUT:
      if (itti_msg_timeout* to = dynamic_cast<itti_msg_timeout*>(msg)) {
        Logger::smf_app().info( "TIME-OUT event timer id %d", to->timer_id);
      }
      break;
    case TERMINATE:
      if (itti_msg_terminate *terminate = dynamic_cast<itti_msg_terminate*>(msg)) {
        Logger::smf_app().info( "Received terminate message");
        return;
      }
    case HEALTH_PING:
      break;
    default:
      Logger::smf_app().info( "no handler for msg type %d", msg->msg_type);
    }
  } while (true);
}

//------------------------------------------------------------------------------
smf_app::smf_app (const std::string& config_file) : m_seid2smf_context()
{
  Logger::smf_app().startup("Starting...");

  supi2smf_context = {};
  set_seid_n4 = {};

  apply_config (smf_cfg);

  if (itti_inst->create_task(TASK_SMF_APP, smf_app_task, nullptr) ) {
    Logger::smf_app().error( "Cannot create task TASK_SMF_APP" );
    throw std::runtime_error( "Cannot create task TASK_SMF_APP" );
  }

  try {
    smf_n4_inst = new smf_n4();
    smf_n10_inst = new smf_n10();
    smf_n11_inst = new smf_n11();
  } catch (std::exception& e) {
    Logger::smf_app().error( "Cannot create SMF_APP: %s", e.what() );
    throw;
  }

  Logger::smf_app().startup( "Started" );
}

//------------------------------------------------------------------------------
void smf_app::handle_itti_msg (itti_n4_session_establishment_response& seresp)
{
  std::shared_ptr<smf_context> pc = {};
  if (seid_2_smf_context(seresp.seid, pc)) {
    pc.get()->handle_itti_msg(seresp);
  } else {
    Logger::smf_app().debug("Received N4 SESSION ESTABLISHMENT RESPONSE seid" TEID_FMT "  pfcp_tx_id %" PRIX64", smf_context not found, discarded!", seresp.seid, seresp.trxn_id);
  }
}

//------------------------------------------------------------------------------
void smf_app::handle_itti_msg (itti_n4_session_modification_response& smresp)
{
  std::shared_ptr<smf_context> pc = {};
  if (seid_2_smf_context(smresp.seid, pc)) {
    pc.get()->handle_itti_msg(smresp);
  } else {
    Logger::smf_app().debug("Received N4 SESSION MODIFICATION RESPONSE seid" TEID_FMT "  pfcp_tx_id %" PRIX64", smf_context not found, discarded!", smresp.seid, smresp.trxn_id);
  }
}

//------------------------------------------------------------------------------
void smf_app::handle_itti_msg (itti_n4_session_deletion_response& smresp)
{
  std::shared_ptr<smf_context> pc = {};
  if (seid_2_smf_context(smresp.seid, pc)) {
    pc.get()->handle_itti_msg(smresp);

    if (pc->dnns.size() == 0) {
      delete_smf_context(pc);
    }
  } else {
    Logger::smf_app().debug("Received N4 SESSION DELETION RESPONSE seid" TEID_FMT "  pfcp_tx_id %" PRIX64", smf_context not found, discarded!", smresp.seid, smresp.trxn_id);
  }
}

//------------------------------------------------------------------------------
void smf_app::handle_itti_msg (std::shared_ptr<itti_n4_session_report_request> snr)
{
  std::shared_ptr<smf_context> pc = {};
  if (seid_2_smf_context(snr->seid, pc)) {
    pc.get()->handle_itti_msg(snr);
  } else {
    Logger::smf_app().debug("Received N4 SESSION REPORT REQUEST seid" TEID_FMT "  pfcp_tx_id %" PRIX64", smf_context not found, discarded!", snr->seid, snr->trxn_id);
  }
}

//------------------------------------------------------------------------------
void smf_app::handle_amf_msg (std::shared_ptr<itti_n11_create_sm_context_request> smreq)
{
	//handle PDU Session Create SM Context Request as specified in section 4.3.2 3GPP TS 23.502
	oai::smf_server::model::SmContextCreateError smContextCreateError;
	oai::smf_server::model::ProblemDetails problem_details;
	oai::smf_server::model::RefToBinaryData binary_data;
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

	Logger::smf_app().info("Handle a PDU Session Create SM Context Request message from AMF, supi " SUPI_64_FMT ", dnn %s, snssai_sst %d", supi64, dnn.c_str(), snssai.sST );

	//check pti
	if ((pti.procedure_transaction_id == PROCEDURE_TRANSACTION_IDENTITY_UNASSIGNED) || (pti.procedure_transaction_id > PROCEDURE_TRANSACTION_IDENTITY_LAST)){
		Logger::smf_app().warn(" Invalid PTI value (pti = %d)\n", pti.procedure_transaction_id);
		problem_details.setCause(pdu_session_application_error_e2str[PDU_SESSION_APPLICATION_ERROR_N1_SM_ERROR]);
		smContextCreateError.setError(problem_details);

		//PDU Session Establishment Reject
		//(24.501 (section 7.3.1)) NAS N1 SM message: response with a 5GSM STATUS message including cause "#81 Invalid PTI value"
		smf_app_inst->create_n1_sm_container(smreq, PDU_SESSION_ESTABLISHMENT_REJECT, n1_container, 81); //TODO: should define 5GSM cause in 24.501
		binary_data.setContentId(n1_container);
		smContextCreateError.setN1SmMsg(binary_data);
		//Send response to AMF
		send_create_session_response(smreq->http_response, smContextCreateError, Pistache::Http::Code::Forbidden);
	}

	//check pdu session id
	if ((pdu_session_id == PDU_SESSION_IDENTITY_UNASSIGNED) || (pdu_session_id > PDU_SESSION_IDENTITY_LAST)){
		Logger::smf_app().warn(" Invalid PDU Session ID value (psi = %d)\n", pdu_session_id);
		//TODO: (24.501 (section 7.3.2)) NAS N1 SM message: ignore the message
		//return;
	}

	//check message type
	if (message_type != PDU_SESSION_ESTABLISHMENT_REQUEST) {
		Logger::smf_app().warn("Invalid message type (message type = %d)\n", message_type);
		//TODO:
		problem_details.setCause(pdu_session_application_error_e2str[PDU_SESSION_APPLICATION_ERROR_N1_SM_ERROR]);
		smContextCreateError.setError(problem_details);

		//PDU Session Establishment Reject
		//(24.501 (section 7.4)) implementation dependent->do similar to UE: response with a 5GSM STATUS message including cause "#98 message type not compatible with protocol state."
		smf_app_inst->create_n1_sm_container(smreq, PDU_SESSION_ESTABLISHMENT_REJECT, n1_container, 98); //TODO: should define 5GSM cause in 24.501
		binary_data.setContentId(n1_container);
		smContextCreateError.setN1SmMsg(binary_data);
		//Send response to AMF
		send_create_session_response(smreq->http_response, smContextCreateError, Pistache::Http::Code::Forbidden);
	}

	//check request type
	if ((request_type & 0x07) != INITIAL_REQUEST){
		Logger::smf_app().warn("Invalid request type (request type = %s)\n", request_type_e2str[request_type & 0x07]);
		//TODO:
		//return
	}

	//Step 2. check if the DNN requested is valid
	if (not smf_cfg.is_dotted_dnn_handled(dnn, pdu_session_type)) {
		// Not a valid request...
		Logger::smf_app().warn("Received PDU_SESSION_CREATESMCONTEXT_REQUEST unknown requested APN %s, ignore message!", dnn.c_str());
		problem_details.setCause(pdu_session_application_error_e2str[PDU_SESSION_APPLICATION_ERROR_DNN_DENIED]);
		smContextCreateError.setError(problem_details);
		//PDU Session Establishment Reject
		//(24.501 cause "#27 Missing or unknown DNN"
		smf_app_inst->create_n1_sm_container(smreq, PDU_SESSION_ESTABLISHMENT_REJECT, n1_container, 27); //TODO: should define 5GSM cause in 24.501
		binary_data.setContentId(n1_container);
		smContextCreateError.setN1SmMsg(binary_data);
		//Send response to AMF
		send_create_session_response(smreq->http_response, smContextCreateError, Pistache::Http::Code::Forbidden);
		return;
	}

	//Step 3. create a context for this supi if not existed, otherwise update
	std::shared_ptr<smf_context> sc;
	if (is_supi_2_smf_context(supi64)) {
		Logger::smf_app().debug("Update SMF context with SUPI " SUPI_64_FMT "", supi64);
		sc = supi_2_smf_context(supi64);
	} else {
		Logger::smf_app().debug("Create a new SMF context with SUPI " SUPI_64_FMT "", supi64);
		sc = std::shared_ptr<smf_context>(new smf_context());
		set_supi_2_smf_context(supi64, sc);
	}

	//update context with dnn information
	std::shared_ptr<dnn_context> sd;

	if (!sc.get()->find_dnn_context(dnn, sd)) {
		if (nullptr == sd.get()){
			//create a new one and insert to the list
			Logger::smf_app().debug("Create a DNN context and add to the SMF context\n");
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
		Logger::smf_app().debug("Retrieve Session Management Subscription data from UDM");
	        session_management_subscription* s=  new session_management_subscription (snssai);
         	std::shared_ptr<session_management_subscription> subscription = std::shared_ptr<session_management_subscription>(s);
		//std::shared_ptr<session_management_subscription> subscription = std::make_shared<session_management_subscription>(snssai);
		//std::shared_ptr<session_management_subscription> subscription = std::shared_ptr<session_management_subscription>(new session_management_subscription (snssai));
		if (smf_n10_inst->get_sm_data(supi64, dnn, snssai, subscription)) {
			Logger::smf_app().debug("Update DNN subscription info");
			//update dnn_context with subscription info
			sc.get()->insert_dnn_subscription(snssai, subscription);
		} else {
			// Not accept to establish a PDU session
			Logger::smf_app().warn("Received PDU_SESSION_CREATESMCONTEXT_REQUEST, couldn't retrieve the Session Management Subscription from UDM, ignore message!");
			problem_details.setCause(pdu_session_application_error_e2str[PDU_SESSION_APPLICATION_ERROR_SUBSCRIPTION_DENIED]);
			smContextCreateError.setError(problem_details);
			//PDU Session Establishment Reject
			//24.501 which cause should be use "29 User authentication or authorization failed"?
			smf_app_inst->create_n1_sm_container(smreq, PDU_SESSION_ESTABLISHMENT_REJECT, n1_container, 29); //TODO: should define 5GSM cause in 24.501
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
bool smf_app::is_supi_2_smf_context(const supi64_t& supi) const
{
	std::shared_lock lock(m_supi2smf_context);
	return bool{supi2smf_context.count(supi) > 0 };
}

//------------------------------------------------------------------------------
std::shared_ptr<smf_context>  smf_app::supi_2_smf_context(const supi64_t& supi) const
{
	std::shared_lock lock(m_supi2smf_context);
	return supi2smf_context.at(supi);
}

//------------------------------------------------------------------------------
void smf_app::set_supi_2_smf_context(const supi64_t& supi, std::shared_ptr<smf_context> sc)
{
    std::shared_lock lock(m_supi2smf_context);
    supi2smf_context[supi] = sc;
}

//------------------------------------------------------------------------------
bool smf_app::use_local_configuration_subscription_data(const std::string& dnn_selection_mode)
{
	//TODO: should be implemented
	return false; //get Session Management Subscription from UDM
}

//------------------------------------------------------------------------------
bool smf_app::is_supi_dnn_snssai_subscription_data(supi_t& supi, std::string& dnn, snssai_t& snssai)
{
	//TODO: should be implemented
	return false; //Session Management Subscription from UDM isn't available
}

//------------------------------------------------------------------------------
bool smf_app::is_create_sm_context_request_valid()
{
	//TODO: should be implemented
	return true;

}

//------------------------------------------------------------------------------
void smf_app::send_create_session_response(Pistache::Http::ResponseWriter& httpResponse, oai::smf_server::model::SmContextCreateError& smContextCreateError, Pistache::Http::Code code)
{
	//Send reply to AMF
	nlohmann::json jsonData;
	to_json(jsonData, smContextCreateError);
	std::string resBody = jsonData.dump();

	//httpResponse.headers().add<Pistache::Http::Header::Location>(url);
	httpResponse.send(code, resBody);
}

//------------------------------------------------------------------------------
void smf_app::create_n1_sm_container(std::shared_ptr<itti_n11_create_sm_context_response> sm_context_res, uint8_t msg_type, std::string& nas_msg_str, uint8_t sm_cause)
{
	//TODO: should work with BUPT to finish this function
	Logger::smf_app().info("Create N1 SM Container, message type %d \n", msg_type);
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


	SM_msg *sm_msg;
	sm_msg = &nas_msg.security_protected.plain.sm;
	sm_msg->header.extended_protocol_discriminator = EPD_5GS_SESSION_MANAGEMENT_MESSAGES;
	sm_msg->header.pdu_session_identity = sm_context_res->res.get_pdu_session_id();
	sm_msg->header.procedure_transaction_identity = 1;//TODO: to be updated

	switch (msg_type){

	case PDU_SESSION_ESTABLISHMENT_ACCEPT: {
		//get the default QoS profile and assign to the NAS message
		supi_t supi =  sm_context_res->res.get_supi();
		supi64_t supi64 = smf_supi_to_u64(supi);
		std::shared_ptr<smf_context> sc;
		if (is_supi_2_smf_context(supi64)) {
			Logger::smf_app().debug("Get SMF context with SUPI " SUPI_64_FMT "", supi64);
			sc = supi_2_smf_context(supi64);
		}
		if (nullptr != sc.get()){
			
			std::shared_ptr<session_management_subscription> ss;
			std::shared_ptr<dnn_configuration_t> sdc;
			sc.get()->find_dnn_subscription(sm_context_res->res.get_snssai(), ss);
			if (nullptr != ss.get()){
				ss.get()->find_dnn_configuration(sm_context_res->res.get_dnn(), sdc);
				if (nullptr != sdc.get()){
					//TODO: assign to QoS profile sdc.get()->_5g_qos_profile;
				}
			}


		}

		//FROM BUPT-TEST (GITHUB)


		printf("PDU_SESSION_ESTABLISHMENT_ACCEPT------------ end\n");

	}
	break;

	case PDU_SESSION_ESTABLISHMENT_REJECT: {

		sm_msg->header.message_type = PDU_SESSION_ESTABLISHMENT_REJECT;
		sm_msg->specific_msg.pdu_session_establishment_reject._5gsmcause = 0b00001000;

		sm_msg->specific_msg.pdu_session_establishment_reject.presence = 0x1f;

		sm_msg->specific_msg.pdu_session_establishment_reject.gprstimer3.unit = GPRSTIMER3_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_1_HOUR;
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

		size += MESSAGE_TYPE_MAXIMUM_LENGTH;

		//memcpy(&nas_msg.plain.sm,&nas_msg.security_protected.plain.sm,sizeof(nas_msg.security_protected.plain.sm));
		nas_msg.plain.sm = *sm_msg;

		//complete sm msg content
		if(size <= 0){
			//return -1;
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



		printf("sm header,extended_protocol_discriminator:0x%x,pdu_session_identity:0x%x,proeduer_transaction_identity:0x%x, message type:0x%x\n",
		sm_msg->header.extended_protocol_discriminator,
	    sm_msg->header.pdu_session_identity,
		sm_msg->header.procedure_transaction_identity,
		sm_msg->header.message_type);


		printf("_5gsmcause: 0x%x\n",sm_msg->specific_msg.pdu_session_establishment_reject._5gsmcause);
	    printf("gprstimer3 --- unit_bits_H3: 0x%x,timeValue_bits_L5: 0x%x\n",sm_msg->specific_msg.pdu_session_establishment_reject.gprstimer3.unit,sm_msg->specific_msg.pdu_session_establishment_reject.gprstimer3.timeValue);
		printf("allowedsscmode --- is_ssc1_allowed: 0x%x, is_ssc2_allowed: 0x%x, is_ssc3_allowed: 0x%x\n",sm_msg->specific_msg.pdu_session_establishment_reject.allowedsscmode.is_ssc1_allowed,sm_msg->specific_msg.pdu_session_establishment_reject.allowedsscmode.is_ssc2_allowed,sm_msg->specific_msg.pdu_session_establishment_reject.allowedsscmode.is_ssc3_allowed);
		printf("eapmessage buffer:0x%x 0x%x\n",(unsigned char)(sm_msg->specific_msg.pdu_session_establishment_reject.eapmessage->data[0]),(unsigned char )(sm_msg->specific_msg.pdu_session_establishment_reject.eapmessage->data[1]));
		printf("extend_options buffer:0x%x 0x%x 0x%x 0x%x\n",(unsigned char)((sm_msg->specific_msg.pdu_session_establishment_reject.extendedprotocolconfigurationoptions)->data[0]),(unsigned char)((sm_msg->specific_msg.pdu_session_establishment_reject.extendedprotocolconfigurationoptions)->data[1]),(unsigned char)((sm_msg->specific_msg.pdu_session_establishment_reject.extendedprotocolconfigurationoptions)->data[2]),(unsigned char)((sm_msg->specific_msg.pdu_session_establishment_reject.extendedprotocolconfigurationoptions)->data[3]));
	    printf("_5gsmcongestionreattemptindicator bits_1 --- abo:0x%x\n",sm_msg->specific_msg.pdu_session_establishment_reject._5gsmcongestionreattemptindicator.abo);


		//bytes = nas_message_encode (data, &nas_msg, 60/*don't know the size*/, security);
		bytes = nas_message_encode (data, &nas_msg, sizeof(data)/*don't know the size*/, security);


		//nas_msg_str = reinterpret_cast<char*> (data);
		printf("Data = ");
		for(int i = 0;i<bytes;i++)
			printf("Data = %02x ",data[i]);
		printf("\n");
		std::string n1Message ((char*) data,  bytes);
		nas_msg_str = n1Message;
		Logger::smf_app().debug("n1MessageContent: %d, %s\n ", bytes, nas_msg_str.c_str());


	}

	break;

	default:
		Logger::smf_app().debug("Unknown message type: %d \n", msg_type);
	}
}


void smf_app::create_n1_sm_container(uint8_t msg_type, std::string& nas_msg_str, uint8_t sm_cause)
{
	Logger::smf_app().info("Create N1 SM Container, message type %d \n", msg_type);
	//To be updated according to NAS implementation
	int bytes = 0;
	int length = BUF_LEN;
	unsigned char data[BUF_LEN] = {'\0'};
	memset(data,0,sizeof(data));

	//construct encode security context
	static uint8_t fivegmm_security_context_flag = 0;
	static fivegmm_security_context_t securityencode;
	if(!fivegmm_security_context_flag)
	{
		securityencode.selected_algorithms.encryption = NAS_SECURITY_ALGORITHMS_NEA1;
		securityencode.dl_count.overflow = 0xffff;
		securityencode.dl_count.seq_num =  0x23;
		securityencode.ul_count.overflow = 0xffff;
		securityencode.ul_count.seq_num =  0x23;
		securityencode.knas_enc[0] = 0x14;
		securityencode.selected_algorithms.integrity = NAS_SECURITY_ALGORITHMS_NIA1;
		securityencode.knas_int[0] = 0x41;
		fivegmm_security_context_flag ++;
	}

	nas_message_t nas_msg;
	memset(&nas_msg, 0, sizeof(nas_message_t));
	nas_msg.header.extended_protocol_discriminator = EPD_5GS_SESSION_MANAGEMENT_MESSAGES;
	nas_msg.header.security_header_type = SECURITY_HEADER_TYPE_INTEGRITY_PROTECTED_CYPHERED;
	uint32_t mac = 0xffee;
	
	//test mac and encrypt, please modify here!
	#if DIRECTION__
		nas_msg.header.sequence_number = securityencode.dl_count.seq_num;
	#else
		nas_msg.header.sequence_number = securityencode.ul_count.seq_num;
	#endif
	
	nas_msg.header.message_authentication_code= mac;
	nas_msg.security_protected.header = nas_msg.header;


	SM_msg *sm_msg;
	sm_msg = &nas_msg.security_protected.plain.sm;
	sm_msg->header.extended_protocol_discriminator  = EPD_5GS_SESSION_MANAGEMENT_MESSAGES;

	sm_msg->header.pdu_session_identity = 5;
	sm_msg->header.procedure_transaction_identity = 1; //TODO: to be updated

	switch (msg_type){
	case PDU_SESSION_ESTABLISHMENT_REQUEST: {
		//TODO:
		printf("\n\nPDU_SESSION_ESTABLISHMENT_REQUEST------------ encode start\n");
		sm_msg->header.message_type = PDU_SESSION_ESTABLISHMENT_REQUEST;
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

		nas_msg.plain.sm = *sm_msg;


		printf("[NAS header] extended_protocol_discriminator:0x%x, security_header_type:0x%x,sequence_number:0x%x,message_authentication_code:0x%x\n",
				nas_msg.header.extended_protocol_discriminator,
				nas_msg.header.security_header_type,
				nas_msg.header.sequence_number,
				nas_msg.header.message_authentication_code);

		printf("[SM header] extended_protocol_discriminator:0x%x,pdu_session_identity:0x%x,procedure_transaction_identity:0x%x, message type:0x%x\n",
				sm_msg->header.extended_protocol_discriminator,
				sm_msg->header.pdu_session_identity,
				sm_msg->header.procedure_transaction_identity,
				sm_msg->header.message_type);


		printf("intergrity buffer:0x%x 0x%x\n",(unsigned char)((sm_msg->specific_msg.pdu_session_establishment_request.intergrityprotectionmaximumdatarate)->data[0]),(unsigned char )((sm_msg->specific_msg.pdu_session_establishment_request.intergrityprotectionmaximumdatarate)->data[1]));
		printf("_pdusessiontype bits_3:0x%x\n",sm_msg->specific_msg.pdu_session_establishment_request._pdusessiontype.pdu_session_type_value);
		printf("sscmode bits_3:0x%x\n",sm_msg->specific_msg.pdu_session_establishment_request.sscmode.ssc_mode_value);
		printf("_5gsmcapability bits_5 --- MPTCP:0x%x ATS-LL:0x%x EPT-S1:0x%x MH6-PDU:0x%x RqoS:0x%x\n",sm_msg->specific_msg.pdu_session_establishment_request._5gsmcapability.is_MPTCP_supported,sm_msg->specific_msg.pdu_session_establishment_request._5gsmcapability.is_ATSLL_supported,sm_msg->specific_msg.pdu_session_establishment_request._5gsmcapability.is_EPTS1_supported,sm_msg->specific_msg.pdu_session_establishment_request._5gsmcapability.is_MH6PDU_supported,sm_msg->specific_msg.pdu_session_establishment_request._5gsmcapability.is_Rqos_supported);
		printf("maximum bits_11:0x%x\n",sm_msg->specific_msg.pdu_session_establishment_request.maximumnumberofsupportedpacketfilters);
		printf("Always-on bits_1 --- APSR:0x%x\n",sm_msg->specific_msg.pdu_session_establishment_request.alwaysonpdusessionrequested.apsr_requested);
		printf("sm_pdu_dn buffer:0x%x 0x%x 0x%x\n",(unsigned char)((sm_msg->specific_msg.pdu_session_establishment_request.smpdudnrequestcontainer)->data[0]),(unsigned char)((sm_msg->specific_msg.pdu_session_establishment_request.smpdudnrequestcontainer)->data[1]),(unsigned char)((sm_msg->specific_msg.pdu_session_establishment_request.smpdudnrequestcontainer)->data[2]));
		printf("extend_options buffer:0x%x 0x%x 0x%x 0x%x\n",(unsigned char)((sm_msg->specific_msg.pdu_session_establishment_request.extendedprotocolconfigurationoptions)->data[0]),(unsigned char)((sm_msg->specific_msg.pdu_session_establishment_request.extendedprotocolconfigurationoptions)->data[1]),(unsigned char)((sm_msg->specific_msg.pdu_session_establishment_request.extendedprotocolconfigurationoptions)->data[2]),(unsigned char)((sm_msg->specific_msg.pdu_session_establishment_request.extendedprotocolconfigurationoptions)->data[3]));

		//bytes = nas_message_encode (data, &nas_msg, 60/*don't know the size*/, security);
		bytes = nas_message_encode (data, &nas_msg, sizeof(data)/*don't know the size*/, &securityencode);

		//nas_msg_str = reinterpret_cast<char*> (data);
		printf("Data = ");
		for(int i = 0;i<bytes;i++)
			printf("%02x ",data[i]);
		printf("\n");
		std::string n1Message ((char*) data,  bytes);
		nas_msg_str = n1Message;
		Logger::smf_app().debug("n1MessageContent: %d, %s\n ", bytes, nas_msg_str.c_str());
		
		printf("PDU_SESSION_ESTABLISHMENT_REQUEST------------ encode end\n\n");
	}
	break;


	case PDU_SESSION_ESTABLISHMENT_ACCEPT: {
		//TODO:
		printf("\n\nPDU_SESSION_ESTABLISHMENT_ACCEPT------------ encode start\n");
		sm_msg->header.message_type = PDU_SESSION_ESTABLISHMENT_ACCEPT;


		sm_msg->specific_msg.pdu_session_establishment_accept._pdusessiontype.pdu_session_type_value = 0x01;

		sm_msg->specific_msg.pdu_session_establishment_accept.sscmode.ssc_mode_value = 0x01;


		QOSRulesIE qosrulesie[2];

		qosrulesie[0].qosruleidentifer=0x01;
		qosrulesie[0].ruleoperationcode = CREATE_NEW_QOS_RULE;
		qosrulesie[0].dqrbit = THE_QOS_RULE_IS_DEFAULT_QOS_RULE;
		qosrulesie[0].numberofpacketfilters = 3;

		Create_ModifyAndAdd_ModifyAndReplace create_modifyandadd_modifyandreplace[3];
		create_modifyandadd_modifyandreplace[0].packetfilterdirection = 0b01;
		create_modifyandadd_modifyandreplace[0].packetfilteridentifier = 1;
		/*unsigned char bitStream_packetfiltercontents00[2] = {MATCHALL_TYPE,MATCHALL_TYPE};
		bstring packetfiltercontents00_tmp = bfromcstralloc(2, "\0");
		packetfiltercontents00_tmp->slen = 2;
		memcpy(packetfiltercontents00_tmp->data,bitStream_packetfiltercontents00,sizeof(bitStream_packetfiltercontents00));
		create_modifyandadd_modifyandreplace[0].packetfiltercontents = packetfiltercontents00_tmp;*/
		create_modifyandadd_modifyandreplace[0].packetfiltercontents.component_type = QOS_RULE_MATCHALL_TYPE;
		create_modifyandadd_modifyandreplace[1].packetfilterdirection = 0b10;
		create_modifyandadd_modifyandreplace[1].packetfilteridentifier = 2;
		/*unsigned char bitStream_packetfiltercontents01[2] = {MATCHALL_TYPE,MATCHALL_TYPE};
		bstring packetfiltercontents01_tmp = bfromcstralloc(2, "\0");
		packetfiltercontents01_tmp->slen = 2;
		memcpy(packetfiltercontents01_tmp->data,bitStream_packetfiltercontents01,sizeof(bitStream_packetfiltercontents01));
		create_modifyandadd_modifyandreplace[1].packetfiltercontents = packetfiltercontents01_tmp;*/
		create_modifyandadd_modifyandreplace[1].packetfiltercontents.component_type = QOS_RULE_MATCHALL_TYPE;
		create_modifyandadd_modifyandreplace[2].packetfilterdirection = 0b11;
		create_modifyandadd_modifyandreplace[2].packetfilteridentifier = 3;
		/*unsigned char bitStream_packetfiltercontents02[2] = {MATCHALL_TYPE,MATCHALL_TYPE};
		bstring packetfiltercontents02_tmp = bfromcstralloc(2, "\0");
		packetfiltercontents02_tmp->slen = 2;
		memcpy(packetfiltercontents02_tmp->data,bitStream_packetfiltercontents02,sizeof(bitStream_packetfiltercontents02));
		create_modifyandadd_modifyandreplace[2].packetfiltercontents = packetfiltercontents02_tmp;*/
		create_modifyandadd_modifyandreplace[2].packetfiltercontents.component_type = QOS_RULE_MATCHALL_TYPE;

		qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace = create_modifyandadd_modifyandreplace;

		qosrulesie[0].qosruleprecedence = 1;
		qosrulesie[0].segregation = SEGREGATION_NOT_REQUESTED;
		qosrulesie[0].qosflowidentifer = 0x07;
	/**********************************************************************/
		qosrulesie[1].qosruleidentifer=0x02;
		qosrulesie[1].ruleoperationcode = MODIFY_EXISTING_QOS_RULE_AND_DELETE_PACKET_FILTERS;
		qosrulesie[1].dqrbit = THE_QOS_RULE_IS_NOT_THE_DEFAULT_QOS_RULE;
		qosrulesie[1].numberofpacketfilters = 3;

		ModifyAndDelete modifyanddelete[3];
		modifyanddelete[0].packetfilteridentifier = 1;
		modifyanddelete[1].packetfilteridentifier = 2;
		modifyanddelete[2].packetfilteridentifier = 3;
		qosrulesie[1].packetfilterlist.modifyanddelete = modifyanddelete;

		qosrulesie[1].qosruleprecedence = 1;
		qosrulesie[1].segregation = SEGREGATION_REQUESTED;
		qosrulesie[1].qosflowidentifer = 0x08;


		sm_msg->specific_msg.pdu_session_establishment_accept.qosrules.lengthofqosrulesie = 2;
		sm_msg->specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie = qosrulesie;

		sm_msg->specific_msg.pdu_session_establishment_accept.sessionambr.uint_for_session_ambr_for_downlink = AMBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_1KBPS;
		sm_msg->specific_msg.pdu_session_establishment_accept.sessionambr.session_ambr_for_downlink = (AMBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_4KBPS << 8) + (AMBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_16KBPS);
		sm_msg->specific_msg.pdu_session_establishment_accept.sessionambr.uint_for_session_ambr_for_uplink = AMBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_64KBPS;
		sm_msg->specific_msg.pdu_session_establishment_accept.sessionambr.session_ambr_for_uplink = (AMBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_256KBPS << 8) + (AMBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_1MBPS);

		sm_msg->specific_msg.pdu_session_establishment_accept.presence = 0xffff;

		sm_msg->specific_msg.pdu_session_establishment_accept._5gsmcause = 0b00001000;

		sm_msg->specific_msg.pdu_session_establishment_accept.pduaddress.pdu_session_type_value = PDU_ADDRESS_IPV4;
		unsigned char bitStream_pdu_address_information[4];
		bitStream_pdu_address_information[0] = 0x11;
		bitStream_pdu_address_information[1] = 0x22;
		bitStream_pdu_address_information[2] = 0x33;
		bitStream_pdu_address_information[3] = 0x44;
		bstring pdu_address_information_tmp = bfromcstralloc(4, "\0");
		pdu_address_information_tmp->slen = 4;
		memcpy(pdu_address_information_tmp->data,bitStream_pdu_address_information,sizeof(bitStream_pdu_address_information));
		sm_msg->specific_msg.pdu_session_establishment_accept.pduaddress.pdu_address_information = pdu_address_information_tmp;

		sm_msg->specific_msg.pdu_session_establishment_accept.gprstimer.unit = GPRSTIMER_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_2_SECONDS;
		sm_msg->specific_msg.pdu_session_establishment_accept.gprstimer.timeValue = 0;

		sm_msg->specific_msg.pdu_session_establishment_accept.snssai.len = SST_AND_SD_LENGHT;
		sm_msg->specific_msg.pdu_session_establishment_accept.snssai.sst = 0x66;
		sm_msg->specific_msg.pdu_session_establishment_accept.snssai.sd = 0x123456;

		sm_msg->specific_msg.pdu_session_establishment_accept.alwaysonpdusessionindication.apsi_indication = ALWAYSON_PDU_SESSION_REQUIRED;

		//sm_msg->specific_msg.pdu_session_establishment_accept.mappedepsbearercontexts

		unsigned char bitStream_eapmessage[2] = {0x01,0x02};
	    bstring eapmessage_tmp = bfromcstralloc(2, "\0");
	    eapmessage_tmp->slen = 2;
	    memcpy(eapmessage_tmp->data,bitStream_eapmessage,sizeof(bitStream_eapmessage));
		sm_msg->specific_msg.pdu_session_establishment_accept.eapmessage = eapmessage_tmp;

		QOSFlowDescriptionsContents qosflowdescriptionscontents[3];
		qosflowdescriptionscontents[0].qfi = 1;
		qosflowdescriptionscontents[0].operationcode = CREATE_NEW_QOS_FLOW_DESCRIPTION;
		qosflowdescriptionscontents[0].e = PARAMETERS_LIST_IS_INCLUDED;
		qosflowdescriptionscontents[0].numberofparameters = 3;
		ParametersList parameterslist00[3];
		parameterslist00[0].parameteridentifier = PARAMETER_IDENTIFIER_5QI;
		parameterslist00[0].parametercontents._5qi = 0b01000001;
		parameterslist00[1].parameteridentifier = PARAMETER_IDENTIFIER_GFBR_UPLINK;
		parameterslist00[1].parametercontents.gfbrormfbr_uplinkordownlink.uint = GFBRORMFBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_1KBPS;
		parameterslist00[1].parametercontents.gfbrormfbr_uplinkordownlink.value = 0x1000;
		parameterslist00[2].parameteridentifier = PARAMETER_IDENTIFIER_GFBR_DOWNLINK;
		parameterslist00[2].parametercontents.gfbrormfbr_uplinkordownlink.uint = GFBRORMFBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_4KBPS;
		parameterslist00[2].parametercontents.gfbrormfbr_uplinkordownlink.value = 0x2000;
		qosflowdescriptionscontents[0].parameterslist = parameterslist00;

		qosflowdescriptionscontents[1].qfi = 2;
		qosflowdescriptionscontents[1].operationcode = DELETE_EXISTING_QOS_FLOW_DESCRIPTION;
		qosflowdescriptionscontents[1].e = PARAMETERS_LIST_IS_NOT_INCLUDED;
		qosflowdescriptionscontents[1].numberofparameters = 0;
		qosflowdescriptionscontents[1].parameterslist = NULL;

		qosflowdescriptionscontents[2].qfi = 1;
		qosflowdescriptionscontents[2].operationcode = MODIFY_EXISTING_QOS_FLOW_DESCRIPTION;
		qosflowdescriptionscontents[2].e = REPLACEMENT_OF_ALL_PREVIOUSLY_PROVIDED_PARAMETERS;
		qosflowdescriptionscontents[2].numberofparameters = 4;
		ParametersList parameterslist02[4];
		parameterslist02[0].parameteridentifier = PARAMETER_IDENTIFIER_MFBR_UPLINK;
		parameterslist02[0].parametercontents.gfbrormfbr_uplinkordownlink.uint = GFBRORMFBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_16KBPS;
		parameterslist02[0].parametercontents.gfbrormfbr_uplinkordownlink.value = 0x3000;
		parameterslist02[1].parameteridentifier = PARAMETER_IDENTIFIER_MFBR_DOWNLINK;
		parameterslist02[1].parametercontents.gfbrormfbr_uplinkordownlink.uint = GFBRORMFBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_64KBPS;
		parameterslist02[1].parametercontents.gfbrormfbr_uplinkordownlink.value = 0x4000;
		parameterslist02[2].parameteridentifier = PARAMETER_IDENTIFIER_AVERAGING_WINDOW;
		parameterslist02[2].parametercontents.averagingwindow.uplinkinmilliseconds = GFBRORMFBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_256KBPS;
		parameterslist02[2].parametercontents.averagingwindow.downlinkinmilliseconds = GFBRORMFBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_1MBPS;
		parameterslist02[3].parameteridentifier = PARAMETER_IDENTIFIER_EPS_BEARER_IDENTITY;
		parameterslist02[3].parametercontents.epsbeareridentity = QOS_FLOW_EPS_BEARER_IDENTITY_VALUE15;
		qosflowdescriptionscontents[2].parameterslist = parameterslist02;

		sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionsnumber = 3;
		sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents = qosflowdescriptionscontents;

		unsigned char bitStream_extendedprotocolconfigurationoptions[4];
		bitStream_extendedprotocolconfigurationoptions[0] = 0x12;
		bitStream_extendedprotocolconfigurationoptions[1] = 0x13;
		bitStream_extendedprotocolconfigurationoptions[2] = 0x14;
		bitStream_extendedprotocolconfigurationoptions[3] = 0x15;
		bstring extendedprotocolconfigurationoptions_tmp = bfromcstralloc(4, "\0");
		//extendedprotocolconfigurationoptions_tmp->data = bitStream_extendedprotocolconfigurationoptions;
		extendedprotocolconfigurationoptions_tmp->slen = 4;
		memcpy(extendedprotocolconfigurationoptions_tmp->data,bitStream_extendedprotocolconfigurationoptions,sizeof(bitStream_extendedprotocolconfigurationoptions));
		sm_msg->specific_msg.pdu_session_establishment_accept.extendedprotocolconfigurationoptions = extendedprotocolconfigurationoptions_tmp;

		unsigned char bitStream_dnn[3] = {0x10,0x20,0x30};
	    bstring dnn_tmp = bfromcstralloc(3, "\0");
	    dnn_tmp->slen = 3;
	    memcpy(dnn_tmp->data,bitStream_dnn,sizeof(bitStream_dnn));
		sm_msg->specific_msg.pdu_session_establishment_accept.dnn = dnn_tmp;

		/*********************sm_msg->specific_msg.pdu_session_establishment_accept end******************************/

		nas_msg.plain.sm = *sm_msg;


		printf("nas header encode extended_protocol_discriminator:0x%x\n, security_header_type:0x%x\n,sequence_number:0x%x\n,message_authentication_code:0x%x\n",
		nas_msg.header.extended_protocol_discriminator,
		nas_msg.header.security_header_type,
		nas_msg.header.sequence_number,
		nas_msg.header.message_authentication_code);



		printf("sm header,extended_protocol_discriminator:0x%x,pdu_session_identity:0x%x,proeduer_transaction_identity:0x%x, message type:0x%x\n",
		sm_msg->header.extended_protocol_discriminator,
		sm_msg->header.pdu_session_identity,
		sm_msg->header.procedure_transaction_identity,
		sm_msg->header.message_type);

		//printf("message type:0x%x\n",sm_msg->specific_msg.pdu_session_establishment_request.messagetype);
		//printf("extendedprotocoldiscriminator:0x%x\n",sm_msg->specific_msg.pdu_session_establishment_request.extendedprotocoldiscriminator);
		//printf("pdu identity buffer:0x%x\n",*(unsigned char *)((sm_msg->specific_msg.pdu_session_establishment_request.pdusessionidentity)->data));
		//printf("PTI buffer:0x%x\n",*(unsigned char *)((sm_msg->specific_msg.pdu_session_establishment_request.proceduretransactionidentity)->data));

		printf("_pdusessiontype bits_3: %#0x\n",sm_msg->specific_msg.pdu_session_establishment_accept._pdusessiontype.pdu_session_type_value);
		printf("sscmode bits_3: %#0x\n",sm_msg->specific_msg.pdu_session_establishment_accept.sscmode.ssc_mode_value);
		printf("qosrules: %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x\n",
				sm_msg->specific_msg.pdu_session_establishment_accept.qosrules.lengthofqosrulesie,
				sm_msg->specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[0].qosruleidentifer,
				sm_msg->specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[0].ruleoperationcode,
				sm_msg->specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[0].dqrbit,
				sm_msg->specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[0].numberofpacketfilters,
				sm_msg->specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[0].packetfilterdirection,
				sm_msg->specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[0].packetfilteridentifier,
				sm_msg->specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[0].packetfiltercontents.component_type,
				sm_msg->specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[1].packetfilterdirection,
				sm_msg->specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[1].packetfilteridentifier,
				sm_msg->specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[1].packetfiltercontents.component_type,
				sm_msg->specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[2].packetfilterdirection,
				sm_msg->specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[2].packetfilteridentifier,
				sm_msg->specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[2].packetfiltercontents.component_type,
				sm_msg->specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[0].qosruleprecedence,
				sm_msg->specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[0].segregation,
				sm_msg->specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[0].qosflowidentifer,
				sm_msg->specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[1].qosruleidentifer,
				sm_msg->specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[1].ruleoperationcode,
				sm_msg->specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[1].dqrbit,
				sm_msg->specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[1].numberofpacketfilters,
				sm_msg->specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[1].packetfilterlist.modifyanddelete[0].packetfilteridentifier,
				sm_msg->specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[1].packetfilterlist.modifyanddelete[1].packetfilteridentifier,
				sm_msg->specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[1].packetfilterlist.modifyanddelete[2].packetfilteridentifier,
				sm_msg->specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[1].qosruleprecedence,
				sm_msg->specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[1].segregation,
				sm_msg->specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[1].qosflowidentifer);

		printf("sessionambr: %x %x %x %x\n",
				sm_msg->specific_msg.pdu_session_establishment_accept.sessionambr.uint_for_session_ambr_for_downlink,
				sm_msg->specific_msg.pdu_session_establishment_accept.sessionambr.session_ambr_for_downlink,
				sm_msg->specific_msg.pdu_session_establishment_accept.sessionambr.uint_for_session_ambr_for_uplink,
				sm_msg->specific_msg.pdu_session_establishment_accept.sessionambr.session_ambr_for_uplink);

		printf("_5gsmcause: %#0x\n",sm_msg->specific_msg.pdu_session_establishment_accept._5gsmcause);

		printf("pduaddress: %x %x %x %x %x\n",
				sm_msg->specific_msg.pdu_session_establishment_accept.pduaddress.pdu_session_type_value,
				(unsigned char)(sm_msg->specific_msg.pdu_session_establishment_accept.pduaddress.pdu_address_information->data[0]),
				(unsigned char)(sm_msg->specific_msg.pdu_session_establishment_accept.pduaddress.pdu_address_information->data[1]),
				(unsigned char)(sm_msg->specific_msg.pdu_session_establishment_accept.pduaddress.pdu_address_information->data[2]),
				(unsigned char)(sm_msg->specific_msg.pdu_session_establishment_accept.pduaddress.pdu_address_information->data[3]));

		printf("gprstimer -- unit: %#0x, timeValue: %#0x\n",
				sm_msg->specific_msg.pdu_session_establishment_accept.gprstimer.unit,
				sm_msg->specific_msg.pdu_session_establishment_accept.gprstimer.timeValue);

		printf("snssai -- len: %#0x, sst: %#0x, sd: %#0x\n",
				sm_msg->specific_msg.pdu_session_establishment_accept.snssai.len,
				sm_msg->specific_msg.pdu_session_establishment_accept.snssai.sst,
				sm_msg->specific_msg.pdu_session_establishment_accept.snssai.sd);

		printf("alwaysonpdusessionindication: %#0x\n",sm_msg->specific_msg.pdu_session_establishment_accept.alwaysonpdusessionindication.apsi_indication);

		//printf("mappedepsbearercontexts");

		printf("eapmessage buffer:%x %x\n",
				(unsigned char)(sm_msg->specific_msg.pdu_session_establishment_accept.eapmessage->data[0]),
				(unsigned char)(sm_msg->specific_msg.pdu_session_establishment_accept.eapmessage->data[1]));

		printf("qosflowdescriptions: %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x\n",
				sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionsnumber,
				sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[0].qfi,
				sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[0].operationcode,
				sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[0].e,
				sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[0].numberofparameters,
				sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[0].parameteridentifier,
				sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[0].parametercontents._5qi,
				sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[1].parameteridentifier,
				sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[1].parametercontents.gfbrormfbr_uplinkordownlink.uint,
				sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[1].parametercontents.gfbrormfbr_uplinkordownlink.value,
				sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[2].parameteridentifier,
				sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[2].parametercontents.gfbrormfbr_uplinkordownlink.uint,
				sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[2].parametercontents.gfbrormfbr_uplinkordownlink.value,
				sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[1].qfi,
				sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[1].operationcode,
				sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[1].e,
				sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[1].numberofparameters,
				sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].qfi,
				sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].operationcode,
				sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].e,
				sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].numberofparameters,
				sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[0].parameteridentifier,
				sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[0].parametercontents.gfbrormfbr_uplinkordownlink.uint,
				sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[0].parametercontents.gfbrormfbr_uplinkordownlink.value,
				sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[1].parameteridentifier,
				sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[1].parametercontents.gfbrormfbr_uplinkordownlink.uint,
				sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[1].parametercontents.gfbrormfbr_uplinkordownlink.value,
				sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[2].parameteridentifier,
				sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[2].parametercontents.averagingwindow.uplinkinmilliseconds,
				sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[2].parametercontents.averagingwindow.downlinkinmilliseconds,
				sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[3].parameteridentifier,
				sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[3].parametercontents.epsbeareridentity);

		printf("extend_options buffer:%x %x %x %x\n",
				(unsigned char)(sm_msg->specific_msg.pdu_session_establishment_accept.extendedprotocolconfigurationoptions->data[0]),
				(unsigned char)(sm_msg->specific_msg.pdu_session_establishment_accept.extendedprotocolconfigurationoptions->data[1]),
				(unsigned char)(sm_msg->specific_msg.pdu_session_establishment_accept.extendedprotocolconfigurationoptions->data[2]),
				(unsigned char)(sm_msg->specific_msg.pdu_session_establishment_accept.extendedprotocolconfigurationoptions->data[3]));

		printf("dnn buffer:%x %x %x\n",
				(unsigned char)(sm_msg->specific_msg.pdu_session_establishment_accept.dnn->data[0]),
				(unsigned char)(sm_msg->specific_msg.pdu_session_establishment_accept.dnn->data[1]),
				(unsigned char)(sm_msg->specific_msg.pdu_session_establishment_accept.dnn->data[2]));

		//bytes = nas_message_encode (data, &nas_msg, 60/*don't know the size*/, security);
		bytes = nas_message_encode (data, &nas_msg, sizeof(data)/*don't know the size*/, &securityencode);

		//nas_msg_str = reinterpret_cast<char*> (data);
		printf("Data = ");
		for(int i = 0;i<bytes;i++)
			printf("%02x ",data[i]);
		printf("\n");
		std::string n1Message ((char*) data,  bytes);
		nas_msg_str = n1Message;
		Logger::smf_app().debug("n1MessageContent (%d bytes), %s\n ", bytes, nas_msg_str.c_str());
		printf("PDU_SESSION_ESTABLISHMENT_ACCEPT------------ encode end\n\n");
	}
	break;

	case PDU_SESSION_ESTABLISHMENT_REJECT: {
		printf("\n\nPDU_SESSION_ESTABLISHMENT_REJECT------------ encode start\n");
		sm_msg->header.message_type = PDU_SESSION_ESTABLISHMENT_REJECT;
		sm_msg->specific_msg.pdu_session_establishment_reject._5gsmcause = 0b00001000;

		sm_msg->specific_msg.pdu_session_establishment_reject.presence = 0x1f;

		sm_msg->specific_msg.pdu_session_establishment_reject.gprstimer3.unit = GPRSTIMER3_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_1_HOUR;
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

		nas_msg.plain.sm = *sm_msg;


		printf("nas header encode extended_protocol_discriminator:0x%x\n, security_header_type:0x%x\n,sequence_number:0x%x\n,message_authentication_code:0x%x\n",
				nas_msg.header.extended_protocol_discriminator,
				nas_msg.header.security_header_type,
				nas_msg.header.sequence_number,
				nas_msg.header.message_authentication_code);



		printf("sm header,extended_protocol_discriminator:0x%x,pdu_session_identity:0x%x,proeduer_transaction_identity:0x%x, message type:0x%x\n",
		sm_msg->header.extended_protocol_discriminator,
	    sm_msg->header.pdu_session_identity,
		sm_msg->header.procedure_transaction_identity,
		sm_msg->header.message_type);


		printf("_5gsmcause: 0x%x\n",sm_msg->specific_msg.pdu_session_establishment_reject._5gsmcause);
	    printf("gprstimer3 --- unit_bits_H3: 0x%x,timeValue_bits_L5: 0x%x\n",sm_msg->specific_msg.pdu_session_establishment_reject.gprstimer3.unit,sm_msg->specific_msg.pdu_session_establishment_reject.gprstimer3.timeValue);
		printf("allowedsscmode --- is_ssc1_allowed: 0x%x, is_ssc2_allowed: 0x%x, is_ssc3_allowed: 0x%x\n",sm_msg->specific_msg.pdu_session_establishment_reject.allowedsscmode.is_ssc1_allowed,sm_msg->specific_msg.pdu_session_establishment_reject.allowedsscmode.is_ssc2_allowed,sm_msg->specific_msg.pdu_session_establishment_reject.allowedsscmode.is_ssc3_allowed);
		printf("eapmessage buffer:0x%x 0x%x\n",(unsigned char)(sm_msg->specific_msg.pdu_session_establishment_reject.eapmessage->data[0]),(unsigned char )(sm_msg->specific_msg.pdu_session_establishment_reject.eapmessage->data[1]));
		printf("extend_options buffer:0x%x 0x%x 0x%x 0x%x\n",(unsigned char)((sm_msg->specific_msg.pdu_session_establishment_reject.extendedprotocolconfigurationoptions)->data[0]),(unsigned char)((sm_msg->specific_msg.pdu_session_establishment_reject.extendedprotocolconfigurationoptions)->data[1]),(unsigned char)((sm_msg->specific_msg.pdu_session_establishment_reject.extendedprotocolconfigurationoptions)->data[2]),(unsigned char)((sm_msg->specific_msg.pdu_session_establishment_reject.extendedprotocolconfigurationoptions)->data[3]));
	    printf("_5gsmcongestionreattemptindicator bits_1 --- abo:0x%x\n",sm_msg->specific_msg.pdu_session_establishment_reject._5gsmcongestionreattemptindicator.abo);

		//bytes = nas_message_encode (data, &nas_msg, 60/*don't know the size*/, security);
		bytes = nas_message_encode (data, &nas_msg, sizeof(data)/*don't know the size*/, &securityencode);

		//nas_msg_str = reinterpret_cast<char*> (data);
		printf("Data = ");
		for(int i = 0;i<bytes;i++)
			printf("Data = %02x ",data[i]);
		printf("\n");
		std::string n1Message ((char*) data,  bytes);
		nas_msg_str = n1Message;
		Logger::smf_app().debug("n1MessageContent: %d, %s\n ", bytes, nas_msg_str.c_str());
		printf("PDU_SESSION_ESTABLISHMENT_REJECT------------ encode end\n\n");
	}
	break;

	case PDU_SESSION_AUTHENTICATION_COMMAND:{
		printf("\n\nPDU_SESSION_AUTHENTICATION_COMMAND------------ encode start\n");
		sm_msg->header.message_type = PDU_SESSION_AUTHENTICATION_COMMAND;
		unsigned char bitStream_eapmessage[2] = {0x01,0x02};
	    bstring eapmessage_tmp = bfromcstralloc(2, "\0");
	    eapmessage_tmp->slen = 2;
	    memcpy(eapmessage_tmp->data,bitStream_eapmessage,sizeof(bitStream_eapmessage));
		sm_msg->specific_msg.pdu_session_authentication_command.eapmessage = eapmessage_tmp;

		sm_msg->specific_msg.pdu_session_authentication_command.presence = 0x01;

		unsigned char bitStream_extendedprotocolconfigurationoptions[4];
	    bitStream_extendedprotocolconfigurationoptions[0] = 0x12;
	    bitStream_extendedprotocolconfigurationoptions[1] = 0x13;
	    bitStream_extendedprotocolconfigurationoptions[2] = 0x14;
	    bitStream_extendedprotocolconfigurationoptions[3] = 0x15;
	    bstring extendedprotocolconfigurationoptions_tmp = bfromcstralloc(4, "\0");
	    //extendedprotocolconfigurationoptions_tmp->data = bitStream_extendedprotocolconfigurationoptions;
	    extendedprotocolconfigurationoptions_tmp->slen = 4;
	    memcpy(extendedprotocolconfigurationoptions_tmp->data,bitStream_extendedprotocolconfigurationoptions,sizeof(bitStream_extendedprotocolconfigurationoptions));
		sm_msg->specific_msg.pdu_session_authentication_command.extendedprotocolconfigurationoptions = extendedprotocolconfigurationoptions_tmp;

	/*********************sm_msg->specific_msg.pdu_session_authentication_command end******************************/

		nas_msg.plain.sm = *sm_msg;


		printf("nas header encode extended_protocol_discriminator:0x%x\n, security_header_type:0x%x\n,sequence_number:0x%x\n,message_authentication_code:0x%x\n",
				nas_msg.header.extended_protocol_discriminator,
				nas_msg.header.security_header_type,
				nas_msg.header.sequence_number,
				nas_msg.header.message_authentication_code);



		printf("sm header,extended_protocol_discriminator:0x%x,pdu_session_identity:0x%x,proeduer_transaction_identity:0x%x, message type:0x%x\n",
		sm_msg->header.extended_protocol_discriminator,
	    sm_msg->header.pdu_session_identity,
		sm_msg->header.procedure_transaction_identity,
		sm_msg->header.message_type);


		printf("eapmessage buffer:0x%x 0x%x\n",(unsigned char)(sm_msg->specific_msg.pdu_session_authentication_command.eapmessage->data[0]),(unsigned char )(sm_msg->specific_msg.pdu_session_authentication_command.eapmessage->data[1]));
		printf("extend_options buffer:0x%x 0x%x 0x%x 0x%x\n",(unsigned char)((sm_msg->specific_msg.pdu_session_authentication_command.extendedprotocolconfigurationoptions)->data[0]),(unsigned char)((sm_msg->specific_msg.pdu_session_authentication_command.extendedprotocolconfigurationoptions)->data[1]),(unsigned char)((sm_msg->specific_msg.pdu_session_authentication_command.extendedprotocolconfigurationoptions)->data[2]),(unsigned char)((sm_msg->specific_msg.pdu_session_authentication_command.extendedprotocolconfigurationoptions)->data[3]));


		//bytes = nas_message_encode (data, &nas_msg, 60/*don't know the size*/, security);
		bytes = nas_message_encode (data, &nas_msg, sizeof(data)/*don't know the size*/, &securityencode);

		//nas_msg_str = reinterpret_cast<char*> (data);
		printf("Data = ");
		for(int i = 0;i<bytes;i++)
			printf("Data = %02x ",data[i]);
		printf("\n");
		std::string n1Message ((char*) data,  bytes);
		nas_msg_str = n1Message;
		Logger::smf_app().debug("n1MessageContent: %d, %s\n ", bytes, nas_msg_str.c_str());
		printf("PDU_SESSION_AUTHENTICATION_COMMAND------------ encode end\n\n");
	}
	break;

	case PDU_SESSION_AUTHENTICATION_COMPLETE:{
		printf("\n\nPDU_SESSION_AUTHENTICATION_COMPLETE------------ encode start\n");
		sm_msg->header.message_type = PDU_SESSION_AUTHENTICATION_COMPLETE;

		unsigned char bitStream_eapmessage[2] = {0x01,0x02};
	    bstring eapmessage_tmp = bfromcstralloc(2, "\0");
	    eapmessage_tmp->slen = 2;
	    memcpy(eapmessage_tmp->data,bitStream_eapmessage,sizeof(bitStream_eapmessage));
		sm_msg->specific_msg.pdu_session_authentication_complete.eapmessage = eapmessage_tmp;

		sm_msg->specific_msg.pdu_session_authentication_complete.presence = 0x01;

		unsigned char bitStream_extendedprotocolconfigurationoptions[4];
	    bitStream_extendedprotocolconfigurationoptions[0] = 0x12;
	    bitStream_extendedprotocolconfigurationoptions[1] = 0x13;
	    bitStream_extendedprotocolconfigurationoptions[2] = 0x14;
	    bitStream_extendedprotocolconfigurationoptions[3] = 0x15;
	    bstring extendedprotocolconfigurationoptions_tmp = bfromcstralloc(4, "\0");
	    //extendedprotocolconfigurationoptions_tmp->data = bitStream_extendedprotocolconfigurationoptions;
	    extendedprotocolconfigurationoptions_tmp->slen = 4;
	    memcpy(extendedprotocolconfigurationoptions_tmp->data,bitStream_extendedprotocolconfigurationoptions,sizeof(bitStream_extendedprotocolconfigurationoptions));
		sm_msg->specific_msg.pdu_session_authentication_complete.extendedprotocolconfigurationoptions = extendedprotocolconfigurationoptions_tmp;

	/*********************sm_msg->specific_msg.pdu_session_authentication_complete end******************************/

		nas_msg.plain.sm = *sm_msg;


		printf("nas header encode extended_protocol_discriminator:0x%x\n, security_header_type:0x%x\n,sequence_number:0x%x\n,message_authentication_code:0x%x\n",
				nas_msg.header.extended_protocol_discriminator,
				nas_msg.header.security_header_type,
				nas_msg.header.sequence_number,
				nas_msg.header.message_authentication_code);



		printf("sm header,extended_protocol_discriminator:0x%x,pdu_session_identity:0x%x,proeduer_transaction_identity:0x%x, message type:0x%x\n",
		sm_msg->header.extended_protocol_discriminator,
	    sm_msg->header.pdu_session_identity,
		sm_msg->header.procedure_transaction_identity,
		sm_msg->header.message_type);


		printf("eapmessage buffer:0x%x 0x%x\n",(unsigned char)(sm_msg->specific_msg.pdu_session_authentication_complete.eapmessage->data[0]),(unsigned char )(sm_msg->specific_msg.pdu_session_authentication_complete.eapmessage->data[1]));
		printf("extend_options buffer:0x%x 0x%x 0x%x 0x%x\n",(unsigned char)((sm_msg->specific_msg.pdu_session_authentication_complete.extendedprotocolconfigurationoptions)->data[0]),(unsigned char)((sm_msg->specific_msg.pdu_session_authentication_complete.extendedprotocolconfigurationoptions)->data[1]),(unsigned char)((sm_msg->specific_msg.pdu_session_authentication_complete.extendedprotocolconfigurationoptions)->data[2]),(unsigned char)((sm_msg->specific_msg.pdu_session_authentication_complete.extendedprotocolconfigurationoptions)->data[3]));

		//bytes = nas_message_encode (data, &nas_msg, 60/*don't know the size*/, security);
		bytes = nas_message_encode (data, &nas_msg, sizeof(data)/*don't know the size*/, &securityencode);

		//nas_msg_str = reinterpret_cast<char*> (data);
		printf("Data = ");
		for(int i = 0;i<bytes;i++)
			printf("Data = %02x ",data[i]);
		printf("\n");
		std::string n1Message ((char*) data,  bytes);
		nas_msg_str = n1Message;
		Logger::smf_app().debug("n1MessageContent: %d, %s\n ", bytes, nas_msg_str.c_str());
		printf("PDU_SESSION_AUTHENTICATION_COMPLETE------------ encode end\n");
	}
	break;

	case PDU_SESSION_AUTHENTICATION_RESULT:{
		printf("\n\nPDU_SESSION_AUTHENTICATION_RESULT------------ encode start\n");
		sm_msg->header.message_type = PDU_SESSION_AUTHENTICATION_RESULT;

		sm_msg->specific_msg.pdu_session_authentication_result.presence = 0x03;

		unsigned char bitStream_eapmessage[2] = {0x01,0x02};
	    bstring eapmessage_tmp = bfromcstralloc(2, "\0");
	    eapmessage_tmp->slen = 2;
	    memcpy(eapmessage_tmp->data,bitStream_eapmessage,sizeof(bitStream_eapmessage));
		sm_msg->specific_msg.pdu_session_authentication_result.eapmessage = eapmessage_tmp;

		unsigned char bitStream_extendedprotocolconfigurationoptions[4];
	    bitStream_extendedprotocolconfigurationoptions[0] = 0x12;
	    bitStream_extendedprotocolconfigurationoptions[1] = 0x13;
	    bitStream_extendedprotocolconfigurationoptions[2] = 0x14;
	    bitStream_extendedprotocolconfigurationoptions[3] = 0x15;
	    bstring extendedprotocolconfigurationoptions_tmp = bfromcstralloc(4, "\0");
	    //extendedprotocolconfigurationoptions_tmp->data = bitStream_extendedprotocolconfigurationoptions;
	    extendedprotocolconfigurationoptions_tmp->slen = 4;
	    memcpy(extendedprotocolconfigurationoptions_tmp->data,bitStream_extendedprotocolconfigurationoptions,sizeof(bitStream_extendedprotocolconfigurationoptions));
		sm_msg->specific_msg.pdu_session_authentication_result.extendedprotocolconfigurationoptions = extendedprotocolconfigurationoptions_tmp;

	/*********************sm_msg->specific_msg.pdu_session_authentication_result end******************************/

		nas_msg.plain.sm = *sm_msg;


		printf("nas header encode extended_protocol_discriminator:0x%x\n, security_header_type:0x%x\n,sequence_number:0x%x\n,message_authentication_code:0x%x\n",
				nas_msg.header.extended_protocol_discriminator,
				nas_msg.header.security_header_type,
				nas_msg.header.sequence_number,
				nas_msg.header.message_authentication_code);



		printf("sm header,extended_protocol_discriminator:0x%x,pdu_session_identity:0x%x,proeduer_transaction_identity:0x%x, message type:0x%x\n",
		sm_msg->header.extended_protocol_discriminator,
	    sm_msg->header.pdu_session_identity,
		sm_msg->header.procedure_transaction_identity,
		sm_msg->header.message_type);


		printf("eapmessage buffer:0x%x 0x%x\n",(unsigned char)(sm_msg->specific_msg.pdu_session_authentication_result.eapmessage->data[0]),(unsigned char )(sm_msg->specific_msg.pdu_session_authentication_result.eapmessage->data[1]));
		printf("extend_options buffer:0x%x 0x%x 0x%x 0x%x\n",(unsigned char)((sm_msg->specific_msg.pdu_session_authentication_result.extendedprotocolconfigurationoptions)->data[0]),(unsigned char)((sm_msg->specific_msg.pdu_session_authentication_result.extendedprotocolconfigurationoptions)->data[1]),(unsigned char)((sm_msg->specific_msg.pdu_session_authentication_result.extendedprotocolconfigurationoptions)->data[2]),(unsigned char)((sm_msg->specific_msg.pdu_session_authentication_result.extendedprotocolconfigurationoptions)->data[3]));

		//bytes = nas_message_encode (data, &nas_msg, 60/*don't know the size*/, security);
		bytes = nas_message_encode (data, &nas_msg, sizeof(data)/*don't know the size*/, &securityencode);

		//nas_msg_str = reinterpret_cast<char*> (data);
		printf("Data = ");
		for(int i = 0;i<bytes;i++)
			printf("Data = %02x ",data[i]);
		printf("\n");
		std::string n1Message ((char*) data,  bytes);
		nas_msg_str = n1Message;
		Logger::smf_app().debug("n1MessageContent: %d, %s\n ", bytes, nas_msg_str.c_str());
		
		printf("PDU_SESSION_AUTHENTICATION_RESULT------------ encode end\n\n");
	}
	break;

	case PDU_SESSION_MODIFICATION_REQUEST:{
		printf("\n\nPDU_SESSION_MODIFICATION_REQUEST------------ encode start\n");
		sm_msg->header.message_type = PDU_SESSION_MODIFICATION_REQUEST;

		sm_msg->specific_msg.pdu_session_modification_request.presence = 0xffff;

		sm_msg->specific_msg.pdu_session_modification_request._5gsmcapability.is_MPTCP_supported = MPTCP_FUNCTIONALITY_SUPPORTED;
		sm_msg->specific_msg.pdu_session_modification_request._5gsmcapability.is_ATSLL_supported = EATSSS_LOW_LAYER_FUNCTIONALITY_NOT_SUPPORTED;
		sm_msg->specific_msg.pdu_session_modification_request._5gsmcapability.is_EPTS1_supported = ETHERNET_PDN_TYPE_IN_S1_MODE_SUPPORTED;
		sm_msg->specific_msg.pdu_session_modification_request._5gsmcapability.is_MH6PDU_supported = MULTI_HOMED_IPV6_PDU_SESSION_SUPPORTED;
		sm_msg->specific_msg.pdu_session_modification_request._5gsmcapability.is_Rqos_supported = REFLECTIVE_QOS_NOT_SUPPORTED;

		sm_msg->specific_msg.pdu_session_modification_request._5gsmcause = 0b00001000;

		sm_msg->specific_msg.pdu_session_modification_request.maximumnumberofsupportedpacketfilters = 0x3ff;


		sm_msg->specific_msg.pdu_session_modification_request.alwaysonpdusessionrequested.apsr_requested = ALWAYSON_PDU_SESSION_REQUESTED;

		unsigned char bitStream_intergrityprotectionmaximumdatarate[2] = {0x01,0x02};
		bstring intergrityprotectionmaximumdatarate_tmp = bfromcstralloc(2, "\0");
		//intergrityprotectionmaximumdatarate_tmp->data = bitStream_intergrityprotectionmaximumdatarate;
		intergrityprotectionmaximumdatarate_tmp->slen = 2;
		memcpy(intergrityprotectionmaximumdatarate_tmp->data,bitStream_intergrityprotectionmaximumdatarate,sizeof(bitStream_intergrityprotectionmaximumdatarate));
		sm_msg->specific_msg.pdu_session_modification_request.intergrityprotectionmaximumdatarate = intergrityprotectionmaximumdatarate_tmp;


		QOSRulesIE qosrulesie[2];

		qosrulesie[0].qosruleidentifer=0x01;
		qosrulesie[0].ruleoperationcode = CREATE_NEW_QOS_RULE;
		qosrulesie[0].dqrbit = THE_QOS_RULE_IS_DEFAULT_QOS_RULE;
		qosrulesie[0].numberofpacketfilters = 3;

		Create_ModifyAndAdd_ModifyAndReplace create_modifyandadd_modifyandreplace[3];
		create_modifyandadd_modifyandreplace[0].packetfilterdirection = 0b01;
		create_modifyandadd_modifyandreplace[0].packetfilteridentifier = 1;
		/*unsigned char bitStream_packetfiltercontents00[2] = {MATCHALL_TYPE,MATCHALL_TYPE};
		bstring packetfiltercontents00_tmp = bfromcstralloc(2, "\0");
		packetfiltercontents00_tmp->slen = 2;
		memcpy(packetfiltercontents00_tmp->data,bitStream_packetfiltercontents00,sizeof(bitStream_packetfiltercontents00));
		create_modifyandadd_modifyandreplace[0].packetfiltercontents = packetfiltercontents00_tmp;*/
		create_modifyandadd_modifyandreplace[0].packetfiltercontents.component_type = QOS_RULE_MATCHALL_TYPE;
		create_modifyandadd_modifyandreplace[1].packetfilterdirection = 0b10;
		create_modifyandadd_modifyandreplace[1].packetfilteridentifier = 2;
		/*unsigned char bitStream_packetfiltercontents01[2] = {MATCHALL_TYPE,MATCHALL_TYPE};
		bstring packetfiltercontents01_tmp = bfromcstralloc(2, "\0");
		packetfiltercontents01_tmp->slen = 2;
		memcpy(packetfiltercontents01_tmp->data,bitStream_packetfiltercontents01,sizeof(bitStream_packetfiltercontents01));
		create_modifyandadd_modifyandreplace[1].packetfiltercontents = packetfiltercontents01_tmp;*/
		create_modifyandadd_modifyandreplace[1].packetfiltercontents.component_type = QOS_RULE_MATCHALL_TYPE;
		create_modifyandadd_modifyandreplace[2].packetfilterdirection = 0b11;
		create_modifyandadd_modifyandreplace[2].packetfilteridentifier = 3;
		/*unsigned char bitStream_packetfiltercontents02[2] = {MATCHALL_TYPE,MATCHALL_TYPE};
		bstring packetfiltercontents02_tmp = bfromcstralloc(2, "\0");
		packetfiltercontents02_tmp->slen = 2;
		memcpy(packetfiltercontents02_tmp->data,bitStream_packetfiltercontents02,sizeof(bitStream_packetfiltercontents02));
		create_modifyandadd_modifyandreplace[2].packetfiltercontents = packetfiltercontents02_tmp;*/
		create_modifyandadd_modifyandreplace[2].packetfiltercontents.component_type = QOS_RULE_MATCHALL_TYPE;

		qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace = create_modifyandadd_modifyandreplace;

		qosrulesie[0].qosruleprecedence = 1;
		qosrulesie[0].segregation = SEGREGATION_NOT_REQUESTED;
		qosrulesie[0].qosflowidentifer = 0x07;
	/**********************************************************************/
		qosrulesie[1].qosruleidentifer=0x02;
		qosrulesie[1].ruleoperationcode = MODIFY_EXISTING_QOS_RULE_AND_DELETE_PACKET_FILTERS;
		qosrulesie[1].dqrbit = THE_QOS_RULE_IS_NOT_THE_DEFAULT_QOS_RULE;
		qosrulesie[1].numberofpacketfilters = 3;

		ModifyAndDelete modifyanddelete[3];
		modifyanddelete[0].packetfilteridentifier = 1;
		modifyanddelete[1].packetfilteridentifier = 2;
		modifyanddelete[2].packetfilteridentifier = 3;
		qosrulesie[1].packetfilterlist.modifyanddelete = modifyanddelete;

		qosrulesie[1].qosruleprecedence = 1;
		qosrulesie[1].segregation = SEGREGATION_REQUESTED;
		qosrulesie[1].qosflowidentifer = 0x08;


		sm_msg->specific_msg.pdu_session_modification_request.qosrules.lengthofqosrulesie = 2;
		sm_msg->specific_msg.pdu_session_modification_request.qosrules.qosrulesie = qosrulesie;


		QOSFlowDescriptionsContents qosflowdescriptionscontents[3];
		qosflowdescriptionscontents[0].qfi = 1;
		qosflowdescriptionscontents[0].operationcode = CREATE_NEW_QOS_FLOW_DESCRIPTION;
		qosflowdescriptionscontents[0].e = PARAMETERS_LIST_IS_INCLUDED;
		qosflowdescriptionscontents[0].numberofparameters = 3;
		ParametersList parameterslist00[3];
		parameterslist00[0].parameteridentifier = PARAMETER_IDENTIFIER_5QI;
		parameterslist00[0].parametercontents._5qi = 0b01000001;
		parameterslist00[1].parameteridentifier = PARAMETER_IDENTIFIER_GFBR_UPLINK;
		parameterslist00[1].parametercontents.gfbrormfbr_uplinkordownlink.uint = GFBRORMFBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_1KBPS;
		parameterslist00[1].parametercontents.gfbrormfbr_uplinkordownlink.value = 0x1000;
		parameterslist00[2].parameteridentifier = PARAMETER_IDENTIFIER_GFBR_DOWNLINK;
		parameterslist00[2].parametercontents.gfbrormfbr_uplinkordownlink.uint = GFBRORMFBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_4KBPS;
		parameterslist00[2].parametercontents.gfbrormfbr_uplinkordownlink.value = 0x2000;
		qosflowdescriptionscontents[0].parameterslist = parameterslist00;

		qosflowdescriptionscontents[1].qfi = 2;
		qosflowdescriptionscontents[1].operationcode = DELETE_EXISTING_QOS_FLOW_DESCRIPTION;
		qosflowdescriptionscontents[1].e = PARAMETERS_LIST_IS_NOT_INCLUDED;
		qosflowdescriptionscontents[1].numberofparameters = 0;
		qosflowdescriptionscontents[1].parameterslist = NULL;

		qosflowdescriptionscontents[2].qfi = 1;
		qosflowdescriptionscontents[2].operationcode = MODIFY_EXISTING_QOS_FLOW_DESCRIPTION;
		qosflowdescriptionscontents[2].e = REPLACEMENT_OF_ALL_PREVIOUSLY_PROVIDED_PARAMETERS;
		qosflowdescriptionscontents[2].numberofparameters = 4;
		ParametersList parameterslist02[4];
		parameterslist02[0].parameteridentifier = PARAMETER_IDENTIFIER_MFBR_UPLINK;
		parameterslist02[0].parametercontents.gfbrormfbr_uplinkordownlink.uint = GFBRORMFBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_16KBPS;
		parameterslist02[0].parametercontents.gfbrormfbr_uplinkordownlink.value = 0x3000;
		parameterslist02[1].parameteridentifier = PARAMETER_IDENTIFIER_MFBR_DOWNLINK;
		parameterslist02[1].parametercontents.gfbrormfbr_uplinkordownlink.uint = GFBRORMFBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_64KBPS;
		parameterslist02[1].parametercontents.gfbrormfbr_uplinkordownlink.value = 0x4000;
		parameterslist02[2].parameteridentifier = PARAMETER_IDENTIFIER_AVERAGING_WINDOW;
		parameterslist02[2].parametercontents.averagingwindow.uplinkinmilliseconds = GFBRORMFBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_256KBPS;
		parameterslist02[2].parametercontents.averagingwindow.downlinkinmilliseconds = GFBRORMFBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_1MBPS;
		parameterslist02[3].parameteridentifier = PARAMETER_IDENTIFIER_EPS_BEARER_IDENTITY;
		parameterslist02[3].parametercontents.epsbeareridentity = QOS_FLOW_EPS_BEARER_IDENTITY_VALUE15;
		qosflowdescriptionscontents[2].parameterslist = parameterslist02;

		sm_msg->specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionsnumber = 3;
		sm_msg->specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents = qosflowdescriptionscontents;

		unsigned char bitStream_extendedprotocolconfigurationoptions[4];
		bitStream_extendedprotocolconfigurationoptions[0] = 0x12;
		bitStream_extendedprotocolconfigurationoptions[1] = 0x13;
		bitStream_extendedprotocolconfigurationoptions[2] = 0x14;
		bitStream_extendedprotocolconfigurationoptions[3] = 0x15;
		bstring extendedprotocolconfigurationoptions_tmp = bfromcstralloc(4, "\0");
		//extendedprotocolconfigurationoptions_tmp->data = bitStream_extendedprotocolconfigurationoptions;
		extendedprotocolconfigurationoptions_tmp->slen = 4;
		memcpy(extendedprotocolconfigurationoptions_tmp->data,bitStream_extendedprotocolconfigurationoptions,sizeof(bitStream_extendedprotocolconfigurationoptions));
		sm_msg->specific_msg.pdu_session_modification_request.extendedprotocolconfigurationoptions = extendedprotocolconfigurationoptions_tmp;

		/*********************sm_msg->specific_msg.pdu_session_modification_request end******************************/

		nas_msg.plain.sm = *sm_msg;

		printf("nas header encode extended_protocol_discriminator:0x%x\n, security_header_type:0x%x\n,sequence_number:0x%x\n,message_authentication_code:0x%x\n",
		nas_msg.header.extended_protocol_discriminator,
		nas_msg.header.security_header_type,
		nas_msg.header.sequence_number,
		nas_msg.header.message_authentication_code);



		printf("sm header,extended_protocol_discriminator:0x%x,pdu_session_identity:0x%x,proeduer_transaction_identity:0x%x, message type:0x%x\n",
		sm_msg->header.extended_protocol_discriminator,
		sm_msg->header.pdu_session_identity,
		sm_msg->header.procedure_transaction_identity,
		sm_msg->header.message_type);

		//printf("message type:0x%x\n",sm_msg->specific_msg.pdu_session_establishment_request.messagetype);
		//printf("extendedprotocoldiscriminator:0x%x\n",sm_msg->specific_msg.pdu_session_establishment_request.extendedprotocoldiscriminator);
		//printf("pdu identity buffer:0x%x\n",*(unsigned char *)((sm_msg->specific_msg.pdu_session_establishment_request.pdusessionidentity)->data));
		//printf("PTI buffer:0x%x\n",*(unsigned char *)((sm_msg->specific_msg.pdu_session_establishment_request.proceduretransactionidentity)->data));


		printf("_5gsmcapability bits_5 --- MPTCP:0x%x ATS-LL:0x%x EPT-S1:0x%x MH6-PDU:0x%x RqoS:0x%x\n",
				sm_msg->specific_msg.pdu_session_modification_request._5gsmcapability.is_MPTCP_supported,
				sm_msg->specific_msg.pdu_session_modification_request._5gsmcapability.is_ATSLL_supported,
				sm_msg->specific_msg.pdu_session_modification_request._5gsmcapability.is_EPTS1_supported,
				sm_msg->specific_msg.pdu_session_modification_request._5gsmcapability.is_MH6PDU_supported,
				sm_msg->specific_msg.pdu_session_modification_request._5gsmcapability.is_Rqos_supported);

		printf("_5gsmcause: %#0x\n",sm_msg->specific_msg.pdu_session_modification_request._5gsmcause);

		printf("maximum bits_11:0x%x\n",sm_msg->specific_msg.pdu_session_modification_request.maximumnumberofsupportedpacketfilters);

		printf("Always-on bits_1 --- APSR:0x%x\n",sm_msg->specific_msg.pdu_session_modification_request.alwaysonpdusessionrequested.apsr_requested);

		printf("intergrity buffer:0x%x 0x%x\n",
				(unsigned char)(sm_msg->specific_msg.pdu_session_modification_request.intergrityprotectionmaximumdatarate->data[0]),
				(unsigned char)(sm_msg->specific_msg.pdu_session_modification_request.intergrityprotectionmaximumdatarate->data[1]));

		printf("qosrules: %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x\n",
				sm_msg->specific_msg.pdu_session_modification_request.qosrules.lengthofqosrulesie,
				sm_msg->specific_msg.pdu_session_modification_request.qosrules.qosrulesie[0].qosruleidentifer,
				sm_msg->specific_msg.pdu_session_modification_request.qosrules.qosrulesie[0].ruleoperationcode,
				sm_msg->specific_msg.pdu_session_modification_request.qosrules.qosrulesie[0].dqrbit,
				sm_msg->specific_msg.pdu_session_modification_request.qosrules.qosrulesie[0].numberofpacketfilters,
				sm_msg->specific_msg.pdu_session_modification_request.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[0].packetfilterdirection,
				sm_msg->specific_msg.pdu_session_modification_request.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[0].packetfilteridentifier,
				sm_msg->specific_msg.pdu_session_modification_request.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[0].packetfiltercontents.component_type,
				sm_msg->specific_msg.pdu_session_modification_request.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[1].packetfilterdirection,
				sm_msg->specific_msg.pdu_session_modification_request.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[1].packetfilteridentifier,
				sm_msg->specific_msg.pdu_session_modification_request.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[1].packetfiltercontents.component_type,
				sm_msg->specific_msg.pdu_session_modification_request.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[2].packetfilterdirection,
				sm_msg->specific_msg.pdu_session_modification_request.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[2].packetfilteridentifier,
				sm_msg->specific_msg.pdu_session_modification_request.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[2].packetfiltercontents.component_type,
				sm_msg->specific_msg.pdu_session_modification_request.qosrules.qosrulesie[0].qosruleprecedence,
				sm_msg->specific_msg.pdu_session_modification_request.qosrules.qosrulesie[0].segregation,
				sm_msg->specific_msg.pdu_session_modification_request.qosrules.qosrulesie[0].qosflowidentifer,
				sm_msg->specific_msg.pdu_session_modification_request.qosrules.qosrulesie[1].qosruleidentifer,
				sm_msg->specific_msg.pdu_session_modification_request.qosrules.qosrulesie[1].ruleoperationcode,
				sm_msg->specific_msg.pdu_session_modification_request.qosrules.qosrulesie[1].dqrbit,
				sm_msg->specific_msg.pdu_session_modification_request.qosrules.qosrulesie[1].numberofpacketfilters,
				sm_msg->specific_msg.pdu_session_modification_request.qosrules.qosrulesie[1].packetfilterlist.modifyanddelete[0].packetfilteridentifier,
				sm_msg->specific_msg.pdu_session_modification_request.qosrules.qosrulesie[1].packetfilterlist.modifyanddelete[1].packetfilteridentifier,
				sm_msg->specific_msg.pdu_session_modification_request.qosrules.qosrulesie[1].packetfilterlist.modifyanddelete[2].packetfilteridentifier,
				sm_msg->specific_msg.pdu_session_modification_request.qosrules.qosrulesie[1].qosruleprecedence,
				sm_msg->specific_msg.pdu_session_modification_request.qosrules.qosrulesie[1].segregation,
				sm_msg->specific_msg.pdu_session_modification_request.qosrules.qosrulesie[1].qosflowidentifer);

		printf("qosflowdescriptions: %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x\n",
				sm_msg->specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionsnumber,
				sm_msg->specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[0].qfi,
				sm_msg->specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[0].operationcode,
				sm_msg->specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[0].e,
				sm_msg->specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[0].numberofparameters,
				sm_msg->specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[0].parameteridentifier,
				sm_msg->specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[0].parametercontents._5qi,
				sm_msg->specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[1].parameteridentifier,
				sm_msg->specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[1].parametercontents.gfbrormfbr_uplinkordownlink.uint,
				sm_msg->specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[1].parametercontents.gfbrormfbr_uplinkordownlink.value,
				sm_msg->specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[2].parameteridentifier,
				sm_msg->specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[2].parametercontents.gfbrormfbr_uplinkordownlink.uint,
				sm_msg->specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[2].parametercontents.gfbrormfbr_uplinkordownlink.value,
				sm_msg->specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[1].qfi,
				sm_msg->specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[1].operationcode,
				sm_msg->specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[1].e,
				sm_msg->specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[1].numberofparameters,
				sm_msg->specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[2].qfi,
				sm_msg->specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[2].operationcode,
				sm_msg->specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[2].e,
				sm_msg->specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[2].numberofparameters,
				sm_msg->specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[0].parameteridentifier,
				sm_msg->specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[0].parametercontents.gfbrormfbr_uplinkordownlink.uint,
				sm_msg->specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[0].parametercontents.gfbrormfbr_uplinkordownlink.value,
				sm_msg->specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[1].parameteridentifier,
				sm_msg->specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[1].parametercontents.gfbrormfbr_uplinkordownlink.uint,
				sm_msg->specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[1].parametercontents.gfbrormfbr_uplinkordownlink.value,
				sm_msg->specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[2].parameteridentifier,
				sm_msg->specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[2].parametercontents.averagingwindow.uplinkinmilliseconds,
				sm_msg->specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[2].parametercontents.averagingwindow.downlinkinmilliseconds,
				sm_msg->specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[3].parameteridentifier,
				sm_msg->specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[3].parametercontents.epsbeareridentity);

		//printf("mappedepsbearercontexts");

		printf("extend_options buffer:%x %x %x %x\n",
				(unsigned char)(sm_msg->specific_msg.pdu_session_modification_request.extendedprotocolconfigurationoptions->data[0]),
				(unsigned char)(sm_msg->specific_msg.pdu_session_modification_request.extendedprotocolconfigurationoptions->data[1]),
				(unsigned char)(sm_msg->specific_msg.pdu_session_modification_request.extendedprotocolconfigurationoptions->data[2]),
				(unsigned char)(sm_msg->specific_msg.pdu_session_modification_request.extendedprotocolconfigurationoptions->data[3]));

		//bytes = nas_message_encode (data, &nas_msg, 60/*don't know the size*/, security);
		bytes = nas_message_encode (data, &nas_msg, sizeof(data)/*don't know the size*/, &securityencode);

		//nas_msg_str = reinterpret_cast<char*> (data);
		printf("Data = ");
		for(int i = 0;i<bytes;i++)
			printf("Data = %02x ",data[i]);
		printf("\n");
		std::string n1Message ((char*) data,  bytes);
		nas_msg_str = n1Message;
		Logger::smf_app().debug("n1MessageContent: %d, %s\n ", bytes, nas_msg_str.c_str());
		printf("PDU_SESSION_MODIFICATION_REQUEST------------ encode end\n\n");
	}
	break;

	case PDU_SESSION_MODIFICATION_REJECT:{
		printf("\n\nPDU_SESSION_MODIFICATION_REJECT------------ encode start\n");
		sm_msg->header.message_type = PDU_SESSION_MODIFICATION_REJECT;

		sm_msg->specific_msg.pdu_session_modification_reject._5gsmcause = 0b00001000;

		sm_msg->specific_msg.pdu_session_modification_reject.presence = 0x07;

		sm_msg->specific_msg.pdu_session_modification_reject.gprstimer3.unit = GPRSTIMER3_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_1_HOUR;
		sm_msg->specific_msg.pdu_session_modification_reject.gprstimer3.timeValue = 0;

		unsigned char bitStream_extendedprotocolconfigurationoptions[4];
	    bitStream_extendedprotocolconfigurationoptions[0] = 0x12;
	    bitStream_extendedprotocolconfigurationoptions[1] = 0x13;
	    bitStream_extendedprotocolconfigurationoptions[2] = 0x14;
	    bitStream_extendedprotocolconfigurationoptions[3] = 0x15;
	    bstring extendedprotocolconfigurationoptions_tmp = bfromcstralloc(4, "\0");
	    //extendedprotocolconfigurationoptions_tmp->data = bitStream_extendedprotocolconfigurationoptions;
	    extendedprotocolconfigurationoptions_tmp->slen = 4;
	    memcpy(extendedprotocolconfigurationoptions_tmp->data,bitStream_extendedprotocolconfigurationoptions,sizeof(bitStream_extendedprotocolconfigurationoptions));
		sm_msg->specific_msg.pdu_session_modification_reject.extendedprotocolconfigurationoptions = extendedprotocolconfigurationoptions_tmp;

		sm_msg->specific_msg.pdu_session_modification_reject._5gsmcongestionreattemptindicator.abo = THE_BACKOFF_TIMER_IS_APPLIED_IN_ALL_PLMNS;

	/*********************sm_msg->specific_msg.pdu_session_modification_reject end******************************/

		nas_msg.plain.sm = *sm_msg;


		printf("nas header encode extended_protocol_discriminator:0x%x\n, security_header_type:0x%x\n,sequence_number:0x%x\n,message_authentication_code:0x%x\n",
				nas_msg.header.extended_protocol_discriminator,
				nas_msg.header.security_header_type,
				nas_msg.header.sequence_number,
				nas_msg.header.message_authentication_code);



		printf("sm header,extended_protocol_discriminator:0x%x,pdu_session_identity:0x%x,proeduer_transaction_identity:0x%x, message type:0x%x\n",
		sm_msg->header.extended_protocol_discriminator,
	    sm_msg->header.pdu_session_identity,
		sm_msg->header.procedure_transaction_identity,
		sm_msg->header.message_type);


		printf("_5gsmcause: 0x%x\n",sm_msg->specific_msg.pdu_session_modification_reject._5gsmcause);
	    printf("gprstimer3 --- unit_bits_H3: 0x%x,timeValue_bits_L5: 0x%x\n",sm_msg->specific_msg.pdu_session_modification_reject.gprstimer3.unit,sm_msg->specific_msg.pdu_session_modification_reject.gprstimer3.timeValue);
		printf("extend_options buffer:0x%x 0x%x 0x%x 0x%x\n",(unsigned char)((sm_msg->specific_msg.pdu_session_modification_reject.extendedprotocolconfigurationoptions)->data[0]),(unsigned char)((sm_msg->specific_msg.pdu_session_modification_reject.extendedprotocolconfigurationoptions)->data[1]),(unsigned char)((sm_msg->specific_msg.pdu_session_modification_reject.extendedprotocolconfigurationoptions)->data[2]),(unsigned char)((sm_msg->specific_msg.pdu_session_modification_reject.extendedprotocolconfigurationoptions)->data[3]));
	    printf("_5gsmcongestionreattemptindicator bits_1 --- abo:0x%x\n",sm_msg->specific_msg.pdu_session_modification_reject._5gsmcongestionreattemptindicator.abo);

		//bytes = nas_message_encode (data, &nas_msg, 60/*don't know the size*/, security);
		bytes = nas_message_encode (data, &nas_msg, sizeof(data)/*don't know the size*/, &securityencode);

		//nas_msg_str = reinterpret_cast<char*> (data);
		printf("Data = ");
		for(int i = 0;i<bytes;i++)
			printf("Data = %02x ",data[i]);
		printf("\n");
		std::string n1Message ((char*) data,  bytes);
		nas_msg_str = n1Message;
		Logger::smf_app().debug("n1MessageContent: %d, %s\n ", bytes, nas_msg_str.c_str());
		printf("PDU_SESSION_MODIFICATION_REJECT------------ encode end\n\n");
	}
	break;

	case PDU_SESSION_MODIFICATION_COMMAND:{
		printf("\n\nPDU_SESSION_MODIFICATION_COMMAND------------ encode start\n");
		sm_msg->header.message_type = PDU_SESSION_MODIFICATION_COMMAND;

		sm_msg->specific_msg.pdu_session_modification_command.presence = 0xff;

		sm_msg->specific_msg.pdu_session_modification_command._5gsmcause = 0b00001000;

		sm_msg->specific_msg.pdu_session_modification_command.sessionambr.uint_for_session_ambr_for_downlink = AMBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_1KBPS;
		sm_msg->specific_msg.pdu_session_modification_command.sessionambr.session_ambr_for_downlink = (AMBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_4KBPS << 8) + (AMBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_16KBPS);
		sm_msg->specific_msg.pdu_session_modification_command.sessionambr.uint_for_session_ambr_for_uplink = AMBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_64KBPS;
		sm_msg->specific_msg.pdu_session_modification_command.sessionambr.session_ambr_for_uplink = (AMBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_256KBPS << 8) + (AMBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_1MBPS);

		sm_msg->specific_msg.pdu_session_modification_command.gprstimer.unit = GPRSTIMER_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_2_SECONDS;
		sm_msg->specific_msg.pdu_session_modification_command.gprstimer.timeValue = 0;

		sm_msg->specific_msg.pdu_session_modification_command.alwaysonpdusessionindication.apsi_indication = ALWAYSON_PDU_SESSION_REQUIRED;

		QOSRulesIE qosrulesie[2];

		qosrulesie[0].qosruleidentifer=0x01;
		qosrulesie[0].ruleoperationcode = CREATE_NEW_QOS_RULE;
		qosrulesie[0].dqrbit = THE_QOS_RULE_IS_DEFAULT_QOS_RULE;
		qosrulesie[0].numberofpacketfilters = 3;

		Create_ModifyAndAdd_ModifyAndReplace create_modifyandadd_modifyandreplace[3];
		create_modifyandadd_modifyandreplace[0].packetfilterdirection = 0b01;
		create_modifyandadd_modifyandreplace[0].packetfilteridentifier = 1;
		/*unsigned char bitStream_packetfiltercontents00[2] = {MATCHALL_TYPE,MATCHALL_TYPE};
		bstring packetfiltercontents00_tmp = bfromcstralloc(2, "\0");
		packetfiltercontents00_tmp->slen = 2;
		memcpy(packetfiltercontents00_tmp->data,bitStream_packetfiltercontents00,sizeof(bitStream_packetfiltercontents00));
		create_modifyandadd_modifyandreplace[0].packetfiltercontents = packetfiltercontents00_tmp;*/
		create_modifyandadd_modifyandreplace[0].packetfiltercontents.component_type = QOS_RULE_MATCHALL_TYPE;
		create_modifyandadd_modifyandreplace[1].packetfilterdirection = 0b10;
		create_modifyandadd_modifyandreplace[1].packetfilteridentifier = 2;
		/*unsigned char bitStream_packetfiltercontents01[2] = {MATCHALL_TYPE,MATCHALL_TYPE};
		bstring packetfiltercontents01_tmp = bfromcstralloc(2, "\0");
		packetfiltercontents01_tmp->slen = 2;
		memcpy(packetfiltercontents01_tmp->data,bitStream_packetfiltercontents01,sizeof(bitStream_packetfiltercontents01));
		create_modifyandadd_modifyandreplace[1].packetfiltercontents = packetfiltercontents01_tmp;*/
		create_modifyandadd_modifyandreplace[1].packetfiltercontents.component_type = QOS_RULE_MATCHALL_TYPE;
		create_modifyandadd_modifyandreplace[2].packetfilterdirection = 0b11;
		create_modifyandadd_modifyandreplace[2].packetfilteridentifier = 3;
		/*unsigned char bitStream_packetfiltercontents02[2] = {MATCHALL_TYPE,MATCHALL_TYPE};
		bstring packetfiltercontents02_tmp = bfromcstralloc(2, "\0");
		packetfiltercontents02_tmp->slen = 2;
		memcpy(packetfiltercontents02_tmp->data,bitStream_packetfiltercontents02,sizeof(bitStream_packetfiltercontents02));
		create_modifyandadd_modifyandreplace[2].packetfiltercontents = packetfiltercontents02_tmp;*/
		create_modifyandadd_modifyandreplace[2].packetfiltercontents.component_type = QOS_RULE_MATCHALL_TYPE;

		qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace = create_modifyandadd_modifyandreplace;

		qosrulesie[0].qosruleprecedence = 1;
		qosrulesie[0].segregation = SEGREGATION_NOT_REQUESTED;
		qosrulesie[0].qosflowidentifer = 0x07;
	/**********************************************************************/
		qosrulesie[1].qosruleidentifer=0x02;
		qosrulesie[1].ruleoperationcode = MODIFY_EXISTING_QOS_RULE_AND_DELETE_PACKET_FILTERS;
		qosrulesie[1].dqrbit = THE_QOS_RULE_IS_NOT_THE_DEFAULT_QOS_RULE;
		qosrulesie[1].numberofpacketfilters = 3;

		ModifyAndDelete modifyanddelete[3];
		modifyanddelete[0].packetfilteridentifier = 1;
		modifyanddelete[1].packetfilteridentifier = 2;
		modifyanddelete[2].packetfilteridentifier = 3;
		qosrulesie[1].packetfilterlist.modifyanddelete = modifyanddelete;

		qosrulesie[1].qosruleprecedence = 1;
		qosrulesie[1].segregation = SEGREGATION_REQUESTED;
		qosrulesie[1].qosflowidentifer = 0x08;


		sm_msg->specific_msg.pdu_session_modification_command.qosrules.lengthofqosrulesie = 2;
		sm_msg->specific_msg.pdu_session_modification_command.qosrules.qosrulesie = qosrulesie;


		QOSFlowDescriptionsContents qosflowdescriptionscontents[3];
		qosflowdescriptionscontents[0].qfi = 1;
		qosflowdescriptionscontents[0].operationcode = CREATE_NEW_QOS_FLOW_DESCRIPTION;
		qosflowdescriptionscontents[0].e = PARAMETERS_LIST_IS_INCLUDED;
		qosflowdescriptionscontents[0].numberofparameters = 3;
		ParametersList parameterslist00[3];
		parameterslist00[0].parameteridentifier = PARAMETER_IDENTIFIER_5QI;
		parameterslist00[0].parametercontents._5qi = 0b01000001;
		parameterslist00[1].parameteridentifier = PARAMETER_IDENTIFIER_GFBR_UPLINK;
		parameterslist00[1].parametercontents.gfbrormfbr_uplinkordownlink.uint = GFBRORMFBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_1KBPS;
		parameterslist00[1].parametercontents.gfbrormfbr_uplinkordownlink.value = 0x1000;
		parameterslist00[2].parameteridentifier = PARAMETER_IDENTIFIER_GFBR_DOWNLINK;
		parameterslist00[2].parametercontents.gfbrormfbr_uplinkordownlink.uint = GFBRORMFBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_4KBPS;
		parameterslist00[2].parametercontents.gfbrormfbr_uplinkordownlink.value = 0x2000;
		qosflowdescriptionscontents[0].parameterslist = parameterslist00;

		qosflowdescriptionscontents[1].qfi = 2;
		qosflowdescriptionscontents[1].operationcode = DELETE_EXISTING_QOS_FLOW_DESCRIPTION;
		qosflowdescriptionscontents[1].e = PARAMETERS_LIST_IS_NOT_INCLUDED;
		qosflowdescriptionscontents[1].numberofparameters = 0;
		qosflowdescriptionscontents[1].parameterslist = NULL;

		qosflowdescriptionscontents[2].qfi = 1;
		qosflowdescriptionscontents[2].operationcode = MODIFY_EXISTING_QOS_FLOW_DESCRIPTION;
		qosflowdescriptionscontents[2].e = REPLACEMENT_OF_ALL_PREVIOUSLY_PROVIDED_PARAMETERS;
		qosflowdescriptionscontents[2].numberofparameters = 4;
		ParametersList parameterslist02[4];
		parameterslist02[0].parameteridentifier = PARAMETER_IDENTIFIER_MFBR_UPLINK;
		parameterslist02[0].parametercontents.gfbrormfbr_uplinkordownlink.uint = GFBRORMFBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_16KBPS;
		parameterslist02[0].parametercontents.gfbrormfbr_uplinkordownlink.value = 0x3000;
		parameterslist02[1].parameteridentifier = PARAMETER_IDENTIFIER_MFBR_DOWNLINK;
		parameterslist02[1].parametercontents.gfbrormfbr_uplinkordownlink.uint = GFBRORMFBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_64KBPS;
		parameterslist02[1].parametercontents.gfbrormfbr_uplinkordownlink.value = 0x4000;
		parameterslist02[2].parameteridentifier = PARAMETER_IDENTIFIER_AVERAGING_WINDOW;
		parameterslist02[2].parametercontents.averagingwindow.uplinkinmilliseconds = GFBRORMFBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_256KBPS;
		parameterslist02[2].parametercontents.averagingwindow.downlinkinmilliseconds = GFBRORMFBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_1MBPS;
		parameterslist02[3].parameteridentifier = PARAMETER_IDENTIFIER_EPS_BEARER_IDENTITY;
		parameterslist02[3].parametercontents.epsbeareridentity = QOS_FLOW_EPS_BEARER_IDENTITY_VALUE15;
		qosflowdescriptionscontents[2].parameterslist = parameterslist02;

		sm_msg->specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionsnumber = 3;
		sm_msg->specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents = qosflowdescriptionscontents;

		unsigned char bitStream_extendedprotocolconfigurationoptions[4];
		bitStream_extendedprotocolconfigurationoptions[0] = 0x12;
		bitStream_extendedprotocolconfigurationoptions[1] = 0x13;
		bitStream_extendedprotocolconfigurationoptions[2] = 0x14;
		bitStream_extendedprotocolconfigurationoptions[3] = 0x15;
		bstring extendedprotocolconfigurationoptions_tmp = bfromcstralloc(4, "\0");
		//extendedprotocolconfigurationoptions_tmp->data = bitStream_extendedprotocolconfigurationoptions;
		extendedprotocolconfigurationoptions_tmp->slen = 4;
		memcpy(extendedprotocolconfigurationoptions_tmp->data,bitStream_extendedprotocolconfigurationoptions,sizeof(bitStream_extendedprotocolconfigurationoptions));
		sm_msg->specific_msg.pdu_session_modification_command.extendedprotocolconfigurationoptions = extendedprotocolconfigurationoptions_tmp;

		/*********************sm_msg->specific_msg.pdu_session_modification_command end******************************/


		nas_msg.plain.sm = *sm_msg;


		printf("nas header encode extended_protocol_discriminator:0x%x\n, security_header_type:0x%x\n,sequence_number:0x%x\n,message_authentication_code:0x%x\n",
		nas_msg.header.extended_protocol_discriminator,
		nas_msg.header.security_header_type,
		nas_msg.header.sequence_number,
		nas_msg.header.message_authentication_code);



		printf("sm header,extended_protocol_discriminator:0x%x,pdu_session_identity:0x%x,proeduer_transaction_identity:0x%x, message type:0x%x\n",
		sm_msg->header.extended_protocol_discriminator,
		sm_msg->header.pdu_session_identity,
		sm_msg->header.procedure_transaction_identity,
		sm_msg->header.message_type);

		//printf("message type:0x%x\n",sm_msg->specific_msg.pdu_session_modification_command.messagetype);
		//printf("extendedprotocoldiscriminator:0x%x\n",sm_msg->specific_msg.pdu_session_modification_command.extendedprotocoldiscriminator);
		//printf("pdu identity buffer:0x%x\n",*(unsigned char *)((sm_msg->specific_msg.pdu_session_modification_command.pdusessionidentity)->data));
		//printf("PTI buffer:0x%x\n",*(unsigned char *)((sm_msg->specific_msg.pdu_session_modification_command.proceduretransactionidentity)->data));


		printf("_5gsmcause: %#0x\n",sm_msg->specific_msg.pdu_session_modification_command._5gsmcause);

		printf("sessionambr: %x %x %x %x\n",
				sm_msg->specific_msg.pdu_session_modification_command.sessionambr.uint_for_session_ambr_for_downlink,
				sm_msg->specific_msg.pdu_session_modification_command.sessionambr.session_ambr_for_downlink,
				sm_msg->specific_msg.pdu_session_modification_command.sessionambr.uint_for_session_ambr_for_uplink,
				sm_msg->specific_msg.pdu_session_modification_command.sessionambr.session_ambr_for_uplink);

		printf("gprstimer -- unit: %#0x, timeValue: %#0x\n",
				sm_msg->specific_msg.pdu_session_modification_command.gprstimer.unit,
				sm_msg->specific_msg.pdu_session_modification_command.gprstimer.timeValue);

		printf("alwaysonpdusessionindication: %#0x\n",sm_msg->specific_msg.pdu_session_modification_command.alwaysonpdusessionindication.apsi_indication);

		printf("qosrules: %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x\n",
				sm_msg->specific_msg.pdu_session_modification_command.qosrules.lengthofqosrulesie,
				sm_msg->specific_msg.pdu_session_modification_command.qosrules.qosrulesie[0].qosruleidentifer,
				sm_msg->specific_msg.pdu_session_modification_command.qosrules.qosrulesie[0].ruleoperationcode,
				sm_msg->specific_msg.pdu_session_modification_command.qosrules.qosrulesie[0].dqrbit,
				sm_msg->specific_msg.pdu_session_modification_command.qosrules.qosrulesie[0].numberofpacketfilters,
				sm_msg->specific_msg.pdu_session_modification_command.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[0].packetfilterdirection,
				sm_msg->specific_msg.pdu_session_modification_command.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[0].packetfilteridentifier,
				sm_msg->specific_msg.pdu_session_modification_command.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[0].packetfiltercontents.component_type,
				sm_msg->specific_msg.pdu_session_modification_command.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[1].packetfilterdirection,
				sm_msg->specific_msg.pdu_session_modification_command.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[1].packetfilteridentifier,
				sm_msg->specific_msg.pdu_session_modification_command.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[1].packetfiltercontents.component_type,
				sm_msg->specific_msg.pdu_session_modification_command.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[2].packetfilterdirection,
				sm_msg->specific_msg.pdu_session_modification_command.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[2].packetfilteridentifier,
				sm_msg->specific_msg.pdu_session_modification_command.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[2].packetfiltercontents.component_type,
				sm_msg->specific_msg.pdu_session_modification_command.qosrules.qosrulesie[0].qosruleprecedence,
				sm_msg->specific_msg.pdu_session_modification_command.qosrules.qosrulesie[0].segregation,
				sm_msg->specific_msg.pdu_session_modification_command.qosrules.qosrulesie[0].qosflowidentifer,
				sm_msg->specific_msg.pdu_session_modification_command.qosrules.qosrulesie[1].qosruleidentifer,
				sm_msg->specific_msg.pdu_session_modification_command.qosrules.qosrulesie[1].ruleoperationcode,
				sm_msg->specific_msg.pdu_session_modification_command.qosrules.qosrulesie[1].dqrbit,
				sm_msg->specific_msg.pdu_session_modification_command.qosrules.qosrulesie[1].numberofpacketfilters,
				sm_msg->specific_msg.pdu_session_modification_command.qosrules.qosrulesie[1].packetfilterlist.modifyanddelete[0].packetfilteridentifier,
				sm_msg->specific_msg.pdu_session_modification_command.qosrules.qosrulesie[1].packetfilterlist.modifyanddelete[1].packetfilteridentifier,
				sm_msg->specific_msg.pdu_session_modification_command.qosrules.qosrulesie[1].packetfilterlist.modifyanddelete[2].packetfilteridentifier,
				sm_msg->specific_msg.pdu_session_modification_command.qosrules.qosrulesie[1].qosruleprecedence,
				sm_msg->specific_msg.pdu_session_modification_command.qosrules.qosrulesie[1].segregation,
				sm_msg->specific_msg.pdu_session_modification_command.qosrules.qosrulesie[1].qosflowidentifer);

		//printf("mappedepsbearercontexts");

		printf("qosflowdescriptions: %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x\n",
				sm_msg->specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionsnumber,
				sm_msg->specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[0].qfi,
				sm_msg->specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[0].operationcode,
				sm_msg->specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[0].e,
				sm_msg->specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[0].numberofparameters,
				sm_msg->specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[0].parameteridentifier,
				sm_msg->specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[0].parametercontents._5qi,
				sm_msg->specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[1].parameteridentifier,
				sm_msg->specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[1].parametercontents.gfbrormfbr_uplinkordownlink.uint,
				sm_msg->specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[1].parametercontents.gfbrormfbr_uplinkordownlink.value,
				sm_msg->specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[2].parameteridentifier,
				sm_msg->specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[2].parametercontents.gfbrormfbr_uplinkordownlink.uint,
				sm_msg->specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[2].parametercontents.gfbrormfbr_uplinkordownlink.value,
				sm_msg->specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[1].qfi,
				sm_msg->specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[1].operationcode,
				sm_msg->specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[1].e,
				sm_msg->specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[1].numberofparameters,
				sm_msg->specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[2].qfi,
				sm_msg->specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[2].operationcode,
				sm_msg->specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[2].e,
				sm_msg->specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[2].numberofparameters,
				sm_msg->specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[0].parameteridentifier,
				sm_msg->specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[0].parametercontents.gfbrormfbr_uplinkordownlink.uint,
				sm_msg->specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[0].parametercontents.gfbrormfbr_uplinkordownlink.value,
				sm_msg->specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[1].parameteridentifier,
				sm_msg->specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[1].parametercontents.gfbrormfbr_uplinkordownlink.uint,
				sm_msg->specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[1].parametercontents.gfbrormfbr_uplinkordownlink.value,
				sm_msg->specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[2].parameteridentifier,
				sm_msg->specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[2].parametercontents.averagingwindow.uplinkinmilliseconds,
				sm_msg->specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[2].parametercontents.averagingwindow.downlinkinmilliseconds,
				sm_msg->specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[3].parameteridentifier,
				sm_msg->specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[3].parametercontents.epsbeareridentity);

		printf("extend_options buffer:%x %x %x %x\n",
				(unsigned char)(sm_msg->specific_msg.pdu_session_modification_command.extendedprotocolconfigurationoptions->data[0]),
				(unsigned char)(sm_msg->specific_msg.pdu_session_modification_command.extendedprotocolconfigurationoptions->data[1]),
				(unsigned char)(sm_msg->specific_msg.pdu_session_modification_command.extendedprotocolconfigurationoptions->data[2]),
				(unsigned char)(sm_msg->specific_msg.pdu_session_modification_command.extendedprotocolconfigurationoptions->data[3]));

		//bytes = nas_message_encode (data, &nas_msg, 60/*don't know the size*/, security);
		bytes = nas_message_encode (data, &nas_msg, sizeof(data)/*don't know the size*/, &securityencode);

		//nas_msg_str = reinterpret_cast<char*> (data);
		printf("Data = ");
		for(int i = 0;i<bytes;i++)
			printf("Data = %02x ",data[i]);
		printf("\n");
		std::string n1Message ((char*) data,  bytes);
		nas_msg_str = n1Message;
		Logger::smf_app().debug("n1MessageContent: %d, %s\n ", bytes, nas_msg_str.c_str());
		printf("PDU_SESSION_MODIFICATION_COMMAND------------ encode end\n\n");
	}
	break;

	case PDU_SESSION_MODIFICATION_COMPLETE:{
		printf("\n\nPDU_SESSION_MODIFICATION_COMPLETE------------ encode start\n");
		sm_msg->header.message_type = PDU_SESSION_MODIFICATION_COMPLETE;

		sm_msg->specific_msg.pdu_session_modification_complete.presence = 0x01;

		unsigned char bitStream_extendedprotocolconfigurationoptions[4];
	    bitStream_extendedprotocolconfigurationoptions[0] = 0x12;
	    bitStream_extendedprotocolconfigurationoptions[1] = 0x13;
	    bitStream_extendedprotocolconfigurationoptions[2] = 0x14;
	    bitStream_extendedprotocolconfigurationoptions[3] = 0x15;
	    bstring extendedprotocolconfigurationoptions_tmp = bfromcstralloc(4, "\0");
	    //extendedprotocolconfigurationoptions_tmp->data = bitStream_extendedprotocolconfigurationoptions;
	    extendedprotocolconfigurationoptions_tmp->slen = 4;
	    memcpy(extendedprotocolconfigurationoptions_tmp->data,bitStream_extendedprotocolconfigurationoptions,sizeof(bitStream_extendedprotocolconfigurationoptions));
		sm_msg->specific_msg.pdu_session_modification_complete.extendedprotocolconfigurationoptions = extendedprotocolconfigurationoptions_tmp;


	/*********************sm_msg->specific_msg.pdu_session_modification_complete end******************************/

		nas_msg.plain.sm = *sm_msg;


		printf("nas header encode extended_protocol_discriminator:0x%x\n, security_header_type:0x%x\n,sequence_number:0x%x\n,message_authentication_code:0x%x\n",
				nas_msg.header.extended_protocol_discriminator,
				nas_msg.header.security_header_type,
				nas_msg.header.sequence_number,
				nas_msg.header.message_authentication_code);



		printf("sm header,extended_protocol_discriminator:0x%x,pdu_session_identity:0x%x,proeduer_transaction_identity:0x%x, message type:0x%x\n",
		sm_msg->header.extended_protocol_discriminator,
	    sm_msg->header.pdu_session_identity,
		sm_msg->header.procedure_transaction_identity,
		sm_msg->header.message_type);


		printf("extend_options buffer:0x%x 0x%x 0x%x 0x%x\n",(unsigned char)((sm_msg->specific_msg.pdu_session_modification_complete.extendedprotocolconfigurationoptions)->data[0]),(unsigned char)((sm_msg->specific_msg.pdu_session_modification_complete.extendedprotocolconfigurationoptions)->data[1]),(unsigned char)((sm_msg->specific_msg.pdu_session_modification_complete.extendedprotocolconfigurationoptions)->data[2]),(unsigned char)((sm_msg->specific_msg.pdu_session_modification_complete.extendedprotocolconfigurationoptions)->data[3]));

		//bytes = nas_message_encode (data, &nas_msg, 60/*don't know the size*/, security);
		bytes = nas_message_encode (data, &nas_msg, sizeof(data)/*don't know the size*/, &securityencode);

		//nas_msg_str = reinterpret_cast<char*> (data);
		printf("Data = ");
		for(int i = 0;i<bytes;i++)
			printf("Data = %02x ",data[i]);
		printf("\n");
		std::string n1Message ((char*) data,  bytes);
		nas_msg_str = n1Message;
		Logger::smf_app().debug("n1MessageContent: %d, %s\n ", bytes, nas_msg_str.c_str());
		printf("PDU_SESSION_MODIFICATION_COMPLETE------------ encode end\n\n");
	}
	break;

	case PDU_SESSION_MODIFICATION_COMMANDREJECT:{
		printf("\n\nPDU_SESSION_MODIFICATION_COMMANDREJECT------------ encode start\n");
		sm_msg->header.message_type = PDU_SESSION_MODIFICATION_COMMANDREJECT;

		sm_msg->specific_msg.pdu_session_modification_command_reject._5gsmcause = 0b00001000;

		sm_msg->specific_msg.pdu_session_modification_command_reject.presence = 0x01;

		unsigned char bitStream_extendedprotocolconfigurationoptions[4];
	    bitStream_extendedprotocolconfigurationoptions[0] = 0x12;
	    bitStream_extendedprotocolconfigurationoptions[1] = 0x13;
	    bitStream_extendedprotocolconfigurationoptions[2] = 0x14;
	    bitStream_extendedprotocolconfigurationoptions[3] = 0x15;
	    bstring extendedprotocolconfigurationoptions_tmp = bfromcstralloc(4, "\0");
	    //extendedprotocolconfigurationoptions_tmp->data = bitStream_extendedprotocolconfigurationoptions;
	    extendedprotocolconfigurationoptions_tmp->slen = 4;
	    memcpy(extendedprotocolconfigurationoptions_tmp->data,bitStream_extendedprotocolconfigurationoptions,sizeof(bitStream_extendedprotocolconfigurationoptions));
		sm_msg->specific_msg.pdu_session_modification_command_reject.extendedprotocolconfigurationoptions = extendedprotocolconfigurationoptions_tmp;

	/*********************sm_msg->specific_msg.pdu_session_modification_command_reject end******************************/

		nas_msg.plain.sm = *sm_msg;


		printf("nas header encode extended_protocol_discriminator:0x%x\n, security_header_type:0x%x\n,sequence_number:0x%x\n,message_authentication_code:0x%x\n",
				nas_msg.header.extended_protocol_discriminator,
				nas_msg.header.security_header_type,
				nas_msg.header.sequence_number,
				nas_msg.header.message_authentication_code);



		printf("sm header,extended_protocol_discriminator:0x%x,pdu_session_identity:0x%x,proeduer_transaction_identity:0x%x, message type:0x%x\n",
		sm_msg->header.extended_protocol_discriminator,
	    sm_msg->header.pdu_session_identity,
		sm_msg->header.procedure_transaction_identity,
		sm_msg->header.message_type);


		printf("_5gsmcause: 0x%x\n",sm_msg->specific_msg.pdu_session_modification_command_reject._5gsmcause);
	    printf("extend_options buffer:0x%x 0x%x 0x%x 0x%x\n",(unsigned char)((sm_msg->specific_msg.pdu_session_modification_command_reject.extendedprotocolconfigurationoptions)->data[0]),(unsigned char)((sm_msg->specific_msg.pdu_session_modification_command_reject.extendedprotocolconfigurationoptions)->data[1]),(unsigned char)((sm_msg->specific_msg.pdu_session_modification_command_reject.extendedprotocolconfigurationoptions)->data[2]),(unsigned char)((sm_msg->specific_msg.pdu_session_modification_command_reject.extendedprotocolconfigurationoptions)->data[3]));

		//bytes = nas_message_encode (data, &nas_msg, 60/*don't know the size*/, security);
		bytes = nas_message_encode (data, &nas_msg, sizeof(data)/*don't know the size*/, &securityencode);

		//nas_msg_str = reinterpret_cast<char*> (data);
		printf("Data = ");
		for(int i = 0;i<bytes;i++)
			printf("Data = %02x ",data[i]);
		printf("\n");
		std::string n1Message ((char*) data,  bytes);
		nas_msg_str = n1Message;
		Logger::smf_app().debug("n1MessageContent: %d, %s\n ", bytes, nas_msg_str.c_str());
		printf("PDU_SESSION_MODIFICATION_COMMANDREJECT------------ encode end\n\n");
	}
	break;

	case PDU_SESSION_RELEASE_REQUEST:{
		printf("\n\nPDU_SESSION_RELEASE_REQUEST------------ encode start\n");
		sm_msg->header.message_type = PDU_SESSION_RELEASE_REQUEST;

		sm_msg->specific_msg.pdu_session_release_request.presence = 0x03;

		sm_msg->specific_msg.pdu_session_release_request._5gsmcause = 0b00001000;

		unsigned char bitStream_extendedprotocolconfigurationoptions[4];
	    bitStream_extendedprotocolconfigurationoptions[0] = 0x12;
	    bitStream_extendedprotocolconfigurationoptions[1] = 0x13;
	    bitStream_extendedprotocolconfigurationoptions[2] = 0x14;
	    bitStream_extendedprotocolconfigurationoptions[3] = 0x15;
	    bstring extendedprotocolconfigurationoptions_tmp = bfromcstralloc(4, "\0");
	    //extendedprotocolconfigurationoptions_tmp->data = bitStream_extendedprotocolconfigurationoptions;
	    extendedprotocolconfigurationoptions_tmp->slen = 4;
	    memcpy(extendedprotocolconfigurationoptions_tmp->data,bitStream_extendedprotocolconfigurationoptions,sizeof(bitStream_extendedprotocolconfigurationoptions));
		sm_msg->specific_msg.pdu_session_release_request.extendedprotocolconfigurationoptions = extendedprotocolconfigurationoptions_tmp;

	/*********************sm_msg->specific_msg.pdu_session_release_request end******************************/

		nas_msg.plain.sm = *sm_msg;

		printf("nas header encode extended_protocol_discriminator:0x%x\n, security_header_type:0x%x\n,sequence_number:0x%x\n,message_authentication_code:0x%x\n",
				nas_msg.header.extended_protocol_discriminator,
				nas_msg.header.security_header_type,
				nas_msg.header.sequence_number,
				nas_msg.header.message_authentication_code);



		printf("sm header,extended_protocol_discriminator:0x%x,pdu_session_identity:0x%x,proeduer_transaction_identity:0x%x, message type:0x%x\n",
		sm_msg->header.extended_protocol_discriminator,
	    sm_msg->header.pdu_session_identity,
		sm_msg->header.procedure_transaction_identity,
		sm_msg->header.message_type);


		printf("_5gsmcause: 0x%x\n",sm_msg->specific_msg.pdu_session_release_request._5gsmcause);
	    printf("extend_options buffer:0x%x 0x%x 0x%x 0x%x\n",(unsigned char)((sm_msg->specific_msg.pdu_session_release_request.extendedprotocolconfigurationoptions)->data[0]),(unsigned char)((sm_msg->specific_msg.pdu_session_release_request.extendedprotocolconfigurationoptions)->data[1]),(unsigned char)((sm_msg->specific_msg.pdu_session_release_request.extendedprotocolconfigurationoptions)->data[2]),(unsigned char)((sm_msg->specific_msg.pdu_session_release_request.extendedprotocolconfigurationoptions)->data[3]));

		//bytes = nas_message_encode (data, &nas_msg, 60/*don't know the size*/, security);
		bytes = nas_message_encode (data, &nas_msg, sizeof(data)/*don't know the size*/, &securityencode);

		//nas_msg_str = reinterpret_cast<char*> (data);
		printf("Data = ");
		for(int i = 0;i<bytes;i++)
			printf("Data = %02x ",data[i]);
		printf("\n");
		std::string n1Message ((char*) data,  bytes);
		nas_msg_str = n1Message;
		Logger::smf_app().debug("n1MessageContent: %d, %s\n ", bytes, nas_msg_str.c_str());
		printf("PDU_SESSION_RELEASE_REQUEST------------ encode end\n\n");
	}
	break;

	case PDU_SESSION_RELEASE_REJECT:{
		printf("\n\nPDU_SESSION_RELEASE_REJECT------------ encode start\n");
		sm_msg->header.message_type = PDU_SESSION_RELEASE_REJECT;

		sm_msg->specific_msg.pdu_session_release_reject._5gsmcause = 0b00001000;

		sm_msg->specific_msg.pdu_session_release_reject.presence = 0x01;

		unsigned char bitStream_extendedprotocolconfigurationoptions[4];
	    bitStream_extendedprotocolconfigurationoptions[0] = 0x12;
	    bitStream_extendedprotocolconfigurationoptions[1] = 0x13;
	    bitStream_extendedprotocolconfigurationoptions[2] = 0x14;
	    bitStream_extendedprotocolconfigurationoptions[3] = 0x15;
	    bstring extendedprotocolconfigurationoptions_tmp = bfromcstralloc(4, "\0");
	    //extendedprotocolconfigurationoptions_tmp->data = bitStream_extendedprotocolconfigurationoptions;
	    extendedprotocolconfigurationoptions_tmp->slen = 4;
	    memcpy(extendedprotocolconfigurationoptions_tmp->data,bitStream_extendedprotocolconfigurationoptions,sizeof(bitStream_extendedprotocolconfigurationoptions));
		sm_msg->specific_msg.pdu_session_release_reject.extendedprotocolconfigurationoptions = extendedprotocolconfigurationoptions_tmp;

	/*********************sm_msg->specific_msg.pdu_session_release_reject end******************************/

		nas_msg.plain.sm = *sm_msg;

		printf("nas header encode extended_protocol_discriminator:0x%x\n, security_header_type:0x%x\n,sequence_number:0x%x\n,message_authentication_code:0x%x\n",
				nas_msg.header.extended_protocol_discriminator,
				nas_msg.header.security_header_type,
				nas_msg.header.sequence_number,
				nas_msg.header.message_authentication_code);



		printf("sm header,extended_protocol_discriminator:0x%x,pdu_session_identity:0x%x,proeduer_transaction_identity:0x%x, message type:0x%x\n",
		sm_msg->header.extended_protocol_discriminator,
	    sm_msg->header.pdu_session_identity,
		sm_msg->header.procedure_transaction_identity,
		sm_msg->header.message_type);


		printf("_5gsmcause: 0x%x\n",sm_msg->specific_msg.pdu_session_release_reject._5gsmcause);
	    printf("extend_options buffer:0x%x 0x%x 0x%x 0x%x\n",(unsigned char)((sm_msg->specific_msg.pdu_session_release_reject.extendedprotocolconfigurationoptions)->data[0]),(unsigned char)((sm_msg->specific_msg.pdu_session_release_reject.extendedprotocolconfigurationoptions)->data[1]),(unsigned char)((sm_msg->specific_msg.pdu_session_release_reject.extendedprotocolconfigurationoptions)->data[2]),(unsigned char)((sm_msg->specific_msg.pdu_session_release_reject.extendedprotocolconfigurationoptions)->data[3]));

		//bytes = nas_message_encode (data, &nas_msg, 60/*don't know the size*/, security);
		bytes = nas_message_encode (data, &nas_msg, sizeof(data)/*don't know the size*/, &securityencode);

		//nas_msg_str = reinterpret_cast<char*> (data);
		printf("Data = ");
		for(int i = 0;i<bytes;i++)
			printf("Data = %02x ",data[i]);
		printf("\n");
		std::string n1Message ((char*) data,  bytes);
		nas_msg_str = n1Message;
		Logger::smf_app().debug("n1MessageContent: %d, %s\n ", bytes, nas_msg_str.c_str());
		printf("PDU_SESSION_RELEASE_REJECT------------ encode end\n\n");
	}
	break;

	case PDU_SESSION_RELEASE_COMMAND:{
		printf("\n\nPDU_SESSION_RELEASE_COMMAND------------ encode start\n");
		sm_msg->header.message_type = PDU_SESSION_RELEASE_COMMAND;

		sm_msg->specific_msg.pdu_session_release_command._5gsmcause = 0b00001000;

		sm_msg->specific_msg.pdu_session_release_command.presence = 0x0f;

		sm_msg->specific_msg.pdu_session_release_command.gprstimer3.unit = GPRSTIMER3_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_1_HOUR;
		sm_msg->specific_msg.pdu_session_release_command.gprstimer3.timeValue = 0;

		unsigned char bitStream_eapmessage[2] = {0x01,0x02};
	    bstring eapmessage_tmp = bfromcstralloc(2, "\0");
	    eapmessage_tmp->slen = 2;
	    memcpy(eapmessage_tmp->data,bitStream_eapmessage,sizeof(bitStream_eapmessage));
		sm_msg->specific_msg.pdu_session_release_command.eapmessage = eapmessage_tmp;

		sm_msg->specific_msg.pdu_session_release_command._5gsmcongestionreattemptindicator.abo = THE_BACKOFF_TIMER_IS_APPLIED_IN_ALL_PLMNS;

		unsigned char bitStream_extendedprotocolconfigurationoptions[4];
	    bitStream_extendedprotocolconfigurationoptions[0] = 0x12;
	    bitStream_extendedprotocolconfigurationoptions[1] = 0x13;
	    bitStream_extendedprotocolconfigurationoptions[2] = 0x14;
	    bitStream_extendedprotocolconfigurationoptions[3] = 0x15;
	    bstring extendedprotocolconfigurationoptions_tmp = bfromcstralloc(4, "\0");
	    //extendedprotocolconfigurationoptions_tmp->data = bitStream_extendedprotocolconfigurationoptions;
	    extendedprotocolconfigurationoptions_tmp->slen = 4;
	    memcpy(extendedprotocolconfigurationoptions_tmp->data,bitStream_extendedprotocolconfigurationoptions,sizeof(bitStream_extendedprotocolconfigurationoptions));
		sm_msg->specific_msg.pdu_session_release_command.extendedprotocolconfigurationoptions = extendedprotocolconfigurationoptions_tmp;



	/*********************sm_msg->specific_msg.pdu_session_release_command end******************************/

		nas_msg.plain.sm = *sm_msg;


		printf("nas header encode extended_protocol_discriminator:0x%x\n, security_header_type:0x%x\n,sequence_number:0x%x\n,message_authentication_code:0x%x\n",
				nas_msg.header.extended_protocol_discriminator,
				nas_msg.header.security_header_type,
				nas_msg.header.sequence_number,
				nas_msg.header.message_authentication_code);



		printf("sm header,extended_protocol_discriminator:0x%x,pdu_session_identity:0x%x,proeduer_transaction_identity:0x%x, message type:0x%x\n",
		sm_msg->header.extended_protocol_discriminator,
	    sm_msg->header.pdu_session_identity,
		sm_msg->header.procedure_transaction_identity,
		sm_msg->header.message_type);


		printf("_5gsmcause: 0x%x\n",sm_msg->specific_msg.pdu_session_release_command._5gsmcause);
	    printf("gprstimer3 --- unit_bits_H3: 0x%x,timeValue_bits_L5: 0x%x\n",sm_msg->specific_msg.pdu_session_release_command.gprstimer3.unit,sm_msg->specific_msg.pdu_session_release_command.gprstimer3.timeValue);
		printf("eapmessage buffer:0x%x 0x%x\n",(unsigned char)(sm_msg->specific_msg.pdu_session_release_command.eapmessage->data[0]),(unsigned char )(sm_msg->specific_msg.pdu_session_release_command.eapmessage->data[1]));
		printf("_5gsmcongestionreattemptindicator bits_1 --- abo:0x%x\n",sm_msg->specific_msg.pdu_session_release_command._5gsmcongestionreattemptindicator.abo);
		printf("extend_options buffer:0x%x 0x%x 0x%x 0x%x\n",(unsigned char)((sm_msg->specific_msg.pdu_session_release_command.extendedprotocolconfigurationoptions)->data[0]),(unsigned char)((sm_msg->specific_msg.pdu_session_release_command.extendedprotocolconfigurationoptions)->data[1]),(unsigned char)((sm_msg->specific_msg.pdu_session_release_command.extendedprotocolconfigurationoptions)->data[2]),(unsigned char)((sm_msg->specific_msg.pdu_session_release_command.extendedprotocolconfigurationoptions)->data[3]));

		//bytes = nas_message_encode (data, &nas_msg, 60/*don't know the size*/, security);
		bytes = nas_message_encode (data, &nas_msg, sizeof(data)/*don't know the size*/, &securityencode);

		//nas_msg_str = reinterpret_cast<char*> (data);
		printf("Data = ");
		for(int i = 0;i<bytes;i++)
			printf("Data = %02x ",data[i]);
		printf("\n");
		std::string n1Message ((char*) data,  bytes);
		nas_msg_str = n1Message;
		Logger::smf_app().debug("n1MessageContent: %d, %s\n ", bytes, nas_msg_str.c_str());
		printf("PDU_SESSION_RELEASE_COMMAND------------ encode end\n");
	}
	break;

	case PDU_SESSION_RELEASE_COMPLETE:{
		printf("\n\nPDU_SESSION_RELEASE_COMPLETE------------ encode start\n");
		sm_msg->header.message_type = PDU_SESSION_RELEASE_COMPLETE;

		sm_msg->specific_msg.pdu_session_release_complete.presence = 0x03;

		sm_msg->specific_msg.pdu_session_release_complete._5gsmcause = 0b00001000;

		unsigned char bitStream_extendedprotocolconfigurationoptions[4];
	    bitStream_extendedprotocolconfigurationoptions[0] = 0x12;
	    bitStream_extendedprotocolconfigurationoptions[1] = 0x13;
	    bitStream_extendedprotocolconfigurationoptions[2] = 0x14;
	    bitStream_extendedprotocolconfigurationoptions[3] = 0x15;
	    bstring extendedprotocolconfigurationoptions_tmp = bfromcstralloc(4, "\0");
	    //extendedprotocolconfigurationoptions_tmp->data = bitStream_extendedprotocolconfigurationoptions;
	    extendedprotocolconfigurationoptions_tmp->slen = 4;
	    memcpy(extendedprotocolconfigurationoptions_tmp->data,bitStream_extendedprotocolconfigurationoptions,sizeof(bitStream_extendedprotocolconfigurationoptions));
		sm_msg->specific_msg.pdu_session_release_complete.extendedprotocolconfigurationoptions = extendedprotocolconfigurationoptions_tmp;



	/*********************sm_msg->specific_msg.pdu_session_release_complete end******************************/

		nas_msg.plain.sm = *sm_msg;


		printf("nas header encode extended_protocol_discriminator:0x%x\n, security_header_type:0x%x\n,sequence_number:0x%x\n,message_authentication_code:0x%x\n",
				nas_msg.header.extended_protocol_discriminator,
				nas_msg.header.security_header_type,
				nas_msg.header.sequence_number,
				nas_msg.header.message_authentication_code);



		printf("sm header,extended_protocol_discriminator:0x%x,pdu_session_identity:0x%x,proeduer_transaction_identity:0x%x, message type:0x%x\n",
		sm_msg->header.extended_protocol_discriminator,
	    sm_msg->header.pdu_session_identity,
		sm_msg->header.procedure_transaction_identity,
		sm_msg->header.message_type);


		printf("_5gsmcause: 0x%x\n",sm_msg->specific_msg.pdu_session_release_complete._5gsmcause);
	    printf("extend_options buffer:0x%x 0x%x 0x%x 0x%x\n",(unsigned char)((sm_msg->specific_msg.pdu_session_release_complete.extendedprotocolconfigurationoptions)->data[0]),(unsigned char)((sm_msg->specific_msg.pdu_session_release_complete.extendedprotocolconfigurationoptions)->data[1]),(unsigned char)((sm_msg->specific_msg.pdu_session_release_complete.extendedprotocolconfigurationoptions)->data[2]),(unsigned char)((sm_msg->specific_msg.pdu_session_release_complete.extendedprotocolconfigurationoptions)->data[3]));

		//bytes = nas_message_encode (data, &nas_msg, 60/*don't know the size*/, security);
		bytes = nas_message_encode (data, &nas_msg, sizeof(data)/*don't know the size*/, &securityencode);

		//nas_msg_str = reinterpret_cast<char*> (data);
		printf("Data = ");
		for(int i = 0;i<bytes;i++)
			printf("Data = %02x ",data[i]);
		printf("\n");
		std::string n1Message ((char*) data,  bytes);
		nas_msg_str = n1Message;
		Logger::smf_app().debug("n1MessageContent: %d, %s\n ", bytes, nas_msg_str.c_str());
		printf("PDU_SESSION_RELEASE_COMPLETE------------ encode end\n\n");
	}
	break;

	case _5GSM_STATUS:{
		printf("\n\n5GSM_STATUS------------ encode start\n");
		sm_msg->header.message_type = _5GSM_STATUS;

		sm_msg->specific_msg._5gsm_status._5gsmcause = 0b00001000;


/*********************sm_msg->specific_msg._5gsm_status end******************************/

		nas_msg.plain.sm = *sm_msg;

		printf("nas header encode extended_protocol_discriminator:0x%x\n, security_header_type:0x%x\n,sequence_number:0x%x\n,message_authentication_code:0x%x\n",
				nas_msg.header.extended_protocol_discriminator,
				nas_msg.header.security_header_type,
				nas_msg.header.sequence_number,
				nas_msg.header.message_authentication_code);



		printf("sm header,extended_protocol_discriminator:0x%x,pdu_session_identity:0x%x,proeduer_transaction_identity:0x%x, message type:0x%x\n",
		sm_msg->header.extended_protocol_discriminator,
	    sm_msg->header.pdu_session_identity,
		sm_msg->header.procedure_transaction_identity,
		sm_msg->header.message_type);


		printf("_5gsmcause: 0x%x\n",sm_msg->specific_msg._5gsm_status._5gsmcause);

		//bytes = nas_message_encode (data, &nas_msg, 60/*don't know the size*/, security);
		bytes = nas_message_encode (data, &nas_msg, sizeof(data)/*don't know the size*/, &securityencode);

		//nas_msg_str = reinterpret_cast<char*> (data);
		printf("Data = ");
		for(int i = 0;i<bytes;i++)
			printf("Data = %02x ",data[i]);
		printf("\n");
		std::string n1Message ((char*) data,  bytes);
		nas_msg_str = n1Message;
		Logger::smf_app().debug("n1MessageContent: %d, %s\n ", bytes, nas_msg_str.c_str());
		printf("5GSM_STATUS------------ encode end\n\n");
	}
	break;

	default:
		Logger::smf_app().debug("Unknown message type: %d \n", msg_type);
	}
}

//------------------------------------------------------------------------------
void smf_app::create_n1_sm_container(std::shared_ptr<itti_n11_create_sm_context_request> sm_context_req, uint8_t msg_type, std::string& nas_msg_str,  uint8_t sm_cause)
{
	//TODO: should work with BUPT to finish this function
}

//------------------------------------------------------------------------------
void smf_app::create_n2_sm_information(std::shared_ptr<itti_n11_create_sm_context_response> sm_context_res, uint8_t ngap_msg_type, uint8_t ngap_ie_type, std::string& ngap_msg_str)
{
	//TODO: should work with BUPT to finish this function
	Logger::smf_app().info("Create N2 SM Information, ngap message type %d, ie type %d\n", ngap_msg_type, ngap_ie_type);

    #if 0
    switch(ngap_ie_type)
    {
        case Ngap_InitiatingMessage__value_PR_PDUSessionResourceSetupRequest:
			 make_NGAP_pdu_session_resource_setup_request();
		break;
		case Ngap_InitiatingMessage__value_PR_PDUSessionResourceSetupRequest:
			 make_NGAP_pdu_session_resource_setup_response();
		break;
        default:
			 printf("don't know ngap_ie_type:%d\n", ngap_ie_type);
	}
    #endif

	make_NGAP_PduSessionResourceSetupRequest("", "");
	make_NGAP_PduSessionResourceSetupResponse("", "");
	make_NGAP_PduSessionResourceReleaseCommand("", "");
	make_NGAP_PduSessionResourceReleaseResponse("", "");
	make_NGAP_PduSessionResourceModifyRequest("", "");
	make_NGAP_PduSessionResourceModifyResponse("","");
	make_NGAP_PduSessionResourceNotify("",  "");
	make_NGAP_PduSessionResourceModifyIndication("", "");
	make_NGAP_PduSessionResourceModifyConfirm("", "");

	
	make_NGAP_PduHandOverRequired("", "");
	make_NGAP_PduHandOverCommand("", "");
	make_NGAP_PduHandOverPreFailure("","");

	
	make_NGAP_PduHandOver_Req_Ack("","");
	make_NGAP_PduHandOver_Failure("","");
	make_NGAP_PduHandOver_Notify("","");
	
	//make_NGAP_PduSessionResourceReleaseCommand("", "");
	
    //make_NGAP_pdu_session_resource_setup_request();
	//make_NGAP_pdu_session_resource_setup_response();
	
       
   
}

//------------------------------------------------------------------------------
int smf_app::decode_nas_message_n1_sm_container(nas_message_t& nas_msg, std::string& n1_sm_msg)
{
	//TODO: should work with BUPT to finish this function
	Logger::smf_app().info("Decode NAS message from N1 SM Container\n");

	//step 1. Decode NAS  message (for instance, ... only served as an example)
	nas_message_decode_status_t   decode_status = {0};
	int decoder_rc = RETURNok;

	unsigned int n1SmMsgLen = n1_sm_msg.length();//strlen(n1_sm_msg.c_str());
	unsigned char datavalue[512]  = {'\0'}; // = (unsigned char *)malloc(n1SmMsgLen/2 + 1);
#if 1

	unsigned char *data = (unsigned char *)malloc(n1SmMsgLen + 1);//hardcoded for the moment
	memset(data,0,n1SmMsgLen + 1);

	memcpy ((void *)data, (void *)n1_sm_msg.c_str(),n1SmMsgLen);

	//memcpy ((void *)datavalue, (void *)n1_sm_msg.c_str(),n1SmMsgLen);

	printf("Data (%d bytes) = %s \n",n1SmMsgLen, data);

	for(int i = 0;i<n1SmMsgLen;i++)
		printf(" %02x ",data[i]);
	printf("\n");

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
#else
	memcpy ((void *)datavalue, (void *)n1_sm_msg.c_str(),n1SmMsgLen);
#endif
	//use a temporary security mechanism
	//construct decode security context
	static uint8_t fivegmm_security_context_flag = 0;
	static fivegmm_security_context_t securitydecode;
	if(!fivegmm_security_context_flag)
	{
		securitydecode.selected_algorithms.encryption = NAS_SECURITY_ALGORITHMS_NEA1;
		securitydecode.dl_count.overflow = 0xffff;
		securitydecode.dl_count.seq_num =  0x23;
		securitydecode.ul_count.overflow = 0xffff;
		securitydecode.ul_count.seq_num =  0x23;
		securitydecode.knas_enc[0] = 0x14;
		securitydecode.selected_algorithms.integrity = NAS_SECURITY_ALGORITHMS_NIA1;
		securitydecode.knas_int[0] = 0x41;
		
		fivegmm_security_context_flag ++;
	}

	//decode the NAS message (using NAS lib)
	decoder_rc = nas_message_decode (datavalue, &nas_msg, n1SmMsgLen/2, &securitydecode, &decode_status);
	Logger::smf_app().debug("NAS msg type 0x%x ", nas_msg.plain.sm.header.message_type);

	Logger::smf_app().debug("NAS header decode, extended_protocol_discriminator 0x%x, security_header_type:0x%x,sequence_number:0x%x,message_authentication_code:0x%x\n",
			nas_msg.header.extended_protocol_discriminator,
			nas_msg.header.security_header_type,
			nas_msg.header.sequence_number,
			nas_msg.header.message_authentication_code);

	Logger::smf_app().debug("NAS msg type 0x%x ", nas_msg.plain.sm.header.message_type);

	//nas_message_decode test
	switch(nas_msg.plain.sm.header.message_type)
	{
	case PDU_SESSION_ESTABLISHMENT_REQUEST:
		printf("PDU_SESSION_ESTABLISHMENT_REQUEST------------ decode start\n");
		printf("sm header,extended_protocol_discriminator:0x%x,pdu_session_identity:0x%x,procedure_transaction_identity:0x%x, message type:0x%x\n", nas_msg.plain.sm.header.extended_protocol_discriminator,nas_msg.plain.sm.header.pdu_session_identity,nas_msg.plain.sm.header.procedure_transaction_identity,nas_msg.plain.sm.header.message_type);
		printf("intergrity buffer:0x%x 0x%x\n",(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_establishment_request.intergrityprotectionmaximumdatarate)->data[0]),(unsigned char )((nas_msg.plain.sm.specific_msg.pdu_session_establishment_request.intergrityprotectionmaximumdatarate)->data[1]));
		printf("_pdusessiontype bits_3:0x%x\n",nas_msg.plain.sm.specific_msg.pdu_session_establishment_request._pdusessiontype.pdu_session_type_value);
		printf("sscmode bits_3:0x%x\n",nas_msg.plain.sm.specific_msg.pdu_session_establishment_request.sscmode.ssc_mode_value);
		printf("_5gsmcapability bits_5 --- MPTCP:0x%x ATS-LL:0x%x EPT-S1:0x%x MH6-PDU:0x%x RqoS:0x%x\n",nas_msg.plain.sm.specific_msg.pdu_session_establishment_request._5gsmcapability.is_MPTCP_supported,nas_msg.plain.sm.specific_msg.pdu_session_establishment_request._5gsmcapability.is_ATSLL_supported,nas_msg.plain.sm.specific_msg.pdu_session_establishment_request._5gsmcapability.is_EPTS1_supported,nas_msg.plain.sm.specific_msg.pdu_session_establishment_request._5gsmcapability.is_MH6PDU_supported,nas_msg.plain.sm.specific_msg.pdu_session_establishment_request._5gsmcapability.is_Rqos_supported);
		printf("maximum bits_11:0x%x\n",nas_msg.plain.sm.specific_msg.pdu_session_establishment_request.maximumnumberofsupportedpacketfilters);
		printf("Always-on bits_1 --- APSR:0x%x\n",nas_msg.plain.sm.specific_msg.pdu_session_establishment_request.alwaysonpdusessionrequested.apsr_requested);
		printf("sm_pdu_dn buffer:0x%x 0x%x 0x%x\n",(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_establishment_request.smpdudnrequestcontainer)->data[0]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_establishment_request.smpdudnrequestcontainer)->data[1]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_establishment_request.smpdudnrequestcontainer)->data[2]));
		printf("extend_options buffer:0x%x 0x%x 0x%x 0x%x\n",(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_establishment_request.extendedprotocolconfigurationoptions)->data[0]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_establishment_request.extendedprotocolconfigurationoptions)->data[1]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_establishment_request.extendedprotocolconfigurationoptions)->data[2]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_establishment_request.extendedprotocolconfigurationoptions)->data[3]));
		printf("PDU_SESSION_ESTABLISHMENT_REQUEST------------ decode end\n");
		break;
	case PDU_SESSION_ESTABLISHMENT_ACCEPT:
		printf("PDU_SESSION_ESTABLISHMENT_ACCEPT------------ decode start\n");
		printf("sm header,extended_protocol_discriminator:0x%x,pdu_session_identity:0x%x,procedure_transaction_identity:0x%x, message type:0x%x\n", nas_msg.plain.sm.header.extended_protocol_discriminator,nas_msg.plain.sm.header.pdu_session_identity,nas_msg.plain.sm.header.procedure_transaction_identity,nas_msg.plain.sm.header.message_type);
		printf("_pdusessiontype bits_3: %#0x\n",nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept._pdusessiontype.pdu_session_type_value);
		printf("sscmode bits_3: %#0x\n",nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.sscmode.ssc_mode_value);
		printf("qosrules: %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x\n",
				nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosrules.lengthofqosrulesie,
				nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[0].qosruleidentifer,
				nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[0].ruleoperationcode,
				nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[0].dqrbit,
				nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[0].numberofpacketfilters,
				nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[0].packetfilterdirection,
				nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[0].packetfilteridentifier,
				nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[0].packetfiltercontents.component_type,
				nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[1].packetfilterdirection,
				nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[1].packetfilteridentifier,
				nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[1].packetfiltercontents.component_type,
				nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[2].packetfilterdirection,
				nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[2].packetfilteridentifier,
				nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[2].packetfiltercontents.component_type,
				nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[0].qosruleprecedence,
				nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[0].segregation,
				nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[0].qosflowidentifer,
				nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[1].qosruleidentifer,
				nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[1].ruleoperationcode,
				nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[1].dqrbit,
				nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[1].numberofpacketfilters,
				nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[1].packetfilterlist.modifyanddelete[0].packetfilteridentifier,
				nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[1].packetfilterlist.modifyanddelete[1].packetfilteridentifier,
				nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[1].packetfilterlist.modifyanddelete[2].packetfilteridentifier,
				nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[1].qosruleprecedence,
				nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[1].segregation,
				nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[1].qosflowidentifer
				);

		printf("sessionambr: %x %x %x %x\n",nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.sessionambr.uint_for_session_ambr_for_downlink,
											nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.sessionambr.session_ambr_for_downlink,
											nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.sessionambr.uint_for_session_ambr_for_uplink,
											nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.sessionambr.session_ambr_for_uplink);

		printf("_5gsmcause: %#0x\n",nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept._5gsmcause);

		printf("pduaddress: %x %x %x %x %x\n",
				nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.pduaddress.pdu_session_type_value,
				(unsigned char)(nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.pduaddress.pdu_address_information->data[0]),
				(unsigned char)(nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.pduaddress.pdu_address_information->data[1]),
				(unsigned char)(nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.pduaddress.pdu_address_information->data[2]),
				(unsigned char)(nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.pduaddress.pdu_address_information->data[3]));

		printf("gprstimer -- unit: %#0x, timeValue: %#0x\n",
				nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.gprstimer.unit,
				nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.gprstimer.timeValue);

		printf("snssai -- len: %#0x, sst: %#0x, sd: %#0x\n",
				nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.snssai.len,
				nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.snssai.sst,
				nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.snssai.sd);

		printf("alwaysonpdusessionindication: %#0x\n",nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.alwaysonpdusessionindication.apsi_indication);

		//printf("mappedepsbearercontexts");

		printf("eapmessage buffer:%x %x\n",
				(unsigned char)(nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.eapmessage->data[0]),
				(unsigned char)(nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.eapmessage->data[1]));

		printf("qosflowdescriptions: %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x\n",
				nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionsnumber,
				nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[0].qfi,
				nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[0].operationcode,
				nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[0].e,
				nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[0].numberofparameters,
				nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[0].parameteridentifier,
				nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[0].parametercontents._5qi,
				nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[1].parameteridentifier,
				nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[1].parametercontents.gfbrormfbr_uplinkordownlink.uint,
				nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[1].parametercontents.gfbrormfbr_uplinkordownlink.value,
				nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[2].parameteridentifier,
				nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[2].parametercontents.gfbrormfbr_uplinkordownlink.uint,
				nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[2].parametercontents.gfbrormfbr_uplinkordownlink.value,
				nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[1].qfi,
				nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[1].operationcode,
				nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[1].e,
				nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[1].numberofparameters,
				nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].qfi,
				nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].operationcode,
				nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].e,
				nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].numberofparameters,
				nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[0].parameteridentifier,
				nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[0].parametercontents.gfbrormfbr_uplinkordownlink.uint,
				nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[0].parametercontents.gfbrormfbr_uplinkordownlink.value,
				nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[1].parameteridentifier,
				nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[1].parametercontents.gfbrormfbr_uplinkordownlink.uint,
				nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[1].parametercontents.gfbrormfbr_uplinkordownlink.value,
				nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[2].parameteridentifier,
				nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[2].parametercontents.averagingwindow.uplinkinmilliseconds,
				nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[2].parametercontents.averagingwindow.downlinkinmilliseconds,
				nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[3].parameteridentifier,
				nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[3].parametercontents.epsbeareridentity);

		printf("extend_options buffer:%x %x %x %x\n",
				(unsigned char)(nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.extendedprotocolconfigurationoptions->data[0]),
				(unsigned char)(nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.extendedprotocolconfigurationoptions->data[1]),
				(unsigned char)(nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.extendedprotocolconfigurationoptions->data[2]),
				(unsigned char)(nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.extendedprotocolconfigurationoptions->data[3]));

		printf("dnn buffer:%x %x %x\n",
				(unsigned char)(nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.dnn->data[0]),
				(unsigned char)(nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.dnn->data[1]),
				(unsigned char)(nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.dnn->data[2]));
		printf("PDU_SESSION_ESTABLISHMENT_ACCEPT------------ decode end\n");
		break;
	case PDU_SESSION_ESTABLISHMENT_REJECT:
		printf("PDU_SESSION_ESTABLISHMENT_REJECT------------ decode start\n");
		printf("sm header,extended_protocol_discriminator:0x%x,pdu_session_identity:0x%x,procedure_transaction_identity:0x%x, message type:0x%x\n", nas_msg.plain.sm.header.extended_protocol_discriminator,nas_msg.plain.sm.header.pdu_session_identity,nas_msg.plain.sm.header.procedure_transaction_identity,nas_msg.plain.sm.header.message_type);
		printf("_5gsmcause: 0x%x\n",nas_msg.plain.sm.specific_msg.pdu_session_establishment_reject._5gsmcause);
		printf("gprstimer3 --- unit_bits_H3: 0x%x,timeValue_bits_L5: 0x%x\n",nas_msg.plain.sm.specific_msg.pdu_session_establishment_reject.gprstimer3.unit,nas_msg.plain.sm.specific_msg.pdu_session_establishment_reject.gprstimer3.timeValue);
		printf("allowedsscmode --- is_ssc1_allowed: 0x%x, is_ssc2_allowed: 0x%x, is_ssc3_allowed: 0x%x\n",nas_msg.plain.sm.specific_msg.pdu_session_establishment_reject.allowedsscmode.is_ssc1_allowed,nas_msg.plain.sm.specific_msg.pdu_session_establishment_reject.allowedsscmode.is_ssc2_allowed,nas_msg.plain.sm.specific_msg.pdu_session_establishment_reject.allowedsscmode.is_ssc3_allowed);
		printf("eapmessage buffer:0x%x 0x%x\n",(unsigned char)(nas_msg.plain.sm.specific_msg.pdu_session_establishment_reject.eapmessage->data[0]),(unsigned char )(nas_msg.plain.sm.specific_msg.pdu_session_establishment_reject.eapmessage->data[1]));
		printf("extend_options buffer:0x%x 0x%x 0x%x 0x%x\n",(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_establishment_reject.extendedprotocolconfigurationoptions)->data[0]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_establishment_reject.extendedprotocolconfigurationoptions)->data[1]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_establishment_reject.extendedprotocolconfigurationoptions)->data[2]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_establishment_reject.extendedprotocolconfigurationoptions)->data[3]));
		printf("_5gsmcongestionreattemptindicator bits_1 --- abo:0x%x\n",nas_msg.plain.sm.specific_msg.pdu_session_establishment_reject._5gsmcongestionreattemptindicator.abo);
		printf("PDU_SESSION_ESTABLISHMENT_REJECT------------ decode end\n");
		break;
	case PDU_SESSION_AUTHENTICATION_COMMAND:
		printf("PDU_SESSION_AUTHENTICATION_COMMAND------------ decode start\n");
		printf("sm header,extended_protocol_discriminator:0x%x,pdu_session_identity:0x%x,procedure_transaction_identity:0x%x, message type:0x%x\n", nas_msg.plain.sm.header.extended_protocol_discriminator,nas_msg.plain.sm.header.pdu_session_identity,nas_msg.plain.sm.header.procedure_transaction_identity,nas_msg.plain.sm.header.message_type);
		printf("eapmessage buffer:0x%x 0x%x\n",(unsigned char)(nas_msg.plain.sm.specific_msg.pdu_session_authentication_command.eapmessage->data[0]),(unsigned char )(nas_msg.plain.sm.specific_msg.pdu_session_authentication_command.eapmessage->data[1]));
		printf("extend_options buffer:0x%x 0x%x 0x%x 0x%x\n",(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_authentication_command.extendedprotocolconfigurationoptions)->data[0]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_authentication_command.extendedprotocolconfigurationoptions)->data[1]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_authentication_command.extendedprotocolconfigurationoptions)->data[2]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_authentication_command.extendedprotocolconfigurationoptions)->data[3]));
		printf("PDU_SESSION_AUTHENTICATION_COMMAND------------ decode end\n");
		break;
	case PDU_SESSION_AUTHENTICATION_COMPLETE:
		printf("PDU_SESSION_AUTHENTICATION_COMPLETE------------ decode start\n");
		printf("sm header,extended_protocol_discriminator:0x%x,pdu_session_identity:0x%x,procedure_transaction_identity:0x%x, message type:0x%x\n", nas_msg.plain.sm.header.extended_protocol_discriminator,nas_msg.plain.sm.header.pdu_session_identity,nas_msg.plain.sm.header.procedure_transaction_identity,nas_msg.plain.sm.header.message_type);
		printf("eapmessage buffer:0x%x 0x%x\n",(unsigned char)(nas_msg.plain.sm.specific_msg.pdu_session_authentication_complete.eapmessage->data[0]),(unsigned char )(nas_msg.plain.sm.specific_msg.pdu_session_authentication_complete.eapmessage->data[1]));
		printf("extend_options buffer:0x%x 0x%x 0x%x 0x%x\n",(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_authentication_complete.extendedprotocolconfigurationoptions)->data[0]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_authentication_complete.extendedprotocolconfigurationoptions)->data[1]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_authentication_complete.extendedprotocolconfigurationoptions)->data[2]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_authentication_complete.extendedprotocolconfigurationoptions)->data[3]));
		printf("PDU_SESSION_AUTHENTICATION_COMPLETE------------ decode end\n");
		break;
	case PDU_SESSION_AUTHENTICATION_RESULT:
		printf("PDU_SESSION_AUTHENTICATION_RESULT------------ decode start\n");
		printf("sm header,extended_protocol_discriminator:0x%x,pdu_session_identity:0x%x,procedure_transaction_identity:0x%x, message type:0x%x\n", nas_msg.plain.sm.header.extended_protocol_discriminator,nas_msg.plain.sm.header.pdu_session_identity,nas_msg.plain.sm.header.procedure_transaction_identity,nas_msg.plain.sm.header.message_type);
		printf("eapmessage buffer:0x%x 0x%x\n",(unsigned char)(nas_msg.plain.sm.specific_msg.pdu_session_authentication_result.eapmessage->data[0]),(unsigned char )(nas_msg.plain.sm.specific_msg.pdu_session_authentication_result.eapmessage->data[1]));
		printf("extend_options buffer:0x%x 0x%x 0x%x 0x%x\n",(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_authentication_result.extendedprotocolconfigurationoptions)->data[0]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_authentication_result.extendedprotocolconfigurationoptions)->data[1]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_authentication_result.extendedprotocolconfigurationoptions)->data[2]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_authentication_result.extendedprotocolconfigurationoptions)->data[3]));
		printf("PDU_SESSION_AUTHENTICATION_RESULT------------ decode end\n");
		break;
	case PDU_SESSION_MODIFICATION_REQUEST:
		printf("PDU_SESSION_MODIFICATION_REQUEST------------ decode start\n");
		printf("sm header,extended_protocol_discriminator:0x%x,pdu_session_identity:0x%x,procedure_transaction_identity:0x%x, message type:0x%x\n", nas_msg.plain.sm.header.extended_protocol_discriminator,nas_msg.plain.sm.header.pdu_session_identity,nas_msg.plain.sm.header.procedure_transaction_identity,nas_msg.plain.sm.header.message_type);
		printf("_5gsmcapability bits_5 --- MPTCP:0x%x ATS-LL:0x%x EPT-S1:0x%x MH6-PDU:0x%x RqoS:0x%x\n",
			nas_msg.plain.sm.specific_msg.pdu_session_modification_request._5gsmcapability.is_MPTCP_supported,
			nas_msg.plain.sm.specific_msg.pdu_session_modification_request._5gsmcapability.is_ATSLL_supported,
			nas_msg.plain.sm.specific_msg.pdu_session_modification_request._5gsmcapability.is_EPTS1_supported,
			nas_msg.plain.sm.specific_msg.pdu_session_modification_request._5gsmcapability.is_MH6PDU_supported,
			nas_msg.plain.sm.specific_msg.pdu_session_modification_request._5gsmcapability.is_Rqos_supported);

		printf("_5gsmcause: %#0x\n",nas_msg.plain.sm.specific_msg.pdu_session_modification_request._5gsmcause);

		printf("maximum bits_11:0x%x\n",nas_msg.plain.sm.specific_msg.pdu_session_modification_request.maximumnumberofsupportedpacketfilters);

		printf("Always-on bits_1 --- APSR:0x%x\n",nas_msg.plain.sm.specific_msg.pdu_session_modification_request.alwaysonpdusessionrequested.apsr_requested);

		printf("intergrity buffer:0x%x 0x%x\n",
				(unsigned char)(nas_msg.plain.sm.specific_msg.pdu_session_modification_request.intergrityprotectionmaximumdatarate->data[0]),
				(unsigned char)(nas_msg.plain.sm.specific_msg.pdu_session_modification_request.intergrityprotectionmaximumdatarate->data[1]));

		printf("qosrules: %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x\n",
				nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosrules.lengthofqosrulesie,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosrules.qosrulesie[0].qosruleidentifer,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosrules.qosrulesie[0].ruleoperationcode,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosrules.qosrulesie[0].dqrbit,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosrules.qosrulesie[0].numberofpacketfilters,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[0].packetfilterdirection,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[0].packetfilteridentifier,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[0].packetfiltercontents.component_type,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[1].packetfilterdirection,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[1].packetfilteridentifier,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[1].packetfiltercontents.component_type,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[2].packetfilterdirection,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[2].packetfilteridentifier,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[2].packetfiltercontents.component_type,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosrules.qosrulesie[0].qosruleprecedence,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosrules.qosrulesie[0].segregation,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosrules.qosrulesie[0].qosflowidentifer,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosrules.qosrulesie[1].qosruleidentifer,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosrules.qosrulesie[1].ruleoperationcode,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosrules.qosrulesie[1].dqrbit,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosrules.qosrulesie[1].numberofpacketfilters,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosrules.qosrulesie[1].packetfilterlist.modifyanddelete[0].packetfilteridentifier,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosrules.qosrulesie[1].packetfilterlist.modifyanddelete[1].packetfilteridentifier,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosrules.qosrulesie[1].packetfilterlist.modifyanddelete[2].packetfilteridentifier,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosrules.qosrulesie[1].qosruleprecedence,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosrules.qosrulesie[1].segregation,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosrules.qosrulesie[1].qosflowidentifer);

		printf("qosflowdescriptions: %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x\n",
				nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionsnumber,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[0].qfi,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[0].operationcode,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[0].e,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[0].numberofparameters,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[0].parameteridentifier,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[0].parametercontents._5qi,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[1].parameteridentifier,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[1].parametercontents.gfbrormfbr_uplinkordownlink.uint,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[1].parametercontents.gfbrormfbr_uplinkordownlink.value,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[2].parameteridentifier,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[2].parametercontents.gfbrormfbr_uplinkordownlink.uint,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[2].parametercontents.gfbrormfbr_uplinkordownlink.value,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[1].qfi,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[1].operationcode,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[1].e,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[1].numberofparameters,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[2].qfi,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[2].operationcode,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[2].e,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[2].numberofparameters,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[0].parameteridentifier,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[0].parametercontents.gfbrormfbr_uplinkordownlink.uint,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[0].parametercontents.gfbrormfbr_uplinkordownlink.value,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[1].parameteridentifier,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[1].parametercontents.gfbrormfbr_uplinkordownlink.uint,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[1].parametercontents.gfbrormfbr_uplinkordownlink.value,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[2].parameteridentifier,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[2].parametercontents.averagingwindow.uplinkinmilliseconds,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[2].parametercontents.averagingwindow.downlinkinmilliseconds,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[3].parameteridentifier,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[3].parametercontents.epsbeareridentity);

		//printf("mappedepsbearercontexts");

		printf("extend_options buffer:%x %x %x %x\n",
				(unsigned char)(nas_msg.plain.sm.specific_msg.pdu_session_modification_request.extendedprotocolconfigurationoptions->data[0]),
				(unsigned char)(nas_msg.plain.sm.specific_msg.pdu_session_modification_request.extendedprotocolconfigurationoptions->data[1]),
				(unsigned char)(nas_msg.plain.sm.specific_msg.pdu_session_modification_request.extendedprotocolconfigurationoptions->data[2]),
				(unsigned char)(nas_msg.plain.sm.specific_msg.pdu_session_modification_request.extendedprotocolconfigurationoptions->data[3]));
		printf("PDU_SESSION_MODIFICATION_REQUEST------------ decode end\n");
		break;
	case PDU_SESSION_MODIFICATION_REJECT:
		printf("PDU_SESSION_MODIFICATION_REJECT------------ decode start\n");
		printf("sm header,extended_protocol_discriminator:0x%x,pdu_session_identity:0x%x,procedure_transaction_identity:0x%x, message type:0x%x\n", nas_msg.plain.sm.header.extended_protocol_discriminator,nas_msg.plain.sm.header.pdu_session_identity,nas_msg.plain.sm.header.procedure_transaction_identity,nas_msg.plain.sm.header.message_type);
		printf("_5gsmcause: 0x%x\n",nas_msg.plain.sm.specific_msg.pdu_session_modification_reject._5gsmcause);
		printf("gprstimer3 --- unit_bits_H3: 0x%x,timeValue_bits_L5: 0x%x\n",nas_msg.plain.sm.specific_msg.pdu_session_modification_reject.gprstimer3.unit,nas_msg.plain.sm.specific_msg.pdu_session_modification_reject.gprstimer3.timeValue);
		printf("extend_options buffer:0x%x 0x%x 0x%x 0x%x\n",(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_modification_reject.extendedprotocolconfigurationoptions)->data[0]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_modification_reject.extendedprotocolconfigurationoptions)->data[1]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_modification_reject.extendedprotocolconfigurationoptions)->data[2]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_modification_reject.extendedprotocolconfigurationoptions)->data[3]));
		printf("_5gsmcongestionreattemptindicator bits_1 --- abo:0x%x\n",nas_msg.plain.sm.specific_msg.pdu_session_modification_reject._5gsmcongestionreattemptindicator.abo);
		printf("PDU_SESSION_MODIFICATION_REJECT------------ decode end\n");
		break;
	case PDU_SESSION_MODIFICATION_COMMAND:
		printf("PDU_SESSION_MODIFICATION_COMMAND------------ decode start\n");
		printf("sm header,extended_protocol_discriminator:0x%x,pdu_session_identity:0x%x,procedure_transaction_identity:0x%x, message type:0x%x\n", nas_msg.plain.sm.header.extended_protocol_discriminator,nas_msg.plain.sm.header.pdu_session_identity,nas_msg.plain.sm.header.procedure_transaction_identity,nas_msg.plain.sm.header.message_type);

		printf("_5gsmcause: %#0x\n",nas_msg.plain.sm.specific_msg.pdu_session_modification_command._5gsmcause);

		printf("sessionambr: %x %x %x %x\n",
				nas_msg.plain.sm.specific_msg.pdu_session_modification_command.sessionambr.uint_for_session_ambr_for_downlink,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_command.sessionambr.session_ambr_for_downlink,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_command.sessionambr.uint_for_session_ambr_for_uplink,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_command.sessionambr.session_ambr_for_uplink);

		printf("gprstimer -- unit: %#0x, timeValue: %#0x\n",
				nas_msg.plain.sm.specific_msg.pdu_session_modification_command.gprstimer.unit,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_command.gprstimer.timeValue);

		printf("alwaysonpdusessionindication: %#0x\n",nas_msg.plain.sm.specific_msg.pdu_session_modification_command.alwaysonpdusessionindication.apsi_indication);

		printf("qosrules: %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x\n",
				nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosrules.lengthofqosrulesie,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosrules.qosrulesie[0].qosruleidentifer,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosrules.qosrulesie[0].ruleoperationcode,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosrules.qosrulesie[0].dqrbit,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosrules.qosrulesie[0].numberofpacketfilters,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[0].packetfilterdirection,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[0].packetfilteridentifier,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[0].packetfiltercontents.component_type,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[1].packetfilterdirection,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[1].packetfilteridentifier,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[1].packetfiltercontents.component_type,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[2].packetfilterdirection,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[2].packetfilteridentifier,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[2].packetfiltercontents.component_type,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosrules.qosrulesie[0].qosruleprecedence,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosrules.qosrulesie[0].segregation,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosrules.qosrulesie[0].qosflowidentifer,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosrules.qosrulesie[1].qosruleidentifer,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosrules.qosrulesie[1].ruleoperationcode,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosrules.qosrulesie[1].dqrbit,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosrules.qosrulesie[1].numberofpacketfilters,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosrules.qosrulesie[1].packetfilterlist.modifyanddelete[0].packetfilteridentifier,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosrules.qosrulesie[1].packetfilterlist.modifyanddelete[1].packetfilteridentifier,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosrules.qosrulesie[1].packetfilterlist.modifyanddelete[2].packetfilteridentifier,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosrules.qosrulesie[1].qosruleprecedence,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosrules.qosrulesie[1].segregation,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosrules.qosrulesie[1].qosflowidentifer);

		//printf("mappedepsbearercontexts");

		printf("qosflowdescriptions: %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x\n",
				nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionsnumber,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[0].qfi,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[0].operationcode,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[0].e,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[0].numberofparameters,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[0].parameteridentifier,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[0].parametercontents._5qi,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[1].parameteridentifier,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[1].parametercontents.gfbrormfbr_uplinkordownlink.uint,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[1].parametercontents.gfbrormfbr_uplinkordownlink.value,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[2].parameteridentifier,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[2].parametercontents.gfbrormfbr_uplinkordownlink.uint,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[2].parametercontents.gfbrormfbr_uplinkordownlink.value,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[1].qfi,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[1].operationcode,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[1].e,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[1].numberofparameters,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[2].qfi,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[2].operationcode,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[2].e,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[2].numberofparameters,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[0].parameteridentifier,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[0].parametercontents.gfbrormfbr_uplinkordownlink.uint,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[0].parametercontents.gfbrormfbr_uplinkordownlink.value,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[1].parameteridentifier,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[1].parametercontents.gfbrormfbr_uplinkordownlink.uint,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[1].parametercontents.gfbrormfbr_uplinkordownlink.value,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[2].parameteridentifier,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[2].parametercontents.averagingwindow.uplinkinmilliseconds,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[2].parametercontents.averagingwindow.downlinkinmilliseconds,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[3].parameteridentifier,
				nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[3].parametercontents.epsbeareridentity);

		printf("extend_options buffer:%x %x %x %x\n",
				(unsigned char)(nas_msg.plain.sm.specific_msg.pdu_session_modification_command.extendedprotocolconfigurationoptions->data[0]),
				(unsigned char)(nas_msg.plain.sm.specific_msg.pdu_session_modification_command.extendedprotocolconfigurationoptions->data[1]),
				(unsigned char)(nas_msg.plain.sm.specific_msg.pdu_session_modification_command.extendedprotocolconfigurationoptions->data[2]),
				(unsigned char)(nas_msg.plain.sm.specific_msg.pdu_session_modification_command.extendedprotocolconfigurationoptions->data[3]));
		printf("PDU_SESSION_MODIFICATION_COMMAND------------ decode end\n");
		break;
	case PDU_SESSION_MODIFICATION_COMPLETE:
		printf("PDU_SESSION_MODIFICATION_COMPLETE------------ decode start\n");
		printf("sm header,extended_protocol_discriminator:0x%x,pdu_session_identity:0x%x,procedure_transaction_identity:0x%x, message type:0x%x\n", nas_msg.plain.sm.header.extended_protocol_discriminator,nas_msg.plain.sm.header.pdu_session_identity,nas_msg.plain.sm.header.procedure_transaction_identity,nas_msg.plain.sm.header.message_type);
		printf("extend_options buffer:0x%x 0x%x 0x%x 0x%x\n",(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_modification_complete.extendedprotocolconfigurationoptions)->data[0]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_modification_complete.extendedprotocolconfigurationoptions)->data[1]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_modification_complete.extendedprotocolconfigurationoptions)->data[2]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_modification_complete.extendedprotocolconfigurationoptions)->data[3]));
		printf("PDU_SESSION_MODIFICATION_COMPLETE------------ decode end\n");
		break;
	case PDU_SESSION_MODIFICATION_COMMANDREJECT:
		printf("PDU_SESSION_MODIFICATION_COMMANDREJECT------------ decode start\n");
		printf("sm header,extended_protocol_discriminator:0x%x,pdu_session_identity:0x%x,procedure_transaction_identity:0x%x, message type:0x%x\n", nas_msg.plain.sm.header.extended_protocol_discriminator,nas_msg.plain.sm.header.pdu_session_identity,nas_msg.plain.sm.header.procedure_transaction_identity,nas_msg.plain.sm.header.message_type);
		printf("_5gsmcause: 0x%x\n",nas_msg.plain.sm.specific_msg.pdu_session_modification_command_reject._5gsmcause);
		printf("extend_options buffer:0x%x 0x%x 0x%x 0x%x\n",(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_modification_command_reject.extendedprotocolconfigurationoptions)->data[0]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_modification_command_reject.extendedprotocolconfigurationoptions)->data[1]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_modification_command_reject.extendedprotocolconfigurationoptions)->data[2]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_modification_command_reject.extendedprotocolconfigurationoptions)->data[3]));
		printf("PDU_SESSION_MODIFICATION_COMMANDREJECT------------ decode end\n");
		break;
	case PDU_SESSION_RELEASE_REQUEST:
		printf("PDU_SESSION_RELEASE_REQUEST------------ decode start\n");
		printf("sm header,extended_protocol_discriminator:0x%x,pdu_session_identity:0x%x,procedure_transaction_identity:0x%x, message type:0x%x\n", nas_msg.plain.sm.header.extended_protocol_discriminator,nas_msg.plain.sm.header.pdu_session_identity,nas_msg.plain.sm.header.procedure_transaction_identity,nas_msg.plain.sm.header.message_type);
		printf("_5gsmcause: 0x%x\n",nas_msg.plain.sm.specific_msg.pdu_session_release_request._5gsmcause);
		printf("extend_options buffer:0x%x 0x%x 0x%x 0x%x\n",(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_release_request.extendedprotocolconfigurationoptions)->data[0]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_release_request.extendedprotocolconfigurationoptions)->data[1]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_release_request.extendedprotocolconfigurationoptions)->data[2]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_release_request.extendedprotocolconfigurationoptions)->data[3]));
		printf("PDU_SESSION_RELEASE_REQUEST------------ decode end\n");
		break;
	case PDU_SESSION_RELEASE_REJECT:
		printf("PDU_SESSION_RELEASE_REJECT------------ decode start\n");
		printf("sm header,extended_protocol_discriminator:0x%x,pdu_session_identity:0x%x,procedure_transaction_identity:0x%x, message type:0x%x\n", nas_msg.plain.sm.header.extended_protocol_discriminator,nas_msg.plain.sm.header.pdu_session_identity,nas_msg.plain.sm.header.procedure_transaction_identity,nas_msg.plain.sm.header.message_type);
		printf("_5gsmcause: 0x%x\n",nas_msg.plain.sm.specific_msg.pdu_session_release_reject._5gsmcause);
		printf("extend_options buffer:0x%x 0x%x 0x%x 0x%x\n",(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_release_reject.extendedprotocolconfigurationoptions)->data[0]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_release_reject.extendedprotocolconfigurationoptions)->data[1]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_release_reject.extendedprotocolconfigurationoptions)->data[2]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_release_reject.extendedprotocolconfigurationoptions)->data[3]));
		printf("PDU_SESSION_RELEASE_REJECT------------ decode end\n");
		break;
	case PDU_SESSION_RELEASE_COMMAND:
		printf("PDU_SESSION_RELEASE_COMMAND------------ decode start\n");
		printf("sm header,extended_protocol_discriminator:0x%x,pdu_session_identity:0x%x,procedure_transaction_identity:0x%x, message type:0x%x\n", nas_msg.plain.sm.header.extended_protocol_discriminator,nas_msg.plain.sm.header.pdu_session_identity,nas_msg.plain.sm.header.procedure_transaction_identity,nas_msg.plain.sm.header.message_type);
		printf("_5gsmcause: 0x%x\n",nas_msg.plain.sm.specific_msg.pdu_session_release_command._5gsmcause);
		printf("gprstimer3 --- unit_bits_H3: 0x%x,timeValue_bits_L5: 0x%x\n",nas_msg.plain.sm.specific_msg.pdu_session_release_command.gprstimer3.unit,nas_msg.plain.sm.specific_msg.pdu_session_release_command.gprstimer3.timeValue);
		printf("eapmessage buffer:0x%x 0x%x\n",(unsigned char)(nas_msg.plain.sm.specific_msg.pdu_session_release_command.eapmessage->data[0]),(unsigned char )(nas_msg.plain.sm.specific_msg.pdu_session_release_command.eapmessage->data[1]));
		printf("_5gsmcongestionreattemptindicator bits_1 --- abo:0x%x\n",nas_msg.plain.sm.specific_msg.pdu_session_release_command._5gsmcongestionreattemptindicator.abo);
		printf("extend_options buffer:0x%x 0x%x 0x%x 0x%x\n",(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_release_command.extendedprotocolconfigurationoptions)->data[0]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_release_command.extendedprotocolconfigurationoptions)->data[1]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_release_command.extendedprotocolconfigurationoptions)->data[2]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_release_command.extendedprotocolconfigurationoptions)->data[3]));
		printf("PDU_SESSION_RELEASE_COMMAND------------ decode end\n");
		break;
	case PDU_SESSION_RELEASE_COMPLETE:
		printf("PDU_SESSION_RELEASE_COMPLETE------------ decode start\n");
		printf("sm header,extended_protocol_discriminator:0x%x,pdu_session_identity:0x%x,procedure_transaction_identity:0x%x, message type:0x%x\n", nas_msg.plain.sm.header.extended_protocol_discriminator,nas_msg.plain.sm.header.pdu_session_identity,nas_msg.plain.sm.header.procedure_transaction_identity,nas_msg.plain.sm.header.message_type);
		printf("_5gsmcause: 0x%x\n",nas_msg.plain.sm.specific_msg.pdu_session_release_complete._5gsmcause);
		printf("extend_options buffer:0x%x 0x%x 0x%x 0x%x\n",(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_release_complete.extendedprotocolconfigurationoptions)->data[0]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_release_complete.extendedprotocolconfigurationoptions)->data[1]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_release_complete.extendedprotocolconfigurationoptions)->data[2]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_release_complete.extendedprotocolconfigurationoptions)->data[3]));
		printf("PDU_SESSION_RELEASE_COMPLETE------------ decode end\n");
		break;
	case _5GSM_STATUS:
		printf("_5GSM_STAUS------------ decode start\n");
		printf("sm header,extended_protocol_discriminator:0x%x,pdu_session_identity:0x%x,procedure_transaction_identity:0x%x, message type:0x%x\n", nas_msg.plain.sm.header.extended_protocol_discriminator,nas_msg.plain.sm.header.pdu_session_identity,nas_msg.plain.sm.header.procedure_transaction_identity,nas_msg.plain.sm.header.message_type);
		printf("_5gsmcause: 0x%x\n",nas_msg.plain.sm.specific_msg._5gsm_status._5gsmcause);
		printf("_5GSM_STAUS------------ decode end\n");
		break;

	}

	return decoder_rc;
}


void smf_app::convert_string_2_hex(std::string& input_str, std::string& output_str){

	unsigned char *data = (unsigned char *) malloc (input_str.length() + 1);
    memset(data, 0, input_str.length()  + 1);
	memcpy ((void *)data, (void *)input_str.c_str(), input_str.length());

	printf("Input str: ");
	for(int i = 0; i < input_str.length(); i++) {
		printf(" %02x ", data[i]);
	}
	printf("\n");

	char *datahex = (char *) malloc (input_str.length() * 2 + 1);
    memset(datahex, 0, input_str.length() *2  + 1);

	for(int i = 0; i < input_str.length(); i++)
		sprintf(datahex + i*2, "%02x", data[i]);

	output_str = reinterpret_cast<char*> (datahex);
	Logger::smf_app().debug("[convert string to hex]: %s\n ", output_str.c_str());
}
