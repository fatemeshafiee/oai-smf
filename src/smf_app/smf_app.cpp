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
#include "async_shell_cmd.hpp"
#include "common_defs.h"
#include "conversions.hpp"
#include "itti.hpp"
#include "logger.hpp"
#include "smf_paa_dynamic.hpp"
#include "smf_n4.hpp"
#include "smf_n10.hpp"
#include "smf_n11.hpp"
#include "smf_ngap.hpp"
#include "string.hpp"
#include "3gpp_29.502.h"
#include "3gpp_24.007.h"
#include "smf.h"
#include "3gpp_24.501.h"
#include "RefToBinaryData.h"
#include "SmContextCreateError.h"
#include "SmContextUpdateError.h"
#include "SmContextMessage.h"
#include "ProblemDetails.h"
//#include "SmContextCreateError.h"
#include "SmContextCreatedData.h"

extern "C"{
#include "nas_message.h"
#include "mmData.h"
#include "nas_sm_encode_to_json.h"
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
void smf_app::generate_smf_context_ref(std::string& smf_ref)
{
  smf_ref = std::to_string(sm_context_ref_generator.get_uid());
}

//------------------------------------------------------------------------------
scid_t smf_app::generate_smf_context_ref()
{
  return sm_context_ref_generator.get_uid();
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
	Logger::smf_app().info("Handle a PDU Session Create SM Context Request from an AMF");
	//handle PDU Session Create SM Context Request as specified in section 4.3.2 3GPP TS 23.502
	oai::smf_server::model::SmContextCreateError smContextCreateError;
	oai::smf_server::model::ProblemDetails problem_details;
	oai::smf_server::model::RefToBinaryData binary_data;
	std::string n1_container; //N1 SM container
	smf_ngap smf_ngap_inst;
	nas_message_t	decoded_nas_msg;

	//Step 1. Decode NAS and get the necessary information
	std::string n1_sm_msg = smreq->req.get_n1_sm_message();
	memset (&decoded_nas_msg, 0, sizeof (nas_message_t));

	pdu_session_create_sm_context_request context_req_msg = smreq->req;

	int decoder_rc = smf_ngap_inst.decode_n1_sm_container(decoded_nas_msg, n1_sm_msg);
	if (decoder_rc != RETURNok) {
		//error, should send reply to AMF with error code!!
		Logger::smf_app().warn("N1 SM container cannot be decoded correctly!\n");
		problem_details.setCause(pdu_session_application_error_e2str[PDU_SESSION_APPLICATION_ERROR_N1_SM_ERROR]);
		smContextCreateError.setError(problem_details);

		//PDU Session Establishment Reject
		//24.501: response with a 5GSM STATUS message including cause "#95 Semantically incorrect message"
		smf_ngap_inst.create_n1_sm_container(context_req_msg, PDU_SESSION_ESTABLISHMENT_REJECT, n1_container, 95); //TODO: should define 5GSM cause in 24.501
		binary_data.setContentId(n1_container);
		smContextCreateError.setN1SmMsg(binary_data);
		//Send response to AMF
		nlohmann::json jsonData;
		to_json(jsonData, smContextCreateError);
		//httpResponse.headers().add<Pistache::Http::Header::Location>(url);
		send_create_session_response(smreq->http_response, smContextCreateError, Pistache::Http::Code::Forbidden);
	}

	Logger::smf_app().debug("NAS header information: extended_protocol_discriminator %d, security_header_type:%d,sequence_number:%d,message_authentication_code:%d\n",
			decoded_nas_msg.header.extended_protocol_discriminator,
			decoded_nas_msg.header.security_header_type,
			decoded_nas_msg.header.sequence_number,
			decoded_nas_msg.header.message_authentication_code);

	//Extended protocol discriminator (Mandatory)
	smreq->req.set_epd(decoded_nas_msg.header.extended_protocol_discriminator);

	//Message type (Mandatory) (PDU SESSION ESTABLISHMENT REQUEST message identity)
	Logger::smf_app().debug("NAS header information, Message Type %d\n", decoded_nas_msg.plain.sm.header.message_type);
	smreq->req.set_message_type(decoded_nas_msg.plain.sm.header.message_type);

	//Integrity protection maximum data rate (Mandatory)

	//PDU session type (Optional)
	smreq->req.set_pdu_session_type(PDU_SESSION_TYPE_E_IPV4); //set default value
	if (decoded_nas_msg.plain.sm.header.message_type == PDU_SESSION_ESTABLISHMENT_REQUEST){
		//TODO: Disable this command temporarily since can't get this info from tester
		//sm_context_req_msg.set_pdu_session_type(decoded_nas_msg.plain.sm.specific_msg.pdu_session_establishment_request._pdusessiontype.pdu_session_type_value);
	}

	//Step 2. get necessary information
	supi_t supi =  smreq->req.get_supi();
	supi64_t supi64 = smf_supi_to_u64(supi);
	std::string dnn = smreq->req.get_dnn();
	snssai_t snssai  =  smreq->req.get_snssai();
	procedure_transaction_id_t pti = {.procedure_transaction_id = decoded_nas_msg.plain.sm.header.procedure_transaction_identity};
	pdu_session_type_t pdu_session_type = {.pdu_session_type = smreq->req.get_pdu_session_type()};
	pdu_session_id_t pdu_session_id = decoded_nas_msg.plain.sm.header.pdu_session_identity;
	uint8_t message_type = decoded_nas_msg.plain.sm.header.message_type;
	std::string request_type = smreq->req.get_request_type();
	Logger::smf_app().info("Handle a PDU Session Create SM Context Request message from AMF, supi " SUPI_64_FMT ", dnn %s, snssai_sst %d", supi64, dnn.c_str(), snssai.sST );

	//check pti
	if ((pti.procedure_transaction_id == PROCEDURE_TRANSACTION_IDENTITY_UNASSIGNED) || (pti.procedure_transaction_id > PROCEDURE_TRANSACTION_IDENTITY_LAST)){
		Logger::smf_app().warn(" Invalid PTI value (pti = %d)\n", pti.procedure_transaction_id);
		problem_details.setCause(pdu_session_application_error_e2str[PDU_SESSION_APPLICATION_ERROR_N1_SM_ERROR]);
		smContextCreateError.setError(problem_details);

		//PDU Session Establishment Reject
		//(24.501 (section 7.3.1)) NAS N1 SM message: response with a 5GSM STATUS message including cause "#81 Invalid PTI value"
		smf_ngap_inst.create_n1_sm_container(context_req_msg, PDU_SESSION_ESTABLISHMENT_REJECT, n1_container, 81); //TODO: should define 5GSM cause in 24.501
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
		smf_ngap_inst.create_n1_sm_container(context_req_msg, PDU_SESSION_ESTABLISHMENT_REJECT, n1_container, 98); //TODO: should define 5GSM cause in 24.501
		binary_data.setContentId(n1_container);
		smContextCreateError.setN1SmMsg(binary_data);
		//Send response to AMF
		send_create_session_response(smreq->http_response, smContextCreateError, Pistache::Http::Code::Forbidden);
	}

	//check request type
	if (request_type.compare("INITIAL_REQUEST") !=0 ){
		Logger::smf_app().warn("Invalid request type (request type = %s)\n", "INITIAL_REQUEST");
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
		smf_ngap_inst.create_n1_sm_container(context_req_msg, PDU_SESSION_ESTABLISHMENT_REJECT, n1_container, 27); //TODO: should define 5GSM cause in 24.501
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
			smf_ngap_inst.create_n1_sm_container(context_req_msg, PDU_SESSION_ESTABLISHMENT_REJECT, n1_container, 29); //TODO: should define 5GSM cause in 24.501
			binary_data.setContentId(n1_container);
			smContextCreateError.setN1SmMsg(binary_data);
			//Send response to AMF
			send_create_session_response(smreq->http_response, smContextCreateError, Pistache::Http::Code::Forbidden);
			return;
		}
	}
    // generate a SMF context Id and store the corresponding information in a map (SM_Context_ID, (supi, dnn, pdu_session_id))
    scid_t scid = generate_smf_context_ref();
    set_scid_2_smf_context(scid, supi, dnn, pdu_session_id);
    smreq->set_scid(scid);

	//Step 5. let the context handle the message
	//in this step, SMF will send N4 Session Establishment/Modification to UPF (step 10a, section 4.3.2 3GPP 23.502)
	//SMF, then, sends response to AMF
	sc.get()->handle_amf_msg(smreq);

}


//------------------------------------------------------------------------------
void smf_app::handle_amf_msg (std::shared_ptr<itti_n11_update_sm_context_request> smreq)
{
	//handle PDU Session Update SM Context Request as specified in section 4.3.2 3GPP TS 23.502
	oai::smf_server::model::SmContextUpdateError smContextUpdateError;
	oai::smf_server::model::ProblemDetails problem_details;
	oai::smf_server::model::RefToBinaryData binary_data;
	std::string n1_container; //N1 SM container

	//Step 0. get supi, dnn, pdu_session id from sm_context
	//SM Context ID - uint32_t in our case
	scid_t scid;
	try {
		scid = std::stoi(smreq->scid);
	}
	/*catch (const std::out_of_range& err){

    } catch (const std::invalid_argument& err){

    }*/
	catch (const std::exception& err) {
     //TODO: send reject with invalid context
	}

	auto sm_context = scid_2_smf_context(scid);
	supi_t supi =  std::get<0>(sm_context);
	std::string dnn = std::get<1>(sm_context);
	pdu_session_id_t pdu_session_id = std::get<2>(sm_context);

	supi64_t supi64 = smf_supi_to_u64(supi);
	//store in itti_n11_update_sm_context_request to be processed later on
	smreq->req.set_supi(supi);
	smreq->req.set_dnn(dnn);
	smreq->req.set_pdu_session_id(pdu_session_id);


	//Step 2. find the smf context
	std::shared_ptr<smf_context> sc;

	if (is_supi_2_smf_context(supi64)) {
		sc = supi_2_smf_context(supi64);
		Logger::smf_app().debug("Retrieve SMF context with SUPI " SUPI_64_FMT "", supi64);
	} else {
		Logger::smf_app().debug("SMF context with SUPI " SUPI_64_FMT "does not existed!", supi64);
		//TODO: send PDU Session EStablishment Reject to AMF
		Logger::smf_app().warn("Received PDU_SESSION_UPDATESMCONTEXT_REQUEST, couldn't retrieve the corresponding SMF context, ignore message!");
		problem_details.setCause(pdu_session_application_error_e2str[PDU_SESSION_APPLICATION_ERROR_CONTEXT_NOT_FOUND]);
		smContextUpdateError.setError(problem_details);
		//PDU Session Update Reject
		//Create N1 container
		//smf_app_inst->create_n1_sm_container(context_req_msg, PDU_SESSION_ESTABLISHMENT_REJECT, n1_container, 29); //TODO: 29 -> should update 5GSM cause in 24.501
		binary_data.setContentId(n1_container);
		smContextUpdateError.setN1SmMsg(binary_data);
		//Send response to AMF
		//send_create_session_response(smreq->http_response, smContextUpdateError, Pistache::Http::Code::Forbidden);
		return;
	}

	//get dnn context
	std::shared_ptr<dnn_context> sd;

	if (!sc.get()->find_dnn_context(dnn, sd)) {
		if (nullptr == sd.get()){
			//TODO: Error, DNN context doesn't exist
		}
	}


    //Step 3. Verify AMF??
	//TODO: based on AMF ID > get the fteid -> get the SMF context (we should also verify AMF_ID)
	//TODO: Step 2.1. if not exist -> send reply to AMF (reject)
	//TODO: create N1 container and send reject message to AMF

	//Step 4. handle the message in smf_context
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
void smf_app::set_scid_2_smf_context(const scid_t& id, supi_t supi, std::string dnn, pdu_session_id_t pdu_session_id)
{
    std::shared_lock lock(m_scid2smf_context);
    scid2smf_context[id] = std::make_tuple(supi, dnn, pdu_session_id);
}

//------------------------------------------------------------------------------
std::tuple<supi_t, std::string, pdu_session_id_t>  smf_app::scid_2_smf_context(const scid_t& scid) const
{
	std::shared_lock lock(m_scid2smf_context);
	return scid2smf_context.at(scid);
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


//---------------------------------------------------------------------------------------------
void smf_app::convert_string_2_hex(std::string& input_str, std::string& output_str){

	Logger::smf_app().debug("Convert std::string to Hex\n");
	unsigned char *data = (unsigned char *) malloc (input_str.length() + 1);
    memset(data, 0, input_str.length()  + 1);
	memcpy ((void *)data, (void *)input_str.c_str(), input_str.length());

	Logger::smf_app().debug("Input string:");
	for(int i = 0; i < input_str.length(); i++) {
		printf("%02x ", data[i]);
	}

	char *datahex = (char *) malloc (input_str.length() * 2 + 1);
    memset(datahex, 0, input_str.length() *2  + 1);

	for(int i = 0; i < input_str.length(); i++)
		sprintf(datahex + i*2, "%02x", data[i]);

	output_str = reinterpret_cast<char*> (datahex);
	Logger::smf_app().debug("Output str: %s\n ", output_str.c_str());
}
