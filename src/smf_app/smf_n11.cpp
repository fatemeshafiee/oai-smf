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

/*! \file smf_n11.cpp
  \brief
  \author 
  \company Eurecom
  \email: 
 */

#include "smf.h"
#include "common_defs.h"
#include "itti.hpp"
#include "logger.hpp"
#include "smf_n11.hpp"
#include "smf_app.hpp"
#include "smf_config.hpp"
#include <curl/curl.h>
#include <nlohmann/json.hpp>

#include <stdexcept>

#define AMF_CURL_TIMEOUT_MS 100L
#define AMF_NUMBER_RETRIES 3
#define HTTP_STATUS_OK 200
#define DEBUG 1

using namespace smf;
using namespace std;
using json = nlohmann::json;

extern itti_mw *itti_inst;
extern smf_n11   *smf_n11_inst;
extern smf::smf_app *smf_app_inst;
extern smf_config smf_cfg;
void smf_n11_task (void*);

/*
 * To read content of the response from UDM
 */
static std::size_t callback(
		const char* in,
		std::size_t size,
		std::size_t num,
		std::string* out)
{
	const std::size_t totalBytes(size * num);
	out->append(in, totalBytes);
	return totalBytes;
}


//------------------------------------------------------------------------------

void smf_n11_task (void *args_p)
{
	const task_id_t task_id = TASK_SMF_N11;
	itti_inst->notify_task_ready(task_id);

	do {
		std::shared_ptr<itti_msg> shared_msg = itti_inst->receive_msg(task_id);
		auto *msg = shared_msg.get();
		switch (msg->msg_type) {

		case N11_SESSION_CREATE_SM_CONTEXT_RESPONSE:
			smf_n11_inst->send_msg_to_amf(std::static_pointer_cast<itti_n11_create_sm_context_response>(shared_msg));
			break;


		case TERMINATE:
			if (itti_msg_terminate *terminate = dynamic_cast<itti_msg_terminate*>(msg)) {
				Logger::smf_n11().info( "Received terminate message");
				return;
			}
			break;


		default:
			Logger::smf_n11().info( "no handler for msg type %d", msg->msg_type);
		}

	} while (true);
}


//------------------------------------------------------------------------------
smf_n11::smf_n11 ()
{
	Logger::smf_n11().startup("Starting...");
	if (itti_inst->create_task(TASK_SMF_N11, smf_n11_task, nullptr) ) {
		Logger::smf_n11().error( "Cannot create task TASK_SMF_N11" );
		throw std::runtime_error( "Cannot create task TASK_SMF_N11" );
	}
	Logger::smf_n11().startup( "Started" );
}




void smf_n11::send_msg_to_amf(std::shared_ptr<itti_n11_create_sm_context_response> sm_context_res)
{
	//Transfer N1/N2 message via AMF by using N_amf_Communication_N1N2MessageTransfer (see TS29518_Namf_Communication.yaml)
	//use curl to send data for the moment

	nlohmann::json jsonData;
	std::string n1_message;

	curl_global_init(CURL_GLOBAL_DEFAULT);
	struct curl_slist *headers = NULL;
	headers = curl_slist_append(headers, "Accept: application/json");
	headers = curl_slist_append(headers, "Content-Type: application/json");
	headers = curl_slist_append(headers, "charsets: utf-8");

	supi64_t supi64 = smf_supi_to_u64(sm_context_res->res.get_supi());

	CURL *curl = curl_easy_init();
	//hardcoded for the moment, should get from NRF/configuration file
	std::string url = std::string(inet_ntoa (*((struct in_addr *)&smf_cfg.amf_addr.ipv4_addr)))  + ":" + std::to_string(smf_cfg.amf_addr.port) + "/namf-comm/v1/ue-contexts/" + std::to_string(supi64) +"/n1-n2-messages";
	Logger::smf_n11().debug("[Send Communication_N1N2MessageTransfer to AMF] AMF's URL: %s ", url.c_str());

	//N1 SM container
	if (sm_context_res->res.get_cause() != REQUEST_ACCEPTED) { //PDU Session Establishment Reject
		Logger::smf_n11().debug("[Send Communication_N1N2MessageTransfer to AMF] PDU Session Establishment Reject\n");
    	smf_app_inst->create_n1_sm_container(sm_context_res, PDU_SESSION_ESTABLISHMENT_REJECT, n1_message); //need cause?
	} else { //PDU Session Establishment Accept
		Logger::smf_n11().debug("[Send Communication_N1N2MessageTransfer to AMF] PDU Session Establishment Accept \n");
		smf_app_inst->create_n1_sm_container(sm_context_res, PDU_SESSION_ESTABLISHMENT_ACCEPT, n1_message); //need cause?
	}

	std::string n1_msg_hex;
	smf_app_inst->convert_string_2_hex(n1_message, n1_msg_hex);

	jsonData["n1MessageContainer"]["n1MessageClass"] = "SM";
	jsonData["n1MessageContainer"]["n1MessageContent"]["contentId"] = n1_msg_hex;
	Logger::smf_n11().debug("n1MessageContent: %s\n ", n1_msg_hex.c_str());

	//TODO: fill the content of N1N2MessageTransferReqData
	//jsonData["n2InfoContainer"]["n2InformationClass"] = "SM";
	//jsonData["n2InfoContainer"]["smInfo"]["PduSessionId"] = 123;
	//jsonData["n2InfoContainer"]["smInfo"]["n2InfoContent"]["ngapMessageType"] = 123; //NGAP message
	//jsonData["n2InfoContainer"]["smInfo"]["n2InfoContent"]["ngapIeType"] = "PDU_RES_SETUP_REQ"; //NGAP message
	//jsonData["n2InfoContainer"]["smInfo"]["n2InfoContent"]["ngapData"]["contentId"] = "NGAP DATA"; //NGAP message
	//jsonData["n2InfoContainer"]["ranInfo"] = "SM";
	jsonData["ppi"] = 1;
	jsonData["pduSessionId"] = sm_context_res->res.get_pdu_session_id();
	//jsonData["arp"]["priorityLevel"] = 1;
	//jsonData["arp"]["preemptCap"] = "NOT_PREEMPT";
	//jsonData["arp"]["preemptVuln"] = "NOT_PREEMPTABLE";
	std::string body = jsonData.dump();


	if(curl) {
		CURLcode res;

		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
		curl_easy_setopt(curl, CURLOPT_URL, url.c_str() );
		curl_easy_setopt(curl, CURLOPT_HTTPGET,1);
		curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, AMF_CURL_TIMEOUT_MS);

		// Response information.
		long httpCode(0);
		std::unique_ptr<std::string> httpData(new std::string());

		// Hook up data handling function.
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &callback);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, httpData.get());
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
		curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)body.length());

		int numRetries = 0;
		while (numRetries < AMF_NUMBER_RETRIES){
			res = curl_easy_perform(curl);
			curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);
			Logger::smf_n11().debug("[send_msg_to_amf] Response from AMF, Http Code: %d ", httpCode);

			if (httpCode == HTTP_STATUS_OK)
			{
				Logger::smf_n11().debug("[send_msg_to_amf] Got successful response from AMF, URL: %s ", url.c_str());
				break;
			}
			else
			{
				Logger::smf_n10().warn("[send_msg_to_amf] Couldn't GET response from AMF, URL %s, retry ...", url.c_str());
				//retry
				numRetries++;
			}
		}
		curl_easy_cleanup(curl);
	}
	//TODO: process the response if necessary

}




