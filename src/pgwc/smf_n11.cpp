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
#include <curl/curl.h>
#include <nlohmann/json.hpp>

#include <stdexcept>

#define UDM_CURL_TIMEOUT_MS 100L
#define UDM_NUMBER_RETRIES 3
#define HTTP_STATUS_OK 200

using namespace pgwc;
using namespace std;
using json = nlohmann::json;

extern itti_mw *itti_inst;
extern smf_n11   *smf_n11_inst;
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
			//if (itti_n10_get_session_management_subscription* m = dynamic_cast<itti_n10_get_session_management_subscription*>(msg)) {
			//  smf_n10_inst->send_sm_data_get_msg(ref(*m));
			//}
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
	amf_addr = "172.16.1.106";//TODO: hardcoded for the moment (should get from configuration file)
	amf_port = 8080;//TODO: hardcoded for the moment (should get from configuration file)

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
	curl_global_init(CURL_GLOBAL_DEFAULT);
	struct curl_slist *headers = NULL;
	headers = curl_slist_append(headers, "Accept: application/json");
	headers = curl_slist_append(headers, "Content-Type: application/json");
	headers = curl_slist_append(headers, "charsets: utf-8");

	supi64_t supi64 = smf_supi_to_u64(sm_context_res->res.get_supi());

	CURL *curl = curl_easy_init();
	//hardcoded for the moment, should get from NRF/configuration file
	std::string url = amf_addr + ":" + std::to_string(amf_port) + "/ue-contexts/" + std::to_string(supi64) +"/n1-n2-messages";
	Logger::smf_n11().debug("[get_sm_data] UDM's URL: %s ", url.c_str());
	std::string body = "";

	if(curl) {
		CURLcode res;

		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
		curl_easy_setopt(curl, CURLOPT_URL, url.c_str() );
		curl_easy_setopt(curl, CURLOPT_HTTPGET,1);
		curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, UDM_CURL_TIMEOUT_MS);

		// Response information.
		long httpCode(0);
		std::unique_ptr<std::string> httpData(new std::string());

		// Hook up data handling function.
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &callback);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, httpData.get());
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
		curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)body.length());

		int numRetries = 0;
		while (numRetries < UDM_NUMBER_RETRIES){
			res = curl_easy_perform(curl);
			curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);
			Logger::smf_n11().debug("[send_msg_to_amf] Response from AMF, Http Code: %d ", httpCode);

			if (httpCode == HTTP_STATUS_OK)
			{
				Logger::smf_n11().debug("[send_msg_to_amf] Got successful response from AMF, URL: %s ", url.c_str());
				try{
					jsonData = nlohmann::json::parse(*httpData.get());
					//curl_easy_cleanup(curl);
					break;
				} catch (json::exception& e){
					Logger::smf_n10().warn("[send_msg_to_amf] Couldn't Parse json data from AMF");

				}
				numRetries++;
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
	//TODO: process the response if neccessary

}




