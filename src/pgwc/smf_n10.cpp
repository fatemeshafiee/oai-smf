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

/*! \file smf_n10.cpp
  \brief
  \author 
  \company Eurecom
  \email: 
*/

#include "smf.h"
#include "common_defs.h"
#include "itti.hpp"
#include "logger.hpp"
#include "smf_n10.hpp"
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
extern smf_n10   *smf_n10_inst;
void smf_n10_task (void*);

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

void smf_n10_task (void *args_p)
{
  const task_id_t task_id = TASK_SMF_N10;
  itti_inst->notify_task_ready(task_id);

  do {
    std::shared_ptr<itti_msg> shared_msg = itti_inst->receive_msg(task_id);
    auto *msg = shared_msg.get();
    switch (msg->msg_type) {

    case N10_GET_SESSION_MANAGEMENT_SUBSCRIPTION:
      //if (itti_n10_get_session_management_subscription* m = dynamic_cast<itti_n10_get_session_management_subscription*>(msg)) {
      //  smf_n10_inst->send_sm_data_get_msg(ref(*m));
      //}
      break;


    case TERMINATE:
      if (itti_msg_terminate *terminate = dynamic_cast<itti_msg_terminate*>(msg)) {
        Logger::smf_n10().info( "Received terminate message");
        return;
      }
      break;


    default:
      Logger::smf_n10().info( "no handler for msg type %d", msg->msg_type);
    }

  } while (true);
}


//------------------------------------------------------------------------------
smf_n10::smf_n10 ()
{
  udm_addr = "172.55.55.101";//TODO: hardcoded for the moment (should get from configuration file)
  udm_port = 8181;//TODO: hardcoded for the moment (should get from configuration file)

  Logger::smf_n10().startup("Starting...");
  if (itti_inst->create_task(TASK_SMF_N10, smf_n10_task, nullptr) ) {
    Logger::smf_n10().error( "Cannot create task TASK_SMF_N10" );
    throw std::runtime_error( "Cannot create task TASK_SMF_N10" );
  }
  Logger::smf_n10().startup( "Started" );
}



void smf_n10::handle_receive_sm_data_notification()
{
}

bool smf_n10::get_sm_data(supi64_t& supi, std::string& dnn, snssai_t& snssai, std::shared_ptr<session_management_subscription> subscription)
{
	//retrieve a UE's Session Management Subscription Data (TS29503_Nudm_SDM.yaml: /{supi}/sm-data)
	//use curl to send data for the moment

	nlohmann::json jsonData;
	curl_global_init(CURL_GLOBAL_DEFAULT);
	struct curl_slist *headers = NULL;
	headers = curl_slist_append(headers, "Accept: application/json");
	headers = curl_slist_append(headers, "Content-Type: application/json");
	headers = curl_slist_append(headers, "charsets: utf-8");

	CURL *curl = curl_easy_init();
	std::string url = udm_addr + ":" + std::to_string(udm_port) + "/nudm-sdm/v2/" + std::to_string(supi) +"/sm-data";
	Logger::smf_n10().debug("[get_sm_data] UDM's URL: %s ", url.c_str());

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
		//curl_easy_setopt(curl, CURLOPT_WRITEDATA, httpData);
		int numRetries = 0;
		while (numRetries < UDM_NUMBER_RETRIES){
			res = curl_easy_perform(curl);
			curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);
			Logger::smf_n10().debug("[get_sm_data] Response from UDM, Http Code: %d ", httpCode);

			if (httpCode == HTTP_STATUS_OK)
			{
				Logger::smf_n10().debug("[get_sm_data] Got successful response from UDM, URL: %s ", url.c_str());
				//Logger::smf_n10().debug("[get_sm_data] Http Data from UDM: %s ", *httpData.get());
				try{
					jsonData = nlohmann::json::parse(*httpData.get());
					//curl_easy_cleanup(curl);
					break;
				} catch (json::exception& e){
					Logger::smf_n10().warn("[get_sm_data] Couldn't Parse json data from UDM");

				}
				numRetries++;
			}
			else
			{
				Logger::smf_n10().warn("[get_sm_data] Couldn't GET response from UDM, URL %s, retry ...", url.c_str());
				//retry
				numRetries++;
			}
		}
		curl_easy_cleanup(curl);
	}

	//process the response
	if (!jsonData.empty()){
		Logger::smf_n10().debug("[get_sm_data] GET response from UDM %s", jsonData.dump().c_str());

		//retrieve SessionManagementSubscription and store in the context
		for (nlohmann::json::iterator it = jsonData["dnnConfigurations"].begin(); it != jsonData["dnnConfigurations"].end(); ++it ){
			Logger::smf_n10().debug("[get_sm_data] DNN %s", it.key().c_str());
			dnn_configuration_t dnn_configuration;

			try {
				//PDU Session Type
				pdu_session_type_t pdu_session_type (pdu_session_type_e::PDU_SESSION_TYPE_E_IPV4);
				std::string default_session_type = it.value()["pduSessionTypes"]["defaultSessionType"];
				Logger::smf_n10().debug("[get_sm_data] default_session_type %s", default_session_type.c_str());
				if (default_session_type.compare("IPV4") == 0) {
					pdu_session_type.pdu_session_type = pdu_session_type_e::PDU_SESSION_TYPE_E_IPV4;
				} else if (default_session_type.compare("IPV6") == 0) {
					pdu_session_type.pdu_session_type = pdu_session_type_e::PDU_SESSION_TYPE_E_IPV6;
				} else if (default_session_type.compare("IPV4V6") == 0) {
					pdu_session_type.pdu_session_type = pdu_session_type_e::PDU_SESSION_TYPE_E_IPV4V6;
				}
				dnn_configuration.pdu_session_types.default_session_type = pdu_session_type;

				//Ssc_Mode
				ssc_mode_t ssc_mode(ssc_mode_e::SSC_MODE_1);
				std::string default_ssc_mode = it.value()["sscModes"]["defaultSscMode"];
				Logger::smf_n10().debug("[get_sm_data] defaultSscMode %s", default_ssc_mode.c_str());
				if (default_ssc_mode.compare("SSC_MODE_1") == 0) {
					dnn_configuration.ssc_modes.default_ssc_mode = ssc_mode_t(ssc_mode_e::SSC_MODE_1);
				} else if (default_ssc_mode.compare("SSC_MODE_2") == 0) {
					dnn_configuration.ssc_modes.default_ssc_mode = ssc_mode_t(ssc_mode_e::SSC_MODE_2);
				} else if (default_ssc_mode.compare("SSC_MODE_3") == 0) {
					dnn_configuration.ssc_modes.default_ssc_mode = ssc_mode_t(ssc_mode_e::SSC_MODE_3);
				}

				//session_ambr
				dnn_configuration.session_ambr.uplink = it.value()["sessionAmbr"]["uplink"];
				dnn_configuration.session_ambr.downlink = it.value()["sessionAmbr"]["downlink"];
				Logger::smf_n10().debug("[get_sm_data] sessionAmbr uplink %s, downlink %s", dnn_configuration.session_ambr.uplink.c_str(), dnn_configuration.session_ambr.downlink.c_str());

				subscription->insert_dnn_configuration(it.key(), dnn_configuration);
			} catch (nlohmann::json::exception& e){
				Logger::smf_n10().warn("[get_sm_data] exception message %s, exception id %d ", e.what(), e.id);
				return false;
			}

		}

		return true;
	} else{

		return false;
	}

}

void smf_n10::subscribe_sm_data()
{
}





