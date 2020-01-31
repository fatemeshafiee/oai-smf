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
  \author  Lionel GAUTHIER, Tien-Thinh NGUYEN
  \company Eurecom
  \date 2019
  \email: lionel.gauthier@eurecom.fr, tien-thinh.nguyen@eurecom.fr
 */

#include "smf.h"
#include "common_defs.h"
#include "itti.hpp"
#include "logger.hpp"
#include "smf_n11.hpp"
#include "smf_app.hpp"
#include "smf_config.hpp"
#include "smf_n1_n2.hpp"
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

    case N11_SESSION_UPDATE_SM_CONTEXT_RESPONSE:
      smf_n11_inst->send_msg_to_amf(std::static_pointer_cast<itti_n11_update_sm_context_response>(shared_msg));
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

//------------------------------------------------------------------------------
void smf_n11::send_msg_to_amf(std::shared_ptr<itti_n11_create_sm_context_response> sm_context_res)
{
  //Transfer N1/N2 message via AMF by using N_amf_Communication_N1N2MessageTransfer (see TS29518_Namf_Communication.yaml)
  //use curl to send data for the moment
  Logger::smf_n11().debug("[SMF N11: N1N2MessageTransfer] Send Communication_N1N2MessageTransfer to AMF");

  nlohmann::json message_transfer_req_data;
  std::string n1_message;
  std::string n2_message;
  smf_n1_n2 smf_n1_n2_inst;

  pdu_session_create_sm_context_response context_res_msg = sm_context_res->res;
  //Curl multipart
  CURL *curl = curl_easy_init();

  //get supi and put into URL
  std::string supi_str;
  supi_t supi = context_res_msg.get_supi();
  supi_str = context_res_msg.get_supi_prefix() + "-" + smf_supi_to_string (supi);
  std::string url = std::string(inet_ntoa (*((struct in_addr *)&smf_cfg.amf_addr.ipv4_addr)))  + ":" + std::to_string(smf_cfg.amf_addr.port) + "/namf-comm/v2/ue-contexts/" + supi_str.c_str() +"/n1-n2-messages";
  Logger::smf_n11().debug("[SMF N11: N1N2MessageTransfer] Sending Communication_N1N2MessageTransfer to AMF, AMF's URL: %s", url.c_str());

  //Create N1 SM container & N2 SM Information
  //TODO: should uncomment these lines when including UPF in the test
  //for the moment, can only test with PDU Session Establishment Reject!!
  context_res_msg.set_cause(REQUEST_ACCEPTED);//for testing purpose

  if (context_res_msg.get_cause() != REQUEST_ACCEPTED) { //PDU Session Establishment Reject
    Logger::smf_n11().debug("[SMF N11: N1N2MessageTransfer] PDU Session Establishment Reject\n");
    //pdu_session_msg& msg = context_res_msg;
    smf_n1_n2_inst.create_n1_sm_container(context_res_msg, PDU_SESSION_ESTABLISHMENT_REJECT, n1_message, 0); //TODO: need cause?
  } else { //PDU Session Establishment Accept
    Logger::smf_n11().debug("[SMF N11: N1N2MessageTransfer] PDU Session Establishment Accept \n");
    smf_n1_n2_inst.create_n1_sm_container(context_res_msg, PDU_SESSION_ESTABLISHMENT_ACCEPT, n1_message, 0); //TODO: need cause?
    //TODO: N2 SM Information (Step 11, section 4.3.2.2.1 @ 3GPP TS 23.502)
    smf_n1_n2_inst.create_n2_sm_information(context_res_msg, 1, 1, n2_message);
  }

  //Fill the json part
  //N1SM
  message_transfer_req_data["n1MessageContainer"]["n1MessageClass"] = "SM";
  message_transfer_req_data["n1MessageContainer"]["n1MessageContent"]["contentId"] = "n1SmMsg"; //part 2

  //N2SM
  if (context_res_msg.get_cause() == REQUEST_ACCEPTED){
    //TODO: fill the content of N1N2MessageTransferReqData
    message_transfer_req_data["n2InfoContainer"]["n2InformationClass"] = "SM";
    message_transfer_req_data["n2InfoContainer"]["smInfo"]["PduSessionId"] = 1;
    //N2InfoContent (section 6.1.6.2.27@3GPP TS 29.518)
    //message_transfer_req_data["n2InfoContainer"]["smInfo"]["n2InfoContent"]["ngapMessageType"] = 123; //NGAP message -to be verified: doesn't exist in tester (not required!!)
    message_transfer_req_data["n2InfoContainer"]["smInfo"]["n2InfoContent"]["ngapIeType"] = "PDU_RES_SETUP_REQ"; //NGAP message
    message_transfer_req_data["n2InfoContainer"]["smInfo"]["n2InfoContent"]["ngapData"]["contentId"] = "n2SmMsg"; //part 3
    //message_transfer_req_data["n2InfoContainer"]["smInfo"]["sNssai"]["sst"] = 222;
    //message_transfer_req_data["n2InfoContainer"]["smInfo"]["sNssai"]["sd"] = "0000D4";
    //message_transfer_req_data["n2InfoContainer"]["smInfo"]["nasPDU"] = ;//TODO: Doesn't exist in the spec (maybe N1MessageContainer in Spec!!), but exist in the tester!!
    message_transfer_req_data["n2InfoContainer"]["ranInfo"] = "SM";
  }
  //Others information
  message_transfer_req_data["ppi"] = 1; //Don't need this info for the moment
  message_transfer_req_data["pduSessionId"] = context_res_msg.get_pdu_session_id();
  //message_transfer_req_data["arp"]["priorityLevel"] = 1;
  //message_transfer_req_data["arp"]["preemptCap"] = "NOT_PREEMPT";
  //message_transfer_req_data["arp"]["preemptVuln"] = "NOT_PREEMPTABLE";
  //message_transfer_req_data["5qi"] = ;
  std::string json_part = message_transfer_req_data.dump();

  //fill the N1SmMsg, N2SmMsg content
  std::string n1_msg_hex;
  smf_app_inst->convert_string_2_hex(n1_message, n1_msg_hex);
  Logger::smf_n11().debug("[SMF N11: N1N2MessageTransfer] n1MessageContent: %s\n ", n1_msg_hex.c_str());

  std::string n2_msg_hex;
  if (context_res_msg.get_cause() == REQUEST_ACCEPTED){
    smf_app_inst->convert_string_2_hex(n2_message, n2_msg_hex);
    Logger::smf_n11().debug("[SMF N11: N1N2MessageTransfer] n2SMInformation %s\n ", n2_msg_hex.c_str());
  }

  Logger::smf_n11().debug("[SMF N11: N1N2MessageTransfer] Sending message to AMF....\n ");
  if(curl) {

    CURLcode res;
    struct curl_slist *headers = NULL;
    struct curl_slist *slist = NULL;
    curl_mime *mime;
    curl_mime *alt;
    curl_mimepart *part;

    //		headers = curl_slist_append(headers, "charsets: utf-8");
    headers = curl_slist_append(headers, "content-type: multipart/related");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str() );
    curl_easy_setopt(curl, CURLOPT_HTTPGET,1);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, AMF_CURL_TIMEOUT_MS);

    mime = curl_mime_init(curl);
    alt = curl_mime_init(curl);

    //part with N1N2MessageTransferReqData (JsonData)
    part = curl_mime_addpart(mime);
    curl_mime_data(part, json_part.c_str(), CURL_ZERO_TERMINATED);
    curl_mime_type(part, "application/json");

    //N1 SM Container
    part = curl_mime_addpart(mime);
    curl_mime_data(part, n1_msg_hex.c_str(), CURL_ZERO_TERMINATED);
    curl_mime_type(part, "application/vnd.3gpp.5gnas");
    curl_mime_name (part, "n1SmMsg");

    if (sm_context_res->res.get_cause() == REQUEST_ACCEPTED) {
      //N2 SM Information
      part = curl_mime_addpart(mime);
      //TODO:
      curl_mime_data(part, n2_msg_hex.substr(0,86).c_str(), CURL_ZERO_TERMINATED); //TODO: need to be solved
      curl_mime_type(part, "application/vnd.3gpp.ngap");
      curl_mime_name (part, "n2SmMsg");
    }

    curl_easy_setopt(curl, CURLOPT_MIMEPOST, mime);
    res = curl_easy_perform(curl);

    // Response information.
    long httpCode(0);
    std::unique_ptr<std::string> httpData(new std::string());
    /*
		// Hook up data handling function.
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &callback);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, httpData.get());
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
		curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)body.length());
     */
    int numRetries = 0;
    while (numRetries < AMF_NUMBER_RETRIES){
      res = curl_easy_perform(curl);
      curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);
      Logger::smf_n11().debug("[SMF N11: N1N2MessageTransfer] Response from AMF, Http Code: %d ", httpCode);

      if (httpCode == HTTP_STATUS_OK)
      {
        Logger::smf_n11().debug("[SMF N11: N1N2MessageTransfer] Got successful response from AMF, URL: %s ", url.c_str());
        break;
      }
      else
      {
        Logger::smf_n10().warn("[SMF N11: N1N2MessageTransfer] Couldn't GET response from AMF, URL %s, retry ...", url.c_str());
        //retry
        numRetries++;
      }
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    curl_mime_free(mime);
  }
  //TODO: process the response if necessary

}

//------------------------------------------------------------------------------
void smf_n11::send_msg_to_amf(std::shared_ptr<itti_n11_update_sm_context_response> sm_context_res)
{
  Logger::smf_n11().debug("[SMF N11] Send PDUSessionUpdateContextResponse to AMF ");
  //TODO: to be completed
  //Send reply to AMF
  /*	Pistache::Http::Code code;
	nlohmann::json jsonData;
	//to_json(jsonData, smContextCreateError);
	std::string resBody = jsonData.dump();
	sm_context_res->http_response.send(code,body);
   */

}
