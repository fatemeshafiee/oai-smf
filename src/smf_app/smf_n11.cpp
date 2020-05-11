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

#include "smf_n11.hpp"

#include <stdexcept>

#include <curl/curl.h>
#include <nlohmann/json.hpp>
#include <pistache/http.h>
#include <pistache/mime.h>

#include "smf.h"
#include "common_defs.h"
#include "itti.hpp"
#include "logger.hpp"
#include "smf_app.hpp"
#include "smf_config.hpp"
#include "smf_n1_n2.hpp"

extern "C" {
#include "dynamic_memory_check.h"
}

using namespace Pistache::Http;
using namespace Pistache::Http::Mime;

using namespace smf;
using namespace std;
using json = nlohmann::json;

extern itti_mw *itti_inst;
extern smf_n11 *smf_n11_inst;
extern smf::smf_app *smf_app_inst;
extern smf_config smf_cfg;
void smf_n11_task(void*);

// To read content of the response from AMF
static std::size_t callback(const char *in, std::size_t size, std::size_t num,
                            std::string *out) {
  const std::size_t totalBytes(size * num);
  out->append(in, totalBytes);
  return totalBytes;
}

//------------------------------------------------------------------------------
void smf_n11_task(void *args_p) {
  const task_id_t task_id = TASK_SMF_N11;
  itti_inst->notify_task_ready(task_id);

  do {
    std::shared_ptr<itti_msg> shared_msg = itti_inst->receive_msg(task_id);
    auto *msg = shared_msg.get();
    switch (msg->msg_type) {

      case N11_SESSION_CREATE_SM_CONTEXT_RESPONSE:
        smf_n11_inst->send_n1n2_message_transfer_request(
            std::static_pointer_cast<itti_n11_create_sm_context_response>(
                shared_msg));
        break;

      case N11_SESSION_UPDATE_SM_CONTEXT_RESPONSE:
        smf_n11_inst->send_pdu_session_update_sm_context_response(
            std::static_pointer_cast<itti_n11_update_sm_context_response>(
                shared_msg));
        break;

      case N11_SESSION_MODIFICATION_REQUEST_SMF_REQUESTED:
        //TODO
        smf_n11_inst->send_n1n2_message_transfer_request(
            std::static_pointer_cast<
                itti_n11_modify_session_request_smf_requested>(shared_msg));
        break;
      case NX_TRIGGER_SESSION_MODIFICATION:
        smf_n11_inst->send_n1n2_message_transfer_request(
            std::static_pointer_cast<itti_nx_trigger_pdu_session_modification>(
                shared_msg));
        break;

      case TERMINATE:
        if (itti_msg_terminate *terminate =
            dynamic_cast<itti_msg_terminate*>(msg)) {
          Logger::smf_n11().info("Received terminate message");
          return;
        }
        break;

      default:
        Logger::smf_n11().info("no handler for msg type %d", msg->msg_type);
    }

  } while (true);
}

//------------------------------------------------------------------------------
smf_n11::smf_n11() {
  Logger::smf_n11().startup("Starting...");
  if (itti_inst->create_task(TASK_SMF_N11, smf_n11_task, nullptr)) {
    Logger::smf_n11().error("Cannot create task TASK_SMF_N11");
    throw std::runtime_error("Cannot create task TASK_SMF_N11");
  }
  Logger::smf_n11().startup("Started");
}

//------------------------------------------------------------------------------
void smf_n11::send_n1n2_message_transfer_request(
    std::shared_ptr<itti_n11_create_sm_context_response> sm_context_res) {
  //Transfer N1/N2 message via AMF by using N_amf_Communication_N1N2MessageTransfer (see TS29518_Namf_Communication.yaml)
  //TODO: use RestSDK for client, use curl to send data for the moment

  Logger::smf_n11().debug("Send Communication_N1N2MessageTransfer to AMF");

  smf_n1_n2 smf_n1_n2_inst = { };
  std::string n1_message = sm_context_res->res.get_n1_sm_message();
  std::string json_part = sm_context_res->res.n1n2_message_transfer_data.dump();
  std::string boundary = "----Boundary";
  std::string body;

  //add N2 content if available
  auto n2_sm_found = sm_context_res->res.n1n2_message_transfer_data.count(
      "n2InfoContainer");
  if (n2_sm_found > 0) {
    std::string n2_message = sm_context_res->res.get_n2_sm_information();
    //prepare the body content for Curl
    create_multipart_related_content(body, json_part, boundary, n1_message,
                                     n2_message);
  } else {
    //prepare the body content for Curl
    create_multipart_related_content(body, json_part, boundary, n1_message,
                                     multipart_related_content_part_e::NAS);
  }

  unsigned int str_len = body.length();
  char *data = (char*) malloc(str_len + 1);
  memset(data, 0, str_len + 1);
  memcpy((void*) data, (void*) body.c_str(), str_len);

  curl_global_init(CURL_GLOBAL_ALL);
  CURL *curl = curl_easy_init();

  if (curl) {
    CURLcode res = { };
    struct curl_slist *headers = nullptr;
    //headers = curl_slist_append(headers, "charsets: utf-8");
    headers = curl_slist_append(
        headers, "content-type: multipart/related; boundary=----Boundary");  //TODO: update Boundary
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_URL,
                     sm_context_res->res.get_amf_url().c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, AMF_CURL_TIMEOUT_MS);
    curl_easy_setopt(curl, CURLOPT_INTERFACE, smf_cfg.sbi.if_name.c_str());

    // Response information.
    long httpCode = { 0 };
    std::unique_ptr<std::string> httpData(new std::string());

    // Hook up data handling function
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, httpData.get());

    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, body.length());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);

    res = curl_easy_perform(curl);

    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);

    //get cause from the response
    json response_data = { };
    try {
      response_data = json::parse(*httpData.get());
    } catch (json::exception &e) {
      Logger::smf_n11().warn("Could not get the cause from the response");
      //Set the default Cause
      response_data["cause"] = "504 Gateway Timeout";
    }
    Logger::smf_n11().debug("Response from AMF, Http Code: %d, cause %s",
                            httpCode, response_data["cause"].dump().c_str());

    //send response to APP to process
    itti_n11_n1n2_message_transfer_response_status *itti_msg =
        new itti_n11_n1n2_message_transfer_response_status(TASK_SMF_N11,
                                                           TASK_SMF_APP);
    itti_msg->set_response_code(httpCode);
    itti_msg->set_scid(sm_context_res->scid);
    itti_msg->set_cause(response_data["cause"]);
    if (sm_context_res->res.get_cause() == REQUEST_ACCEPTED) {
      itti_msg->set_msg_type(PDU_SESSION_ESTABLISHMENT_ACCEPT);
    } else {
      itti_msg->set_msg_type(PDU_SESSION_ESTABLISHMENT_REJECT);
    }
    std::shared_ptr<itti_n11_n1n2_message_transfer_response_status> i =
        std::shared_ptr<itti_n11_n1n2_message_transfer_response_status>(
            itti_msg);
    int ret = itti_inst->send_msg(i);
    if (RETURNok != ret) {
      Logger::smf_n11().error(
          "Could not send ITTI message %s to task TASK_SMF_APP",
          i->get_msg_name());
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
  }
  curl_global_cleanup();
  free_wrapper((void**) &data);

  /*
   //Curl MIME
   //format string as hex
   unsigned char *n1_msg_hex = smf_app_inst->format_string_as_hex(n1_message);

   CURL *curl = curl_easy_init();

   //N1N2MessageTransfer Notification URI??
   std::string json_part = context_res_msg.n1n2_message_transfer_data.dump();

   Logger::smf_n11().debug("Sending message to AMF....");

   if (curl) {
   CURLcode res = { };
   struct curl_slist *headers = nullptr;
   struct curl_slist *slist = nullptr;
   curl_mime *mime;
   curl_mime *alt;
   curl_mimepart *part;

   //headers = curl_slist_append(headers, "charsets: utf-8");
   headers = curl_slist_append(headers, "content-type: multipart/related");
   curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
   curl_easy_setopt(curl, CURLOPT_URL, context_res_msg.get_amf_url().c_str());
   curl_easy_setopt(curl, CURLOPT_HTTPGET, 1);
   curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, AMF_CURL_TIMEOUT_MS);
   curl_easy_setopt(curl, CURLOPT_INTERFACE, smf_cfg.sbi.if_name.c_str());

   mime = curl_mime_init(curl);
   alt = curl_mime_init(curl);

   //part with N1N2MessageTransferReqData (JsonData)
   part = curl_mime_addpart(mime);
   curl_mime_data(part, json_part.c_str(), CURL_ZERO_TERMINATED);
   curl_mime_type(part, "application/json");

   //N1 SM Container
   Logger::smf_n11().debug(
   "Add N1 SM Container (NAS) into the message: %s (bytes %d)",
   context_res_msg.get_n1_sm_message().c_str(),
   context_res_msg.get_n1_sm_message().length() / 2);
   part = curl_mime_addpart(mime);
   curl_mime_data(part, reinterpret_cast<const char*>(n1_msg_hex),
   context_res_msg.get_n1_sm_message().length() / 2);
   curl_mime_type(part, "application/vnd.3gpp.5gnas");
   curl_mime_name(
   part,
   context_res_msg.n1n2_message_transfer_data["n1MessageContainer"]["n1MessageContent"]["contentId"]
   .dump().c_str());

   auto n2_sm_found = context_res_msg.n1n2_message_transfer_data.count(
   "n2InfoContainer");
   if (n2_sm_found > 0) {
   std::string n2_message = context_res_msg.get_n2_sm_information();
   unsigned char *n2_msg_hex = smf_app_inst->format_string_as_hex(
   n2_message);
   Logger::smf_n11().debug(
   "Add N2 SM Information (NGAP) into the message: %s (bytes %d)",
   n2_message.c_str(), n2_message.length() / 2);
   part = curl_mime_addpart(mime);
   curl_mime_data(part, reinterpret_cast<const char*>(n2_msg_hex), 80);  //TODO: n2_message.length()/2 ISSUE need to be solved
   curl_mime_type(part, "application/vnd.3gpp.ngap");
   curl_mime_name(
   part,
   context_res_msg.n1n2_message_transfer_data["n2InfoContainer"]["smInfo"]["n2InfoContent"]["ngapData"]["contentId"]
   .dump().c_str());
   }

   curl_easy_setopt(curl, CURLOPT_MIMEPOST, mime);

   // Response information.
   long httpCode = { 0 };
   std::unique_ptr<std::string> httpData(new std::string());

   // Hook up data handling function.
   curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &callback);
   curl_easy_setopt(curl, CURLOPT_WRITEDATA, httpData.get());

   res = curl_easy_perform(curl);
   curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);

   //get cause from the response
   json response_data = { };
   try {
   response_data = json::parse(*httpData.get());
   } catch (json::exception &e) {
   Logger::smf_n11().error("Could not get the cause from the response");
   //Set the default Cause
   response_data["cause"] = "504 Gateway Timeout";
   }
   Logger::smf_n11().debug("Response from AMF, Http Code: %d, cause %s",
   httpCode, response_data["cause"].dump().c_str());

   //send response to APP to process
   itti_n11_n1n2_message_transfer_response_status *itti_msg =
   new itti_n11_n1n2_message_transfer_response_status(TASK_SMF_N11,
   TASK_SMF_APP);
   itti_msg->set_response_code(httpCode);
   itti_msg->set_scid(sm_context_res->scid);
   itti_msg->set_cause(response_data["cause"]);
   if (context_res_msg.get_cause() == REQUEST_ACCEPTED) {
   itti_msg->set_msg_type(PDU_SESSION_ESTABLISHMENT_ACCEPT);
   } else {
   itti_msg->set_msg_type(PDU_SESSION_ESTABLISHMENT_REJECT);
   }
   std::shared_ptr<itti_n11_n1n2_message_transfer_response_status> i =
   std::shared_ptr<itti_n11_n1n2_message_transfer_response_status>(
   itti_msg);
   int ret = itti_inst->send_msg(i);
   if (RETURNok != ret) {
   Logger::smf_n11().error(
   "Could not send ITTI message %s to task TASK_SMF_APP",
   i->get_msg_name());
   }

   curl_slist_free_all(headers);
   curl_easy_cleanup(curl);
   curl_mime_free(mime);
   }
   */
}



//------------------------------------------------------------------------------
void smf_n11::send_n1n2_message_transfer_request(
    std::shared_ptr<itti_nx_trigger_pdu_session_modification> sm_context_res) {
  //Transfer N1/N2 message via AMF by using N_amf_Communication_N1N2MessageTransfer (see TS29518_Namf_Communication.yaml)

  Logger::smf_n11().debug("Send Communication_N1N2MessageTransfer to AMF");

  smf_n1_n2 smf_n1_n2_inst = { };
  std::string n1_message = sm_context_res->msg.get_n1_sm_message();
  std::string json_part = sm_context_res->msg.n1n2_message_transfer_data.dump();
  std::string boundary = "----Boundary";
  std::string body;

  //add N2 content if available
  auto n2_sm_found = sm_context_res->msg.n1n2_message_transfer_data.count(
      "n2InfoContainer");
  if (n2_sm_found > 0) {
    std::string n2_message = sm_context_res->msg.get_n2_sm_information();
    //prepare the body content for Curl
    create_multipart_related_content(body, json_part, boundary, n1_message,
                                     n2_message);
  } else {
    //prepare the body content for Curl
    create_multipart_related_content(body, json_part, boundary, n1_message,
                                     multipart_related_content_part_e::NAS);
  }

  unsigned int str_len = body.length();
  char *data = (char*) malloc(str_len + 1);
  memset(data, 0, str_len + 1);
  memcpy((void*) data, (void*) body.c_str(), str_len);

  curl_global_init(CURL_GLOBAL_ALL);
  CURL *curl = curl_easy_init();

  if (curl) {
    CURLcode res = { };
    struct curl_slist *headers = nullptr;
    //headers = curl_slist_append(headers, "charsets: utf-8");
    headers = curl_slist_append(
        headers, "content-type: multipart/related; boundary=----Boundary");  //TODO: update Boundary
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_URL,
                     sm_context_res->msg.get_amf_url().c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, AMF_CURL_TIMEOUT_MS);
    curl_easy_setopt(curl, CURLOPT_INTERFACE, smf_cfg.sbi.if_name.c_str());

    // Response information.
    long httpCode = { 0 };
    std::unique_ptr<std::string> httpData(new std::string());

    // Hook up data handling function
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, httpData.get());

    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, body.length());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);

    res = curl_easy_perform(curl);

    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);

    //get cause from the response
    json response_data = { };
    try {
      response_data = json::parse(*httpData.get());
    } catch (json::exception &e) {
      Logger::smf_n11().warn("Could not get the cause from the response");
      //Set the default Cause
      //response_data["cause"] = "504 Gateway Timeout";
    }
    Logger::smf_n11().debug("Response from AMF, Http Code: %d",
                            httpCode);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
  }
  curl_global_cleanup();
  free_wrapper((void**) &data);

}


//------------------------------------------------------------------------------
void smf_n11::send_pdu_session_update_sm_context_response(
    std::shared_ptr<itti_n11_update_sm_context_response> sm_context_res) {
  Logger::smf_n11().debug("Send PDUSession_UpdateSMContext Response to AMF.");

  switch (sm_context_res->session_procedure_type) {

    case session_management_procedures_type_e::PDU_SESSION_TEST: {
      Logger::smf_n11().debug("PDU_SESSION_TEST");

      std::string boundary = "----Boundary";
      std::string json_part =
          sm_context_res->res.sm_context_updated_data.dump();
      std::string n1_message = sm_context_res->res.get_n1_sm_message();
      std::string n2_message = sm_context_res->res.get_n2_sm_information();
      std::string body;

      create_multipart_related_content(body, json_part, boundary, n1_message,
                                       n2_message);
      sm_context_res->http_response.headers()
          .add<Pistache::Http::Header::ContentType>(
          Pistache::Http::Mime::MediaType(
              "multipart/related; boundary=" + boundary));
      sm_context_res->http_response.send(Pistache::Http::Code::Ok, body);
    }
      break;

    case session_management_procedures_type_e::PDU_SESSION_ESTABLISHMENT_UE_REQUESTED: {
      Logger::smf_n11().info("PDU_SESSION_ESTABLISHMENT_UE_REQUESTED");
      std::string json_part =
          sm_context_res->res.sm_context_updated_data.dump();
      sm_context_res->http_response.headers()
          .add<Pistache::Http::Header::ContentType>(
          Pistache::Http::Mime::MediaType("application/json"));
      sm_context_res->http_response.send(Pistache::Http::Code::Ok,
                                         json_part.c_str());
    }
      break;

    case session_management_procedures_type_e::PDU_SESSION_MODIFICATION_UE_INITIATED_STEP1: {
      Logger::smf_n11().info("PDU_SESSION_MODIFICATION_UE_INITIATED (step 1)");

      std::string boundary = "----Boundary";
      std::string json_part =
          sm_context_res->res.sm_context_updated_data.dump();
      std::string n1_message = sm_context_res->res.get_n1_sm_message();
      std::string n2_message = sm_context_res->res.get_n2_sm_information();
      std::string body;

      create_multipart_related_content(body, json_part, boundary, n1_message,
                                       n2_message);
      sm_context_res->http_response.headers()
          .add<Pistache::Http::Header::ContentType>(
          Pistache::Http::Mime::MediaType(
              "multipart/related; boundary=" + boundary));
      sm_context_res->http_response.send(Pistache::Http::Code::Ok, body);

    }
      break;

    case session_management_procedures_type_e::PDU_SESSION_MODIFICATION_UE_INITIATED_STEP2: {
      Logger::smf_n11().info("PDU_SESSION_MODIFICATION_UE_INITIATED (step 2)");
      sm_context_res->http_response.send(Pistache::Http::Code::No_Content);
    }
      break;

    case session_management_procedures_type_e::PDU_SESSION_MODIFICATION_UE_INITIATED_STEP3: {
      Logger::smf_n11().info("PDU_SESSION_MODIFICATION_UE_INITIATED (step 3)");
      sm_context_res->http_response.send(Pistache::Http::Code::No_Content);
    }
      break;

    case session_management_procedures_type_e::SERVICE_REQUEST_UE_TRIGGERED_STEP1: {
      Logger::smf_n11().info("SERVICE_REQUEST_UE_TRIGGERED (step 1)");

      std::string boundary = "----Boundary";
      std::string json_part =
          sm_context_res->res.sm_context_updated_data.dump();
      std::string n2_message = sm_context_res->res.get_n2_sm_information();
      std::string body;

      create_multipart_related_content(body, json_part, boundary, n2_message,
                                       multipart_related_content_part_e::NGAP);
      sm_context_res->http_response.headers()
          .add<Pistache::Http::Header::ContentType>(
          Pistache::Http::Mime::MediaType(
              "multipart/related; boundary=" + boundary));
      sm_context_res->http_response.send(Pistache::Http::Code::Ok, body);

    }
      break;

    case session_management_procedures_type_e::SERVICE_REQUEST_UE_TRIGGERED_STEP2: {
      Logger::smf_n11().info("SERVICE_REQUEST_UE_TRIGGERED (step 2)");
      std::string json_part =
          sm_context_res->res.sm_context_updated_data.dump();
      sm_context_res->http_response.headers()
          .add<Pistache::Http::Header::ContentType>(
          Pistache::Http::Mime::MediaType("application/json"));
      sm_context_res->http_response.send(Pistache::Http::Code::Ok,
                                         json_part.c_str());

    }
      break;

    case session_management_procedures_type_e::PDU_SESSION_RELEASE_UE_REQUESTED_STEP1: {
      Logger::smf_n11().info("PDU_SESSION_RELEASE_UE_REQUESTED (step 1)");

      std::string boundary = "----Boundary";
      std::string json_part =
          sm_context_res->res.sm_context_updated_data.dump();
      std::string n1_message = sm_context_res->res.get_n1_sm_message();
      std::string n2_message = sm_context_res->res.get_n2_sm_information();
      std::string body;

      create_multipart_related_content(body, json_part, boundary, n1_message,
                                       n2_message);
      sm_context_res->http_response.headers()
          .add<Pistache::Http::Header::ContentType>(
          Pistache::Http::Mime::MediaType(
              "multipart/related; boundary=" + boundary));
      sm_context_res->http_response.send(Pistache::Http::Code::Ok, body);
    }
      break;

    case session_management_procedures_type_e::PDU_SESSION_RELEASE_UE_REQUESTED_STEP2: {
      Logger::smf_n11().info("PDU_SESSION_RELEASE_UE_REQUESTED (step 2)");
      sm_context_res->http_response.send(Pistache::Http::Code::No_Content);
    }
      break;

    case session_management_procedures_type_e::PDU_SESSION_RELEASE_UE_REQUESTED_STEP3: {
      Logger::smf_n11().info("PDU_SESSION_RELEASE_UE_REQUESTED (step 3)");
      sm_context_res->http_response.send(Pistache::Http::Code::No_Content);
    }
      break;

    default: {
      Logger::smf_n11().debug("Session management procedure: unknown!");
    }
  }

}

//------------------------------------------------------------------------------
void smf_n11::send_pdu_session_update_sm_context_response(
    Pistache::Http::ResponseWriter &httpResponse,
    oai::smf_server::model::SmContextUpdateError &smContextUpdateError,
    Pistache::Http::Code code) {

  Logger::smf_n11().debug(
      "Send PDUSession_UpdateSMContext Response to AMF.");
  nlohmann::json json_data = { };
  to_json(json_data, smContextUpdateError);

  if (!json_data.empty()) {
    httpResponse.headers().add<Pistache::Http::Header::ContentType>(
        Pistache::Http::Mime::MediaType("application/json"));
    httpResponse.send(code, json_data.dump().c_str());
  } else {
    httpResponse.send(code);
  }

}

//------------------------------------------------------------------------------
void smf_n11::send_pdu_session_update_sm_context_response(
    Pistache::Http::ResponseWriter &httpResponse,
    oai::smf_server::model::SmContextUpdateError &smContextUpdateError,
    Pistache::Http::Code code, std::string &n1_sm_msg) {
  Logger::smf_n11().debug(
      "Send PDUSession_UpdateSMContext Response to AMF.");

  std::string boundary = "----Boundary";
  nlohmann::json json_part = { };
  to_json(json_part, smContextUpdateError);
  std::string json_str = json_part.dump();
  std::string body;

  create_multipart_related_content(body, json_str, boundary, n1_sm_msg,
                                   multipart_related_content_part_e::NAS);
  httpResponse.headers().add<Pistache::Http::Header::ContentType>(
      Pistache::Http::Mime::MediaType(
          "multipart/related; boundary=" + boundary));
  httpResponse.send(code, body);

}

//------------------------------------------------------------------------------
void smf_n11::send_pdu_session_create_sm_context_response(
    Pistache::Http::ResponseWriter &httpResponse,
    oai::smf_server::model::SmContextCreateError &smContextCreateError,
    Pistache::Http::Code code, std::string &n1_sm_msg) {
  Logger::smf_n11().debug(
      "Send PDUSession_CreateSMContext Response to AMF.");

  std::string boundary = "----Boundary";
  nlohmann::json json_part = { };
  to_json(json_part, smContextCreateError);
  std::string json_str = json_part.dump();
  std::string body;

  create_multipart_related_content(body, json_str, boundary, n1_sm_msg,
                                   multipart_related_content_part_e::NAS);
  httpResponse.headers().add<Pistache::Http::Header::ContentType>(
      Pistache::Http::Mime::MediaType(
          "multipart/related; boundary=" + boundary));
  httpResponse.send(code, body);

}

//------------------------------------------------------------------------------
void smf_n11::send_pdu_session_update_sm_context_response(
    Pistache::Http::ResponseWriter &httpResponse,
    oai::smf_server::model::SmContextUpdatedData &smContextUpdatedData,
    Pistache::Http::Code code) {
  Logger::smf_n11().debug(
      "Send PDUSession_UpdateSMContext Response to AMF.");
  nlohmann::json json_data = { };
  to_json(json_data, smContextUpdatedData);
  if (!json_data.empty()) {
    httpResponse.headers().add<Pistache::Http::Header::ContentType>(
        Pistache::Http::Mime::MediaType("application/json"));
    httpResponse.send(code, json_data.dump().c_str());
  } else {
    httpResponse.send(code);
  }

}

//------------------------------------------------------------------------------
void smf_n11::send_pdu_session_create_sm_context_response(
    Pistache::Http::ResponseWriter &httpResponse,
    oai::smf_server::model::SmContextCreatedData &smContextCreatedData,
    Pistache::Http::Code code) {
  Logger::smf_n11().debug(
      "Send PDUSession_CreateSMContext Response to AMF.");
  nlohmann::json json_data = { };
  to_json(json_data, smContextCreatedData);
  if (!json_data.empty()) {
    httpResponse.headers().add<Pistache::Http::Header::ContentType>(
        Pistache::Http::Mime::MediaType("application/json"));
    httpResponse.send(code, json_data.dump().c_str());
  } else {
    httpResponse.send(code);
  }

}

//------------------------------------------------------------------------------
void smf_n11::send_n1n2_message_transfer_request(
    std::shared_ptr<itti_n11_modify_session_request_smf_requested> sm_context_mod) {
  //TODO:
}

//------------------------------------------------------------------------------
void smf_n11::send_pdu_session_release_sm_context_response(
    Pistache::Http::ResponseWriter &httpResponse, Pistache::Http::Code code) {
  Logger::smf_n11().debug(
      "Send PDUSession_ReleaseSMContext Response to AMF.");
  httpResponse.send(code);
}

//------------------------------------------------------------------------------
void smf_n11::send_pdu_session_release_sm_context_response(
    Pistache::Http::ResponseWriter &httpResponse,
    oai::smf_server::model::ProblemDetails &problem,
    Pistache::Http::Code code) {

  Logger::smf_n11().debug(
      "Send PDUSession_ReleaseSMContext Response to AMF.");
  nlohmann::json json_data = { };
  to_json(json_data, problem);
  if (!json_data.empty()) {
    httpResponse.headers().add<Pistache::Http::Header::ContentType>(
        Pistache::Http::Mime::MediaType("application/json"));
    httpResponse.send(code, json_data.dump().c_str());
  } else {
    httpResponse.send(code);
  }
}

//------------------------------------------------------------------------------
void smf_n11::create_multipart_related_content(std::string &body,
                                               std::string &json_part,
                                               std::string &boundary,
                                               std::string &n1_message,
                                               std::string &n2_message) {

  //format string as hex
  unsigned char *n1_msg_hex = smf_app_inst->format_string_as_hex(n1_message);
  unsigned char *n2_msg_hex = smf_app_inst->format_string_as_hex(n2_message);

  string CRLF = "\r\n";
  body.append("--" + boundary + CRLF);
  body.append("Content-Type: application/json" + CRLF);
  body.append(CRLF);
  body.append(json_part + CRLF);

  body.append("--" + boundary + CRLF);
  body.append(
      "Content-Type: application/vnd.3gpp.5gnas" + CRLF + "Content-Id: n1SmMsg"
          + CRLF);
  body.append(CRLF);
  body.append(std::string((char*) n1_msg_hex, n1_message.length() / 2) + CRLF);
  //body.append(n1_message + CRLF);

  body.append("--" + boundary + CRLF);
  body.append(
      "Content-Type: application/vnd.3gpp.ngap" + CRLF + "Content-Id: n2SmMsg"
          + CRLF);
  body.append(CRLF);
  body.append(std::string((char*) n2_msg_hex, n2_message.length() / 2) + CRLF);
  body.append("--" + boundary + "--" + CRLF);
}

//------------------------------------------------------------------------------
void smf_n11::create_multipart_related_content(
    std::string &body, std::string &json_part, std::string &boundary,
    std::string &message, multipart_related_content_part_e content_type) {

  //format string as hex
  unsigned char *msg_hex = smf_app_inst->format_string_as_hex(message);

  string CRLF = "\r\n";
  body.append("--" + boundary + CRLF);
  body.append("Content-Type: application/json" + CRLF);
  body.append(CRLF);
  body.append(json_part + CRLF);

  body.append("--" + boundary + CRLF);
  if (content_type == multipart_related_content_part_e::NAS) {  //NAS
    body.append(
        "Content-Type: application/vnd.3gpp.5gnas" + CRLF
            + "Content-Id: n1SmMsg" + CRLF);
  } else if (content_type == multipart_related_content_part_e::NGAP) {  //NGAP
    body.append(
        "Content-Type: application/vnd.3gpp.ngap" + CRLF + "Content-Id: n2SmMsg"
            + CRLF);
  }
  body.append(CRLF);
  body.append(std::string((char*) msg_hex, message.length() / 2) + CRLF);
  body.append("--" + boundary + "--" + CRLF);
}
