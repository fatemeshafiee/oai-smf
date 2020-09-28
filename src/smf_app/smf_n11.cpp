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
#include "mime_parser.hpp"

extern "C" {
#include "dynamic_memory_check.h"
}

using namespace Pistache::Http;
using namespace Pistache::Http::Mime;

using namespace smf;
using json = nlohmann::json;

extern itti_mw *itti_inst;
extern smf_n11 *smf_n11_inst;
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

      case NX_TRIGGER_SESSION_MODIFICATION:
        smf_n11_inst->send_n1n2_message_transfer_request(
            std::static_pointer_cast<itti_nx_trigger_pdu_session_modification>(
                shared_msg));
        break;

      case N11_SESSION_REPORT_RESPONSE:
        smf_n11_inst->send_n1n2_message_transfer_request(
            std::static_pointer_cast<itti_n11_session_report_request>(
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

  Logger::smf_n11().debug("Send Communication_N1N2MessageTransfer to AMF (HTTP version %d)", sm_context_res->http_version);

  mime_parser parser = {};
  std::string n1_message = sm_context_res->res.get_n1_sm_message();
  nlohmann::json json_data = {};
  std::string body;

  sm_context_res->res.get_json_data(json_data);
  std::string json_part = json_data.dump();
  //add N2 content if available
  auto n2_sm_found = json_data.count(
      "n2InfoContainer");
  if (n2_sm_found > 0) {
    std::string n2_message = sm_context_res->res.get_n2_sm_information();
    //prepare the body content for Curl
    parser.create_multipart_related_content(body, json_part, CURL_MIME_BOUNDARY, n1_message,
                                     n2_message);
  } else {
    //prepare the body content for Curl
    parser.create_multipart_related_content(body, json_part, CURL_MIME_BOUNDARY, n1_message,
                                     multipart_related_content_part_e::NAS);
  }

  Logger::smf_n11().debug("Send Communication_N1N2MessageTransfer to AMF, body %s", body.c_str());

  uint32_t str_len = body.length();
  char *data = (char*) malloc(str_len + 1);
  memset(data, 0, str_len + 1);
  memcpy((void*) data, (void*) body.c_str(), str_len);

  curl_global_init(CURL_GLOBAL_ALL);
  CURL *curl = curl_easy_init();

  if (curl) {
    CURLcode res = { };
    struct curl_slist *headers = nullptr;
    //headers = curl_slist_append(headers, "charsets: utf-8");
    std::string content_type = "content-type: multipart/related; boundary="
        + std::string(CURL_MIME_BOUNDARY);
    headers = curl_slist_append(headers, content_type.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_URL,
                     sm_context_res->res.get_amf_url().c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, AMF_CURL_TIMEOUT_MS);
    curl_easy_setopt(curl, CURLOPT_INTERFACE, smf_cfg.sbi.if_name.c_str());

    if (sm_context_res->http_version == 2) {
        curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
        // we use a self-signed test server, skip verification during debugging
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
        curl_easy_setopt(curl, CURLOPT_HTTP_VERSION,
                         CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE);
    }

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
    itti_msg->set_procedure_type(
        session_management_procedures_type_e::PDU_SESSION_ESTABLISHMENT_UE_REQUESTED);
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
}

//------------------------------------------------------------------------------
void smf_n11::send_n1n2_message_transfer_request(
    std::shared_ptr<itti_nx_trigger_pdu_session_modification> sm_session_modification) {
  //Transfer N1/N2 message via AMF by using N_amf_Communication_N1N2MessageTransfer (see TS29518_Namf_Communication.yaml)

  Logger::smf_n11().debug("Send Communication_N1N2MessageTransfer to AMF");

  mime_parser parser = {};
  std::string body;
  nlohmann::json json_data = {};
  std::string json_part;
  std::string n1_message = sm_session_modification->msg.get_n1_sm_message();
  sm_session_modification->msg.get_json_data(json_data);
  json_part = json_data.dump();

  //add N2 content if available
  auto n2_sm_found = json_data.count(
      "n2InfoContainer");
  if (n2_sm_found > 0) {
    std::string n2_message = sm_session_modification->msg.get_n2_sm_information();
    parser.create_multipart_related_content(body, json_part, CURL_MIME_BOUNDARY, n1_message,
                                     n2_message);
  } else {
    parser.create_multipart_related_content(body, json_part, CURL_MIME_BOUNDARY, n1_message,
                                     multipart_related_content_part_e::NAS);
  }

  uint32_t str_len = body.length();
  char *data = (char*) malloc(str_len + 1);
  memset(data, 0, str_len + 1);
  memcpy((void*) data, (void*) body.c_str(), str_len);

  curl_global_init(CURL_GLOBAL_ALL);
  CURL *curl = curl_easy_init();

  if (curl) {
    CURLcode res = { };
    struct curl_slist *headers = nullptr;
    //headers = curl_slist_append(headers, "charsets: utf-8");
    std::string content_type = "content-type: multipart/related; boundary="
        + std::string(CURL_MIME_BOUNDARY);
    headers = curl_slist_append(headers, content_type.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_URL,
                     sm_session_modification->msg.get_amf_url().c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, AMF_CURL_TIMEOUT_MS);
    curl_easy_setopt(curl, CURLOPT_INTERFACE, smf_cfg.sbi.if_name.c_str());

    if (sm_session_modification->http_version == 2) {
        curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
        // we use a self-signed test server, skip verification during debugging
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
        curl_easy_setopt(curl, CURLOPT_HTTP_VERSION,
                         CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE);
    }

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
    }
    Logger::smf_n11().debug("Response from AMF, Http Code: %d", httpCode);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
  }
  curl_global_cleanup();
  free_wrapper((void**) &data);
}

//------------------------------------------------------------------------------
void smf_n11::send_n1n2_message_transfer_request(
    std::shared_ptr<itti_n11_session_report_request> report_msg) {

  Logger::smf_n11().debug(
      "Send Communication_N1N2MessageTransfer to AMF (Network-initiated Service Request)");

  mime_parser parser = {};
  std::string n2_message = report_msg->res.get_n2_sm_information();
  nlohmann::json json_data = {};
  std::string body;
  report_msg->res.get_json_data(json_data);
  std::string json_part = json_data.dump();

  //add N1 content if available
  auto n1_sm_found = json_data.count(
      "n1MessageContainer");
  if (n1_sm_found > 0) {
    std::string n1_message = report_msg->res.get_n1_sm_message();
    //prepare the body content for Curl
    parser.create_multipart_related_content(body, json_part, CURL_MIME_BOUNDARY, n1_message,
                                     n2_message);
  } else {
    parser.create_multipart_related_content(body, json_part, CURL_MIME_BOUNDARY, n2_message,
                                     multipart_related_content_part_e::NGAP);
  }

  uint32_t str_len = body.length();
  char *data = (char*) malloc(str_len + 1);
  memset(data, 0, str_len + 1);
  memcpy((void*) data, (void*) body.c_str(), str_len);

  curl_global_init(CURL_GLOBAL_ALL);
  CURL *curl = curl_easy_init();

  if (curl) {
    CURLcode res = { };
    struct curl_slist *headers = nullptr;
    //headers = curl_slist_append(headers, "charsets: utf-8");
    std::string content_type = "content-type: multipart/related; boundary="
        + std::string(CURL_MIME_BOUNDARY);
    headers = curl_slist_append(headers, content_type.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_URL, report_msg->res.get_amf_url().c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, AMF_CURL_TIMEOUT_MS);
    curl_easy_setopt(curl, CURLOPT_INTERFACE, smf_cfg.sbi.if_name.c_str());

    if (report_msg->http_version == 2) {
        curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
        // we use a self-signed test server, skip verification during debugging
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
        curl_easy_setopt(curl, CURLOPT_HTTP_VERSION,
                         CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE);
    }

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
    itti_msg->set_procedure_type(
        session_management_procedures_type_e::SERVICE_REQUEST_NETWORK_TRIGGERED);
    itti_msg->set_cause(response_data["cause"]);
    itti_msg->set_seid(report_msg->res.get_seid());
    itti_msg->set_trxn_id(report_msg->res.get_trxn_id());

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
}
