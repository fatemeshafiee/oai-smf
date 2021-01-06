/*
 * Licensed to the OpenAirInterface (OAI) Software Alliance under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The OpenAirInterface Software Alliance licenses this file to You under
 * the OAI Public License, Version 1.1  (the "License"); you may not use this
 * file except in compliance with the License. You may obtain a copy of the
 * License at
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
#include <pistache/http.h>
#include <pistache/mime.h>
#include <nlohmann/json.hpp>

#include "common_defs.h"
#include "itti.hpp"
#include "logger.hpp"
#include "mime_parser.hpp"
#include "smf.h"
#include "smf_app.hpp"
#include "smf_config.hpp"

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
void smf_n11_task(void *);

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

      case N11_SESSION_NOTIFY_SM_CONTEXT_STATUS:
        smf_n11_inst->send_sm_context_status_notification(
            std::static_pointer_cast<itti_n11_notify_sm_context_status>(
                shared_msg));
        break;

      case N11_NOTIFY_SUBSCRIBED_EVENT:
        smf_n11_inst->notify_subscribed_event(
            std::static_pointer_cast<itti_n11_notify_subscribed_event>(
                shared_msg));
        break;

      case N11_REGISTER_NF_INSTANCE_REQUEST:
        smf_n11_inst->register_nf_instance(
            std::static_pointer_cast<itti_n11_register_nf_instance_request>(
                shared_msg));
        break;

      case N11_UPDATE_NF_INSTANCE_REQUEST:
        smf_n11_inst->update_nf_instance(
            std::static_pointer_cast<itti_n11_update_nf_instance_request>(
                shared_msg));
        break;

      case TERMINATE:
        if (itti_msg_terminate *terminate =
                dynamic_cast<itti_msg_terminate *>(msg)) {
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
  Logger::smf_n11().debug(
      "Send Communication_N1N2MessageTransfer to AMF (HTTP version %d)",
      sm_context_res->http_version);

  mime_parser parser = {};
  std::string n1_message = sm_context_res->res.get_n1_sm_message();
  nlohmann::json json_data = {};
  std::string body;

  sm_context_res->res.get_json_data(json_data);
  std::string json_part = json_data.dump();
  // add N2 content if available
  auto n2_sm_found = json_data.count("n2InfoContainer");
  if (n2_sm_found > 0) {
    std::string n2_message = sm_context_res->res.get_n2_sm_information();
    // prepare the body content for Curl
    parser.create_multipart_related_content(body, json_part, CURL_MIME_BOUNDARY,
                                            n1_message, n2_message);
  } else {
    // prepare the body content for Curl
    parser.create_multipart_related_content(
        body, json_part, CURL_MIME_BOUNDARY, n1_message,
        multipart_related_content_part_e::NAS);
  }

  Logger::smf_n11().debug(
      "Send Communication_N1N2MessageTransfer to AMF, body %s", body.c_str());

  uint32_t str_len = body.length();
  char *data = (char *)malloc(str_len + 1);
  memset(data, 0, str_len + 1);
  memcpy((void *)data, (void *)body.c_str(), str_len);

  curl_global_init(CURL_GLOBAL_ALL);
  CURL *curl = curl_easy_init();

  if (curl) {
    CURLcode res = {};
    struct curl_slist *headers = nullptr;
    // headers = curl_slist_append(headers, "charsets: utf-8");
    std::string content_type = "content-type: multipart/related; boundary=" +
                               std::string(CURL_MIME_BOUNDARY);
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
    long httpCode = {0};
    std::unique_ptr<std::string> httpData(new std::string());

    // Hook up data handling function
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, httpData.get());

    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, body.length());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);

    res = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);
    // get cause from the response
    json response_data = {};
    try {
      response_data = json::parse(*httpData.get());
    } catch (json::exception &e) {
      Logger::smf_n11().warn("Could not get the cause from the response");
      // Set the default Cause
      response_data["cause"] = "504 Gateway Timeout";
    }
    Logger::smf_n11().debug("Response from AMF, Http Code: %d, cause %s",
                            httpCode, response_data["cause"].dump().c_str());

    // send response to APP to process
    itti_n11_n1n2_message_transfer_response_status *itti_msg =
        new itti_n11_n1n2_message_transfer_response_status(TASK_SMF_N11,
                                                           TASK_SMF_APP);
    itti_msg->set_response_code(httpCode);
    itti_msg->set_scid(sm_context_res->scid);
    itti_msg->set_procedure_type(session_management_procedures_type_e::
                                     PDU_SESSION_ESTABLISHMENT_UE_REQUESTED);
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
  free_wrapper((void **)&data);
}

//------------------------------------------------------------------------------
void smf_n11::send_n1n2_message_transfer_request(
    std::shared_ptr<itti_nx_trigger_pdu_session_modification>
        sm_session_modification) {
  Logger::smf_n11().debug("Send Communication_N1N2MessageTransfer to AMF");

  mime_parser parser = {};
  std::string body;
  nlohmann::json json_data = {};
  std::string json_part;
  std::string n1_message = sm_session_modification->msg.get_n1_sm_message();
  sm_session_modification->msg.get_json_data(json_data);
  json_part = json_data.dump();

  // add N2 content if available
  auto n2_sm_found = json_data.count("n2InfoContainer");
  if (n2_sm_found > 0) {
    std::string n2_message =
        sm_session_modification->msg.get_n2_sm_information();
    parser.create_multipart_related_content(body, json_part, CURL_MIME_BOUNDARY,
                                            n1_message, n2_message);
  } else {
    parser.create_multipart_related_content(
        body, json_part, CURL_MIME_BOUNDARY, n1_message,
        multipart_related_content_part_e::NAS);
  }

  uint32_t str_len = body.length();
  char *data = (char *)malloc(str_len + 1);
  memset(data, 0, str_len + 1);
  memcpy((void *)data, (void *)body.c_str(), str_len);

  curl_global_init(CURL_GLOBAL_ALL);
  CURL *curl = curl_easy_init();

  if (curl) {
    CURLcode res = {};
    struct curl_slist *headers = nullptr;
    // headers = curl_slist_append(headers, "charsets: utf-8");
    std::string content_type = "content-type: multipart/related; boundary=" +
                               std::string(CURL_MIME_BOUNDARY);
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
    long httpCode = {0};
    std::unique_ptr<std::string> httpData(new std::string());

    // Hook up data handling function
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, httpData.get());

    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, body.length());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);

    res = curl_easy_perform(curl);

    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);

    // get cause from the response
    json response_data = {};
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
  free_wrapper((void **)&data);
}

//------------------------------------------------------------------------------
void smf_n11::send_n1n2_message_transfer_request(
    std::shared_ptr<itti_n11_session_report_request> report_msg) {
  Logger::smf_n11().debug(
      "Send Communication_N1N2MessageTransfer to AMF (Network-initiated "
      "Service Request)");

  mime_parser parser = {};
  std::string n2_message = report_msg->res.get_n2_sm_information();
  nlohmann::json json_data = {};
  std::string body;
  report_msg->res.get_json_data(json_data);
  std::string json_part = json_data.dump();

  // add N1 content if available
  auto n1_sm_found = json_data.count("n1MessageContainer");
  if (n1_sm_found > 0) {
    std::string n1_message = report_msg->res.get_n1_sm_message();
    // prepare the body content for Curl
    parser.create_multipart_related_content(body, json_part, CURL_MIME_BOUNDARY,
                                            n1_message, n2_message);
  } else {
    parser.create_multipart_related_content(
        body, json_part, CURL_MIME_BOUNDARY, n2_message,
        multipart_related_content_part_e::NGAP);
  }

  uint32_t str_len = body.length();
  char *data = (char *)malloc(str_len + 1);
  memset(data, 0, str_len + 1);
  memcpy((void *)data, (void *)body.c_str(), str_len);

  curl_global_init(CURL_GLOBAL_ALL);
  CURL *curl = curl_easy_init();

  if (curl) {
    CURLcode res = {};
    struct curl_slist *headers = nullptr;
    // headers = curl_slist_append(headers, "charsets: utf-8");
    std::string content_type = "content-type: multipart/related; boundary=" +
                               std::string(CURL_MIME_BOUNDARY);
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
    long httpCode = {0};
    std::unique_ptr<std::string> httpData(new std::string());

    // Hook up data handling function
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, httpData.get());

    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, body.length());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);

    res = curl_easy_perform(curl);

    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);

    // get cause from the response
    json response_data = {};
    try {
      response_data = json::parse(*httpData.get());
    } catch (json::exception &e) {
      Logger::smf_n11().warn("Could not get the cause from the response");
      // Set the default Cause
      response_data["cause"] = "504 Gateway Timeout";
    }
    Logger::smf_n11().debug("Response from AMF, Http Code: %d, cause %s",
                            httpCode, response_data["cause"].dump().c_str());

    // send response to APP to process
    itti_n11_n1n2_message_transfer_response_status *itti_msg =
        new itti_n11_n1n2_message_transfer_response_status(TASK_SMF_N11,
                                                           TASK_SMF_APP);
    itti_msg->set_response_code(httpCode);
    itti_msg->set_procedure_type(session_management_procedures_type_e::
                                     SERVICE_REQUEST_NETWORK_TRIGGERED);
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
  free_wrapper((void **)&data);
}

//------------------------------------------------------------------------------
void smf_n11::send_sm_context_status_notification(
    std::shared_ptr<itti_n11_notify_sm_context_status> sm_context_status) {
  Logger::smf_n11().debug(
      "Send SM Context Status Notification to AMF(HTTP version %d)",
      sm_context_status->http_version);
  Logger::smf_n11().debug("AMF URI: %s",
                          sm_context_status->amf_status_uri.c_str());

  nlohmann::json json_data = {};
  // Fill the json part
  json_data["statusInfo"]["resourceStatus"] =
      sm_context_status->sm_context_status;
  std::string body = json_data.dump();

  curl_global_init(CURL_GLOBAL_ALL);
  CURL *curl = curl = curl_easy_init();

  if (curl) {
    CURLcode res = {};
    struct curl_slist *headers = nullptr;
    // headers = curl_slist_append(headers, "charsets: utf-8");
    headers = curl_slist_append(headers, "content-type: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_URL,
                     sm_context_status->amf_status_uri.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, AMF_CURL_TIMEOUT_MS);

    if (sm_context_status->http_version == 2) {
      curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
      // we use a self-signed test server, skip verification during debugging
      curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
      curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
      curl_easy_setopt(curl, CURLOPT_HTTP_VERSION,
                       CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE);
    }

    // Response information.
    long httpCode = {0};
    std::unique_ptr<std::string> httpData(new std::string());

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, httpData.get());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, body.length());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
    res = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);

    Logger::smf_n11().debug("Response from AMF, Http Code: %d", httpCode);
    // TODO: in case of "307 temporary redirect"

    curl_easy_cleanup(curl);
  }
  curl_global_cleanup();
}

//-----------------------------------------------------------------------------------------------------
void smf_n11::notify_subscribed_event(
    std::shared_ptr<itti_n11_notify_subscribed_event> msg) {
  Logger::smf_n11().debug(
      "Send notification for the subscribed event to the subscription");

  int still_running = 0, numfds = 0, res = 0;
  CURLMsg *curl_msg = nullptr;
  CURL *curl = nullptr;
  CURLcode return_code = {};
  int http_status_code = 0, msgs_left = 0;
  CURLM *m_curl_multi = nullptr;
  char *url = nullptr;

  std::unique_ptr<std::string> httpData(new std::string());
  std::string data;

  curl_global_init(CURL_GLOBAL_ALL);
  m_curl_multi = curl_multi_init();
  // init header
  struct curl_slist *headers = NULL;
  headers = curl_slist_append(headers, "Accept: application/json");
  headers = curl_slist_append(headers, "Content-Type: application/json");
  headers = curl_slist_append(headers, "charsets: utf-8");

  std::vector<std::string> bodys = {};  // store body for all the request
  for (auto i : msg->event_notifs) {
    // Fill the json part
    nlohmann::json json_data = {};
    json_data["notifId"] = i.get_notif_id();
    auto event_notifs = nlohmann::json::array();
    nlohmann::json event_notif = {};
    event_notif["event"] = i.get_smf_event();
    event_notif["pduSeId"] = i.get_pdu_session_id();
    event_notif["supi"] = std::to_string(i.get_supi());
    // timestamp
    std::time_t time_epoch_ntp = std::time(nullptr);
    uint64_t tv_ntp = time_epoch_ntp + SECONDS_SINCE_FIRST_EPOCH;
    event_notif["timeStamp"] = std::to_string(tv_ntp);
    event_notifs.push_back(event_notif);
    json_data["eventNotifs"] = event_notifs;
    std::string body = json_data.dump();
    bodys.push_back(body);
  }

  int index = 0;
  // create and add an easy handle to a  multi curl request
  for (auto i : msg->event_notifs) {
    CURL *curl = curl_easy_init();
    if (curl) {
      std::string url = i.get_notif_uri();
      Logger::smf_n11().debug("Send notification to NF with URI: %s",
                              url.c_str());
      curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
      curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
      curl_easy_setopt(curl, CURLOPT_HTTPPOST, 1);
      curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 100L);
      // Hook up data handling function.
      curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &callback);
      curl_easy_setopt(curl, CURLOPT_WRITEDATA, httpData.get());
      curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
      curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, bodys.at(index).length());
      curl_easy_setopt(curl, CURLOPT_POSTFIELDS, bodys.at(index).c_str());
    }
    curl_multi_add_handle(m_curl_multi, curl);
    index++;
  }

  curl_multi_perform(m_curl_multi, &still_running);
  // block until activity is detected on at least one of the handles or
  // MAX_WAIT_MSECS has passed.
  do {
    res = curl_multi_wait(m_curl_multi, NULL, 0, 1000, &numfds);
    if (res != CURLM_OK) {
      Logger::smf_n11().debug("curl_multi_wait() returned %d!", res);
    }
    curl_multi_perform(m_curl_multi, &still_running);
  } while (still_running);

  // process multiple curl
  // read the messages
  while ((curl_msg = curl_multi_info_read(m_curl_multi, &msgs_left))) {
    if (curl_msg->msg == CURLMSG_DONE) {
      curl = curl_msg->easy_handle;
      return_code = curl_msg->data.result;
      res = curl_easy_getinfo(curl, CURLINFO_EFFECTIVE_URL, &url);

      if (return_code != CURLE_OK) {
        Logger::smf_n11().debug("CURL error code  %d!", curl_msg->data.result);
        continue;
      }
      // Get HTTP status code
      curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_status_code);
      Logger::smf_n11().debug("HTTP status code  %d!", http_status_code);

      // remove this handle from the multi session and end this handle
      curl_multi_remove_handle(m_curl_multi, curl);
      curl_easy_cleanup(curl);
    } else {
      Logger::smf_n11().debug("Error after curl_multi_info_read(), CURLMsg %s",
                              curl_msg->msg);
    }
  }
}

//-----------------------------------------------------------------------------------------------------
CURL *smf_n11::curl_create_handle(event_notification &ev_notif,
                                  std::string *httpData) {
  // create handle for a curl request
  struct curl_slist *headers = NULL;
  headers = curl_slist_append(headers, "Accept: application/json");
  headers = curl_slist_append(headers, "Content-Type: application/json");
  headers = curl_slist_append(headers, "charsets: utf-8");

  CURL *curl = curl_easy_init();

  if (curl) {
    std::string url = ev_notif.get_notif_uri();
    Logger::smf_n11().debug("Send notification to NF with URI: %s", url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    // curl_easy_setopt(curl, CURLOPT_PRIVATE, str);
    // curl_easy_setopt(curl, CURLOPT_VERBOSE, 0L);
    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 100L);
    // Hook up data handling function.
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, httpData);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
  }
  return curl;
}

//-----------------------------------------------------------------------------------------------------
void smf_n11::register_nf_instance(
    std::shared_ptr<itti_n11_register_nf_instance_request> msg) {
  Logger::smf_n11().debug(
      "Send NF Instance Registration to NRF (HTTP version %d)",
      msg->http_version);
  nlohmann::json json_data = {};
  msg->profile.to_json(json_data);

  std::string url =
      std::string(inet_ntoa(*((struct in_addr *)&smf_cfg.nrf_addr.ipv4_addr))) +
      ":" + std::to_string(smf_cfg.nrf_addr.port) + NNRF_NFM_BASE +
      smf_cfg.nrf_addr.api_version + NNRF_NF_REGISTER_URL +
      msg->profile.get_nf_instance_id();

  Logger::smf_n11().debug("Send NF Instance Registration to NRF (NRF URL %s)",
                          url.c_str());

  std::string body = json_data.dump();
  Logger::smf_n11().debug("Send NF Instance Registration to NRF (Msg body %s)",
                          body.c_str());

  curl_global_init(CURL_GLOBAL_ALL);
  CURL *curl = curl = curl_easy_init();

  if (curl) {
    CURLcode res = {};
    struct curl_slist *headers = nullptr;
    // headers = curl_slist_append(headers, "charsets: utf-8");
    headers = curl_slist_append(headers, "content-type: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT");
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, AMF_CURL_TIMEOUT_MS);

    if (msg->http_version == 2) {
      curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
      // we use a self-signed test server, skip verification during debugging
      curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
      curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
      curl_easy_setopt(curl, CURLOPT_HTTP_VERSION,
                       CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE);
    }

    // Response information.
    long httpCode = {0};
    std::unique_ptr<std::string> httpData(new std::string());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, httpData.get());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, body.length());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
    res = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);

    Logger::smf_n11().debug("Response from AMF, Http Code: %d", httpCode);

    if (static_cast<http_response_codes_e>(httpCode) ==
        http_response_codes_e::HTTP_RESPONSE_CODE_CREATED) {
      Logger::smf_n11().debug("Got successful response from NRF");

      json response_data = {};
      try {
        response_data = json::parse(*httpData.get());
      } catch (json::exception &e) {
        Logger::smf_n11().warn("Could not parse json from the NRF response");
      }
      Logger::smf_n11().debug("Response from NRF, Http Code: %d", httpCode);

      // send response to APP to process
      std::shared_ptr<itti_n11_register_nf_instance_response> itti_msg =
          std::make_shared<itti_n11_register_nf_instance_response>(
              TASK_SMF_N11, TASK_SMF_APP);
      itti_msg->http_response_code = httpCode;
      itti_msg->http_version = msg->http_version;
      itti_msg->profile.from_json(response_data);

      int ret = itti_inst->send_msg(itti_msg);
      if (RETURNok != ret) {
        Logger::smf_n11().error(
            "Could not send ITTI message %s to task TASK_SMF_APP",
            itti_msg->get_msg_name());
      }
    } else {
      Logger::smf_n11().warn("Could not get response from NRF");
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
  }
  curl_global_cleanup();
}

//-----------------------------------------------------------------------------------------------------
void smf_n11::update_nf_instance(
    std::shared_ptr<itti_n11_update_nf_instance_request> msg) {
  Logger::smf_n11().debug(
      "Send NF Instance Registration to NRF (HTTP version %d)",
      msg->http_version);

  nlohmann::json json_data = nlohmann::json::array();
  for (auto i : msg->patch_items) {
    nlohmann::json item = {};
    to_json(item, i);
    json_data.push_back(item);
  }
  std::string body = json_data.dump();
  Logger::smf_n11().debug("Send NF Instance Registration to NRF (Msg body %s)",
                          body.c_str());

  std::string url =
      std::string(inet_ntoa(*((struct in_addr *)&smf_cfg.nrf_addr.ipv4_addr))) +
      ":" + std::to_string(smf_cfg.nrf_addr.port) + NNRF_NFM_BASE +
      smf_cfg.nrf_addr.api_version + NNRF_NF_REGISTER_URL +
      msg->smf_instance_id;

  Logger::smf_n11().debug("Send NF Update to NRF (NRF URL %s)", url.c_str());

  curl_global_init(CURL_GLOBAL_ALL);
  CURL *curl = curl = curl_easy_init();

  if (curl) {
    CURLcode res = {};
    struct curl_slist *headers = nullptr;
    // headers = curl_slist_append(headers, "charsets: utf-8");
    headers = curl_slist_append(headers, "content-type: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PATCH");
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, AMF_CURL_TIMEOUT_MS);

    if (msg->http_version == 2) {
      curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
      // we use a self-signed test server, skip verification during debugging
      curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
      curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
      curl_easy_setopt(curl, CURLOPT_HTTP_VERSION,
                       CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE);
    }

    // Response information.
    long httpCode = {0};
    std::unique_ptr<std::string> httpData(new std::string());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, httpData.get());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, body.length());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
    res = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);

    Logger::smf_n11().debug("Response from NRF, Http Code: %d", httpCode);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
  }
  curl_global_cleanup();
}
