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
 \author  Tien-Thinh NGUYEN
 \company Eurecom
 \date 2019
 \email: tien-thinh.nguyen@eurecom.fr
 */

#include "smf_n10.hpp"

#include <stdexcept>

#include <curl/curl.h>
#include <nlohmann/json.hpp>
#include "smf.h"
#include "common_defs.h"
#include "itti.hpp"
#include "logger.hpp"
#include "smf_config.hpp"

using namespace smf;
using namespace std;
using json = nlohmann::json;

extern itti_mw *itti_inst;
extern smf_n10 *smf_n10_inst;
extern smf_config smf_cfg;
void smf_n10_task(void*);

/*
 * To read content of the response from UDM
 */
static std::size_t callback(const char *in, std::size_t size, std::size_t num,
                            std::string *out) {
  const std::size_t totalBytes(size * num);
  out->append(in, totalBytes);
  return totalBytes;
}

//------------------------------------------------------------------------------
void smf_n10_task(void *args_p) {
  const task_id_t task_id = TASK_SMF_N10;
  itti_inst->notify_task_ready(task_id);

  do {
    std::shared_ptr<itti_msg> shared_msg = itti_inst->receive_msg(task_id);
    auto *msg = shared_msg.get();
    switch (msg->msg_type) {

      case N10_SESSION_GET_SESSION_MANAGEMENT_SUBSCRIPTION:
        //if (itti_n10_get_session_management_subscription* m = dynamic_cast<itti_n10_get_session_management_subscription*>(msg)) {
        //  smf_n10_inst->send_sm_data_get_msg(ref(*m));
        //}
        break;

      case TERMINATE:
        if (itti_msg_terminate *terminate =
            dynamic_cast<itti_msg_terminate*>(msg)) {
          Logger::smf_n10().info("Received terminate message");
          return;
        }
        break;

      default:
        Logger::smf_n10().info("no handler for msg type %d", msg->msg_type);
    }

  } while (true);
}

//------------------------------------------------------------------------------
smf_n10::smf_n10() {
  Logger::smf_n10().startup("Starting...");
  if (itti_inst->create_task(TASK_SMF_N10, smf_n10_task, nullptr)) {
    Logger::smf_n10().error("Cannot create task TASK_SMF_N10");
    throw std::runtime_error("Cannot create task TASK_SMF_N10");
  }
  Logger::smf_n10().startup("Started");
}

//------------------------------------------------------------------------------
bool smf_n10::get_sm_data(
    const supi64_t &supi, const std::string &dnn, const snssai_t &snssai,
    std::shared_ptr<session_management_subscription> subscription) {
  //retrieve a UE's Session Management Subscription Data (TS29503_Nudm_SDM.yaml: /{supi}/sm-data)
  //use curl to send data for the moment

  nlohmann::json jsonData = { };
  curl_global_init(CURL_GLOBAL_DEFAULT);
  struct curl_slist *headers = nullptr;
  headers = curl_slist_append(headers, "Accept: application/json");
  headers = curl_slist_append(headers, "Content-Type: application/json");
  headers = curl_slist_append(headers, "charsets: utf-8");

  CURL *curl = curl_easy_init();
  std::string url = std::string(
      inet_ntoa(*((struct in_addr*) &smf_cfg.udm_addr.ipv4_addr))) + ":"
      + std::to_string(smf_cfg.udm_addr.port)
      + fmt::format(NUDM_SDM_GET_SM_DATA_URL, std::to_string(supi));
  Logger::smf_n10().debug("UDM's URL: %s ", url.c_str());

  if (curl) {
    CURLcode res = { };

    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, UDM_CURL_TIMEOUT_MS);
    curl_easy_setopt(curl, CURLOPT_INTERFACE, smf_cfg.sbi.if_name.c_str());

    // Response information.
    long httpCode = { 0 };
    std::unique_ptr<std::string> httpData(new std::string());

    // Hook up data handling function.
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, httpData.get());
    //curl_easy_setopt(curl, CURLOPT_WRITEDATA, httpData);
    int numRetries = 0;
    while (numRetries < UDM_NUMBER_RETRIES) {
      res = curl_easy_perform(curl);
      curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);
      Logger::smf_n10().debug("Response from UDM, HTTP Code: %d ", httpCode);

      if (static_cast<http_response_codes_e>(httpCode)
          == http_response_codes_e::HTTP_RESPONSE_CODE_OK) {
        Logger::smf_n10().debug("Got successful response from UDM, URL: %s ",
                                url.c_str());
        try {
          jsonData = nlohmann::json::parse(*httpData.get());
          //curl_easy_cleanup(curl);
          break;
        } catch (json::exception &e) {
          Logger::smf_n10().warn("Could not parse json data from UDM");
        }
        numRetries++;
      } else {
        Logger::smf_n10().warn(
            "Could not get response from UDM, URL %s, retry ...", url.c_str());
        //retry
        numRetries++;
      }
    }
    curl_easy_cleanup(curl);
  }

  //process the response
  if (!jsonData.empty()) {
    Logger::smf_n10().debug("Response from UDM %s", jsonData.dump().c_str());

    //retrieve SessionManagementSubscription and store in the context
    for (nlohmann::json::iterator it = jsonData["dnnConfigurations"].begin();
        it != jsonData["dnnConfigurations"].end(); ++it) {
      Logger::smf_n10().debug("DNN %s", it.key().c_str());
      try {
        std::shared_ptr<dnn_configuration_t> dnn_configuration =
            std::make_shared<dnn_configuration_t>();
        //PDU Session Type
        pdu_session_type_t pdu_session_type(
            pdu_session_type_e::PDU_SESSION_TYPE_E_IPV4);
        std::string default_session_type =
            it.value()["pduSessionTypes"]["defaultSessionType"];
        Logger::smf_n10().debug("Default session type %s",
                                default_session_type.c_str());
        if (default_session_type.compare("IPV4") == 0) {
          pdu_session_type.pdu_session_type =
              pdu_session_type_e::PDU_SESSION_TYPE_E_IPV4;
        } else if (default_session_type.compare("IPV6") == 0) {
          pdu_session_type.pdu_session_type =
              pdu_session_type_e::PDU_SESSION_TYPE_E_IPV6;
        } else if (default_session_type.compare("IPV4V6") == 0) {
          pdu_session_type.pdu_session_type =
              pdu_session_type_e::PDU_SESSION_TYPE_E_IPV4V6;
        }
        dnn_configuration->pdu_session_types.default_session_type =
            pdu_session_type;

        //Ssc_Mode
        ssc_mode_t ssc_mode(ssc_mode_e::SSC_MODE_1);
        std::string default_ssc_mode = it.value()["sscModes"]["defaultSscMode"];
        Logger::smf_n10().debug("Default SSC Mode %s",
                                default_ssc_mode.c_str());
        if (default_ssc_mode.compare("SSC_MODE_1") == 0) {
          dnn_configuration->ssc_modes.default_ssc_mode = ssc_mode_t(
              ssc_mode_e::SSC_MODE_1);
        } else if (default_ssc_mode.compare("SSC_MODE_2") == 0) {
          dnn_configuration->ssc_modes.default_ssc_mode = ssc_mode_t(
              ssc_mode_e::SSC_MODE_2);
        } else if (default_ssc_mode.compare("SSC_MODE_3") == 0) {
          dnn_configuration->ssc_modes.default_ssc_mode = ssc_mode_t(
              ssc_mode_e::SSC_MODE_3);
        }

        //5gQosProfile
        dnn_configuration->_5g_qos_profile._5qi =
            it.value()["5gQosProfile"]["5qi"];
        dnn_configuration->_5g_qos_profile.arp.priority_level =
            it.value()["5gQosProfile"]["arp"]["priorityLevel"];
        dnn_configuration->_5g_qos_profile.arp.preempt_cap =
            it.value()["5gQosProfile"]["arp"]["preemptCap"];
        dnn_configuration->_5g_qos_profile.arp.preempt_vuln =
            it.value()["5gQosProfile"]["arp"]["preemptVuln"];
        dnn_configuration->_5g_qos_profile.priority_level = 1;  //TODO: hardcoded

        //session_ambr
        dnn_configuration->session_ambr.uplink =
            it.value()["sessionAmbr"]["uplink"];
        dnn_configuration->session_ambr.downlink =
            it.value()["sessionAmbr"]["downlink"];
        Logger::smf_n10().debug(
            "Session AMBR Uplink %s, Downlink %s",
            dnn_configuration->session_ambr.uplink.c_str(),
            dnn_configuration->session_ambr.downlink.c_str());

        subscription->insert_dnn_configuration(it.key(), dnn_configuration);
      } catch (nlohmann::json::exception &e) {
        Logger::smf_n10().warn("Exception message %s, exception id %d ",
                               e.what(), e.id);
        return false;
      }
    }
    return true;
  } else {
    return false;
  }

}

//------------------------------------------------------------------------------
void smf_n10::subscribe_sm_data() {
  //TODO:
}

