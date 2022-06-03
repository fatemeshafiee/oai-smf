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

/*! \file smf_n7.cpp
 \author  Stefan Spettel
 \company Openairinterface Software Alliance
 \date 2022
 \email: stefan.spettel@eurecom.fr
 */

#include "smf_n7.hpp"
#include "smf_config.hpp"
#include "fqdn.hpp"
#include "smf_sbi.hpp"
#include "nlohmann/json.hpp"
#include "3gpp_29.500.h"
#include "ProblemDetails.h"

using namespace smf;
using namespace smf::n7;
using namespace oai::smf_server::model;

extern smf_config smf_cfg;
extern smf_sbi* smf_sbi_inst;

sm_policy_status_code smf_n7::create_sm_policy_association(
    const std::string pcf_addr, const std::string pcf_api_version,
    const oai::smf_server::model::SmPolicyContextData& context,
    oai::smf_server::model::SmPolicyDecision& policy_decision) {
  // TODO abstraction: Here we should choose between local PCC rules and PCF
  // client

  return policy_api_client.send_create_policy_association(
      pcf_addr, pcf_api_version, context, policy_decision);
}

bool smf_n7::discover_pcf(
    std::string& addr, std::string& api_version, const Snssai snssai,
    const PlmnId plmn_id, const std::string dnn) {
  if (smf_cfg.use_local_pcc_rules) {
    Logger::smf_n7().info("Local PCC rules are enabled, do not discover PCF");
    return false;
  }

  if (smf_cfg.discover_pcf) {
    return discover_pcf_with_nrf(addr, api_version, snssai, plmn_id, dnn);
  } else {
    return discover_pcf_from_config_file(
        addr, api_version, snssai, plmn_id, dnn);
  }
}

bool smf_n7::discover_pcf_with_nrf(
    std::string& addr, std::string& api_version, const Snssai snssai,
    const PlmnId plmn_id, const std::string dnn) {
  Logger::smf_n7().debug("Discover PCF with NRF");
  Logger::smf_n7().warn("NRF discovery not yet supported!");
  return false;
}

bool smf_n7::discover_pcf_from_config_file(
    std::string& addr, std::string& api_version, const Snssai snssai,
    const PlmnId plmn_id, const std::string dnn) {
  // TODO ignore snssai, plmn_id and dnn, because it is not part of
  // configuration
  Logger::smf_n7().debug("Discover PCF from config file");
  api_version = smf_cfg.pcf_addr.api_version;
  if (!smf_cfg.use_fqdn_dns) {
    // read config from config file
    addr = std::string(
        inet_ntoa(*((struct in_addr*) &smf_cfg.pcf_addr.ipv4_addr)));
    addr += ":" + std::to_string(smf_cfg.pcf_addr.port);
    return true;
  } else {
    Logger::smf_n7().debug(
        "Resolving %s with DNS", smf_cfg.pcf_addr.fqdn.c_str());
    // resolve IP address
    uint8_t addr_type     = 0;
    uint32_t pcf_port     = 0;
    std::string addr_temp = "";
    if (!fqdn::resolve(smf_cfg.fqdn, addr_temp, pcf_port, addr_type)) {
      Logger::smf_n7().warn("Could not resolve FQDN %s", smf_cfg.fqdn.c_str());
      return false;
    }

    if (addr_type != 0) {
      // TODO IPv6
      Logger::smf_n7().warn("IPv6 not supported for PCF address");
      return false;
    } else {
      if (smf_cfg.http_version == 2) {
        pcf_port = 8080;  // TODO this is not good to hardcode it here.
        // Shouldnt we be able to get this from the DNS query based on the
        // service?
      }
      addr = addr_temp + ":" + std::to_string(pcf_port);
      return true;
    }
  }
}
smf_n7::~smf_n7() {
  Logger::smf_n7().info("Deleting SMF N7 instance...");
}

///////////////////////////////////////////////////////////////////////////
/////////////////////// smf_pcf_client ////////////////////////////////////
///////////////////////////////////////////////////////////////////////////

sm_policy_status_code smf_pcf_client::send_create_policy_association(
    const std::string pcf_addr, const std::string pcf_api_version,
    const SmPolicyContextData& context, SmPolicyDecision& policy_decision) {
  nlohmann::json json_data;
  to_json(json_data, context);

  Logger::smf_n7().info("Sending PCF SM policy association creation request");

  std::string url = "http://" + pcf_addr + "/" + sm_api_name + "/" +
                    pcf_api_version + "/" + sm_api_policy_resource_part;

  std::string response_data;

  // generate a promise for the curl handle
  uint32_t promise_id = smf_sbi_inst->generate_promise_id();

  Logger::smf_sbi().debug("Promise ID generated %d", promise_id);
  uint32_t* pid_ptr = &promise_id;
  boost::shared_ptr<boost::promise<uint32_t>> p =
      boost::make_shared<boost::promise<uint32_t>>();
  boost::shared_future<uint32_t> f;
  f = p->get_future();
  smf_sbi_inst->add_promise(promise_id, p);

  // Create a new curl easy handle and add to the multi handle
  if (!smf_sbi_inst->curl_create_handle(
          url, json_data.dump(), response_data, pid_ptr, "POST",
          smf_cfg.http_version)) {
    Logger::smf_sbi().warn(
        "Could not create a new handle to send message to PCF");
    smf_sbi_inst->remove_promise(promise_id);
    return sm_policy_status_code::INTERNAL_ERROR;
  }

  // Wait for the response
  // TODO what happens if PCF is not reachable? Should check that scenario
  // TODO it seems that it just hangs and is stuck "forever".. The problem is
  // that the CURL ERROR CODE in curl_release_handles are just ignored. e.g when
  // I have an error code 28, does that mean that this thread is just stuck?

  uint32_t response_code = smf_sbi_inst->get_available_response(f);

  Logger::smf_sbi().debug("Got result for promise ID %d", promise_id);
  Logger::smf_sbi().debug("Response data %s", response_data.c_str());

  if (response_code == http_status_code_e::HTTP_STATUS_CODE_201_CREATED) {
    from_json(response_data, policy_decision);
    Logger::smf_n7().info(
        "Successfully created SM Policy Association for SUPI %s",
        context.getSupi().c_str());
    return sm_policy_status_code::CREATED;
  }

  // failure case
  ProblemDetails problem_details;
  from_json(response_data, problem_details);

  std::string info = "";
  sm_policy_status_code response;
  switch (response_code) {
    case http_status_code_e::HTTP_STATUS_CODE_403_FORBIDDEN:
      info     = "SM Policy Association Creation Forbidden";
      response = sm_policy_status_code::CONTEXT_DENIED;
      break;
    case http_status_code_e::HTTP_STATUS_CODE_400_BAD_REQUEST:
      if (problem_details.getCause() == "USER_UNKNOWN") {
        response = sm_policy_status_code::USER_UNKOWN;
        info     = "SM Policy Association Creation: Unknown User";
      } else {
        response = sm_policy_status_code::INVALID_PARAMETERS;
        info     = "SM Policy Association Creation: Bad Request";
      }
      break;
    case http_status_code_e::HTTP_STATUS_CODE_500_INTERNAL_SERVER_ERROR:
      response = sm_policy_status_code::INTERNAL_ERROR;
      info     = "SM Policy Association Creation: Internal Error";
      break;
    default:
      response = sm_policy_status_code::INTERNAL_ERROR;
      info =
          "SM Policy Association Creation: Unknown Error Code from "
          "PCF: " +
          response_code;
  }

  Logger::smf_n7().warn(
      "%s -- Details: %s - %s", info.c_str(),
      problem_details.getCause().c_str(), problem_details.getDetail().c_str());
  return response;
}