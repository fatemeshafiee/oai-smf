/**
 * Nsmf_PDUSession
 * SMF PDU Session Service. © 2019, 3GPP Organizational Partners (ARIB, ATIS,
 * CCSA, ETSI, TSDSI, TTA, TTC). All rights reserved.
 *
 * The version of the OpenAPI document: 1.1.0.alpha-1
 *
 *
 * NOTE: This class is auto generated by OpenAPI Generator
 * (https://openapi-generator.tech). https://openapi-generator.tech Do not edit
 * the class manually.
 */

/*
 * Licensed to the OpenAirInterface (OAI) Software Alliance under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The OpenAirInterface Software Alliance licenses this file to You under
 * the OAI Public License, Version 1.1  (the "License"); you may not use this
 *file except in compliance with the License. You may obtain a copy of the
 *License at
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

#include "IndividualSMContextApi.h"

#include <cassert>
#include <cstring>
#include <cstdio>
#include <iostream>
#include <list>
#include <map>
#include <string>

#include "logger.hpp"
#include "Helpers.h"
#include "mime_parser.hpp"
#include "smf_config.hpp"

extern std::unique_ptr<oai::config::smf::smf_config> smf_cfg;

namespace oai {
namespace smf_server {
namespace api {

using namespace oai::smf_server::helpers;
using namespace oai::smf_server::model;

IndividualSMContextApi::IndividualSMContextApi(
    std::shared_ptr<Pistache::Rest::Router> rtr) {
  router = rtr;
}

void IndividualSMContextApi::init() {
  setupRoutes();
}

void IndividualSMContextApi::setupRoutes() {
  using namespace Pistache::Rest;

  Routes::Post(
      *router,
      base + smf_cfg->sbi_api_version + "/sm-contexts/:smContextRef/release",
      Routes::bind(&IndividualSMContextApi::release_sm_context_handler, this));
  Routes::Post(
      *router,
      base + smf_cfg->sbi_api_version + "/sm-contexts/:smContextRef/retrieve",
      Routes::bind(&IndividualSMContextApi::retrieve_sm_context_handler, this));
  Routes::Post(
      *router,
      base + smf_cfg->sbi_api_version + "/sm-contexts/:smContextRef/modify",
      Routes::bind(&IndividualSMContextApi::update_sm_context_handler, this));

  // Default handler, called when a route is not found
  router->addCustomHandler(Routes::bind(
      &IndividualSMContextApi::individual_sm_context_api_default_handler,
      this));
}

void IndividualSMContextApi::release_sm_context_handler(
    const Pistache::Rest::Request& request,
    Pistache::Http::ResponseWriter response) {
  Logger::smf_api_server().debug("");
  Logger::smf_api_server().info(
      "Received a SM context Release request from AMF.");
  Logger::smf_api_server().debug("Request body: %s\n", request.body().c_str());
  SmContextReleaseMessage smContextReleaseMessage = {};

  // Simple parser
  mime_parser sp = {};
  if (!sp.parse(request.body())) {
    response.send(Pistache::Http::Code::Bad_Request);
    return;
  }

  std::vector<mime_part> parts = {};
  sp.get_mime_parts(parts);
  uint8_t size = parts.size();
  Logger::smf_api_server().debug("Number of MIME parts %d", size);

  // Getting the body param
  SmContextReleaseData smContextReleaseData = {};

  try {
    if (size > 0) {
      nlohmann::json::parse(parts[0].body.c_str()).get_to(smContextReleaseData);
    } else {
      nlohmann::json::parse(request.body().c_str())
          .get_to(smContextReleaseData);
    }

    smContextReleaseMessage.setJsonData(smContextReleaseData);

    for (int i = 1; i < size; i++) {
      if (parts[i].content_type.compare("application/vnd.3gpp.ngap") == 0) {
        smContextReleaseMessage.setBinaryDataN2SmInformation(parts[i].body);
        Logger::smf_api_server().debug("N2 SM information is set");
      }
    }

    // Getting the path params
    auto smContextRef = request.param(":smContextRef").as<std::string>();
    this->release_sm_context(smContextRef, smContextReleaseMessage, response);

  } catch (nlohmann::detail::exception& e) {
    // send a 400 error
    Logger::smf_api_server().warn(
        "Error in parsing json (error: %s), send a msg with a 400 error code "
        "to AMF",
        e.what());
    response.send(Pistache::Http::Code::Bad_Request, e.what());
    return;
  } catch (std::exception& e) {
    // send a 500 error
    Logger::smf_api_server().warn(
        "Error (%s ), send a msg with a 500 error code to AMF", e.what());
    response.send(Pistache::Http::Code::Internal_Server_Error, e.what());
    return;
  }
}

void IndividualSMContextApi::retrieve_sm_context_handler(
    const Pistache::Rest::Request& request,
    Pistache::Http::ResponseWriter response) {
  // Getting the path params
  auto smContextRef = request.param(":smContextRef").as<std::string>();

  // Getting the body param

  SmContextRetrieveData smContextRetrieveData = {};

  try {
    nlohmann::json::parse(request.body()).get_to(smContextRetrieveData);
    this->retrieve_sm_context(smContextRef, smContextRetrieveData, response);
  } catch (nlohmann::detail::exception& e) {
    // send a 400 error
    response.send(Pistache::Http::Code::Bad_Request, e.what());
    return;
  } catch (std::exception& e) {
    // send a 500 error
    response.send(Pistache::Http::Code::Internal_Server_Error, e.what());
    return;
  }
}
void IndividualSMContextApi::update_sm_context_handler(
    const Pistache::Rest::Request& request,
    Pistache::Http::ResponseWriter response) {
  Logger::smf_api_server().debug("");
  Logger::smf_api_server().info(
      "Received a SM context update request from AMF.");
  Logger::smf_api_server().debug("Request body: %s\n", request.body().c_str());
  SmContextUpdateMessage smContextUpdateMessage = {};

  // Simple parser
  mime_parser sp = {};
  if (!sp.parse(request.body())) {
    response.send(Pistache::Http::Code::Bad_Request);
    return;
  }

  std::vector<mime_part> parts = {};
  sp.get_mime_parts(parts);
  uint8_t size = parts.size();
  Logger::smf_api_server().debug("Number of MIME parts %d", size);

  // Getting the body param
  SmContextUpdateData smContextUpdateData = {};
  try {
    if (size > 0) {
      nlohmann::json::parse(parts[0].body.c_str()).get_to(smContextUpdateData);
    } else {
      nlohmann::json::parse(request.body().c_str()).get_to(smContextUpdateData);
    }

    smContextUpdateMessage.setJsonData(smContextUpdateData);

    for (int i = 1; i < size; i++) {
      if (parts[i].content_type.compare("application/vnd.3gpp.5gnas") == 0) {
        smContextUpdateMessage.setBinaryDataN1SmMessage(parts[i].body);
        Logger::smf_api_server().debug("N1 SM message is set");
      } else if (
          parts[i].content_type.compare("application/vnd.3gpp.ngap") == 0) {
        smContextUpdateMessage.setBinaryDataN2SmInformation(parts[i].body);
        Logger::smf_api_server().debug("N2 SM information is set");
      }
    }

    // Getting the path params
    auto smContextRef = request.param(":smContextRef").as<std::string>();
    this->update_sm_context(smContextRef, smContextUpdateMessage, response);

  } catch (nlohmann::detail::exception& e) {
    // send a 400 error
    Logger::smf_api_server().warn(
        "Error in parsing json (error: %s), send a msg with a 400 error code "
        "to AMF",
        e.what());
    response.send(Pistache::Http::Code::Bad_Request, e.what());
    return;
  } catch (std::exception& e) {
    // send a 500 error
    Logger::smf_api_server().warn(
        "Error (%s ), send a msg with a 500 error code to AMF", e.what());
    response.send(Pistache::Http::Code::Internal_Server_Error, e.what());
    return;
  }
}

void IndividualSMContextApi::individual_sm_context_api_default_handler(
    const Pistache::Rest::Request&, Pistache::Http::ResponseWriter response) {
  response.send(
      Pistache::Http::Code::Not_Found, "The requested method does not exist");
}

}  // namespace api
}  // namespace smf_server
}  // namespace oai
