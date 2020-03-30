/**
 * Nsmf_PDUSession
 * SMF PDU Session Service. © 2019, 3GPP Organizational Partners (ARIB, ATIS, CCSA, ETSI, TSDSI, TTA, TTC). All rights reserved.
 *
 * The version of the OpenAPI document: 1.1.0.alpha-1
 *
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */

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


#include "IndividualSMContextApi.h"
#include "logger.hpp"
#include "Helpers.h"
extern "C" {
#include "multipartparser.h"
}

#include <cassert>
#include <cstring>
#include <cstdio>
#include <iostream>
#include <list>
#include <map>
#include <string>


namespace oai {
namespace smf_server {
namespace api {

using namespace oai::smf_server::helpers;
using namespace oai::smf_server::model;

IndividualSMContextApi::IndividualSMContextApi(std::shared_ptr<Pistache::Rest::Router> rtr) { 
  router = rtr;
}

void IndividualSMContextApi::init() {
  setupRoutes();
}

void IndividualSMContextApi::setupRoutes() {
  using namespace Pistache::Rest;

  Routes::Post(*router, base + "/sm-contexts/:smContextRef/release", Routes::bind(&IndividualSMContextApi::release_sm_context_handler, this));
  Routes::Post(*router, base + "/sm-contexts/:smContextRef/retrieve", Routes::bind(&IndividualSMContextApi::retrieve_sm_context_handler, this));
  Routes::Post(*router, base + "/sm-contexts/:smContextRef/modify", Routes::bind(&IndividualSMContextApi::update_sm_context_handler, this));

  // Default handler, called when a route is not found
  router->addCustomHandler(Routes::bind(&IndividualSMContextApi::individual_sm_context_api_default_handler, this));
}

void IndividualSMContextApi::release_sm_context_handler(const Pistache::Rest::Request &request, Pistache::Http::ResponseWriter response) {

  //TODO: to be updated as update_sm_context_handler
  Logger::smf_api_server().info("Received a Nsmf_PDUSession_UpdateSMContext: PDU Session Release request from AMF");
  Logger::smf_api_server().debug("Request body: %s\n",request.body().c_str());
  SmContextReleaseMessage smContextReleaseMessage;

  // Getting the path params
  auto smContextRef = request.param(":smContextRef").as<std::string>();

  //step 1. use multipartparser to decode the request
  multipartparser_callbacks_init(&g_callbacks);
  g_callbacks.on_body_begin = &on_body_begin;
  g_callbacks.on_part_begin = &on_part_begin;
  g_callbacks.on_header_field = &on_header_field;
  g_callbacks.on_header_value = &on_header_value;
  g_callbacks.on_headers_complete = &on_headers_complete;
  g_callbacks.on_data = &on_data;
  g_callbacks.on_part_end = &on_part_end;
  g_callbacks.on_body_end = &on_body_end;

  multipartparser parser;
  init_globals();
  multipartparser_init(&parser, BOUNDARY);
  if ((multipartparser_execute(&parser, &g_callbacks, request.body().c_str(), strlen(request.body().c_str())) != strlen(request.body().c_str())) or (!g_body_begin_called)){
    response.send(Pistache::Http::Code::Bad_Request, "");
    return;
  }

  //at least 2 parts for Json data and N1/N2
  if (g_parts.size() < 2){
    response.send(Pistache::Http::Code::Bad_Request, "");
    return;
  }
  part p0 = g_parts.front(); g_parts.pop_front();
  Logger::smf_api_server().debug("Request body, part 1: \n%s", p0.body.c_str());
  part p1 = g_parts.front(); g_parts.pop_front();
  Logger::smf_api_server().debug("Request body, part 2: \n %s",p1.body.c_str());
  //part p2 = g_parts.front(); g_parts.pop_front();
  //Logger::smf_api_server().debug("Request body, part 3: \n %s",p2.body.c_str());

  // Getting the body param
  SmContextReleaseData smContextReleaseData;

  try {
    nlohmann::json::parse(p0.body.c_str()).get_to(smContextReleaseData);
    smContextReleaseMessage.setJsonData(smContextReleaseData);
    smContextReleaseMessage.setBinaryDataN2SmInformation(p1.body.c_str());
    this->release_sm_context(smContextRef, smContextReleaseMessage, response);

  } catch (nlohmann::detail::exception &e) {
    //send a 400 error
    response.send(Pistache::Http::Code::Bad_Request, e.what());
    return;
  } catch (std::exception &e) {
    //send a 500 error
    response.send(Pistache::Http::Code::Internal_Server_Error, e.what());
    return;
  }

}
void IndividualSMContextApi::retrieve_sm_context_handler(const Pistache::Rest::Request &request, Pistache::Http::ResponseWriter response) {
  // Getting the path params
  auto smContextRef = request.param(":smContextRef").as<std::string>();

  // Getting the body param

  SmContextRetrieveData smContextRetrieveData;

  try {
    nlohmann::json::parse(request.body()).get_to(smContextRetrieveData);
    this->retrieve_sm_context(smContextRef, smContextRetrieveData, response);
  } catch (nlohmann::detail::exception &e) {
    //send a 400 error
    response.send(Pistache::Http::Code::Bad_Request, e.what());
    return;
  } catch (std::exception &e) {
    //send a 500 error
    response.send(Pistache::Http::Code::Internal_Server_Error, e.what());
    return;
  }

}
void IndividualSMContextApi::update_sm_context_handler(const Pistache::Rest::Request &request, Pistache::Http::ResponseWriter response) {

  Logger::smf_api_server().info("Received a SM context update request from AMF");
  Logger::smf_api_server().debug("Request body: %s\n",request.body().c_str());

  //find boundary
  std::size_t found = request.body().find("Content-Type");
  std::string boundary_str = request.body().substr(2, found - 4);
  Logger::smf_api_server().debug("Boundary: %s", boundary_str.c_str());

  SmContextUpdateMessage smContextUpdateMessage;

  //step 1. use multipartparser to decode the request
  multipartparser_callbacks_init(&g_callbacks);
  g_callbacks.on_body_begin = &on_body_begin;
  g_callbacks.on_part_begin = &on_part_begin;
  g_callbacks.on_header_field = &on_header_field;
  g_callbacks.on_header_value = &on_header_value;
  g_callbacks.on_headers_complete = &on_headers_complete;
  g_callbacks.on_data = &on_data;
  g_callbacks.on_part_end = &on_part_end;
  g_callbacks.on_body_end = &on_body_end;

  multipartparser parser;
  init_globals();
  multipartparser_init(&parser, reinterpret_cast<const char*>(boundary_str.c_str()));

  unsigned int str_len = request.body().length();
  unsigned char *data = (unsigned char *)malloc(str_len + 1);
  memset(data,0,str_len + 1);
  memcpy ((void *)data, (void *)request.body().c_str(),str_len);

  //if ((multipartparser_execute(&parser, &g_callbacks, request.body().c_str(), strlen(request.body().c_str())) != strlen(request.body().c_str())) or (!g_body_begin_called)){
  if ((multipartparser_execute(&parser, &g_callbacks, reinterpret_cast<const char*>(data), str_len) != strlen(request.body().c_str())) or (!g_body_begin_called)){
    Logger::smf_api_server().warn("The received message can not be parsed properly!");
    //TODO: fix this issue
    //response.send(Pistache::Http::Code::Bad_Request, "");
    //return;
  }
  free(data);
  data = nullptr;

  uint8_t size = g_parts.size();

  Logger::smf_api_server().debug("Number of g_parts %d", g_parts.size());
  part p0 = g_parts.front(); g_parts.pop_front();
  Logger::smf_api_server().debug("Request body, part 1: %s", p0.body.c_str());
  part p1 = {};

  if (size > 1){
    p1 = g_parts.front(); g_parts.pop_front();
    Logger::smf_api_server().debug("Request body, part 2: %s (%d bytes)",p1.body.c_str(), p1.body.length());
    //part p2 = g_parts.front(); g_parts.pop_front();
    //Logger::smf_api_server().debug("Request body, part 3: \n %s",p2.body.c_str());
  }

  // Getting the body param
  SmContextUpdateData smContextUpdateData;
  try {
    nlohmann::json::parse(p0.body.c_str()).get_to(smContextUpdateData);
    smContextUpdateMessage.setJsonData(smContextUpdateData);

    if (size > 1){
      if (smContextUpdateData.n2SmInfoIsSet()){
        //N2 SM (for Session establishment, or for session modification)
        Logger::smf_api_server().debug("N2 SM information is set");
        smContextUpdateMessage.setBinaryDataN2SmInformation(p1.body);
      }
      if (smContextUpdateData.n1SmMsgIsSet()){
        //N1 SM (for session modification, UE-initiated)
        Logger::smf_api_server().debug("N1 SM message is set");
        smContextUpdateMessage.setBinaryDataN1SmMessage(p1.body.c_str());
      }
    }
    // Getting the path params
    auto smContextRef = request.param(":smContextRef").as<std::string>();
    this->update_sm_context(smContextRef, smContextUpdateMessage, response);

  } catch (nlohmann::detail::exception &e) {
    //send a 400 error
    Logger::smf_api_server().warn("Error in parsing json (error: %s), send a msg with a 400 error code to AMF", e.what());
    response.send(Pistache::Http::Code::Bad_Request, e.what());
    return;
  } catch (std::exception &e) {
    //send a 500 error
    Logger::smf_api_server().warn("Error (%s ), Send a msg with a 500 error code to AMF", e.what());
    response.send(Pistache::Http::Code::Internal_Server_Error, e.what());
    return;
  }
}

void IndividualSMContextApi::individual_sm_context_api_default_handler(const Pistache::Rest::Request &, Pistache::Http::ResponseWriter response) {
  response.send(Pistache::Http::Code::Not_Found, "The requested method does not exist");
}

}
}
}

