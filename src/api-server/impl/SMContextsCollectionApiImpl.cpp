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

#include "SMContextsCollectionApiImpl.h"
#include "logger.hpp"
#include "smf_msg.hpp"
#include "itti_msg_n11.hpp"
#include "3gpp_29.502.h"
#include <nghttp2/asio_http2_server.h>
#include "smf_config.hpp"

extern smf::smf_config smf_cfg;

namespace oai {
namespace smf_server {
namespace api {

using namespace oai::smf_server::model;

SMContextsCollectionApiImpl::SMContextsCollectionApiImpl(
    std::shared_ptr<Pistache::Rest::Router> rtr, smf::smf_app *smf_app_inst,
    std::string address)
    :
    SMContextsCollectionApi(rtr),
    m_smf_app(smf_app_inst),
    m_address(address) {
}

void SMContextsCollectionApiImpl::post_sm_contexts(
    const SmContextMessage &smContextMessage,
    Pistache::Http::ResponseWriter &response) {

  Logger::smf_api_server().info("PDU Session Create SM Context Request.");

  //Assign the necessary informations to smf::pdu_session_create_sm_context_request
  //and pass this message to SMF to handle this message
  //decode NAS should be done in SMF APP

  SmContextCreateData smContextCreateData = smContextMessage.getJsonData();
  std::string n1_sm_msg = smContextMessage.getBinaryDataN1SmMessage();
  Logger::smf_api_server().debug("N1 SM message: %s", n1_sm_msg.c_str());

  //Step 2. Create a pdu_session_create_sm_context_request message and store the necessary information
  Logger::smf_api_server().debug(
      "Create a pdu_session_create_sm_context_request message and store the necessary information");
  smf::pdu_session_create_sm_context_request sm_context_req_msg = { };

  //set N1 SM Message
  sm_context_req_msg.set_n1_sm_message(n1_sm_msg);
  //set api root to be used as location header in HTTP response
  sm_context_req_msg.set_api_root(m_address + base + smf_cfg.sbi_api_version + "/sm-contexts");

  //supi
  supi_t supi = { .length = 0 };
  std::size_t pos = smContextCreateData.getSupi().find("-");
  std::string supi_str = smContextCreateData.getSupi().substr(pos + 1);
  std::string supi_prefix = smContextCreateData.getSupi().substr(0, pos);
  smf_string_to_supi(&supi, supi_str.c_str());
  sm_context_req_msg.set_supi(supi);
  sm_context_req_msg.set_supi_prefix(supi_prefix);
  Logger::smf_api_server().debug("SUPI %s, SUPI Prefix %s, IMSI %s",
                                 smContextCreateData.getSupi().c_str(),
                                 supi_prefix.c_str(), supi_str.c_str());

  //dnn
  Logger::smf_api_server().debug("DNN %s",
                                 smContextCreateData.getDnn().c_str());
  sm_context_req_msg.set_dnn(smContextCreateData.getDnn().c_str());

  //S-Nssai
  Logger::smf_api_server().debug(
      "S-NSSAI SST %d, SD %s", smContextCreateData.getSNssai().getSst(),
      smContextCreateData.getSNssai().getSd().c_str());
  snssai_t snssai(smContextCreateData.getSNssai().getSst(),
                  smContextCreateData.getSNssai().getSd());
  sm_context_req_msg.set_snssai(snssai);

  //PDU session ID
  Logger::smf_api_server().debug("PDU Session ID %d",
                                 smContextCreateData.getPduSessionId());
  sm_context_req_msg.set_pdu_session_id(smContextCreateData.getPduSessionId());

  //AMF ID (ServingNFId)
  Logger::smf_api_server().debug("ServingNfId %s",
                                 smContextCreateData.getServingNfId().c_str());
  sm_context_req_msg.set_serving_nf_id(
      smContextCreateData.getServingNfId().c_str());  //TODO: should be verified that AMF ID is stored in GUAMI or ServingNfId

  //Request Type
  Logger::smf_api_server().debug("RequestType %s",
                                 smContextCreateData.getRequestType().c_str());
  sm_context_req_msg.set_request_type(smContextCreateData.getRequestType());
  //PCF ID
  // Priority Access
  //User Location Information
  //Access Type
  // PEI
  // GPSI
  // UE presence in LADN service area
  //Guami
  //servingNetwork
  //anType
  //UETimeZone
  //SMContextStatusUri
  //PCFId

  // DNN Selection Mode
  Logger::smf_api_server().debug("SelMode %s",
                                 smContextCreateData.getSelMode().c_str());
  sm_context_req_msg.set_dnn_selection_mode(
      smContextCreateData.getSelMode().c_str());

  //Subscription for PDU Session Status Notification
  // Trace requirement

  //SSC mode (Optional)
  //5GSM capability (Optional)
  //Maximum number of supported (Optional)
  //Maximum number of supported packet filters (Optional)
  //Always-on PDU session requested (Optional)
  //SM PDU DN request container (Optional)
  //Extended protocol configuration options (Optional) e.g, FOR DHCP

  boost::shared_ptr<boost::promise<smf::pdu_session_create_sm_context_response> > p =
      boost::make_shared<
          boost::promise<smf::pdu_session_create_sm_context_response> >();
  boost::shared_future<smf::pdu_session_create_sm_context_response> f;
  f = p->get_future();

  //Generate ID for this promise (to be used in SMF-APP)
  uint32_t promise_id = generate_promise_id();
  Logger::smf_api_server().debug("Promise ID generated %d", promise_id);
  m_smf_app->add_promise(promise_id, p);

  //Step 3. Handle the pdu_session_create_sm_context_request message in smf_app
  std::shared_ptr<itti_n11_create_sm_context_request> itti_msg =
      std::make_shared<itti_n11_create_sm_context_request>(TASK_SMF_N11,
                                                           TASK_SMF_APP,
                                                           promise_id);
  itti_msg->req = sm_context_req_msg;
  itti_msg->http_version = 1;
  m_smf_app->handle_pdu_session_create_sm_context_request(itti_msg);

  //wait for the result from APP and send reply to AMF
  smf::pdu_session_create_sm_context_response sm_context_response = f.get();
  Logger::smf_api_server().debug("Got result for promise ID %d", promise_id);

  nlohmann::json json_data = { };

  response.headers().add < Pistache::Http::Header::Location
      > (sm_context_response.get_smf_context_uri());  //Location header
  sm_context_response.get_json_data(json_data);
  if (!json_data.empty()) {
    response.headers().add < Pistache::Http::Header::ContentType
        > (Pistache::Http::Mime::MediaType("application/json"));
    response.send(Pistache::Http::Code(sm_context_response.get_http_code()),
                  json_data.dump().c_str());
  } else {
    response.send(Pistache::Http::Code(sm_context_response.get_http_code()));
  }
}
}
}
}
