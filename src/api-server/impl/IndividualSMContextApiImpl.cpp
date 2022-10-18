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

#include "IndividualSMContextApiImpl.h"
#include <nghttp2/asio_http2_server.h>
#include "mime_parser.hpp"
#include "3gpp_conversions.hpp"

namespace oai {
namespace smf_server {
namespace api {

using namespace oai::smf_server::model;

IndividualSMContextApiImpl::IndividualSMContextApiImpl(
    std::shared_ptr<Pistache::Rest::Router> rtr, smf::smf_app* smf_app_inst,
    std::string address)
    : IndividualSMContextApi(rtr),
      m_smf_app(smf_app_inst),
      m_address(address) {}

void IndividualSMContextApiImpl::release_sm_context(
    const std::string& smContextRef,
    const SmContextReleaseMessage& smContextReleaseMessage,
    Pistache::Http::ResponseWriter& response) {
  // Get the SmContextReleaseData from this message and process in smf_app
  Logger::smf_api_server().info(
      "Received a PDUSession_ReleaseSMContext Request from AMF.");

  smf::pdu_session_release_sm_context_request sm_context_req_msg = {};

  // convert from SmContextReleaseMessage to
  // pdu_session_release_sm_context_request
  xgpp_conv::sm_context_release_from_openapi(
      smContextReleaseMessage, sm_context_req_msg);

  boost::shared_ptr<
      boost::promise<smf::pdu_session_release_sm_context_response> >
      p = boost::make_shared<
          boost::promise<smf::pdu_session_release_sm_context_response> >();
  boost::shared_future<smf::pdu_session_release_sm_context_response> f;
  f = p->get_future();

  // Generate ID for this promise (to be used in SMF-APP)
  uint32_t promise_id = generate_promise_id();
  Logger::smf_api_server().debug("Promise ID generated %d", promise_id);
  m_smf_app->add_promise(promise_id, p);

  // Handle the itti_n11_release_sm_context_request message in smf_app
  std::shared_ptr<itti_n11_release_sm_context_request> itti_msg =
      std::make_shared<itti_n11_release_sm_context_request>(
          TASK_SMF_SBI, TASK_SMF_APP, promise_id, smContextRef);
  itti_msg->req          = sm_context_req_msg;
  itti_msg->http_version = 1;
  m_smf_app->handle_pdu_session_release_sm_context_request(itti_msg);

  boost::future_status status;
  // wait for timeout or ready
  status = f.wait_for(boost::chrono::milliseconds(FUTURE_STATUS_TIMEOUT_MS));
  if (status == boost::future_status::ready) {
    assert(f.is_ready());
    assert(f.has_value());
    assert(!f.has_exception());
    // Wait for the result from APP and send reply to NF consumer (e.g., AMF)
    smf::pdu_session_release_sm_context_response sm_context_response = f.get();
    Logger::smf_api_server().debug("Got result for promise ID %d", promise_id);

    // TODO: Process the response
    response.send(Pistache::Http::Code(sm_context_response.get_http_code()));
  } else {
    response.send(Pistache::Http::Code::Request_Timeout);
  }
}

void IndividualSMContextApiImpl::retrieve_sm_context(
    const std::string& smContextRef,
    const SmContextRetrieveData& smContextRetrieveData,
    Pistache::Http::ResponseWriter& response) {
  Logger::smf_api_server().info("retrieve_sm_context...");
  response.send(
      Pistache::Http::Code::Not_Implemented,
      "Retrieve_sm_context API has not been implemented yet!\n");
}

void IndividualSMContextApiImpl::update_sm_context(
    const std::string& smContextRef,
    const SmContextUpdateMessage& smContextUpdateMessage,
    Pistache::Http::ResponseWriter& response) {
  // Get the SmContextUpdateData from this message and process in smf_app
  Logger::smf_api_server().info(
      "Received a PDUSession_UpdateSMContext Request from AMF.");

  smf::pdu_session_update_sm_context_request sm_context_req_msg = {};

  // convert from SmContextUpdateMessage to
  // pdu_session_update_sm_context_request
  xgpp_conv::sm_context_update_from_openapi(
      smContextUpdateMessage, sm_context_req_msg);

  boost::shared_ptr<
      boost::promise<smf::pdu_session_update_sm_context_response> >
      p = boost::make_shared<
          boost::promise<smf::pdu_session_update_sm_context_response> >();
  boost::shared_future<smf::pdu_session_update_sm_context_response> f;
  f = p->get_future();

  // Generate ID for this promise (to be used in SMF-APP)
  uint32_t promise_id = generate_promise_id();
  Logger::smf_api_server().debug("Promise ID generated %d", promise_id);
  m_smf_app->add_promise(promise_id, p);

  // Handle the itti_n11_update_sm_context_request message in smf_app
  std::shared_ptr<itti_n11_update_sm_context_request> itti_msg =
      std::make_shared<itti_n11_update_sm_context_request>(
          TASK_SMF_SBI, TASK_SMF_APP, promise_id, smContextRef);
  itti_msg->req          = sm_context_req_msg;
  itti_msg->http_version = 1;
  m_smf_app->handle_pdu_session_update_sm_context_request(itti_msg);

  boost::future_status status;
  // wait for timeout or ready
  status = f.wait_for(boost::chrono::milliseconds(FUTURE_STATUS_TIMEOUT_MS));
  if (status == boost::future_status::ready) {
    assert(f.is_ready());
    assert(f.has_value());
    assert(!f.has_exception());
    // Wait for the result from APP and send reply to NF consumer (e.g., AMF)
    smf::pdu_session_update_sm_context_response sm_context_response = f.get();
    Logger::smf_api_server().debug("Got result for promise ID %d", promise_id);

    nlohmann::json json_data = {};
    std::string body         = {};
    std::string json_format;

    sm_context_response.get_json_format(json_format);
    sm_context_response.get_json_data(json_data);
    Logger::smf_api_server().debug("Json data %s", json_data.dump().c_str());

    if (sm_context_response.n1_sm_msg_is_set() and
        sm_context_response.n2_sm_info_is_set()) {
      mime_parser::create_multipart_related_content(
          body, json_data.dump(), CURL_MIME_BOUNDARY,
          sm_context_response.get_n1_sm_message(),
          sm_context_response.get_n2_sm_information(), json_format);
      response.headers().add<Pistache::Http::Header::ContentType>(
          Pistache::Http::Mime::MediaType(
              "multipart/related; boundary=" +
              std::string(CURL_MIME_BOUNDARY)));
    } else if (sm_context_response.n1_sm_msg_is_set()) {
      mime_parser::create_multipart_related_content(
          body, json_data.dump(), CURL_MIME_BOUNDARY,
          sm_context_response.get_n1_sm_message(),
          multipart_related_content_part_e::NAS, json_format);
      response.headers().add<Pistache::Http::Header::ContentType>(
          Pistache::Http::Mime::MediaType(
              "multipart/related; boundary=" +
              std::string(CURL_MIME_BOUNDARY)));
    } else if (sm_context_response.n2_sm_info_is_set()) {
      mime_parser::create_multipart_related_content(
          body, json_data.dump(), CURL_MIME_BOUNDARY,
          sm_context_response.get_n2_sm_information(),
          multipart_related_content_part_e::NGAP, json_format);
      response.headers().add<Pistache::Http::Header::ContentType>(
          Pistache::Http::Mime::MediaType(
              "multipart/related; boundary=" +
              std::string(CURL_MIME_BOUNDARY)));
    } else if (json_data.size() > 0) {
      response.headers().add<Pistache::Http::Header::ContentType>(
          Pistache::Http::Mime::MediaType(json_format));
      body = json_data.dump().c_str();
    } else {
      response.send(Pistache::Http::Code(sm_context_response.get_http_code()));
      return;
    }

    response.send(
        Pistache::Http::Code(sm_context_response.get_http_code()), body);
  } else {
    response.send(Pistache::Http::Code::Request_Timeout);
  }
}
}  // namespace api
}  // namespace smf_server
}  // namespace oai
