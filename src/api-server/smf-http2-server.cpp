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

/*! \file smf_http2-server.cpp
 \brief
 \author  Tien-Thinh NGUYEN
 \company Eurecom
 \date 2020
 \email: tien-thinh.nguyen@eurecom.fr
 */

#include "smf-http2-server.h"
#include <string>
#include <boost/algorithm/string.hpp>
#include <boost/thread.hpp>
#include <boost/thread/future.hpp>
#include <nlohmann/json.hpp>

#include "logger.hpp"
#include "smf_msg.hpp"
#include "itti_msg_n11.hpp"
#include "3gpp_29.502.h"
#include "mime_parser.hpp"
#include "3gpp_29.500.h"
#include "smf_config.hpp"
#include "smf.h"

using namespace nghttp2::asio_http2;
using namespace nghttp2::asio_http2::server;
using namespace oai::smf_server::model;

extern smf::smf_config smf_cfg;

//------------------------------------------------------------------------------
void smf_http2_server::start() {
  boost::system::error_code ec;

  Logger::smf_api_server().info("HTTP2 server started");
  // Create SM Context Request
  server.handle(
      NSMF_PDU_SESSION_BASE + smf_cfg.sbi_api_version +
          NSMF_PDU_SESSION_SM_CONTEXT_CREATE_URL,
      [&](const request& request, const response& response) {
        request.on_data([&](const uint8_t* data, std::size_t len) {
          if (len > 0) {
            std::string msg((char*) data, len);
            Logger::smf_api_server().debug("");
            Logger::smf_api_server().info(
                "Received a SM context create request from AMF.");
            Logger::smf_api_server().debug(
                "Message content \n %s", msg.c_str());
            // check HTTP method manually
            if (request.method().compare("POST") != 0) {
              // error
              Logger::smf_api_server().debug(
                  "This method (%s) is not supported",
                  request.method().c_str());
              response.write_head(
                  http_status_code_e::HTTP_STATUS_CODE_405_METHOD_NOT_ALLOWED);
              response.end();
              return;
            }

            SmContextMessage smContextMessage       = {};
            SmContextCreateData smContextCreateData = {};

            // simple parser
            mime_parser sp = {};
            sp.parse(msg);

            std::vector<mime_part> parts = {};
            sp.get_mime_parts(parts);
            uint8_t size = parts.size();
            Logger::smf_api_server().debug("Number of MIME parts %d", size);
            // at least 2 parts for Json data and N1 (+ N2)
            if (size < 2) {
              // send reply!!!
              response.write_head(
                  http_status_code_e::HTTP_STATUS_CODE_400_BAD_REQUEST);
              response.end();
              return;
            }

            // step 2. process the request
            try {
              nlohmann::json::parse(parts[0].body.c_str())
                  .get_to(smContextCreateData);
              smContextMessage.setJsonData(smContextCreateData);
              if (parts[1].content_type.compare("application/vnd.3gpp.5gnas") ==
                  0) {
                smContextMessage.setBinaryDataN1SmMessage(parts[1].body);
              } else if (
                  parts[1].content_type.compare("application/vnd.3gpp.ngap") ==
                  0) {
                smContextMessage.setBinaryDataN2SmInformation(parts[1].body);
              }
              // process the request
              this->create_sm_contexts_handler(smContextMessage, response);
            } catch (nlohmann::detail::exception& e) {
              Logger::smf_api_server().warn(
                  "Can not parse the json data (error: %s)!", e.what());
              response.write_head(
                  http_status_code_e::HTTP_STATUS_CODE_400_BAD_REQUEST);
              response.end();
              return;
            } catch (std::exception& e) {
              Logger::smf_api_server().warn("Error: %s!", e.what());
              response.write_head(
                  http_status_code_e::
                      HTTP_STATUS_CODE_500_INTERNAL_SERVER_ERROR);
              response.end();
              return;
            }
          }
        });
      });

  // Update SM Context Request
  server.handle(
      NSMF_PDU_SESSION_BASE + smf_cfg.sbi_api_version +
          NSMF_PDU_SESSION_SM_CONTEXT_UPDATE_URL,
      [&](const request& request, const response& response) {
        request.on_data([&](const uint8_t* data, std::size_t len) {
          if (len > 0) {
            std::string msg((char*) data, len);
            Logger::smf_api_server().debug("");
            Logger::smf_api_server().info(
                "Received a SM context update request from AMF.");
            Logger::smf_api_server().debug(
                "Message content \n %s", msg.c_str());

            // Get the smf reference context and method
            std::vector<std::string> split_result;
            boost::split(
                split_result, request.uri().path, boost::is_any_of("/"));
            if (split_result.size() != 6) {
              Logger::smf_api_server().warn("Requested URL is not implemented");
              response.write_head(
                  http_status_code_e::HTTP_STATUS_CODE_501_NOT_IMPLEMENTED);
              response.end();
              return;
            }

            std::string smf_ref = split_result[split_result.size() - 2];
            std::string method  = split_result[split_result.size() - 1];
            Logger::smf_api_server().info(
                "smf_ref %s, method %s",
                split_result[split_result.size() - 2].c_str(),
                split_result[split_result.size() - 1].c_str());

            if (method.compare("modify") == 0) {  // Update SM Context Request
              Logger::smf_api_server().info(
                  "Handle Update SM Context Request from AMF");

              SmContextUpdateMessage smContextUpdateMessage = {};
              SmContextUpdateData smContextUpdateData       = {};

              // simple parser
              mime_parser sp = {};
              sp.parse(msg);

              std::vector<mime_part> parts = {};
              sp.get_mime_parts(parts);
              uint8_t size = parts.size();
              Logger::smf_api_server().debug("Number of MIME parts %d", size);

              try {
                if (size > 0) {
                  nlohmann::json::parse(parts[0].body.c_str())
                      .get_to(smContextUpdateData);
                } else {
                  nlohmann::json::parse(msg.c_str())
                      .get_to(smContextUpdateData);
                }
                smContextUpdateMessage.setJsonData(smContextUpdateData);

                for (int i = 1; i < size; i++) {
                  if (parts[i].content_type.compare(
                          "application/vnd.3gpp.5gnas") == 0) {
                    smContextUpdateMessage.setBinaryDataN1SmMessage(
                        parts[i].body);
                    Logger::smf_api_server().debug("N1 SM message is set");
                  } else if (
                      parts[i].content_type.compare(
                          "application/vnd.3gpp.ngap") == 0) {
                    smContextUpdateMessage.setBinaryDataN2SmInformation(
                        parts[i].body);
                    Logger::smf_api_server().debug("N2 SM information is set");
                  }
                }
                this->update_sm_context_handler(
                    smf_ref, smContextUpdateMessage, response);

              } catch (nlohmann::detail::exception& e) {
                Logger::smf_api_server().warn(
                    "Can not parse the json data (error: %s)!", e.what());
                response.write_head(
                    http_status_code_e::HTTP_STATUS_CODE_400_BAD_REQUEST);
                response.end();
                return;
              } catch (std::exception& e) {
                Logger::smf_api_server().warn("Error: %s!", e.what());
                response.write_head(
                    http_status_code_e::
                        HTTP_STATUS_CODE_500_INTERNAL_SERVER_ERROR);
                response.end();
                return;
              }

            } else if (method.compare("release") == 0) {  // smContextReleaseData
              Logger::smf_api_server().info(
                  "Handle Release SM Context Request from AMF");

              SmContextReleaseData smContextReleaseData = {};
              try {
                nlohmann::json::parse(msg.c_str()).get_to(smContextReleaseData);
                this->release_sm_context_handler(
                    smf_ref, smContextReleaseData, response);

              } catch (nlohmann::detail::exception& e) {
                Logger::smf_api_server().warn(
                    "Can not parse the json data (error: %s)!", e.what());
                response.write_head(
                    http_status_code_e::HTTP_STATUS_CODE_400_BAD_REQUEST);
                response.end();
                return;
              } catch (std::exception& e) {
                Logger::smf_api_server().warn("Error: %s!", e.what());
                response.write_head(
                    http_status_code_e::
                        HTTP_STATUS_CODE_500_INTERNAL_SERVER_ERROR);
                response.end();
                return;
              }

            } else if (
                method.compare("retrieve") == 0) {  // smContextRetrieveData
              // TODO: retrieve_sm_context_handler

            } else {  // Unknown method
              Logger::smf_api_server().warn("Unknown method");
              response.write_head(
                  http_status_code_e::HTTP_STATUS_CODE_405_METHOD_NOT_ALLOWED);
              response.end();
              return;
            }
          }
        });
      });

  if (server.listen_and_serve(ec, m_address, std::to_string(m_port))) {
    std::cerr << "HTTP Server error: " << ec.message() << std::endl;
  }
}

//------------------------------------------------------------------------------
void smf_http2_server::create_sm_contexts_handler(
    const SmContextMessage& smContextMessage, const response& response) {
  Logger::smf_api_server().info(
      "Handle PDU Session Create SM Context Request.");

  SmContextCreateData smContextCreateData = smContextMessage.getJsonData();
  std::string n1_sm_msg = smContextMessage.getBinaryDataN1SmMessage();
  Logger::smf_api_server().debug("N1 SM message: %s", n1_sm_msg.c_str());

  // Step 1. Create a pdu_session_create_sm_context_request message and store
  // the necessary information
  Logger::smf_api_server().debug(
      "Create a pdu_session_create_sm_context_request message and store the "
      "necessary information");
  smf::pdu_session_create_sm_context_request sm_context_req_msg = {};

  // set N1 SM Message
  sm_context_req_msg.set_n1_sm_message(n1_sm_msg);
  // set api root to be used as location header in HTTP response
  sm_context_req_msg.set_api_root(
      // m_address + ":" + std::to_string(m_port) +
		  NSMF_PDU_SESSION_BASE + smf_cfg.sbi_api_version + NSMF_PDU_SESSION_SM_CONTEXT_CREATE_URL);

  // supi
  supi_t supi             = {.length = 0};
  std::size_t pos         = smContextCreateData.getSupi().find("-");
  std::string supi_str    = smContextCreateData.getSupi().substr(pos + 1);
  std::string supi_prefix = smContextCreateData.getSupi().substr(0, pos);
  smf_string_to_supi(&supi, supi_str.c_str());
  sm_context_req_msg.set_supi(supi);
  sm_context_req_msg.set_supi_prefix(supi_prefix);
  Logger::smf_api_server().debug(
      "SUPI %s, SUPI Prefix %s, IMSI %s", smContextCreateData.getSupi().c_str(),
      supi_prefix.c_str(), supi_str.c_str());

  // dnn
  Logger::smf_api_server().debug(
      "DNN %s", smContextCreateData.getDnn().c_str());
  sm_context_req_msg.set_dnn(smContextCreateData.getDnn().c_str());

  // S-Nssai
  Logger::smf_api_server().debug(
      "S-NSSAI SST %d, SD %s", smContextCreateData.getSNssai().getSst(),
      smContextCreateData.getSNssai().getSd().c_str());
  snssai_t snssai(
      smContextCreateData.getSNssai().getSst(),
      smContextCreateData.getSNssai().getSd());
  sm_context_req_msg.set_snssai(snssai);

  // PDU session ID
  Logger::smf_api_server().debug(
      "PDU Session ID %d", smContextCreateData.getPduSessionId());
  sm_context_req_msg.set_pdu_session_id(smContextCreateData.getPduSessionId());

  // AMF ID (ServingNFId)
  Logger::smf_api_server().debug(
      "ServingNfId %s", smContextCreateData.getServingNfId().c_str());
  sm_context_req_msg.set_serving_nf_id(
      smContextCreateData.getServingNfId().c_str());

  // Request Type
  Logger::smf_api_server().debug(
      "RequestType %s", smContextCreateData.getRequestType().c_str());
  sm_context_req_msg.set_request_type(smContextCreateData.getRequestType());
  // PCF ID
  // Priority Access
  // User Location Information
  // Access Type
  // PEI
  // GPSI
  // UE presence in LADN service area
  // Guami
  // servingNetwork
  // anType
  // UETimeZone
  // SMContextStatusUri
  // PCFId

  // DNN Selection Mode
  Logger::smf_api_server().debug(
      "SelMode %s", smContextCreateData.getSelMode().c_str());
  sm_context_req_msg.set_dnn_selection_mode(
      smContextCreateData.getSelMode().c_str());

  // Subscription for PDU Session Status Notification
  // Trace requirement
  // SSC mode (Optional)
  // 5GSM capability (Optional)
  // Maximum number of supported (Optional)
  // Maximum number of supported packet filters (Optional)
  // Always-on PDU session requested (Optional)
  // SM PDU DN request container (Optional)
  // Extended protocol configuration options (Optional) e.g, FOR DHCP

  boost::shared_ptr<
      boost::promise<smf::pdu_session_create_sm_context_response> >
      p = boost::make_shared<
          boost::promise<smf::pdu_session_create_sm_context_response> >();
  boost::shared_future<smf::pdu_session_create_sm_context_response> f;
  f = p->get_future();

  // Generate ID for this promise (to be used in SMF-APP)
  uint32_t promise_id = generate_promise_id();
  Logger::smf_api_server().debug("Promise ID generated %d", promise_id);
  m_smf_app->add_promise(promise_id, p);

  // Step 2. Handle the pdu_session_create_sm_context_request message in smf_app
  std::shared_ptr<itti_n11_create_sm_context_request> itti_msg =
      std::make_shared<itti_n11_create_sm_context_request>(
          TASK_SMF_N11, TASK_SMF_APP, promise_id);
  itti_msg->req          = sm_context_req_msg;
  itti_msg->http_version = 2;
  m_smf_app->handle_pdu_session_create_sm_context_request(itti_msg);

  // wait for the result from APP and send reply to AMF
  smf::pdu_session_create_sm_context_response sm_context_response = f.get();
  Logger::smf_api_server().debug("Got result for promise ID %d", promise_id);
  nlohmann::json json_data = {};
  sm_context_response.get_json_data(json_data);
  std::string json_format;
  sm_context_response.get_json_format(json_format);

  // Add header
  header_map h;
  // Location header
  if (sm_context_response.get_smf_context_uri().size() > 0) {
    Logger::smf_api_server().debug(
        "Add location header %s",
        sm_context_response.get_smf_context_uri().c_str());
    h.emplace(
        "location",
        header_value{sm_context_response.get_smf_context_uri().c_str()});
  }
  // content-type header
  h.emplace("content-type", header_value{json_format});
  response.write_head(sm_context_response.get_http_code(), h);

  response.end(json_data.dump().c_str());
}

//------------------------------------------------------------------------------
void smf_http2_server::update_sm_context_handler(
    const std::string& smf_ref,
    const SmContextUpdateMessage& smContextUpdateMessage,
    const response& response) {
  Logger::smf_api_server().info(
      "Handle PDU Session Update SM Context Request.");

  // Get the SmContextUpdateData from this message and process in smf_app
  Logger::smf_api_server().info(
      "Received a PDUSession_UpdateSMContext Request from AMF.");

  smf::pdu_session_update_sm_context_request sm_context_req_msg = {};
  SmContextUpdateData smContextUpdateData =
      smContextUpdateMessage.getJsonData();

  if (smContextUpdateData.n2SmInfoIsSet()) {
    // N2 SM (for Session establishment)
    std::string n2_sm_information =
        smContextUpdateMessage.getBinaryDataN2SmInformation();
    Logger::smf_api_server().debug(
        "N2 SM Information %s", n2_sm_information.c_str());
    std::string n2_sm_info_type = smContextUpdateData.getN2SmInfoType();
    sm_context_req_msg.set_n2_sm_information(n2_sm_information);
    sm_context_req_msg.set_n2_sm_info_type(n2_sm_info_type);

  } else if (smContextUpdateData.n1SmMsgIsSet()) {
    // N1 SM (for session modification)
    std::string n1_sm_message =
        smContextUpdateMessage.getBinaryDataN1SmMessage();
    Logger::smf_api_server().debug("N1 SM Message %s", n1_sm_message.c_str());
    sm_context_req_msg.set_n1_sm_message(n1_sm_message);
  }
  // Step 2. TODO: initialize necessary values for sm context req from
  // smContextUpdateData

  /* UE-initiated Service Request Operation, section 4.2.3.2@3GPP TS 23.502 */
  // Step 4: PDU Session IDs, Operation Type, UE location Info, Access Type, RAT
  // Type, UE presence in LADN service area, Indication of Access Type can be
  // changed PDU Session IDs UpCnxState, for activation of user plane
  // (see 5.2.2.3.2.2@3GPP TS 29.502, step 1)
  if (smContextUpdateData.upCnxStateIsSet())
    sm_context_req_msg.set_upCnx_state(smContextUpdateData.getUpCnxState());
  // Access Type (step 1 and 2)
  if (smContextUpdateData.anTypeIsSet())
    sm_context_req_msg.set_an_type(smContextUpdateData.getAnType());
  // RAT Type (step 1 and 2)
  if (smContextUpdateData.ratTypeIsSet())
    sm_context_req_msg.set_rat_type(smContextUpdateData.getRatType());
  // TODO:
  // UE presence in LADN service area
  // UE location information
  // Indication of Access Type can be changed
  // if (smContextUpdateData.anTypeCanBeChangedIsSet())
  // sm_context_req_msg.set_access_type_can_be_changed(smContextUpdateData.isAnTypeCanBeChanged());
  // Step 15: N2 SM Info (AN Tunnel Info, List of accepted QoS Flow, List of
  // rejected Qos Flows, PDU Session ID), RAT Type, Access Type

  /* UE-initiated PDU Session Establishment Operation - section 4.3.2.2.1@3GPP
   * TS 23.502 */
  // TODO: Existing PDU session, step 3, SUPI, DNN, S-NSSAIs, SM Context ID, AMF
  // ID, Request Type, N1 SM Container (PDU Session Establishment Request), User
  // location, Access Type, RAT Type, PEI step 15. (SM Context ID -> SCID, N2 SM,
  // Request Type)(Initial Request)
  // TODO: verify why Request Type is not define in smContextUpdateData
  /* AMF-initiated with a release indication to request the release of the PDU
   * Session  (step 3.d, section 4.3.4.2@3GPP TS 23.502)*/
  if (smContextUpdateData.releaseIsSet()) {
    sm_context_req_msg.set_release(smContextUpdateData.isRelease());
  }

  /* PDU Session Modification (SM Context ID -> SCID, N1/N2),
   * section 4.3.3.2@3GPP TS 23.502: */
  // step 1.a,UE-initiated: SM Context ID + N1 (PDU Session Modification
  // Request) step 1.e (AN initiated modification): SM Context ID, N2 SM
  // information (QFI, User location Information and an indication that the QoS
  // Flow is released) step 7a, SM Context ID, N2 SM information, UE location
  // information Step 11, SM Context ID, N1 SM (PDU Session Modification Command
  // ACK), User location
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

  // Step 3. Handle the itti_n11_update_sm_context_request message in smf_app
  std::shared_ptr<itti_n11_update_sm_context_request> itti_msg =
      std::make_shared<itti_n11_update_sm_context_request>(
          TASK_SMF_N11, TASK_SMF_APP, promise_id, smf_ref);
  itti_msg->req          = sm_context_req_msg;
  itti_msg->http_version = 2;
  m_smf_app->handle_pdu_session_update_sm_context_request(itti_msg);

  // wait for the result from APP and send reply to AMF
  smf::pdu_session_update_sm_context_response sm_context_response = f.get();
  Logger::smf_api_server().debug("Got result for promise ID %d", promise_id);

  nlohmann::json json_data = {};
  mime_parser parser       = {};
  std::string body         = {};
  header_map h             = {};
  std::string json_format;

  sm_context_response.get_json_format(json_format);
  sm_context_response.get_json_data(json_data);
  Logger::smf_api_server().debug("Json data %s", json_data.dump().c_str());

  if (sm_context_response.n1_sm_msg_is_set() and
      sm_context_response.n2_sm_info_is_set()) {
    parser.create_multipart_related_content(
        body, json_data.dump(), CURL_MIME_BOUNDARY,
        sm_context_response.get_n1_sm_message(),
        sm_context_response.get_n2_sm_information(), json_format);
    h.emplace(
        "content-type", header_value{"multipart/related; boundary=" +
                                     std::string(CURL_MIME_BOUNDARY)});
  } else if (sm_context_response.n1_sm_msg_is_set()) {
    parser.create_multipart_related_content(
        body, json_data.dump(), CURL_MIME_BOUNDARY,
        sm_context_response.get_n1_sm_message(),
        multipart_related_content_part_e::NAS, json_format);
    h.emplace(
        "content-type", header_value{"multipart/related; boundary=" +
                                     std::string(CURL_MIME_BOUNDARY)});
  } else if (sm_context_response.n2_sm_info_is_set()) {
    parser.create_multipart_related_content(
        body, json_data.dump(), CURL_MIME_BOUNDARY,
        sm_context_response.get_n2_sm_information(),
        multipart_related_content_part_e::NGAP, json_format);
    h.emplace(
        "content-type", header_value{"multipart/related; boundary=" +
                                     std::string(CURL_MIME_BOUNDARY)});
  } else {
    h.emplace("content-type", header_value{json_format});
    body = json_data.dump().c_str();
  }

  response.write_head(sm_context_response.get_http_code(), h);
  response.end(body);
}

//------------------------------------------------------------------------------
void smf_http2_server::release_sm_context_handler(
    const std::string& smf_ref,
    const SmContextReleaseData& smContextReleaseData,
    const response& response) {
  Logger::smf_api_server().info(
      "Handle PDU Session Release SM Context Request.");

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

  // handle Nsmf_PDUSession_UpdateSMContext Request
  Logger::smf_api_server().info(
      "Received a PDUSession_ReleaseSMContext Request: PDU Session Release "
      "request from AMF.");
  std::shared_ptr<itti_n11_release_sm_context_request> itti_msg =
      std::make_shared<itti_n11_release_sm_context_request>(
          TASK_SMF_N11, TASK_SMF_APP, promise_id, smf_ref);

  itti_msg->scid         = smf_ref;
  itti_msg->http_version = 2;
  m_smf_app->handle_pdu_session_release_sm_context_request(itti_msg);

  // wait for the result from APP and send reply to AMF
  smf::pdu_session_release_sm_context_response sm_context_response = f.get();
  Logger::smf_api_server().debug("Got result for promise ID %d", promise_id);

  response.write_head(sm_context_response.get_http_code());
  response.end();
}

//------------------------------------------------------------------------------
void smf_http2_server::stop() {
  server.stop();
}
