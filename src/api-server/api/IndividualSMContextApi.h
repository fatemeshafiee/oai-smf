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

/*
 * IndividualSMContextApi.h
 *
 *
 */

#ifndef IndividualSMContextApi_H_
#define IndividualSMContextApi_H_

#include <pistache/http.h>
#include <pistache/router.h>
#include <pistache/http_headers.h>
#include <pistache/optional.h>

#include "ProblemDetails.h"
#include "SmContextReleaseData.h"
#include "SmContextRetrieveData.h"
#include "SmContextRetrievedData.h"
#include "SmContextUpdateData.h"
#include "SmContextUpdateError.h"
#include "SmContextUpdatedData.h"
#include "SmContextUpdateMessage.h"
#include "SmContextReleaseMessage.h"

#include "SmContextMessage.h"
#include "SmContextCreateError.h"
#include "SmContextCreatedData.h"

namespace oai {
namespace smf_server {
namespace api {

using namespace oai::smf_server::model;

class IndividualSMContextApi {
 public:
  IndividualSMContextApi(std::shared_ptr<Pistache::Rest::Router>);
  virtual ~IndividualSMContextApi() {}
  void init();

  const std::string base = "/nsmf-pdusession/";

 private:
  void setupRoutes();

  void release_sm_context_handler(
      const Pistache::Rest::Request& request,
      Pistache::Http::ResponseWriter response);
  void retrieve_sm_context_handler(
      const Pistache::Rest::Request& request,
      Pistache::Http::ResponseWriter response);
  void update_sm_context_handler(
      const Pistache::Rest::Request& request,
      Pistache::Http::ResponseWriter response);
  void individual_sm_context_api_default_handler(
      const Pistache::Rest::Request& request,
      Pistache::Http::ResponseWriter response);

  std::shared_ptr<Pistache::Rest::Router> router;

  /// <summary>
  /// Release SM Context
  /// </summary>
  /// <remarks>
  ///
  /// </remarks>
  /// <param name="smContextRef">SM context reference</param>
  /// <param name="smContextReleaseData">representation of the data to be sent
  /// to the SMF when releasing the SM context (optional)</param>
  virtual void release_sm_context(
      const std::string& smContextRef,
      const SmContextReleaseMessage& smContextReleaseMessage,
      Pistache::Http::ResponseWriter& response) = 0;

  /// <summary>
  /// Retrieve SM Context
  /// </summary>
  /// <remarks>
  ///
  /// </remarks>
  /// <param name="smContextRef">SM context reference</param>
  /// <param name="smContextRetrieveData">parameters used to retrieve the SM
  /// context (optional)</param>
  virtual void retrieve_sm_context(
      const std::string& smContextRef,
      const SmContextRetrieveData& smContextRetrieveData,
      Pistache::Http::ResponseWriter& response) = 0;

  /// <summary>
  /// Update SM Context
  /// </summary>
  /// <remarks>
  ///
  /// </remarks>
  /// <param name="smContextRef">SM context reference</param>
  /// <param name="smContextUpdateData">representation of the updates to apply
  /// to the SM context</param>
  virtual void update_sm_context(
      const std::string& smContextRef,
      const SmContextUpdateMessage& smContextUpdateMessage,
      Pistache::Http::ResponseWriter& response) = 0;
};

}  // namespace api
}  // namespace smf_server
}  // namespace oai

#endif /* IndividualSMContextApi_H_ */
