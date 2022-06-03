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

/*! \file smf_n7.hpp
 \author  Stefan Spettel
 \company Openairinterface Software Alliance
 \date 2022
 \email: stefan.spettel@eurecom.fr
 */

#ifndef FILE_SMF_N7_HPP_SEEN
#define FILE_SMF_N7_HPP_SEEN

#include <string>
#include "Snssai.h"
#include "PlmnId.h"
#include "SmPolicyDecision.h"
#include "SmPolicyContextData.h"

namespace smf::n7 {

/**
 * @brief Status codes for the communication with the PCF
 *
 */
enum class sm_policy_status_code {
  CREATED,
  USER_UNKOWN,
  INVALID_PARAMETERS,
  CONTEXT_DENIED,
  NOT_FOUND,
  OK,
  PCF_NOT_AVAILABLE,
  INTERNAL_ERROR
};

/**
 *
 */
class smf_pcf_client {
 public:
  const std::string sm_api_name                 = "npcf-smpolicycontrol";
  const std::string sm_api_policy_resource_part = "sm-policies";

  sm_policy_status_code send_create_policy_association(
      const std::string pcf_addr, const std::string pcf_api_version,
      const oai::smf_server::model::SmPolicyContextData& context,
      oai::smf_server::model::SmPolicyDecision& policy_decision);
};

/**
 * @brief Implements the N7 procedures (communication between SMF and PCF). It
 * is the interface for PCF communication that should be used by other
 * components
 *
 */
class smf_n7 {
 public:
  smf_n7(){};
  smf_n7(smf_n7 const&) = delete;
  void operator=(smf_n7 const&) = delete;
  virtual ~smf_n7();

  static smf_n7& get_instance() {
    static smf_n7 instance;
    return instance;
  }

  /**
   * @brief Creates a SM Policy Association (as defined in 3GPP TS 29.512)
   * towards the PCF specified with pcf_addr.
   *
   * @param pcf_addr PCF address in format ip:port (see discover_pcf)
   * @param pcf_api_version PCF API version
   * @param context context data, the mandatory parameters need to be set
   * @param policy_decision policy decision received from the PCF (is empty on
   * error)
   * @return smf::n7::sm_policy_status_code Status code depending on the result
   * from the PCF API
   */
  smf::n7::sm_policy_status_code create_sm_policy_association(
      const std::string pcf_addr, const std::string pcf_api_version,
      const oai::smf_server::model::SmPolicyContextData& context,
      oai::smf_server::model::SmPolicyDecision& policy_decision);

  /**
   * @brief Allows the discovery of a PCF, either via NRF or local
   * configuration, depending on the DISCOVER_PCF option in the configuration
   * file.
   *
   * @param addr output: The address of the PCF, ip:port
   * @param api_version output: The API version of the PCF
   * @param snssai input: The Snssai of the context
   * @param plmn_id input: The PLMN of the context
   * @param dnn input: The DNN of the context
   * @return true
   * @return false
   */
  bool discover_pcf(
      std::string& addr, std::string& api_version,
      const oai::smf_server::model::Snssai snssai,
      const oai::smf_server::model::PlmnId plmn_id, const std::string dnn);

 private:
  bool discover_pcf_with_nrf(
      std::string& addr, std::string& api_version,
      const oai::smf_server::model::Snssai snssai,
      const oai::smf_server::model::PlmnId plmn_id, const std::string dnn);

  bool discover_pcf_from_config_file(
      std::string& addr, std::string& api_version,
      const oai::smf_server::model::Snssai snssai,
      const oai::smf_server::model::PlmnId plmn_id, const std::string dnn);

  smf_pcf_client policy_api_client = {};
};

}  // namespace smf::n7
#endif /* FILE_SMF_N4_HPP_SEEN */
