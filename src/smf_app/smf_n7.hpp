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
#include <memory>
//#include <folly/concurrency/ConcurrentHashMap.h>
#include <folly/AtomicHashMap.h>

#include "Snssai.h"
#include "PlmnId.h"
#include "SmPolicyDecision.h"
#include "SmPolicyContextData.h"
#include "SmPolicyUpdateContextData.h"
#include "SmPolicyDeleteData.h"
#include "smf.h"

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
 * @brief Used to store all policy-related fields in one struct.
 *
 */
struct policy_association {
  oai::smf_server::model::SmPolicyDecision decision;
  oai::smf_server::model::SmPolicyContextData context;
  uint32_t id     = -1;
  uint32_t pcf_id = -1;
  std::string pcf_location;

  void set_context(
      std::string supi, std::string dnn, snssai_t snssai, plmn_t plmn,
      uint8_t pdu_session_id, pdu_session_type_t pdu_session_type) {
    oai::smf_server::model::Snssai snssai_model;
    snssai_model.setSst(snssai.sST);
    snssai_model.setSd(snssai.sD);
    oai::smf_server::model::PlmnId plmn_id_model;
    std::string mnc_string = std::to_string(plmn.mnc_digit1) +
                             std::to_string(plmn.mnc_digit2) +
                             std::to_string(plmn.mnc_digit3);
    std::string mcc_string = std::to_string(plmn.mcc_digit1) +
                             std::to_string(plmn.mcc_digit2) +
                             std::to_string(plmn.mcc_digit3);
    plmn_id_model.setMnc(mnc_string);
    plmn_id_model.setMcc(mcc_string);
    context = {};

    context.setPduSessionId(pdu_session_id);
    // TODO only support imsi SUPI, not NAI
    context.setSupi("imsi-" + supi);
    oai::smf_server::model::PduSessionType pdu_session_type_model;
    // hacky
    from_json(pdu_session_type.toString(), pdu_session_type_model);
    context.setPduSessionType(pdu_session_type_model);
    context.setDnn(dnn);
  }
};

/**
 * @brief Abstract class to receive policies based on the source (either PCF or
 * local files)
 *
 */
class policy_storage {
 public:
  /**
   * @brief Creates a policy association based on the given context and provides
   * a policy decision.
   *
   * Precondition: context data needs to be set
   * Postcondition: In case of success, return CREATED,
   * association.decision and policy_association.id is set
   *
   * @param association when the ID is already set, this ID is used and the
   * client ensures uniqueness
   * @return sm_policy_status_code CREATED in case of success, otherwise
   * USER_UNKNOWN, INVALID_PARAMETERS, CONTEXT_DENIED, INTERNAL_ERROR
   */
  virtual sm_policy_status_code create_policy_association(
      policy_association& association) = 0;

  /**
   * @brief Removes a policy association, identified by the ID,
   *
   * @param policy_id input: policy ID
   * @param delete_data input: must not be null, but values are optional
   * @return sm_policy_status_code OK in case of success, otherwise NOT_FOUND,
   * INTERNAL_ERROR, PCF_NOT_AVAILABLE
   */
  virtual sm_policy_status_code remove_policy_association(
      uint32_t policy_id,
      const oai::smf_server::model::SmPolicyDeleteData& delete_data) = 0;

  /**
   * @brief Updates a policy association, identified by the ID
   *
   * @param policy_id input: policy ID
   * @param update_data input: must not be null and set accordingly to the
   * triggers
   * @param policy_association output: Updated policy association with new
   * context and decision in case of OK status code
   * @return sm_policy_status_code OK in case of success, otherwise NOT_FOUND,
   * INTERNAL_ERROR, PCF_NOT_AVAILABLE
   */
  virtual sm_policy_status_code update_policy_association(
      uint32_t policy_id,
      const oai::smf_server::model::SmPolicyUpdateContextData& update_data,
      policy_association& association) = 0;
  /**
   * @brief Get the the policy association together with the original context
   *
   * @param policy_id input: policy ID
   * @param association output: contains the original context and the policy
   * decision
   * @return sm_policy_status_code OK in case of success, otherwise NOT_FOUND,
   * ITERNAL_ERROR, PCF_NOT_AVAILABLE
   */
  virtual sm_policy_status_code get_policy_association(
      uint32_t policy_id, policy_association& association) = 0;
};

/**
 * @brief Implements Npcf_SMPolicyControlAPI to interact with a PCF to recieve
 * policies
 */
class smf_pcf_client : public policy_storage {
 public:
  const std::string sm_api_name                 = "npcf-smpolicycontrol";
  const std::string sm_api_policy_resource_part = "sm-policies";

  explicit smf_pcf_client(std::string pcf_addr, std::string pcf_api_version) {
    root_uri = "http://" + pcf_addr + "/" + sm_api_name + "/" +
               pcf_api_version + "/" + sm_api_policy_resource_part;
  }

  virtual ~smf_pcf_client();

  /**
   * @brief Discover PCF either based on NRF or local configuration (based on
   * the config file)
   *
   * @param snssai
   * @param plmn_id
   * @param dnn
   * @return & smf_pcf_client nullptr in case of an error
   */
  static std::shared_ptr<smf_pcf_client> discover_pcf(
      const oai::smf_server::model::Snssai snssai,
      const oai::smf_server::model::PlmnId plmn_id, const std::string dnn);

  sm_policy_status_code create_policy_association(
      policy_association& association) override;

  sm_policy_status_code remove_policy_association(
      uint32_t policy_id,
      const oai::smf_server::model::SmPolicyDeleteData& delete_data) override;

  sm_policy_status_code update_policy_association(
      uint32_t policy_id,
      const oai::smf_server::model::SmPolicyUpdateContextData& update_data,
      policy_association& association) override;

  sm_policy_status_code get_policy_association(
      uint32_t policy_id, policy_association& association) override;

 private:
  static bool discover_pcf_with_nrf(
      std::string& addr, std::string& api_version,
      const oai::smf_server::model::Snssai snssai,
      const oai::smf_server::model::PlmnId plmn_id, const std::string dnn);

  static bool discover_pcf_from_config_file(
      std::string& addr, std::string& api_version,
      const oai::smf_server::model::Snssai snssai,
      const oai::smf_server::model::PlmnId plmn_id, const std::string dnn);

  std::string root_uri;
};

// TODO implement for file based policy rules
// class smf_file_pcc_rules : public policy_storage {};

/**
 * @brief Implements the N7 procedures (communication between SMF and PCF). It
 * is the interface for PCF communication that should be used by other
 * components. Depending on the configuration, the policy rules may come from a
 * PCF or from local files (currently not supported)
 *
 */
class smf_n7 {
 public:
  const uint32_t ASSOCIATIONS_SIZE = 1024;
  const uint32_t PCF_CLIENTS       = 16;

  smf_n7() : associations(ASSOCIATIONS_SIZE), policy_storages(PCF_CLIENTS){};
  smf_n7(smf_n7 const&) = delete;
  void operator=(smf_n7 const&) = delete;
  virtual ~smf_n7();

  static smf_n7& get_instance() {
    static smf_n7 instance;
    return instance;
  }

  /**
   * @brief Creates a SM Policy Association (as defined in 3GPP TS 29.512).
   * The PCF is selected based on the configuration file (NRF or pre-configured)
   * The PCC rules may also be selected from local configuration (depending on
   * option in config file)
   *  @param association: context needs to be set, if id is set, client ensures
   * that the value is unique, if not, other associations may be overwritten
   *
   *
   * @param context input: context data, the mandatory parameters need to be set
   * @param policy_decision output: policy decision
   * @param policy_id output: ID of the policy association
   * @return sm_policy_status_code
   */
  sm_policy_status_code create_sm_policy_association(
      policy_association& association);

 private:
  /**
   * @brief Allows the discovery of a PCF, either via NRF or local
   * configuration, depending on the DISCOVER_PCF option in the configuration
   * file.
   * In case the input parameters are not set, they are ignored.
   *
   * @param context: Context containing at least Snssai, plmn ID and DNN
   * @return 0 in case of failure, otherwise ID > 0
   */
  uint32_t select_pcf(
      const oai::smf_server::model::SmPolicyContextData& context);

  // TODO the ConcurrentHashMap of folly would be much better, but I get a
  // linker error, we should fix that Reason: AtomicHashMap requires that the
  // amount of objects is known upfront.
  folly::AtomicHashMap<uint32_t, std::shared_ptr<policy_storage>>
      policy_storages;
  folly::AtomicHashMap<uint32_t, smf::n7::policy_association> associations;
};
}  // namespace smf::n7
#endif /* FILE_SMF_N4_HPP_SEEN */
