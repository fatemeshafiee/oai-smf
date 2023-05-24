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

/*! \file smf_config_types.hpp
 * \brief
 \author Stefan Spettel
 \company phine.tech
 \date 2023
 \email: stefan.spettel@phine.tech
 */

#pragma once

#include "config_types.hpp"
#include "3gpp_29.571.h"
#include "3gpp_24.501.h"
#include "smf.h"

const std::string PDU_SESSION_TYPE_REGEX = "IPV4|IPV6|IPV4V6";

namespace oai::config::smf {

class smf_support_features : public config_type {
 private:
  option_config_value m_local_subscription_infos{};
  option_config_value m_local_pcc_rules{};
  option_config_value m_external_ausf{};
  option_config_value m_external_udm{};
  option_config_value m_external_nssf{};

 public:
  explicit smf_support_features(
      bool local_subscription_info, bool local_pcc_rules);
  explicit smf_support_features(
      bool external_ausf, bool external_udm, bool external_nssf);

  void from_yaml(const YAML::Node& node) override;

  // TODO can we unify SMF-style use_local_subscription_infos and AMF
  // use_external_UDM?
  [[nodiscard]] std::string to_string(const std::string& indent) const override;
  [[nodiscard]] bool use_local_subscription_info() const;
  [[nodiscard]] bool use_local_pcc_rules() const;
  [[nodiscard]] bool use_external_ausf() const;
  [[nodiscard]] bool use_external_udm() const;
  [[nodiscard]] bool use_external_nssf() const;
};

// TODO remove this after refactor
class upf_info_config_value : public config_type {
 private:
  string_config_value m_n3_nwi;
  string_config_value m_n6_nwi;

 public:
  explicit upf_info_config_value(
      const std::string& n3_nwi, const std::string& n6_nwi);

  void from_yaml(const YAML::Node& node) override;

  [[nodiscard]] std::string to_string(const std::string& indent) const override;

  [[nodiscard]] const std::string& get_n3_nwi() const;

  [[nodiscard]] const std::string& get_n6_nwi() const;
};

// TODO again, we should just use the DnnConfiguration data structure, but that
// requires a lot of changes in the using classes

class dnn_config : public config_type {
 private:
  string_config_value m_dnn;
  string_config_value m_pdu_session_type;
  string_config_value m_ipv4_pool;
  string_config_value m_ipv6_prefix;

  // generated
  in_addr m_ipv4_pool_start_ip;
  in_addr m_ipv4_pool_end_ip;
  in6_addr m_ipv6_prefix_ip;

 private:
  uint8_t m_ipv6_prefix_length;
  pdu_session_type_t m_pdu_session_type_generated;

 public:
  explicit dnn_config(
      const std::string& dnn, const std::string& pdu_type,
      const std::string& ipv4_pool, const std::string& ipv6_prefix);

  void from_yaml(const YAML::Node& node) override;

  [[nodiscard]] std::string to_string(const std::string& indent) const override;

  void validate() override;

  [[nodiscard]] const in_addr& get_ipv4_pool_start() const;
  [[nodiscard]] const in_addr& get_ipv4_pool_end() const;
  [[nodiscard]] const in6_addr& get_ipv6_prefix() const;
  [[nodiscard]] uint8_t get_ipv6_prefix_length() const;
  [[nodiscard]] const pdu_session_type_t& get_pdu_session_type() const;
  [[nodiscard]] const std::string& get_dnn() const;
};

class upf : public config_type {
 private:
  string_config_value m_host;
  int_config_value m_port;
  option_config_value m_usage_reporting;
  option_config_value m_dl_pdr_in_session_establishment;
  string_config_value m_local_n3_ipv4;
  // TODO this is just stupid
  // We have to refactor as follows:
  // 1) Use the UPF info from the model here
  // Write a small parser that converts YAML to JSON and then call the from_json
  // method Like I did on the PCF for the PCC rules Now we have 3(!!!!) UPF info
  // DTOs, but I can't / don't want to just easily move the smf_profile in the
  // common src submodule
  upf_info_config_value m_upf_config_value;

 public:
  explicit upf(
      const std::string& host, int port, bool enable_usage_reporting,
      bool enable_dl_pdr_in_session_establishment,
      const std::string& local_n3_ip);

  void from_yaml(const YAML::Node& node) override;

  [[nodiscard]] std::string to_string(const std::string& indent) const override;

  void validate() override;

  [[nodiscard]] const std::string& get_host() const;

  [[nodiscard]] uint16_t get_port() const;

  [[nodiscard]] bool enable_usage_reporting() const;
  [[nodiscard]] bool enable_dl_pdr_in_session_establishment() const;
  [[nodiscard]] const std::string& get_local_n3_ip() const;
  [[nodiscard]] const upf_info_config_value& get_upf_info() const;
};

class ue_dns : public config_type {
 private:
  string_config_value m_primary_dns_v4;
  string_config_value m_secondary_dns_v4;
  string_config_value m_primary_dns_v6;
  string_config_value m_secondary_dns_v6;

  // generated values
  in_addr m_primary_dns_v4_ip{};
  in_addr m_secondary_dns_v4_ip{};
  in6_addr m_primary_dns_v6_ip{};
  in6_addr m_secondary_dns_v6_ip{};

 public:
  explicit ue_dns(
      const std::string& primary_dns_v4, const std::string& secondary_dns_v4,
      const std::string& primary_dns_v6, const std::string& secondary_dns_v6);

  void from_yaml(const YAML::Node& node) override;

  [[nodiscard]] std::string to_string(const std::string& indent) const override;

  void validate() override;

  [[nodiscard]] const in_addr& get_primary_dns_v4() const;
  [[nodiscard]] const in_addr& get_secondary_dns_v4() const;
  [[nodiscard]] const in6_addr& get_primary_dns_v6() const;
  [[nodiscard]] const in6_addr& get_secondary_dns_v6() const;
};

class ims_config : public config_type {
 private:
  string_config_value m_pcscf_v4;
  string_config_value m_pcscf_v6;

  // generated values
  in_addr m_pcscf_v4_ip{};
  in6_addr m_pcscf_v6_ip{};

 public:
  explicit ims_config(
      const std::string& pcscf_ip_v4, const std::string& pcscf_ip_v6);

  void from_yaml(const YAML::Node& node) override;
  [[nodiscard]] std::string to_string(const std::string& indent) const override;

  void validate() override;

  [[nodiscard]] const in_addr& get_pcscf_v4() const;
  [[nodiscard]] const in6_addr& get_pcscf_v6() const;
};

class subscription_info : public config_type {};

class smf_config_type : public nf {
 private:
  smf_support_features m_support_feature;
  ue_dns m_ue_dns;
  ims_config m_ims_config;
  std::vector<upf> m_upfs;

  int_config_value m_ue_mtu;

 public:
  explicit smf_config_type(
      const std::string& name, const std::string& host,
      const sbi_interface& sbi, const local_interface& n4);
  void from_yaml(const YAML::Node& node) override;

  [[nodiscard]] std::string to_string(const std::string& indent) const override;

  void validate() override;

  [[nodiscard]] const smf_support_features& get_smf_support_features() const;
  [[nodiscard]] const ue_dns& get_ue_dns() const;
  [[nodiscard]] const ims_config& get_ims_config() const;

  [[nodiscard]] uint16_t get_ue_mtu() const;

  [[nodiscard]] const std::vector<upf>& get_upfs() const;
};

}  // namespace oai::config::smf
