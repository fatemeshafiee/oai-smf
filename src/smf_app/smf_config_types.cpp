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

/*! \file smf_config_types.cpp
 * \brief
 \author Stefan Spettel
 \company phine.tech
 \date 2023
 \email: stefan.spettel@phine.tech
 */

#include "smf_config_types.hpp"
#include "smf_config.hpp"

using namespace oai::config::smf;
using namespace oai::config;

smf_support_features::smf_support_features(
    bool local_subscription_info, bool local_pcc_rules) {
  m_config_name              = "Supported Features";
  m_local_subscription_infos = option_config_value(
      "Use Local Subscription Info", local_subscription_info);
  m_local_pcc_rules =
      option_config_value("Use Local PCC Rules", local_pcc_rules);
}

// TODO we should move this to common and use it together with AMF and other NFs
smf_support_features::smf_support_features(
    bool external_ausf, bool external_udm, bool external_nssf) {
  m_config_name   = "Supported Features";
  m_external_ausf = option_config_value("Use External AUSF", external_ausf);
  m_external_udm  = option_config_value("Use External UDM", external_udm);
  m_external_nssf = option_config_value("Use External NSSF", external_nssf);
}

void smf_support_features::from_yaml(const YAML::Node& node) {
  if (node[USE_LOCAL_PCC_RULES_CONFIG_VALUE]) {
    m_local_pcc_rules.from_yaml(node[USE_LOCAL_PCC_RULES_CONFIG_VALUE]);
  }
  if (node[USE_LOCAL_SUBSCRIPTION_INFOS_CONFIG_VALUE]) {
    m_local_subscription_infos.from_yaml(
        node[USE_LOCAL_SUBSCRIPTION_INFOS_CONFIG_VALUE]);
  }
  if (node[USE_EXTERNAL_AUSF_CONFIG_VALUE]) {
    m_external_ausf.from_yaml(node[USE_EXTERNAL_AUSF_CONFIG_VALUE]);
  }
  if (node[USE_EXTERNAL_UDM_CONFIG_VALUE]) {
    m_external_udm.from_yaml(node[USE_EXTERNAL_UDM_CONFIG_VALUE]);
  }
  if (node[USE_EXTERNAL_NSSF_CONFIG_VALUE]) {
    m_external_ausf.from_yaml(node[USE_EXTERNAL_AUSF_CONFIG_VALUE]);
  }
}

std::string smf_support_features::to_string(const std::string& indent) const {
  std::string out;
  std::string inner_indent = indent + indent;
  unsigned int inner_width = get_inner_width(inner_indent.length());
  out.append(indent).append(m_config_name).append(":\n");

  if (!m_local_subscription_infos.get_config_name().empty()) {
    out.append(inner_indent)
        .append(fmt::format(
            BASE_FORMATTER, INNER_LIST_ELEM,
            m_local_subscription_infos.get_config_name(), inner_width,
            m_local_subscription_infos.to_string("")));
  }

  if (!m_local_pcc_rules.get_config_name().empty()) {
    out.append(inner_indent)
        .append(fmt::format(
            BASE_FORMATTER, INNER_LIST_ELEM,
            m_local_pcc_rules.get_config_name(), inner_width,
            m_local_pcc_rules.to_string("")));
  }

  if (!m_external_ausf.get_config_name().empty()) {
    out.append(inner_indent)
        .append(fmt::format(
            BASE_FORMATTER, INNER_LIST_ELEM, m_external_ausf.get_config_name(),
            inner_width, m_external_ausf.to_string("")));
  }

  if (!m_external_udm.get_config_name().empty()) {
    out.append(inner_indent)
        .append(fmt::format(
            BASE_FORMATTER, INNER_LIST_ELEM, m_external_udm.get_config_name(),
            inner_width, m_external_udm.to_string("")));
  }

  if (!m_external_nssf.get_config_name().empty()) {
    out.append(inner_indent)
        .append(fmt::format(
            BASE_FORMATTER, INNER_LIST_ELEM, m_external_nssf.get_config_name(),
            inner_width, m_external_nssf.to_string("")));
  }

  return out;
}

bool smf_support_features::use_local_subscription_info() const {
  return m_local_subscription_infos.get_value();
}

bool smf_support_features::use_local_pcc_rules() const {
  return m_local_pcc_rules.get_value();
}

bool smf_support_features::use_external_ausf() const {
  return m_external_ausf.get_value();
}

bool smf_support_features::use_external_udm() const {
  return m_external_udm.get_value();
}

bool smf_support_features::use_external_nssf() const {
  return m_external_nssf.get_value();
}

upf_info_config_value::upf_info_config_value(
    const std::string& n3_nwi, const std::string& n6_nwi) {
  m_n3_nwi = string_config_value("NWI N3", n3_nwi);
  m_n6_nwi = string_config_value("NWI N6", n6_nwi);
}

void upf_info_config_value::from_yaml(const YAML::Node& node) {
  if (node["interfaceUpfInfoList"]) {
    YAML::Node inner_node = node["interfaceUpfInfoList"];
    for (const auto& elem : inner_node) {
      if (elem["interfaceType"] && elem["networkInstance"]) {
        if (elem["interfaceType"].as<std::string>() == "N3") {
          m_n3_nwi.from_yaml(elem["networkInstance"]);
        } else if (elem["interfaceType"].as<std::string>() == "N6") {
          m_n6_nwi.from_yaml(elem["networkInstance"]);
        }
      }
    }
  }
}

std::string upf_info_config_value::to_string(const std::string& indent) const {
  std::string out;

  std::string inner_indent = add_indent(indent);
  unsigned int inner_width = get_inner_width(inner_indent.length());

  out.append(indent).append(
      fmt::format("{} Interface Configuration:\n", INNER_LIST_ELEM));

  out.append(inner_indent)
      .append(fmt::format(
          BASE_FORMATTER, OUTER_LIST_ELEM, m_n3_nwi.get_config_name(),
          inner_width, m_n3_nwi.to_string("")));

  out.append(inner_indent)
      .append(fmt::format(
          BASE_FORMATTER, OUTER_LIST_ELEM, m_n6_nwi.get_config_name(),
          inner_width, m_n6_nwi.to_string("")));
  return out;
}

const std::string& upf_info_config_value::get_n3_nwi() const {
  return m_n3_nwi.get_value();
}

const std::string& upf_info_config_value::get_n6_nwi() const {
  return m_n6_nwi.get_value();
}

upf::upf(
    const std::string& host, int port, bool enable_usage_reporting,
    bool enable_dl_pdr_in_session_establishment, const std::string& local_n3_ip)
    : m_upf_config_value("access.oai.org", "core.oai.org") {
  m_host = string_config_value("Host", host);
  m_port = int_config_value("Port", port);
  m_usage_reporting =
      option_config_value("Enable Usage Reporting", enable_usage_reporting);
  m_dl_pdr_in_session_establishment = option_config_value(
      "Enable DL PDR In Session Establishment",
      enable_dl_pdr_in_session_establishment);
  m_local_n3_ipv4 = string_config_value("Local N3 IPv4", local_n3_ip);

  m_host.set_validation_regex(HOST_VALIDATOR_REGEX);
  m_port.set_validation_interval(PORT_MIN_VALUE, PORT_MAX_VALUE);
  m_local_n3_ipv4.set_validation_regex(IPV4_ADDRESS_VALIDATOR_REGEX);
  if (local_n3_ip.empty()) {
    m_local_n3_ipv4.unset_config();
  }
}

void upf::from_yaml(const YAML::Node& node) {
  if (node["host"]) {
    m_host.from_yaml(node["host"]);
  }
  if (node["port"]) {
    m_port.from_yaml(node["port"]);
  }
  if (node["config"]) {
    if (node["config"]["enable_usage_reporting"]) {
      m_usage_reporting.from_yaml(node["config"]["enable_usage_reporting"]);
    }
    if (node["config"]["enable_dl_pdr_in_pfcp_session_establishment"]) {
      m_dl_pdr_in_session_establishment.from_yaml(
          node["config"]["enable_dl_pdr_in_pfcp_session_establishment"]);
    }
    if (node["config"]["n3_local_ipv4"]) {
      m_local_n3_ipv4.from_yaml(node["config"]["n3_local_ipv4"]);
    }
  }
  if (node["config"]) {
    m_upf_config_value.from_yaml(node["config"]);
  }
}

std::string upf::to_string(const std::string& indent) const {
  std::string out;
  std::string inner_indent = add_indent(indent);
  unsigned int inner_width = get_inner_width(inner_indent.length());
  out.append(indent).append(
      fmt::format("{} {}\n", OUTER_LIST_ELEM, m_host.get_value()));

  out.append(inner_indent)
      .append(fmt::format(
          BASE_FORMATTER, INNER_LIST_ELEM, m_host.get_config_name(),
          inner_width, m_host.to_string("")));
  out.append(inner_indent)
      .append(fmt::format(
          BASE_FORMATTER, INNER_LIST_ELEM, m_port.get_config_name(),
          inner_width, m_port.to_string("")));
  out.append(inner_indent)
      .append(fmt::format(
          BASE_FORMATTER, INNER_LIST_ELEM, m_usage_reporting.get_config_name(),
          inner_width, m_usage_reporting.to_string("")));
  out.append(inner_indent)
      .append(fmt::format(
          BASE_FORMATTER, INNER_LIST_ELEM,
          m_dl_pdr_in_session_establishment.get_config_name(), inner_width,
          m_dl_pdr_in_session_establishment.to_string("")));
  if (m_local_n3_ipv4.is_set()) {
    out.append(inner_indent)
        .append(fmt::format(
            BASE_FORMATTER, INNER_LIST_ELEM, m_local_n3_ipv4.get_config_name(),
            inner_width, m_local_n3_ipv4.to_string("")));
  }
  out.append(m_upf_config_value.to_string(inner_indent));
  return out;
}

void upf::validate() {
  if (!m_set) return;
  m_host.validate();
  m_port.validate();
  m_local_n3_ipv4.validate();
  m_upf_config_value.validate();
}

const std::string& upf::get_host() const {
  return m_host.get_value();
}

uint16_t upf::get_port() const {
  return m_port.get_value();
}

bool upf::enable_usage_reporting() const {
  return m_usage_reporting.get_value();
}

bool upf::enable_dl_pdr_in_session_establishment() const {
  return m_dl_pdr_in_session_establishment.get_value();
}

const std::string& upf::get_local_n3_ip() const {
  return m_local_n3_ipv4.get_value();
}

const upf_info_config_value& upf::get_upf_info() const {
  return m_upf_config_value;
}

ims_config::ims_config(
    const std::string& pcscf_ip_v4, const std::string& pcscf_ip_v6) {
  m_pcscf_v4 = string_config_value("P-CSCF IPv4", pcscf_ip_v4);
  m_pcscf_v6 = string_config_value("P-CSCF IPv6", pcscf_ip_v6);

  m_pcscf_v4.set_validation_regex(IPV4_ADDRESS_VALIDATOR_REGEX);
  m_pcscf_v6.set_validation_regex(IPV6_ADDRESS_VALIDATOR_REGEX);
  if (pcscf_ip_v6.empty()) {
    m_pcscf_v6.unset_config();
  }
}

void ims_config::from_yaml(const YAML::Node& node) {
  if (node["pcscf_ipv4"]) {
    m_pcscf_v4.from_yaml(node["pcscf_ipv4"]);
  }
  if (node["pcscf_ipv6"]) {
    m_pcscf_v6.from_yaml(node["pcscf_ipv6"]);
  }
}

std::string ims_config::to_string(const std::string& indent) const {
  std::string out;
  unsigned int inner_width = get_inner_width(indent.length());

  out.append(indent).append(fmt::format(
      BASE_FORMATTER, OUTER_LIST_ELEM, m_pcscf_v4.get_config_name(),
      inner_width, m_pcscf_v4.to_string("")));
  if (m_pcscf_v6.is_set()) {
    out.append(indent).append(fmt::format(
        BASE_FORMATTER, OUTER_LIST_ELEM, m_pcscf_v6.get_config_name(),
        inner_width, m_pcscf_v6.to_string("")));
  }
  return out;
}

void ims_config::validate() {
  m_pcscf_v4.validate();
  m_pcscf_v6.validate();

  if (m_pcscf_v4.is_set()) {
    m_pcscf_v4_ip = safe_convert_ip(m_pcscf_v4.get_value());
  } else if (m_pcscf_v6.is_set()) {
    m_pcscf_v6_ip = safe_convert_ip6(m_pcscf_v6.get_value());
  } else {
    throw std::runtime_error(
        fmt::format("You need to specify either a valid IPv4 or IPv6 address"));
  }
}

const in_addr& ims_config::get_pcscf_v4() const {
  return m_pcscf_v4_ip;
}

const in6_addr& ims_config::get_pcscf_v6() const {
  return m_pcscf_v6_ip;
}

smf_config_type::smf_config_type(
    const std::string& name, const std::string& host, const sbi_interface& sbi,
    const local_interface& n4)
    : nf(name, host, sbi, n4),
      m_ims_config("127.0.0.1", ""),
      m_support_feature(false, true),
      m_ue_dns("8.8.8.8", "1.1.1.1", "", "") {
  m_config_name = "SMF Config";
  m_ue_mtu      = int_config_value("UE MTU", 1500);
}

void smf_config_type::from_yaml(const YAML::Node& node) {
  nf::from_yaml(node);
  if (node["support_features"]) {
    m_support_feature.from_yaml(node["support_features"]);
  }
  if (node["ue_dns"]) {
    m_ue_dns.from_yaml(node["ue_dns"]);
  }
  if (node["ims"]) {
    m_ims_config.from_yaml(node["ims"]);
  }
  if (node["upfs"]) {
    // any default UPF is deleted if people configure UPFs
    m_upfs.clear();
    for (const auto& yaml_upf : node["upfs"]) {
      // TODO should we have a default host here?
      upf u = upf("", 8805, false, false, "");
      u.from_yaml(yaml_upf);
      m_upfs.push_back(u);
    }
  }
  if (node["local_subscription_infos"]) {
    // any default subscription is deleted if people configure it
    m_subscription_infos.clear();
    for (const auto& yaml_sub : node["local_subscription_infos"]) {
      subscription_info_config subcfg(
          DEFAULT_DNN, DEFAULT_SSC_MODE, DEFAULT_QOS, DEFAULT_S_AMBR,
          DEFAULT_SNSSAI);
      subcfg.from_yaml(yaml_sub);
      m_subscription_infos.push_back(subcfg);
    }
  }
}

std::string smf_config_type::to_string(const std::string& indent) const {
  std::string out = nf::to_string("");

  unsigned int inner_width = get_inner_width(indent.length());
  out.append(m_support_feature.to_string(indent));
  out.append(indent).append(fmt::format(
      BASE_FORMATTER, OUTER_LIST_ELEM, m_ue_mtu.get_config_name(), inner_width,
      m_ue_mtu.to_string("")));
  out.append(m_ims_config.to_string(indent));
  std::string inner_indent = indent + indent;
  if (!m_upfs.empty()) {
    out.append(indent).append("UPF List:\n");
    for (const auto& upf : m_upfs) {
      out.append(upf.to_string(inner_indent));
    }
  }
  if (!m_subscription_infos.empty()) {
    out.append(indent).append("Local Subscription Infos:\n");
    for (const auto& sub : m_subscription_infos) {
      out.append(sub.to_string(inner_indent));
    }
  }

  return out;
}

void smf_config_type::validate() {
  nf::validate();
  m_ue_dns.validate();
  m_ue_mtu.validate();
  for (auto& upf : m_upfs) {
    upf.validate();
  }
  m_ims_config.validate();
  for (auto& sub : m_subscription_infos) {
    sub.validate();
  }
}

const smf_support_features& smf_config_type::get_smf_support_features() const {
  return m_support_feature;
}

const ue_dns& smf_config_type::get_ue_dns() const {
  return m_ue_dns;
}

const ims_config& smf_config_type::get_ims_config() const {
  return m_ims_config;
}

uint16_t smf_config_type::get_ue_mtu() const {
  return m_ue_mtu.get_value();
}

const std::vector<upf>& smf_config_type::get_upfs() const {
  return m_upfs;
}

std::vector<subscription_info_config>&
smf_config_type::get_subscription_info() {
  return m_subscription_infos;
}

subscription_info_config::subscription_info_config(
    const std::string& dnn, uint8_t ssc_mode,
    const subscribed_default_qos_t& qos, const session_ambr_t& session_ambr,
    const snssai_t& snssai)
    : m_snssai(snssai), m_qos_profile(qos, session_ambr) {
  m_dnn         = string_config_value("DNN", dnn);
  m_ssc_mode    = int_config_value("SSC Mode", ssc_mode);
  m_config_name = "Local Subscription Info";

  // TODO do we need a validation regex for DNN?
  m_ssc_mode.set_validation_interval(1, 3);
}

void subscription_info_config::from_yaml(const YAML::Node& node) {
  if (node["dnn"]) {
    m_dnn.from_yaml(node["dnn"]);
  }
  if (node["scc_mode"]) {
    m_ssc_mode.from_yaml(node["scc_mode"]);
  }
  if (node["single_nssai"]) {
    m_snssai.from_yaml(node["single_nssai"]);
  }
  if (node["qos_profile"]) {
    m_qos_profile.from_yaml(node["qos_profile"]);
  }
}

std::string subscription_info_config::to_string(
    const std::string& indent) const {
  std::string out;
  out.append(indent).append(
      fmt::format("{} {}\n", OUTER_LIST_ELEM, m_config_name));
  std::string inner_indent = add_indent(indent);
  unsigned int inner_width = get_inner_width(inner_indent.length());

  out.append(inner_indent)
      .append(fmt::format(
          BASE_FORMATTER, INNER_LIST_ELEM, m_dnn.get_config_name(), inner_width,
          m_dnn.to_string("")));

  out.append(inner_indent)
      .append(fmt::format(
          BASE_FORMATTER, INNER_LIST_ELEM, m_ssc_mode.get_config_name(),
          inner_width, m_ssc_mode.to_string("")));

  out.append(m_snssai.to_string(inner_indent));
  out.append(m_qos_profile.to_string(inner_indent));

  return out;
}

void subscription_info_config::validate() {
  m_dnn.validate();
  m_ssc_mode.validate();
  m_snssai.validate();
  m_qos_profile.validate();
}

const std::string& subscription_info_config::get_dnn() const {
  return m_dnn.get_value();
}

uint8_t subscription_info_config::get_ssc_mode() const {
  return m_ssc_mode.get_value();
}

const subscribed_default_qos_t& subscription_info_config::get_default_qos()
    const {
  return m_qos_profile.get_default_qos();
}

const session_ambr_t& subscription_info_config::get_session_ambr() const {
  return m_qos_profile.get_session_ambr();
}

const snssai_t& subscription_info_config::get_single_nssai() const {
  return m_snssai.get_snssai();
}

snssai_config_value::snssai_config_value(const snssai_t& snssai) {
  m_snssai = snssai;
  // narrowing conversion, but should be okay because max value is 16777215
  m_sd  = int_config_value("SD", m_snssai.sd);
  m_sst = int_config_value("SST", m_snssai.sst);

  m_sd.set_validation_interval(0, 16777215);
  m_sst.set_validation_interval(0, 255);

  m_config_name = "Single NSSAI";
}

void snssai_config_value::from_yaml(const YAML::Node& node) {
  if (node["sd"]) {
    m_sd.from_yaml(node["sd"]);
    m_snssai.sd = m_sd.get_value();
  }
  if (node["sst"]) {
    m_sst.from_yaml(node["sst"]);
    m_snssai.sst = m_sst.get_value();
  }
}

std::string snssai_config_value::to_string(const std::string& indent) const {
  std::string out;

  out.append(indent).append(
      fmt::format("{} {}:\n", INNER_LIST_ELEM, m_config_name));

  std::string inner_indent = add_indent(indent);

  unsigned int inner_width = get_inner_width(inner_indent.length());
  out.append(inner_indent)
      .append(fmt::format(
          BASE_FORMATTER, OUTER_LIST_ELEM, m_sst.get_config_name(), inner_width,
          m_sst.to_string("")));

  std::string sd_value =
      fmt::format("{:#X} ({})", m_sd.get_value(), m_sd.get_value());
  out.append(inner_indent)
      .append(fmt::format(
          BASE_FORMATTER, OUTER_LIST_ELEM, m_sd.get_config_name(), inner_width,
          sd_value));

  return out;
}

void snssai_config_value::validate() {
  m_sst.validate();
  m_sd.validate();
}

const snssai_t& snssai_config_value::get_snssai() const {
  return m_snssai;
}

qos_profile_config_value::qos_profile_config_value(
    const subscribed_default_qos_t& qos, const session_ambr_t& ambr) {
  m_qos          = qos;
  m_ambr         = ambr;
  m_5qi          = int_config_value("5QI", m_qos._5qi);
  m_priority     = int_config_value("Priority", m_qos.priority_level);
  m_arp_priority = int_config_value("ARP Priority", m_qos.arp.priority_level);
  m_arp_preempt_capability =
      string_config_value("ARP Preempt Capability", m_qos.arp.preempt_cap);
  m_arp_preempt_vulnerability =
      string_config_value("ARP Preempt Vulnerability", m_qos.arp.preempt_vuln);
  m_session_ambr_dl = string_config_value("Session AMBR DL", m_ambr.downlink);
  m_session_ambr_ul = string_config_value("Session AMBR UL", m_ambr.uplink);

  m_5qi.set_validation_interval(1, 254);
  m_priority.set_validation_interval(1, 127);
  m_arp_priority.set_validation_interval(1, 15);

  m_config_name = "QoS Profile";

  // TODO ARP Preempt and session AMBR String regex validators
}

void qos_profile_config_value::from_yaml(const YAML::Node& node) {
  if (node["5qi"]) {
    m_5qi.from_yaml(node["5qi"]);
    m_qos._5qi = m_5qi.get_value();
  }
  if (node["priority"]) {
    m_priority.from_yaml(node["priority"]);
    m_qos.priority_level = m_priority.get_value();
  }
  if (node["arp_priority"]) {
    m_arp_priority.from_yaml(node["arp_priority"]);
    m_qos.arp.priority_level = m_arp_priority.get_value();
  }
  if (node["arp_preempt_capability"]) {
    m_arp_preempt_capability.from_yaml(node["arp_preempt_capability"]);
    m_qos.arp.preempt_cap = m_arp_preempt_capability.get_value();
  }
  if (node["arp_preempt_vulnerability"]) {
    m_arp_preempt_vulnerability.from_yaml(node["arp_preempt_vulnerability"]);
    m_qos.arp.preempt_vuln = m_arp_preempt_vulnerability.get_value();
  }
  if (node["session_ambr_ul"]) {
    m_session_ambr_ul.from_yaml(node["session_ambr_ul"]);
    m_ambr.uplink = m_session_ambr_ul.get_value();
  }
  if (node["session_ambr_dl"]) {
    m_session_ambr_dl.from_yaml(node["session_ambr_dl"]);
    m_ambr.downlink = m_session_ambr_dl.get_value();
  }
}

std::string qos_profile_config_value::to_string(
    const std::string& indent) const {
  std::string out;

  out.append(indent).append(
      fmt::format("{} {}:\n", INNER_LIST_ELEM, m_config_name));
  std::string inner_indent = add_indent(indent);

  unsigned int inner_width = get_inner_width(inner_indent.length());

  out.append(inner_indent)
      .append(fmt::format(
          BASE_FORMATTER, OUTER_LIST_ELEM, m_5qi.get_config_name(), inner_width,
          m_5qi.to_string("")));

  out.append(inner_indent)
      .append(fmt::format(
          BASE_FORMATTER, OUTER_LIST_ELEM, m_priority.get_config_name(),
          inner_width, m_priority.to_string("")));

  out.append(inner_indent)
      .append(fmt::format(
          BASE_FORMATTER, OUTER_LIST_ELEM, m_arp_priority.get_config_name(),
          inner_width, m_arp_priority.to_string("")));

  out.append(inner_indent)
      .append(fmt::format(
          BASE_FORMATTER, OUTER_LIST_ELEM,
          m_arp_preempt_vulnerability.get_config_name(), inner_width,
          m_arp_preempt_vulnerability.to_string("")));

  out.append(inner_indent)
      .append(fmt::format(
          BASE_FORMATTER, OUTER_LIST_ELEM,
          m_arp_preempt_capability.get_config_name(), inner_width,
          m_arp_preempt_capability.to_string("")));

  out.append(inner_indent)
      .append(fmt::format(
          BASE_FORMATTER, OUTER_LIST_ELEM, m_session_ambr_dl.get_config_name(),
          inner_width, m_session_ambr_dl.to_string("")));

  out.append(inner_indent)
      .append(fmt::format(
          BASE_FORMATTER, OUTER_LIST_ELEM, m_session_ambr_ul.get_config_name(),
          inner_width, m_session_ambr_ul.to_string("")));

  return out;
}

void qos_profile_config_value::validate() {
  m_5qi.validate();
  m_priority.validate();
  m_arp_priority.validate();
  m_arp_preempt_vulnerability.validate();
  m_arp_preempt_capability.validate();
  m_session_ambr_ul.validate();
  m_session_ambr_dl.validate();
}

const subscribed_default_qos_t& qos_profile_config_value::get_default_qos()
    const {
  return m_qos;
}

const session_ambr_t& qos_profile_config_value::get_session_ambr() const {
  return m_ambr;
}
