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

/*! \file smf_config.cpp
 \brief
 \author  Lionel GAUTHIER, Tien-Thinh NGUYEN, Stefan Spettel
 \company Eurecom, phine.tech
 \date 2023
 \email: lionel.gauthier@eurecom.fr, tien-thinh.nguyen@eurecom.fr,
 stefan.spettel@phine.tech
 */

#include "smf_config.hpp"

#include <iostream>

#include <arpa/inet.h>
#include <regex>

#include "common_defs.h"
#include "if.hpp"
#include "logger.hpp"
#include "fqdn.hpp"
#include "smf_config_types.hpp"
#include "ProblemDetails.h"

using namespace std;
using namespace smf;
using namespace oai::config::smf;
using namespace oai::config;

smf_config::smf_config(
    const std::string& configPath, bool logStdout, bool logRotFile)
    : config(configPath, oai::config::SMF_CONFIG_NAME, logStdout, logRotFile),
      n4(),
      sbi(),
      itti(),
      upfs() {
  m_used_config_values = {LOG_LEVEL_CONFIG_NAME, REGISTER_NF_CONFIG_NAME,
                          NF_LIST_CONFIG_NAME,   SMF_CONFIG_NAME,
                          DNNS_CONFIG_NAME,      NF_CONFIG_HTTP_NAME};

  m_used_sbi_values = {SMF_CONFIG_NAME, PCF_CONFIG_NAME, NRF_CONFIG_NAME,
                       AMF_CONFIG_NAME, UDM_CONFIG_NAME};

  // Define default values in YAML
  auto smf = std::make_shared<smf_config_type>(
      "smf", "oai-smf", sbi_interface("SBI", "oai-smf", 80, "v1", "eth0"),
      local_interface("N4", "oai-smf", 8805, "eth0"));
  add_nf("smf", smf);

  auto amf = std::make_shared<nf>(
      "amf", "oai-amf", sbi_interface("SBI", "oai-amf", 80, "v1", ""));
  add_nf("amf", amf);

  auto udm = std::make_shared<nf>(
      "udm", "oai-udm", sbi_interface("SBI", "oai-udm", 80, "v1", ""));
  add_nf("udm", udm);

  auto pcf = std::make_shared<nf>(
      "pcf", "oai-pcf", sbi_interface("SBI", "oai-pcf", 80, "v1", ""));
  add_nf("pcf", pcf);

  auto nrf = std::make_shared<nf>(
      "nrf", "oai-nrf", sbi_interface("SBI", "oai-nrf", 80, "v1", ""));
  add_nf("nrf", nrf);

  // DNN default values
  dnn_config dnn("default", "IPV4", "12.1.1.0 - 12.1.1.255", "");
  m_dnns.push_back(dnn);

  // Local subscription default values
  subscription_info_config info(
      "default", 1, DEFAULT_QOS, DEFAULT_S_AMBR, DEFAULT_SNSSAI);
  smf->get_subscription_info().push_back(info);
}

//------------------------------------------------------------------------------
int smf_config::get_pfcp_node_id(pfcp::node_id_t& node_id) {
  oai::config::local_interface _n4 = local().get_nx();
  // if we give a FQDN here, the IP address will be empty
  if (!conv::fromString(local().get_host()).s_addr) {
    node_id.node_id_type = pfcp::NODE_ID_TYPE_FQDN;
    node_id.fqdn         = local().get_host();
    return RETURNok;
  } else {
    if (_n4.get_addr4().s_addr) {
      node_id.node_id_type    = pfcp::NODE_ID_TYPE_IPV4_ADDRESS;
      node_id.u1.ipv4_address = _n4.get_addr4();
      return RETURNok;
    }
    if (!IN6_IS_ADDR_UNSPECIFIED(&_n4.get_addr6())) {
      node_id.node_id_type    = pfcp::NODE_ID_TYPE_IPV6_ADDRESS;
      node_id.u1.ipv6_address = _n4.get_addr6();
      return RETURNok;
    }
  }
  return RETURNerror;
}

int smf_config::get_pfcp_fseid(pfcp::fseid_t& fseid) {
  oai::config::local_interface _n4 = local().get_nx();
  if (_n4.get_addr4().s_addr) {
    fseid.v4           = 1;
    fseid.ipv4_address = _n4.get_addr4();
    return RETURNok;
  }
  if (!IN6_IS_ADDR_UNSPECIFIED(&_n4.get_addr6())) {
    fseid.v6           = 1;
    fseid.ipv6_address = _n4.get_addr6();
    return RETURNok;
  }
  return RETURNerror;
}

//------------------------------------------------------------------------------
bool smf_config::is_dotted_dnn_handled(
    const std::string& dnn, const pdu_session_type_t& pdn_session_type) {
  Logger::smf_app().debug("Requested DNN: %s", dnn.c_str());

  for (const auto& it : dnns) {
    Logger::smf_app().debug(
        "DNN label: %s, dnn: %s", it.second.dnn_label.c_str(),
        it.second.dnn.c_str());
    if (dnn == it.second.dnn) {
      Logger::smf_app().debug("DNN matched!");
      Logger::smf_app().debug(
          "PDU Session Type %d, PDN Type %d", pdn_session_type.pdu_session_type,
          it.second.pdu_session_type.pdu_session_type);
      if (pdn_session_type.pdu_session_type ==
          it.second.pdu_session_type.pdu_session_type) {
        return true;
      }
    }
  }

  return false;
}

//------------------------------------------------------------------------------
std::string smf_config::get_default_dnn() {
  for (const auto& it : dnns) {
    Logger::smf_app().debug("Default DNN: %s", it.second.dnn.c_str());
    return it.second.dnn;
  }
  return "default";  // default DNN
}

//------------------------------------------------------------------------------
std::string smf_config::get_nwi(
    const pfcp::node_id_t& node_id, const iface_type& type) const {
  try {
    upf used_upf = get_upf(node_id);
    switch (type) {
      case iface_type::N3:
        return used_upf.get_upf_info().get_n3_nwi();
      case iface_type::N6:
        return used_upf.get_upf_info().get_n6_nwi();
      case iface_type::N9:
        Logger::smf_app().warn(
            "N9 interface type not supported for locally configured NWI");
        return "";
      default:
        Logger::smf_app().error("Unsupported enum parameter in get_nwi");
        return "";
    }
  } catch (invalid_argument&) {
  }
  return "";
}

void smf_config::to_smf_config() {
  log_level    = spdlog::level::from_str(config::log_level());
  auto smf_cfg = smf();

  use_local_subscription_info =
      smf_cfg->get_smf_support_features().use_local_subscription_info();
  use_local_pcc_rules =
      smf_cfg->get_smf_support_features().use_local_pcc_rules();

  register_nrf = config::register_nrf();
  // TODO discover PCF is not implemented
  discover_pcf = false;
  discover_upf = config::register_nrf();

  // we need to set some things (e.g. API version even if we do NRF
  // discovery...)
  amf_addr.from_sbi_config_type_no_resolving(
      get_nf(AMF_CONFIG_NAME)->get_sbi(), http_version);
  udm_addr.from_sbi_config_type_no_resolving(
      get_nf(UDM_CONFIG_NAME)->get_sbi(), http_version);

  if (get_nf(NRF_CONFIG_NAME)->is_set()) {
    nrf_addr.from_sbi_config_type(
        get_nf(NRF_CONFIG_NAME)->get_sbi(), http_version);
  }
  if (get_nf(AMF_CONFIG_NAME)->is_set()) {
    amf_addr.from_sbi_config_type(
        get_nf(AMF_CONFIG_NAME)->get_sbi(), http_version);
  }
  if (get_nf(UDM_CONFIG_NAME)->is_set()) {
    udm_addr.from_sbi_config_type(
        get_nf(UDM_CONFIG_NAME)->get_sbi(), http_version);
  }
  if (get_nf(PCF_CONFIG_NAME)->is_set()) {
    pcf_addr.from_sbi_config_type(
        get_nf(PCF_CONFIG_NAME)->get_sbi(), http_version);
  }

  local_interface _n4 = local().get_nx();

  n4.port    = _n4.get_port();
  n4.addr4   = _n4.get_addr4();
  n4.addr6   = local().get_nx().get_addr6();
  n4.if_name = local().get_nx().get_if_name();
  n4.mtu     = local().get_nx().get_mtu();

  // TODO these values are not configurable anymore
  sbi.thread_rd_sched_params.sched_priority   = 90;
  itti.itti_timer_sched_params.sched_priority = 85;
  itti.n4_sched_params.sched_priority         = 84;
  itti.smf_app_sched_params.sched_priority    = 84;
  itti.async_cmd_sched_params.sched_priority  = 84;
  n4.thread_rd_sched_params.sched_priority    = 90;

  force_push_pco = true;

  sbi.port        = smf_cfg->get_sbi().get_port();
  sbi.addr4       = smf_cfg->get_sbi().get_addr4();
  sbi.addr6       = smf_cfg->get_sbi().get_addr6();
  sbi.if_name     = smf_cfg->get_sbi().get_if_name();
  sbi_http2_port  = smf_cfg->get_sbi().get_port();
  sbi_api_version = smf_cfg->get_sbi().get_api_version();
  http_version    = get_http_version();

  default_dnsv4     = smf_cfg->get_ue_dns().get_primary_dns_v4();
  default_dns_secv4 = smf_cfg->get_ue_dns().get_secondary_dns_v4();
  default_dnsv6     = smf_cfg->get_ue_dns().get_primary_dns_v6();
  default_dns_secv6 = smf_cfg->get_ue_dns().get_secondary_dns_v6();

  default_cscfv4 = smf_cfg->get_ims_config().get_pcscf_v4();
  default_cscfv6 = smf_cfg->get_ims_config().get_pcscf_v6();

  ue_mtu = smf_cfg->get_ue_mtu();

  // UPF configuration
  // NWI is handled in get_nwi function directly from new configuration
  for (const auto& upf : smf_cfg->get_upfs()) {
    if (!discover_upf) {
      pfcp::node_id_t node_id;
      // Here we resolve the IP so that the Node ID Type is always V4
      in_addr ip              = resolve_nf(upf.get_host());
      node_id.u1.ipv4_address = ip;
      node_id.node_id_type    = pfcp::NODE_ID_TYPE_IPV4_ADDRESS;
      // Stefan: smf_app already checks if the UPF is present in configuration
      // and does not start association when receiving an NRF notification. WHY?
      // that should better be handled by the PFCP associations
      upfs.push_back(node_id);
    }

    // TODO here we just take the enable UR and enable DL in PFCP session
    // establishment from the last UPF we have to refactor PFCP association to
    // fix this
    enable_ur = upf.enable_usage_reporting();
    enable_dl_pdr_in_pfcp_sess_estab =
        upf.enable_dl_pdr_in_session_establishment();
  }
  logger::logger_registry::get_logger(LOGGER_NAME)
      .warn(
          "Enable UR and enable DL PDR in PFCP Session Establishment per UPF "
          "is not supported currently, we use the same values for all UPFs.");

  // DNNs
  for (const auto& cfg_dnn : get_dnns()) {
    dnn_t dnn;
    dnn.pdu_session_type     = cfg_dnn.get_pdu_session_type();
    dnn.dnn                  = cfg_dnn.get_dnn();
    dnn.ue_pool_range_low    = cfg_dnn.get_ipv4_pool_start();
    dnn.ue_pool_range_high   = cfg_dnn.get_ipv4_pool_end();
    dnn.paa_pool6_prefix     = cfg_dnn.get_ipv6_prefix();
    dnn.paa_pool6_prefix_len = cfg_dnn.get_ipv6_prefix_length();
    dnns[dnn.dnn]            = dnn;
  }
}

in_addr smf_config::resolve_nf(const std::string& host) {
  // we remove use_fqdn_dns towards the user, if it is an IPv4 we don't resolve
  std::regex re(IPV4_ADDRESS_VALIDATOR_REGEX);
  if (!std::regex_match(host, re)) {
    logger::logger_registry::get_logger(LOGGER_NAME)
        .info("Configured host %s is an FQDN. Resolve on SMF startup", host);
    std::string ip_address;
    // we ignore the port for now
    uint32_t port;
    uint8_t addr_type;
    fqdn::resolve(host, ip_address, port, addr_type);
    if (addr_type != 0) {
      // TODO:
      throw std::invalid_argument(fmt::format(
          "IPv6 is not supported at the moment. Please provide a valid IPv4 "
          "address in your DNS configuration for the host {}.",
          host));
    }
    return conv::fromString(ip_address);
  }
  return conv::fromString(host);
}

const upf& smf_config::get_upf(const pfcp::node_id_t& node_id) const {
  auto smf_cfg = smf();

  for (const auto& upf : smf_cfg->get_upfs()) {
    if (node_id.node_id_type == pfcp::NODE_ID_TYPE_FQDN &&
        node_id.fqdn == upf.get_host()) {
      return upf;
    } else if (node_id.node_id_type == pfcp::NODE_ID_TYPE_IPV4_ADDRESS) {
      in_addr configured_v4_address = conv::fromString(upf.get_host());
      if (configured_v4_address.s_addr &&
          configured_v4_address.s_addr == node_id.u1.ipv4_address.s_addr) {
        return upf;
      }
    } else if (node_id.node_id_type == pfcp::NODE_ID_TYPE_IPV6_ADDRESS) {
      in6_addr configured_v6_address = conv::fromStringV6(upf.get_host());
      if (!IN6_IS_ADDR_UNSPECIFIED(&configured_v6_address)) {
        return upf;
      }
    }
  }
  throw std::invalid_argument("UPF could not be found in configuration");
}

bool smf_config::init() {
  bool success = config::init();
  // if there is an error here, we print the configuration before throwing
  try {
    to_smf_config();
  } catch (std::exception&) {
    display();
    throw;
  }

  return success;
}

std::shared_ptr<smf_config_type> smf_config::smf() const {
  return std::dynamic_pointer_cast<smf_config_type>(get_local());
}

void smf_config::update_used_nfs() {
  config::update_used_nfs();
  if (config::register_nrf()) {
    if (!smf()->get_smf_support_features().use_local_pcc_rules()) {
      logger::logger_registry::get_logger(LOGGER_NAME)
          .warn("PCF NRF discovery not supported. Using the provided values");
      get_nf(PCF_CONFIG_NAME)->set_config();
    }
  }
  if (!smf()->get_smf_support_features().use_local_subscription_info()) {
    // here we remove the local subscription info
    smf()->get_subscription_info().clear();
    logger::logger_registry::get_logger(LOGGER_NAME)
        .warn("UDM NRF discovery not supported. Using the provided values");
    get_nf(UDM_CONFIG_NAME)->set_config();
    // TODO check if DNN from configuration is still used
  } else {
    get_nf(UDM_CONFIG_NAME)->unset_config();
  }
  if (smf()->get_smf_support_features().use_local_pcc_rules()) {
    get_nf(PCF_CONFIG_NAME)->unset_config();
  }
}

//------------------------------------------------------------------------------
void smf_config::to_json(nlohmann::json& json_data) const {
  json_data["instance"] = instance;

  json_data["interfaces"]["n4"]  = n4.to_json();
  json_data["interfaces"]["sbi"] = sbi.to_json();

  json_data["http2_port"]      = sbi_http2_port;
  json_data["sbi_api_version"] = sbi_api_version;

  json_data["dnn_list"] = nlohmann::json::array();
  for (auto s : dnns) {
    json_data["dnn_list"].push_back(s.second.to_json());
  }

  json_data["default_dns_ipv4_address"]     = inet_ntoa(default_dnsv4);
  json_data["default_dns_sec_ipv4_address"] = inet_ntoa(default_dns_secv4);
  json_data["default_dns_ipv6_address"]     = conv::toString(default_dnsv6);
  json_data["default_dns_sec_ipv6_address"] = conv::toString(default_dns_secv6);

  json_data["default_cscf_ipv4_address"] = inet_ntoa(default_cscfv4);
  json_data["default_cscf_ipv6_address"] = conv::toString(default_cscfv6);

  json_data["ue_mtu"] = ue_mtu;

  // TODO: change to support_features (?)
  json_data["supported_features"]["registered_nrf"] = register_nrf;
  json_data["supported_features"]["discover_upf"]   = discover_upf;
  json_data["supported_features"]["force_push_protocol_configuration_options"] =
      force_push_pco;
  json_data["supported_features"]["use_local_subscription_info"] =
      use_local_subscription_info;
  // json_data["supported_features"]["use_network_instance"]   = use_nwi;
  json_data["supported_features"]["enable_usage_reporting"] = enable_ur;
  json_data["supported_features"]["http_version"]           = http_version;

  if (register_nrf) {
    json_data["nrf"] = nrf_addr.to_json();
  }
  json_data["upf_list"] = nlohmann::json::array();
  for (auto s : upfs) {
    json_data["upf_list"].push_back(s.toString());
  }

  if (amf_addr.ipv4_addr.s_addr != INADDR_ANY) {
    json_data["amf"] = amf_addr.to_json();
  }
  if (udm_addr.ipv4_addr.s_addr != INADDR_ANY) {
    json_data["udm"] = udm_addr.to_json();
  }

  json_data["local_configuration"]["session_management_subscription_list"] =
      nlohmann::json::array();

  for (const auto& sub : smf()->get_subscription_info()) {
    nlohmann::json json_data_tmp = {};

    // PDU Session Type
    pdu_session_type_t pdu_session_type(
        pdu_session_type_e::PDU_SESSION_TYPE_E_IPV4);
    for (const auto& cfg_dnn : get_dnns()) {
      if (cfg_dnn.get_dnn() == sub.get_dnn()) {
        pdu_session_type = cfg_dnn.get_pdu_session_type();
      }
    }
    Logger::smf_app().debug(
        "Default session type %s", pdu_session_type.to_string());

    json_data_tmp["session_type"] = pdu_session_type.to_string();

    // SSC_Mode
    json_data_tmp["ssc_mode"] = sub.get_ssc_mode();

    // 5gQosProfile
    /*
    json_data_tmp["qos_profile"]["5qi"] = sub.get_default_qos()._5qi;
    dnn_configuration->_5g_qos_profile.arp.priority_level =
        sub.get_default_qos().arp.priority_level;
    dnn_configuration->_5g_qos_profile.arp.preempt_cap =
        sub.get_default_qos().arp.preempt_cap;
    dnn_configuration->_5g_qos_profile.arp.preempt_vuln =
        sub.get_default_qos().arp.preempt_vuln;
    dnn_configuration->_5g_qos_profile.priority_level =
        sub.get_default_qos().priority_level;

    // Session_ambr
    dnn_configuration->session_ambr.uplink = sub.get_session_ambr().uplink;
    dnn_configuration->session_ambr.downlink =
        sub.get_session_ambr().downlink;
    Logger::smf_app().debug(
        "Session AMBR Uplink %s, Downlink %s",
        dnn_configuration->session_ambr.uplink.c_str(),
        dnn_configuration->session_ambr.downlink.c_str());

*/
  }

  /*
    for (auto s : session_management_subscriptions) {
      json_data["local_configuration"]["session_management_subscription_list"]
          .push_back(s.to_json());
    }
  */

  for (auto s : upf_nwi_list) {
    json_data["upf_nwi_list"].push_back(s.to_json());
  }
}

//------------------------------------------------------------------------------
bool smf_config::from_json(nlohmann::json& json_data) {
  nlohmann::json json_missing = {}, json_tmp = {};
  oai::smf_server::model::ProblemDetails prob_details;

  // TODO: Branch on the Supported Features whenever possible

  try {
    if (json_data.find("supported_features") != json_data.end()) {
      json_tmp = json_data["supported_features"];

      if (json_tmp.find("use_local_subscription_info") != json_tmp.end())
        use_local_subscription_info =
            json_tmp["use_local_subscription_info"].get<bool>();

      // TODO: Check if VPP is used
      if (true and json_tmp.find("enable_usage_reporting") != json_tmp.end())
        enable_ur = json_tmp["enable_usage_reporting"].get<bool>();

      //  if (true and json_tmp.find("use_network_instance") != json_tmp.end())
      //    smf_cfg.use_nwi = json_tmp["use_network_instance"].get<bool>();
    }

    if (json_data.find("dnn_list") != json_data.end()) {
      for (auto s : json_data["dnn_list"]) {
        dnn_t dnn_item = {};
        dnn_item.from_json(s);
        std::map<std::string, dnn_t>::iterator it = dnns.find(dnn_item.dnn);
        if (it != dnns.end()) {
          // TODO: Check that the DNN is not used
          if (true) {
            it->second = dnn_item;
          }
        } else {
          // ADD a new one
          dnns.insert(std::pair<std::string, dnn_t>(dnn_item.dnn, dnn_item));
        }
      }
    }

    // TODO: Check that no UE is connected
    if (true) {
      if (json_data.find("default_dns_ipv4_address") != json_data.end()) {
        std::string addr =
            json_data["default_dns_ipv4_address"].get<std::string>();
        default_dnsv4 = conv::fromString(addr);
      }
      if (json_data.find("default_dns_ipv6_address") != json_data.end()) {
        std::string addr =
            json_data["default_dns_ipv6_address"].get<std::string>();
        unsigned char buf_in6_addr[sizeof(struct in6_addr)];
        if (inet_pton(AF_INET6, addr.c_str(), buf_in6_addr) == 1) {
          memcpy(&default_dnsv6, buf_in6_addr, sizeof(struct in6_addr));
          Logger::smf_app().info(
              "New Default DNS IPv6 address: %s",
              conv::toString(default_dnsv6));
        } else {
          Logger::smf_app().debug(
              "Failed to update DNS IPv6 address from %s to %s",
              conv::toString(default_dnsv6));
          json_tmp["default_dns_ipv6_address"] =
              json_data["default_dns_ipv6_address"];
          json_missing.push_back(json_tmp);
        }
      }
      if (json_data.find("default_dns_sec_ipv4_address") != json_data.end()) {
        std::string addr =
            json_data["default_dns_sec_ipv4_address"].get<std::string>();
        default_dns_secv4 = conv::fromString(addr);
      }
      if (json_data.find("default_dns_sec_ipv6_address") != json_data.end()) {
        std::string addr =
            json_data["default_dns_sec_ipv6_address"].get<std::string>();
        unsigned char buf_in6_addr[sizeof(struct in6_addr)];
        if (inet_pton(AF_INET6, addr.c_str(), buf_in6_addr) == 1) {
          memcpy(&default_dns_secv6, buf_in6_addr, sizeof(struct in6_addr));
          Logger::smf_app().info(
              "New Default DNS Sec IPv6 address: %s",
              conv::toString(default_dnsv6));
        } else {
          Logger::smf_app().debug(
              "Failed to update DNS Sec IPv6 address from %s to %s",
              conv::toString(default_dnsv6));
        }
      }
      if (json_data.find("default_cscf_ipv4_address") != json_data.end()) {
        std::string addr =
            json_data["default_cscf_ipv4_address"].get<std::string>();
        default_cscfv4 = conv::fromString(addr);
      }
      if (json_data.find("default_cscf_ipv6_address") != json_data.end()) {
        std::string addr =
            json_data["default_cscf_ipv6_address"].get<std::string>();
        unsigned char buf_in6_addr[sizeof(struct in6_addr)];
        if (inet_pton(AF_INET6, addr.c_str(), buf_in6_addr) == 1) {
          memcpy(&default_cscfv6, buf_in6_addr, sizeof(struct in6_addr));
          Logger::smf_app().info(
              "New Default CSCF IPv6 address: %s",
              conv::toString(default_dnsv6));
        } else {
          Logger::smf_app().debug(
              "Failed to update DNS Sec IPv6 address from %s to %s",
              conv::toString(default_dnsv6));
        }
      }

      if (json_data.find("ue_mtu") != json_data.end()) {
        ue_mtu = json_data["ue_mtu"].get<uint32_t>();
      }
    } else {
      // TODO: Add to json_missing the non-updatable fields from json_data (?)
    }

    if (!discover_upf && json_data.find("upf_list") != json_data.end()) {
      for (auto s : json_data["upf_list"]) {
        bool used                = false;
        std::string astring      = {};
        pfcp::node_id_t new_node = {};
        unsigned char buf_in_addr[sizeof(struct in_addr) + 1];
        // IPv4/6
        // TODO: Is IPv6 supported???
        astring               = s.get<std::string>();
        new_node.node_id_type = pfcp::NODE_ID_TYPE_IPV4_ADDRESS;
        if (inet_pton(AF_INET, util::trim(astring).c_str(), buf_in_addr) == 1) {
          memcpy(
              &new_node.u1.ipv4_address, buf_in_addr, sizeof(struct in_addr));
          for (auto upf : upfs) {
            if (new_node == upf) {
              used = true;
              break;
            }
          }
          if (!used) {
            upfs.push_back(new_node);
          }
        } else {
          Logger::smf_app().warn(
              "Failed to read UPF id in configuration update: %s", astring);
          // TODO: Add to ProblemDetails
        }
      }
    }
    /*
        if (json_data.find("local_configuration") != json_data.end()) {
          json_tmp = json_data["local_configuration"];
          if (json_tmp.find("session_management_subscription_list") !=
              json_tmp.end()) {
            for (auto s : json_tmp["session_management_subscription_list"]) {
              session_management_subscription_t new_sub = {};
              bool used                                 = false;
              new_sub.from_json(s);
              for (auto sub : smf_cfg.session_management_subscriptions) {
                if (!sub.dnn.compare(new_sub.dnn)) {
                  used = true;
                  break;
                }
              }
              if (!used) {
                smf_cfg.session_management_subscriptions.push_back(new_sub);
              }
            }
          }
        }
        */

  } catch (nlohmann::detail::exception& e) {
    Logger::smf_app().error(
        "Exception when reading configuration from json %s", e.what());
    return false;
  } catch (std::exception& e) {
    Logger::smf_app().error(
        "Exception when reading configuration from json %s", e.what());
    return false;
  }
  return true;
}
