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

/*! \file smf_n7.cpp
 \author  Stefan Spettel
 \company Openairinterface Software Alliance
 \date 2021
 \email: stefan.spettel@gmx.at
 */

#include "smf_n7.hpp"
#include "smf_config.hpp"
#include "fqdn.hpp"

using namespace smf;
using namespace smf::n7;
using namespace oai::smf_server::model;

extern smf_config smf_cfg;

bool smf_n7::discover_pcf(
    std::string& addr, std::string& api_version, const Snssai snssai,
    const PlmnId plmn_id, const std::string dnn) {
  if (smf_cfg.use_local_pcc_rules) {
    Logger::smf_n7().info("Local PCC rules are enabled, do not discover PCF");
    return false;
  }

  if (smf_cfg.discover_pcf) {
    return discover_pcf_with_nrf(addr, api_version, snssai, plmn_id, dnn);
  } else {
    return discover_pcf_from_config_file(
        addr, api_version, snssai, plmn_id, dnn);
  }
}

bool smf_n7::discover_pcf_with_nrf(
    std::string& addr, std::string& api_version, const Snssai snssai,
    const PlmnId plmn_id, const std::string dnn) {
  Logger::smf_n7().debug("Discover PCF with NRF");
  Logger::smf_n7().warn("NRF discovery not yet supported!");
  return false;
}

bool smf_n7::discover_pcf_from_config_file(
    std::string& addr, std::string& api_version, const Snssai snssai,
    const PlmnId plmn_id, const std::string dnn) {
  // TODO ignore snssai, plmn_id and dnn, because it is not part of
  // configuration
  Logger::smf_n7().debug("Discover PCF from config file");
  api_version = smf_cfg.pcf_addr.api_version;
  if (!smf_cfg.use_fqdn_dns) {
    // read config from config file
    addr = std::string(
        inet_ntoa(*((struct in_addr*) &smf_cfg.pcf_addr.ipv4_addr)));
    addr += ":" + std::to_string(smf_cfg.pcf_addr.port);
    return true;
  } else {
    Logger::smf_n7().debug(
        "Resolving %s with DNS", smf_cfg.pcf_addr.fqdn.c_str());
    // resolve IP address
    uint8_t addr_type     = 0;
    uint32_t pcf_port     = 0;
    std::string addr_temp = "";
    if (!fqdn::resolve(smf_cfg.fqdn, addr_temp, pcf_port, addr_type)) {
      Logger::smf_n7().warn("Could not resolve FQDN %s", smf_cfg.fqdn.c_str());
      return false;
    }

    if (addr_type != 0) {
      // TODO IPv6
      Logger::smf_n7().warn("IPv6 not supported for PCF address");
      return false;
    } else {
      if (smf_cfg.http_version == 2) {
        pcf_port = 8080;  // TODO this is not good to hardcode it here.
        // Shouldnt we be able to get this from the DNS query based on the
        // service?
      }
      addr = addr_temp + ":" + std::to_string(pcf_port);
      return true;
    }
  }
}
