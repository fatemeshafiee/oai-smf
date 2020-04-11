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

/*! \file smf_config.cpp
 \brief
 \author  Lionel GAUTHIER, Tien-Thinh NGUYEN
 \company Eurecom
 \date 2019
 \email: lionel.gauthier@eurecom.fr, tien-thinh.nguyen@eurecom.fr
 */

#include "smf_config.hpp"

#include <cstdlib>
#include <iomanip>
#include <iostream>
#include "string.hpp"

// C includes
#include <arpa/inet.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/split.hpp>
#include "3gpp_29.274.hpp"
#include "common_defs.h"
#include "epc.h"
#include "if.hpp"
#include "logger.hpp"
#include "smf_app.hpp"

using namespace std;
using namespace libconfig;
using namespace smf;

extern smf_app *smf_app_inst;
extern smf_config smf_cfg;

//------------------------------------------------------------------------------
int smf_config::finalize() {
  Logger::smf_app().info("Finalize config...");

  for (int i = 0; i < num_ue_pool; i++) {
    uint32_t range_low_hbo = ntohl(ue_pool_range_low[i].s_addr);
    uint32_t range_high_hbo = ntohl(ue_pool_range_high[i].s_addr);
    uint32_t tmp_hbo = range_low_hbo ^ range_high_hbo;
    uint8_t nbits = 32;
    while (tmp_hbo) {
      tmp_hbo = tmp_hbo >> 1;
      nbits -= 1;
    }
    uint32_t network_hbo = range_high_hbo & (UINT32_MAX << (32 - nbits));
    uint32_t netmask_hbo = 0xFFFFFFFF << (32 - nbits);
    ue_pool_network[i].s_addr = htonl(network_hbo);
    ue_pool_netmask[i].s_addr = htonl(netmask_hbo);
  }
  // "TODO"
  //pgw_pcef_emulation_init(config_pP);
  Logger::smf_app().info("Finalized config");
  return 0;
}

//------------------------------------------------------------------------------
int smf_config::load_thread_sched_params(const Setting &thread_sched_params_cfg, util::thread_sched_params &cfg) {

  try {
    thread_sched_params_cfg.lookupValue(SMF_CONFIG_STRING_THREAD_RD_CPU_ID, cfg.cpu_id);
  } catch (const SettingNotFoundException &nfex) {
    Logger::smf_app().info("%s : %s, using defaults", nfex.what(), nfex.getPath());
  }
  try {
    std::string thread_rd_sched_policy;
    thread_sched_params_cfg.lookupValue(SMF_CONFIG_STRING_THREAD_RD_SCHED_POLICY, thread_rd_sched_policy);
    util::trim(thread_rd_sched_policy);
    if (boost::iequals(thread_rd_sched_policy, "SCHED_OTHER")) {
      cfg.sched_policy = SCHED_OTHER;
    } else if (boost::iequals(thread_rd_sched_policy, "SCHED_IDLE")) {
      cfg.sched_policy = SCHED_IDLE;
    } else if (boost::iequals(thread_rd_sched_policy, "SCHED_BATCH")) {
      cfg.sched_policy = SCHED_BATCH;
    } else if (boost::iequals(thread_rd_sched_policy, "SCHED_FIFO")) {
      cfg.sched_policy = SCHED_FIFO;
    } else if (boost::iequals(thread_rd_sched_policy, "SCHED_RR")) {
      cfg.sched_policy = SCHED_RR;
    } else {
      Logger::smf_app().error("thread_rd_sched_policy: %s, unknown in config file", thread_rd_sched_policy.c_str());
      return RETURNerror ;
    }
  } catch (const SettingNotFoundException &nfex) {
    Logger::smf_app().info("%s : %s, using defaults", nfex.what(), nfex.getPath());
  }

  try {
    thread_sched_params_cfg.lookupValue(SMF_CONFIG_STRING_THREAD_RD_SCHED_PRIORITY, cfg.sched_priority);
    if ((cfg.sched_priority > 99) || (cfg.sched_priority < 1)) {
      Logger::smf_app().error("thread_rd_sched_priority: %d, must be in interval [1..99] in config file", cfg.sched_priority);
      return RETURNerror ;
    }
  } catch (const SettingNotFoundException &nfex) {
    Logger::smf_app().info("%s : %s, using defaults", nfex.what(), nfex.getPath());
  }
  return RETURNok ;
}
//------------------------------------------------------------------------------
int smf_config::load_itti(const Setting &itti_cfg, itti_cfg_t &cfg) {
  try {
    const Setting &itti_timer_sched_params_cfg = itti_cfg[SMF_CONFIG_STRING_ITTI_TIMER_SCHED_PARAMS];
    load_thread_sched_params(itti_timer_sched_params_cfg, cfg.itti_timer_sched_params);
  } catch (const SettingNotFoundException &nfex) {
    Logger::smf_app().info("%s : %s, using defaults", nfex.what(), nfex.getPath());
  }

  try {
    const Setting &n4_sched_params_cfg = itti_cfg[SMF_CONFIG_STRING_N4_SCHED_PARAMS];
    load_thread_sched_params(n4_sched_params_cfg, cfg.n4_sched_params);
  } catch (const SettingNotFoundException &nfex) {
    Logger::smf_app().info("%s : %s, using defaults", nfex.what(), nfex.getPath());
  }

  try {
    const Setting &smf_app_sched_params_cfg = itti_cfg[SMF_CONFIG_STRING_SMF_APP_SCHED_PARAMS];
    load_thread_sched_params(smf_app_sched_params_cfg, cfg.smf_app_sched_params);
  } catch (const SettingNotFoundException &nfex) {
    Logger::smf_app().info("%s : %s, using defaults", nfex.what(), nfex.getPath());
  }

  try {
    const Setting &async_cmd_sched_params_cfg = itti_cfg[SMF_CONFIG_STRING_ASYNC_CMD_SCHED_PARAMS];
    load_thread_sched_params(async_cmd_sched_params_cfg, cfg.async_cmd_sched_params);
  } catch (const SettingNotFoundException &nfex) {
    Logger::smf_app().info("%s : %s, using defaults", nfex.what(), nfex.getPath());
  }

  return RETURNok ;
}

//------------------------------------------------------------------------------
int smf_config::load_interface(const Setting &if_cfg, interface_cfg_t &cfg) {
  if_cfg.lookupValue(SMF_CONFIG_STRING_INTERFACE_NAME, cfg.if_name);
  util::trim(cfg.if_name);
  if (not boost::iequals(cfg.if_name, "none")) {
    std::string address = { };
    if_cfg.lookupValue(SMF_CONFIG_STRING_IPV4_ADDRESS, address);
    util::trim(address);
    if (boost::iequals(address, "read")) {
      if (get_inet_addr_infos_from_iface(cfg.if_name, cfg.addr4, cfg.network4, cfg.mtu)) {
        Logger::smf_app().error("Could not read %s network interface configuration", cfg.if_name);
        return RETURNerror ;
      }
    } else {
      std::vector<std::string> words;
      boost::split(words, address, boost::is_any_of("/"), boost::token_compress_on);
      if (words.size() != 2) {
        Logger::smf_app().error("Bad value " SMF_CONFIG_STRING_IPV4_ADDRESS " = %s in config file", address.c_str());
        return RETURNerror ;
      }
      unsigned char buf_in_addr[sizeof(struct in6_addr)];  // you never know...
      if (inet_pton(AF_INET, util::trim(words.at(0)).c_str(), buf_in_addr) == 1) {
        memcpy(&cfg.addr4, buf_in_addr, sizeof(struct in_addr));
      } else {
        Logger::smf_app().error("In conversion: Bad value " SMF_CONFIG_STRING_IPV4_ADDRESS " = %s in config file", util::trim(words.at(0)).c_str());
        return RETURNerror ;
      }
      cfg.network4.s_addr = htons(ntohs(cfg.addr4.s_addr) & 0xFFFFFFFF << (32 - std::stoi(util::trim(words.at(1)))));
    }
    if_cfg.lookupValue(SMF_CONFIG_STRING_PORT, cfg.port);

    try {
      const Setting &sched_params_cfg = if_cfg[SMF_CONFIG_STRING_SCHED_PARAMS];
      load_thread_sched_params(sched_params_cfg, cfg.thread_rd_sched_params);
    } catch (const SettingNotFoundException &nfex) {
      Logger::smf_app().info("%s : %s, using defaults", nfex.what(), nfex.getPath());
    }
  }
  return RETURNok ;
}

//------------------------------------------------------------------------------
int smf_config::load_upf_config(const Setting &if_cfg, test_upf_cfg_t &cfg) {
  std::string is_test = { };
  if_cfg.lookupValue(SMF_CONFIG_STRING_TEST_UPF_IS_TEST, is_test);
  util::trim(is_test);
  if (not boost::iequals(is_test, "none")) {
    cfg.is_test = atoi(is_test.c_str());

    std::string address = { };
    if_cfg.lookupValue(SMF_CONFIG_STRING_TEST_UPF_GNB_IPV4_ADDRESS, address);
    util::trim(address);
    inet_aton(address.c_str(), &cfg.gnb_addr4);
  }
  return RETURNok ;
}

//------------------------------------------------------------------------------
int smf_config::load(const string &config_file) {
  Config cfg;
  unsigned char buf_in6_addr[sizeof(struct in6_addr)];

  // Read the file. If there is an error, report it and exit.
  try {
    cfg.readFile(config_file.c_str());
  } catch (const FileIOException &fioex) {
    Logger::smf_app().error("I/O error while reading file %s - %s", config_file.c_str(), fioex.what());
    throw;
  } catch (const ParseException &pex) {
    Logger::smf_app().error("Parse error at %s:%d - %s", pex.getFile(), pex.getLine(), pex.getError());
    throw;
  }

  const Setting &root = cfg.getRoot();

  try {
    const Setting &smf_cfg = root[SMF_CONFIG_STRING_SMF_CONFIG];
  } catch (const SettingNotFoundException &nfex) {
    Logger::smf_app().error("%s : %s", nfex.what(), nfex.getPath());
    return RETURNerror ;
  }

  const Setting &smf_cfg = root[SMF_CONFIG_STRING_SMF_CONFIG];

  try {
    smf_cfg.lookupValue(SMF_CONFIG_STRING_INSTANCE, instance);
  } catch (const SettingNotFoundException &nfex) {
    Logger::smf_app().info("%s : %s, using defaults", nfex.what(), nfex.getPath());
  }

  try {
    smf_cfg.lookupValue(SMF_CONFIG_STRING_PID_DIRECTORY, pid_dir);
  } catch (const SettingNotFoundException &nfex) {
    Logger::smf_app().info("%s : %s, using defaults", nfex.what(), nfex.getPath());
  }

  try {
    const Setting &itti_cfg = smf_cfg[SMF_CONFIG_STRING_ITTI_TASKS];
    load_itti(itti_cfg, itti);
  } catch (const SettingNotFoundException &nfex) {
    Logger::smf_app().info("%s : %s, using defaults", nfex.what(), nfex.getPath());
  }

  try {
    const Setting &nw_if_cfg = smf_cfg[SMF_CONFIG_STRING_INTERFACES];

    const Setting &n4_cfg = nw_if_cfg[SMF_CONFIG_STRING_INTERFACE_N4];
    load_interface(n4_cfg, n4);

    const Setting &n11_cfg = nw_if_cfg[SMF_CONFIG_STRING_INTERFACE_SBI];
    load_interface(n11_cfg, sbi);

  } catch (const SettingNotFoundException &nfex) {
    Logger::smf_app().error("%s : %s", nfex.what(), nfex.getPath());
    return RETURNerror ;
  }

  try {
    string astring;

    const Setting &pool_cfg = smf_cfg[SMF_CONFIG_STRING_IP_ADDRESS_POOL];

    const Setting &ipv4_pool_cfg = pool_cfg[SMF_CONFIG_STRING_IPV4_ADDRESS_LIST];
    int count = ipv4_pool_cfg.getLength();
    for (int i = 0; i < count; i++) {
      const Setting &ipv4_cfg = ipv4_pool_cfg[i];
      string ipv4_range;
      unsigned char buf_in_addr[sizeof(struct in_addr)];

      ipv4_cfg.lookupValue(SMF_CONFIG_STRING_RANGE, ipv4_range);
      std::vector<std::string> ips;
      boost::split(ips, ipv4_range, boost::is_any_of(SMF_CONFIG_STRING_IPV4_ADDRESS_RANGE_DELIMITER), boost::token_compress_on);
      if (ips.size() != 2) {
        Logger::smf_app().error("Bad value %s : %s in config file %s", SMF_CONFIG_STRING_IPV4_ADDRESS_RANGE_DELIMITER, ipv4_range.c_str(), config_file.c_str());
        throw("Bad value %s : %s in config file %s", SMF_CONFIG_STRING_IPV4_ADDRESS_RANGE_DELIMITER, ipv4_range.c_str(), config_file.c_str());
      }

      memset(buf_in_addr, 0, sizeof(buf_in_addr));
      if (inet_pton(AF_INET, util::trim(ips.at(0)).c_str(), buf_in_addr) == 1) {
        memcpy(&ue_pool_range_low[num_ue_pool], buf_in_addr, sizeof(struct in_addr));
      } else {
        Logger::smf_app().error("CONFIG POOL ADDR IPV4: BAD LOWER ADDRESS in " SMF_CONFIG_STRING_IPV4_ADDRESS_LIST " pool %d", i);
        throw("CONFIG POOL ADDR IPV4: BAD ADDRESS in " SMF_CONFIG_STRING_IPV4_ADDRESS_LIST);
      }

      memset(buf_in_addr, 0, sizeof(buf_in_addr));
      if (inet_pton(AF_INET, util::trim(ips.at(1)).c_str(), buf_in_addr) == 1) {
        memcpy(&ue_pool_range_high[num_ue_pool], buf_in_addr, sizeof(struct in_addr));
      } else {
        Logger::smf_app().error("CONFIG POOL ADDR IPV4: BAD HIGHER ADDRESS in " SMF_CONFIG_STRING_IPV4_ADDRESS_LIST " pool %d", i);
        throw("CONFIG POOL ADDR IPV4: BAD ADDRESS in " SMF_CONFIG_STRING_IPV4_ADDRESS_LIST);
      }
      if (htonl(ue_pool_range_low[num_ue_pool].s_addr) >= htonl(ue_pool_range_high[num_ue_pool].s_addr)) {
        Logger::smf_app().error("CONFIG POOL ADDR IPV4: BAD RANGE in " SMF_CONFIG_STRING_IPV4_ADDRESS_LIST " pool %d", i);
        throw("CONFIG POOL ADDR IPV4: BAD RANGE in " SMF_CONFIG_STRING_IPV4_ADDRESS_LIST);
      }
      num_ue_pool += 1;
    }

    const Setting &ipv6_pool_cfg = pool_cfg[SMF_CONFIG_STRING_IPV6_ADDRESS_LIST];
    int count6 = ipv6_pool_cfg.getLength();
    for (int i = 0; i < count6; i++) {
      const Setting &ipv6_cfg = ipv6_pool_cfg[i];
      string ipv6_prefix;
      ipv6_cfg.lookupValue(SMF_CONFIG_STRING_PREFIX, ipv6_prefix);
      std::vector<std::string> ips6;
      boost::split(ips6, ipv6_prefix, boost::is_any_of(SMF_CONFIG_STRING_IPV6_ADDRESS_PREFIX_DELIMITER), boost::token_compress_on);
      if (ips6.size() != 2) {
        Logger::smf_app().error("Bad value %s : %s in config file %s", SMF_CONFIG_STRING_PREFIX, ipv6_prefix.c_str(), config_file.c_str());
        throw("Bad value %s : %s in config file %s", SMF_CONFIG_STRING_PREFIX, ipv6_prefix.c_str(), config_file.c_str());
      }

      std::string addr = ips6.at(0);
      util::trim(addr);
      if (inet_pton(AF_INET6, addr.c_str(), buf_in6_addr) == 1) {
        memcpy(&paa_pool6_prefix[num_paa6_pool], buf_in6_addr, sizeof(struct in6_addr));
      } else {
        Logger::smf_app().error("CONFIG POOL ADDR IPV6: BAD ADDRESS in " SMF_CONFIG_STRING_IPV6_ADDRESS_LIST " pool %d", i);
        throw("CONFIG POOL ADDR IPV6: BAD ADDRESS in " SMF_CONFIG_STRING_IPV6_ADDRESS_LIST);
      }

      std::string prefix = ips6.at(1);
      util::trim(prefix);
      paa_pool6_prefix_len[num_paa6_pool] = std::stoi(prefix);
      num_paa6_pool += 1;
    }

    const Setting &apn_list_cfg = smf_cfg[SMF_CONFIG_STRING_APN_LIST];
    count = apn_list_cfg.getLength();
    int apn_idx = 0;
    num_apn = 0;
    for (int i = 0; i < count; i++) {
      const Setting &apn_cfg = apn_list_cfg[i];
      apn_cfg.lookupValue(SMF_CONFIG_STRING_APN_NI, astring);
      apn[apn_idx].apn = astring;
      apn[apn_idx].apn_label = EPC::Utility::apn_label(astring);
      apn_cfg.lookupValue(SMF_CONFIG_STRING_PDN_TYPE, astring);
      if (boost::iequals(astring, "IPv4")) {
        apn[apn_idx].pdn_type.pdn_type = PDN_TYPE_E_IPV4;
      } else if (boost::iequals(astring, "IPv6") == 0) {
        apn[apn_idx].pdn_type.pdn_type = PDN_TYPE_E_IPV6;
      } else if (boost::iequals(astring, "IPv4IPv6") == 0) {
        apn[apn_idx].pdn_type.pdn_type = PDN_TYPE_E_IPV4V6;
      } else if (boost::iequals(astring, "Non-IP") == 0) {
        apn[apn_idx].pdn_type.pdn_type = PDN_TYPE_E_NON_IP;
      } else {
        Logger::smf_app().error(" " SMF_CONFIG_STRING_PDN_TYPE " in %d'th APN :%s", i + 1, astring.c_str());
        throw("Error PDN_TYPE in config file");
      }
      apn_cfg.lookupValue(SMF_CONFIG_STRING_IPV4_POOL, apn[apn_idx].pool_id_iv4);
      apn_cfg.lookupValue(SMF_CONFIG_STRING_IPV6_POOL, apn[apn_idx].pool_id_iv6);

      if ((0 <= apn[apn_idx].pool_id_iv4) && (apn[apn_idx].pdn_type.pdn_type == PDN_TYPE_E_IPV6)) {
        Logger::smf_app().error("PDN_TYPE versus pool identifier %d 'th APN in config file", i + 1);
        throw("PDN_TYPE versus pool identifier APN");
      }
      if ((0 <= apn[apn_idx].pool_id_iv6) && (apn[apn_idx].pdn_type.pdn_type == PDN_TYPE_E_IPV4)) {
        Logger::smf_app().error("PDN_TYPE versus pool identifier %d 'th APN in config file", i + 1);
        throw("PDN_TYPE versus pool identifier APN");
      }

      if (((0 <= apn[apn_idx].pool_id_iv4) || (0 <= apn[apn_idx].pool_id_iv6)) && (not boost::iequals(apn[apn_idx].apn, "none"))) {
        bool doublon = false;
        for (int j = 0; j < apn_idx; j++) {
          if (boost::iequals(apn[j].apn, apn[apn_idx].apn)) {
            doublon = true;
            Logger::smf_app().info("%d'th APN %s already found in config file (%d 'th APN %s), bypassing", i + 1, apn[apn_idx].apn.c_str(), j + 1, apn[j].apn.c_str());
          }
        }
        if (not doublon) {
          apn_idx++;
          num_apn++;
        }
      } else {
        Logger::smf_app().error("Bypass %d'th APN %s in config file", i + 1, apn[apn_idx].apn.c_str());
      }
    }
    smf_cfg.lookupValue(SMF_CONFIG_STRING_DEFAULT_DNS_IPV4_ADDRESS, astring);
    IPV4_STR_ADDR_TO_INADDR(util::trim(astring).c_str(), default_dnsv4, "BAD IPv4 ADDRESS FORMAT FOR DEFAULT DNS !");

    smf_cfg.lookupValue(SMF_CONFIG_STRING_DEFAULT_DNS_SEC_IPV4_ADDRESS, astring);
    IPV4_STR_ADDR_TO_INADDR(util::trim(astring).c_str(), default_dns_secv4, "BAD IPv4 ADDRESS FORMAT FOR DEFAULT DNS !");

    smf_cfg.lookupValue(SMF_CONFIG_STRING_DEFAULT_DNS_IPV6_ADDRESS, astring);
    if (inet_pton(AF_INET6, util::trim(astring).c_str(), buf_in6_addr) == 1) {
      memcpy(&default_dnsv6, buf_in6_addr, sizeof(struct in6_addr));
    } else {
      Logger::smf_app().error("CONFIG : BAD ADDRESS in " SMF_CONFIG_STRING_DEFAULT_DNS_IPV6_ADDRESS " %s", astring.c_str());
      throw("CONFIG : BAD ADDRESS in " SMF_CONFIG_STRING_DEFAULT_DNS_IPV6_ADDRESS " %s", astring.c_str());
    }
    smf_cfg.lookupValue(SMF_CONFIG_STRING_DEFAULT_DNS_SEC_IPV6_ADDRESS, astring);
    if (inet_pton(AF_INET6, util::trim(astring).c_str(), buf_in6_addr) == 1) {
      memcpy(&default_dns_secv6, buf_in6_addr, sizeof(struct in6_addr));
    } else {
      Logger::smf_app().error("CONFIG : BAD ADDRESS in " SMF_CONFIG_STRING_DEFAULT_DNS_SEC_IPV6_ADDRESS " %s", astring.c_str());
      throw("CONFIG : BAD ADDRESS in " SMF_CONFIG_STRING_DEFAULT_DNS_SEC_IPV6_ADDRESS " %s", astring.c_str());
    }

    smf_cfg.lookupValue(SMF_CONFIG_STRING_NAS_FORCE_PUSH_PCO, astring);
    if (boost::iequals(astring, "yes")) {
      force_push_pco = true;
    } else {
      force_push_pco = false;
    }
    smf_cfg.lookupValue(SMF_CONFIG_STRING_UE_MTU, ue_mtu);

    const Setting &pcef_cfg = smf_cfg[SMF_CONFIG_STRING_PCEF];
    unsigned int apn_ambr = 0;
    if (!(pcef_cfg.lookupValue(SMF_CONFIG_STRING_APN_AMBR_UL, apn_ambr))) {
      Logger::smf_app().error(SMF_CONFIG_STRING_APN_AMBR_UL "failed");
      throw(SMF_CONFIG_STRING_APN_AMBR_UL "failed");
    }
    pcef.apn_ambr_ul = apn_ambr;
    if (!(pcef_cfg.lookupValue(SMF_CONFIG_STRING_APN_AMBR_DL, apn_ambr))) {
      Logger::smf_app().error(SMF_CONFIG_STRING_APN_AMBR_DL "failed");
      //throw (SMF_CONFIG_STRING_APN_AMBR_DL "failed");
    }
    pcef.apn_ambr_dl = apn_ambr;

    const Setting &amf_cfg = smf_cfg[SMF_CONFIG_STRING_AMF];
    struct in_addr amf_ipv4_addr;
    unsigned int amf_port = 0;
    amf_cfg.lookupValue(SMF_CONFIG_STRING_AMF_IPV4_ADDRESS, astring);
    IPV4_STR_ADDR_TO_INADDR(util::trim(astring).c_str(), amf_ipv4_addr, "BAD IPv4 ADDRESS FORMAT FOR AMF !");
    amf_addr.ipv4_addr = amf_ipv4_addr;
    if (!(amf_cfg.lookupValue(SMF_CONFIG_STRING_AMF_PORT, amf_port))) {
      Logger::smf_app().error(SMF_CONFIG_STRING_AMF_PORT "failed");
      throw(SMF_CONFIG_STRING_AMF_PORT "failed");
    }
    amf_addr.port = amf_port;

    const Setting &udm_cfg = smf_cfg[SMF_CONFIG_STRING_UDM];
    struct in_addr udm_ipv4_addr;
    unsigned int udm_port = 0;
    udm_cfg.lookupValue(SMF_CONFIG_STRING_UDM_IPV4_ADDRESS, astring);
    IPV4_STR_ADDR_TO_INADDR(util::trim(astring).c_str(), udm_ipv4_addr, "BAD IPv4 ADDRESS FORMAT FOR UDM !");
    udm_addr.ipv4_addr = udm_ipv4_addr;
    if (!(udm_cfg.lookupValue(SMF_CONFIG_STRING_UDM_PORT, udm_port))) {
      Logger::smf_app().error(SMF_CONFIG_STRING_UDM_PORT "failed");
      throw(SMF_CONFIG_STRING_UDM_PORT "failed");
    }
    udm_addr.port = udm_port;

    //UPF list
    unsigned char buf_in_addr[sizeof(struct in_addr) + 1];
    const Setting &upf_list_cfg = smf_cfg[SMF_CONFIG_STRING_UPF_LIST];
    count = upf_list_cfg.getLength();
    for (int i = 0; i < count; i++) {
      const Setting &upf_cfg = upf_list_cfg[i];

      string address = { };
      if (upf_cfg.lookupValue(SMF_CONFIG_STRING_UPF_IPV4_ADDRESS, address)) {
        pfcp::node_id_t n = { };
        n.node_id_type = pfcp::NODE_ID_TYPE_IPV4_ADDRESS;  // actually
        if (inet_pton(AF_INET, util::trim(address).c_str(), buf_in_addr) == 1) {
          memcpy(&n.u1.ipv4_address, buf_in_addr, sizeof(struct in_addr));
        } else {
          Logger::smf_app().error("CONFIG: BAD IPV4 ADDRESS in " SMF_CONFIG_STRING_UPF_LIST " item %d", i);
          throw("CONFIG: BAD ADDRESS in " SMF_CONFIG_STRING_UPF_LIST);
        }
        upfs.push_back(n);
      } else {
        // TODO IPV6_ADDRESS, FQDN
        throw("Bad value in section %s : item no %d in config file %s", SMF_CONFIG_STRING_UPF_LIST, i, config_file.c_str());
      }
    }
  } catch (const SettingNotFoundException &nfex) {
    Logger::smf_app().error("%s : %s", nfex.what(), nfex.getPath());
    return RETURNerror ;
  }
  return finalize();
}

//------------------------------------------------------------------------------
void smf_config::display() {
  Logger::smf_app().info("==== EURECOM %s v%s ====", PACKAGE_NAME, PACKAGE_VERSION);
  Logger::smf_app().info("Configuration SMF:");
  Logger::smf_app().info("- Instance ..............: %d\n", instance);
  Logger::smf_app().info("- PID dir ...............: %s\n", pid_dir.c_str());

  Logger::smf_app().info("- N4 Networking:");
  Logger::smf_app().info("    iface ................: %s", n4.if_name.c_str());
  Logger::smf_app().info("    ip ...................: %s", inet_ntoa(n4.addr4));
  Logger::smf_app().info("    port .................: %d", n4.port);

  Logger::smf_app().info("- SBI Networking:");
  Logger::smf_app().info("    iface ................: %s", sbi.if_name.c_str());
  Logger::smf_app().info("    ip ...................: %s", inet_ntoa(sbi.addr4));
  Logger::smf_app().info("    port .................: %d", sbi.port);

  Logger::smf_app().info("- N4 Threading:");
  Logger::smf_app().info("    CPU id............: %d", n4.thread_rd_sched_params.cpu_id);
  Logger::smf_app().info("    Scheduling policy : %d", n4.thread_rd_sched_params.sched_policy);
  Logger::smf_app().info("    Scheduling prio  .: %d", n4.thread_rd_sched_params.sched_priority);

  Logger::smf_app().info("- ITTI Timer Task Threading:");
  Logger::smf_app().info("    CPU id............: %d", itti.itti_timer_sched_params.cpu_id);
  Logger::smf_app().info("    Scheduling policy : %d", itti.itti_timer_sched_params.sched_policy);
  Logger::smf_app().info("    Scheduling prio  .: %d", itti.itti_timer_sched_params.sched_priority);
  Logger::smf_app().info("- ITTI N4 Task Threading:");
  Logger::smf_app().info("    CPU id............: %d", itti.n4_sched_params.cpu_id);
  Logger::smf_app().info("    Scheduling policy : %d", itti.n4_sched_params.sched_policy);
  Logger::smf_app().info("    Scheduling prio  .: %d", itti.n4_sched_params.sched_priority);
  Logger::smf_app().info("- ITTI SMF_APP task Threading:");
  Logger::smf_app().info("    CPU id............: %d", itti.smf_app_sched_params.cpu_id);
  Logger::smf_app().info("    Scheduling policy : %d", itti.smf_app_sched_params.sched_policy);
  Logger::smf_app().info("    Scheduling prio  .: %d", itti.smf_app_sched_params.sched_priority);
  Logger::smf_app().info("- ITTI ASYNC_CMD task Threading:");
  Logger::smf_app().info("    CPU id............: %d", itti.async_cmd_sched_params.cpu_id);
  Logger::smf_app().info("    Scheduling policy : %d", itti.async_cmd_sched_params.sched_policy);
  Logger::smf_app().info("    Scheduling prio  .: %d", itti.async_cmd_sched_params.sched_priority);
  Logger::smf_app().info("- " SMF_CONFIG_STRING_IP_ADDRESS_POOL ":");
  for (int i = 0; i < num_ue_pool; i++) {
    std::string range_low(inet_ntoa(ue_pool_range_low[apn[i].pool_id_iv4]));
    std::string range_high(inet_ntoa(ue_pool_range_high[apn[i].pool_id_iv4]));
    Logger::smf_app().info("    IPv4 pool %d ..........: %s - %s", i, range_low.c_str(), range_high.c_str());
  }
  char str_addr6[INET6_ADDRSTRLEN];
  for (int i = 0; i < num_paa6_pool; i++) {
    if (inet_ntop(AF_INET6, &paa_pool6_prefix[i], str_addr6, sizeof(str_addr6))) {
      Logger::smf_app().info("    IPv6 pool %d ..........: %s / %d", i, str_addr6, paa_pool6_prefix_len[i]);
    }
  }
  Logger::smf_app().info("- DEFAULT DNS:");
  Logger::smf_app().info("    Primary DNS ..........: %s", inet_ntoa(*((struct in_addr*) &default_dnsv4)));
  Logger::smf_app().info("    Secondary DNS ........: %s", inet_ntoa(*((struct in_addr*) &default_dns_secv4)));
  if (inet_ntop(AF_INET6, &default_dnsv6, str_addr6, sizeof(str_addr6))) {
    Logger::smf_app().info("    Primary DNS v6........: %s", str_addr6);
  }
  if (inet_ntop(AF_INET6, &default_dns_secv6, str_addr6, sizeof(str_addr6))) {
    Logger::smf_app().info("    Secondary DNS v6 .....: %s", str_addr6);
  }

  Logger::smf_app().info("- " SMF_CONFIG_STRING_APN_LIST ":");
  for (int i = 0; i < num_apn; i++) {
    Logger::smf_app().info("    APN %d:", i);
    Logger::smf_app().info("        " SMF_CONFIG_STRING_APN_NI ":  %s", apn[i].apn.c_str());
    Logger::smf_app().info("        " SMF_CONFIG_STRING_PDN_TYPE ":  %s", apn[i].pdn_type.toString().c_str());
    if (apn[i].pool_id_iv4 >= 0) {
      std::string range_low(inet_ntoa(ue_pool_range_low[apn[i].pool_id_iv4]));
      std::string range_high(inet_ntoa(ue_pool_range_high[apn[i].pool_id_iv4]));
      Logger::smf_app().info("        " SMF_CONFIG_STRING_IPV4_POOL ":  %d ( %s - %s)", apn[i].pool_id_iv4, range_low.c_str(), range_high.c_str());
    }
    if (apn[i].pool_id_iv6 >= 0) {
      Logger::smf_app().info("        " SMF_CONFIG_STRING_IPV6_POOL ":  %d", apn[i].pool_id_iv6);
    }
  }
  Logger::smf_app().info("- PCEF support (in development)");
  Logger::smf_app().info("    APN AMBR UL ..........: %lu  (Kilo bits/s)", pcef.apn_ambr_ul);
  Logger::smf_app().info("    APN AMBR DL ..........: %lu  (Kilo bits/s)", pcef.apn_ambr_dl);
  Logger::smf_app().info("- Helpers:");
  Logger::smf_app().info("    Push PCO (DNS+MTU) ........: %s", force_push_pco == 0 ? "false" : "true");

  Logger::smf_app().info("    AMF Address..........: %s", inet_ntoa(*((struct in_addr*) &amf_addr.ipv4_addr)));
  Logger::smf_app().info("    AMF Port  ..........: %lu  ", amf_addr.port);
  Logger::smf_app().info("    UDM ..........: %s", inet_ntoa(*((struct in_addr*) &udm_addr.ipv4_addr)));
  Logger::smf_app().info("    UDM Port  ..........: %lu  ", udm_addr.port);

  Logger::smf_app().info("- UPF support (test upf)");
  Logger::smf_app().info("       UPF is test ..........: %lu  ", test_upf_cfg.is_test);
  Logger::smf_app().info("       Gnb Address ..........: %s", inet_ntoa(*((struct in_addr*) &test_upf_cfg.gnb_addr4)));

}

//------------------------------------------------------------------------------
bool smf_config::is_dotted_apn_handled(const string &apn, const pdn_type_t &pdn_type) {
  for (int i = 0; i < smf_cfg.num_apn; i++) {
    if (0 == apn.compare(smf_cfg.apn[i].apn_label)) {
      // TODO refine
      if (pdn_type.pdn_type == smf_cfg.apn[i].pdn_type.pdn_type) {
        return true;
      }
    }
  }
  return false;
}

//------------------------------------------------------------------------------
int smf_config::get_pfcp_node_id(pfcp::node_id_t &node_id) {
  node_id = { };
  if (n4.addr4.s_addr) {
    node_id.node_id_type = pfcp::NODE_ID_TYPE_IPV4_ADDRESS;
    node_id.u1.ipv4_address = n4.addr4;
    return RETURNok ;
  }
  if (n4.addr6.s6_addr32[0] | n4.addr6.s6_addr32[1] | n4.addr6.s6_addr32[2] | n4.addr6.s6_addr32[3]) {
    node_id.node_id_type = pfcp::NODE_ID_TYPE_IPV6_ADDRESS;
    node_id.u1.ipv6_address = n4.addr6;
    return RETURNok ;
  }
  return RETURNerror ;
}
//------------------------------------------------------------------------------
int smf_config::get_pfcp_fseid(pfcp::fseid_t &fseid) {
  int rc = RETURNerror;
  fseid = { };
  if (n4.addr4.s_addr) {
    fseid.v4 = 1;
    fseid.ipv4_address = n4.addr4;
    rc = RETURNok;
  }
  if (n4.addr6.s6_addr32[0] | n4.addr6.s6_addr32[1] | n4.addr6.s6_addr32[2] | n4.addr6.s6_addr32[3]) {
    fseid.v6 = 1;
    fseid.ipv6_address = n4.addr6;
    rc = RETURNok;
  }
  return rc;
}

//------------------------------------------------------------------------------
smf_config::~smf_config() {
}

//------------------------------------------------------------------------------
bool smf_config::is_dotted_dnn_handled(const std::string &dnn, const pdu_session_type_t &pdn_session_type) {
  Logger::smf_app().debug("requested dnn: %s", dnn.c_str());
  for (int i = 0; i < smf_cfg.num_apn; i++) {
    Logger::smf_app().debug("apn_label: %s, apn: %s", smf_cfg.apn[i].apn_label.c_str(), smf_cfg.apn[i].apn.c_str());
    //if (0 == dnn.compare(smf_cfg.apn[i].apn_label)) {
    if (0 == dnn.compare(smf_cfg.apn[i].apn)) {
      Logger::smf_app().debug("DNN matched!");
      Logger::smf_app().debug("pdu session type %d, pdn_type %d", pdn_session_type.pdu_session_type, smf_cfg.apn[i].pdn_type.pdn_type);
      if (pdn_session_type.pdu_session_type == smf_cfg.apn[i].pdn_type.pdn_type) {
        return true;
      }
    }
  }
  return false;
}

//------------------------------------------------------------------------------
std::string smf_config::get_default_dnn() {
  Logger::smf_app().debug("Default DNN: %s", smf_cfg.apn[0].apn.c_str());
  return smf_cfg.apn[0].apn;
}

