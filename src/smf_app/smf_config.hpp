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

/*! \file smf_config.hpp
 * \brief
  \author  Lionel GAUTHIER, Tien-Thinh NGUYEN
  \company Eurecom
  \date 2019
  \email: lionel.gauthier@eurecom.fr, tien-thinh.nguyen@eurecom.fr
 */

#ifndef FILE_SMF_CONFIG_HPP_SEEN
#define FILE_SMF_CONFIG_HPP_SEEN

#include <arpa/inet.h>
#include <libconfig.h++>
#include <netinet/in.h>
#include <sys/socket.h>

#include <mutex>
#include <vector>
#include "thread_sched.hpp"

#include "3gpp_29.244.h"
#include "3gpp_29.274.h"
#include "gtpv2c.hpp"
#include "pfcp.hpp"
#include "smf.h"


#define SMF_CONFIG_STRING_SMF_CONFIG                            "SMF"
#define SMF_CONFIG_STRING_PID_DIRECTORY                         "PID_DIRECTORY"
#define SMF_CONFIG_STRING_INSTANCE                              "INSTANCE"
#define SMF_CONFIG_STRING_INTERFACES                            "INTERFACES"
#define SMF_CONFIG_STRING_INTERFACE_NAME                        "INTERFACE_NAME"
#define SMF_CONFIG_STRING_IPV4_ADDRESS                          "IPV4_ADDRESS"
#define SMF_CONFIG_STRING_PORT                                  "PORT"
#define SMF_CONFIG_STRING_INTERFACE_N4                          "N4"
#define SMF_CONFIG_STRING_INTERFACE_N11                          "N11"

#define SMF_CONFIG_STRING_SMF_MASQUERADE_SGI                    "PGW_MASQUERADE_SGI"
#define SMF_CONFIG_STRING_UE_TCP_MSS_CLAMPING                   "UE_TCP_MSS_CLAMPING"
#define SMF_CONFIG_STRING_NAS_FORCE_PUSH_PCO                    "FORCE_PUSH_PROTOCOL_CONFIGURATION_OPTIONS"

#define SMF_CONFIG_STRING_IP_ADDRESS_POOL                       "IP_ADDRESS_POOL"
#define SMF_CONFIG_STRING_ARP_UE                                "ARP_UE"
#define SMF_CONFIG_STRING_ARP_UE_CHOICE_NO                      "NO"
#define SMF_CONFIG_STRING_ARP_UE_CHOICE_LINUX                   "LINUX"
#define SMF_CONFIG_STRING_ARP_UE_CHOICE_OAI                     "OAI"
#define SMF_CONFIG_STRING_IPV4_ADDRESS_LIST                     "IPV4_LIST"
#define SMF_CONFIG_STRING_IPV6_ADDRESS_LIST                     "IPV6_LIST"
#define SMF_CONFIG_STRING_RANGE                                 "RANGE"
#define SMF_CONFIG_STRING_PREFIX                                "PREFIX"
#define SMF_CONFIG_STRING_IPV4_ADDRESS_RANGE_DELIMITER          "-"
#define SMF_CONFIG_STRING_IPV6_ADDRESS_PREFIX_DELIMITER         "/"
#define SMF_CONFIG_STRING_DEFAULT_DNS_IPV4_ADDRESS              "DEFAULT_DNS_IPV4_ADDRESS"
#define SMF_CONFIG_STRING_DEFAULT_DNS_SEC_IPV4_ADDRESS          "DEFAULT_DNS_SEC_IPV4_ADDRESS"
#define SMF_CONFIG_STRING_DEFAULT_DNS_IPV6_ADDRESS              "DEFAULT_DNS_IPV6_ADDRESS"
#define SMF_CONFIG_STRING_DEFAULT_DNS_SEC_IPV6_ADDRESS          "DEFAULT_DNS_SEC_IPV6_ADDRESS"
#define SMF_CONFIG_STRING_UE_MTU                                "UE_MTU"
#define SMF_CONFIG_STRING_GTPV1U_REALIZATION                    "GTPV1U_REALIZATION"
#define SMF_CONFIG_STRING_NO_GTP_KERNEL_AVAILABLE               "NO_GTP_KERNEL_AVAILABLE"
#define SMF_CONFIG_STRING_GTP_KERNEL_MODULE                     "GTP_KERNEL_MODULE"
#define SMF_CONFIG_STRING_GTP_KERNEL                            "GTP_KERNEL"

#define SMF_CONFIG_STRING_INTERFACE_DISABLED                    "none"

#define SMF_CONFIG_STRING_APN_LIST                              "APN_LIST"
#define SMF_CONFIG_STRING_APN_NI                                "APN_NI"
#define SMF_CONFIG_STRING_PDN_TYPE                              "PDN_TYPE"
#define SMF_CONFIG_STRING_IPV4_POOL                             "IPV4_POOL"
#define SMF_CONFIG_STRING_IPV6_POOL                             "IPV6_POOL"

#define SMF_CONFIG_STRING_PCEF                                  "PCEF"
#define SMF_CONFIG_STRING_PCEF_ENABLED                          "PCEF_ENABLED"
#define SMF_CONFIG_STRING_TCP_ECN_ENABLED                       "TCP_ECN_ENABLED"
#define SMF_CONFIG_STRING_AUTOMATIC_PUSH_DEDICATED_BEARER_PCC_RULE  "AUTOMATIC_PUSH_DEDICATED_BEARER_PCC_RULE"
#define SMF_CONFIG_STRING_DEFAULT_BEARER_STATIC_PCC_RULE        "DEFAULT_BEARER_STATIC_PCC_RULE"
#define SMF_CONFIG_STRING_PUSH_STATIC_PCC_RULES                 "PUSH_STATIC_PCC_RULES"
#define SMF_CONFIG_STRING_APN_AMBR_UL                           "APN_AMBR_UL"
#define SMF_CONFIG_STRING_APN_AMBR_DL                           "APN_AMBR_DL"
#define SMF_ABORT_ON_ERROR true
#define SMF_WARN_ON_ERROR  false

#define SMF_CONFIG_STRING_OVS_CONFIG                            "OVS"
#define SMF_CONFIG_STRING_OVS_BRIDGE_NAME                       "BRIDGE_NAME"
#define SMF_CONFIG_STRING_OVS_EGRESS_PORT_NUM                   "EGRESS_PORT_NUM"
#define SMF_CONFIG_STRING_OVS_GTP_PORT_NUM                      "GTP_PORT_NUM"
#define SMF_CONFIG_STRING_OVS_L2_EGRESS_PORT                    "L2_EGRESS_PORT"
#define SMF_CONFIG_STRING_OVS_UPLINK_MAC                        "UPLINK_MAC"
#define SMF_CONFIG_STRING_OVS_SGI_ARP_CACHE                     "SGI_ARP_CACHE"
#define SMF_CONFIG_STRING_IP                                    "IP"
#define SMF_CONFIG_STRING_MAC                                   "MAC"

#define SMF_CONFIG_STRING_SCHED_PARAMS                          "SCHED_PARAMS"
#define SMF_CONFIG_STRING_THREAD_RD_CPU_ID                      "CPU_ID"
#define SMF_CONFIG_STRING_THREAD_RD_SCHED_POLICY                "SCHED_POLICY"
#define SMF_CONFIG_STRING_THREAD_RD_SCHED_PRIORITY              "SCHED_PRIORITY"

#define SMF_CONFIG_STRING_ITTI_TASKS                            "ITTI_TASKS"
#define SMF_CONFIG_STRING_ITTI_TIMER_SCHED_PARAMS               "ITTI_TIMER_SCHED_PARAMS"
#define SMF_CONFIG_STRING_S11_SCHED_PARAMS                      "S11_SCHED_PARAMS"
#define SMF_CONFIG_STRING_N4_SCHED_PARAMS                       "N4_SCHED_PARAMS"
#define SMF_CONFIG_STRING_SMF_APP_SCHED_PARAMS                  "SMF_APP_SCHED_PARAMS"
#define SMF_CONFIG_STRING_ASYNC_CMD_SCHED_PARAMS                "ASYNC_CMD_SCHED_PARAMS"


#define SMF_CONFIG_STRING_AMF                                  "AMF"
#define SMF_CONFIG_STRING_AMF_IPV4_ADDRESS                     "IPV4_ADDRESS"
#define SMF_CONFIG_STRING_AMF_PORT                             "PORT"
#define SMF_CONFIG_STRING_UDM                                  "UDM"
#define SMF_CONFIG_STRING_UDM_IPV4_ADDRESS                     "IPV4_ADDRESS"
#define SMF_CONFIG_STRING_UDM_PORT                             "PORT"

//test_upf
#define SMF_CONFIG_STRING_TEST_UPF                             "TEST_UPF"
#define SMF_CONFIG_STRING_TEST_UPF_IS_TEST                     "IS_TEST"
#define SMF_CONFIG_STRING_TEST_UPF_GNB_IPV4_ADDRESS            "GNB_IPV4_ADDRESS"

#define SMF_CONFIG_STRING_UPF_LIST                             "UPF_LIST"
#define SMF_CONFIG_STRING_UPF_IPV4_ADDRESS                     "IPV4_ADDRESS"

#define PGW_MAX_ALLOCATED_PDN_ADDRESSES 1024

namespace smf {

typedef struct interface_cfg_s {
  std::string     if_name;
  struct in_addr  addr4;
  struct in_addr  network4;
  struct in6_addr addr6;
  unsigned int    mtu;
  unsigned int    port;
  util::thread_sched_params thread_rd_sched_params;
} interface_cfg_t;

typedef struct test_upf_cfg_s {
  uint8_t         is_test;
  struct in_addr  gnb_addr4;
} test_upf_cfg_t;

typedef struct itti_cfg_s {
  util::thread_sched_params itti_timer_sched_params;
  util::thread_sched_params n4_sched_params;
  util::thread_sched_params smf_app_sched_params;
  util::thread_sched_params async_cmd_sched_params;
} itti_cfg_t;

class smf_config {
private:
  int load_itti(const libconfig::Setting& itti_cfg, itti_cfg_t& cfg);
  int load_upf_config(const libconfig::Setting& if_cfg, test_upf_cfg_t & cfg);
  int load_interface(const libconfig::Setting& if_cfg, interface_cfg_t& cfg);
  int load_thread_sched_params(const libconfig::Setting& thread_sched_params_cfg, util::thread_sched_params& cfg);

public:
  /* Reader/writer lock for this configuration */
  std::mutex        m_rw_lock;
  std::string       pid_dir;
  unsigned int      instance = 0;

  interface_cfg_t n4;
  interface_cfg_t n11;
  itti_cfg_t      itti;
  test_upf_cfg_t  test_upf_cfg;

  struct in_addr default_dnsv4;
  struct in_addr default_dns_secv4;
  struct in6_addr default_dnsv6;
  struct in6_addr default_dns_secv6;


#define PGW_NUM_APN_MAX 5
  int              num_apn;
  struct {
    std::string    apn;
    std::string    apn_label;
    int            pool_id_iv4;
    int            pool_id_iv6;
    pdn_type_t     pdn_type;
  } apn[PGW_NUM_APN_MAX];

  int              num_ue_pool;
#define PGW_NUM_UE_POOL_MAX 96
  struct in_addr   ue_pool_range_low[PGW_NUM_UE_POOL_MAX];
  struct in_addr   ue_pool_range_high[PGW_NUM_UE_POOL_MAX];
  struct in_addr   ue_pool_network[PGW_NUM_UE_POOL_MAX];
  struct in_addr   ue_pool_netmask[PGW_NUM_UE_POOL_MAX];
  //computed from config, UE IP adresses that matches ue_pool_network[]/ue_pool_netmask[] but do not match ue_pool_range_low[] - ue_pool_range_high[]
  // The problem here is that OpenFlow do not deal with ip ranges but with netmasks
  std::vector<struct in_addr> ue_pool_excluded[PGW_NUM_UE_POOL_MAX];

  int              num_paa6_pool;
  struct in6_addr  paa_pool6_prefix[PGW_NUM_UE_POOL_MAX];
  uint8_t          paa_pool6_prefix_len[PGW_NUM_UE_POOL_MAX];



  bool             force_push_pco;
  uint             ue_mtu;

  struct {
    bool      tcp_ecn_enabled = false;           // test for CoDel qdisc
    unsigned int  apn_ambr_ul;
    unsigned int  apn_ambr_dl;
  } pcef;

  struct {
    struct in_addr ipv4_addr;
    unsigned int port;
  } amf_addr;

  struct {
    struct in_addr ipv4_addr;
    unsigned int port;
  } udm_addr;

  std::vector<pfcp::node_id_t> upfs;

  smf_config() : m_rw_lock(), pcef(), num_apn(0), pid_dir(), instance(0), n4(), n11(), itti(), upfs() {
    for (int i = 0; i < PGW_NUM_APN_MAX; i++) {
      apn[i] = {};
    }
    default_dnsv4.s_addr = INADDR_ANY;
    default_dns_secv4.s_addr = INADDR_ANY;
    default_dnsv6 = in6addr_any;
    default_dns_secv6 = in6addr_any;

    num_ue_pool = 0;
    num_paa6_pool = 0;
    for (int i = 0; i < PGW_NUM_UE_POOL_MAX; i++) {
      ue_pool_range_low[i] = {};
      ue_pool_range_high[i] = {};
      ue_pool_network[i] = {};
      ue_pool_netmask[i] = {};
      paa_pool6_prefix[i] = {};
      paa_pool6_prefix_len[i] = {};
      ue_pool_excluded[i] = {};
    }
    force_push_pco = true;
    ue_mtu = 1500;

    itti.itti_timer_sched_params.sched_priority = 85;
    itti.n4_sched_params.sched_priority = 84;
    itti.smf_app_sched_params.sched_priority = 84;
    itti.async_cmd_sched_params.sched_priority = 84;

    n4.thread_rd_sched_params.sched_priority = 90;
    n4.port = pfcp::default_port;

    n11.thread_rd_sched_params.sched_priority = 90;
    n11.port = 80;

    amf_addr.ipv4_addr.s_addr = INADDR_ANY;
    amf_addr.port = 80;
    amf_addr.ipv4_addr.s_addr = INADDR_ANY;
    udm_addr.port = 80;

  };
  ~smf_config();
  void lock() {m_rw_lock.lock();};
  void unlock() {m_rw_lock.unlock();};
  int load(const std::string& config_file);
  int finalize();
  void display();
  bool is_dotted_apn_handled(const std::string& apn, const pdn_type_t& pdn_type);
  int get_pfcp_node_id(pfcp::node_id_t& node_id);
  int get_pfcp_fseid(pfcp::fseid_t& fseid);
  bool is_dotted_dnn_handled(const std::string& apn, const pdu_session_type_t& pdn_session_type);
  std::string get_default_dnn();
};

} // namespace smf


#endif /* FILE_SMF_CONFIG_HPP_SEEN */
