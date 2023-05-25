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
#include <netinet/in.h>
#include <sys/socket.h>
#include <libconfig.h++>
#include <mutex>
#include <vector>
#include "thread_sched.hpp"

#include "3gpp_29.244.h"
#include "pfcp.hpp"
#include "smf.h"
#include "smf_profile.hpp"
#include "config.hpp"
#include "logger_base.hpp"
#include "smf_config_types.hpp"

#define SMF_CONFIG_STRING_SMF_CONFIG "SMF"
#define SMF_CONFIG_STRING_PID_DIRECTORY "PID_DIRECTORY"
#define SMF_CONFIG_STRING_INSTANCE "INSTANCE"
#define SMF_CONFIG_STRING_FQDN_DNS "FQDN"
#define SMF_CONFIG_STRING_INTERFACES "INTERFACES"
#define SMF_CONFIG_STRING_INTERFACE_NAME "INTERFACE_NAME"
#define SMF_CONFIG_STRING_IPV4_ADDRESS "IPV4_ADDRESS"
#define SMF_CONFIG_STRING_PORT "PORT"
#define SMF_CONFIG_STRING_INTERFACE_N4 "N4"
#define SMF_CONFIG_STRING_INTERFACE_SBI "SBI"
#define SMF_CONFIG_STRING_SBI_HTTP2_PORT "HTTP2_PORT"
#define SMF_CONFIG_STRING_API_VERSION "API_VERSION"

#define SMF_CONFIG_STRING_IP_ADDRESS_POOL "IP_ADDRESS_POOL"
#define SMF_CONFIG_STRING_ARP_UE "ARP_UE"
#define SMF_CONFIG_STRING_ARP_UE_CHOICE_NO "NO"
#define SMF_CONFIG_STRING_ARP_UE_CHOICE_LINUX "LINUX"
#define SMF_CONFIG_STRING_ARP_UE_CHOICE_OAI "OAI"
#define SMF_CONFIG_STRING_IPV4_ADDRESS_LIST "IPV4_LIST"
#define SMF_CONFIG_STRING_IPV6_ADDRESS_LIST "IPV6_LIST"
#define SMF_CONFIG_STRING_RANGE "RANGE"
#define SMF_CONFIG_STRING_PREFIX "PREFIX"
#define SMF_CONFIG_STRING_IPV4_ADDRESS_RANGE_DELIMITER "-"
#define SMF_CONFIG_STRING_IPV6_ADDRESS_PREFIX_DELIMITER "/"
#define SMF_CONFIG_STRING_DEFAULT_DNS_IPV4_ADDRESS "DEFAULT_DNS_IPV4_ADDRESS"
#define SMF_CONFIG_STRING_DEFAULT_CSCF_IPV4_ADDRESS "DEFAULT_CSCF_IPV4_ADDRESS"
#define SMF_CONFIG_STRING_DEFAULT_CSCF_IPV6_ADDRESS "DEFAULT_CSCF_IPV6_ADDRESS"

#define SMF_CONFIG_STRING_DEFAULT_DNS_SEC_IPV4_ADDRESS                         \
  "DEFAULT_DNS_SEC_IPV4_ADDRESS"
#define SMF_CONFIG_STRING_DEFAULT_DNS_IPV6_ADDRESS "DEFAULT_DNS_IPV6_ADDRESS"
#define SMF_CONFIG_STRING_DEFAULT_DNS_SEC_IPV6_ADDRESS                         \
  "DEFAULT_DNS_SEC_IPV6_ADDRESS"
#define SMF_CONFIG_STRING_UE_MTU "UE_MTU"

#define SMF_CONFIG_STRING_INTERFACE_DISABLED "none"

#define SMF_CONFIG_STRING_DNN_LIST "DNN_LIST"
#define SMF_CONFIG_STRING_DNN_NI "DNN_NI"
#define SMF_CONFIG_STRING_PDU_SESSION_TYPE "PDU_SESSION_TYPE"
#define SMF_CONFIG_STRING_IPV4_POOL "IPV4_POOL"
#define SMF_CONFIG_STRING_IPV6_POOL "IPV6_POOL"
#define SMF_CONFIG_STRING_IPV4_RANGE "IPV4_RANGE"
#define SMF_CONFIG_STRING_IPV6_PREFIX "IPV6_PREFIX"

#define SMF_ABORT_ON_ERROR true
#define SMF_WARN_ON_ERROR false

#define SMF_CONFIG_STRING_SCHED_PARAMS "SCHED_PARAMS"
#define SMF_CONFIG_STRING_THREAD_RD_CPU_ID "CPU_ID"
#define SMF_CONFIG_STRING_THREAD_RD_SCHED_POLICY "SCHED_POLICY"
#define SMF_CONFIG_STRING_THREAD_RD_SCHED_PRIORITY "SCHED_PRIORITY"

#define SMF_CONFIG_STRING_ITTI_TASKS "ITTI_TASKS"
#define SMF_CONFIG_STRING_ITTI_TIMER_SCHED_PARAMS "ITTI_TIMER_SCHED_PARAMS"
#define SMF_CONFIG_STRING_S11_SCHED_PARAMS "S11_SCHED_PARAMS"
#define SMF_CONFIG_STRING_N4_SCHED_PARAMS "N4_SCHED_PARAMS"
#define SMF_CONFIG_STRING_SMF_APP_SCHED_PARAMS "SMF_APP_SCHED_PARAMS"
#define SMF_CONFIG_STRING_ASYNC_CMD_SCHED_PARAMS "ASYNC_CMD_SCHED_PARAMS"

#define SMF_CONFIG_STRING_AMF "AMF"
#define SMF_CONFIG_STRING_AMF_IPV4_ADDRESS "IPV4_ADDRESS"
#define SMF_CONFIG_STRING_AMF_PORT "PORT"
#define SMF_CONFIG_STRING_UDM "UDM"
#define SMF_CONFIG_STRING_UDM_IPV4_ADDRESS "IPV4_ADDRESS"
#define SMF_CONFIG_STRING_UDM_PORT "PORT"

#define SMF_CONFIG_STRING_PCF "PCF"
#define SMF_CONFIG_STRING_PCF_IPV4_ADDRESS "IPV4_ADDRESS"
#define SMF_CONFIG_STRING_PCF_PORT "PORT"

#define SMF_CONFIG_STRING_UPF_LIST "UPF_LIST"
#define SMF_CONFIG_STRING_UPF_IPV4_ADDRESS "IPV4_ADDRESS"

#define SMF_CONFIG_STRING_NRF "NRF"
#define SMF_CONFIG_STRING_NRF_IPV4_ADDRESS "IPV4_ADDRESS"
#define SMF_CONFIG_STRING_NRF_PORT "PORT"

#define SMF_CONFIG_STRING_NWI_LIST "NWI_LIST"
#define SMF_CONFIG_STRING_DOMAIN_ACCESS "DOMAIN_ACCESS"
#define SMF_CONFIG_STRING_DOMAIN_CORE "DOMAIN_CORE"
#define SMF_CONFIG_STRING_DOMAIN_SGI_LAN "DOMAIN_SGI_LAN"

#define SMF_CONFIG_STRING_LOCAL_CONFIGURATION "LOCAL_CONFIGURATION"
#define SMF_CONFIG_STRING_SESSION_MANAGEMENT_SUBSCRIPTION_LIST                 \
  "SESSION_MANAGEMENT_SUBSCRIPTION_LIST"
#define SMF_CONFIG_STRING_NSSAI_SST "NSSAI_SST"
#define SMF_CONFIG_STRING_NSSAI_SD "NSSAI_SD"
#define SMF_CONFIG_STRING_DNN "DNN"
#define SMF_CONFIG_STRING_DEFAULT_SESSION_TYPE "DEFAULT_SESSION_TYPE"
#define SMF_CONFIG_STRING_DEFAULT_SSC_MODE "DEFAULT_SSC_MODE"
#define SMF_CONFIG_STRING_QOS_PROFILE_5QI "QOS_PROFILE_5QI"
#define SMF_CONFIG_STRING_QOS_PROFILE_PRIORITY_LEVEL                           \
  "QOS_PROFILE_PRIORITY_LEVEL"
#define SMF_CONFIG_STRING_QOS_PROFILE_ARP_PRIORITY_LEVEL                       \
  "QOS_PROFILE_ARP_PRIORITY_LEVEL"
#define SMF_CONFIG_STRING_QOS_PROFILE_ARP_PREEMPTCAP                           \
  "QOS_PROFILE_ARP_PREEMPTCAP"
#define SMF_CONFIG_STRING_QOS_PROFILE_ARP_PREEMPTVULN                          \
  "QOS_PROFILE_ARP_PREEMPTVULN"
#define SMF_CONFIG_STRING_SESSION_AMBR_UL "SESSION_AMBR_UL"
#define SMF_CONFIG_STRING_SESSION_AMBR_DL "SESSION_AMBR_DL"

#define SMF_CONFIG_STRING_SUPPORT_FEATURES "SUPPORT_FEATURES"
#define SMF_CONFIG_STRING_SUPPORT_FEATURES_REGISTER_NRF "REGISTER_NRF"
#define SMF_CONFIG_STRING_SUPPORT_FEATURES_DISCOVER_UPF "DISCOVER_UPF"
#define SMF_CONFIG_STRING_SUPPORT_FEATURES_DISCOVER_PCF "DISCOVER_PCF"
#define SMF_CONFIG_STRING_SUPPORT_FEATURES_USE_LOCAL_PCC_RULES                 \
  "USE_LOCAL_PCC_RULES"
#define SMF_CONFIG_STRING_SUPPORT_FEATURES_USE_LOCAL_SUBSCRIPTION_INFO         \
  "USE_LOCAL_SUBSCRIPTION_INFO"
#define SMF_CONFIG_STRING_NAS_FORCE_PUSH_PCO                                   \
  "FORCE_PUSH_PROTOCOL_CONFIGURATION_OPTIONS"
#define SMF_CONFIG_STRING_SUPPORT_FEATURES_USE_FQDN_DNS "USE_FQDN_DNS"
#define SMF_CONFIG_STRING_SUPPORT_FEATURES_SBI_HTTP_VERSION "HTTP_VERSION"
#define SMF_CONFIG_STRING_SUPPORT_FEATURES_ENABLE_USAGE_REPORTING              \
  "ENABLE_USAGE_REPORTING"
#define SMF_CONFIG_STRING_SUPPORT_FEATURES_enable_dl_pdr_in_pfcp_sess_estab    \
  "ENABLE_DL_PDR_IN_PFCP_SESS_ESTAB"
#define SMF_CONFIG_STRING_N3_LOCAL_IPV4_ADDRESS "N3_LOCAL_IPV4_ADDRESS"

#define SMF_MAX_ALLOCATED_PDN_ADDRESSES 1024

#define SMF_CONFIG_STRING_LOG_LEVEL "LOG_LEVEL"

namespace oai::config::smf {

const std::string USE_LOCAL_PCC_RULES_CONFIG_VALUE = "use_local_pcc_rules";
const std::string USE_LOCAL_SUBSCRIPTION_INFOS_CONFIG_VALUE =
    "use_local_subscription_info";
const std::string USE_EXTERNAL_AUSF_CONFIG_VALUE = "use_external_ausf";
const std::string USE_EXTERNAL_UDM_CONFIG_VALUE  = "use_external_udm";
const std::string USE_EXTERNAL_NSSF_CONFIG_VALUE = "use_external_nssf";

const snssai_t DEFAULT_SNSSAI{1, 0};
const session_ambr_t DEFAULT_S_AMBR{"1000Mbps", "1000Mbps"};
const std::string DEFAULT_DNN  = "default";
const uint8_t DEFAULT_SSC_MODE = 1;
const subscribed_default_qos_t DEFAULT_QOS{
    9,
    {1, "NOT_PREEMPT", "NOT_PREEMPTABLE"},
    1};

typedef struct interface_cfg_s {
  std::string if_name;
  struct in_addr addr4;
  struct in_addr network4;
  struct in6_addr addr6;
  unsigned int mtu;
  unsigned int port;
  util::thread_sched_params thread_rd_sched_params;
} interface_cfg_t;

typedef struct itti_cfg_s {
  util::thread_sched_params itti_timer_sched_params;
  util::thread_sched_params n4_sched_params;
  util::thread_sched_params smf_app_sched_params;
  util::thread_sched_params async_cmd_sched_params;
} itti_cfg_t;

typedef struct dnn_s {
  std::string dnn;
  std::string dnn_label;
  bool is_ipv4;
  bool is_ipv6;
  int pool_id_iv4;
  int pool_id_iv6;
  struct in_addr ue_pool_range_low;
  struct in_addr ue_pool_range_high;
  struct in6_addr paa_pool6_prefix;
  uint8_t paa_pool6_prefix_len;
  pdu_session_type_t pdu_session_type;
} dnn_t;

typedef struct session_management_subscription_s {
  snssai_t single_nssai;
  std::string session_type;
  std::string dnn;
  uint8_t ssc_mode;
  subscribed_default_qos_t default_qos;
  session_ambr_t session_ambr;
} session_management_subscription_t;

class smf_config : public config {
 private:
  int load_itti(const libconfig::Setting& itti_cfg, itti_cfg_t& cfg);
  int load_interface(const libconfig::Setting& if_cfg, interface_cfg_t& cfg);
  int load_thread_sched_params(
      const libconfig::Setting& thread_sched_params_cfg,
      util::thread_sched_params& cfg);

  // TODO only temporary, to avoid changing all the references to the config in
  // all the calling classes
  void to_smf_config();

  // TODO only temporary, we should not resolve on startup in the config
  static in_addr resolve_nf(const std::string& host);

 public:
  /* Reader/writer lock for this configuration */
  std::mutex m_rw_lock;
  std::string pid_dir;
  spdlog::level::level_enum log_level;
  unsigned int instance = 0;
  std::string fqdn      = {};

  interface_cfg_t n4;
  interface_cfg_t sbi;
  unsigned int sbi_http2_port;
  std::string sbi_api_version;
  itti_cfg_t itti;

  struct in_addr default_dnsv4;
  struct in_addr default_dns_secv4;
  struct in_addr default_cscfv4;
  struct in6_addr default_dnsv6;
  struct in6_addr default_dns_secv6;
  std::map<std::string, dnn_t> dnns;
  struct in6_addr default_cscfv6;

  bool force_push_pco;
  uint ue_mtu;

  bool register_nrf;
  bool discover_upf;
  bool discover_pcf;
  bool use_local_subscription_info;
  bool use_local_pcc_rules;
  bool use_fqdn_dns;
  unsigned int http_version;
  bool enable_ur;
  bool enable_dl_pdr_in_pfcp_sess_estab;
  std::string local_n3_addr;

  std::vector<pfcp::node_id_t> upfs;

  struct sbi_addr {
    struct in_addr ipv4_addr;
    unsigned int port;
    unsigned int http_version;
    std::string api_version;
    std::string fqdn;

    void log_infos(bool _use_fqdn_dns) {
      Logger::smf_app().info(
          "    IPv4 Addr ...........: %s",
          inet_ntoa(*((struct in_addr*) &ipv4_addr)));
      Logger::smf_app().info("    Port ................: %lu  ", port);
      Logger::smf_app().info(
          "    API version .........: %s", api_version.c_str());
      if (_use_fqdn_dns)
        Logger::smf_app().info("    FQDN ................: %s", fqdn.c_str());
    }

    // TODO delete, just for now until we refactor the calling classes as well
    void from_sbi_config_type(const sbi_interface& sbi_val) {
      ipv4_addr = resolve_nf(sbi_val.get_host());
      port      = sbi_val.use_http2() ? sbi_val.get_port_http2() :
                                   sbi_val.get_port_http1();
      http_version = sbi_val.use_http2() ? 2 : 1;
      api_version  = sbi_val.get_api_version();
      fqdn         = sbi_val.get_host();
    }
  };

  sbi_addr nrf_addr;
  sbi_addr pcf_addr;
  sbi_addr udm_addr;
  sbi_addr amf_addr;

  // Network instance
  // bool network_instance_configuration;
  struct upf_nwi_list_s {
    pfcp::node_id_t upf_id;
    std::string domain_access;
    std::string domain_core;
    //      std::string domain_sgi_lan;
  };
  typedef struct upf_nwi_list_s upf_nwi_list_t;

  std::vector<upf_nwi_list_t> upf_nwi_list;

  std::vector<session_management_subscription_t>
      session_management_subscriptions;

  smf_config(const std::string& configPath, bool logStdout, bool logRotFile);
  ~smf_config();
  void lock() { m_rw_lock.lock(); };
  void unlock() { m_rw_lock.unlock(); };
  int load(const std::string& config_file);
  void display();
  int get_pfcp_node_id(pfcp::node_id_t& node_id);
  int get_pfcp_fseid(pfcp::fseid_t& fseid);
  bool is_dotted_dnn_handled(
      const std::string& dnn, const pdu_session_type_t& pdn_session_type);
  std::string get_default_dnn();

  /**
   * Returns network instance of iface_type typ. If not found, empty string is
   * returned
   * @param node_id IP address or FQDN to match against configuration
   * @return NWI or empty string
   */
  std::string get_nwi(
      const pfcp::node_id_t& node_id, const ::smf::iface_type& type);

  /**
   * Returns configured UPF based on node_id.
   * Compares UPF host config value with node_id FQDN and IPv4 address in this
   * order
   * @param node_id PFCP node id, FQDN, IPv4 address must be set
   * @throws std::invalid_argument  in case UPF is not to be found or type is
   * IPv6
   * @return upf
   */
  const oai::config::smf::upf& get_upf(const pfcp::node_id_t& node_id) const;

  /**
   * Returns SMF configuration pointer which stores SMF-specific configuration
   * @return SMF configuration
   */
  std::shared_ptr<smf_config_type> smf() const;

  bool init() override;
};

}  // namespace oai::config::smf

#endif /* FILE_SMF_CONFIG_HPP_SEEN */
