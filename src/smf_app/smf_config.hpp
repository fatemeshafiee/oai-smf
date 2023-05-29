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
  // TODO only temporary, to avoid changing all the references to the config in
  // all the calling classes
  void to_smf_config();

  // TODO only temporary, we should not resolve on startup in the config
  static in_addr resolve_nf(const std::string& host);

  void update_used_nfs() override;

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
