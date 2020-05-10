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

/*! \file smf_msg.hpp
 \brief
 \author  Tien-Thinh NGUYEN
 \company Eurecom
 \date 2019
 \email: tien-thinh.nguyen@eurecom.fr
 */
#ifndef FILE_SMF_MSG_HPP_SEEN
#define FILE_SMF_MSG_HPP_SEEN

#include "pistache/http.h"
#include "smf.h"
#include "3gpp_29.274.h"
#include "3gpp_29.244.h"
#include "3gpp_24.007.h"
#include "3gpp_24.501.h"
#include "3gpp_29.571.h"
#include "Guami.h"
#include "RefToBinaryData.h"
#include "NgRanTargetId.h"

extern "C" {
#include "QOSRules.h"
}

typedef enum {
  PDU_SESSION_MSG_TYPE_NONE = -1,
  PDU_SESSION_MSG_TYPE_FIRST = 0,
  PDU_SESSION_CREATE_SM_CONTEXT_REQUEST = PDU_SESSION_MSG_TYPE_FIRST,
  PDU_SESSION_CREATE_SM_CONTEXT_RESPONSE,
  PDU_SESSION_UPDATE_SM_CONTEXT_REQUEST,
  PDU_SESSION_UPDATE_SM_CONTEXT_RESPONSE,
  PDU_SESSION_RELEASE_SM_CONTEXT_REQUEST,
  PDU_SESSION_RELEASE_SM_CONTEXT_RESPONSE,
  PDU_SESSION_MODIFICATION_SMF_REQUESTED,
  PDU_SESSION_MSG_TYPE_MAX
} pdu_session_msg_type_t;

namespace smf {

//QoS flow to be created/modified/removed
class qos_flow_context_updated {
 public:
  qos_flow_context_updated()
      :
      cause_value(),
      qfi(),
      ul_fteid(),
      dl_fteid(),
      qos_profile(),
      to_be_removed(false) {
  }

  void set_cause(const uint8_t cause);
  void set_qfi(const pfcp::qfi_t &q);
  void set_ul_fteid(const fteid_t &teid);
  void set_dl_fteid(const fteid_t &teid);
  void add_qos_rule(const QOSRulesIE &rule);
  void set_qos_profile(const qos_profile_t &profile);
  void set_priority_level(uint8_t p);
  uint8_t cause_value;
  pfcp::qfi_t qfi;
  fteid_t ul_fteid;
  fteid_t dl_fteid;
  std::map<uint8_t, QOSRulesIE> qos_rules;
  qos_profile_t qos_profile;
  bool to_be_removed;
};

//---------------------------------------------------------------------------------------
class pdu_session_msg {
 public:
  pdu_session_msg()
      :
      m_msg_type(),
      m_supi(),
      m_pdu_session_id(),
      m_dnn(),
      m_snssai(),
      m_pdu_session_type(0) {
  }
  ;
  pdu_session_msg(pdu_session_msg_type_t msg_type)
      :
      m_msg_type(msg_type),
      m_supi(),
      m_pdu_session_id(),
      m_dnn(),
      m_snssai(),
      m_pdu_session_type(0) {
  }
  ;
  pdu_session_msg(pdu_session_msg_type_t msg_type, supi_t supi,
                  pdu_session_id_t pdi, std::string dnn, snssai_t snssai)
      :
      m_msg_type(msg_type),
      m_supi(supi),
      m_pdu_session_id(pdi),
      m_dnn(dnn),
      m_snssai(snssai),
      m_pdu_session_type(0) {
  }
  virtual ~pdu_session_msg() = default;

  pdu_session_msg_type_t get_msg_type() const;
  void set_msg_type(pdu_session_msg_type_t const &value);
  supi_t get_supi() const;
  void set_supi(supi_t const &value);
  std::string get_supi_prefix() const;
  void set_supi_prefix(std::string const &value);
  pdu_session_id_t get_pdu_session_id() const;
  void set_pdu_session_id(pdu_session_id_t const value);
  std::string get_dnn() const;
  void set_dnn(std::string const &value);
  snssai_t get_snssai() const;
  void set_snssai(snssai_t const &value);
  void set_api_root(std::string const &value);
  std::string get_api_root() const;
  uint8_t get_pdu_session_type() const;
  void set_pdu_session_type(uint8_t const &pdu_session_type);
  procedure_transaction_id_t get_pti() const;
  void set_pti(procedure_transaction_id_t const &pti);

 private:
  pdu_session_msg_type_t m_msg_type;
  std::string m_api_root;
  supi_t m_supi;
  std::string m_supi_prefix;
  pdu_session_id_t m_pdu_session_id;
  std::string m_dnn;
  snssai_t m_snssai;
  uint8_t m_pdu_session_type;
  procedure_transaction_id_t m_pti;
};

//---------------------------------------------------------------------------------------
class pdu_session_create_sm_context : public pdu_session_msg {

 public:
  pdu_session_create_sm_context()
      :
      pdu_session_msg() {
    m_epd = EPD_5GS_SESSION_MANAGEMENT_MESSAGES;
    m_message_type = PDU_SESSION_MESSAGE_TYPE_UNKNOWN;
  }
  ;
  pdu_session_create_sm_context(pdu_session_msg_type_t msg_type)
      :
      pdu_session_msg(msg_type) {
    m_epd = EPD_5GS_SESSION_MANAGEMENT_MESSAGES;
    m_message_type = PDU_SESSION_MESSAGE_TYPE_UNKNOWN;
  }
  ;
  pdu_session_create_sm_context(pdu_session_msg_type_t msg_type, supi_t supi,
                                pdu_session_id_t pdi, std::string dnn,
                                snssai_t snssai)
      :
      pdu_session_msg(msg_type, supi, pdi, dnn, snssai) {
    m_epd = EPD_5GS_SESSION_MANAGEMENT_MESSAGES;
    m_message_type = PDU_SESSION_MESSAGE_TYPE_UNKNOWN;
  }

  extended_protocol_discriminator_t get_epd() const;
  void set_epd(extended_protocol_discriminator_t const &epd);
  uint8_t get_message_type() const;
  void set_message_type(uint8_t const &message_type);

 private:
  extended_protocol_discriminator_t m_epd;
  uint8_t m_message_type;
};

//---------------------------------------------------------------------------------------
class pdu_session_create_sm_context_request :
    public pdu_session_create_sm_context {

 public:
  pdu_session_create_sm_context_request()
      :
      pdu_session_create_sm_context(PDU_SESSION_CREATE_SM_CONTEXT_REQUEST),
      m_unauthenticated_supi(true) {
  }
  pdu_session_create_sm_context_request(supi_t supi, pdu_session_id_t pdi,
                                        std::string dnn, snssai_t snssai)
      :
      pdu_session_create_sm_context(PDU_SESSION_CREATE_SM_CONTEXT_REQUEST, supi,
                                    pdi, dnn, snssai),
      m_unauthenticated_supi(true) {
  }

  std::string get_n1_sm_message() const;
  void set_n1_sm_message(std::string const &value);
  std::string get_serving_nf_id() const;
  void set_serving_nf_id(std::string const &value);
  std::string get_request_type() const;
  void set_request_type(std::string const &value);
  void set_dnn_selection_mode(std::string const &value);
  std::string get_dnn_selection_mode() const;

 private:
  std::string m_n1_sm_message;  //N1 SM Message before decoding
  bool m_unauthenticated_supi;
  std::string m_serving_nf_id;  //AMF Id
  std::string m_request_type;
  std::string m_rat_type;
  std::string m_presence_in_ladn;
  std::string m_an_type;
  std::string m_dnn_selection_mode;  //SelMode
};

//---------------------------------------------------------------------------------------
class pdu_session_create_sm_context_response :
    public pdu_session_create_sm_context {

 public:
  pdu_session_create_sm_context_response()
      :
      pdu_session_create_sm_context(PDU_SESSION_CREATE_SM_CONTEXT_RESPONSE) {
    m_n1_sm_msg_is_set = false;
    m_n2_sm_info_is_set = false;
    m_cause = 0;
    m_paa = { };
    m_code = { };
    qos_flow_context = { };
    m_supi = { };
  }
  pdu_session_create_sm_context_response(supi_t supi, pdu_session_id_t pdi,
                                         std::string dnn, snssai_t snssai)
      :
      pdu_session_create_sm_context(PDU_SESSION_CREATE_SM_CONTEXT_RESPONSE,
                                    supi, pdi, dnn, snssai) {
    m_n1_sm_msg_is_set = false;
    m_n2_sm_info_is_set = false;
    m_cause = 0;
    m_paa = { };
    m_code = { };
    qos_flow_context = { };
  }

  void set_cause(uint8_t cause);
  uint8_t get_cause();
  void set_paa(paa_t paa);
  paa_t get_paa();
  void set_http_code(Pistache::Http::Code code);
  Pistache::Http::Code get_http_code();
  void set_qos_flow_context(const qos_flow_context_updated &qos_flow);
  qos_flow_context_updated get_qos_flow_context() const;
  std::string get_n2_sm_information() const;
  void set_n2_sm_information(std::string const &value);
  std::string get_n1_sm_message() const;
  void set_n1_sm_message(std::string const &value);
  bool n1_sm_msg_is_set() const;
  bool n2_sm_info_is_set() const;
  void set_amf_url(std::string const &value);
  std::string get_amf_url() const;
  nlohmann::json n1n2_message_transfer_data;  //N1N2MessageTransferReqData from oai::amf::model

 private:
  std::string m_n1_sm_message;  //N1 SM message after decoding
  bool m_n1_sm_msg_is_set;
  std::string m_n2_sm_information;  //N2 SM info after decoding
  bool m_n2_sm_info_is_set;
  uint8_t m_cause;
  paa_t m_paa;
  Pistache::Http::Code m_code;
  qos_flow_context_updated qos_flow_context;
  supi_t m_supi;
  std::string m_supi_prefix;
  std::string amf_url;
};

//---------------------------------------------------------------------------------------
class pdu_session_update_sm_context : public pdu_session_msg {

 public:
  pdu_session_update_sm_context()
      :
      pdu_session_msg() {
    m_n1_sm_msg_is_set = false;
    m_n2_sm_info_is_set = false;
  }
  ;
  pdu_session_update_sm_context(pdu_session_msg_type_t msg_type)
      :
      pdu_session_msg(msg_type) {
    m_n1_sm_msg_is_set = false;
    m_n2_sm_info_is_set = false;
  }
  ;

  std::string get_n2_sm_information() const;
  void set_n2_sm_information(std::string const &value);
  std::string get_n2_sm_info_type() const;
  void set_n2_sm_info_type(std::string const &value);
  std::string get_n1_sm_message() const;
  void set_n1_sm_message(std::string const &value);
  bool n1_sm_msg_is_set() const;
  bool n2_sm_info_is_set() const;

 private:
  std::string m_n1_sm_message;  //N1 SM message before decoding
  bool m_n1_sm_msg_is_set;
  std::string m_n2_sm_information;  //N2 SM before decoding
  bool m_n2_sm_info_is_set;
  std::string m_n2_sm_info_type;
};

//see SmContextUpdateData (TS29502_Nsmf_PDUSession.yaml)
class pdu_session_update_sm_context_request :
    public pdu_session_update_sm_context {
 public:
  pdu_session_update_sm_context_request()
      :
      pdu_session_update_sm_context(PDU_SESSION_UPDATE_SM_CONTEXT_REQUEST) {
    m_5gMm_cause_value = 0;
    m_data_forwarding = false;
    m_upCnx_state_is_set = false;
    qfis = { };
    dl_fteid = { };
    m_release = false;
    m_release_is_set = false;
    m_an_type_is_set = false;
    m_rat_type_is_set = false;
  }
  ;

  void add_qfi(pfcp::qfi_t const &qfi);
  void add_qfi(uint8_t const &qfi);
  void get_qfis(std::vector<pfcp::qfi_t> &q);
  void set_dl_fteid(fteid_t const &t);
  void get_dl_fteid(fteid_t &t);
  void set_upCnx_state(std::string const &value);
  bool upCnx_state_is_set() const;
  void set_rat_type(std::string const &value);
  bool rat_type_is_set() const;
  void set_an_type(std::string const &value);
  bool an_type_is_set() const;
  bool release_is_set() const;
  void set_release(bool const value);

 private:
  std::vector<pfcp::qfi_t> qfis;
  fteid_t dl_fteid;  //AN Tunnel Info
  std::string m_nf_instanceId;
  std::string m_an_type;
  bool m_an_type_is_set;
  std::string m_rat_type;
  bool m_rat_type_is_set;
  std::string m_upCnx_state;
  bool m_upCnx_state_is_set;
  std::string m_target_serving_nfId;
  std::string m_sm_context_status_uri;
  bool m_data_forwarding;
  uint8_t m_5gMm_cause_value;
  bool m_release_is_set;
  bool m_release;

};

//---------------------------------------------------------------------------------------
//for PDU session update response
class pdu_session_update_sm_context_response :
    public pdu_session_update_sm_context {
 public:
  pdu_session_update_sm_context_response()
      :
      pdu_session_update_sm_context(PDU_SESSION_UPDATE_SM_CONTEXT_RESPONSE) {
    m_cause = 0;
    qos_flow_context_updateds = { };
  }
  ;

  pdu_session_update_sm_context_response(pdu_session_msg_type_t type)
      :
      pdu_session_update_sm_context(type) {
    m_cause = 0;
    qos_flow_context_updateds = { };
  }
  ;

  void set_cause(uint8_t cause);
  uint8_t get_cause();
  void add_qos_flow_context_updated(const qos_flow_context_updated &qos_flow);
  bool get_qos_flow_context_updated(const pfcp::qfi_t &qfi,
                                    qos_flow_context_updated &qos_flow);
  void get_all_qos_flow_context_updateds(
      std::map<uint8_t, qos_flow_context_updated> &all_flows);
  void remove_all_qos_flow_context_updateds();
  nlohmann::json sm_context_updated_data;  //N1N2MessageTransferReqData from oai::amf::model

 private:
  uint8_t m_cause;
  std::map<uint8_t, qos_flow_context_updated> qos_flow_context_updateds;

};

class pdu_session_release_sm_context_request : public pdu_session_msg {
 public:
  pdu_session_release_sm_context_request()
      :
      pdu_session_msg(PDU_SESSION_RELEASE_SM_CONTEXT_REQUEST) {

  }
  ;

 private:

};

class pdu_session_release_sm_context_response : public pdu_session_msg {
 public:
  pdu_session_release_sm_context_response()
      :
      pdu_session_msg(PDU_SESSION_RELEASE_SM_CONTEXT_RESPONSE) {
    m_cause = 0;
  }
  ;
  void set_cause(uint8_t cause);
  uint8_t get_cause();

 private:
  uint8_t m_cause;
};

//---------------------------------------------------------------------------------------
class pdu_session_modification_network_requested :
    public pdu_session_update_sm_context_response {

 public:
  pdu_session_modification_network_requested()
      :
      pdu_session_update_sm_context_response(
          PDU_SESSION_MODIFICATION_SMF_REQUESTED) {
    m_code = { };
    m_supi = { };
  }

  void set_http_code(Pistache::Http::Code code);
  Pistache::Http::Code get_http_code();
  void set_amf_url(std::string const &value);
  std::string get_amf_url() const;
  void add_qfi(pfcp::qfi_t const &qfi);
  void add_qfi(uint8_t const &qfi);
  void get_qfis(std::vector<pfcp::qfi_t> &q);
  nlohmann::json n1n2_message_transfer_data;  //N1N2MessageTransferReqData from oai::amf::model

 private:
  Pistache::Http::Code m_code;
  supi_t m_supi;
  std::string m_supi_prefix;
  std::string amf_url;
  std::vector<pfcp::qfi_t> qfis;
  std::map<uint8_t, qos_flow_context_updated> qos_flow_context_updateds;
};

}

#endif
