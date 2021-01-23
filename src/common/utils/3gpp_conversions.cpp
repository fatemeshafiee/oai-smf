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

/*! \file 3gpp_conversions.cpp
 * \brief
 * \author Lionel Gauthier
 * \company Eurecom
 * \email: lionel.gauthier@eurecom.fr
 */
#include "3gpp_conversions.hpp"

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <ctype.h>
#include <inttypes.h>
#include "SmContextCreateData.h"

//------------------------------------------------------------------------------
void xgpp_conv::paa_to_pfcp_ue_ip_address(
    const paa_t& paa, pfcp::ue_ip_address_t& ue_ip_address) {
  switch (paa.pdu_session_type.pdu_session_type) {
    case PDU_SESSION_TYPE_E_IPV4:
      ue_ip_address.v4           = 1;
      ue_ip_address.ipv4_address = paa.ipv4_address;
      break;
    case PDU_SESSION_TYPE_E_IPV6:
      ue_ip_address.v6           = 1;
      ue_ip_address.ipv6_address = paa.ipv6_address;
      break;
    case PDU_SESSION_TYPE_E_IPV4V6:
      ue_ip_address.v4           = 1;
      ue_ip_address.v6           = 1;
      ue_ip_address.ipv4_address = paa.ipv4_address;
      ue_ip_address.ipv6_address = paa.ipv6_address;
      break;
    case PDU_SESSION_TYPE_E_UNSTRUCTURED:
    case PDU_SESSION_TYPE_E_ETHERNET:
    case PDU_SESSION_TYPE_E_RESERVED:
    default:;
  }
}
//------------------------------------------------------------------------------
void xgpp_conv::pdn_ip_to_pfcp_ue_ip_address(
    const pdu_session_type_t& pdu_session_type,
    const struct in_addr& ipv4_address, const struct in6_addr ipv6_address,
    pfcp::ue_ip_address_t& ue_ip_address) {
  switch (pdu_session_type.pdu_session_type) {
    case PDU_SESSION_TYPE_E_IPV4:
      ue_ip_address.v4           = 1;
      ue_ip_address.ipv4_address = ipv4_address;
      break;
    case PDU_SESSION_TYPE_E_IPV6:
      ue_ip_address.v6           = 1;
      ue_ip_address.ipv6_address = ipv6_address;
      break;
    case PDU_SESSION_TYPE_E_IPV4V6:
      ue_ip_address.v4           = 1;
      ue_ip_address.v6           = 1;
      ue_ip_address.ipv4_address = ipv4_address;
      ue_ip_address.ipv6_address = ipv6_address;
      break;
    case PDU_SESSION_TYPE_E_UNSTRUCTURED:
    case PDU_SESSION_TYPE_E_ETHERNET:
    case PDU_SESSION_TYPE_E_RESERVED:
    default:;
  }
}

void xgpp_conv::pco_nas_to_core(
    const protocol_configuration_options_nas_t& pco_nas,
    protocol_configuration_options_t& pco) {
  pco.ext                          = pco_nas.ext;
  pco.spare                        = pco_nas.spare;
  pco.configuration_protocol       = pco_nas.configuration_protocol;
  pco.num_protocol_or_container_id = pco_nas.num_protocol_or_container_id;

  for (int i = 0; i < pco.num_protocol_or_container_id; i++) {
    pco_protocol_or_container_id_t pco_item = {};

    pco_item.length_of_protocol_id_contents =
        pco_nas.protocol_or_container_ids[i].length;
    pco_item.protocol_id = pco_nas.protocol_or_container_ids[i].id;

    // pco.protocol_or_container_ids[i].length_of_protocol_id_contents =
    // pco_nas.protocol_or_container_ids[i].length;
    // pco.protocol_or_container_ids[i].protocol_id =
    // pco_nas.protocol_or_container_ids[i].id;
    if (pco_nas.protocol_or_container_ids[i].contents != nullptr) {
      unsigned char data[512] = {'\0'};
      memcpy(
          (void*) &data,
          (void*) pco_nas.protocol_or_container_ids[i].contents->data,
          pco_nas.protocol_or_container_ids[i].contents->slen);
      std::string msg_bstr(
          (char*) data, pco_nas.protocol_or_container_ids[i].contents->slen);
      // pco.protocol_or_container_ids[i].protocol_id_contents  = msg_bstr;
      pco_item.protocol_id_contents = msg_bstr;
    }

    pco.protocol_or_container_ids.push_back(pco_item);
  }
}

void xgpp_conv::pco_core_to_nas(
    const protocol_configuration_options_t& pco,
    protocol_configuration_options_nas_t& pco_nas) {
  pco_nas.ext                          = pco.ext;
  pco_nas.spare                        = pco.spare;
  pco_nas.configuration_protocol       = pco.configuration_protocol;
  pco_nas.num_protocol_or_container_id = pco.num_protocol_or_container_id;

  for (int i = 0; i < pco.num_protocol_or_container_id; i++) {
    pco_nas.protocol_or_container_ids[i].length =
        pco.protocol_or_container_ids[i].length_of_protocol_id_contents;
    pco_nas.protocol_or_container_ids[i].id =
        pco.protocol_or_container_ids[i].protocol_id;

    pco_nas.protocol_or_container_ids[i].contents = bfromcstralloc(
        pco.protocol_or_container_ids[i].protocol_id_contents.length(), "\0");
    pco_nas.protocol_or_container_ids[i].contents->slen =
        pco.protocol_or_container_ids[i].protocol_id_contents.length();
    memcpy(
        (void*) pco_nas.protocol_or_container_ids[i].contents->data,
        (void*) pco.protocol_or_container_ids[i].protocol_id_contents.c_str(),
        pco.protocol_or_container_ids[i].protocol_id_contents.length());
  }
}

void xgpp_conv::sm_context_create_data_from_openapi(
    const oai::smf_server::model::SmContextMessage& scd,
    smf::pdu_session_create_sm_context_request& pcr) {
  Logger::smf_app().debug(
      "Convert SmContextMessage (OpenAPI) to "
      "pdu_session_create_sm_context_request");

  oai::smf_server::model::SmContextCreateData context_data = scd.getJsonData();

  std::string n1_sm_msg = scd.getBinaryDataN1SmMessage();
  // N1 SM Message
  pcr.set_n1_sm_message(n1_sm_msg);
  Logger::smf_app().debug("N1 SM message: %s", n1_sm_msg.c_str());

  // supi
  supi_t supi             = {.length = 0};
  std::size_t pos         = context_data.getSupi().find("-");
  std::string supi_str    = context_data.getSupi().substr(pos + 1);
  std::string supi_prefix = context_data.getSupi().substr(0, pos);
  smf_string_to_supi(&supi, supi_str.c_str());
  pcr.set_supi(supi);
  pcr.set_supi_prefix(supi_prefix);
  Logger::smf_app().debug(
      "SUPI %s, SUPI Prefix %s, IMSI %s", context_data.getSupi().c_str(),
      supi_prefix.c_str(), supi_str.c_str());

  // dnn
  Logger::smf_app().debug("DNN %s", context_data.getDnn().c_str());
  pcr.set_dnn(context_data.getDnn().c_str());

  // S-Nssai
  Logger::smf_app().debug(
      "S-NSSAI SST %d, SD %s", context_data.getSNssai().getSst(),
      context_data.getSNssai().getSd().c_str());
  snssai_t snssai(
      context_data.getSNssai().getSst(), context_data.getSNssai().getSd());
  pcr.set_snssai(snssai);

  // PDU session ID
  Logger::smf_app().debug("PDU Session ID %d", context_data.getPduSessionId());
  pcr.set_pdu_session_id(context_data.getPduSessionId());

  // AMF ID (ServingNFId)
  Logger::smf_app().debug(
      "ServingNfId %s", context_data.getServingNfId().c_str());
  pcr.set_serving_nf_id(context_data.getServingNfId()
                            .c_str());  // TODO: should be verified that AMF ID
                                        // is stored in GUAMI or ServingNfId

  // Request Type
  Logger::smf_app().debug(
      "RequestType %s", context_data.getRequestType().c_str());
  pcr.set_request_type(context_data.getRequestType());
  // PCF ID
  // Priority Access
  // User Location Information
  // Access Type
  // PEI
  // GPSI
  // UE presence in LADN service area
  // Guami
  // servingNetwork
  // anType
  // UETimeZone
  // SMContextStatusUri
  pcr.set_sm_context_status_uri(context_data.getSmContextStatusUri());
  // PCFId

  // DNN Selection Mode
  Logger::smf_app().debug("SelMode %s", context_data.getSelMode().c_str());
  pcr.set_dnn_selection_mode(context_data.getSelMode().c_str());

  // Subscription for PDU Session Status Notification
  // Trace requirement

  // SSC mode (Optional)
  // 5GSM capability (Optional)
  // Maximum number of supported (Optional)
  // Maximum number of supported packet filters (Optional)
  // Always-on PDU session requested (Optional)
  // SM PDU DN request container (Optional)
  // Extended protocol configuration options (Optional) e.g, FOR DHCP
}
