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

void xgpp_conv::protocol_configuration_options_nas_to_core(
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

void xgpp_conv::protocol_configuration_options_core_to_nas(
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
