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

/*! \file 3gpp_conversions.hpp
 \brief
 \author Lionel Gauthier
 \company Eurecom
 \email: lionel.gauthier@eurecom.fr
 */

#ifndef FILE_3GPP_CONVERSIONS_HPP_SEEN
#define FILE_3GPP_CONVERSIONS_HPP_SEEN
#include "3gpp_29.274.h"
#include "3gpp_29.244.h"
#include "3gpp_24.501.h"
#include "endpoint.hpp"
#include "3gpp_24.008.h"
#include "nas_lib.h"
#include "SmContextMessage.h"
#include "smf_msg.hpp"

namespace xgpp_conv {

void paa_to_pfcp_ue_ip_address(
    const paa_t& paa, pfcp::ue_ip_address_t& ue_ip_address);
void pdn_ip_to_pfcp_ue_ip_address(
    const pdu_session_type_t& pdu_session_type,
    const struct in_addr& ipv4_address, const struct in6_addr ipv6_address,
    pfcp::ue_ip_address_t& ue_ip_address);

void pco_nas_to_core(
    const protocol_configuration_options_nas_t& pco_nas,
    protocol_configuration_options_t& pco);

void pco_core_to_nas(
    const protocol_configuration_options_t& pco,
    protocol_configuration_options_nas_t& pco_nas);
void sm_context_create_data_from_openapi(
    const oai::smf_server::model::SmContextMessage& scd,
    smf::pdu_session_create_sm_context_request& pcr);

}  // namespace xgpp_conv

#endif /* FILE_3GPP_CONVERSIONS_HPP_SEEN */
