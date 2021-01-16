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

/*! \file 3gpp_29.281.h
 \brief
 \author Lionel Gauthier
 \company Eurecom
 \email: lionel.gauthier@eurecom.fr
 */

#ifndef FILE_3GPP_29_281_SEEN
#define FILE_3GPP_29_281_SEEN
#include "3gpp_29.274.h"
#include "3gpp_commons.h"
#include "common_root_types.h"
#include "logger.hpp"  // for fmt::format in spdlog

#include <arpa/inet.h>
#include <stdint.h>
#include <string>
#include <vector>

// 8.2 Recovery

// 8.3 Tunnel Endpoint Identifier Data I
typedef struct tunnel_endpoint_identifier_data_i_s {
  uint32_t tunnel_endpoint_identifier_data_i;
} tunnel_endpoint_identifier_data_i_t;

// 8.4 GTP-U Peer Address
typedef struct gtp_u_peer_address_s {
  // may use variant if can stay with C++17
  struct in_addr ipv4_address;
  struct in6_addr ipv6_address;
  bool is_v4;
} gtp_u_peer_address_t;

// 8.5 Extension Header Type List
typedef struct extension_header_type_list_s {
  uint8_t length;
  std::vector<uint8_t> extension_types_list;
} extension_header_type_list_t;

// 8.6 Private Extension defined in 3gpp_29.274.h
// typedef struct private_extension_s {
//  uint16_t  extension_identifier;
//  std::string  extension_value;
//} private_extension_t;

#endif /* FILE_3GPP_29_281_SEEN */
