/*
 * Licensed to the OpenAirInterface (OAI) Software Alliance under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The OpenAirInterface Software Alliance licenses this file to You under
 * the Apache License, Version 2.0  (the "License"); you may not use this file
 * except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
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


#ifndef FILE_SMF_SEEN
#define FILE_SMF_SEEN

#include"3gpp_29.274.h"

typedef uint64_t supi64_t;
#define SUPI_64_FMT     "%" SCNu64
//typedef imsi_t supi_t;

#define SUPI_DIGITS_MAX 15

typedef struct {
  uint32_t length;
  char data[SUPI_DIGITS_MAX + 1];
} supi_t;

static void
smf_string_to_supi (supi_t * const supi, char const * const supi_str)
{
    //strncpy(supi->data, supi_str, SUPI_DIGITS_MAX + 1);
    memcpy((void *) supi->data, (void *) supi_str, SUPI_DIGITS_MAX + 1);
    supi->length = strlen(supi->data);
    return;
}

static std::string
smf_supi_to_string (supi_t const supi)
{
      std::string supi_str;
      supi_str.assign(supi.data, SUPI_DIGITS_MAX+1);
      return supi_str;
}

static uint64_t
smf_supi_to_u64 (supi_t supi)
{
  uint64_t uint_supi;
  sscanf(supi.data, "%" SCNu64, &uint_supi);
  return uint_supi;
}

typedef struct s_nssai // section 28.4, TS23.003
{
   uint8_t  sST;
   //uint32_t sD:24;
   std::string sD;
   //s_nssai(const uint8_t& sst,  const uint32_t sd) : sST(sst), sD(sd) {}
   s_nssai(const uint8_t& sst,  const std::string sd) : sST(sst), sD(sd) {}
   s_nssai(): sST(),sD() {}
   s_nssai(const s_nssai& p) : sST(p.sST), sD(p.sD) {}

} snssai_t;

typedef uint8_t pdu_session_id;

//should move to 24.501

enum pdu_session_type_e {
  PDU_SESSION_TYPE_E_IPV4 = 1,
  PDU_SESSION_TYPE_E_IPV6 = 2,
  PDU_SESSION_TYPE_E_IPV4V6 = 3,
  PDU_SESSION_TYPE_E_UNSTRUCTURED = 4,
  PDU_SESSION_TYPE_E_ETHERNET = 5,
  PDU_SESSION_TYPE_E_RESERVED = 7,
};

static const std::vector<std::string> pdu_session_type_e2str = {"Error", "IPV4", "IPV6", "IPV4V6", "UNSTRUCTURED", "ETHERNET", "IPV4V6", "RESERVED"};

typedef struct pdu_session_type_s {
  uint8_t pdu_session_type;
  pdu_session_type_s() : pdu_session_type(PDU_SESSION_TYPE_E_IPV4) {}
  pdu_session_type_s(const uint8_t& p) : pdu_session_type(p) {}
  pdu_session_type_s(const struct pdu_session_type_s& p) : pdu_session_type(p.pdu_session_type) {}
  bool operator==(const struct pdu_session_type_s& p) const
  {
    return (p.pdu_session_type == pdu_session_type);
  }
  //------------------------------------------------------------------------------
  bool operator==(const pdu_session_type_e& p) const
  {
    return (p == pdu_session_type);
  }
  //------------------------------------------------------------------------------
  const std::string& toString() const {return pdu_session_type_e2str.at(pdu_session_type);}
} pdu_session_type_t;


#endif
