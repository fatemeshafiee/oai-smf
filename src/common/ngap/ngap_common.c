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

#include <stdint.h>

#include "ngap_common.h"
#include "dynamic_memory_check.h"

//--------------------------------------------------------------------
int check_NGAP_pdu_constraints(Ngap_NGAP_PDU_t *pdu) {
  int ret = -1;
  char errbuf[512];
  size_t errlen = sizeof(errbuf);
  ret = asn_check_constraints(&asn_DEF_Ngap_NGAP_PDU, pdu, errbuf, &errlen);
  if (ret != 0) {
    printf("Constraint validation  failed:%s\n", errbuf);
  }
  return ret;
}

//--------------------------------------------------------------------
int ngap_amf_decode_pdu(Ngap_NGAP_PDU_t *pdu, const_bstring const raw) {
  Ngap_NGAP_PDU_t *decoded_pdu = pdu;

  asn_dec_rval_t rc = asn_decode(NULL, ATS_ALIGNED_CANONICAL_PER, &asn_DEF_Ngap_NGAP_PDU, (void**) &decoded_pdu, bdata(raw), blength(raw));
  if (rc.code != RC_OK) {
    printf("asn_decode failed(%d)\n", rc.code);
    return rc.code;
  }
  return rc.code;
}

