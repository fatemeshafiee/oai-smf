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

#ifndef FILE_NGAP_COMMON_SEEN
#define FILE_NGAP_COMMON_SEEN

#include  "common_defs.h"
#include  "common_types.h"
#include  "conversions.h"
#include  "bstrlib.h"

#include  "Ngap_NGAP-PDU.h"
#include  "Ngap_ProcedureCode.h"
#include  "Ngap_TriggeringMessage.h"
#include  "Ngap_Criticality.h"
#include  "Ngap_CriticalityDiagnostics-IE-Item.h"

#include  "assertions.h"

#define NGAP_FIND_PROTOCOLIE_BY_ID(IE_TYPE, ie, container, IE_ID, mandatory) \
  do {\
    IE_TYPE **ptr; \
    ie = NULL; \
    for (ptr = container->protocolIEs.list.array; \
         ptr < &container->protocolIEs.list.array[container->protocolIEs.list.count]; \
         ptr++) { \
      if((*ptr)->id == IE_ID) { \
        ie = *ptr; \
        break; \
      } \
    } \
    if (mandatory) DevAssert(ie != NULL); \
  } while(0)

typedef int (*ngap_message_decoded_callback)(const sctp_assoc_id_t assoc_id,
                                             const sctp_stream_id_t stream,
                                             struct Ngap_NGAP_PDU *message_p);

int check_NGAP_pdu_constraints(Ngap_NGAP_PDU_t *pdu);

int ngap_amf_decode_pdu(Ngap_NGAP_PDU_t *pdu, const_bstring const raw);

#endif
