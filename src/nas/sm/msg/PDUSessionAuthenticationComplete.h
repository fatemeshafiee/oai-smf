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

#ifndef _PDUSESSIONAUTHENTICATIONCOMPLETE_H_
#define _PDUSESSIONAUTHENTICATIONCOMPLETE_H_

#include <stdint.h>

#include "ExtendedProtocolDiscriminator.h"
#include "PDUSessionIdentity.h"
#include "ProcedureTransactionIdentity.h"
#include "MessageType.h"
#include "EAPMessage.h"
#include "ExtendedProtocolConfigurationOptions.h"

#if 0
/* Minimum length macro. Formed by minimum length of each mandatory field */
#define PDU_SESSION_AUTHENTICATION_COMPLETE_MINIMUM_LENGTH ( \
		EXTENDED_PROTOCOL_DISCRIMINATOR_MINIMUM_LENGTH + \
		PDU_SESSION_IDENTITY_MINIMUM_LENGTH + \
		PROCEDURE_TRANSACTION_IDENTITY_MINIMUM_LENGTH + \
		MESSAGE_TYPE_MINIMUM_LENGTH + \
		EAP_MESSAGE_MINIMUM_LENGTH + \
		EXTENDED_PROTOCOL_CONFIGURATION_OPTIONS_MINIMUM_LENGTH + \
0)
#endif

/* Minimum length macro. Formed by minimum length of each mandatory field */
#define PDU_SESSION_AUTHENTICATION_COMPLETE_MINIMUM_LENGTH ( \
		EAP_MESSAGE_MINIMUM_LENGTH_LVE + \
0)

/* Maximum length macro. Formed by maximum length of each field */
#define PDU_SESSION_AUTHENTICATION_COMPLETE_MAXIMUM_LENGTH ( \
		EXTENDED_PROTOCOL_DISCRIMINATOR_MAXIMUM_LENGTH + \
		PDU_SESSION_IDENTITY_MAXIMUM_LENGTH + \
		PROCEDURE_TRANSACTION_IDENTITY_MAXIMUM_LENGTH + \
		MESSAGE_TYPE_MAXIMUM_LENGTH + \
		EAP_MESSAGE_MAXIMUM_LENGTH_LVE + \
		EXTENDED_PROTOCOL_CONFIGURATION_OPTIONS_MAXIMUM_LENGTH_TLVE + \
0)

#define PDU_SESSION_AUTHENTICATION_COMPLETE_EPCO_IEI			  0x7B
#define PDU_SESSION_AUTHENTICATION_COMPLETE_EPCO_PRESENCE	(1<<0)

typedef struct pdu_session_authentication_complete_msg_tag {
  ExtendedProtocolDiscriminator extendedprotocoldiscriminator;
  PDUSessionIdentity pdusessionidentity;
  ProcedureTransactionIdentity proceduretransactionidentity;
  MessageType messagetype;
  EAPMessage eapmessage;
  uint8_t presence;
  ExtendedProtocolConfigurationOptions extendedprotocolconfigurationoptions;
} pdu_session_authentication_complete_msg;

int decode_pdu_session_authentication_complete(
    pdu_session_authentication_complete_msg *pdusessionauthenticationcomplete,
    uint8_t *buffer, uint32_t len);
int encode_pdu_session_authentication_complete(
    pdu_session_authentication_complete_msg *pdusessionauthenticationcomplete,
    uint8_t *buffer, uint32_t len);

#endif
