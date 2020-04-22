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

/*! \file smf_n1_n2.cpp
 \brief
 \author  Tien-Thinh NGUYEN, Keliang DU
 \company Eurecom
 \date 2019
 \email:  tien-thinh.nguyen@eurecom.fr
 */

#include "smf_n1_n2.hpp"

#include "string.hpp"
#include <stdexcept>

#include <curl/curl.h>
#include <nlohmann/json.hpp>
#include <pistache/http.h>
#include <pistache/mime.h>
#include <arpa/inet.h>

extern "C" {
#include "nas_message.h"
#include "Ngap_NGAP-PDU.h"
#include "Ngap_ProtocolIE-Field.h"
#include "Ngap_ProcedureCode.h"
#include "Ngap_Criticality.h"
#include "Ngap_PDUSessionResourceSetupRequestTransfer.h"
#include "Ngap_PDUSessionResourceSetupResponseTransfer.h"
#include "Ngap_QosFlowSetupRequestItem.h"
#include "Ngap_GTPTunnel.h"
#include "Ngap_NonDynamic5QIDescriptor.h"
#include "Ngap_Dynamic5QIDescriptor.h"
#include "Ngap_AssociatedQosFlowItem.h"
#include "Ngap_PDUSessionResourceModifyRequestTransfer.h"
#include "Ngap_UL-NGU-UP-TNLModifyItem.h"
#include "Ngap_QosFlowAddOrModifyRequestItem.h"
#include "Ngap_PDUSessionResourceReleaseCommandTransfer.h"
#include "dynamic_memory_check.h"
#include "Ngap_PDUSessionResourceReleaseResponseTransfer.h"
}

#define BUF_LEN 512
using namespace Pistache::Http;
using namespace Pistache::Http::Mime;

//TODO: move to a common file
#define AMF_CURL_TIMEOUT_MS 100L
#define AMF_NUMBER_RETRIES 3

using namespace smf;
extern smf_app *smf_app_inst;

/*
 * To read content of the response from UDM
 */
static std::size_t callback(const char *in, std::size_t size, std::size_t num,
                            std::string *out) {
  const std::size_t totalBytes(size * num);
  out->append(in, totalBytes);
  return totalBytes;
}

//-----------------------------------------------------------------------------------------------------
void smf_n1_n2::create_n1_sm_container(pdu_session_msg &msg,
                                       uint8_t n1_msg_type,
                                       std::string &nas_msg_str,
                                       cause_value_5gsm_e sm_cause) {

  Logger::smf_app().info("Create N1 SM Container, n1 message type %d",
                         n1_msg_type);

  //To be updated according to NAS implementation
  int size = NAS_MESSAGE_SECURITY_HEADER_SIZE;
  int bytes = { 0 };
  int length = BUF_LEN;
  unsigned char data[BUF_LEN] = { '\0' };
  memset(data, 0, sizeof(data));

  nas_message_t nas_msg = { };
  memset(&nas_msg, 0, sizeof(nas_message_t));
  nas_msg.header.extended_protocol_discriminator =
      EPD_5GS_SESSION_MANAGEMENT_MESSAGES;
  nas_msg.header.security_header_type = SECURITY_HEADER_TYPE_NOT_PROTECTED;
  //nas_msg.header.sequence_number = 0xfe;
  //nas_msg.header.message_authentication_code = 0xffee;

  SM_msg *sm_msg = &nas_msg.plain.sm;
  //Fill the content of SM header
  //Extended Protocol Discriminator
  sm_msg->header.extended_protocol_discriminator =
      EPD_5GS_SESSION_MANAGEMENT_MESSAGES;
  //PDU Session Identity
  sm_msg->header.pdu_session_identity = msg.get_pdu_session_id();

  switch (n1_msg_type) {

    //PDU Session Establishment Accept
    case PDU_SESSION_ESTABLISHMENT_ACCEPT: {
      //PDU Session Establishment Accept is including in the N1N2MessageTransfer Request
      //sent from SMF to AMF (PDU Session Establishment procedure)
      if (msg.get_msg_type() != PDU_SESSION_CREATE_SM_CONTEXT_RESPONSE) {
        Logger::smf_app().error(
            "Cannot create an PDU Session Establishment Accept for this message (type %d)",
            msg.get_msg_type());
        return;
      }

      pdu_session_create_sm_context_response &sm_context_res =
          static_cast<pdu_session_create_sm_context_response&>(msg);

      //get default QoS value
      qos_flow_context_updated qos_flow = { };
      qos_flow = sm_context_res.get_qos_flow_context();
      //TODO: to be completed
      //get the default QoS profile and assign to the NAS message

      Logger::smf_app().info(
          "PDU_SESSION_ESTABLISHMENT_ACCEPT, encode starting...");

      //Fill the rest of SM header
      //PTI
      sm_msg->header.procedure_transaction_identity = sm_context_res.get_pti()
          .procedure_transaction_id;
      //Message Type
      sm_msg->header.message_type = PDU_SESSION_ESTABLISHMENT_ACCEPT;

      Logger::smf_app().debug(
          "NAS header, Extended Protocol Discriminator 0x%x, Security Header Type 0x%x",
          nas_msg.header.extended_protocol_discriminator,
          nas_msg.header.security_header_type);
      Logger::smf_app().debug(
          "SM header, Extended Protocol Discriminator 0x%x, PDU Session Identity 0x%x, Procedure Transaction Identity: 0x%x, Message Type: 0x%x",
          sm_msg->header.extended_protocol_discriminator,
          sm_msg->header.pdu_session_identity,
          sm_msg->header.procedure_transaction_identity,
          sm_msg->header.message_type);

      //Fill the content of PDU Session Establishment Accept message
      //PDU Session Type
      sm_msg->pdu_session_establishment_accept._pdusessiontype
          .pdu_session_type_value = sm_context_res.get_pdu_session_type();
      Logger::smf_app().debug(
          "PDU Session Type: %#0x",
          sm_msg->pdu_session_establishment_accept._pdusessiontype
              .pdu_session_type_value);

      //SSC Mode
      sm_msg->pdu_session_establishment_accept.sscmode.ssc_mode_value =
          SSC_MODE_1;  //TODO: get from sm_context_res
      Logger::smf_app().debug(
          "SSC Mode: %#0x",
          sm_msg->pdu_session_establishment_accept.sscmode.ssc_mode_value);

      //authorized QoS rules of the PDU session: QOSRules (Section 6.2.5@3GPP TS 24.501)
      //(Section 6.4.1.3@3GPP TS 24.501 V16.1.0) Make sure that the number of the packet filters used in the authorized QoS rules of the PDU Session does not
      // exceed the maximum number of packet filters supported by the UE for the PDU session
      sm_msg->pdu_session_establishment_accept.qosrules.lengthofqosrulesie = 1;
      sm_msg->pdu_session_establishment_accept.qosrules.qosrulesie =
          (QOSRulesIE*) calloc(1, sizeof(QOSRulesIE));
      sm_msg->pdu_session_establishment_accept.qosrules.qosrulesie[0]
          .qosruleidentifer = qos_flow.qos_rule.qosruleidentifer;
      sm_msg->pdu_session_establishment_accept.qosrules.qosrulesie[0]
          .ruleoperationcode = qos_flow.qos_rule.ruleoperationcode;
      sm_msg->pdu_session_establishment_accept.qosrules.qosrulesie[0].dqrbit =
          qos_flow.qos_rule.dqrbit;
      sm_msg->pdu_session_establishment_accept.qosrules.qosrulesie[0]
          .numberofpacketfilters = qos_flow.qos_rule.numberofpacketfilters;
      //1st rule
      sm_msg->pdu_session_establishment_accept.qosrules.qosrulesie[0]
          .packetfilterlist.create_modifyandadd_modifyandreplace =
          (Create_ModifyAndAdd_ModifyAndReplace*) calloc(
              1, sizeof(Create_ModifyAndAdd_ModifyAndReplace));
      sm_msg->pdu_session_establishment_accept.qosrules.qosrulesie[0]
          .packetfilterlist.create_modifyandadd_modifyandreplace
          ->packetfilterdirection = qos_flow.qos_rule.packetfilterlist
          .create_modifyandadd_modifyandreplace->packetfilterdirection;
      sm_msg->pdu_session_establishment_accept.qosrules.qosrulesie[0]
          .packetfilterlist.create_modifyandadd_modifyandreplace
          ->packetfilteridentifier = qos_flow.qos_rule.packetfilterlist
          .create_modifyandadd_modifyandreplace->packetfilteridentifier;
      sm_msg->pdu_session_establishment_accept.qosrules.qosrulesie[0]
          .packetfilterlist.create_modifyandadd_modifyandreplace
          ->packetfiltercontents.component_type = qos_flow.qos_rule
          .packetfilterlist.create_modifyandadd_modifyandreplace
          ->packetfiltercontents.component_type;
      sm_msg->pdu_session_establishment_accept.qosrules.qosrulesie[0]
          .qosruleprecedence = qos_flow.qos_rule.qosruleprecedence;
      sm_msg->pdu_session_establishment_accept.qosrules.qosrulesie[0]
          .segregation = qos_flow.qos_rule.segregation;
      sm_msg->pdu_session_establishment_accept.qosrules.qosrulesie[0]
          .qosflowidentifer = qos_flow.qfi.qfi;

      //SessionAMBR
      //TODO: get from subscription DB
      supi_t supi = sm_context_res.get_supi();
      supi64_t supi64 = smf_supi_to_u64(supi);
      std::shared_ptr<smf_context> sc = { };
      if (smf_app_inst->is_supi_2_smf_context(supi64)) {
        Logger::smf_app().debug("Get SMF context with SUPI " SUPI_64_FMT "",
                                supi64);
        sc = smf_app_inst->supi_2_smf_context(supi64);
        sc.get()->get_session_ambr(
            sm_msg->pdu_session_establishment_accept.sessionambr,
            sm_context_res.get_snssai(), sm_context_res.get_dnn());
      } else {
        Logger::smf_app().warn(
            "SMF context with SUPI " SUPI_64_FMT " does not exist!", supi64);
        //TODO:
      }

      //Presence
      sm_msg->pdu_session_establishment_accept.presence = 0xffff;  //TODO: To be updated
      //_5GSMCause
      //sm_msg->pdu_session_establishment_accept._5gsmcause = sm_context_res.get_cause();
      sm_msg->pdu_session_establishment_accept._5gsmcause =
          static_cast<uint8_t>(sm_cause);
      Logger::smf_app().debug(
          "5GSM Cause: %#0x",
          sm_msg->pdu_session_establishment_accept._5gsmcause);

      //PDUAddress
      paa_t paa = sm_context_res.get_paa();
      unsigned char bitStream_pdu_address_information[4];
      bitStream_pdu_address_information[0] =
          (uint8_t) ((paa.ipv4_address.s_addr) & 0x000000ff);
      bitStream_pdu_address_information[1] = (uint8_t) (((paa.ipv4_address
          .s_addr) & 0x0000ff00) >> 8);
      bitStream_pdu_address_information[2] = (uint8_t) (((paa.ipv4_address
          .s_addr) & 0x00ff0000) >> 16);
      bitStream_pdu_address_information[3] = (uint8_t) (((paa.ipv4_address
          .s_addr) & 0xff000000) >> 24);

      sm_msg->pdu_session_establishment_accept.pduaddress
          .pdu_address_information = bfromcstralloc(4, "\0");
      sm_msg->pdu_session_establishment_accept.pduaddress
          .pdu_address_information->slen = 4;

      memcpy(
          sm_msg->pdu_session_establishment_accept.pduaddress
              .pdu_address_information->data,
          bitStream_pdu_address_information,
          sizeof(bitStream_pdu_address_information));

      sm_msg->pdu_session_establishment_accept.pduaddress.pdu_session_type_value =
          static_cast<uint8_t>(PDU_SESSION_TYPE_E_IPV4);
      Logger::smf_app().debug("PDU Address %s",
                              conv::toString(paa.ipv4_address).c_str());

      //GPRSTimer
      //sm_msg->pdu_session_establishment_accept.gprstimer.unit = GPRSTIMER_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_2_SECONDS;
      //sm_msg->pdu_session_establishment_accept.gprstimer.timeValue = 0;

      //SNSSAI
      sm_msg->pdu_session_establishment_accept.snssai.len = SST_AND_SD_LENGTH;
      sm_msg->pdu_session_establishment_accept.snssai.sst = sm_context_res
          .get_snssai().sST;

      try {
        sm_msg->pdu_session_establishment_accept.snssai.sd = std::stoul(
            sm_context_res.get_snssai().sD, nullptr, 16);
      } catch (const std::exception &e) {
        Logger::smf_app().warn(
            "Error when converting from string to int for snssai.SD, error: %s",
            e.what());
        //"no SD value associated with the SST"
        sm_msg->pdu_session_establishment_accept.snssai.sd = 0xFFFFFF;
      }

      Logger::smf_app().debug(
          "SNSSAI SST %#0x, SD %#0x",
          sm_msg->pdu_session_establishment_accept.snssai.sst,
          sm_msg->pdu_session_establishment_accept.snssai.sd);

      //AlwaysonPDUSessionIndication
      //sm_msg->pdu_session_establishment_accept.alwaysonpdusessionindication.apsi_indication = ALWAYSON_PDU_SESSION_REQUIRED;

      //MappedEPSBearerContexts mappedepsbearercontexts;
      //EAPMessage

      //authorized QoS flow descriptions IE: QoSFlowDescritions
      if (smf_app_inst->is_supi_2_smf_context(supi64)) {
        Logger::smf_app().debug("Get SMF context with SUPI " SUPI_64_FMT "",
                                supi64);
        sc = smf_app_inst->supi_2_smf_context(supi64);
        sm_msg->pdu_session_establishment_accept.qosflowdescriptions
            .qosflowdescriptionsnumber = 1;
        sm_msg->pdu_session_establishment_accept.qosflowdescriptions
            .qosflowdescriptionscontents =
            (QOSFlowDescriptionsContents*) calloc(
                1, sizeof(QOSFlowDescriptionsContents));
        sc.get()->get_default_qos_flow_description(
            sm_msg->pdu_session_establishment_accept.qosflowdescriptions
                .qosflowdescriptionscontents[0],
            sm_context_res.get_pdu_session_type());
      }

      //ExtendedProtocolConfigurationOptions

      //DNN
      sm_msg->pdu_session_establishment_accept.dnn = bfromcstralloc(
          sm_context_res.get_dnn().length(), "\0");
      sm_msg->pdu_session_establishment_accept.dnn->slen = sm_context_res
          .get_dnn().length();
      memcpy((void*) sm_msg->pdu_session_establishment_accept.dnn->data,
             (void*) sm_context_res.get_dnn().c_str(),
             sm_context_res.get_dnn().length());
      std::string dnn_str(
          (char*) sm_msg->pdu_session_establishment_accept.dnn->data,
          sm_msg->pdu_session_establishment_accept.dnn->slen);
      Logger::smf_app().debug("DNN %s", dnn_str.c_str());

      //Encode NAS message
      bytes = nas_message_encode(data, &nas_msg,
                                 sizeof(data)/*don't know the size*/, nullptr);

      Logger::smf_app().debug("Buffer Data: ");
      for (int i = 0; i < bytes; i++)
        printf("%02x ", data[i]);
      printf(" (bytes %d)\n", bytes);

      std::string n1Message((char*) data, bytes);
      nas_msg_str = n1Message;

      //free memory
      free_wrapper(
          (void**) &sm_msg->pdu_session_establishment_accept.qosrules.qosrulesie[0]
              .packetfilterlist.create_modifyandadd_modifyandreplace);
      free_wrapper(
          (void**) &sm_msg->pdu_session_establishment_accept.qosrules.qosrulesie);
      free_wrapper(
          (void**) &sm_msg->pdu_session_establishment_accept.qosflowdescriptions
              .qosflowdescriptionscontents);

    }
      break;

    case PDU_SESSION_ESTABLISHMENT_REJECT: {
      //PDU Session Establishment Reject is included in the following messages:
      //1 - PDU Session Create SM Context Response (PDU Session Establishment procedure - reject)
      //2 - N1N2MessageTransfer Request (PDU Session Establishment procedure - reject)
      //3-  PDU Session Update SM Context Response (PDU Session Establishment procedure - reject)​
      //PDU_SESSION_CREATE_SM_CONTEXT_RESPONSE or PDU_SESSION_CREATE_SM_CONTEXT_REQUEST

      Logger::smf_app().info(
          "PDU_SESSION_ESTABLISHMENT_REJECT, encode starting...");

      //Fill the content of PDU Session Establishment Reject message
      //PDU Session ID
      sm_msg->header.pdu_session_identity = msg.get_pdu_session_id();
      //PTI
      sm_msg->header.procedure_transaction_identity = msg.get_pti()
          .procedure_transaction_id;
      //Message Type
      sm_msg->header.message_type = PDU_SESSION_ESTABLISHMENT_REJECT;
      Logger::smf_app().debug(
          "NAS header, Extended Protocol Discriminator  0x%x, Security Header Type: 0x%x",
          nas_msg.header.extended_protocol_discriminator,
          nas_msg.header.security_header_type);

      Logger::smf_app().debug(
          "SM header, PDU Session Identity 0x%x, Procedure Transaction Identity 0x%x, Message Type 0x%x",
          sm_msg->header.pdu_session_identity,
          sm_msg->header.procedure_transaction_identity,
          sm_msg->header.message_type);

      //5GSM Cause
      sm_msg->pdu_session_establishment_reject._5gsmcause =
          static_cast<uint8_t>(sm_cause);
      //Presence
      sm_msg->pdu_session_establishment_reject.presence =
      PDU_SESSION_ESTABLISHMENT_REJECT_ALLOWED_SSC_MODE_PRESENCE;  //Should be updated according to the following IEs
      /*
       //GPRSTimer3
       sm_msg->pdu_session_establishment_reject.gprstimer3.unit =
       GPRSTIMER3_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_1_HOUR;
       sm_msg->pdu_session_establishment_reject.gprstimer3.timeValue = 0;
       */
      //AllowedSSCMode
      sm_msg->pdu_session_establishment_reject.allowedsscmode.is_ssc1_allowed =
      SSC_MODE1_ALLOWED;
      sm_msg->pdu_session_establishment_reject.allowedsscmode.is_ssc2_allowed =
      SSC_MODE2_NOT_ALLOWED;
      sm_msg->pdu_session_establishment_reject.allowedsscmode.is_ssc3_allowed =
      SSC_MODE3_NOT_ALLOWED;

      /*
       //EAPMessage
       unsigned char bitStream_eapmessage[2] = {0x01,0x02};
       bstring eapmessage_tmp = bfromcstralloc(2, "\0");
       eapmessage_tmp->slen = 2;
       memcpy(eapmessage_tmp->data,bitStream_eapmessage,sizeof(bitStream_eapmessage));
       sm_msg->pdu_session_establishment_reject.eapmessage = bfromcstralloc(2, "\0");
       sm_msg->pdu_session_establishment_reject.eapmessage->slen = 2;

       //ExtendedProtocolConfigurationOptions
       unsigned char bitStream_extendedprotocolconfigurationoptions[4];
       bitStream_extendedprotocolconfigurationoptions[0] = 0x12;
       bitStream_extendedprotocolconfigurationoptions[1] = 0x13;
       bitStream_extendedprotocolconfigurationoptions[2] = 0x14;
       bitStream_extendedprotocolconfigurationoptions[3] = 0x15;
       bstring extendedprotocolconfigurationoptions_tmp = bfromcstralloc(4, "\0");
       extendedprotocolconfigurationoptions_tmp->slen = 4;
       memcpy(extendedprotocolconfigurationoptions_tmp->data,bitStream_extendedprotocolconfigurationoptions,sizeof(bitStream_extendedprotocolconfigurationoptions));
       sm_msg->pdu_session_establishment_reject.extendedprotocolconfigurationoptions = extendedprotocolconfigurationoptions_tmp;

       //5GSM CongestionReattemptIndicator
       sm_msg->pdu_session_establishment_reject._5gsmcongestionreattemptindicator.abo = THE_BACKOFF_TIMER_IS_APPLIED_IN_ALL_PLMNS;
       */

      Logger::smf_app().debug(
          "SM MSG, 5GSM Cause: 0x%x",
          sm_msg->pdu_session_establishment_reject._5gsmcause);
      Logger::smf_app().debug(
          "SM MSG, Allowed SSC Mode, SSC1 allowed 0x%x, SSC2 allowed 0x%x, SSC3 allowed 0x%x",
          sm_msg->pdu_session_establishment_reject.allowedsscmode
              .is_ssc1_allowed,
          sm_msg->pdu_session_establishment_reject.allowedsscmode
              .is_ssc2_allowed,
          sm_msg->pdu_session_establishment_reject.allowedsscmode
              .is_ssc3_allowed);

      //Encode NAS message
      bytes = nas_message_encode(data, &nas_msg,
                                 sizeof(data)/*don't know the size*/, nullptr);

      Logger::smf_app().debug("Buffer Data: ");
      for (int i = 0; i < bytes; i++)
        printf("%02x ", data[i]);
      printf(" (bytes %d)\n", bytes);

      std::string n1Message((char*) data, bytes);
      nas_msg_str = n1Message;

    }
      break;

    case PDU_SESSION_MODIFICATION_COMMAND: {
      //PDU Session Modification Command is included in the following messages:
      //1- PDU Session Update SM Context Response (PDU Session Modification UE-Initiated procedure - step 1)
      //2- N1N2MessageTransfer Request (PDU Session Modification SMF-Requested, step 1 (from SMF to AMF)) ​

      Logger::smf_app().debug(
          "[Create N1 SM Message] PDU Session Modification Command");
      //case 1 (case2: need to be verified?)
      pdu_session_update_sm_context_response &sm_context_res =
          static_cast<pdu_session_update_sm_context_response&>(msg);

      Logger::smf_app().info(
          "PDU_SESSION_MODIFICATION_COMMAND, encode starting...");

      //Fill the content of PDU Session Establishment Request message with hardcoded values (to be completed)
      //PTI
      sm_msg->header.procedure_transaction_identity = sm_context_res.get_pti()
          .procedure_transaction_id;
      //Message Type
      sm_msg->header.message_type = PDU_SESSION_MODIFICATION_COMMAND;
      //PDU Session Type
      sm_msg->pdu_session_modification_command.messagetype = sm_context_res
          .get_msg_type();
      //Presence
      sm_msg->pdu_session_modification_command.presence = 0xff;  //TODO: to be updated
      //5GSMCause
      sm_msg->pdu_session_modification_command._5gsmcause =
          static_cast<uint8_t>(sm_cause);  //sm_context_res.get_cause();

      /*
       ExtendedProtocolDiscriminator extendedprotocoldiscriminator;
       PDUSessionIdentity pdusessionidentity;
       ProcedureTransactionIdentity proceduretransactionidentity;
       MessageType messagetype;
       uint8_t presence;
       _5GSMCause _5gsmcause;
       SessionAMBR sessionambr;
       GPRSTimer gprstimer;
       AlwaysonPDUSessionIndication alwaysonpdusessionindication;
       QOSRules qosrules;
       MappedEPSBearerContexts mappedepsbearercontexts;
       QOSFlowDescriptions qosflowdescriptions;
       ExtendedProtocolConfigurationOptions extendedprotocolconfigurationoptions;
       */

      //SessionAMBR
      //TODO: get from subscription DB
      supi_t supi = sm_context_res.get_supi();
      supi64_t supi64 = smf_supi_to_u64(supi);
      std::shared_ptr<smf_context> sc = { };
      if (smf_app_inst->is_supi_2_smf_context(supi64)) {
        Logger::smf_app().debug("Get SMF context with SUPI " SUPI_64_FMT "",
                                supi64);
        sc = smf_app_inst->supi_2_smf_context(supi64);
        sc.get()->get_session_ambr(
            sm_msg->pdu_session_modification_command.sessionambr,
            sm_context_res.get_snssai(), sm_context_res.get_dnn());
      } else {
        Logger::smf_app().warn(
            "SMF context with SUPI " SUPI_64_FMT " does not exist!", supi64);
        //TODO:
      }

      //GPRSTimer
      //TODO:
      //AlwaysonPDUSessionIndication
      //TODO:

      //QOSRules
      sm_msg->pdu_session_modification_command.qosrules.lengthofqosrulesie = 1;
      sm_msg->pdu_session_modification_command.qosrules.qosrulesie =
          (QOSRulesIE*) calloc(1, sizeof(QOSRulesIE));
      sm_msg->pdu_session_modification_command.qosrules.qosrulesie[0]
          .qosruleidentifer = 0x01;
      sm_msg->pdu_session_modification_command.qosrules.qosrulesie[0]
          .ruleoperationcode = CREATE_NEW_QOS_RULE;
      sm_msg->pdu_session_modification_command.qosrules.qosrulesie[0].dqrbit =
      THE_QOS_RULE_IS_DEFAULT_QOS_RULE;
      sm_msg->pdu_session_modification_command.qosrules.qosrulesie[0]
          .numberofpacketfilters = 1;
      //1st rule
      sm_msg->pdu_session_modification_command.qosrules.qosrulesie[0]
          .packetfilterlist.create_modifyandadd_modifyandreplace =
          (Create_ModifyAndAdd_ModifyAndReplace*) calloc(
              1, sizeof(Create_ModifyAndAdd_ModifyAndReplace));
      sm_msg->pdu_session_modification_command.qosrules.qosrulesie[0]
          .packetfilterlist.create_modifyandadd_modifyandreplace
          ->packetfilterdirection = 0b01;
      sm_msg->pdu_session_modification_command.qosrules.qosrulesie[0]
          .packetfilterlist.create_modifyandadd_modifyandreplace
          ->packetfilteridentifier = 1;
      sm_msg->pdu_session_modification_command.qosrules.qosrulesie[0]
          .packetfilterlist.create_modifyandadd_modifyandreplace
          ->packetfiltercontents.component_type = QOS_RULE_MATCHALL_TYPE;
      sm_msg->pdu_session_modification_command.qosrules.qosrulesie[0]
          .qosruleprecedence = 1;
      sm_msg->pdu_session_modification_command.qosrules.qosrulesie[0]
          .segregation = SEGREGATION_NOT_REQUESTED;
      sm_msg->pdu_session_modification_command.qosrules.qosrulesie[0]
          .qosflowidentifer = 60;

      //MappedEPSBearerContexts
      //TODO:

      //QOSFlowDescriptions
      //authorized QoS flow descriptions IE: QoSFlowDescritions
      if (smf_app_inst->is_supi_2_smf_context(supi64)) {
        Logger::smf_app().debug("Get SMF context with SUPI " SUPI_64_FMT "",
                                supi64);
        sc = smf_app_inst->supi_2_smf_context(supi64);
        sm_msg->pdu_session_modification_command.qosflowdescriptions
            .qosflowdescriptionsnumber = 1;
        sm_msg->pdu_session_modification_command.qosflowdescriptions
            .qosflowdescriptionscontents =
            (QOSFlowDescriptionsContents*) calloc(
                1, sizeof(QOSFlowDescriptionsContents));
        sc.get()->get_default_qos_flow_description(
            sm_msg->pdu_session_modification_command.qosflowdescriptions
                .qosflowdescriptionscontents[0],
            sm_context_res.get_pdu_session_type());
      }

      //Encode NAS message
      bytes = nas_message_encode(data, &nas_msg,
                                 sizeof(data)/*don't know the size*/, nullptr);

      Logger::smf_app().debug("Buffer Data: ");
      for (int i = 0; i < bytes; i++)
        printf("%02x ", data[i]);
      printf(" (bytes %d)\n", bytes);

      std::string n1Message((char*) data, bytes);
      nas_msg_str = n1Message;

      //free memory
      free_wrapper(
          (void**) &sm_msg->pdu_session_modification_command.qosrules.qosrulesie[0]
              .packetfilterlist.create_modifyandadd_modifyandreplace);
      free_wrapper(
          (void**) &sm_msg->pdu_session_modification_command.qosrules.qosrulesie);
      free_wrapper(
          (void**) &sm_msg->pdu_session_modification_command.qosflowdescriptions
              .qosflowdescriptionscontents);

    }
      break;

      //PDU Session Release UE-Initiated (section 4.3.4@3GPP TS 23.502, step 1)
    case PDU_SESSION_RELEASE_COMMAND: {
      //this IE is included in the following message
      //1 - PDU Session Update SM Context Response (PDU Session Release UE-Initiated, step 1)
      //2 - N1N2MessageTransfer Request (PDU Session Release SMF-Requested, step 1)

      Logger::smf_app().debug(
          "[Create N1 SM Message] PDU Session Release Command");
      //case 1 (case2: need to be verified?)
      pdu_session_update_sm_context_response &sm_context_res =
          static_cast<pdu_session_update_sm_context_response&>(msg);

      Logger::smf_app().info("PDU_SESSION_RELEASE_COMMAND, encode starting...");
      //Fill the content of PDU Session Release Command
      //PDU Session ID
      sm_msg->header.pdu_session_identity = sm_context_res.get_pdu_session_id();
      //PTI
      sm_msg->header.procedure_transaction_identity = sm_context_res.get_pti()
          .procedure_transaction_id;
      //Message Type
      sm_msg->header.message_type = PDU_SESSION_RELEASE_COMMAND;
      //5GSMCause
      sm_msg->pdu_session_release_command._5gsmcause =
          static_cast<uint8_t>(sm_cause);  //sm_context_res.get_cause();
      //Presence
      sm_msg->pdu_session_release_command.presence = 0x00;  //TODO: to be updated when adding the following IEs
      //GPRSTimer3
      //EAPMessage
      //_5GSMCongestionReattemptIndicator
      // ExtendedProtocolConfigurationOptions

      Logger::smf_app().debug("SM MSG, 5GSM Cause: 0x%x, %d",
                              sm_msg->pdu_session_release_command._5gsmcause,
                              static_cast<uint8_t>(sm_cause));

      //Encode NAS message
      bytes = nas_message_encode(data, &nas_msg,
                                 sizeof(data)/*don't know the size*/, nullptr);

      Logger::smf_app().debug("Buffer Data: ");
      for (int i = 0; i < bytes; i++)
        printf("%02x ", data[i]);
      printf(" (bytes %d)\n", bytes);

      std::string n1Message((char*) data, bytes);
      nas_msg_str = n1Message;

    }
      break;

    case PDU_SESSION_RELEASE_REJECT: {
      //This IE is included in the PDU Session Update SM Context Response (PDU Session Release UE-Initiated, step 1)

      Logger::smf_app().debug(
          "[Create N1 SM Message] PDU Session Release Reject");
      Logger::smf_app().info("PDU_SESSION_RELEASE_REJECT, encode starting...");
      pdu_session_update_sm_context_response &sm_context_res =
          static_cast<pdu_session_update_sm_context_response&>(msg);

      //Fill the content of PDU Session Release Reject
      //PDU Session ID
      sm_msg->header.pdu_session_identity = sm_context_res.get_pdu_session_id();
      //PTI
      sm_msg->header.procedure_transaction_identity = sm_context_res.get_pti()
          .procedure_transaction_id;
      //Message Type
      sm_msg->header.message_type = PDU_SESSION_RELEASE_REJECT;
      //5GSMCause
      sm_msg->pdu_session_release_reject._5gsmcause =
          static_cast<uint8_t>(sm_cause);  //sm_context_res.get_cause();

      //Presence
      sm_msg->pdu_session_release_command.presence = 0x00;  //TODO: to be updated when adding the following IE
      //Extended protocol configuration options

      //Encode NAS message
      bytes = nas_message_encode(data, &nas_msg,
                                 sizeof(data)/*don't know the size*/, nullptr);

      Logger::smf_app().debug("Buffer Data: ");
      for (int i = 0; i < bytes; i++)
        printf("%02x ", data[i]);
      printf(" (bytes %d)\n", bytes);

      std::string n1Message((char*) data, bytes);
      nas_msg_str = n1Message;

    }
      break;

    default: {
      Logger::smf_app().debug("Unknown PDU Session Type");
      //TODO:
    }

  }      //end Switch

}

//------------------------------------------------------------------------------
void smf_n1_n2::create_n2_sm_information(pdu_session_msg &msg,
                                         uint8_t ngap_msg_type,
                                         n2_sm_info_type_e ngap_ie_type,
                                         std::string &ngap_msg_str) {
  //TODO: To be filled with the correct parameters
  Logger::smf_app().info(
      "Create N2 SM Information, NGAP message type %d, IE type %d",
      ngap_msg_type, ngap_ie_type);

  switch (ngap_ie_type) {

    //PDU Session Resource Setup Request Transfer
    //need to be verified with Wireshark (case 1)
    case n2_sm_info_type_e::PDU_RES_SETUP_REQ: {
      //PDU Session Resource Setup Request Transfer
      //This IE is included in the following messages:
      //1 - N1N2MessageTransfer Request (Accept, PDU Session Establishment procedure - UE initiated) (PDU Session Create SM Context)
      //2 - PDU Session Update SM Context Response​ (Service Request, step 2)

      Ngap_PDUSessionResourceSetupRequestTransfer_t *ngap_IEs = nullptr;
      ngap_IEs = (Ngap_PDUSessionResourceSetupRequestTransfer_t*) calloc(
          1, sizeof(Ngap_PDUSessionResourceSetupRequestTransfer_t));
      qos_flow_context_updated qos_flow = { };

      switch (msg.get_msg_type()) {
        //Case 1: in N1N2MessageTransfer Request
        case PDU_SESSION_CREATE_SM_CONTEXT_RESPONSE: {
          pdu_session_create_sm_context_response &sm_context_res =
              static_cast<pdu_session_create_sm_context_response&>(msg);
          //get default QoS value
          qos_flow = sm_context_res.get_qos_flow_context();

          Logger::smf_app().debug(
              "UL F-TEID, Teid" "0x%" PRIx32 ", IP Address %s",
              qos_flow.ul_fteid.teid_gre_key,
              conv::toString(qos_flow.ul_fteid.ipv4_address).c_str());
          Logger::smf_app().info(
              "QoS parameters: QFI %d, Priority level %d, ARP priority level %d",
              qos_flow.qfi.qfi, qos_flow.qos_profile.priority_level,
              qos_flow.qos_profile.arp.priority_level);
        }
          break;

          //Case 2: in PDU Session Update SM Context Response​ (Service Request, step 2)​
        case PDU_SESSION_UPDATE_SM_CONTEXT_RESPONSE: {
          Logger::smf_app().info("PDU_SESSION_UPDATE_SM_CONTEXT_RESPONSE");
          pdu_session_update_sm_context_response &sm_context_res =
              static_cast<pdu_session_update_sm_context_response&>(msg);

          //get default QoS value
          std::map<uint8_t, qos_flow_context_updated> qos_flows = { };
          sm_context_res.get_all_qos_flow_context_updateds(qos_flows);
          for (std::map<uint8_t, qos_flow_context_updated>::iterator it =
              qos_flows.begin(); it != qos_flows.end(); ++it)
            Logger::smf_app().debug("qos_flow_context_updated qfi %d",
                                    it->first);
          //TODO: support only 1 qos flow
          qos_flow = qos_flows.begin()->second;

          Logger::smf_app().debug("UL F-TEID, Teid" "0x%" PRIx32 "",
                                  qos_flow.ul_fteid.teid_gre_key);
          Logger::smf_app().debug(
              "UL F-TEID, IP Addr: %s",
              conv::toString(qos_flow.ul_fteid.ipv4_address).c_str());
          Logger::smf_app().info(
              "QoS parameters: QFI %d, Priority level %d, ARP priority level %d",
              qos_flow.qfi.qfi, qos_flow.qos_profile.priority_level,
              qos_flow.qos_profile.arp.priority_level);
        }
          break;

        default:
          Logger::smf_app().warn("Unknown message type: %d \n",
                                 msg.get_msg_type());
          //TODO:
          free_wrapper((void**) &ngap_IEs);
          return;
      }

      //PDUSessionAggregateMaximumBitRate
      Ngap_PDUSessionResourceSetupRequestTransferIEs_t *pduSessionAggregateMaximumBitRate =
          nullptr;
      pduSessionAggregateMaximumBitRate =
          (Ngap_PDUSessionResourceSetupRequestTransferIEs_t*) calloc(
              1, sizeof(Ngap_PDUSessionResourceSetupRequestTransferIEs_t));
      pduSessionAggregateMaximumBitRate->id =
      Ngap_ProtocolIE_ID_id_PDUSessionAggregateMaximumBitRate;
      pduSessionAggregateMaximumBitRate->criticality = Ngap_Criticality_reject;
      pduSessionAggregateMaximumBitRate->value.present =
          Ngap_PDUSessionResourceSetupRequestTransferIEs__value_PR_PDUSessionAggregateMaximumBitRate;

      //SessionAMBR
      supi_t supi = msg.get_supi();
      supi64_t supi64 = smf_supi_to_u64(supi);
      std::shared_ptr<smf_context> sc = { };
      if (smf_app_inst->is_supi_2_smf_context(supi64)) {
        Logger::smf_app().debug("Get SMF context with SUPI " SUPI_64_FMT "",
                                supi64);
        sc = smf_app_inst->supi_2_smf_context(supi64);
        sc.get()->get_session_ambr(
            pduSessionAggregateMaximumBitRate->value.choice
                .PDUSessionAggregateMaximumBitRate,
            msg.get_snssai(), msg.get_dnn());
      } else {
        Logger::smf_app().warn(
            "SMF context with SUPI " SUPI_64_FMT " does not exist!", supi64);
        //TODO:
      }
      ASN_SEQUENCE_ADD(&ngap_IEs->protocolIEs.list,
                       pduSessionAggregateMaximumBitRate);

      //UPTransportLayerInformation
      Ngap_PDUSessionResourceSetupRequestTransferIEs_t *upTransportLayerInformation =
          nullptr;
      upTransportLayerInformation =
          (Ngap_PDUSessionResourceSetupRequestTransferIEs_t*) calloc(
              1, sizeof(Ngap_PDUSessionResourceSetupRequestTransferIEs_t));
      upTransportLayerInformation->id =
      Ngap_ProtocolIE_ID_id_UL_NGU_UP_TNLInformation;
      upTransportLayerInformation->criticality = Ngap_Criticality_reject;
      upTransportLayerInformation->value.present =
          Ngap_PDUSessionResourceSetupRequestTransferIEs__value_PR_UPTransportLayerInformation;
      upTransportLayerInformation->value.choice.UPTransportLayerInformation
          .present = Ngap_UPTransportLayerInformation_PR_gTPTunnel;

      upTransportLayerInformation->value.choice.UPTransportLayerInformation
          .choice.gTPTunnel = (Ngap_GTPTunnel_t*) calloc(
          1, sizeof(Ngap_GTPTunnel_t));
      upTransportLayerInformation->value.choice.UPTransportLayerInformation
          .choice.gTPTunnel->transportLayerAddress.size = 4;
      upTransportLayerInformation->value.choice.UPTransportLayerInformation
          .choice.gTPTunnel->transportLayerAddress.buf = (uint8_t*) calloc(
          4, sizeof(uint8_t));
      memcpy(
          upTransportLayerInformation->value.choice.UPTransportLayerInformation
              .choice.gTPTunnel->transportLayerAddress.buf,
          &qos_flow.ul_fteid.ipv4_address, 4);
      upTransportLayerInformation->value.choice.UPTransportLayerInformation
          .choice.gTPTunnel->transportLayerAddress.bits_unused = 0;

      upTransportLayerInformation->value.choice.UPTransportLayerInformation
          .choice.gTPTunnel->gTP_TEID.size = sizeof(struct in_addr);
      upTransportLayerInformation->value.choice.UPTransportLayerInformation
          .choice.gTPTunnel->gTP_TEID.buf = (uint8_t*) calloc(
          sizeof(struct in_addr), sizeof(uint8_t));
      memcpy(
          upTransportLayerInformation->value.choice.UPTransportLayerInformation
              .choice.gTPTunnel->gTP_TEID.buf,
          &qos_flow.ul_fteid.teid_gre_key, sizeof(struct in_addr));

      ASN_SEQUENCE_ADD(&ngap_IEs->protocolIEs.list,
                       upTransportLayerInformation);

      //DataForwardingNotPossible
      //TODO:

      //PDUSessionType
      Ngap_PDUSessionResourceSetupRequestTransferIEs_t *pduSessionType = nullptr;
      pduSessionType =
          (Ngap_PDUSessionResourceSetupRequestTransferIEs_t*) calloc(
              1, sizeof(Ngap_PDUSessionResourceSetupRequestTransferIEs_t));
      pduSessionType->id = Ngap_ProtocolIE_ID_id_PDUSessionType;
      pduSessionType->criticality = Ngap_Criticality_reject;
      pduSessionType->value.present =
          Ngap_PDUSessionResourceSetupRequestTransferIEs__value_PR_PDUSessionType;
      pduSessionType->value.choice.PDUSessionType = msg.get_pdu_session_type();  //TODO: different between Ngap_PDUSessionType_ipv4 vs pdu_session_type_e::PDU_SESSION_TYPE_E_IPV4
      ASN_SEQUENCE_ADD(&ngap_IEs->protocolIEs.list, pduSessionType);

      //SecurityIndication
      //TODO: should get from UDM
      //    Ngap_PDUSessionResourceSetupRequestTransferIEs_t  *securityIndication =  nullptr;
      //   securityIndication = (Ngap_PDUSessionResourceSetupRequestTransferIEs_t *) calloc(1, sizeof(Ngap_PDUSessionResourceSetupRequestTransferIEs_t));
      //   securityIndication->value.choice.SecurityIndication.integrityProtectionIndication = Ngap_IntegrityProtectionIndication_not_needed;
      //   securityIndication->value.choice.SecurityIndication.confidentialityProtectionIndication = Ngap_ConfidentialityProtectionIndication_not_needed;

      //NetworkInstance
      //TODO:

      //QosFlowSetupRequestList
      Ngap_PDUSessionResourceSetupRequestTransferIEs_t *qosFlowSetupRequestList =
          nullptr;
      qosFlowSetupRequestList =
          (Ngap_PDUSessionResourceSetupRequestTransferIEs_t*) calloc(
              1, sizeof(Ngap_PDUSessionResourceSetupRequestTransferIEs_t));
      qosFlowSetupRequestList->id =
      Ngap_ProtocolIE_ID_id_QosFlowSetupRequestList;
      qosFlowSetupRequestList->criticality = Ngap_Criticality_reject;
      qosFlowSetupRequestList->value.present =
          Ngap_PDUSessionResourceSetupRequestTransferIEs__value_PR_QosFlowSetupRequestList;

      Ngap_QosFlowSetupRequestItem_t *ngap_QosFlowSetupRequestItem = nullptr;
      ngap_QosFlowSetupRequestItem = (Ngap_QosFlowSetupRequestItem_t*) calloc(
          1, sizeof(Ngap_QosFlowSetupRequestItem_t));
      ngap_QosFlowSetupRequestItem->qosFlowIdentifier = (uint8_t) qos_flow.qfi
          .qfi;
      ngap_QosFlowSetupRequestItem->qosFlowLevelQosParameters.qosCharacteristics
          .present = Ngap_QosCharacteristics_PR_nonDynamic5QI;
      ngap_QosFlowSetupRequestItem->qosFlowLevelQosParameters.qosCharacteristics
          .choice.nonDynamic5QI = (Ngap_NonDynamic5QIDescriptor_t*) (calloc(
          1, sizeof(Ngap_NonDynamic5QIDescriptor_t)));
      ngap_QosFlowSetupRequestItem->qosFlowLevelQosParameters.qosCharacteristics
          .choice.nonDynamic5QI->fiveQI = (uint8_t) qos_flow.qfi.qfi;
      ngap_QosFlowSetupRequestItem->qosFlowLevelQosParameters
          .allocationAndRetentionPriority.priorityLevelARP = qos_flow
          .qos_profile.arp.priority_level;
      if (qos_flow.qos_profile.arp.preempt_cap.compare("NOT_PREEMPT") == 0) {
        ngap_QosFlowSetupRequestItem->qosFlowLevelQosParameters
            .allocationAndRetentionPriority.pre_emptionCapability =
            Ngap_Pre_emptionCapability_shall_not_trigger_pre_emption;
      } else {
        ngap_QosFlowSetupRequestItem->qosFlowLevelQosParameters
            .allocationAndRetentionPriority.pre_emptionCapability =
            Ngap_Pre_emptionCapability_may_trigger_pre_emption;
      }
      if (qos_flow.qos_profile.arp.preempt_vuln.compare("NOT_PREEMPTABLE")
          == 0) {
        ngap_QosFlowSetupRequestItem->qosFlowLevelQosParameters
            .allocationAndRetentionPriority.pre_emptionVulnerability =
            Ngap_Pre_emptionVulnerability_not_pre_emptable;
      } else {
        ngap_QosFlowSetupRequestItem->qosFlowLevelQosParameters
            .allocationAndRetentionPriority.pre_emptionVulnerability =
            Ngap_Pre_emptionVulnerability_pre_emptable;
      }

      ASN_SEQUENCE_ADD(
          &qosFlowSetupRequestList->value.choice.QosFlowSetupRequestList.list,
          ngap_QosFlowSetupRequestItem);
      ASN_SEQUENCE_ADD(&ngap_IEs->protocolIEs.list, qosFlowSetupRequestList);

      //encode
      size_t buffer_size = 512;
      char *buffer = (char*) calloc(1, buffer_size);

      asn_enc_rval_t er = aper_encode_to_buffer(
          &asn_DEF_Ngap_PDUSessionResourceSetupRequestTransfer, nullptr,
          ngap_IEs, (void*) buffer, buffer_size);
      if (er.encoded < 0) {
        Logger::smf_app().warn(
            "[Create N2 SM Information] NGAP PDU Session Resource Setup Request Transfer encode failed, er.encoded: %d",
            er.encoded);
        return;
      }

      Logger::smf_app().debug("N2 SM buffer data: ");
      for (int i = 0; i < er.encoded; i++)
        printf("%02x ", (char) buffer[i]);
      printf(" (%d bytes)\n", (int) er.encoded);
      std::string ngap_message((char*) buffer, er.encoded);
      ngap_msg_str = ngap_message;

      //free memory
      free_wrapper((void**) &pduSessionAggregateMaximumBitRate);
      free_wrapper(
          (void**) &upTransportLayerInformation->value.choice
              .UPTransportLayerInformation.choice.gTPTunnel
              ->transportLayerAddress.buf);
      free_wrapper(
          (void**) &upTransportLayerInformation->value.choice
              .UPTransportLayerInformation.choice.gTPTunnel->gTP_TEID.buf);
      free_wrapper(
          (void**) &upTransportLayerInformation->value.choice
              .UPTransportLayerInformation.choice.gTPTunnel);
      free_wrapper((void**) &upTransportLayerInformation);
      free_wrapper((void**) &pduSessionType);
      free_wrapper((void**) &qosFlowSetupRequestList);
      free_wrapper(
          (void**) &ngap_QosFlowSetupRequestItem->qosFlowLevelQosParameters
              .qosCharacteristics.choice.nonDynamic5QI);
      free_wrapper((void**) &ngap_QosFlowSetupRequestItem);
      free_wrapper((void**) &ngap_IEs);
      free_wrapper((void**) &buffer);

    }
      break;

      //PDU Session Resource Modify Request Transfer IE
    case n2_sm_info_type_e::PDU_RES_MOD_REQ: {
      //PDU Session Resource Modify Request Transfer IE​
      //This IE is included in the following messages (PDU Session SM Context Update):
      //1 - PDU Session Update SM Context Response (PDU Session Modification procedure, UE-initiated, step 1)
      //2 - N1N2MessageTransfer Request (PDU Session Modification procedure, SMF-requested, step 1)

      Logger::smf_app().debug(
          "[Create N2 SM Information] NGAP PDU Session Resource Modify Request Transfer");

      pdu_session_update_sm_context_response &sm_context_res =
          static_cast<pdu_session_update_sm_context_response&>(msg);

      //get default QoS info
      std::map<uint8_t, qos_flow_context_updated> qos_flows = { };
      sm_context_res.get_all_qos_flow_context_updateds(qos_flows);
      for (std::map<uint8_t, qos_flow_context_updated>::iterator it = qos_flows
          .begin(); it != qos_flows.end(); ++it)
        Logger::smf_app().debug("qos_flow_context_updated qfi %d", it->first);
      //TODO: support only 1 qos flow
      qos_flow_context_updated qos_flow = qos_flows.begin()->second;

      Logger::smf_app().debug(
          "QoS Flow, UL gTP_TEID " "0x%" PRIx32 ", UL IP Address %s ",
          qos_flow.ul_fteid.teid_gre_key,
          conv::toString(qos_flow.ul_fteid.ipv4_address).c_str());
      Logger::smf_app().debug(
          "QoS Flow, DL gTP_TEID " "0x%" PRIx32 ", DL IP Address %s",
          qos_flow.dl_fteid.teid_gre_key,
          conv::toString(qos_flow.dl_fteid.ipv4_address).c_str());

      Ngap_PDUSessionResourceModifyRequestTransfer_t *ngap_IEs = nullptr;
      ngap_IEs = (Ngap_PDUSessionResourceModifyRequestTransfer_t*) calloc(
          1, sizeof(Ngap_PDUSessionResourceModifyRequestTransfer_t));

      //PDUSessionAggregateMaximumBitRate
      Ngap_PDUSessionResourceModifyRequestTransferIEs_t *pduSessionAggregateMaximumBitRate =
          nullptr;
      pduSessionAggregateMaximumBitRate =
          (Ngap_PDUSessionResourceModifyRequestTransferIEs_t*) calloc(
              1, sizeof(Ngap_PDUSessionResourceModifyRequestTransferIEs_t));
      pduSessionAggregateMaximumBitRate->id =
      Ngap_ProtocolIE_ID_id_PDUSessionAggregateMaximumBitRate;
      pduSessionAggregateMaximumBitRate->criticality = Ngap_Criticality_reject;
      pduSessionAggregateMaximumBitRate->value.present =
          Ngap_PDUSessionResourceModifyRequestTransferIEs__value_PR_PDUSessionAggregateMaximumBitRate;

      supi_t supi = sm_context_res.get_supi();
      supi64_t supi64 = smf_supi_to_u64(supi);
      std::shared_ptr<smf_context> sc = { };
      if (smf_app_inst->is_supi_2_smf_context(supi64)) {
        Logger::smf_app().debug("Get SMF context with SUPI " SUPI_64_FMT "",
                                supi64);
        sc = smf_app_inst->supi_2_smf_context(supi64);
        sc.get()->get_session_ambr(
            pduSessionAggregateMaximumBitRate->value.choice
                .PDUSessionAggregateMaximumBitRate,
            sm_context_res.get_snssai(), sm_context_res.get_dnn());
      } else {
        Logger::smf_app().warn(
            "SMF context with SUPI " SUPI_64_FMT " does not exist!", supi64);
        //TODO:
      }
      ASN_SEQUENCE_ADD(&ngap_IEs->protocolIEs.list,
                       pduSessionAggregateMaximumBitRate);

      //Ngap_UL_NGU_UP_TNLModifyList_t
      Ngap_PDUSessionResourceModifyRequestTransferIEs_t *ul_NGU_UP_TNLModifyList =
          nullptr;
      ul_NGU_UP_TNLModifyList =
          (Ngap_PDUSessionResourceModifyRequestTransferIEs_t*) calloc(
              1, sizeof(Ngap_PDUSessionResourceModifyRequestTransferIEs_t));
      ul_NGU_UP_TNLModifyList->id =
      Ngap_ProtocolIE_ID_id_UL_NGU_UP_TNLModifyList;
      ul_NGU_UP_TNLModifyList->criticality = Ngap_Criticality_reject;
      ul_NGU_UP_TNLModifyList->value.present =
          Ngap_PDUSessionResourceModifyRequestTransferIEs__value_PR_UL_NGU_UP_TNLModifyList;
      Ngap_UL_NGU_UP_TNLModifyItem_t *ngap_UL_NGU_UP_TNLModifyItem = nullptr;
      ngap_UL_NGU_UP_TNLModifyItem = (Ngap_UL_NGU_UP_TNLModifyItem_t*) calloc(
          1, sizeof(Ngap_UL_NGU_UP_TNLModifyItem_t));
      ngap_UL_NGU_UP_TNLModifyItem->uL_NGU_UP_TNLInformation.present =
          Ngap_UPTransportLayerInformation_PR_gTPTunnel;
      ngap_UL_NGU_UP_TNLModifyItem->uL_NGU_UP_TNLInformation.choice.gTPTunnel =
          (Ngap_GTPTunnel_t*) calloc(1, sizeof(Ngap_GTPTunnel_t));
      ngap_UL_NGU_UP_TNLModifyItem->uL_NGU_UP_TNLInformation.choice.gTPTunnel
          ->transportLayerAddress.buf = (uint8_t*) calloc(4, sizeof(uint8_t));
      memcpy(
          ngap_UL_NGU_UP_TNLModifyItem->uL_NGU_UP_TNLInformation.choice
              .gTPTunnel->transportLayerAddress.buf,
          &qos_flow.ul_fteid.ipv4_address, 4);
      ngap_UL_NGU_UP_TNLModifyItem->uL_NGU_UP_TNLInformation.choice.gTPTunnel
          ->transportLayerAddress.size = 4;
      ngap_UL_NGU_UP_TNLModifyItem->uL_NGU_UP_TNLInformation.choice.gTPTunnel
          ->transportLayerAddress.bits_unused = 0;

      ngap_UL_NGU_UP_TNLModifyItem->uL_NGU_UP_TNLInformation.choice.gTPTunnel
          ->gTP_TEID.size = sizeof(struct in_addr);
      ngap_UL_NGU_UP_TNLModifyItem->uL_NGU_UP_TNLInformation.choice.gTPTunnel
          ->gTP_TEID.buf = (uint8_t*) calloc(sizeof(struct in_addr),
                                             sizeof(uint8_t));
      memcpy(
          ngap_UL_NGU_UP_TNLModifyItem->uL_NGU_UP_TNLInformation.choice
              .gTPTunnel->gTP_TEID.buf,
          &qos_flow.ul_fteid.teid_gre_key, sizeof(struct in_addr));

      ngap_UL_NGU_UP_TNLModifyItem->dL_NGU_UP_TNLInformation.present =
          Ngap_UPTransportLayerInformation_PR_gTPTunnel;
      ngap_UL_NGU_UP_TNLModifyItem->dL_NGU_UP_TNLInformation.choice.gTPTunnel =
          (Ngap_GTPTunnel_t*) calloc(1, sizeof(Ngap_GTPTunnel_t));
      ngap_UL_NGU_UP_TNLModifyItem->dL_NGU_UP_TNLInformation.choice.gTPTunnel
          ->transportLayerAddress.buf = (uint8_t*) calloc(4, sizeof(uint8_t));
      memcpy(
          ngap_UL_NGU_UP_TNLModifyItem->dL_NGU_UP_TNLInformation.choice
              .gTPTunnel->transportLayerAddress.buf,
          &qos_flow.dl_fteid.ipv4_address, 4);
      ngap_UL_NGU_UP_TNLModifyItem->dL_NGU_UP_TNLInformation.choice.gTPTunnel
          ->transportLayerAddress.size = 4;
      ngap_UL_NGU_UP_TNLModifyItem->dL_NGU_UP_TNLInformation.choice.gTPTunnel
          ->transportLayerAddress.bits_unused = 0;

      ngap_UL_NGU_UP_TNLModifyItem->dL_NGU_UP_TNLInformation.choice.gTPTunnel
          ->gTP_TEID.size = sizeof(struct in_addr);
      ngap_UL_NGU_UP_TNLModifyItem->dL_NGU_UP_TNLInformation.choice.gTPTunnel
          ->gTP_TEID.buf = (uint8_t*) calloc(sizeof(struct in_addr),
                                             sizeof(uint8_t));
      memcpy(
          ngap_UL_NGU_UP_TNLModifyItem->dL_NGU_UP_TNLInformation.choice
              .gTPTunnel->gTP_TEID.buf,
          &qos_flow.dl_fteid.teid_gre_key, 4);
      ASN_SEQUENCE_ADD(
          &ul_NGU_UP_TNLModifyList->value.choice.UL_NGU_UP_TNLModifyList.list,
          ngap_UL_NGU_UP_TNLModifyItem);
      ASN_SEQUENCE_ADD(&ngap_IEs->protocolIEs.list, ul_NGU_UP_TNLModifyList);

      //Ngap_NetworkInstance_t
      //TODO

      //Ngap_QosFlowAddOrModifyRequestList_t
      //TODO: to be completed
      Ngap_PDUSessionResourceModifyRequestTransferIEs_t *qosFlowAddOrModifyRequestList =
          nullptr;
      qosFlowAddOrModifyRequestList =
          (Ngap_PDUSessionResourceModifyRequestTransferIEs_t*) calloc(
              1, sizeof(Ngap_PDUSessionResourceModifyRequestTransferIEs_t));

      qosFlowAddOrModifyRequestList->id =
      Ngap_ProtocolIE_ID_id_QosFlowAddOrModifyRequestList;
      qosFlowAddOrModifyRequestList->criticality = Ngap_Criticality_reject;
      qosFlowAddOrModifyRequestList->value.present =
          Ngap_PDUSessionResourceModifyRequestTransferIEs__value_PR_QosFlowAddOrModifyRequestList;
      Ngap_QosFlowAddOrModifyRequestItem *ngap_QosFlowAddOrModifyRequestItem =
          nullptr;
      ngap_QosFlowAddOrModifyRequestItem =
          (Ngap_QosFlowAddOrModifyRequestItem*) calloc(
              1, sizeof(Ngap_QosFlowAddOrModifyRequestItem));
      ngap_QosFlowAddOrModifyRequestItem->qosFlowIdentifier = qos_flow.qfi.qfi;

      ngap_QosFlowAddOrModifyRequestItem->qosFlowLevelQosParameters =
          (struct Ngap_QosFlowLevelQosParameters*) calloc(
              1, sizeof(struct Ngap_QosFlowLevelQosParameters));
      ngap_QosFlowAddOrModifyRequestItem->qosFlowLevelQosParameters
          ->qosCharacteristics.present =
          Ngap_QosCharacteristics_PR_nonDynamic5QI;
      ngap_QosFlowAddOrModifyRequestItem->qosFlowLevelQosParameters
          ->qosCharacteristics.choice.nonDynamic5QI =
          (Ngap_NonDynamic5QIDescriptor_t*) (calloc(
              1, sizeof(Ngap_NonDynamic5QIDescriptor_t)));
      ngap_QosFlowAddOrModifyRequestItem->qosFlowLevelQosParameters
          ->qosCharacteristics.choice.nonDynamic5QI->fiveQI = qos_flow.qfi.qfi;
      ngap_QosFlowAddOrModifyRequestItem->qosFlowLevelQosParameters
          ->allocationAndRetentionPriority.priorityLevelARP = qos_flow
          .qos_profile.priority_level;
      if (qos_flow.qos_profile.arp.preempt_cap.compare("NOT_PREEMPT") == 0) {
        ngap_QosFlowAddOrModifyRequestItem->qosFlowLevelQosParameters
            ->allocationAndRetentionPriority.pre_emptionCapability =
            Ngap_Pre_emptionCapability_shall_not_trigger_pre_emption;
      } else {
        ngap_QosFlowAddOrModifyRequestItem->qosFlowLevelQosParameters
            ->allocationAndRetentionPriority.pre_emptionCapability =
            Ngap_Pre_emptionCapability_may_trigger_pre_emption;
      }
      if (qos_flow.qos_profile.arp.preempt_vuln.compare("NOT_PREEMPTABLE")
          == 0) {
        ngap_QosFlowAddOrModifyRequestItem->qosFlowLevelQosParameters
            ->allocationAndRetentionPriority.pre_emptionVulnerability =
            Ngap_Pre_emptionVulnerability_not_pre_emptable;
      } else {
        ngap_QosFlowAddOrModifyRequestItem->qosFlowLevelQosParameters
            ->allocationAndRetentionPriority.pre_emptionVulnerability =
            Ngap_Pre_emptionVulnerability_pre_emptable;
      }

      ASN_SEQUENCE_ADD(
          &qosFlowAddOrModifyRequestList->value.choice
              .QosFlowAddOrModifyRequestList.list,
          ngap_QosFlowAddOrModifyRequestItem);
      //Ngap_E_RAB_ID_t *e_RAB_ID;  //optional
      ASN_SEQUENCE_ADD(&ngap_IEs->protocolIEs.list,
                       qosFlowAddOrModifyRequestList);

      //Ngap_QosFlowList_t - QoS to release list??
      //TODO
      //Ngap_UPTransportLayerInformation_t
      //TODO

      //encode
      size_t buffer_size = 512;
      char *buffer = (char*) calloc(1, buffer_size);

      asn_enc_rval_t er = aper_encode_to_buffer(
          &asn_DEF_Ngap_PDUSessionResourceModifyRequestTransfer, nullptr,
          ngap_IEs, (void*) buffer, buffer_size);
      if (er.encoded < 0) {
        Logger::smf_app().warn(
            "[Create N2 SM Information] NGAP PDU Session Resource Modify Request Transfer encode failed, er.encoded: %d",
            er.encoded);
        return;
      }

      Logger::smf_app().debug("N2 SM buffer data: ");
      for (int i = 0; i < er.encoded; i++)
        printf("%02x ", (char) buffer[i]);
      printf(" (%d bytes)\n", (int) er.encoded);
      std::string ngap_message((char*) buffer, er.encoded);
      ngap_msg_str = ngap_message;

      //free memory
      free_wrapper((void**) &pduSessionAggregateMaximumBitRate);
      free_wrapper(
          (void**) &ngap_UL_NGU_UP_TNLModifyItem->uL_NGU_UP_TNLInformation
              .choice.gTPTunnel->transportLayerAddress.buf);
      free_wrapper(
          (void**) &ngap_UL_NGU_UP_TNLModifyItem->uL_NGU_UP_TNLInformation
              .choice.gTPTunnel->gTP_TEID.buf);
      free_wrapper(
          (void**) &ngap_UL_NGU_UP_TNLModifyItem->dL_NGU_UP_TNLInformation
              .choice.gTPTunnel->transportLayerAddress.buf);
      free_wrapper(
          (void**) &ngap_UL_NGU_UP_TNLModifyItem->dL_NGU_UP_TNLInformation
              .choice.gTPTunnel->gTP_TEID.buf);
      free_wrapper((void**) &ngap_UL_NGU_UP_TNLModifyItem);
      free_wrapper((void**) &ul_NGU_UP_TNLModifyList);
      free_wrapper(
          (void**) &ngap_QosFlowAddOrModifyRequestItem
              ->qosFlowLevelQosParameters->qosCharacteristics.choice
              .nonDynamic5QI);
      free_wrapper(
          (void**) &ngap_QosFlowAddOrModifyRequestItem
              ->qosFlowLevelQosParameters);
      free_wrapper((void**) &ngap_QosFlowAddOrModifyRequestItem);
      free_wrapper((void**) &qosFlowAddOrModifyRequestList);
      free_wrapper((void**) &ngap_IEs);
      free_wrapper((void**) &buffer);
    }
      break;

    case n2_sm_info_type_e::PDU_RES_SETUP_RSP: {
      //PDU Session Resource Setup Response Transfer
      //for testing purpose

      Logger::smf_app().debug(
          "[Create N2 SM Information] NGAP PDU Session Resource Setup Response Transfer");
      //	  Ngap_QosFlowPerTNLInformation_t  qosFlowPerTNLInformation;
      //	  struct Ngap_QosFlowPerTNLInformation  *additionalQosFlowPerTNLInformation;  /* OPTIONAL */
      //	  struct Ngap_SecurityResult  *securityResult;  /* OPTIONAL */
      //	  struct Ngap_QosFlowList *qosFlowFailedToSetupList;  /* OPTIONAL */
      //	  struct Ngap_ProtocolExtensionContainer  *iE_Extensions; /* OPTIONAL */

      Ngap_PDUSessionResourceSetupResponseTransfer_t *ngap_resource_response_transfer =
          nullptr;
      ngap_resource_response_transfer =
          (Ngap_PDUSessionResourceSetupResponseTransfer_t*) calloc(
              1, sizeof(Ngap_PDUSessionResourceSetupResponseTransfer_t));
      ngap_resource_response_transfer->dLQosFlowPerTNLInformation
          .uPTransportLayerInformation.present =
          Ngap_UPTransportLayerInformation_PR_gTPTunnel;
      ngap_resource_response_transfer->dLQosFlowPerTNLInformation
          .uPTransportLayerInformation.choice.gTPTunnel =
          (Ngap_GTPTunnel_t*) calloc(1, sizeof(Ngap_GTPTunnel_t));

      ngap_resource_response_transfer->dLQosFlowPerTNLInformation
          .uPTransportLayerInformation.choice.gTPTunnel->transportLayerAddress
          .size = 4;
      ngap_resource_response_transfer->dLQosFlowPerTNLInformation
          .uPTransportLayerInformation.choice.gTPTunnel->transportLayerAddress
          .buf = (uint8_t*) calloc(4, sizeof(uint8_t));
      ngap_resource_response_transfer->dLQosFlowPerTNLInformation
          .uPTransportLayerInformation.choice.gTPTunnel->transportLayerAddress
          .buf[0] = 0xc0;
      ngap_resource_response_transfer->dLQosFlowPerTNLInformation
          .uPTransportLayerInformation.choice.gTPTunnel->transportLayerAddress
          .buf[1] = 0xa8;
      ngap_resource_response_transfer->dLQosFlowPerTNLInformation
          .uPTransportLayerInformation.choice.gTPTunnel->transportLayerAddress
          .buf[2] = 0xf8;
      ngap_resource_response_transfer->dLQosFlowPerTNLInformation
          .uPTransportLayerInformation.choice.gTPTunnel->transportLayerAddress
          .buf[3] = 0x9f;
      ngap_resource_response_transfer->dLQosFlowPerTNLInformation
          .uPTransportLayerInformation.choice.gTPTunnel->transportLayerAddress
          .bits_unused = 0;

      ngap_resource_response_transfer->dLQosFlowPerTNLInformation
          .uPTransportLayerInformation.choice.gTPTunnel->gTP_TEID.size =
          sizeof(struct in_addr);
      ngap_resource_response_transfer->dLQosFlowPerTNLInformation
          .uPTransportLayerInformation.choice.gTPTunnel->gTP_TEID.buf =
          (uint8_t*) calloc(sizeof(struct in_addr), sizeof(uint8_t));
      ngap_resource_response_transfer->dLQosFlowPerTNLInformation
          .uPTransportLayerInformation.choice.gTPTunnel->gTP_TEID.buf[0] = 0x00;
      ngap_resource_response_transfer->dLQosFlowPerTNLInformation
          .uPTransportLayerInformation.choice.gTPTunnel->gTP_TEID.buf[1] = 0x00;
      ngap_resource_response_transfer->dLQosFlowPerTNLInformation
          .uPTransportLayerInformation.choice.gTPTunnel->gTP_TEID.buf[2] = 0x00;
      ngap_resource_response_transfer->dLQosFlowPerTNLInformation
          .uPTransportLayerInformation.choice.gTPTunnel->gTP_TEID.buf[3] = 0x01;

      Ngap_AssociatedQosFlowItem_t *qos_flow_item = nullptr;
      qos_flow_item = (Ngap_AssociatedQosFlowItem_t*) calloc(
          1, sizeof(Ngap_AssociatedQosFlowItem_t));
      qos_flow_item->qosFlowIdentifier = 60;

      ASN_SEQUENCE_ADD(
          &ngap_resource_response_transfer->dLQosFlowPerTNLInformation
              .associatedQosFlowList.list,
          qos_flow_item);

      //encode
      size_t buffer_size = 512;
      char *buffer = (char*) calloc(1, buffer_size);

      asn_enc_rval_t er = aper_encode_to_buffer(
          &asn_DEF_Ngap_PDUSessionResourceSetupResponseTransfer, nullptr,
          ngap_resource_response_transfer, (void*) buffer, buffer_size);
      if (er.encoded < 0) {
        Logger::smf_app().warn(
            "[Create N2 SM Information] NGAP PDU Session Resource Setup Response Transfer encode failed, er.encoded: %d",
            er.encoded);
        return;
      }

      Logger::smf_app().debug("N2 SM buffer data: ");
      for (int i = 0; i < er.encoded; i++)
        printf("%02x ", (char) buffer[i]);
      Logger::smf_app().debug(" (%d bytes) \n", er.encoded);
      std::string ngap_message((char*) buffer, er.encoded);
      ngap_msg_str = ngap_message;

      //free memory
      free_wrapper(
          (void**) &ngap_resource_response_transfer->dLQosFlowPerTNLInformation
              .uPTransportLayerInformation.choice.gTPTunnel
              ->transportLayerAddress.buf);
      free_wrapper(
          (void**) &ngap_resource_response_transfer->dLQosFlowPerTNLInformation
              .uPTransportLayerInformation.choice.gTPTunnel->gTP_TEID.buf);
      free_wrapper(
          (void**) &ngap_resource_response_transfer->dLQosFlowPerTNLInformation
              .uPTransportLayerInformation.choice.gTPTunnel);
      free_wrapper((void**) &ngap_resource_response_transfer);
      free_wrapper((void**) &qos_flow_item);
      free_wrapper((void**) &buffer);
    }
      break;

      //PDU Session Resource Release Command Transfer
    case n2_sm_info_type_e::PDU_RES_REL_CMD: {
      //PDU Session Resource Release Command Transfer IE
      //This IE is included in the following messages:
      //1 - PDU Session Update SM Context Response (PDU Session Release UE-Initiated: section 4.3.4@3GPP TS 23.502, step 1)
      //2 - N1N2MessageTransfer Request​ (PDU Session Release SMF-Requested, step 1)
      //TODO:

      Ngap_PDUSessionResourceReleaseCommandTransfer_t *ngap_resource_release_command_transfer =
          nullptr;
      ngap_resource_release_command_transfer =
          (Ngap_PDUSessionResourceReleaseCommandTransfer_t*) calloc(
              1, sizeof(Ngap_PDUSessionResourceReleaseCommandTransfer_t));

      //TODO: To be completed, here's an example
      /*
       typedef struct Ngap_Cause {
       Ngap_Cause_PR present;
       union Ngap_Cause_u {
       Ngap_CauseRadioNetwork_t   radioNetwork;
       Ngap_CauseTransport_t  transport;
       Ngap_CauseNas_t  nas;
       Ngap_CauseProtocol_t   protocol;
       Ngap_CauseMisc_t   misc;
       struct Ngap_ProtocolIE_SingleContainer  *choice_Extensions;
       } choice;

       asn_struct_ctx_t _asn_ctx;
       } Ngap_Cause_t;
       */
      ngap_resource_release_command_transfer->cause.present =
          Ngap_Cause_PR_radioNetwork;
      ngap_resource_release_command_transfer->cause.choice.radioNetwork = 1;

      //encode
      size_t buffer_size = 512;
      char *buffer = (char*) calloc(1, buffer_size);

      asn_enc_rval_t er = aper_encode_to_buffer(
          &asn_DEF_Ngap_PDUSessionResourceReleaseCommandTransfer, nullptr,
          ngap_resource_release_command_transfer, (void*) buffer, buffer_size);

      if (er.encoded < 0) {
        Logger::smf_app().warn(
            "[Create N2 SM Information] NGAP PDU Session Release Command encode failed, er.encoded: %d",
            er.encoded);
        return;
      }

      Logger::smf_app().debug("N2 SM buffer data: ");
      for (int i = 0; i < er.encoded; i++)
        printf("%02x ", (char) buffer[i]);
      Logger::smf_app().debug(" (%d bytes) \n", er.encoded);
      std::string ngap_message((char*) buffer, er.encoded);
      ngap_msg_str = ngap_message;

      //free memory
      free_wrapper((void**) &ngap_resource_release_command_transfer);
      free_wrapper((void**) &buffer);

    }
      break;

      //PDU Session Resource Release Response Transfer
      //FOR TESTING PURPOSE ONLY!!
    case n2_sm_info_type_e::PDU_RES_REL_RSP: {
      //PDU Session Resource Release Response Transfer IE
      //This IE is included in:
      //1 - PDU Session Update SM Context Request (PDU Session Release UE-Initiated, step 2 - UPLINK)

      Ngap_PDUSessionResourceReleaseResponseTransfer_t *ngap_resource_release_response_transfer =
          nullptr;
      ngap_resource_release_response_transfer =
          (Ngap_PDUSessionResourceReleaseResponseTransfer_t*) calloc(
              1, sizeof(Ngap_PDUSessionResourceReleaseResponseTransfer_t));

      //TODO: To be completed, here's an example
      //encode
      size_t buffer_size = 512;
      char *buffer = (char*) calloc(1, buffer_size);

      asn_enc_rval_t er = aper_encode_to_buffer(
          &asn_DEF_Ngap_PDUSessionResourceReleaseResponseTransfer, nullptr,
          ngap_resource_release_response_transfer, (void*) buffer, buffer_size);

      if (er.encoded < 0) {
        Logger::smf_app().warn(
            "[Create N2 SM Information] NGAP PDU Session Release Command encode failed, er.encoded: %d",
            er.encoded);
        return;
      }

      Logger::smf_app().debug("N2 SM buffer data: ");
      for (int i = 0; i < er.encoded; i++)
        printf("%02x ", (char) buffer[i]);
      Logger::smf_app().debug(" (%d bytes) \n", er.encoded);
      std::string ngap_message((char*) buffer, er.encoded);
      ngap_msg_str = ngap_message;

      //free memory
      free_wrapper((void**) &ngap_resource_release_response_transfer);
      free_wrapper((void**) &buffer);

    }
      break;

    default:
      Logger::smf_app().warn("Unknown NGAP IE type: %s \n",
                             n2_sm_info_type_e2str[(uint8_t) ngap_ie_type]);
  }

}

//------------------------------------------------------------------------------
int smf_n1_n2::decode_n1_sm_container(nas_message_t &nas_msg,
                                      std::string &n1_sm_msg) {
  Logger::smf_app().info("Decode NAS message from N1 SM Container");

  //step 1. Decode NAS  message (for instance, ... only served as an example)
  nas_message_decode_status_t decode_status = { 0 };
  int decoder_rc = RETURNok;

  unsigned int data_len = n1_sm_msg.length();
  unsigned char *data = (unsigned char*) malloc(data_len + 1);
  memset(data, 0, data_len + 1);
  memcpy((void*) data, (void*) n1_sm_msg.c_str(), data_len);

  printf("Content: ");
  for (int i = 0; i < data_len; i++)
    printf(" %02x ", data[i]);
  printf("\n");

  //decode the NAS message (using NAS lib)
  decoder_rc = nas_message_decode(data, &nas_msg, data_len, nullptr,
                                  &decode_status);

  Logger::smf_app().debug("NAS message type 0x%x ",
                          nas_msg.plain.sm.header.message_type);

  Logger::smf_app().debug(
      "NAS header decode, Extended protocol discriminator 0x%x, Security header type 0x%x",
      nas_msg.header.extended_protocol_discriminator,
      nas_msg.header.security_header_type);

  Logger::smf_app().debug(
      "NAS message, Extended protocol discriminator 0x%x, PDU session identity 0x%x, Procedure transaction identity 0x%x, Message type 0x%x",
      nas_msg.plain.sm.header.extended_protocol_discriminator,
      nas_msg.plain.sm.header.pdu_session_identity,
      nas_msg.plain.sm.header.procedure_transaction_identity,
      nas_msg.plain.sm.header.message_type);

  //free memory
  free_wrapper((void**) &data);

  return decoder_rc;
}

//---------------------------------------------------------------------------------------------
int smf_n1_n2::decode_n2_sm_information(
    std::shared_ptr<Ngap_PDUSessionResourceSetupResponseTransfer_t> &ngap_IE,
    std::string &n2_sm_info) {
  Logger::smf_app().info(
      "Decode NGAP message (PDUSessionResourceSetupResponseTransfer) from N2 SM Information");
  unsigned int data_len = n2_sm_info.length();
  unsigned char *data = (unsigned char*) malloc(data_len + 1);
  memset(data, 0, data_len + 1);
  memcpy((void*) data, (void*) n2_sm_info.c_str(), data_len);

  printf("Content: ");
  for (int i = 0; i < data_len; i++)
    printf(" %02x ", data[i]);
  printf("\n");

  //PDUSessionResourceSetupResponseTransfer
  asn_dec_rval_t rc = asn_decode(
      nullptr, ATS_ALIGNED_CANONICAL_PER,
      &asn_DEF_Ngap_PDUSessionResourceSetupResponseTransfer, (void**) &ngap_IE,
      (void*) data, data_len);

  //free memory
  free_wrapper((void**) &data);

  if (rc.code != RC_OK) {
    Logger::smf_api_server().warn("asn_decode failed with code %d", rc.code);
    return RETURNerror ;
  }
  return RETURNok ;

}

//---------------------------------------------------------------------------------------------
int smf_n1_n2::decode_n2_sm_information(
    std::shared_ptr<Ngap_PDUSessionResourceModifyResponseTransfer_t> &ngap_IE,
    std::string &n2_sm_info) {
  Logger::smf_app().info(
      "Decode NGAP message (Ngap_PDUSessionResourceModifyResponseTransfer) from N2 SM Information");

  unsigned int data_len = n2_sm_info.length();
  unsigned char *data = (unsigned char*) malloc(data_len + 1);
  memset(data, 0, data_len + 1);
  memcpy((void*) data, (void*) n2_sm_info.c_str(), data_len);

  //Ngap_PDUSessionResourceModifyResponseTransfer
  asn_dec_rval_t rc = asn_decode(
      nullptr, ATS_ALIGNED_CANONICAL_PER,
      &asn_DEF_Ngap_PDUSessionResourceModifyResponseTransfer, (void**) &ngap_IE,
      (void*) data, data_len);

  //free memory
  free_wrapper((void**) &data);

  if (rc.code != RC_OK) {
    Logger::smf_api_server().warn("asn_decode failed with code %d", rc.code);

    return RETURNerror ;
  }
  return RETURNok ;

}

//---------------------------------------------------------------------------------------------
int smf_n1_n2::decode_n2_sm_information(
    std::shared_ptr<Ngap_PDUSessionResourceReleaseResponseTransfer_t> &ngap_IE,
    std::string &n2_sm_info) {
  Logger::smf_app().info(
      "Decode NGAP message (Ngap_PDUSessionResourceReleaseResponseTransfer) from N2 SM Information");

  unsigned int data_len = n2_sm_info.length();
  unsigned char *data = (unsigned char*) malloc(data_len + 1);
  memset(data, 0, data_len + 1);
  memcpy((void*) data, (void*) n2_sm_info.c_str(), data_len);

  //Ngap_PDUSessionResourceModifyResponseTransfer
  asn_dec_rval_t rc = asn_decode(
      nullptr, ATS_ALIGNED_CANONICAL_PER,
      &asn_DEF_Ngap_PDUSessionResourceReleaseResponseTransfer,
      (void**) &ngap_IE, (void*) data, data_len);

  //free memory
  free_wrapper((void**) &data);

  if (rc.code != RC_OK) {
    Logger::smf_api_server().warn("asn_decode failed with code %d", rc.code);

    return RETURNerror ;
  }
  return RETURNok ;

}

