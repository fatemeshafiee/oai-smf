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
  \author  Tien-Thinh NGUYEN
  \company Eurecom
  \date 2019
  \email:  tien-thinh.nguyen@eurecom.fr
 */

#include "smf_n1_n2.hpp"
#include "string.hpp"

extern "C" {
#include "nas_message.h"
#include "mmData.h"
#include "nas_sm_encode_to_json.h"
#include "Ngap_NGAP-PDU.h"
#include "ng_pdu_session_resource_setup_request.h"
#include "ng_pdu_session_resource_setup_response.h"
#include "ng_pdu_session_resource_release_command.h"
#include "ng_pdu_session_resource_release_response.h"
#include "ng_pdu_session_resource_modify_request.h"
#include "ng_pdu_session_resource_modify_response.h"
#include "ng_pdu_session_resource_notify.h"
#include "ng_pdu_session_resource_modify_indication.h"
#include "ng_pdu_session_resource_modify_confirm.h"
#include "ng_pdu_handover_required.h"
#include "ng_pdu_handover_command.h"
#include "ng_pdu_handover_preparation_failure.h"
#include "ng_pdu_handover_request.h"
#include "ng_pdu_handover_request_acknowledge.h"
#include "ng_pdu_handover_failure.h"
#include "ng_pdu_handover_notify.h"
#include "ng_pdu_path_switch_request.h"
#include "ng_pdu_path_switch_request_acknowledge.h"
#include "ng_pdu_path_switch_request_failure.h"
#include "ng_pdu_handover_cancel.h"
#include "ng_pdu_handover_cancel_acknowledge.h"
#include "ng_pdu_uplink_ran_status_transfer.h"
#include "ng_pdu_downlink_ran_status_transfer.h"
#include "Ngap_ProtocolIE-Field.h"
#include "Ngap_ProcedureCode.h"
#include "Ngap_Criticality.h"
#include "Ngap_PDUSessionResourceSetupRequestTransfer.h"
#include "Ngap_QosFlowSetupRequestItem.h"
#include "Ngap_GTPTunnel.h"
#include "Ngap_NonDynamic5QIDescriptor.h"
#include "Ngap_Dynamic5QIDescriptor.h"
}

#define BUF_LEN 512

using namespace smf;
extern smf_app *smf_app_inst;

//-----------------------------------------------------------------------------------------------------
void smf_n1_n2::create_n1_sm_container(pdu_session_msg& msg, uint8_t n1_msg_type, std::string& nas_msg_str, uint8_t sm_cause)
{
  //TODO: should work with BUPT to finish this function
  Logger::smf_app().info("Create N1 SM Container, n1 message type %d", n1_msg_type);

  //To be updated according to NAS implementation
  int size = NAS_MESSAGE_SECURITY_HEADER_SIZE;
  int bytes = 0;
  int length = BUF_LEN;
  unsigned char data[BUF_LEN] = {'\0'};
  memset(data,0,sizeof(data));

  nas_message_t nas_msg;
  memset(&nas_msg, 0, sizeof(nas_message_t));
  nas_msg.header.extended_protocol_discriminator = EPD_5GS_SESSION_MANAGEMENT_MESSAGES;
  nas_msg.header.security_header_type = SECURITY_HEADER_TYPE_INTEGRITY_PROTECTED_CYPHERED;
  //TODO: Should be updated
  uint8_t sequencenumber = 0xfe;
  uint32_t mac = 0xffee;
  nas_msg.header.sequence_number = sequencenumber;
  nas_msg.header.message_authentication_code= mac;
  nas_msg.security_protected.header = nas_msg.header;

  SM_msg *sm_msg;
  sm_msg = &nas_msg.security_protected.plain.sm;
  sm_msg->header.extended_protocol_discriminator = EPD_5GS_SESSION_MANAGEMENT_MESSAGES;

  sm_msg->header.pdu_session_identity = msg.get_pdu_session_id();

  //TODO: should be updated
  // construct security context
  fivegmm_security_context_t * security = (fivegmm_security_context_t *)calloc(1,sizeof(fivegmm_security_context_t));
  security->selected_algorithms.encryption = NAS_SECURITY_ALGORITHMS_NEA1;
  security->dl_count.overflow = 0xffff;
  security->dl_count.seq_num =  0x23;
  security->knas_enc[0] = 0x14;
  security->selected_algorithms.integrity = NAS_SECURITY_ALGORITHMS_NIA1;
  security->knas_int[0] = 0x41;

  switch (msg.get_msg_type()) {
  case PDU_SESSION_CREATE_SM_CONTEXT_RESPONSE: {
    Logger::smf_app().info("PDU_SESSION_CREATE_SM_CONTEXT_RESPONSE");
    pdu_session_create_sm_context_response& sm_context_res = static_cast<pdu_session_create_sm_context_response&>(msg);

    //get default QoS value
    qos_flow_context_created qos_flow = {};
    qos_flow = sm_context_res.get_qos_flow_context();

    //N1 message
    switch (n1_msg_type){

    case PDU_SESSION_ESTABLISHMENT_ACCEPT: {
      //TODO: to be completed
      //get the default QoS profile and assign to the NAS message
      Logger::smf_app().info("PDU_SESSION_CREATE_SM_CONTEXT_RESPONSE, NAS: PDU_SESSION_ESTABLISHMENT_ACCEPT");

      Logger::smf_app().info("PDU_SESSION_ESTABLISHMENT_ACCEPT, encode starting...");
      sm_msg->header.message_type = PDU_SESSION_ESTABLISHMENT_ACCEPT;

      //Fill the content of PDU Session Establishment Request message with hardcoded values
      //PTI
      sm_msg->header.procedure_transaction_identity = sm_context_res.get_pti().procedure_transaction_id;
      //PDU Session Type
      sm_msg->specific_msg.pdu_session_establishment_accept._pdusessiontype.pdu_session_type_value = sm_context_res.get_pdu_session_type();
      //SSC Mode
      //TODO: should get from sm_context_res
      sm_msg->specific_msg.pdu_session_establishment_accept.sscmode.ssc_mode_value = SSC_MODE_1;

      //authorized QoS rules of the PDU session: QOSRules
      //Section 6.2.5@3GPP TS 24.501
      //(Section 6.4.1.3@3GPP TS 24.501 V16.1.0) Make sure that the number of the packet filters used in the authorized QoS rules of the PDU Session does not
      // exceed the maximum number of packet filters supported by the UE for the PDU session
      //TODO: remove hardcoded varlues
      QOSRulesIE qosrulesie[1];
      qosrulesie[0].qosruleidentifer=0x01;
      qosrulesie[0].ruleoperationcode = CREATE_NEW_QOS_RULE;
      qosrulesie[0].dqrbit = THE_QOS_RULE_IS_DEFAULT_QOS_RULE;
      qosrulesie[0].numberofpacketfilters = 1;

      Create_ModifyAndAdd_ModifyAndReplace create_modifyandadd_modifyandreplace[1];
      create_modifyandadd_modifyandreplace[0].packetfilterdirection = 0b01;
      create_modifyandadd_modifyandreplace[0].packetfilteridentifier = 1;
      create_modifyandadd_modifyandreplace[0].packetfiltercontents.component_type = QOS_RULE_MATCHALL_TYPE;
      /*      create_modifyandadd_modifyandreplace[1].packetfilterdirection = 0b10;
      create_modifyandadd_modifyandreplace[1].packetfilteridentifier = 2;
      create_modifyandadd_modifyandreplace[1].packetfiltercontents.component_type = QOS_RULE_MATCHALL_TYPE;
      create_modifyandadd_modifyandreplace[2].packetfilterdirection = 0b11;
      create_modifyandadd_modifyandreplace[2].packetfilteridentifier = 3;
      create_modifyandadd_modifyandreplace[2].packetfiltercontents.component_type = QOS_RULE_MATCHALL_TYPE;
       */
      //1st rule
      qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace = create_modifyandadd_modifyandreplace;
      qosrulesie[0].qosruleprecedence = 1;
      qosrulesie[0].segregation = SEGREGATION_NOT_REQUESTED;
      qosrulesie[0].qosflowidentifer = qos_flow.qfi.qfi;

      /*
      //2nd rule
      qosrulesie[1].qosruleidentifer=0x02;
      qosrulesie[1].ruleoperationcode = MODIFY_EXISTING_QOS_RULE_AND_DELETE_PACKET_FILTERS;
      qosrulesie[1].dqrbit = THE_QOS_RULE_IS_NOT_THE_DEFAULT_QOS_RULE;
      qosrulesie[1].numberofpacketfilters = 3;

      ModifyAndDelete modifyanddelete[3];
      modifyanddelete[0].packetfilteridentifier = 1;
      modifyanddelete[1].packetfilteridentifier = 2;
      modifyanddelete[2].packetfilteridentifier = 3;
      qosrulesie[1].packetfilterlist.modifyanddelete = modifyanddelete;

      qosrulesie[1].qosruleprecedence = 1;
      qosrulesie[1].segregation = SEGREGATION_REQUESTED;
      qosrulesie[1].qosflowidentifer = 0x08;
       */
      sm_msg->specific_msg.pdu_session_establishment_accept.qosrules.lengthofqosrulesie = 1;
      sm_msg->specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie = (QOSRulesIE *)calloc (1, sizeof (QOSRulesIE));
      sm_msg->specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie = qosrulesie;

      //SessionAMBR
      //TODO: get from subscription DB
      supi_t supi =  sm_context_res.get_supi();
      supi64_t supi64 = smf_supi_to_u64(supi);
      std::shared_ptr<smf_context> sc;
      if (smf_app_inst->is_supi_2_smf_context(supi64)) {
        Logger::smf_app().debug("Get SMF context with SUPI " SUPI_64_FMT "", supi64);
        sc = smf_app_inst->supi_2_smf_context(supi64);
        std::shared_ptr<session_management_subscription> ss;
        snssai_t snssai  =  sm_context_res.get_snssai();
        std::shared_ptr<dnn_configuration_t> sdc;
        sc.get()->find_dnn_subscription(snssai, ss);
        if (nullptr != ss.get()){
          ss.get()->find_dnn_configuration(sm_context_res.get_dnn(), sdc);
          if (nullptr != sdc.get()){
            //Downlink
            size_t leng_of_session_ambr_dl = (sdc.get()->session_ambr).downlink.length();
            std::string session_ambr_dl_unit = (sdc.get()->session_ambr).downlink.substr(leng_of_session_ambr_dl-4); //4 last characters stand for mbps, kbps, ..
            if (session_ambr_dl_unit.compare("Kbps"))
              sm_msg->specific_msg.pdu_session_establishment_accept.sessionambr.uint_for_session_ambr_for_downlink = AMBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_1KBPS;
            if (session_ambr_dl_unit.compare("Mbps"))
              sm_msg->specific_msg.pdu_session_establishment_accept.sessionambr.uint_for_session_ambr_for_downlink = AMBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_1MBPS;
            if (session_ambr_dl_unit.compare("Gbps"))
              sm_msg->specific_msg.pdu_session_establishment_accept.sessionambr.uint_for_session_ambr_for_downlink = AMBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_1GBPS;
            if (session_ambr_dl_unit.compare("Tbps"))
              sm_msg->specific_msg.pdu_session_establishment_accept.sessionambr.uint_for_session_ambr_for_downlink = AMBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_1TBPS;
            if (session_ambr_dl_unit.compare("Pbps"))
              sm_msg->specific_msg.pdu_session_establishment_accept.sessionambr.uint_for_session_ambr_for_downlink = AMBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_1PBPS;
            sm_msg->specific_msg.pdu_session_establishment_accept.sessionambr.session_ambr_for_downlink  = std::stoi((sdc.get()->session_ambr).downlink.substr(0, leng_of_session_ambr_dl-4));
            //Uplink
            size_t leng_of_session_ambr_ul = (sdc.get()->session_ambr).uplink.length();
            std::string session_ambr_ul_unit = (sdc.get()->session_ambr).uplink.substr(leng_of_session_ambr_ul-4); //4 last characters stand for mbps, kbps, ..
            if (session_ambr_ul_unit.compare("Kbps"))
              sm_msg->specific_msg.pdu_session_establishment_accept.sessionambr.uint_for_session_ambr_for_uplink = AMBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_1KBPS;
            if (session_ambr_ul_unit.compare("Mbps"))
              sm_msg->specific_msg.pdu_session_establishment_accept.sessionambr.uint_for_session_ambr_for_uplink = AMBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_1MBPS;
            if (session_ambr_ul_unit.compare("Gbps"))
              sm_msg->specific_msg.pdu_session_establishment_accept.sessionambr.uint_for_session_ambr_for_uplink = AMBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_1GBPS;
            if (session_ambr_ul_unit.compare("Tbps"))
              sm_msg->specific_msg.pdu_session_establishment_accept.sessionambr.uint_for_session_ambr_for_uplink = AMBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_1TBPS;
            if (session_ambr_ul_unit.compare("Pbps"))
              sm_msg->specific_msg.pdu_session_establishment_accept.sessionambr.uint_for_session_ambr_for_uplink = AMBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_1PBPS;
            sm_msg->specific_msg.pdu_session_establishment_accept.sessionambr.session_ambr_for_uplink  = std::stoi((sdc.get()->session_ambr).uplink.substr(0, leng_of_session_ambr_ul-4));
          }
        }


      } else {
        Logger::smf_app().warn(" SMF context with SUPI " SUPI_64_FMT " does not exist!", supi64);
        //TODO:
      }

      /*

			sm_msg->specific_msg.pdu_session_establishment_accept.sessionambr.uint_for_session_ambr_for_downlink = AMBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_1KBPS;
			sm_msg->specific_msg.pdu_session_establishment_accept.sessionambr.session_ambr_for_downlink = (AMBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_4KBPS << 8) + (AMBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_16KBPS);
			sm_msg->specific_msg.pdu_session_establishment_accept.sessionambr.uint_for_session_ambr_for_uplink = AMBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_64KBPS;
			sm_msg->specific_msg.pdu_session_establishment_accept.sessionambr.session_ambr_for_uplink = (AMBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_256KBPS << 8) + (AMBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_1MBPS);
       */

      sm_msg->specific_msg.pdu_session_establishment_accept.presence = 0xffff;
      sm_msg->specific_msg.pdu_session_establishment_accept._5gsmcause = sm_cause;
      sm_msg->specific_msg.pdu_session_establishment_accept.pduaddress.pdu_session_type_value = sm_context_res.get_pdu_session_type();

      //Presence
      //_5GSMCause _5gsmcause;
      sm_msg->specific_msg.pdu_session_establishment_accept._5gsmcause = sm_context_res.get_cause();

      //PDUAddress
      paa_t paa = sm_context_res.get_paa();
      unsigned char bitStream_pdu_address_information[4];
      bitStream_pdu_address_information[0] = (uint8_t)((paa.ipv4_address.s_addr)  & 0x000000ff);
      bitStream_pdu_address_information[1] = (uint8_t)(((paa.ipv4_address.s_addr) & 0x0000ff00) >> 8 );
      bitStream_pdu_address_information[2] = (uint8_t)(((paa.ipv4_address.s_addr) & 0x00ff0000) >> 16);
      bitStream_pdu_address_information[3] = (uint8_t)(((paa.ipv4_address.s_addr) & 0xff000000) >> 24);
      bstring pdu_address_information= bfromcstralloc(4, "\0");
      pdu_address_information->slen = 4;
      memcpy(pdu_address_information->data, bitStream_pdu_address_information, sizeof(bitStream_pdu_address_information));
      sm_msg->specific_msg.pdu_session_establishment_accept.pduaddress.pdu_address_information = pdu_address_information;

      //GPRSTimer
      sm_msg->specific_msg.pdu_session_establishment_accept.gprstimer.unit = GPRSTIMER_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_2_SECONDS;
      sm_msg->specific_msg.pdu_session_establishment_accept.gprstimer.timeValue = 0;

      //SNSSAI
      sm_msg->specific_msg.pdu_session_establishment_accept.snssai.len = SST_AND_SD_LENGHT;
      sm_msg->specific_msg.pdu_session_establishment_accept.snssai.sst = sm_context_res.get_snssai().sST;
      sm_msg->specific_msg.pdu_session_establishment_accept.snssai.sd = 0x123456; //TODO: sm_context_res.get_snssai().sD;

      //AlwaysonPDUSessionIndication
      sm_msg->specific_msg.pdu_session_establishment_accept.alwaysonpdusessionindication.apsi_indication = ALWAYSON_PDU_SESSION_REQUIRED;

      //MappedEPSBearerContexts mappedepsbearercontexts;
      //EAPMessage
      unsigned char bitStream_eapmessage[2] = {0x01,0x02};
      bstring eapmessage_tmp = bfromcstralloc(2, "\0");
      eapmessage_tmp->slen = 2;
      memcpy(eapmessage_tmp->data,bitStream_eapmessage,sizeof(bitStream_eapmessage));
      sm_msg->specific_msg.pdu_session_establishment_accept.eapmessage = eapmessage_tmp;

      //authorized QoS flow descriptions IE: QoSFlowDescritions
      QOSFlowDescriptionsContents qosflowdescriptionscontents[3];
      qosflowdescriptionscontents[0].qfi = 1;
      qosflowdescriptionscontents[0].operationcode = CREATE_NEW_QOS_FLOW_DESCRIPTION;
      qosflowdescriptionscontents[0].e = PARAMETERS_LIST_IS_INCLUDED;
      qosflowdescriptionscontents[0].numberofparameters = 3;
      ParametersList parameterslist00[3];
      parameterslist00[0].parameteridentifier = PARAMETER_IDENTIFIER_5QI;
      parameterslist00[0].parametercontents._5qi = 0b01000001;
      parameterslist00[1].parameteridentifier = PARAMETER_IDENTIFIER_GFBR_UPLINK;
      parameterslist00[1].parametercontents.gfbrormfbr_uplinkordownlink.uint = GFBRORMFBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_1KBPS;
      parameterslist00[1].parametercontents.gfbrormfbr_uplinkordownlink.value = 0x1000;
      parameterslist00[2].parameteridentifier = PARAMETER_IDENTIFIER_GFBR_DOWNLINK;
      parameterslist00[2].parametercontents.gfbrormfbr_uplinkordownlink.uint = GFBRORMFBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_4KBPS;
      parameterslist00[2].parametercontents.gfbrormfbr_uplinkordownlink.value = 0x2000;
      qosflowdescriptionscontents[0].parameterslist = parameterslist00;

      qosflowdescriptionscontents[1].qfi = 2;
      qosflowdescriptionscontents[1].operationcode = DELETE_EXISTING_QOS_FLOW_DESCRIPTION;
      qosflowdescriptionscontents[1].e = PARAMETERS_LIST_IS_NOT_INCLUDED;
      qosflowdescriptionscontents[1].numberofparameters = 0;
      qosflowdescriptionscontents[1].parameterslist = nullptr;

      qosflowdescriptionscontents[2].qfi = 1;
      qosflowdescriptionscontents[2].operationcode = MODIFY_EXISTING_QOS_FLOW_DESCRIPTION;
      qosflowdescriptionscontents[2].e = REPLACEMENT_OF_ALL_PREVIOUSLY_PROVIDED_PARAMETERS;
      qosflowdescriptionscontents[2].numberofparameters = 4;
      ParametersList parameterslist02[4];
      parameterslist02[0].parameteridentifier = PARAMETER_IDENTIFIER_MFBR_UPLINK;
      parameterslist02[0].parametercontents.gfbrormfbr_uplinkordownlink.uint = GFBRORMFBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_16KBPS;
      parameterslist02[0].parametercontents.gfbrormfbr_uplinkordownlink.value = 0x3000;
      parameterslist02[1].parameteridentifier = PARAMETER_IDENTIFIER_MFBR_DOWNLINK;
      parameterslist02[1].parametercontents.gfbrormfbr_uplinkordownlink.uint = GFBRORMFBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_64KBPS;
      parameterslist02[1].parametercontents.gfbrormfbr_uplinkordownlink.value = 0x4000;
      parameterslist02[2].parameteridentifier = PARAMETER_IDENTIFIER_AVERAGING_WINDOW;
      parameterslist02[2].parametercontents.averagingwindow.uplinkinmilliseconds = GFBRORMFBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_256KBPS;
      parameterslist02[2].parametercontents.averagingwindow.downlinkinmilliseconds = GFBRORMFBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_1MBPS;
      parameterslist02[3].parameteridentifier = PARAMETER_IDENTIFIER_EPS_BEARER_IDENTITY;
      parameterslist02[3].parametercontents.epsbeareridentity = QOS_FLOW_EPS_BEARER_IDENTITY_VALUE15;
      qosflowdescriptionscontents[2].parameterslist = parameterslist02;

      sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionsnumber = 3;
      sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents = qosflowdescriptionscontents;

      //ExtendedProtocolConfigurationOptions
      unsigned char bitStream_extendedprotocolconfigurationoptions[4];
      bitStream_extendedprotocolconfigurationoptions[0] = 0x12;
      bitStream_extendedprotocolconfigurationoptions[1] = 0x13;
      bitStream_extendedprotocolconfigurationoptions[2] = 0x14;
      bitStream_extendedprotocolconfigurationoptions[3] = 0x15;
      bstring extendedprotocolconfigurationoptions_tmp = bfromcstralloc(4, "\0");
      extendedprotocolconfigurationoptions_tmp->slen = 4;
      memcpy(extendedprotocolconfigurationoptions_tmp->data,bitStream_extendedprotocolconfigurationoptions,sizeof(bitStream_extendedprotocolconfigurationoptions));
      sm_msg->specific_msg.pdu_session_establishment_accept.extendedprotocolconfigurationoptions = extendedprotocolconfigurationoptions_tmp;

      //DNN
      bstring dnn = bfromcstralloc(sm_context_res.get_dnn().length(), "\0");
      dnn->slen = sm_context_res.get_dnn().length();
      memcpy ((void *)dnn->data, (void *)sm_context_res.get_dnn().c_str(), sm_context_res.get_dnn().length());
      sm_msg->specific_msg.pdu_session_establishment_accept.dnn = dnn;

      //assign SM msg to NAS content
      nas_msg.plain.sm = *sm_msg;

      //Print the logs
      Logger::smf_app().debug("NAS header, encode extended_protocol_discriminator: 0x%x, security_header_type: 0x%x,sequence_number: 0x%x, message_authentication_code: 0x%x",
          nas_msg.header.extended_protocol_discriminator,
          nas_msg.header.security_header_type,
          nas_msg.header.sequence_number,
          nas_msg.header.message_authentication_code);

      Logger::smf_app().debug("SM header, extended_protocol_discriminator: 0x%x, pdu_session_identity: 0x%x, procedure_transaction_identity: 0x%x, message type: 0x%x",
          sm_msg->header.extended_protocol_discriminator,
          sm_msg->header.pdu_session_identity,
          sm_msg->header.procedure_transaction_identity,
          sm_msg->header.message_type);

      Logger::smf_app().debug("PDUSessionType bits_3: %#0x",sm_msg->specific_msg.pdu_session_establishment_accept._pdusessiontype.pdu_session_type_value);
      Logger::smf_app().debug("SSC Mode bits_3: %#0x",sm_msg->specific_msg.pdu_session_establishment_accept.sscmode.ssc_mode_value);

      sm_msg->specific_msg.pdu_session_establishment_accept.qosrules.lengthofqosrulesie = 1;
      sm_msg->specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie = qosrulesie;


      Logger::smf_app().debug("QoSRules: %x %x %x %x %x %x %x %x %x %x %x ",
          sm_msg->specific_msg.pdu_session_establishment_accept.qosrules.lengthofqosrulesie,
          sm_msg->specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[0].qosruleidentifer,
          sm_msg->specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[0].ruleoperationcode,
          sm_msg->specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[0].dqrbit,
          sm_msg->specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[0].numberofpacketfilters,
          sm_msg->specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[0].packetfilterdirection,
          sm_msg->specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[0].packetfilteridentifier,
          sm_msg->specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[0].packetfiltercontents.component_type,
          sm_msg->specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[0].qosruleprecedence,
          sm_msg->specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[0].segregation,
          sm_msg->specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[0].qosflowidentifer);

      Logger::smf_app().debug("SessionAMBR: %x %x %x %x",
          sm_msg->specific_msg.pdu_session_establishment_accept.sessionambr.uint_for_session_ambr_for_downlink,
          sm_msg->specific_msg.pdu_session_establishment_accept.sessionambr.session_ambr_for_downlink,
          sm_msg->specific_msg.pdu_session_establishment_accept.sessionambr.uint_for_session_ambr_for_uplink,
          sm_msg->specific_msg.pdu_session_establishment_accept.sessionambr.session_ambr_for_uplink);

      Logger::smf_app().debug("5GSMCause: %#0x",sm_msg->specific_msg.pdu_session_establishment_accept._5gsmcause);

      Logger::smf_app().debug("PDUAddress: %x %x %x %x %x",
          sm_msg->specific_msg.pdu_session_establishment_accept.pduaddress.pdu_session_type_value,
          (unsigned char)(sm_msg->specific_msg.pdu_session_establishment_accept.pduaddress.pdu_address_information->data[0]),
          (unsigned char)(sm_msg->specific_msg.pdu_session_establishment_accept.pduaddress.pdu_address_information->data[1]),
          (unsigned char)(sm_msg->specific_msg.pdu_session_establishment_accept.pduaddress.pdu_address_information->data[2]),
          (unsigned char)(sm_msg->specific_msg.pdu_session_establishment_accept.pduaddress.pdu_address_information->data[3]));

      Logger::smf_app().debug("GPRSTimer, unit: %#0x, timeValue: %#0x",
          sm_msg->specific_msg.pdu_session_establishment_accept.gprstimer.unit,
          sm_msg->specific_msg.pdu_session_establishment_accept.gprstimer.timeValue);

      Logger::smf_app().debug("SNSSAI, len: %#0x, sst: %#0x, sd: %#0x",
          sm_msg->specific_msg.pdu_session_establishment_accept.snssai.len,
          sm_msg->specific_msg.pdu_session_establishment_accept.snssai.sst,
          sm_msg->specific_msg.pdu_session_establishment_accept.snssai.sd);

      Logger::smf_app().debug("AlwaysOnPDUSessionIndication: %#0x",sm_msg->specific_msg.pdu_session_establishment_accept.alwaysonpdusessionindication.apsi_indication);

      Logger::smf_app().debug("EAPMessage buffer:%x %x",
          (unsigned char)(sm_msg->specific_msg.pdu_session_establishment_accept.eapmessage->data[0]),
          (unsigned char)(sm_msg->specific_msg.pdu_session_establishment_accept.eapmessage->data[1]));

      Logger::smf_app().debug("QosFlowDescriptions: %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x\n",
          sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionsnumber,
          sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[0].qfi,
          sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[0].operationcode,
          sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[0].e,
          sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[0].numberofparameters,
          sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[0].parameteridentifier,
          sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[0].parametercontents._5qi,
          sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[1].parameteridentifier,
          sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[1].parametercontents.gfbrormfbr_uplinkordownlink.uint,
          sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[1].parametercontents.gfbrormfbr_uplinkordownlink.value,
          sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[2].parameteridentifier,
          sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[2].parametercontents.gfbrormfbr_uplinkordownlink.uint,
          sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[2].parametercontents.gfbrormfbr_uplinkordownlink.value,
          sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[1].qfi,
          sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[1].operationcode,
          sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[1].e,
          sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[1].numberofparameters,
          sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].qfi,
          sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].operationcode,
          sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].e,
          sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].numberofparameters,
          sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[0].parameteridentifier,
          sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[0].parametercontents.gfbrormfbr_uplinkordownlink.uint,
          sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[0].parametercontents.gfbrormfbr_uplinkordownlink.value,
          sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[1].parameteridentifier,
          sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[1].parametercontents.gfbrormfbr_uplinkordownlink.uint,
          sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[1].parametercontents.gfbrormfbr_uplinkordownlink.value,
          sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[2].parameteridentifier,
          sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[2].parametercontents.averagingwindow.uplinkinmilliseconds,
          sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[2].parametercontents.averagingwindow.downlinkinmilliseconds,
          sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[3].parameteridentifier,
          sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[3].parametercontents.epsbeareridentity);

      Logger::smf_app().debug("Extend_options buffer:%x %x %x %x\n",
          (unsigned char)(sm_msg->specific_msg.pdu_session_establishment_accept.extendedprotocolconfigurationoptions->data[0]),
          (unsigned char)(sm_msg->specific_msg.pdu_session_establishment_accept.extendedprotocolconfigurationoptions->data[1]),
          (unsigned char)(sm_msg->specific_msg.pdu_session_establishment_accept.extendedprotocolconfigurationoptions->data[2]),
          (unsigned char)(sm_msg->specific_msg.pdu_session_establishment_accept.extendedprotocolconfigurationoptions->data[3]));

      Logger::smf_app().debug("DNN buffer:%x %x %x\n",
          (unsigned char)(sm_msg->specific_msg.pdu_session_establishment_accept.dnn->data[0]),
          (unsigned char)(sm_msg->specific_msg.pdu_session_establishment_accept.dnn->data[1]),
          (unsigned char)(sm_msg->specific_msg.pdu_session_establishment_accept.dnn->data[2]));

      //bytes = nas_message_encode (data, &nas_msg, 60/*don't know the size*/, security);
      bytes = nas_message_encode (data, &nas_msg, sizeof(data)/*don't know the size*/, security);

      Logger::smf_app().debug("Buffer Data: ");
      for(int i = 0; i < bytes; i++)
        printf("%02x ", data[i]);
      std::string n1Message ((char*) data,  bytes);
      nas_msg_str = n1Message;
      Logger::smf_app().debug("n1MessageContent (%d bytes), %s\n ", bytes, nas_msg_str.c_str());
      Logger::smf_app().info("PDU_SESSION_ESTABLISHMENT_ACCEPT, encode finished");

      //For testing purpose!!!
      Logger::smf_app().info("PDU_SESSION_ESTABLISHMENT_ACCEPT, start decoding ...");

      bstring  info = bfromcstralloc(length, "\0");
      info->data = data;
      info->slen = bytes;
      bstring plain_msg = bstrcpy(info);
      nas_message_security_header_t header = {};
      nas_message_decode_status_t   decode_status = {};
      nas_message_t	decoded_nas_msg;
      memset (&decoded_nas_msg,		 0, sizeof (nas_message_t));

      int decoder_rc = RETURNok;
      decoder_rc = nas_message_decode (data, &decoded_nas_msg, sizeof(data), security, &decode_status);
      Logger::smf_app().debug("[Decoded NAS message] header, extended_protocol_discriminator:0x%x, security_header_type:0x%x, sequence_number:0x%x, message_authentication_code:0x%x",
          decoded_nas_msg.header.extended_protocol_discriminator,
          decoded_nas_msg.header.security_header_type,
          decoded_nas_msg.header.sequence_number,
          decoded_nas_msg.header.message_authentication_code);

      SM_msg * decoded_sm_msg = &decoded_nas_msg.plain.sm;
      //SM_msg * decoded_sm_msg = &decoded_nas_msg.security_protected.plain.sm;

      Logger::smf_app().debug("[Decoded NAS message] SM header, extended_protocol_discriminator:0x%x, pdu_session_identity: 0x%x, procedure_transaction_identity: 0x%x, message type:0x%x\n", decoded_sm_msg->header.extended_protocol_discriminator,
          decoded_sm_msg->header.pdu_session_identity,
          decoded_sm_msg->header.procedure_transaction_identity,
          decoded_sm_msg->header.message_type);

      Logger::smf_app().debug("[Decoded NAS message] size of security_protected.plain.sm = %d",sizeof(decoded_nas_msg.security_protected.plain.sm));

      Logger::smf_app().debug("[Decoded NAS message] message type: 0x%x",decoded_sm_msg->specific_msg.pdu_session_establishment_accept.messagetype);
      Logger::smf_app().debug("[Decoded NAS message] extended protocol discriminator: 0x%x",decoded_sm_msg->specific_msg.pdu_session_establishment_accept.extendedprotocoldiscriminator);
      //   Logger::smf_app().debug("[Decoded NAS message] pdu identity buffer: 0x%x",*(unsigned char *)((decoded_sm_msg->specific_msg.pdu_session_establishment_accept.pdusessionidentity)->data));
      //   Logger::smf_app().debug("[Decoded NAS message] PTI buffer:0x%x",*(unsigned char *)((decoded_sm_msg->specific_msg.pdu_session_establishment_accept.proceduretransactionidentity)->data));

      Logger::smf_app().debug("[Decoded NAS message] pdusessiontype: 0x%x",decoded_sm_msg->specific_msg.pdu_session_establishment_accept._pdusessiontype.pdu_session_type_value);
      Logger::smf_app().debug("[Decoded NAS message] sscmode :0x%x",decoded_sm_msg->specific_msg.pdu_session_establishment_accept.sscmode.ssc_mode_value);
      Logger::smf_app().debug("[Decoded NAS message] Always-on bit --- %B",decoded_sm_msg->specific_msg.pdu_session_establishment_accept.alwaysonpdusessionindication.apsi_indication);

      Logger::smf_app().debug("[Decoded NAS message] PDUSessionType: %#0x",decoded_sm_msg->specific_msg.pdu_session_establishment_accept._pdusessiontype.pdu_session_type_value);
      Logger::smf_app().debug("[Decoded NAS message] SSC Mode bits_3: %#0x",decoded_sm_msg->specific_msg.pdu_session_establishment_accept.sscmode.ssc_mode_value);
      Logger::smf_app().debug("[Decoded NAS message] QoSRules: %x %x %x %x %x %x %x %x %x %x %x ",
          decoded_sm_msg->specific_msg.pdu_session_establishment_accept.qosrules.lengthofqosrulesie,
          decoded_sm_msg->specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[0].qosruleidentifer,
          decoded_sm_msg->specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[0].ruleoperationcode,
          decoded_sm_msg->specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[0].dqrbit,
          decoded_sm_msg->specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[0].numberofpacketfilters,
          decoded_sm_msg->specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[0].packetfilterdirection,
          decoded_sm_msg->specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[0].packetfilteridentifier,
          decoded_sm_msg->specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[0].packetfiltercontents.component_type,
          decoded_sm_msg->specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[0].qosruleprecedence,
          decoded_sm_msg->specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[0].segregation,
          decoded_sm_msg->specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[0].qosflowidentifer);

      /*     Logger::smf_app().debug("[Decoded NAS message] SessionAMBR: %x %x %x %x",
          decoded_sm_msg->specific_msg.pdu_session_establishment_accept.sessionambr.uint_for_session_ambr_for_downlink,
          decoded_sm_msg->specific_msg.pdu_session_establishment_accept.sessionambr.session_ambr_for_downlink,
          decoded_sm_msg->specific_msg.pdu_session_establishment_accept.sessionambr.uint_for_session_ambr_for_uplink,
          decoded_sm_msg->specific_msg.pdu_session_establishment_accept.sessionambr.session_ambr_for_uplink);
       */
      Logger::smf_app().debug("[Decoded NAS message] 5GSMCause: %#0x",decoded_sm_msg->specific_msg.pdu_session_establishment_accept._5gsmcause);

      Logger::smf_app().debug("[Decoded NAS message] PDUAddress: %x %x %x %x %x",
          decoded_sm_msg->specific_msg.pdu_session_establishment_accept.pduaddress.pdu_session_type_value,
          (unsigned char)(decoded_sm_msg->specific_msg.pdu_session_establishment_accept.pduaddress.pdu_address_information->data[0]),
          (unsigned char)(decoded_sm_msg->specific_msg.pdu_session_establishment_accept.pduaddress.pdu_address_information->data[1]),
          (unsigned char)(decoded_sm_msg->specific_msg.pdu_session_establishment_accept.pduaddress.pdu_address_information->data[2]),
          (unsigned char)(decoded_sm_msg->specific_msg.pdu_session_establishment_accept.pduaddress.pdu_address_information->data[3]));

      Logger::smf_app().debug("[Decoded NAS message] GPRSTimer, unit: %#0x, timeValue: %#0x",
          decoded_sm_msg->specific_msg.pdu_session_establishment_accept.gprstimer.unit,
          decoded_sm_msg->specific_msg.pdu_session_establishment_accept.gprstimer.timeValue);

      Logger::smf_app().debug("[Decoded NAS message] SNSSAI, len: %#0x, sst: %#0x, sd: %#0x",
          decoded_sm_msg->specific_msg.pdu_session_establishment_accept.snssai.len,
          decoded_sm_msg->specific_msg.pdu_session_establishment_accept.snssai.sst,
          decoded_sm_msg->specific_msg.pdu_session_establishment_accept.snssai.sd);

      Logger::smf_app().debug("[Decoded NAS message] AlwaysOnPDUSessionIndication: %#0x",decoded_sm_msg->specific_msg.pdu_session_establishment_accept.alwaysonpdusessionindication.apsi_indication);

      Logger::smf_app().debug("[Decoded NAS message] EAPMessage buffer:%x %x",
          (unsigned char)(decoded_sm_msg->specific_msg.pdu_session_establishment_accept.eapmessage->data[0]),
          (unsigned char)(decoded_sm_msg->specific_msg.pdu_session_establishment_accept.eapmessage->data[1]));

      Logger::smf_app().debug("[Decoded NAS message] QosFlowDescriptions: %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x\n",
          decoded_sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionsnumber,
          decoded_sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[0].qfi,
          decoded_sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[0].operationcode,
          decoded_sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[0].e,
          decoded_sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[0].numberofparameters,
          decoded_sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[0].parameteridentifier,
          decoded_sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[0].parametercontents._5qi,
          decoded_sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[1].parameteridentifier,
          decoded_sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[1].parametercontents.gfbrormfbr_uplinkordownlink.uint,
          decoded_sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[1].parametercontents.gfbrormfbr_uplinkordownlink.value,
          decoded_sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[2].parameteridentifier,
          decoded_sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[2].parametercontents.gfbrormfbr_uplinkordownlink.uint,
          decoded_sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[2].parametercontents.gfbrormfbr_uplinkordownlink.value,
          decoded_sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[1].qfi,
          decoded_sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[1].operationcode,
          decoded_sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[1].e,
          decoded_sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[1].numberofparameters,
          decoded_sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].qfi,
          decoded_sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].operationcode,
          decoded_sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].e,
          decoded_sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].numberofparameters,
          decoded_sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[0].parameteridentifier,
          decoded_sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[0].parametercontents.gfbrormfbr_uplinkordownlink.uint,
          decoded_sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[0].parametercontents.gfbrormfbr_uplinkordownlink.value,
          decoded_sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[1].parameteridentifier,
          decoded_sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[1].parametercontents.gfbrormfbr_uplinkordownlink.uint,
          decoded_sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[1].parametercontents.gfbrormfbr_uplinkordownlink.value,
          decoded_sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[2].parameteridentifier,
          decoded_sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[2].parametercontents.averagingwindow.uplinkinmilliseconds,
          decoded_sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[2].parametercontents.averagingwindow.downlinkinmilliseconds,
          decoded_sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[3].parameteridentifier,
          decoded_sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[3].parametercontents.epsbeareridentity);

      Logger::smf_app().debug("[Decoded NAS message] Extend_options buffer:%x %x %x %x\n",
          (unsigned char)(decoded_sm_msg->specific_msg.pdu_session_establishment_accept.extendedprotocolconfigurationoptions->data[0]),
          (unsigned char)(decoded_sm_msg->specific_msg.pdu_session_establishment_accept.extendedprotocolconfigurationoptions->data[1]),
          (unsigned char)(decoded_sm_msg->specific_msg.pdu_session_establishment_accept.extendedprotocolconfigurationoptions->data[2]),
          (unsigned char)(decoded_sm_msg->specific_msg.pdu_session_establishment_accept.extendedprotocolconfigurationoptions->data[3]));

      Logger::smf_app().debug("[Decoded NAS message] DNN buffer:%x %x %x\n",
          (unsigned char)(decoded_sm_msg->specific_msg.pdu_session_establishment_accept.dnn->data[0]),
          (unsigned char)(decoded_sm_msg->specific_msg.pdu_session_establishment_accept.dnn->data[1]),
          (unsigned char)(decoded_sm_msg->specific_msg.pdu_session_establishment_accept.dnn->data[2]));

      Logger::smf_app().debug("PDU_SESSION_ESTABLISHMENT_ACCEPT, decode finished");


    }
    break;

    case PDU_SESSION_ESTABLISHMENT_REJECT: {

      //TODO: to be completed
      Logger::smf_app().info("PDU_SESSION_CREATE_SM_CONTEXT_RESPONSE, NAS: PDU_SESSION_ESTABLISHMENT_REJECT");

      sm_msg->header.message_type = PDU_SESSION_ESTABLISHMENT_REJECT;
      sm_msg->specific_msg.pdu_session_establishment_reject._5gsmcause = 0b00001000;
      sm_msg->specific_msg.pdu_session_establishment_reject.presence = 0x1f;
      sm_msg->specific_msg.pdu_session_establishment_reject.gprstimer3.unit = GPRSTIMER3_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_1_HOUR;
      sm_msg->specific_msg.pdu_session_establishment_reject.gprstimer3.timeValue = 0;
      sm_msg->specific_msg.pdu_session_establishment_reject.allowedsscmode.is_ssc1_allowed = SSC_MODE1_ALLOWED;
      sm_msg->specific_msg.pdu_session_establishment_reject.allowedsscmode.is_ssc2_allowed = SSC_MODE2_NOT_ALLOWED;
      sm_msg->specific_msg.pdu_session_establishment_reject.allowedsscmode.is_ssc3_allowed = SSC_MODE3_ALLOWED;

      unsigned char bitStream_eapmessage[2] = {0x01,0x02};
      bstring eapmessage_tmp = bfromcstralloc(2, "\0");
      eapmessage_tmp->slen = 2;
      memcpy(eapmessage_tmp->data,bitStream_eapmessage,sizeof(bitStream_eapmessage));
      sm_msg->specific_msg.pdu_session_establishment_reject.eapmessage = eapmessage_tmp;

      unsigned char bitStream_extendedprotocolconfigurationoptions[4];
      bitStream_extendedprotocolconfigurationoptions[0] = 0x12;
      bitStream_extendedprotocolconfigurationoptions[1] = 0x13;
      bitStream_extendedprotocolconfigurationoptions[2] = 0x14;
      bitStream_extendedprotocolconfigurationoptions[3] = 0x15;
      bstring extendedprotocolconfigurationoptions_tmp = bfromcstralloc(4, "\0");
      extendedprotocolconfigurationoptions_tmp->slen = 4;
      memcpy(extendedprotocolconfigurationoptions_tmp->data,bitStream_extendedprotocolconfigurationoptions,sizeof(bitStream_extendedprotocolconfigurationoptions));
      sm_msg->specific_msg.pdu_session_establishment_reject.extendedprotocolconfigurationoptions = extendedprotocolconfigurationoptions_tmp;
      sm_msg->specific_msg.pdu_session_establishment_reject._5gsmcongestionreattemptindicator.abo = THE_BACKOFF_TIMER_IS_APPLIED_IN_ALL_PLMNS;
      size += MESSAGE_TYPE_MAXIMUM_LENGTH;

      nas_msg.plain.sm = *sm_msg;

      //complete sm msg content
      if(size <= 0){
        //return -1;
      }

      bstring  info = bfromcstralloc(length, "\0");//info the nas_message_encode result

      Logger::smf_app().debug("nas header, extended_protocol_discriminator: %d, security_header_type: %d,sequence_number: %d,message_authentication_code: %d ",
          nas_msg.header.extended_protocol_discriminator,
          nas_msg.header.security_header_type,
          nas_msg.header.sequence_number,
          nas_msg.header.message_authentication_code);

      Logger::smf_app().debug("sm header,extended_protocol_discriminator: %d, pdu_session_identity: %d, procedure_transaction_identity: %d, message type: %d",
          sm_msg->header.extended_protocol_discriminator,
          sm_msg->header.pdu_session_identity,
          sm_msg->header.procedure_transaction_identity,
          sm_msg->header.message_type);

      Logger::smf_app().debug("SM MSG, 5gsmcause: 0x%x",sm_msg->specific_msg.pdu_session_establishment_reject._5gsmcause);
      Logger::smf_app().debug("SM MSG, gprstimer3, unit_bits_H3: 0x%x, timeValue_bits_L5: 0x%x",sm_msg->specific_msg.pdu_session_establishment_reject.gprstimer3.unit,sm_msg->specific_msg.pdu_session_establishment_reject.gprstimer3.timeValue);
      Logger::smf_app().debug("SM MSG, allowedsscmode, is_ssc1_allowed: 0x%x, is_ssc2_allowed: 0x%x, is_ssc3_allowed: 0x%x",sm_msg->specific_msg.pdu_session_establishment_reject.allowedsscmode.is_ssc1_allowed,sm_msg->specific_msg.pdu_session_establishment_reject.allowedsscmode.is_ssc2_allowed,sm_msg->specific_msg.pdu_session_establishment_reject.allowedsscmode.is_ssc3_allowed);
      Logger::smf_app().debug("SM MSG, EAP message buffer: 0x%x 0x%x",(unsigned char)(sm_msg->specific_msg.pdu_session_establishment_reject.eapmessage->data[0]),(unsigned char )(sm_msg->specific_msg.pdu_session_establishment_reject.eapmessage->data[1]));
      Logger::smf_app().debug("SM MSG, extend_options buffer: 0x%x 0x%x 0x%x 0x%x",(unsigned char)((sm_msg->specific_msg.pdu_session_establishment_reject.extendedprotocolconfigurationoptions)->data[0]),(unsigned char)((sm_msg->specific_msg.pdu_session_establishment_reject.extendedprotocolconfigurationoptions)->data[1]),(unsigned char)((sm_msg->specific_msg.pdu_session_establishment_reject.extendedprotocolconfigurationoptions)->data[2]),(unsigned char)((sm_msg->specific_msg.pdu_session_establishment_reject.extendedprotocolconfigurationoptions)->data[3]));
      Logger::smf_app().debug("SM MSG, 5gsmcongestionreattemptindicator bits_1 --- abo: 0x%x",sm_msg->specific_msg.pdu_session_establishment_reject._5gsmcongestionreattemptindicator.abo);

      bytes = nas_message_encode (data, &nas_msg, sizeof(data)/*don't know the size*/, security);

      Logger::smf_app().debug("Buffer Data = ");
      for(int i = 0; i < bytes; i++)
        printf("%02x ",data[i]);
      std::string n1Message ((char*) data,  bytes);
      nas_msg_str = n1Message;
      Logger::smf_app().debug("\n n1MessageContent: %s (%d bytes)", nas_msg_str.c_str(), bytes);
    }

    break;

    default:
      Logger::smf_app().debug("Unknown message type: %d \n",n1_msg_type);
    }
  }
  break;
  case PDU_SESSION_CREATE_SM_CONTEXT_REQUEST: {
    Logger::smf_app().info("PDU_SESSION_CREATE_SM_CONTEXT_REQUEST");
    pdu_session_create_sm_context_request& sm_context_req = static_cast<pdu_session_create_sm_context_request&>(msg);

    switch (n1_msg_type){
    case PDU_SESSION_ESTABLISHMENT_REJECT: {
      //TODO: to be completed

      sm_msg->header.message_type = PDU_SESSION_ESTABLISHMENT_REJECT;
      sm_msg->specific_msg.pdu_session_establishment_reject._5gsmcause = 0b00001000;
      sm_msg->specific_msg.pdu_session_establishment_reject.presence = 0x1f;
      sm_msg->specific_msg.pdu_session_establishment_reject.gprstimer3.unit = GPRSTIMER3_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_1_HOUR;
      sm_msg->specific_msg.pdu_session_establishment_reject.gprstimer3.timeValue = 0;
      sm_msg->specific_msg.pdu_session_establishment_reject.allowedsscmode.is_ssc1_allowed = SSC_MODE1_ALLOWED;
      sm_msg->specific_msg.pdu_session_establishment_reject.allowedsscmode.is_ssc2_allowed = SSC_MODE2_NOT_ALLOWED;
      sm_msg->specific_msg.pdu_session_establishment_reject.allowedsscmode.is_ssc3_allowed = SSC_MODE3_ALLOWED;

      unsigned char bitStream_eapmessage[2] = {0x01,0x02};
      bstring eapmessage_tmp = bfromcstralloc(2, "\0");
      eapmessage_tmp->slen = 2;
      memcpy(eapmessage_tmp->data,bitStream_eapmessage,sizeof(bitStream_eapmessage));
      sm_msg->specific_msg.pdu_session_establishment_reject.eapmessage = eapmessage_tmp;

      unsigned char bitStream_extendedprotocolconfigurationoptions[4];
      bitStream_extendedprotocolconfigurationoptions[0] = 0x12;
      bitStream_extendedprotocolconfigurationoptions[1] = 0x13;
      bitStream_extendedprotocolconfigurationoptions[2] = 0x14;
      bitStream_extendedprotocolconfigurationoptions[3] = 0x15;
      bstring extendedprotocolconfigurationoptions_tmp = bfromcstralloc(4, "\0");
      extendedprotocolconfigurationoptions_tmp->slen = 4;
      memcpy(extendedprotocolconfigurationoptions_tmp->data,bitStream_extendedprotocolconfigurationoptions,sizeof(bitStream_extendedprotocolconfigurationoptions));
      sm_msg->specific_msg.pdu_session_establishment_reject.extendedprotocolconfigurationoptions = extendedprotocolconfigurationoptions_tmp;
      sm_msg->specific_msg.pdu_session_establishment_reject._5gsmcongestionreattemptindicator.abo = THE_BACKOFF_TIMER_IS_APPLIED_IN_ALL_PLMNS;
      size += MESSAGE_TYPE_MAXIMUM_LENGTH;

      nas_msg.plain.sm = *sm_msg;

      //complete sm msg content
      if(size <= 0){
        //return -1;
      }

      bstring  info = bfromcstralloc(length, "\0");//info the nas_message_encode result

      Logger::smf_app().debug("nas header, extended_protocol_discriminator: %d, security_header_type: %d,sequence_number: %d,message_authentication_code: %d ",
          nas_msg.header.extended_protocol_discriminator,
          nas_msg.header.security_header_type,
          nas_msg.header.sequence_number,
          nas_msg.header.message_authentication_code);

      Logger::smf_app().debug("sm header,extended_protocol_discriminator: %d, pdu_session_identity: %d, procedure_transaction_identity: %d, message type: %d",
          sm_msg->header.extended_protocol_discriminator,
          sm_msg->header.pdu_session_identity,
          sm_msg->header.procedure_transaction_identity,
          sm_msg->header.message_type);

      Logger::smf_app().debug("SM MSG, 5gsmcause: 0x%x\n",sm_msg->specific_msg.pdu_session_establishment_reject._5gsmcause);
      Logger::smf_app().debug("SM MSG, gprstimer3, unit_bits_H3: 0x%x, timeValue_bits_L5: 0x%x",sm_msg->specific_msg.pdu_session_establishment_reject.gprstimer3.unit,sm_msg->specific_msg.pdu_session_establishment_reject.gprstimer3.timeValue);
      Logger::smf_app().debug("SM MSG, allowedsscmode, is_ssc1_allowed: 0x%x, is_ssc2_allowed: 0x%x, is_ssc3_allowed: 0x%x",sm_msg->specific_msg.pdu_session_establishment_reject.allowedsscmode.is_ssc1_allowed,sm_msg->specific_msg.pdu_session_establishment_reject.allowedsscmode.is_ssc2_allowed,sm_msg->specific_msg.pdu_session_establishment_reject.allowedsscmode.is_ssc3_allowed);
      Logger::smf_app().debug("SM MSG, EAP message buffer: 0x%x 0x%x",(unsigned char)(sm_msg->specific_msg.pdu_session_establishment_reject.eapmessage->data[0]),(unsigned char )(sm_msg->specific_msg.pdu_session_establishment_reject.eapmessage->data[1]));
      Logger::smf_app().debug("SM MSG, extend_options buffer: 0x%x 0x%x 0x%x 0x%x",(unsigned char)((sm_msg->specific_msg.pdu_session_establishment_reject.extendedprotocolconfigurationoptions)->data[0]),(unsigned char)((sm_msg->specific_msg.pdu_session_establishment_reject.extendedprotocolconfigurationoptions)->data[1]),(unsigned char)((sm_msg->specific_msg.pdu_session_establishment_reject.extendedprotocolconfigurationoptions)->data[2]),(unsigned char)((sm_msg->specific_msg.pdu_session_establishment_reject.extendedprotocolconfigurationoptions)->data[3]));
      Logger::smf_app().debug("SM MSG, 5gsmcongestionreattemptindicator bits_1 --- abo: 0x%x",sm_msg->specific_msg.pdu_session_establishment_reject._5gsmcongestionreattemptindicator.abo);

      bytes = nas_message_encode (data, &nas_msg, sizeof(data)/*don't know the size*/, security);

      Logger::smf_app().debug("Buffer Data = ");
      for(int i = 0;i<bytes;i++)
        printf("%02x ",data[i]);
      std::string n1Message ((char*) data,  bytes);
      nas_msg_str = n1Message;
      Logger::smf_app().debug("n1MessageContent: %s (%d bytes)", nas_msg_str.c_str(), bytes);
    }

    break;

    default:
      Logger::smf_app().debug("Unknown message type: %d \n", n1_msg_type);
    } //end second switch
  }//end first switch
  break;
  default:
    break;
  }

}

//-----------------------------------------------------------------------------------------------------
// This is a function is an example for encoding all the NAS messages
void smf_n1_n2::create_n1_sm_container(uint8_t msg_type, std::string& nas_msg_str, uint8_t sm_cause)
{
  //TODO: clean the code!!
  Logger::smf_app().info("Create N1 SM Container, message type %d \n", msg_type);
  //To be updated according to NAS implementation
  int bytes = 0;
  int length = BUF_LEN;
  unsigned char data[BUF_LEN] = {'\0'};
  memset(data,0,sizeof(data));

  //construct encode security context
  static uint8_t fivegmm_security_context_flag = 0;
  static fivegmm_security_context_t securityencode;
  if(!fivegmm_security_context_flag)
  {
    securityencode.selected_algorithms.encryption = NAS_SECURITY_ALGORITHMS_NEA1;
    securityencode.dl_count.overflow = 0xffff;
    securityencode.dl_count.seq_num =  0x23;
    securityencode.ul_count.overflow = 0xffff;
    securityencode.ul_count.seq_num =  0x23;
    securityencode.knas_enc[0] = 0x14;
    securityencode.selected_algorithms.integrity = NAS_SECURITY_ALGORITHMS_NIA1;
    securityencode.knas_int[0] = 0x41;
    fivegmm_security_context_flag ++;
  }

  nas_message_t nas_msg;
  memset(&nas_msg, 0, sizeof(nas_message_t));
  nas_msg.header.extended_protocol_discriminator = EPD_5GS_SESSION_MANAGEMENT_MESSAGES;
  nas_msg.header.security_header_type = SECURITY_HEADER_TYPE_INTEGRITY_PROTECTED_CYPHERED;
  uint32_t mac = 0xffee;

  //test mac and encrypt, please modify here!
#if DIRECTION__
  nas_msg.header.sequence_number = securityencode.dl_count.seq_num;
#else
  nas_msg.header.sequence_number = securityencode.ul_count.seq_num;
#endif

  nas_msg.header.message_authentication_code= mac;
  nas_msg.security_protected.header = nas_msg.header;

  SM_msg *sm_msg;
  sm_msg = &nas_msg.security_protected.plain.sm;
  sm_msg->header.extended_protocol_discriminator  = EPD_5GS_SESSION_MANAGEMENT_MESSAGES;

  sm_msg->header.pdu_session_identity = 5;
  sm_msg->header.procedure_transaction_identity = 1; //TODO: to be updated

  switch (msg_type){
  case PDU_SESSION_ESTABLISHMENT_REQUEST: {
    //TODO:
    Logger::smf_app().debug("PDU_SESSION_ESTABLISHMENT_REQUEST, encode starting ....");
    sm_msg->header.message_type = PDU_SESSION_ESTABLISHMENT_REQUEST;

    unsigned char bitStream_intergrityprotectionmaximumdatarate[2] = {0x01,0x02};
    bstring intergrityprotectionmaximumdatarate_tmp = bfromcstralloc(2, "\0");
    //intergrityprotectionmaximumdatarate_tmp->data = bitStream_intergrityprotectionmaximumdatarate;
    intergrityprotectionmaximumdatarate_tmp->slen = 2;
    memcpy(intergrityprotectionmaximumdatarate_tmp->data,bitStream_intergrityprotectionmaximumdatarate,sizeof(bitStream_intergrityprotectionmaximumdatarate));
    sm_msg->specific_msg.pdu_session_establishment_request.intergrityprotectionmaximumdatarate = intergrityprotectionmaximumdatarate_tmp;
    sm_msg->specific_msg.pdu_session_establishment_request.presence = 0x7f;
    sm_msg->specific_msg.pdu_session_establishment_request._pdusessiontype.pdu_session_type_value = 0x01;
    sm_msg->specific_msg.pdu_session_establishment_request.sscmode.ssc_mode_value = 0x01;
    sm_msg->specific_msg.pdu_session_establishment_request._5gsmcapability.is_MPTCP_supported = MPTCP_FUNCTIONALITY_SUPPORTED;
    sm_msg->specific_msg.pdu_session_establishment_request._5gsmcapability.is_ATSLL_supported = EATSSS_LOW_LAYER_FUNCTIONALITY_NOT_SUPPORTED;
    sm_msg->specific_msg.pdu_session_establishment_request._5gsmcapability.is_EPTS1_supported = ETHERNET_PDN_TYPE_IN_S1_MODE_SUPPORTED;
    sm_msg->specific_msg.pdu_session_establishment_request._5gsmcapability.is_MH6PDU_supported = MULTI_HOMED_IPV6_PDU_SESSION_SUPPORTED;
    sm_msg->specific_msg.pdu_session_establishment_request._5gsmcapability.is_Rqos_supported = REFLECTIVE_QOS_NOT_SUPPORTED;
    sm_msg->specific_msg.pdu_session_establishment_request.maximumnumberofsupportedpacketfilters = 0x3ff;
    sm_msg->specific_msg.pdu_session_establishment_request.alwaysonpdusessionrequested.apsr_requested = ALWAYSON_PDU_SESSION_REQUESTED;

    //for smpdudnrequestcontainer
    unsigned char bitStream_smpdudnrequestcontainer[3];
    bitStream_smpdudnrequestcontainer[0] = 0x11;
    bitStream_smpdudnrequestcontainer[1] = 0x22;
    bitStream_smpdudnrequestcontainer[2] = 0x33;
    bstring smpdudnrequestcontainer_tmp = bfromcstralloc(3, "\0");
    //smpdudnrequestcontainer_tmp->data = bitStream_smpdudnrequestcontainer;
    smpdudnrequestcontainer_tmp->slen = 3;
    memcpy(smpdudnrequestcontainer_tmp->data,bitStream_smpdudnrequestcontainer,sizeof(bitStream_smpdudnrequestcontainer));
    sm_msg->specific_msg.pdu_session_establishment_request.smpdudnrequestcontainer = smpdudnrequestcontainer_tmp;

    //For extendedprotocolconfigurationoptions
    unsigned char bitStream_extendedprotocolconfigurationoptions[4];
    bitStream_extendedprotocolconfigurationoptions[0] = 0x12;
    bitStream_extendedprotocolconfigurationoptions[1] = 0x13;
    bitStream_extendedprotocolconfigurationoptions[2] = 0x14;
    bitStream_extendedprotocolconfigurationoptions[3] = 0x15;
    bstring extendedprotocolconfigurationoptions_tmp = bfromcstralloc(4, "\0");
    //extendedprotocolconfigurationoptions_tmp->data = bitStream_extendedprotocolconfigurationoptions;
    extendedprotocolconfigurationoptions_tmp->slen = 4;
    memcpy(extendedprotocolconfigurationoptions_tmp->data,bitStream_extendedprotocolconfigurationoptions,sizeof(bitStream_extendedprotocolconfigurationoptions));
    sm_msg->specific_msg.pdu_session_establishment_request.extendedprotocolconfigurationoptions = extendedprotocolconfigurationoptions_tmp;

    //assign content of NAS to SM MSG
    nas_msg.plain.sm = *sm_msg;

    Logger::smf_app().debug("NAS header, extended_protocol_discriminator: 0x%x, security_header_type: 0x%x, sequence_number: 0x%x, message_authentication_code: 0x%x",
        nas_msg.header.extended_protocol_discriminator,
        nas_msg.header.security_header_type,
        nas_msg.header.sequence_number,
        nas_msg.header.message_authentication_code);

    Logger::smf_app().debug("SM header, extended_protocol_discriminator: 0x%x, pdu_session_identity: 0x%x, procedure_transaction_identity: 0x%x, message type: 0x%x",
        sm_msg->header.extended_protocol_discriminator,
        sm_msg->header.pdu_session_identity,
        sm_msg->header.procedure_transaction_identity,
        sm_msg->header.message_type);

    Logger::smf_app().debug("Integrity buffer: 0x%x 0x%x",(unsigned char)((sm_msg->specific_msg.pdu_session_establishment_request.intergrityprotectionmaximumdatarate)->data[0]),(unsigned char )((sm_msg->specific_msg.pdu_session_establishment_request.intergrityprotectionmaximumdatarate)->data[1]));
    Logger::smf_app().debug("pdusessiontype bits_3: 0x%x",sm_msg->specific_msg.pdu_session_establishment_request._pdusessiontype.pdu_session_type_value);
    Logger::smf_app().debug("sscmode bits_3: 0x%x",sm_msg->specific_msg.pdu_session_establishment_request.sscmode.ssc_mode_value);
    Logger::smf_app().debug("_5gsmcapability bits_5 --- MPTCP: 0x%x ATS-LL: 0x%x EPT-S1: 0x%x MH6-PDU: 0x%x RqoS: 0x%x",sm_msg->specific_msg.pdu_session_establishment_request._5gsmcapability.is_MPTCP_supported,sm_msg->specific_msg.pdu_session_establishment_request._5gsmcapability.is_ATSLL_supported,sm_msg->specific_msg.pdu_session_establishment_request._5gsmcapability.is_EPTS1_supported,sm_msg->specific_msg.pdu_session_establishment_request._5gsmcapability.is_MH6PDU_supported,sm_msg->specific_msg.pdu_session_establishment_request._5gsmcapability.is_Rqos_supported);
    Logger::smf_app().debug("maximum bits_11: 0x%x",sm_msg->specific_msg.pdu_session_establishment_request.maximumnumberofsupportedpacketfilters);
    Logger::smf_app().debug("Always-on bits_1 --- APSR: 0x%x",sm_msg->specific_msg.pdu_session_establishment_request.alwaysonpdusessionrequested.apsr_requested);
    Logger::smf_app().debug("sm_pdu_dn buffer: 0x%x 0x%x 0x%x",(unsigned char)((sm_msg->specific_msg.pdu_session_establishment_request.smpdudnrequestcontainer)->data[0]),(unsigned char)((sm_msg->specific_msg.pdu_session_establishment_request.smpdudnrequestcontainer)->data[1]),(unsigned char)((sm_msg->specific_msg.pdu_session_establishment_request.smpdudnrequestcontainer)->data[2]));
    Logger::smf_app().debug("extend_options buffer: 0x%x 0x%x 0x%x 0x%x",(unsigned char)((sm_msg->specific_msg.pdu_session_establishment_request.extendedprotocolconfigurationoptions)->data[0]),(unsigned char)((sm_msg->specific_msg.pdu_session_establishment_request.extendedprotocolconfigurationoptions)->data[1]),(unsigned char)((sm_msg->specific_msg.pdu_session_establishment_request.extendedprotocolconfigurationoptions)->data[2]),(unsigned char)((sm_msg->specific_msg.pdu_session_establishment_request.extendedprotocolconfigurationoptions)->data[3]));

    //bytes = nas_message_encode (data, &nas_msg, 60/*don't know the size*/, security);
    bytes = nas_message_encode (data, &nas_msg, sizeof(data)/*don't know the size*/, &securityencode);

    //nas_msg_str = reinterpret_cast<char*> (data);
    Logger::smf_app().debug("Buffer Data:");
    for(int i = 0;i<bytes;i++)
      printf("%02x ",data[i]);

    std::string n1Message ((char*) data,  bytes);
    nas_msg_str = n1Message;
    Logger::smf_app().debug("n1MessageContent: %d, %s\n ", bytes, nas_msg_str.c_str());

    Logger::smf_app().debug("PDU_SESSION_ESTABLISHMENT_REQUEST, encode finished...");
  }
  break;


  case PDU_SESSION_ESTABLISHMENT_ACCEPT: {
    //TODO:
    Logger::smf_app().info("PDU_SESSION_ESTABLISHMENT_ACCEPT, encode starting...");
    sm_msg->header.message_type = PDU_SESSION_ESTABLISHMENT_ACCEPT;

    //Fill the content of PDU Session Establishment Request message with hardcoded values
    /* ExtendedProtocolDiscriminator extendedprotocoldiscriminator;
		PDUSessionIdentity pdusessionidentity;
		ProcedureTransactionIdentity proceduretransactionidentity;
		MessageType messagetype;
		_PDUSessionType _pdusessiontype;
		SSCMode sscmode;
		QOSRules qosrules;
		SessionAMBR sessionambr;
		uint16_t presence;
		_5GSMCause _5gsmcause;
		PDUAddress pduaddress;
		GPRSTimer gprstimer;
		SNSSAI snssai;
		AlwaysonPDUSessionIndication alwaysonpdusessionindication;
		MappedEPSBearerContexts mappedepsbearercontexts;
		EAPMessage eapmessage;
		QOSFlowDescriptions qosflowdescriptions;
		ExtendedProtocolConfigurationOptions extendedprotocolconfigurationoptions;
		DNN dnn;
     */

    sm_msg->specific_msg.pdu_session_establishment_accept._pdusessiontype.pdu_session_type_value = 0x01;
    sm_msg->specific_msg.pdu_session_establishment_accept.sscmode.ssc_mode_value = 0x01;

    //QOSRules
    QOSRulesIE qosrulesie[2];

    qosrulesie[0].qosruleidentifer=0x01;
    qosrulesie[0].ruleoperationcode = CREATE_NEW_QOS_RULE;
    qosrulesie[0].dqrbit = THE_QOS_RULE_IS_DEFAULT_QOS_RULE;
    qosrulesie[0].numberofpacketfilters = 3;

    Create_ModifyAndAdd_ModifyAndReplace create_modifyandadd_modifyandreplace[3];
    create_modifyandadd_modifyandreplace[0].packetfilterdirection = 0b01;
    create_modifyandadd_modifyandreplace[0].packetfilteridentifier = 1;
    /*unsigned char bitStream_packetfiltercontents00[2] = {MATCHALL_TYPE,MATCHALL_TYPE};
		bstring packetfiltercontents00_tmp = bfromcstralloc(2, "\0");
		packetfiltercontents00_tmp->slen = 2;
		memcpy(packetfiltercontents00_tmp->data,bitStream_packetfiltercontents00,sizeof(bitStream_packetfiltercontents00));
		create_modifyandadd_modifyandreplace[0].packetfiltercontents = packetfiltercontents00_tmp;*/
    create_modifyandadd_modifyandreplace[0].packetfiltercontents.component_type = QOS_RULE_MATCHALL_TYPE;
    create_modifyandadd_modifyandreplace[1].packetfilterdirection = 0b10;
    create_modifyandadd_modifyandreplace[1].packetfilteridentifier = 2;
    /*unsigned char bitStream_packetfiltercontents01[2] = {MATCHALL_TYPE,MATCHALL_TYPE};
		bstring packetfiltercontents01_tmp = bfromcstralloc(2, "\0");
		packetfiltercontents01_tmp->slen = 2;
		memcpy(packetfiltercontents01_tmp->data,bitStream_packetfiltercontents01,sizeof(bitStream_packetfiltercontents01));
		create_modifyandadd_modifyandreplace[1].packetfiltercontents = packetfiltercontents01_tmp;*/
    create_modifyandadd_modifyandreplace[1].packetfiltercontents.component_type = QOS_RULE_MATCHALL_TYPE;
    create_modifyandadd_modifyandreplace[2].packetfilterdirection = 0b11;
    create_modifyandadd_modifyandreplace[2].packetfilteridentifier = 3;
    /*unsigned char bitStream_packetfiltercontents02[2] = {MATCHALL_TYPE,MATCHALL_TYPE};
		bstring packetfiltercontents02_tmp = bfromcstralloc(2, "\0");
		packetfiltercontents02_tmp->slen = 2;
		memcpy(packetfiltercontents02_tmp->data,bitStream_packetfiltercontents02,sizeof(bitStream_packetfiltercontents02));
		create_modifyandadd_modifyandreplace[2].packetfiltercontents = packetfiltercontents02_tmp;*/
    create_modifyandadd_modifyandreplace[2].packetfiltercontents.component_type = QOS_RULE_MATCHALL_TYPE;

    //1st rule
    qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace = create_modifyandadd_modifyandreplace;
    qosrulesie[0].qosruleprecedence = 1;
    qosrulesie[0].segregation = SEGREGATION_NOT_REQUESTED;
    qosrulesie[0].qosflowidentifer = 0x07;
    //2nd rule
    qosrulesie[1].qosruleidentifer=0x02;
    qosrulesie[1].ruleoperationcode = MODIFY_EXISTING_QOS_RULE_AND_DELETE_PACKET_FILTERS;
    qosrulesie[1].dqrbit = THE_QOS_RULE_IS_NOT_THE_DEFAULT_QOS_RULE;
    qosrulesie[1].numberofpacketfilters = 3;

    ModifyAndDelete modifyanddelete[3];
    modifyanddelete[0].packetfilteridentifier = 1;
    modifyanddelete[1].packetfilteridentifier = 2;
    modifyanddelete[2].packetfilteridentifier = 3;
    qosrulesie[1].packetfilterlist.modifyanddelete = modifyanddelete;

    qosrulesie[1].qosruleprecedence = 1;
    qosrulesie[1].segregation = SEGREGATION_REQUESTED;
    qosrulesie[1].qosflowidentifer = 0x08;

    sm_msg->specific_msg.pdu_session_establishment_accept.qosrules.lengthofqosrulesie = 2;
    sm_msg->specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie = qosrulesie;

    //SessionAMBR
    sm_msg->specific_msg.pdu_session_establishment_accept.sessionambr.uint_for_session_ambr_for_downlink = AMBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_1KBPS;
    sm_msg->specific_msg.pdu_session_establishment_accept.sessionambr.session_ambr_for_downlink = (AMBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_4KBPS << 8) + (AMBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_16KBPS);
    sm_msg->specific_msg.pdu_session_establishment_accept.sessionambr.uint_for_session_ambr_for_uplink = AMBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_64KBPS;
    sm_msg->specific_msg.pdu_session_establishment_accept.sessionambr.session_ambr_for_uplink = (AMBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_256KBPS << 8) + (AMBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_1MBPS);

    sm_msg->specific_msg.pdu_session_establishment_accept.presence = 0xffff;
    sm_msg->specific_msg.pdu_session_establishment_accept._5gsmcause = 0b00001000;
    sm_msg->specific_msg.pdu_session_establishment_accept.pduaddress.pdu_session_type_value = PDU_ADDRESS_IPV4;

    //PDUAddress
    unsigned char bitStream_pdu_address_information[4];
    bitStream_pdu_address_information[0] = 0x11;
    bitStream_pdu_address_information[1] = 0x22;
    bitStream_pdu_address_information[2] = 0x33;
    bitStream_pdu_address_information[3] = 0x44;
    bstring pdu_address_information_tmp = bfromcstralloc(4, "\0");
    pdu_address_information_tmp->slen = 4;
    memcpy(pdu_address_information_tmp->data,bitStream_pdu_address_information,sizeof(bitStream_pdu_address_information));
    sm_msg->specific_msg.pdu_session_establishment_accept.pduaddress.pdu_address_information = pdu_address_information_tmp;

    //GPRSTimer
    sm_msg->specific_msg.pdu_session_establishment_accept.gprstimer.unit = GPRSTIMER_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_2_SECONDS;
    sm_msg->specific_msg.pdu_session_establishment_accept.gprstimer.timeValue = 0;

    //SNSSAI
    sm_msg->specific_msg.pdu_session_establishment_accept.snssai.len = SST_AND_SD_LENGHT;
    sm_msg->specific_msg.pdu_session_establishment_accept.snssai.sst = 0x66;
    sm_msg->specific_msg.pdu_session_establishment_accept.snssai.sd = 0x123456;

    //AlwaysonPDUSessionIndication
    sm_msg->specific_msg.pdu_session_establishment_accept.alwaysonpdusessionindication.apsi_indication = ALWAYSON_PDU_SESSION_REQUIRED;

    //sm_msg->specific_msg.pdu_session_establishment_accept.mappedepsbearercontexts

    //EAPMessage
    unsigned char bitStream_eapmessage[2] = {0x01,0x02};
    bstring eapmessage_tmp = bfromcstralloc(2, "\0");
    eapmessage_tmp->slen = 2;
    memcpy(eapmessage_tmp->data,bitStream_eapmessage,sizeof(bitStream_eapmessage));
    sm_msg->specific_msg.pdu_session_establishment_accept.eapmessage = eapmessage_tmp;

    //QoSFlowDescritions
    QOSFlowDescriptionsContents qosflowdescriptionscontents[3];
    qosflowdescriptionscontents[0].qfi = 1;
    qosflowdescriptionscontents[0].operationcode = CREATE_NEW_QOS_FLOW_DESCRIPTION;
    qosflowdescriptionscontents[0].e = PARAMETERS_LIST_IS_INCLUDED;
    qosflowdescriptionscontents[0].numberofparameters = 3;
    ParametersList parameterslist00[3];
    parameterslist00[0].parameteridentifier = PARAMETER_IDENTIFIER_5QI;
    parameterslist00[0].parametercontents._5qi = 0b01000001;
    parameterslist00[1].parameteridentifier = PARAMETER_IDENTIFIER_GFBR_UPLINK;
    parameterslist00[1].parametercontents.gfbrormfbr_uplinkordownlink.uint = GFBRORMFBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_1KBPS;
    parameterslist00[1].parametercontents.gfbrormfbr_uplinkordownlink.value = 0x1000;
    parameterslist00[2].parameteridentifier = PARAMETER_IDENTIFIER_GFBR_DOWNLINK;
    parameterslist00[2].parametercontents.gfbrormfbr_uplinkordownlink.uint = GFBRORMFBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_4KBPS;
    parameterslist00[2].parametercontents.gfbrormfbr_uplinkordownlink.value = 0x2000;
    qosflowdescriptionscontents[0].parameterslist = parameterslist00;

    qosflowdescriptionscontents[1].qfi = 2;
    qosflowdescriptionscontents[1].operationcode = DELETE_EXISTING_QOS_FLOW_DESCRIPTION;
    qosflowdescriptionscontents[1].e = PARAMETERS_LIST_IS_NOT_INCLUDED;
    qosflowdescriptionscontents[1].numberofparameters = 0;
    qosflowdescriptionscontents[1].parameterslist = nullptr;

    qosflowdescriptionscontents[2].qfi = 1;
    qosflowdescriptionscontents[2].operationcode = MODIFY_EXISTING_QOS_FLOW_DESCRIPTION;
    qosflowdescriptionscontents[2].e = REPLACEMENT_OF_ALL_PREVIOUSLY_PROVIDED_PARAMETERS;
    qosflowdescriptionscontents[2].numberofparameters = 4;
    ParametersList parameterslist02[4];
    parameterslist02[0].parameteridentifier = PARAMETER_IDENTIFIER_MFBR_UPLINK;
    parameterslist02[0].parametercontents.gfbrormfbr_uplinkordownlink.uint = GFBRORMFBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_16KBPS;
    parameterslist02[0].parametercontents.gfbrormfbr_uplinkordownlink.value = 0x3000;
    parameterslist02[1].parameteridentifier = PARAMETER_IDENTIFIER_MFBR_DOWNLINK;
    parameterslist02[1].parametercontents.gfbrormfbr_uplinkordownlink.uint = GFBRORMFBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_64KBPS;
    parameterslist02[1].parametercontents.gfbrormfbr_uplinkordownlink.value = 0x4000;
    parameterslist02[2].parameteridentifier = PARAMETER_IDENTIFIER_AVERAGING_WINDOW;
    parameterslist02[2].parametercontents.averagingwindow.uplinkinmilliseconds = GFBRORMFBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_256KBPS;
    parameterslist02[2].parametercontents.averagingwindow.downlinkinmilliseconds = GFBRORMFBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_1MBPS;
    parameterslist02[3].parameteridentifier = PARAMETER_IDENTIFIER_EPS_BEARER_IDENTITY;
    parameterslist02[3].parametercontents.epsbeareridentity = QOS_FLOW_EPS_BEARER_IDENTITY_VALUE15;
    qosflowdescriptionscontents[2].parameterslist = parameterslist02;

    sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionsnumber = 3;
    sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents = qosflowdescriptionscontents;

    //ExtendedProtocolConfigurationOptions
    unsigned char bitStream_extendedprotocolconfigurationoptions[4];
    bitStream_extendedprotocolconfigurationoptions[0] = 0x12;
    bitStream_extendedprotocolconfigurationoptions[1] = 0x13;
    bitStream_extendedprotocolconfigurationoptions[2] = 0x14;
    bitStream_extendedprotocolconfigurationoptions[3] = 0x15;
    bstring extendedprotocolconfigurationoptions_tmp = bfromcstralloc(4, "\0");
    //extendedprotocolconfigurationoptions_tmp->data = bitStream_extendedprotocolconfigurationoptions;
    extendedprotocolconfigurationoptions_tmp->slen = 4;
    memcpy(extendedprotocolconfigurationoptions_tmp->data,bitStream_extendedprotocolconfigurationoptions,sizeof(bitStream_extendedprotocolconfigurationoptions));
    sm_msg->specific_msg.pdu_session_establishment_accept.extendedprotocolconfigurationoptions = extendedprotocolconfigurationoptions_tmp;

    unsigned char bitStream_dnn[3] = {0x10,0x20,0x30};
    bstring dnn_tmp = bfromcstralloc(3, "\0");
    dnn_tmp->slen = 3;
    memcpy(dnn_tmp->data,bitStream_dnn,sizeof(bitStream_dnn));
    sm_msg->specific_msg.pdu_session_establishment_accept.dnn = dnn_tmp;

    //assign SM msg to NAS content
    nas_msg.plain.sm = *sm_msg;

    //Print the logs
    Logger::smf_app().debug("NAS header, encode extended_protocol_discriminator: 0x%x, security_header_type: 0x%x,sequence_number: 0x%x, message_authentication_code: 0x%x",
        nas_msg.header.extended_protocol_discriminator,
        nas_msg.header.security_header_type,
        nas_msg.header.sequence_number,
        nas_msg.header.message_authentication_code);

    Logger::smf_app().debug("SM header, extended_protocol_discriminator: 0x%x, pdu_session_identity: 0x%x, procedure_transaction_identity: 0x%x, message type: 0x%x",
        sm_msg->header.extended_protocol_discriminator,
        sm_msg->header.pdu_session_identity,
        sm_msg->header.procedure_transaction_identity,
        sm_msg->header.message_type);

    Logger::smf_app().debug("PDUSessionType bits_3: %#0x",sm_msg->specific_msg.pdu_session_establishment_accept._pdusessiontype.pdu_session_type_value);
    Logger::smf_app().debug("SSC Mode bits_3: %#0x",sm_msg->specific_msg.pdu_session_establishment_accept.sscmode.ssc_mode_value);
    Logger::smf_app().debug("QoSRules: %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x",
        sm_msg->specific_msg.pdu_session_establishment_accept.qosrules.lengthofqosrulesie,
        sm_msg->specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[0].qosruleidentifer,
        sm_msg->specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[0].ruleoperationcode,
        sm_msg->specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[0].dqrbit,
        sm_msg->specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[0].numberofpacketfilters,
        sm_msg->specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[0].packetfilterdirection,
        sm_msg->specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[0].packetfilteridentifier,
        sm_msg->specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[0].packetfiltercontents.component_type,
        sm_msg->specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[1].packetfilterdirection,
        sm_msg->specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[1].packetfilteridentifier,
        sm_msg->specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[1].packetfiltercontents.component_type,
        sm_msg->specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[2].packetfilterdirection,
        sm_msg->specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[2].packetfilteridentifier,
        sm_msg->specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[2].packetfiltercontents.component_type,
        sm_msg->specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[0].qosruleprecedence,
        sm_msg->specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[0].segregation,
        sm_msg->specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[0].qosflowidentifer,
        sm_msg->specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[1].qosruleidentifer,
        sm_msg->specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[1].ruleoperationcode,
        sm_msg->specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[1].dqrbit,
        sm_msg->specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[1].numberofpacketfilters,
        sm_msg->specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[1].packetfilterlist.modifyanddelete[0].packetfilteridentifier,
        sm_msg->specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[1].packetfilterlist.modifyanddelete[1].packetfilteridentifier,
        sm_msg->specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[1].packetfilterlist.modifyanddelete[2].packetfilteridentifier,
        sm_msg->specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[1].qosruleprecedence,
        sm_msg->specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[1].segregation,
        sm_msg->specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[1].qosflowidentifer);

    Logger::smf_app().debug("SessionAMBR: %x %x %x %x",
        sm_msg->specific_msg.pdu_session_establishment_accept.sessionambr.uint_for_session_ambr_for_downlink,
        sm_msg->specific_msg.pdu_session_establishment_accept.sessionambr.session_ambr_for_downlink,
        sm_msg->specific_msg.pdu_session_establishment_accept.sessionambr.uint_for_session_ambr_for_uplink,
        sm_msg->specific_msg.pdu_session_establishment_accept.sessionambr.session_ambr_for_uplink);

    Logger::smf_app().debug("5GSMCause: %#0x",sm_msg->specific_msg.pdu_session_establishment_accept._5gsmcause);

    Logger::smf_app().debug("PDUAddress: %x %x %x %x %x",
        sm_msg->specific_msg.pdu_session_establishment_accept.pduaddress.pdu_session_type_value,
        (unsigned char)(sm_msg->specific_msg.pdu_session_establishment_accept.pduaddress.pdu_address_information->data[0]),
        (unsigned char)(sm_msg->specific_msg.pdu_session_establishment_accept.pduaddress.pdu_address_information->data[1]),
        (unsigned char)(sm_msg->specific_msg.pdu_session_establishment_accept.pduaddress.pdu_address_information->data[2]),
        (unsigned char)(sm_msg->specific_msg.pdu_session_establishment_accept.pduaddress.pdu_address_information->data[3]));

    Logger::smf_app().debug("GPRSTimer, unit: %#0x, timeValue: %#0x",
        sm_msg->specific_msg.pdu_session_establishment_accept.gprstimer.unit,
        sm_msg->specific_msg.pdu_session_establishment_accept.gprstimer.timeValue);

    Logger::smf_app().debug("SNSSAI, len: %#0x, sst: %#0x, sd: %#0x",
        sm_msg->specific_msg.pdu_session_establishment_accept.snssai.len,
        sm_msg->specific_msg.pdu_session_establishment_accept.snssai.sst,
        sm_msg->specific_msg.pdu_session_establishment_accept.snssai.sd);

    Logger::smf_app().debug("AlwaysOnPDUSessionIndication: %#0x",sm_msg->specific_msg.pdu_session_establishment_accept.alwaysonpdusessionindication.apsi_indication);

    Logger::smf_app().debug("EAPMessage buffer:%x %x",
        (unsigned char)(sm_msg->specific_msg.pdu_session_establishment_accept.eapmessage->data[0]),
        (unsigned char)(sm_msg->specific_msg.pdu_session_establishment_accept.eapmessage->data[1]));

    Logger::smf_app().debug("QosFlowDescriptions: %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x\n",
        sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionsnumber,
        sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[0].qfi,
        sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[0].operationcode,
        sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[0].e,
        sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[0].numberofparameters,
        sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[0].parameteridentifier,
        sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[0].parametercontents._5qi,
        sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[1].parameteridentifier,
        sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[1].parametercontents.gfbrormfbr_uplinkordownlink.uint,
        sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[1].parametercontents.gfbrormfbr_uplinkordownlink.value,
        sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[2].parameteridentifier,
        sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[2].parametercontents.gfbrormfbr_uplinkordownlink.uint,
        sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[2].parametercontents.gfbrormfbr_uplinkordownlink.value,
        sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[1].qfi,
        sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[1].operationcode,
        sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[1].e,
        sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[1].numberofparameters,
        sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].qfi,
        sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].operationcode,
        sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].e,
        sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].numberofparameters,
        sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[0].parameteridentifier,
        sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[0].parametercontents.gfbrormfbr_uplinkordownlink.uint,
        sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[0].parametercontents.gfbrormfbr_uplinkordownlink.value,
        sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[1].parameteridentifier,
        sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[1].parametercontents.gfbrormfbr_uplinkordownlink.uint,
        sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[1].parametercontents.gfbrormfbr_uplinkordownlink.value,
        sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[2].parameteridentifier,
        sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[2].parametercontents.averagingwindow.uplinkinmilliseconds,
        sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[2].parametercontents.averagingwindow.downlinkinmilliseconds,
        sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[3].parameteridentifier,
        sm_msg->specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[3].parametercontents.epsbeareridentity);

    Logger::smf_app().debug("Extend_options buffer:%x %x %x %x\n",
        (unsigned char)(sm_msg->specific_msg.pdu_session_establishment_accept.extendedprotocolconfigurationoptions->data[0]),
        (unsigned char)(sm_msg->specific_msg.pdu_session_establishment_accept.extendedprotocolconfigurationoptions->data[1]),
        (unsigned char)(sm_msg->specific_msg.pdu_session_establishment_accept.extendedprotocolconfigurationoptions->data[2]),
        (unsigned char)(sm_msg->specific_msg.pdu_session_establishment_accept.extendedprotocolconfigurationoptions->data[3]));

    Logger::smf_app().debug("DNN buffer:%x %x %x\n",
        (unsigned char)(sm_msg->specific_msg.pdu_session_establishment_accept.dnn->data[0]),
        (unsigned char)(sm_msg->specific_msg.pdu_session_establishment_accept.dnn->data[1]),
        (unsigned char)(sm_msg->specific_msg.pdu_session_establishment_accept.dnn->data[2]));

    //bytes = nas_message_encode (data, &nas_msg, 60/*don't know the size*/, security);
    bytes = nas_message_encode (data, &nas_msg, sizeof(data)/*don't know the size*/, &securityencode);

    //nas_msg_str = reinterpret_cast<char*> (data);
    Logger::smf_app().debug("Buffer Data: ");
    for(int i = 0;i<bytes;i++)
      printf("%02x ",data[i]);
    std::string n1Message ((char*) data,  bytes);
    nas_msg_str = n1Message;
    Logger::smf_app().debug("n1MessageContent (%d bytes), %s\n ", bytes, nas_msg_str.c_str());
    Logger::smf_app().info("PDU_SESSION_ESTABLISHMENT_ACCEPT, encode finished");
  }
  break;

  case PDU_SESSION_ESTABLISHMENT_REJECT: {
    printf("\n\nPDU_SESSION_ESTABLISHMENT_REJECT------------ encode start\n");
    sm_msg->header.message_type = PDU_SESSION_ESTABLISHMENT_REJECT;
    sm_msg->specific_msg.pdu_session_establishment_reject._5gsmcause = 0b00001000;

    sm_msg->specific_msg.pdu_session_establishment_reject.presence = 0x1f;

    sm_msg->specific_msg.pdu_session_establishment_reject.gprstimer3.unit = GPRSTIMER3_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_1_HOUR;
    sm_msg->specific_msg.pdu_session_establishment_reject.gprstimer3.timeValue = 0;

    sm_msg->specific_msg.pdu_session_establishment_reject.allowedsscmode.is_ssc1_allowed = SSC_MODE1_ALLOWED;
    sm_msg->specific_msg.pdu_session_establishment_reject.allowedsscmode.is_ssc2_allowed = SSC_MODE2_NOT_ALLOWED;
    sm_msg->specific_msg.pdu_session_establishment_reject.allowedsscmode.is_ssc3_allowed = SSC_MODE3_ALLOWED;

    unsigned char bitStream_eapmessage[2] = {0x01,0x02};
    bstring eapmessage_tmp = bfromcstralloc(2, "\0");
    eapmessage_tmp->slen = 2;
    memcpy(eapmessage_tmp->data,bitStream_eapmessage,sizeof(bitStream_eapmessage));
    sm_msg->specific_msg.pdu_session_establishment_reject.eapmessage = eapmessage_tmp;

    unsigned char bitStream_extendedprotocolconfigurationoptions[4];
    bitStream_extendedprotocolconfigurationoptions[0] = 0x12;
    bitStream_extendedprotocolconfigurationoptions[1] = 0x13;
    bitStream_extendedprotocolconfigurationoptions[2] = 0x14;
    bitStream_extendedprotocolconfigurationoptions[3] = 0x15;
    bstring extendedprotocolconfigurationoptions_tmp = bfromcstralloc(4, "\0");
    //extendedprotocolconfigurationoptions_tmp->data = bitStream_extendedprotocolconfigurationoptions;
    extendedprotocolconfigurationoptions_tmp->slen = 4;
    memcpy(extendedprotocolconfigurationoptions_tmp->data,bitStream_extendedprotocolconfigurationoptions,sizeof(bitStream_extendedprotocolconfigurationoptions));
    sm_msg->specific_msg.pdu_session_establishment_reject.extendedprotocolconfigurationoptions = extendedprotocolconfigurationoptions_tmp;

    sm_msg->specific_msg.pdu_session_establishment_reject._5gsmcongestionreattemptindicator.abo = THE_BACKOFF_TIMER_IS_APPLIED_IN_ALL_PLMNS;

    nas_msg.plain.sm = *sm_msg;


    printf("nas header encode extended_protocol_discriminator:0x%x\n, security_header_type:0x%x\n,sequence_number:0x%x\n,message_authentication_code:0x%x\n",
        nas_msg.header.extended_protocol_discriminator,
        nas_msg.header.security_header_type,
        nas_msg.header.sequence_number,
        nas_msg.header.message_authentication_code);



    printf("sm header,extended_protocol_discriminator:0x%x,pdu_session_identity:0x%x,proeduer_transaction_identity:0x%x, message type:0x%x\n",
        sm_msg->header.extended_protocol_discriminator,
        sm_msg->header.pdu_session_identity,
        sm_msg->header.procedure_transaction_identity,
        sm_msg->header.message_type);


    printf("_5gsmcause: 0x%x\n",sm_msg->specific_msg.pdu_session_establishment_reject._5gsmcause);
    printf("gprstimer3 --- unit_bits_H3: 0x%x,timeValue_bits_L5: 0x%x\n",sm_msg->specific_msg.pdu_session_establishment_reject.gprstimer3.unit,sm_msg->specific_msg.pdu_session_establishment_reject.gprstimer3.timeValue);
    printf("allowedsscmode --- is_ssc1_allowed: 0x%x, is_ssc2_allowed: 0x%x, is_ssc3_allowed: 0x%x\n",sm_msg->specific_msg.pdu_session_establishment_reject.allowedsscmode.is_ssc1_allowed,sm_msg->specific_msg.pdu_session_establishment_reject.allowedsscmode.is_ssc2_allowed,sm_msg->specific_msg.pdu_session_establishment_reject.allowedsscmode.is_ssc3_allowed);
    printf("eapmessage buffer:0x%x 0x%x\n",(unsigned char)(sm_msg->specific_msg.pdu_session_establishment_reject.eapmessage->data[0]),(unsigned char )(sm_msg->specific_msg.pdu_session_establishment_reject.eapmessage->data[1]));
    printf("extend_options buffer:0x%x 0x%x 0x%x 0x%x\n",(unsigned char)((sm_msg->specific_msg.pdu_session_establishment_reject.extendedprotocolconfigurationoptions)->data[0]),(unsigned char)((sm_msg->specific_msg.pdu_session_establishment_reject.extendedprotocolconfigurationoptions)->data[1]),(unsigned char)((sm_msg->specific_msg.pdu_session_establishment_reject.extendedprotocolconfigurationoptions)->data[2]),(unsigned char)((sm_msg->specific_msg.pdu_session_establishment_reject.extendedprotocolconfigurationoptions)->data[3]));
    printf("_5gsmcongestionreattemptindicator bits_1 --- abo:0x%x\n",sm_msg->specific_msg.pdu_session_establishment_reject._5gsmcongestionreattemptindicator.abo);

    //bytes = nas_message_encode (data, &nas_msg, 60/*don't know the size*/, security);
    bytes = nas_message_encode (data, &nas_msg, sizeof(data)/*don't know the size*/, &securityencode);

    //nas_msg_str = reinterpret_cast<char*> (data);
    printf("Data = ");
    for(int i = 0;i<bytes;i++)
      printf("Data = %02x ",data[i]);
    printf("\n");
    std::string n1Message ((char*) data,  bytes);
    nas_msg_str = n1Message;
    Logger::smf_app().debug("n1MessageContent: %d, %s\n ", bytes, nas_msg_str.c_str());
    printf("PDU_SESSION_ESTABLISHMENT_REJECT------------ encode end\n\n");
  }
  break;

  case PDU_SESSION_AUTHENTICATION_COMMAND:{
    printf("\n\nPDU_SESSION_AUTHENTICATION_COMMAND------------ encode start\n");
    sm_msg->header.message_type = PDU_SESSION_AUTHENTICATION_COMMAND;
    unsigned char bitStream_eapmessage[2] = {0x01,0x02};
    bstring eapmessage_tmp = bfromcstralloc(2, "\0");
    eapmessage_tmp->slen = 2;
    memcpy(eapmessage_tmp->data,bitStream_eapmessage,sizeof(bitStream_eapmessage));
    sm_msg->specific_msg.pdu_session_authentication_command.eapmessage = eapmessage_tmp;

    sm_msg->specific_msg.pdu_session_authentication_command.presence = 0x01;

    unsigned char bitStream_extendedprotocolconfigurationoptions[4];
    bitStream_extendedprotocolconfigurationoptions[0] = 0x12;
    bitStream_extendedprotocolconfigurationoptions[1] = 0x13;
    bitStream_extendedprotocolconfigurationoptions[2] = 0x14;
    bitStream_extendedprotocolconfigurationoptions[3] = 0x15;
    bstring extendedprotocolconfigurationoptions_tmp = bfromcstralloc(4, "\0");
    //extendedprotocolconfigurationoptions_tmp->data = bitStream_extendedprotocolconfigurationoptions;
    extendedprotocolconfigurationoptions_tmp->slen = 4;
    memcpy(extendedprotocolconfigurationoptions_tmp->data,bitStream_extendedprotocolconfigurationoptions,sizeof(bitStream_extendedprotocolconfigurationoptions));
    sm_msg->specific_msg.pdu_session_authentication_command.extendedprotocolconfigurationoptions = extendedprotocolconfigurationoptions_tmp;

    /*********************sm_msg->specific_msg.pdu_session_authentication_command end******************************/

    nas_msg.plain.sm = *sm_msg;


    printf("nas header encode extended_protocol_discriminator:0x%x\n, security_header_type:0x%x\n,sequence_number:0x%x\n,message_authentication_code:0x%x\n",
        nas_msg.header.extended_protocol_discriminator,
        nas_msg.header.security_header_type,
        nas_msg.header.sequence_number,
        nas_msg.header.message_authentication_code);



    printf("sm header,extended_protocol_discriminator:0x%x,pdu_session_identity:0x%x,proeduer_transaction_identity:0x%x, message type:0x%x\n",
        sm_msg->header.extended_protocol_discriminator,
        sm_msg->header.pdu_session_identity,
        sm_msg->header.procedure_transaction_identity,
        sm_msg->header.message_type);


    printf("eapmessage buffer:0x%x 0x%x\n",(unsigned char)(sm_msg->specific_msg.pdu_session_authentication_command.eapmessage->data[0]),(unsigned char )(sm_msg->specific_msg.pdu_session_authentication_command.eapmessage->data[1]));
    printf("extend_options buffer:0x%x 0x%x 0x%x 0x%x\n",(unsigned char)((sm_msg->specific_msg.pdu_session_authentication_command.extendedprotocolconfigurationoptions)->data[0]),(unsigned char)((sm_msg->specific_msg.pdu_session_authentication_command.extendedprotocolconfigurationoptions)->data[1]),(unsigned char)((sm_msg->specific_msg.pdu_session_authentication_command.extendedprotocolconfigurationoptions)->data[2]),(unsigned char)((sm_msg->specific_msg.pdu_session_authentication_command.extendedprotocolconfigurationoptions)->data[3]));


    //bytes = nas_message_encode (data, &nas_msg, 60/*don't know the size*/, security);
    bytes = nas_message_encode (data, &nas_msg, sizeof(data)/*don't know the size*/, &securityencode);

    //nas_msg_str = reinterpret_cast<char*> (data);
    printf("Data = ");
    for(int i = 0;i<bytes;i++)
      printf("Data = %02x ",data[i]);
    printf("\n");
    std::string n1Message ((char*) data,  bytes);
    nas_msg_str = n1Message;
    Logger::smf_app().debug("n1MessageContent: %d, %s\n ", bytes, nas_msg_str.c_str());
    printf("PDU_SESSION_AUTHENTICATION_COMMAND------------ encode end\n\n");
  }
  break;

  case PDU_SESSION_AUTHENTICATION_COMPLETE:{
    printf("\n\nPDU_SESSION_AUTHENTICATION_COMPLETE------------ encode start\n");
    sm_msg->header.message_type = PDU_SESSION_AUTHENTICATION_COMPLETE;

    unsigned char bitStream_eapmessage[2] = {0x01,0x02};
    bstring eapmessage_tmp = bfromcstralloc(2, "\0");
    eapmessage_tmp->slen = 2;
    memcpy(eapmessage_tmp->data,bitStream_eapmessage,sizeof(bitStream_eapmessage));
    sm_msg->specific_msg.pdu_session_authentication_complete.eapmessage = eapmessage_tmp;

    sm_msg->specific_msg.pdu_session_authentication_complete.presence = 0x01;

    unsigned char bitStream_extendedprotocolconfigurationoptions[4];
    bitStream_extendedprotocolconfigurationoptions[0] = 0x12;
    bitStream_extendedprotocolconfigurationoptions[1] = 0x13;
    bitStream_extendedprotocolconfigurationoptions[2] = 0x14;
    bitStream_extendedprotocolconfigurationoptions[3] = 0x15;
    bstring extendedprotocolconfigurationoptions_tmp = bfromcstralloc(4, "\0");
    //extendedprotocolconfigurationoptions_tmp->data = bitStream_extendedprotocolconfigurationoptions;
    extendedprotocolconfigurationoptions_tmp->slen = 4;
    memcpy(extendedprotocolconfigurationoptions_tmp->data,bitStream_extendedprotocolconfigurationoptions,sizeof(bitStream_extendedprotocolconfigurationoptions));
    sm_msg->specific_msg.pdu_session_authentication_complete.extendedprotocolconfigurationoptions = extendedprotocolconfigurationoptions_tmp;

    /*********************sm_msg->specific_msg.pdu_session_authentication_complete end******************************/

    nas_msg.plain.sm = *sm_msg;


    printf("nas header encode extended_protocol_discriminator:0x%x\n, security_header_type:0x%x\n,sequence_number:0x%x\n,message_authentication_code:0x%x\n",
        nas_msg.header.extended_protocol_discriminator,
        nas_msg.header.security_header_type,
        nas_msg.header.sequence_number,
        nas_msg.header.message_authentication_code);



    printf("sm header,extended_protocol_discriminator:0x%x,pdu_session_identity:0x%x,proeduer_transaction_identity:0x%x, message type:0x%x\n",
        sm_msg->header.extended_protocol_discriminator,
        sm_msg->header.pdu_session_identity,
        sm_msg->header.procedure_transaction_identity,
        sm_msg->header.message_type);


    printf("eapmessage buffer:0x%x 0x%x\n",(unsigned char)(sm_msg->specific_msg.pdu_session_authentication_complete.eapmessage->data[0]),(unsigned char )(sm_msg->specific_msg.pdu_session_authentication_complete.eapmessage->data[1]));
    printf("extend_options buffer:0x%x 0x%x 0x%x 0x%x\n",(unsigned char)((sm_msg->specific_msg.pdu_session_authentication_complete.extendedprotocolconfigurationoptions)->data[0]),(unsigned char)((sm_msg->specific_msg.pdu_session_authentication_complete.extendedprotocolconfigurationoptions)->data[1]),(unsigned char)((sm_msg->specific_msg.pdu_session_authentication_complete.extendedprotocolconfigurationoptions)->data[2]),(unsigned char)((sm_msg->specific_msg.pdu_session_authentication_complete.extendedprotocolconfigurationoptions)->data[3]));

    //bytes = nas_message_encode (data, &nas_msg, 60/*don't know the size*/, security);
    bytes = nas_message_encode (data, &nas_msg, sizeof(data)/*don't know the size*/, &securityencode);

    //nas_msg_str = reinterpret_cast<char*> (data);
    printf("Data = ");
    for(int i = 0;i<bytes;i++)
      printf("Data = %02x ",data[i]);
    printf("\n");
    std::string n1Message ((char*) data,  bytes);
    nas_msg_str = n1Message;
    Logger::smf_app().debug("n1MessageContent: %d, %s\n ", bytes, nas_msg_str.c_str());
    printf("PDU_SESSION_AUTHENTICATION_COMPLETE------------ encode end\n");
  }
  break;

  case PDU_SESSION_AUTHENTICATION_RESULT:{
    printf("\n\nPDU_SESSION_AUTHENTICATION_RESULT------------ encode start\n");
    sm_msg->header.message_type = PDU_SESSION_AUTHENTICATION_RESULT;

    sm_msg->specific_msg.pdu_session_authentication_result.presence = 0x03;

    unsigned char bitStream_eapmessage[2] = {0x01,0x02};
    bstring eapmessage_tmp = bfromcstralloc(2, "\0");
    eapmessage_tmp->slen = 2;
    memcpy(eapmessage_tmp->data,bitStream_eapmessage,sizeof(bitStream_eapmessage));
    sm_msg->specific_msg.pdu_session_authentication_result.eapmessage = eapmessage_tmp;

    unsigned char bitStream_extendedprotocolconfigurationoptions[4];
    bitStream_extendedprotocolconfigurationoptions[0] = 0x12;
    bitStream_extendedprotocolconfigurationoptions[1] = 0x13;
    bitStream_extendedprotocolconfigurationoptions[2] = 0x14;
    bitStream_extendedprotocolconfigurationoptions[3] = 0x15;
    bstring extendedprotocolconfigurationoptions_tmp = bfromcstralloc(4, "\0");
    //extendedprotocolconfigurationoptions_tmp->data = bitStream_extendedprotocolconfigurationoptions;
    extendedprotocolconfigurationoptions_tmp->slen = 4;
    memcpy(extendedprotocolconfigurationoptions_tmp->data,bitStream_extendedprotocolconfigurationoptions,sizeof(bitStream_extendedprotocolconfigurationoptions));
    sm_msg->specific_msg.pdu_session_authentication_result.extendedprotocolconfigurationoptions = extendedprotocolconfigurationoptions_tmp;

    /*********************sm_msg->specific_msg.pdu_session_authentication_result end******************************/

    nas_msg.plain.sm = *sm_msg;


    printf("nas header encode extended_protocol_discriminator:0x%x\n, security_header_type:0x%x\n,sequence_number:0x%x\n,message_authentication_code:0x%x\n",
        nas_msg.header.extended_protocol_discriminator,
        nas_msg.header.security_header_type,
        nas_msg.header.sequence_number,
        nas_msg.header.message_authentication_code);



    printf("sm header,extended_protocol_discriminator:0x%x,pdu_session_identity:0x%x,proeduer_transaction_identity:0x%x, message type:0x%x\n",
        sm_msg->header.extended_protocol_discriminator,
        sm_msg->header.pdu_session_identity,
        sm_msg->header.procedure_transaction_identity,
        sm_msg->header.message_type);


    printf("eapmessage buffer:0x%x 0x%x\n",(unsigned char)(sm_msg->specific_msg.pdu_session_authentication_result.eapmessage->data[0]),(unsigned char )(sm_msg->specific_msg.pdu_session_authentication_result.eapmessage->data[1]));
    printf("extend_options buffer:0x%x 0x%x 0x%x 0x%x\n",(unsigned char)((sm_msg->specific_msg.pdu_session_authentication_result.extendedprotocolconfigurationoptions)->data[0]),(unsigned char)((sm_msg->specific_msg.pdu_session_authentication_result.extendedprotocolconfigurationoptions)->data[1]),(unsigned char)((sm_msg->specific_msg.pdu_session_authentication_result.extendedprotocolconfigurationoptions)->data[2]),(unsigned char)((sm_msg->specific_msg.pdu_session_authentication_result.extendedprotocolconfigurationoptions)->data[3]));

    //bytes = nas_message_encode (data, &nas_msg, 60/*don't know the size*/, security);
    bytes = nas_message_encode (data, &nas_msg, sizeof(data)/*don't know the size*/, &securityencode);

    //nas_msg_str = reinterpret_cast<char*> (data);
    printf("Data = ");
    for(int i = 0;i<bytes;i++)
      printf("Data = %02x ",data[i]);
    printf("\n");
    std::string n1Message ((char*) data,  bytes);
    nas_msg_str = n1Message;
    Logger::smf_app().debug("n1MessageContent: %d, %s\n ", bytes, nas_msg_str.c_str());

    printf("PDU_SESSION_AUTHENTICATION_RESULT------------ encode end\n\n");
  }
  break;

  case PDU_SESSION_MODIFICATION_REQUEST:{
    printf("\n\nPDU_SESSION_MODIFICATION_REQUEST------------ encode start\n");
    sm_msg->header.message_type = PDU_SESSION_MODIFICATION_REQUEST;

    sm_msg->specific_msg.pdu_session_modification_request.presence = 0xffff;

    sm_msg->specific_msg.pdu_session_modification_request._5gsmcapability.is_MPTCP_supported = MPTCP_FUNCTIONALITY_SUPPORTED;
    sm_msg->specific_msg.pdu_session_modification_request._5gsmcapability.is_ATSLL_supported = EATSSS_LOW_LAYER_FUNCTIONALITY_NOT_SUPPORTED;
    sm_msg->specific_msg.pdu_session_modification_request._5gsmcapability.is_EPTS1_supported = ETHERNET_PDN_TYPE_IN_S1_MODE_SUPPORTED;
    sm_msg->specific_msg.pdu_session_modification_request._5gsmcapability.is_MH6PDU_supported = MULTI_HOMED_IPV6_PDU_SESSION_SUPPORTED;
    sm_msg->specific_msg.pdu_session_modification_request._5gsmcapability.is_Rqos_supported = REFLECTIVE_QOS_NOT_SUPPORTED;

    sm_msg->specific_msg.pdu_session_modification_request._5gsmcause = 0b00001000;

    sm_msg->specific_msg.pdu_session_modification_request.maximumnumberofsupportedpacketfilters = 0x3ff;


    sm_msg->specific_msg.pdu_session_modification_request.alwaysonpdusessionrequested.apsr_requested = ALWAYSON_PDU_SESSION_REQUESTED;

    unsigned char bitStream_intergrityprotectionmaximumdatarate[2] = {0x01,0x02};
    bstring intergrityprotectionmaximumdatarate_tmp = bfromcstralloc(2, "\0");
    //intergrityprotectionmaximumdatarate_tmp->data = bitStream_intergrityprotectionmaximumdatarate;
    intergrityprotectionmaximumdatarate_tmp->slen = 2;
    memcpy(intergrityprotectionmaximumdatarate_tmp->data,bitStream_intergrityprotectionmaximumdatarate,sizeof(bitStream_intergrityprotectionmaximumdatarate));
    sm_msg->specific_msg.pdu_session_modification_request.intergrityprotectionmaximumdatarate = intergrityprotectionmaximumdatarate_tmp;


    QOSRulesIE qosrulesie[2];

    qosrulesie[0].qosruleidentifer=0x01;
    qosrulesie[0].ruleoperationcode = CREATE_NEW_QOS_RULE;
    qosrulesie[0].dqrbit = THE_QOS_RULE_IS_DEFAULT_QOS_RULE;
    qosrulesie[0].numberofpacketfilters = 3;

    Create_ModifyAndAdd_ModifyAndReplace create_modifyandadd_modifyandreplace[3];
    create_modifyandadd_modifyandreplace[0].packetfilterdirection = 0b01;
    create_modifyandadd_modifyandreplace[0].packetfilteridentifier = 1;
    /*unsigned char bitStream_packetfiltercontents00[2] = {MATCHALL_TYPE,MATCHALL_TYPE};
		bstring packetfiltercontents00_tmp = bfromcstralloc(2, "\0");
		packetfiltercontents00_tmp->slen = 2;
		memcpy(packetfiltercontents00_tmp->data,bitStream_packetfiltercontents00,sizeof(bitStream_packetfiltercontents00));
		create_modifyandadd_modifyandreplace[0].packetfiltercontents = packetfiltercontents00_tmp;*/
    create_modifyandadd_modifyandreplace[0].packetfiltercontents.component_type = QOS_RULE_MATCHALL_TYPE;
    create_modifyandadd_modifyandreplace[1].packetfilterdirection = 0b10;
    create_modifyandadd_modifyandreplace[1].packetfilteridentifier = 2;
    /*unsigned char bitStream_packetfiltercontents01[2] = {MATCHALL_TYPE,MATCHALL_TYPE};
		bstring packetfiltercontents01_tmp = bfromcstralloc(2, "\0");
		packetfiltercontents01_tmp->slen = 2;
		memcpy(packetfiltercontents01_tmp->data,bitStream_packetfiltercontents01,sizeof(bitStream_packetfiltercontents01));
		create_modifyandadd_modifyandreplace[1].packetfiltercontents = packetfiltercontents01_tmp;*/
    create_modifyandadd_modifyandreplace[1].packetfiltercontents.component_type = QOS_RULE_MATCHALL_TYPE;
    create_modifyandadd_modifyandreplace[2].packetfilterdirection = 0b11;
    create_modifyandadd_modifyandreplace[2].packetfilteridentifier = 3;
    /*unsigned char bitStream_packetfiltercontents02[2] = {MATCHALL_TYPE,MATCHALL_TYPE};
		bstring packetfiltercontents02_tmp = bfromcstralloc(2, "\0");
		packetfiltercontents02_tmp->slen = 2;
		memcpy(packetfiltercontents02_tmp->data,bitStream_packetfiltercontents02,sizeof(bitStream_packetfiltercontents02));
		create_modifyandadd_modifyandreplace[2].packetfiltercontents = packetfiltercontents02_tmp;*/
    create_modifyandadd_modifyandreplace[2].packetfiltercontents.component_type = QOS_RULE_MATCHALL_TYPE;

    qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace = create_modifyandadd_modifyandreplace;

    qosrulesie[0].qosruleprecedence = 1;
    qosrulesie[0].segregation = SEGREGATION_NOT_REQUESTED;
    qosrulesie[0].qosflowidentifer = 0x07;
    /**********************************************************************/
    qosrulesie[1].qosruleidentifer=0x02;
    qosrulesie[1].ruleoperationcode = MODIFY_EXISTING_QOS_RULE_AND_DELETE_PACKET_FILTERS;
    qosrulesie[1].dqrbit = THE_QOS_RULE_IS_NOT_THE_DEFAULT_QOS_RULE;
    qosrulesie[1].numberofpacketfilters = 3;

    ModifyAndDelete modifyanddelete[3];
    modifyanddelete[0].packetfilteridentifier = 1;
    modifyanddelete[1].packetfilteridentifier = 2;
    modifyanddelete[2].packetfilteridentifier = 3;
    qosrulesie[1].packetfilterlist.modifyanddelete = modifyanddelete;

    qosrulesie[1].qosruleprecedence = 1;
    qosrulesie[1].segregation = SEGREGATION_REQUESTED;
    qosrulesie[1].qosflowidentifer = 0x08;


    sm_msg->specific_msg.pdu_session_modification_request.qosrules.lengthofqosrulesie = 2;
    sm_msg->specific_msg.pdu_session_modification_request.qosrules.qosrulesie = qosrulesie;


    QOSFlowDescriptionsContents qosflowdescriptionscontents[3];
    qosflowdescriptionscontents[0].qfi = 1;
    qosflowdescriptionscontents[0].operationcode = CREATE_NEW_QOS_FLOW_DESCRIPTION;
    qosflowdescriptionscontents[0].e = PARAMETERS_LIST_IS_INCLUDED;
    qosflowdescriptionscontents[0].numberofparameters = 3;
    ParametersList parameterslist00[3];
    parameterslist00[0].parameteridentifier = PARAMETER_IDENTIFIER_5QI;
    parameterslist00[0].parametercontents._5qi = 0b01000001;
    parameterslist00[1].parameteridentifier = PARAMETER_IDENTIFIER_GFBR_UPLINK;
    parameterslist00[1].parametercontents.gfbrormfbr_uplinkordownlink.uint = GFBRORMFBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_1KBPS;
    parameterslist00[1].parametercontents.gfbrormfbr_uplinkordownlink.value = 0x1000;
    parameterslist00[2].parameteridentifier = PARAMETER_IDENTIFIER_GFBR_DOWNLINK;
    parameterslist00[2].parametercontents.gfbrormfbr_uplinkordownlink.uint = GFBRORMFBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_4KBPS;
    parameterslist00[2].parametercontents.gfbrormfbr_uplinkordownlink.value = 0x2000;
    qosflowdescriptionscontents[0].parameterslist = parameterslist00;

    qosflowdescriptionscontents[1].qfi = 2;
    qosflowdescriptionscontents[1].operationcode = DELETE_EXISTING_QOS_FLOW_DESCRIPTION;
    qosflowdescriptionscontents[1].e = PARAMETERS_LIST_IS_NOT_INCLUDED;
    qosflowdescriptionscontents[1].numberofparameters = 0;
    qosflowdescriptionscontents[1].parameterslist = nullptr;

    qosflowdescriptionscontents[2].qfi = 1;
    qosflowdescriptionscontents[2].operationcode = MODIFY_EXISTING_QOS_FLOW_DESCRIPTION;
    qosflowdescriptionscontents[2].e = REPLACEMENT_OF_ALL_PREVIOUSLY_PROVIDED_PARAMETERS;
    qosflowdescriptionscontents[2].numberofparameters = 4;
    ParametersList parameterslist02[4];
    parameterslist02[0].parameteridentifier = PARAMETER_IDENTIFIER_MFBR_UPLINK;
    parameterslist02[0].parametercontents.gfbrormfbr_uplinkordownlink.uint = GFBRORMFBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_16KBPS;
    parameterslist02[0].parametercontents.gfbrormfbr_uplinkordownlink.value = 0x3000;
    parameterslist02[1].parameteridentifier = PARAMETER_IDENTIFIER_MFBR_DOWNLINK;
    parameterslist02[1].parametercontents.gfbrormfbr_uplinkordownlink.uint = GFBRORMFBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_64KBPS;
    parameterslist02[1].parametercontents.gfbrormfbr_uplinkordownlink.value = 0x4000;
    parameterslist02[2].parameteridentifier = PARAMETER_IDENTIFIER_AVERAGING_WINDOW;
    parameterslist02[2].parametercontents.averagingwindow.uplinkinmilliseconds = GFBRORMFBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_256KBPS;
    parameterslist02[2].parametercontents.averagingwindow.downlinkinmilliseconds = GFBRORMFBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_1MBPS;
    parameterslist02[3].parameteridentifier = PARAMETER_IDENTIFIER_EPS_BEARER_IDENTITY;
    parameterslist02[3].parametercontents.epsbeareridentity = QOS_FLOW_EPS_BEARER_IDENTITY_VALUE15;
    qosflowdescriptionscontents[2].parameterslist = parameterslist02;

    sm_msg->specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionsnumber = 3;
    sm_msg->specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents = qosflowdescriptionscontents;

    unsigned char bitStream_extendedprotocolconfigurationoptions[4];
    bitStream_extendedprotocolconfigurationoptions[0] = 0x12;
    bitStream_extendedprotocolconfigurationoptions[1] = 0x13;
    bitStream_extendedprotocolconfigurationoptions[2] = 0x14;
    bitStream_extendedprotocolconfigurationoptions[3] = 0x15;
    bstring extendedprotocolconfigurationoptions_tmp = bfromcstralloc(4, "\0");
    //extendedprotocolconfigurationoptions_tmp->data = bitStream_extendedprotocolconfigurationoptions;
    extendedprotocolconfigurationoptions_tmp->slen = 4;
    memcpy(extendedprotocolconfigurationoptions_tmp->data,bitStream_extendedprotocolconfigurationoptions,sizeof(bitStream_extendedprotocolconfigurationoptions));
    sm_msg->specific_msg.pdu_session_modification_request.extendedprotocolconfigurationoptions = extendedprotocolconfigurationoptions_tmp;

    /*********************sm_msg->specific_msg.pdu_session_modification_request end******************************/

    nas_msg.plain.sm = *sm_msg;

    printf("nas header encode extended_protocol_discriminator:0x%x\n, security_header_type:0x%x\n,sequence_number:0x%x\n,message_authentication_code:0x%x\n",
        nas_msg.header.extended_protocol_discriminator,
        nas_msg.header.security_header_type,
        nas_msg.header.sequence_number,
        nas_msg.header.message_authentication_code);



    printf("sm header,extended_protocol_discriminator:0x%x,pdu_session_identity:0x%x,proeduer_transaction_identity:0x%x, message type:0x%x\n",
        sm_msg->header.extended_protocol_discriminator,
        sm_msg->header.pdu_session_identity,
        sm_msg->header.procedure_transaction_identity,
        sm_msg->header.message_type);

    //printf("message type:0x%x\n",sm_msg->specific_msg.pdu_session_establishment_request.messagetype);
    //printf("extendedprotocoldiscriminator:0x%x\n",sm_msg->specific_msg.pdu_session_establishment_request.extendedprotocoldiscriminator);
    //printf("pdu identity buffer:0x%x\n",*(unsigned char *)((sm_msg->specific_msg.pdu_session_establishment_request.pdusessionidentity)->data));
    //printf("PTI buffer:0x%x\n",*(unsigned char *)((sm_msg->specific_msg.pdu_session_establishment_request.proceduretransactionidentity)->data));


    printf("_5gsmcapability bits_5 --- MPTCP:0x%x ATS-LL:0x%x EPT-S1:0x%x MH6-PDU:0x%x RqoS:0x%x\n",
        sm_msg->specific_msg.pdu_session_modification_request._5gsmcapability.is_MPTCP_supported,
        sm_msg->specific_msg.pdu_session_modification_request._5gsmcapability.is_ATSLL_supported,
        sm_msg->specific_msg.pdu_session_modification_request._5gsmcapability.is_EPTS1_supported,
        sm_msg->specific_msg.pdu_session_modification_request._5gsmcapability.is_MH6PDU_supported,
        sm_msg->specific_msg.pdu_session_modification_request._5gsmcapability.is_Rqos_supported);

    printf("_5gsmcause: %#0x\n",sm_msg->specific_msg.pdu_session_modification_request._5gsmcause);

    printf("maximum bits_11:0x%x\n",sm_msg->specific_msg.pdu_session_modification_request.maximumnumberofsupportedpacketfilters);

    printf("Always-on bits_1 --- APSR:0x%x\n",sm_msg->specific_msg.pdu_session_modification_request.alwaysonpdusessionrequested.apsr_requested);

    printf("intergrity buffer:0x%x 0x%x\n",
        (unsigned char)(sm_msg->specific_msg.pdu_session_modification_request.intergrityprotectionmaximumdatarate->data[0]),
        (unsigned char)(sm_msg->specific_msg.pdu_session_modification_request.intergrityprotectionmaximumdatarate->data[1]));

    printf("qosrules: %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x\n",
        sm_msg->specific_msg.pdu_session_modification_request.qosrules.lengthofqosrulesie,
        sm_msg->specific_msg.pdu_session_modification_request.qosrules.qosrulesie[0].qosruleidentifer,
        sm_msg->specific_msg.pdu_session_modification_request.qosrules.qosrulesie[0].ruleoperationcode,
        sm_msg->specific_msg.pdu_session_modification_request.qosrules.qosrulesie[0].dqrbit,
        sm_msg->specific_msg.pdu_session_modification_request.qosrules.qosrulesie[0].numberofpacketfilters,
        sm_msg->specific_msg.pdu_session_modification_request.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[0].packetfilterdirection,
        sm_msg->specific_msg.pdu_session_modification_request.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[0].packetfilteridentifier,
        sm_msg->specific_msg.pdu_session_modification_request.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[0].packetfiltercontents.component_type,
        sm_msg->specific_msg.pdu_session_modification_request.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[1].packetfilterdirection,
        sm_msg->specific_msg.pdu_session_modification_request.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[1].packetfilteridentifier,
        sm_msg->specific_msg.pdu_session_modification_request.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[1].packetfiltercontents.component_type,
        sm_msg->specific_msg.pdu_session_modification_request.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[2].packetfilterdirection,
        sm_msg->specific_msg.pdu_session_modification_request.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[2].packetfilteridentifier,
        sm_msg->specific_msg.pdu_session_modification_request.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[2].packetfiltercontents.component_type,
        sm_msg->specific_msg.pdu_session_modification_request.qosrules.qosrulesie[0].qosruleprecedence,
        sm_msg->specific_msg.pdu_session_modification_request.qosrules.qosrulesie[0].segregation,
        sm_msg->specific_msg.pdu_session_modification_request.qosrules.qosrulesie[0].qosflowidentifer,
        sm_msg->specific_msg.pdu_session_modification_request.qosrules.qosrulesie[1].qosruleidentifer,
        sm_msg->specific_msg.pdu_session_modification_request.qosrules.qosrulesie[1].ruleoperationcode,
        sm_msg->specific_msg.pdu_session_modification_request.qosrules.qosrulesie[1].dqrbit,
        sm_msg->specific_msg.pdu_session_modification_request.qosrules.qosrulesie[1].numberofpacketfilters,
        sm_msg->specific_msg.pdu_session_modification_request.qosrules.qosrulesie[1].packetfilterlist.modifyanddelete[0].packetfilteridentifier,
        sm_msg->specific_msg.pdu_session_modification_request.qosrules.qosrulesie[1].packetfilterlist.modifyanddelete[1].packetfilteridentifier,
        sm_msg->specific_msg.pdu_session_modification_request.qosrules.qosrulesie[1].packetfilterlist.modifyanddelete[2].packetfilteridentifier,
        sm_msg->specific_msg.pdu_session_modification_request.qosrules.qosrulesie[1].qosruleprecedence,
        sm_msg->specific_msg.pdu_session_modification_request.qosrules.qosrulesie[1].segregation,
        sm_msg->specific_msg.pdu_session_modification_request.qosrules.qosrulesie[1].qosflowidentifer);

    printf("qosflowdescriptions: %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x\n",
        sm_msg->specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionsnumber,
        sm_msg->specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[0].qfi,
        sm_msg->specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[0].operationcode,
        sm_msg->specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[0].e,
        sm_msg->specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[0].numberofparameters,
        sm_msg->specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[0].parameteridentifier,
        sm_msg->specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[0].parametercontents._5qi,
        sm_msg->specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[1].parameteridentifier,
        sm_msg->specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[1].parametercontents.gfbrormfbr_uplinkordownlink.uint,
        sm_msg->specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[1].parametercontents.gfbrormfbr_uplinkordownlink.value,
        sm_msg->specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[2].parameteridentifier,
        sm_msg->specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[2].parametercontents.gfbrormfbr_uplinkordownlink.uint,
        sm_msg->specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[2].parametercontents.gfbrormfbr_uplinkordownlink.value,
        sm_msg->specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[1].qfi,
        sm_msg->specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[1].operationcode,
        sm_msg->specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[1].e,
        sm_msg->specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[1].numberofparameters,
        sm_msg->specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[2].qfi,
        sm_msg->specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[2].operationcode,
        sm_msg->specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[2].e,
        sm_msg->specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[2].numberofparameters,
        sm_msg->specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[0].parameteridentifier,
        sm_msg->specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[0].parametercontents.gfbrormfbr_uplinkordownlink.uint,
        sm_msg->specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[0].parametercontents.gfbrormfbr_uplinkordownlink.value,
        sm_msg->specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[1].parameteridentifier,
        sm_msg->specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[1].parametercontents.gfbrormfbr_uplinkordownlink.uint,
        sm_msg->specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[1].parametercontents.gfbrormfbr_uplinkordownlink.value,
        sm_msg->specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[2].parameteridentifier,
        sm_msg->specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[2].parametercontents.averagingwindow.uplinkinmilliseconds,
        sm_msg->specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[2].parametercontents.averagingwindow.downlinkinmilliseconds,
        sm_msg->specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[3].parameteridentifier,
        sm_msg->specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[3].parametercontents.epsbeareridentity);

    //printf("mappedepsbearercontexts");

    printf("extend_options buffer:%x %x %x %x\n",
        (unsigned char)(sm_msg->specific_msg.pdu_session_modification_request.extendedprotocolconfigurationoptions->data[0]),
        (unsigned char)(sm_msg->specific_msg.pdu_session_modification_request.extendedprotocolconfigurationoptions->data[1]),
        (unsigned char)(sm_msg->specific_msg.pdu_session_modification_request.extendedprotocolconfigurationoptions->data[2]),
        (unsigned char)(sm_msg->specific_msg.pdu_session_modification_request.extendedprotocolconfigurationoptions->data[3]));

    //bytes = nas_message_encode (data, &nas_msg, 60/*don't know the size*/, security);
    bytes = nas_message_encode (data, &nas_msg, sizeof(data)/*don't know the size*/, &securityencode);

    //nas_msg_str = reinterpret_cast<char*> (data);
    printf("Data = ");
    for(int i = 0;i<bytes;i++)
      printf("Data = %02x ",data[i]);
    printf("\n");
    std::string n1Message ((char*) data,  bytes);
    nas_msg_str = n1Message;
    Logger::smf_app().debug("n1MessageContent: %d, %s\n ", bytes, nas_msg_str.c_str());
    printf("PDU_SESSION_MODIFICATION_REQUEST------------ encode end\n\n");
  }
  break;

  case PDU_SESSION_MODIFICATION_REJECT:{
    printf("\n\nPDU_SESSION_MODIFICATION_REJECT------------ encode start\n");
    sm_msg->header.message_type = PDU_SESSION_MODIFICATION_REJECT;

    sm_msg->specific_msg.pdu_session_modification_reject._5gsmcause = 0b00001000;

    sm_msg->specific_msg.pdu_session_modification_reject.presence = 0x07;

    sm_msg->specific_msg.pdu_session_modification_reject.gprstimer3.unit = GPRSTIMER3_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_1_HOUR;
    sm_msg->specific_msg.pdu_session_modification_reject.gprstimer3.timeValue = 0;

    unsigned char bitStream_extendedprotocolconfigurationoptions[4];
    bitStream_extendedprotocolconfigurationoptions[0] = 0x12;
    bitStream_extendedprotocolconfigurationoptions[1] = 0x13;
    bitStream_extendedprotocolconfigurationoptions[2] = 0x14;
    bitStream_extendedprotocolconfigurationoptions[3] = 0x15;
    bstring extendedprotocolconfigurationoptions_tmp = bfromcstralloc(4, "\0");
    //extendedprotocolconfigurationoptions_tmp->data = bitStream_extendedprotocolconfigurationoptions;
    extendedprotocolconfigurationoptions_tmp->slen = 4;
    memcpy(extendedprotocolconfigurationoptions_tmp->data,bitStream_extendedprotocolconfigurationoptions,sizeof(bitStream_extendedprotocolconfigurationoptions));
    sm_msg->specific_msg.pdu_session_modification_reject.extendedprotocolconfigurationoptions = extendedprotocolconfigurationoptions_tmp;

    sm_msg->specific_msg.pdu_session_modification_reject._5gsmcongestionreattemptindicator.abo = THE_BACKOFF_TIMER_IS_APPLIED_IN_ALL_PLMNS;

    /*********************sm_msg->specific_msg.pdu_session_modification_reject end******************************/

    nas_msg.plain.sm = *sm_msg;


    printf("nas header encode extended_protocol_discriminator:0x%x\n, security_header_type:0x%x\n,sequence_number:0x%x\n,message_authentication_code:0x%x\n",
        nas_msg.header.extended_protocol_discriminator,
        nas_msg.header.security_header_type,
        nas_msg.header.sequence_number,
        nas_msg.header.message_authentication_code);



    printf("sm header,extended_protocol_discriminator:0x%x,pdu_session_identity:0x%x,proeduer_transaction_identity:0x%x, message type:0x%x\n",
        sm_msg->header.extended_protocol_discriminator,
        sm_msg->header.pdu_session_identity,
        sm_msg->header.procedure_transaction_identity,
        sm_msg->header.message_type);


    printf("_5gsmcause: 0x%x\n",sm_msg->specific_msg.pdu_session_modification_reject._5gsmcause);
    printf("gprstimer3 --- unit_bits_H3: 0x%x,timeValue_bits_L5: 0x%x\n",sm_msg->specific_msg.pdu_session_modification_reject.gprstimer3.unit,sm_msg->specific_msg.pdu_session_modification_reject.gprstimer3.timeValue);
    printf("extend_options buffer:0x%x 0x%x 0x%x 0x%x\n",(unsigned char)((sm_msg->specific_msg.pdu_session_modification_reject.extendedprotocolconfigurationoptions)->data[0]),(unsigned char)((sm_msg->specific_msg.pdu_session_modification_reject.extendedprotocolconfigurationoptions)->data[1]),(unsigned char)((sm_msg->specific_msg.pdu_session_modification_reject.extendedprotocolconfigurationoptions)->data[2]),(unsigned char)((sm_msg->specific_msg.pdu_session_modification_reject.extendedprotocolconfigurationoptions)->data[3]));
    printf("_5gsmcongestionreattemptindicator bits_1 --- abo:0x%x\n",sm_msg->specific_msg.pdu_session_modification_reject._5gsmcongestionreattemptindicator.abo);

    //bytes = nas_message_encode (data, &nas_msg, 60/*don't know the size*/, security);
    bytes = nas_message_encode (data, &nas_msg, sizeof(data)/*don't know the size*/, &securityencode);

    //nas_msg_str = reinterpret_cast<char*> (data);
    printf("Data = ");
    for(int i = 0;i<bytes;i++)
      printf("Data = %02x ",data[i]);
    printf("\n");
    std::string n1Message ((char*) data,  bytes);
    nas_msg_str = n1Message;
    Logger::smf_app().debug("n1MessageContent: %d, %s\n ", bytes, nas_msg_str.c_str());
    printf("PDU_SESSION_MODIFICATION_REJECT------------ encode end\n\n");
  }
  break;

  case PDU_SESSION_MODIFICATION_COMMAND:{
    printf("\n\nPDU_SESSION_MODIFICATION_COMMAND------------ encode start\n");
    sm_msg->header.message_type = PDU_SESSION_MODIFICATION_COMMAND;

    sm_msg->specific_msg.pdu_session_modification_command.presence = 0xff;

    sm_msg->specific_msg.pdu_session_modification_command._5gsmcause = 0b00001000;

    sm_msg->specific_msg.pdu_session_modification_command.sessionambr.uint_for_session_ambr_for_downlink = AMBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_1KBPS;
    sm_msg->specific_msg.pdu_session_modification_command.sessionambr.session_ambr_for_downlink = (AMBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_4KBPS << 8) + (AMBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_16KBPS);
    sm_msg->specific_msg.pdu_session_modification_command.sessionambr.uint_for_session_ambr_for_uplink = AMBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_64KBPS;
    sm_msg->specific_msg.pdu_session_modification_command.sessionambr.session_ambr_for_uplink = (AMBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_256KBPS << 8) + (AMBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_1MBPS);

    sm_msg->specific_msg.pdu_session_modification_command.gprstimer.unit = GPRSTIMER_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_2_SECONDS;
    sm_msg->specific_msg.pdu_session_modification_command.gprstimer.timeValue = 0;

    sm_msg->specific_msg.pdu_session_modification_command.alwaysonpdusessionindication.apsi_indication = ALWAYSON_PDU_SESSION_REQUIRED;

    QOSRulesIE qosrulesie[2];

    qosrulesie[0].qosruleidentifer=0x01;
    qosrulesie[0].ruleoperationcode = CREATE_NEW_QOS_RULE;
    qosrulesie[0].dqrbit = THE_QOS_RULE_IS_DEFAULT_QOS_RULE;
    qosrulesie[0].numberofpacketfilters = 3;

    Create_ModifyAndAdd_ModifyAndReplace create_modifyandadd_modifyandreplace[3];
    create_modifyandadd_modifyandreplace[0].packetfilterdirection = 0b01;
    create_modifyandadd_modifyandreplace[0].packetfilteridentifier = 1;
    /*unsigned char bitStream_packetfiltercontents00[2] = {MATCHALL_TYPE,MATCHALL_TYPE};
		bstring packetfiltercontents00_tmp = bfromcstralloc(2, "\0");
		packetfiltercontents00_tmp->slen = 2;
		memcpy(packetfiltercontents00_tmp->data,bitStream_packetfiltercontents00,sizeof(bitStream_packetfiltercontents00));
		create_modifyandadd_modifyandreplace[0].packetfiltercontents = packetfiltercontents00_tmp;*/
    create_modifyandadd_modifyandreplace[0].packetfiltercontents.component_type = QOS_RULE_MATCHALL_TYPE;
    create_modifyandadd_modifyandreplace[1].packetfilterdirection = 0b10;
    create_modifyandadd_modifyandreplace[1].packetfilteridentifier = 2;
    /*unsigned char bitStream_packetfiltercontents01[2] = {MATCHALL_TYPE,MATCHALL_TYPE};
		bstring packetfiltercontents01_tmp = bfromcstralloc(2, "\0");
		packetfiltercontents01_tmp->slen = 2;
		memcpy(packetfiltercontents01_tmp->data,bitStream_packetfiltercontents01,sizeof(bitStream_packetfiltercontents01));
		create_modifyandadd_modifyandreplace[1].packetfiltercontents = packetfiltercontents01_tmp;*/
    create_modifyandadd_modifyandreplace[1].packetfiltercontents.component_type = QOS_RULE_MATCHALL_TYPE;
    create_modifyandadd_modifyandreplace[2].packetfilterdirection = 0b11;
    create_modifyandadd_modifyandreplace[2].packetfilteridentifier = 3;
    /*unsigned char bitStream_packetfiltercontents02[2] = {MATCHALL_TYPE,MATCHALL_TYPE};
		bstring packetfiltercontents02_tmp = bfromcstralloc(2, "\0");
		packetfiltercontents02_tmp->slen = 2;
		memcpy(packetfiltercontents02_tmp->data,bitStream_packetfiltercontents02,sizeof(bitStream_packetfiltercontents02));
		create_modifyandadd_modifyandreplace[2].packetfiltercontents = packetfiltercontents02_tmp;*/
    create_modifyandadd_modifyandreplace[2].packetfiltercontents.component_type = QOS_RULE_MATCHALL_TYPE;

    qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace = create_modifyandadd_modifyandreplace;

    qosrulesie[0].qosruleprecedence = 1;
    qosrulesie[0].segregation = SEGREGATION_NOT_REQUESTED;
    qosrulesie[0].qosflowidentifer = 0x07;
    /**********************************************************************/
    qosrulesie[1].qosruleidentifer=0x02;
    qosrulesie[1].ruleoperationcode = MODIFY_EXISTING_QOS_RULE_AND_DELETE_PACKET_FILTERS;
    qosrulesie[1].dqrbit = THE_QOS_RULE_IS_NOT_THE_DEFAULT_QOS_RULE;
    qosrulesie[1].numberofpacketfilters = 3;

    ModifyAndDelete modifyanddelete[3];
    modifyanddelete[0].packetfilteridentifier = 1;
    modifyanddelete[1].packetfilteridentifier = 2;
    modifyanddelete[2].packetfilteridentifier = 3;
    qosrulesie[1].packetfilterlist.modifyanddelete = modifyanddelete;

    qosrulesie[1].qosruleprecedence = 1;
    qosrulesie[1].segregation = SEGREGATION_REQUESTED;
    qosrulesie[1].qosflowidentifer = 0x08;


    sm_msg->specific_msg.pdu_session_modification_command.qosrules.lengthofqosrulesie = 2;
    sm_msg->specific_msg.pdu_session_modification_command.qosrules.qosrulesie = qosrulesie;


    QOSFlowDescriptionsContents qosflowdescriptionscontents[3];
    qosflowdescriptionscontents[0].qfi = 1;
    qosflowdescriptionscontents[0].operationcode = CREATE_NEW_QOS_FLOW_DESCRIPTION;
    qosflowdescriptionscontents[0].e = PARAMETERS_LIST_IS_INCLUDED;
    qosflowdescriptionscontents[0].numberofparameters = 3;
    ParametersList parameterslist00[3];
    parameterslist00[0].parameteridentifier = PARAMETER_IDENTIFIER_5QI;
    parameterslist00[0].parametercontents._5qi = 0b01000001;
    parameterslist00[1].parameteridentifier = PARAMETER_IDENTIFIER_GFBR_UPLINK;
    parameterslist00[1].parametercontents.gfbrormfbr_uplinkordownlink.uint = GFBRORMFBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_1KBPS;
    parameterslist00[1].parametercontents.gfbrormfbr_uplinkordownlink.value = 0x1000;
    parameterslist00[2].parameteridentifier = PARAMETER_IDENTIFIER_GFBR_DOWNLINK;
    parameterslist00[2].parametercontents.gfbrormfbr_uplinkordownlink.uint = GFBRORMFBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_4KBPS;
    parameterslist00[2].parametercontents.gfbrormfbr_uplinkordownlink.value = 0x2000;
    qosflowdescriptionscontents[0].parameterslist = parameterslist00;

    qosflowdescriptionscontents[1].qfi = 2;
    qosflowdescriptionscontents[1].operationcode = DELETE_EXISTING_QOS_FLOW_DESCRIPTION;
    qosflowdescriptionscontents[1].e = PARAMETERS_LIST_IS_NOT_INCLUDED;
    qosflowdescriptionscontents[1].numberofparameters = 0;
    qosflowdescriptionscontents[1].parameterslist = nullptr;

    qosflowdescriptionscontents[2].qfi = 1;
    qosflowdescriptionscontents[2].operationcode = MODIFY_EXISTING_QOS_FLOW_DESCRIPTION;
    qosflowdescriptionscontents[2].e = REPLACEMENT_OF_ALL_PREVIOUSLY_PROVIDED_PARAMETERS;
    qosflowdescriptionscontents[2].numberofparameters = 4;
    ParametersList parameterslist02[4];
    parameterslist02[0].parameteridentifier = PARAMETER_IDENTIFIER_MFBR_UPLINK;
    parameterslist02[0].parametercontents.gfbrormfbr_uplinkordownlink.uint = GFBRORMFBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_16KBPS;
    parameterslist02[0].parametercontents.gfbrormfbr_uplinkordownlink.value = 0x3000;
    parameterslist02[1].parameteridentifier = PARAMETER_IDENTIFIER_MFBR_DOWNLINK;
    parameterslist02[1].parametercontents.gfbrormfbr_uplinkordownlink.uint = GFBRORMFBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_64KBPS;
    parameterslist02[1].parametercontents.gfbrormfbr_uplinkordownlink.value = 0x4000;
    parameterslist02[2].parameteridentifier = PARAMETER_IDENTIFIER_AVERAGING_WINDOW;
    parameterslist02[2].parametercontents.averagingwindow.uplinkinmilliseconds = GFBRORMFBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_256KBPS;
    parameterslist02[2].parametercontents.averagingwindow.downlinkinmilliseconds = GFBRORMFBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_1MBPS;
    parameterslist02[3].parameteridentifier = PARAMETER_IDENTIFIER_EPS_BEARER_IDENTITY;
    parameterslist02[3].parametercontents.epsbeareridentity = QOS_FLOW_EPS_BEARER_IDENTITY_VALUE15;
    qosflowdescriptionscontents[2].parameterslist = parameterslist02;

    sm_msg->specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionsnumber = 3;
    sm_msg->specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents = qosflowdescriptionscontents;

    unsigned char bitStream_extendedprotocolconfigurationoptions[4];
    bitStream_extendedprotocolconfigurationoptions[0] = 0x12;
    bitStream_extendedprotocolconfigurationoptions[1] = 0x13;
    bitStream_extendedprotocolconfigurationoptions[2] = 0x14;
    bitStream_extendedprotocolconfigurationoptions[3] = 0x15;
    bstring extendedprotocolconfigurationoptions_tmp = bfromcstralloc(4, "\0");
    //extendedprotocolconfigurationoptions_tmp->data = bitStream_extendedprotocolconfigurationoptions;
    extendedprotocolconfigurationoptions_tmp->slen = 4;
    memcpy(extendedprotocolconfigurationoptions_tmp->data,bitStream_extendedprotocolconfigurationoptions,sizeof(bitStream_extendedprotocolconfigurationoptions));
    sm_msg->specific_msg.pdu_session_modification_command.extendedprotocolconfigurationoptions = extendedprotocolconfigurationoptions_tmp;

    /*********************sm_msg->specific_msg.pdu_session_modification_command end******************************/


    nas_msg.plain.sm = *sm_msg;


    printf("nas header encode extended_protocol_discriminator:0x%x\n, security_header_type:0x%x\n,sequence_number:0x%x\n,message_authentication_code:0x%x\n",
        nas_msg.header.extended_protocol_discriminator,
        nas_msg.header.security_header_type,
        nas_msg.header.sequence_number,
        nas_msg.header.message_authentication_code);



    printf("sm header,extended_protocol_discriminator:0x%x,pdu_session_identity:0x%x,proeduer_transaction_identity:0x%x, message type:0x%x\n",
        sm_msg->header.extended_protocol_discriminator,
        sm_msg->header.pdu_session_identity,
        sm_msg->header.procedure_transaction_identity,
        sm_msg->header.message_type);

    //printf("message type:0x%x\n",sm_msg->specific_msg.pdu_session_modification_command.messagetype);
    //printf("extendedprotocoldiscriminator:0x%x\n",sm_msg->specific_msg.pdu_session_modification_command.extendedprotocoldiscriminator);
    //printf("pdu identity buffer:0x%x\n",*(unsigned char *)((sm_msg->specific_msg.pdu_session_modification_command.pdusessionidentity)->data));
    //printf("PTI buffer:0x%x\n",*(unsigned char *)((sm_msg->specific_msg.pdu_session_modification_command.proceduretransactionidentity)->data));


    printf("_5gsmcause: %#0x\n",sm_msg->specific_msg.pdu_session_modification_command._5gsmcause);

    printf("sessionambr: %x %x %x %x\n",
        sm_msg->specific_msg.pdu_session_modification_command.sessionambr.uint_for_session_ambr_for_downlink,
        sm_msg->specific_msg.pdu_session_modification_command.sessionambr.session_ambr_for_downlink,
        sm_msg->specific_msg.pdu_session_modification_command.sessionambr.uint_for_session_ambr_for_uplink,
        sm_msg->specific_msg.pdu_session_modification_command.sessionambr.session_ambr_for_uplink);

    printf("gprstimer -- unit: %#0x, timeValue: %#0x\n",
        sm_msg->specific_msg.pdu_session_modification_command.gprstimer.unit,
        sm_msg->specific_msg.pdu_session_modification_command.gprstimer.timeValue);

    printf("alwaysonpdusessionindication: %#0x\n",sm_msg->specific_msg.pdu_session_modification_command.alwaysonpdusessionindication.apsi_indication);

    printf("qosrules: %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x\n",
        sm_msg->specific_msg.pdu_session_modification_command.qosrules.lengthofqosrulesie,
        sm_msg->specific_msg.pdu_session_modification_command.qosrules.qosrulesie[0].qosruleidentifer,
        sm_msg->specific_msg.pdu_session_modification_command.qosrules.qosrulesie[0].ruleoperationcode,
        sm_msg->specific_msg.pdu_session_modification_command.qosrules.qosrulesie[0].dqrbit,
        sm_msg->specific_msg.pdu_session_modification_command.qosrules.qosrulesie[0].numberofpacketfilters,
        sm_msg->specific_msg.pdu_session_modification_command.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[0].packetfilterdirection,
        sm_msg->specific_msg.pdu_session_modification_command.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[0].packetfilteridentifier,
        sm_msg->specific_msg.pdu_session_modification_command.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[0].packetfiltercontents.component_type,
        sm_msg->specific_msg.pdu_session_modification_command.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[1].packetfilterdirection,
        sm_msg->specific_msg.pdu_session_modification_command.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[1].packetfilteridentifier,
        sm_msg->specific_msg.pdu_session_modification_command.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[1].packetfiltercontents.component_type,
        sm_msg->specific_msg.pdu_session_modification_command.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[2].packetfilterdirection,
        sm_msg->specific_msg.pdu_session_modification_command.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[2].packetfilteridentifier,
        sm_msg->specific_msg.pdu_session_modification_command.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[2].packetfiltercontents.component_type,
        sm_msg->specific_msg.pdu_session_modification_command.qosrules.qosrulesie[0].qosruleprecedence,
        sm_msg->specific_msg.pdu_session_modification_command.qosrules.qosrulesie[0].segregation,
        sm_msg->specific_msg.pdu_session_modification_command.qosrules.qosrulesie[0].qosflowidentifer,
        sm_msg->specific_msg.pdu_session_modification_command.qosrules.qosrulesie[1].qosruleidentifer,
        sm_msg->specific_msg.pdu_session_modification_command.qosrules.qosrulesie[1].ruleoperationcode,
        sm_msg->specific_msg.pdu_session_modification_command.qosrules.qosrulesie[1].dqrbit,
        sm_msg->specific_msg.pdu_session_modification_command.qosrules.qosrulesie[1].numberofpacketfilters,
        sm_msg->specific_msg.pdu_session_modification_command.qosrules.qosrulesie[1].packetfilterlist.modifyanddelete[0].packetfilteridentifier,
        sm_msg->specific_msg.pdu_session_modification_command.qosrules.qosrulesie[1].packetfilterlist.modifyanddelete[1].packetfilteridentifier,
        sm_msg->specific_msg.pdu_session_modification_command.qosrules.qosrulesie[1].packetfilterlist.modifyanddelete[2].packetfilteridentifier,
        sm_msg->specific_msg.pdu_session_modification_command.qosrules.qosrulesie[1].qosruleprecedence,
        sm_msg->specific_msg.pdu_session_modification_command.qosrules.qosrulesie[1].segregation,
        sm_msg->specific_msg.pdu_session_modification_command.qosrules.qosrulesie[1].qosflowidentifer);

    //printf("mappedepsbearercontexts");

    printf("qosflowdescriptions: %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x\n",
        sm_msg->specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionsnumber,
        sm_msg->specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[0].qfi,
        sm_msg->specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[0].operationcode,
        sm_msg->specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[0].e,
        sm_msg->specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[0].numberofparameters,
        sm_msg->specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[0].parameteridentifier,
        sm_msg->specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[0].parametercontents._5qi,
        sm_msg->specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[1].parameteridentifier,
        sm_msg->specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[1].parametercontents.gfbrormfbr_uplinkordownlink.uint,
        sm_msg->specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[1].parametercontents.gfbrormfbr_uplinkordownlink.value,
        sm_msg->specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[2].parameteridentifier,
        sm_msg->specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[2].parametercontents.gfbrormfbr_uplinkordownlink.uint,
        sm_msg->specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[2].parametercontents.gfbrormfbr_uplinkordownlink.value,
        sm_msg->specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[1].qfi,
        sm_msg->specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[1].operationcode,
        sm_msg->specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[1].e,
        sm_msg->specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[1].numberofparameters,
        sm_msg->specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[2].qfi,
        sm_msg->specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[2].operationcode,
        sm_msg->specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[2].e,
        sm_msg->specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[2].numberofparameters,
        sm_msg->specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[0].parameteridentifier,
        sm_msg->specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[0].parametercontents.gfbrormfbr_uplinkordownlink.uint,
        sm_msg->specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[0].parametercontents.gfbrormfbr_uplinkordownlink.value,
        sm_msg->specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[1].parameteridentifier,
        sm_msg->specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[1].parametercontents.gfbrormfbr_uplinkordownlink.uint,
        sm_msg->specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[1].parametercontents.gfbrormfbr_uplinkordownlink.value,
        sm_msg->specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[2].parameteridentifier,
        sm_msg->specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[2].parametercontents.averagingwindow.uplinkinmilliseconds,
        sm_msg->specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[2].parametercontents.averagingwindow.downlinkinmilliseconds,
        sm_msg->specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[3].parameteridentifier,
        sm_msg->specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[3].parametercontents.epsbeareridentity);

    printf("extend_options buffer:%x %x %x %x\n",
        (unsigned char)(sm_msg->specific_msg.pdu_session_modification_command.extendedprotocolconfigurationoptions->data[0]),
        (unsigned char)(sm_msg->specific_msg.pdu_session_modification_command.extendedprotocolconfigurationoptions->data[1]),
        (unsigned char)(sm_msg->specific_msg.pdu_session_modification_command.extendedprotocolconfigurationoptions->data[2]),
        (unsigned char)(sm_msg->specific_msg.pdu_session_modification_command.extendedprotocolconfigurationoptions->data[3]));

    //bytes = nas_message_encode (data, &nas_msg, 60/*don't know the size*/, security);
    bytes = nas_message_encode (data, &nas_msg, sizeof(data)/*don't know the size*/, &securityencode);

    //nas_msg_str = reinterpret_cast<char*> (data);
    printf("Data = ");
    for(int i = 0;i<bytes;i++)
      printf("Data = %02x ",data[i]);
    printf("\n");
    std::string n1Message ((char*) data,  bytes);
    nas_msg_str = n1Message;
    Logger::smf_app().debug("n1MessageContent: %d, %s\n ", bytes, nas_msg_str.c_str());
    printf("PDU_SESSION_MODIFICATION_COMMAND------------ encode end\n\n");
  }
  break;

  case PDU_SESSION_MODIFICATION_COMPLETE:{
    printf("\n\nPDU_SESSION_MODIFICATION_COMPLETE------------ encode start\n");
    sm_msg->header.message_type = PDU_SESSION_MODIFICATION_COMPLETE;

    sm_msg->specific_msg.pdu_session_modification_complete.presence = 0x01;

    unsigned char bitStream_extendedprotocolconfigurationoptions[4];
    bitStream_extendedprotocolconfigurationoptions[0] = 0x12;
    bitStream_extendedprotocolconfigurationoptions[1] = 0x13;
    bitStream_extendedprotocolconfigurationoptions[2] = 0x14;
    bitStream_extendedprotocolconfigurationoptions[3] = 0x15;
    bstring extendedprotocolconfigurationoptions_tmp = bfromcstralloc(4, "\0");
    //extendedprotocolconfigurationoptions_tmp->data = bitStream_extendedprotocolconfigurationoptions;
    extendedprotocolconfigurationoptions_tmp->slen = 4;
    memcpy(extendedprotocolconfigurationoptions_tmp->data,bitStream_extendedprotocolconfigurationoptions,sizeof(bitStream_extendedprotocolconfigurationoptions));
    sm_msg->specific_msg.pdu_session_modification_complete.extendedprotocolconfigurationoptions = extendedprotocolconfigurationoptions_tmp;


    /*********************sm_msg->specific_msg.pdu_session_modification_complete end******************************/

    nas_msg.plain.sm = *sm_msg;


    printf("nas header encode extended_protocol_discriminator:0x%x\n, security_header_type:0x%x\n,sequence_number:0x%x\n,message_authentication_code:0x%x\n",
        nas_msg.header.extended_protocol_discriminator,
        nas_msg.header.security_header_type,
        nas_msg.header.sequence_number,
        nas_msg.header.message_authentication_code);



    printf("sm header,extended_protocol_discriminator:0x%x,pdu_session_identity:0x%x,proeduer_transaction_identity:0x%x, message type:0x%x\n",
        sm_msg->header.extended_protocol_discriminator,
        sm_msg->header.pdu_session_identity,
        sm_msg->header.procedure_transaction_identity,
        sm_msg->header.message_type);


    printf("extend_options buffer:0x%x 0x%x 0x%x 0x%x\n",(unsigned char)((sm_msg->specific_msg.pdu_session_modification_complete.extendedprotocolconfigurationoptions)->data[0]),(unsigned char)((sm_msg->specific_msg.pdu_session_modification_complete.extendedprotocolconfigurationoptions)->data[1]),(unsigned char)((sm_msg->specific_msg.pdu_session_modification_complete.extendedprotocolconfigurationoptions)->data[2]),(unsigned char)((sm_msg->specific_msg.pdu_session_modification_complete.extendedprotocolconfigurationoptions)->data[3]));

    //bytes = nas_message_encode (data, &nas_msg, 60/*don't know the size*/, security);
    bytes = nas_message_encode (data, &nas_msg, sizeof(data)/*don't know the size*/, &securityencode);

    //nas_msg_str = reinterpret_cast<char*> (data);
    printf("Data = ");
    for(int i = 0;i<bytes;i++)
      printf("Data = %02x ",data[i]);
    printf("\n");
    std::string n1Message ((char*) data,  bytes);
    nas_msg_str = n1Message;
    Logger::smf_app().debug("n1MessageContent: %d, %s\n ", bytes, nas_msg_str.c_str());
    printf("PDU_SESSION_MODIFICATION_COMPLETE------------ encode end\n\n");
  }
  break;

  case PDU_SESSION_MODIFICATION_COMMANDREJECT:{
    printf("\n\nPDU_SESSION_MODIFICATION_COMMANDREJECT------------ encode start\n");
    sm_msg->header.message_type = PDU_SESSION_MODIFICATION_COMMANDREJECT;

    sm_msg->specific_msg.pdu_session_modification_command_reject._5gsmcause = 0b00001000;

    sm_msg->specific_msg.pdu_session_modification_command_reject.presence = 0x01;

    unsigned char bitStream_extendedprotocolconfigurationoptions[4];
    bitStream_extendedprotocolconfigurationoptions[0] = 0x12;
    bitStream_extendedprotocolconfigurationoptions[1] = 0x13;
    bitStream_extendedprotocolconfigurationoptions[2] = 0x14;
    bitStream_extendedprotocolconfigurationoptions[3] = 0x15;
    bstring extendedprotocolconfigurationoptions_tmp = bfromcstralloc(4, "\0");
    //extendedprotocolconfigurationoptions_tmp->data = bitStream_extendedprotocolconfigurationoptions;
    extendedprotocolconfigurationoptions_tmp->slen = 4;
    memcpy(extendedprotocolconfigurationoptions_tmp->data,bitStream_extendedprotocolconfigurationoptions,sizeof(bitStream_extendedprotocolconfigurationoptions));
    sm_msg->specific_msg.pdu_session_modification_command_reject.extendedprotocolconfigurationoptions = extendedprotocolconfigurationoptions_tmp;

    /*********************sm_msg->specific_msg.pdu_session_modification_command_reject end******************************/

    nas_msg.plain.sm = *sm_msg;


    printf("nas header encode extended_protocol_discriminator:0x%x\n, security_header_type:0x%x\n,sequence_number:0x%x\n,message_authentication_code:0x%x\n",
        nas_msg.header.extended_protocol_discriminator,
        nas_msg.header.security_header_type,
        nas_msg.header.sequence_number,
        nas_msg.header.message_authentication_code);



    printf("sm header,extended_protocol_discriminator:0x%x,pdu_session_identity:0x%x,proeduer_transaction_identity:0x%x, message type:0x%x\n",
        sm_msg->header.extended_protocol_discriminator,
        sm_msg->header.pdu_session_identity,
        sm_msg->header.procedure_transaction_identity,
        sm_msg->header.message_type);


    printf("_5gsmcause: 0x%x\n",sm_msg->specific_msg.pdu_session_modification_command_reject._5gsmcause);
    printf("extend_options buffer:0x%x 0x%x 0x%x 0x%x\n",(unsigned char)((sm_msg->specific_msg.pdu_session_modification_command_reject.extendedprotocolconfigurationoptions)->data[0]),(unsigned char)((sm_msg->specific_msg.pdu_session_modification_command_reject.extendedprotocolconfigurationoptions)->data[1]),(unsigned char)((sm_msg->specific_msg.pdu_session_modification_command_reject.extendedprotocolconfigurationoptions)->data[2]),(unsigned char)((sm_msg->specific_msg.pdu_session_modification_command_reject.extendedprotocolconfigurationoptions)->data[3]));

    //bytes = nas_message_encode (data, &nas_msg, 60/*don't know the size*/, security);
    bytes = nas_message_encode (data, &nas_msg, sizeof(data)/*don't know the size*/, &securityencode);

    //nas_msg_str = reinterpret_cast<char*> (data);
    printf("Data = ");
    for(int i = 0;i<bytes;i++)
      printf("Data = %02x ",data[i]);
    printf("\n");
    std::string n1Message ((char*) data,  bytes);
    nas_msg_str = n1Message;
    Logger::smf_app().debug("n1MessageContent: %d, %s\n ", bytes, nas_msg_str.c_str());
    printf("PDU_SESSION_MODIFICATION_COMMANDREJECT------------ encode end\n\n");
  }
  break;

  case PDU_SESSION_RELEASE_REQUEST:{
    printf("\n\nPDU_SESSION_RELEASE_REQUEST------------ encode start\n");
    sm_msg->header.message_type = PDU_SESSION_RELEASE_REQUEST;

    sm_msg->specific_msg.pdu_session_release_request.presence = 0x03;

    sm_msg->specific_msg.pdu_session_release_request._5gsmcause = 0b00001000;

    unsigned char bitStream_extendedprotocolconfigurationoptions[4];
    bitStream_extendedprotocolconfigurationoptions[0] = 0x12;
    bitStream_extendedprotocolconfigurationoptions[1] = 0x13;
    bitStream_extendedprotocolconfigurationoptions[2] = 0x14;
    bitStream_extendedprotocolconfigurationoptions[3] = 0x15;
    bstring extendedprotocolconfigurationoptions_tmp = bfromcstralloc(4, "\0");
    //extendedprotocolconfigurationoptions_tmp->data = bitStream_extendedprotocolconfigurationoptions;
    extendedprotocolconfigurationoptions_tmp->slen = 4;
    memcpy(extendedprotocolconfigurationoptions_tmp->data,bitStream_extendedprotocolconfigurationoptions,sizeof(bitStream_extendedprotocolconfigurationoptions));
    sm_msg->specific_msg.pdu_session_release_request.extendedprotocolconfigurationoptions = extendedprotocolconfigurationoptions_tmp;

    /*********************sm_msg->specific_msg.pdu_session_release_request end******************************/

    nas_msg.plain.sm = *sm_msg;

    printf("nas header encode extended_protocol_discriminator:0x%x\n, security_header_type:0x%x\n,sequence_number:0x%x\n,message_authentication_code:0x%x\n",
        nas_msg.header.extended_protocol_discriminator,
        nas_msg.header.security_header_type,
        nas_msg.header.sequence_number,
        nas_msg.header.message_authentication_code);



    printf("sm header,extended_protocol_discriminator:0x%x,pdu_session_identity:0x%x,proeduer_transaction_identity:0x%x, message type:0x%x\n",
        sm_msg->header.extended_protocol_discriminator,
        sm_msg->header.pdu_session_identity,
        sm_msg->header.procedure_transaction_identity,
        sm_msg->header.message_type);


    printf("_5gsmcause: 0x%x\n",sm_msg->specific_msg.pdu_session_release_request._5gsmcause);
    printf("extend_options buffer:0x%x 0x%x 0x%x 0x%x\n",(unsigned char)((sm_msg->specific_msg.pdu_session_release_request.extendedprotocolconfigurationoptions)->data[0]),(unsigned char)((sm_msg->specific_msg.pdu_session_release_request.extendedprotocolconfigurationoptions)->data[1]),(unsigned char)((sm_msg->specific_msg.pdu_session_release_request.extendedprotocolconfigurationoptions)->data[2]),(unsigned char)((sm_msg->specific_msg.pdu_session_release_request.extendedprotocolconfigurationoptions)->data[3]));

    //bytes = nas_message_encode (data, &nas_msg, 60/*don't know the size*/, security);
    bytes = nas_message_encode (data, &nas_msg, sizeof(data)/*don't know the size*/, &securityencode);

    //nas_msg_str = reinterpret_cast<char*> (data);
    printf("Data = ");
    for(int i = 0;i<bytes;i++)
      printf("Data = %02x ",data[i]);
    printf("\n");
    std::string n1Message ((char*) data,  bytes);
    nas_msg_str = n1Message;
    Logger::smf_app().debug("n1MessageContent: %d, %s\n ", bytes, nas_msg_str.c_str());
    printf("PDU_SESSION_RELEASE_REQUEST------------ encode end\n\n");
  }
  break;

  case PDU_SESSION_RELEASE_REJECT:{
    printf("\n\nPDU_SESSION_RELEASE_REJECT------------ encode start\n");
    sm_msg->header.message_type = PDU_SESSION_RELEASE_REJECT;

    sm_msg->specific_msg.pdu_session_release_reject._5gsmcause = 0b00001000;

    sm_msg->specific_msg.pdu_session_release_reject.presence = 0x01;

    unsigned char bitStream_extendedprotocolconfigurationoptions[4];
    bitStream_extendedprotocolconfigurationoptions[0] = 0x12;
    bitStream_extendedprotocolconfigurationoptions[1] = 0x13;
    bitStream_extendedprotocolconfigurationoptions[2] = 0x14;
    bitStream_extendedprotocolconfigurationoptions[3] = 0x15;
    bstring extendedprotocolconfigurationoptions_tmp = bfromcstralloc(4, "\0");
    //extendedprotocolconfigurationoptions_tmp->data = bitStream_extendedprotocolconfigurationoptions;
    extendedprotocolconfigurationoptions_tmp->slen = 4;
    memcpy(extendedprotocolconfigurationoptions_tmp->data,bitStream_extendedprotocolconfigurationoptions,sizeof(bitStream_extendedprotocolconfigurationoptions));
    sm_msg->specific_msg.pdu_session_release_reject.extendedprotocolconfigurationoptions = extendedprotocolconfigurationoptions_tmp;

    /*********************sm_msg->specific_msg.pdu_session_release_reject end******************************/

    nas_msg.plain.sm = *sm_msg;

    printf("nas header encode extended_protocol_discriminator:0x%x\n, security_header_type:0x%x\n,sequence_number:0x%x\n,message_authentication_code:0x%x\n",
        nas_msg.header.extended_protocol_discriminator,
        nas_msg.header.security_header_type,
        nas_msg.header.sequence_number,
        nas_msg.header.message_authentication_code);



    printf("sm header,extended_protocol_discriminator:0x%x,pdu_session_identity:0x%x,proeduer_transaction_identity:0x%x, message type:0x%x\n",
        sm_msg->header.extended_protocol_discriminator,
        sm_msg->header.pdu_session_identity,
        sm_msg->header.procedure_transaction_identity,
        sm_msg->header.message_type);


    printf("_5gsmcause: 0x%x\n",sm_msg->specific_msg.pdu_session_release_reject._5gsmcause);
    printf("extend_options buffer:0x%x 0x%x 0x%x 0x%x\n",(unsigned char)((sm_msg->specific_msg.pdu_session_release_reject.extendedprotocolconfigurationoptions)->data[0]),(unsigned char)((sm_msg->specific_msg.pdu_session_release_reject.extendedprotocolconfigurationoptions)->data[1]),(unsigned char)((sm_msg->specific_msg.pdu_session_release_reject.extendedprotocolconfigurationoptions)->data[2]),(unsigned char)((sm_msg->specific_msg.pdu_session_release_reject.extendedprotocolconfigurationoptions)->data[3]));

    //bytes = nas_message_encode (data, &nas_msg, 60/*don't know the size*/, security);
    bytes = nas_message_encode (data, &nas_msg, sizeof(data)/*don't know the size*/, &securityencode);

    //nas_msg_str = reinterpret_cast<char*> (data);
    printf("Data = ");
    for(int i = 0;i<bytes;i++)
      printf("Data = %02x ",data[i]);
    printf("\n");
    std::string n1Message ((char*) data,  bytes);
    nas_msg_str = n1Message;
    Logger::smf_app().debug("n1MessageContent: %d, %s\n ", bytes, nas_msg_str.c_str());
    printf("PDU_SESSION_RELEASE_REJECT------------ encode end\n\n");
  }
  break;

  case PDU_SESSION_RELEASE_COMMAND:{
    printf("\n\nPDU_SESSION_RELEASE_COMMAND------------ encode start\n");
    sm_msg->header.message_type = PDU_SESSION_RELEASE_COMMAND;

    sm_msg->specific_msg.pdu_session_release_command._5gsmcause = 0b00001000;

    sm_msg->specific_msg.pdu_session_release_command.presence = 0x0f;

    sm_msg->specific_msg.pdu_session_release_command.gprstimer3.unit = GPRSTIMER3_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_1_HOUR;
    sm_msg->specific_msg.pdu_session_release_command.gprstimer3.timeValue = 0;

    unsigned char bitStream_eapmessage[2] = {0x01,0x02};
    bstring eapmessage_tmp = bfromcstralloc(2, "\0");
    eapmessage_tmp->slen = 2;
    memcpy(eapmessage_tmp->data,bitStream_eapmessage,sizeof(bitStream_eapmessage));
    sm_msg->specific_msg.pdu_session_release_command.eapmessage = eapmessage_tmp;

    sm_msg->specific_msg.pdu_session_release_command._5gsmcongestionreattemptindicator.abo = THE_BACKOFF_TIMER_IS_APPLIED_IN_ALL_PLMNS;

    unsigned char bitStream_extendedprotocolconfigurationoptions[4];
    bitStream_extendedprotocolconfigurationoptions[0] = 0x12;
    bitStream_extendedprotocolconfigurationoptions[1] = 0x13;
    bitStream_extendedprotocolconfigurationoptions[2] = 0x14;
    bitStream_extendedprotocolconfigurationoptions[3] = 0x15;
    bstring extendedprotocolconfigurationoptions_tmp = bfromcstralloc(4, "\0");
    //extendedprotocolconfigurationoptions_tmp->data = bitStream_extendedprotocolconfigurationoptions;
    extendedprotocolconfigurationoptions_tmp->slen = 4;
    memcpy(extendedprotocolconfigurationoptions_tmp->data,bitStream_extendedprotocolconfigurationoptions,sizeof(bitStream_extendedprotocolconfigurationoptions));
    sm_msg->specific_msg.pdu_session_release_command.extendedprotocolconfigurationoptions = extendedprotocolconfigurationoptions_tmp;



    /*********************sm_msg->specific_msg.pdu_session_release_command end******************************/

    nas_msg.plain.sm = *sm_msg;


    printf("nas header encode extended_protocol_discriminator:0x%x\n, security_header_type:0x%x\n,sequence_number:0x%x\n,message_authentication_code:0x%x\n",
        nas_msg.header.extended_protocol_discriminator,
        nas_msg.header.security_header_type,
        nas_msg.header.sequence_number,
        nas_msg.header.message_authentication_code);



    printf("sm header,extended_protocol_discriminator:0x%x,pdu_session_identity:0x%x,proeduer_transaction_identity:0x%x, message type:0x%x\n",
        sm_msg->header.extended_protocol_discriminator,
        sm_msg->header.pdu_session_identity,
        sm_msg->header.procedure_transaction_identity,
        sm_msg->header.message_type);


    printf("_5gsmcause: 0x%x\n",sm_msg->specific_msg.pdu_session_release_command._5gsmcause);
    printf("gprstimer3 --- unit_bits_H3: 0x%x,timeValue_bits_L5: 0x%x\n",sm_msg->specific_msg.pdu_session_release_command.gprstimer3.unit,sm_msg->specific_msg.pdu_session_release_command.gprstimer3.timeValue);
    printf("eapmessage buffer:0x%x 0x%x\n",(unsigned char)(sm_msg->specific_msg.pdu_session_release_command.eapmessage->data[0]),(unsigned char )(sm_msg->specific_msg.pdu_session_release_command.eapmessage->data[1]));
    printf("_5gsmcongestionreattemptindicator bits_1 --- abo:0x%x\n",sm_msg->specific_msg.pdu_session_release_command._5gsmcongestionreattemptindicator.abo);
    printf("extend_options buffer:0x%x 0x%x 0x%x 0x%x\n",(unsigned char)((sm_msg->specific_msg.pdu_session_release_command.extendedprotocolconfigurationoptions)->data[0]),(unsigned char)((sm_msg->specific_msg.pdu_session_release_command.extendedprotocolconfigurationoptions)->data[1]),(unsigned char)((sm_msg->specific_msg.pdu_session_release_command.extendedprotocolconfigurationoptions)->data[2]),(unsigned char)((sm_msg->specific_msg.pdu_session_release_command.extendedprotocolconfigurationoptions)->data[3]));

    //bytes = nas_message_encode (data, &nas_msg, 60/*don't know the size*/, security);
    bytes = nas_message_encode (data, &nas_msg, sizeof(data)/*don't know the size*/, &securityencode);

    //nas_msg_str = reinterpret_cast<char*> (data);
    printf("Data = ");
    for(int i = 0;i<bytes;i++)
      printf("Data = %02x ",data[i]);
    printf("\n");
    std::string n1Message ((char*) data,  bytes);
    nas_msg_str = n1Message;
    Logger::smf_app().debug("n1MessageContent: %d, %s\n ", bytes, nas_msg_str.c_str());
    printf("PDU_SESSION_RELEASE_COMMAND------------ encode end\n");
  }
  break;

  case PDU_SESSION_RELEASE_COMPLETE:{
    printf("\n\nPDU_SESSION_RELEASE_COMPLETE------------ encode start\n");
    sm_msg->header.message_type = PDU_SESSION_RELEASE_COMPLETE;

    sm_msg->specific_msg.pdu_session_release_complete.presence = 0x03;

    sm_msg->specific_msg.pdu_session_release_complete._5gsmcause = 0b00001000;

    unsigned char bitStream_extendedprotocolconfigurationoptions[4];
    bitStream_extendedprotocolconfigurationoptions[0] = 0x12;
    bitStream_extendedprotocolconfigurationoptions[1] = 0x13;
    bitStream_extendedprotocolconfigurationoptions[2] = 0x14;
    bitStream_extendedprotocolconfigurationoptions[3] = 0x15;
    bstring extendedprotocolconfigurationoptions_tmp = bfromcstralloc(4, "\0");
    //extendedprotocolconfigurationoptions_tmp->data = bitStream_extendedprotocolconfigurationoptions;
    extendedprotocolconfigurationoptions_tmp->slen = 4;
    memcpy(extendedprotocolconfigurationoptions_tmp->data,bitStream_extendedprotocolconfigurationoptions,sizeof(bitStream_extendedprotocolconfigurationoptions));
    sm_msg->specific_msg.pdu_session_release_complete.extendedprotocolconfigurationoptions = extendedprotocolconfigurationoptions_tmp;



    /*********************sm_msg->specific_msg.pdu_session_release_complete end******************************/

    nas_msg.plain.sm = *sm_msg;


    printf("nas header encode extended_protocol_discriminator:0x%x\n, security_header_type:0x%x\n,sequence_number:0x%x\n,message_authentication_code:0x%x\n",
        nas_msg.header.extended_protocol_discriminator,
        nas_msg.header.security_header_type,
        nas_msg.header.sequence_number,
        nas_msg.header.message_authentication_code);



    printf("sm header,extended_protocol_discriminator:0x%x,pdu_session_identity:0x%x,proeduer_transaction_identity:0x%x, message type:0x%x\n",
        sm_msg->header.extended_protocol_discriminator,
        sm_msg->header.pdu_session_identity,
        sm_msg->header.procedure_transaction_identity,
        sm_msg->header.message_type);


    printf("_5gsmcause: 0x%x\n",sm_msg->specific_msg.pdu_session_release_complete._5gsmcause);
    printf("extend_options buffer:0x%x 0x%x 0x%x 0x%x\n",(unsigned char)((sm_msg->specific_msg.pdu_session_release_complete.extendedprotocolconfigurationoptions)->data[0]),(unsigned char)((sm_msg->specific_msg.pdu_session_release_complete.extendedprotocolconfigurationoptions)->data[1]),(unsigned char)((sm_msg->specific_msg.pdu_session_release_complete.extendedprotocolconfigurationoptions)->data[2]),(unsigned char)((sm_msg->specific_msg.pdu_session_release_complete.extendedprotocolconfigurationoptions)->data[3]));

    //bytes = nas_message_encode (data, &nas_msg, 60/*don't know the size*/, security);
    bytes = nas_message_encode (data, &nas_msg, sizeof(data)/*don't know the size*/, &securityencode);

    //nas_msg_str = reinterpret_cast<char*> (data);
    printf("Data = ");
    for(int i = 0;i<bytes;i++)
      printf("Data = %02x ",data[i]);
    printf("\n");
    std::string n1Message ((char*) data,  bytes);
    nas_msg_str = n1Message;
    Logger::smf_app().debug("n1MessageContent: %d, %s\n ", bytes, nas_msg_str.c_str());
    printf("PDU_SESSION_RELEASE_COMPLETE------------ encode end\n\n");
  }
  break;

  case _5GSM_STATUS:{
    printf("\n\n5GSM_STATUS------------ encode start\n");
    sm_msg->header.message_type = _5GSM_STATUS;

    sm_msg->specific_msg._5gsm_status._5gsmcause = 0b00001000;


    /*********************sm_msg->specific_msg._5gsm_status end******************************/

    nas_msg.plain.sm = *sm_msg;

    printf("nas header encode extended_protocol_discriminator:0x%x\n, security_header_type:0x%x\n,sequence_number:0x%x\n,message_authentication_code:0x%x\n",
        nas_msg.header.extended_protocol_discriminator,
        nas_msg.header.security_header_type,
        nas_msg.header.sequence_number,
        nas_msg.header.message_authentication_code);



    printf("sm header,extended_protocol_discriminator:0x%x,pdu_session_identity:0x%x,proeduer_transaction_identity:0x%x, message type:0x%x\n",
        sm_msg->header.extended_protocol_discriminator,
        sm_msg->header.pdu_session_identity,
        sm_msg->header.procedure_transaction_identity,
        sm_msg->header.message_type);


    printf("_5gsmcause: 0x%x\n",sm_msg->specific_msg._5gsm_status._5gsmcause);

    //bytes = nas_message_encode (data, &nas_msg, 60/*don't know the size*/, security);
    bytes = nas_message_encode (data, &nas_msg, sizeof(data)/*don't know the size*/, &securityencode);

    //nas_msg_str = reinterpret_cast<char*> (data);
    printf("Data = ");
    for(int i = 0;i<bytes;i++)
      printf("Data = %02x ",data[i]);
    printf("\n");
    std::string n1Message ((char*) data,  bytes);
    nas_msg_str = n1Message;
    Logger::smf_app().debug("n1MessageContent: %d, %s\n ", bytes, nas_msg_str.c_str());
    printf("5GSM_STATUS------------ encode end\n\n");
  }
  break;

  default:
    Logger::smf_app().debug("Unknown message type: %d \n", msg_type);
  }
}

//------------------------------------------------------------------------------
void smf_n1_n2::create_n2_sm_information(pdu_session_msg& msg, uint8_t ngap_msg_type, n2_sm_info_type_e ngap_ie_type, std::string& ngap_msg_str)
{
  //TODO: To be filled with the correct parameters
  Logger::smf_app().info("Create N2 SM Information, ngap message type %d, ie type %d\n", ngap_msg_type, ngap_ie_type);

  switch (ngap_ie_type){
  //PDU Session Resource Setup Request Transfer
  case n2_sm_info_type_e::PDU_RES_SETUP_REQ: {
    Ngap_PDUSessionResourceSetupRequestTransfer_t *ngap_IEs = nullptr;
    ngap_IEs = (Ngap_PDUSessionResourceSetupRequestTransfer_t *) calloc(1, sizeof(Ngap_PDUSessionResourceSetupRequestTransfer_t));
    /* Ngap_PDUSessionAggregateMaximumBitRate_t  PDUSessionAggregateMaximumBitRate;
        Ngap_UPTransportLayerInformation_t   UPTransportLayerInformation;
        Ngap_DataForwardingNotPossible_t   DataForwardingNotPossible;
        Ngap_PDUSessionType_t  PDUSessionType;
        Ngap_SecurityIndication_t  SecurityIndication;
        Ngap_NetworkInstance_t   NetworkInstance;
        Ngap_QosFlowSetupRequestList_t   QosFlowSetupRequestList;
     */

    switch (msg.get_msg_type()) {
    case PDU_SESSION_CREATE_SM_CONTEXT_RESPONSE: {
      Logger::smf_app().info("PDU_SESSION_CREATE_SM_CONTEXT_RESPONSE");
      pdu_session_create_sm_context_response& sm_context_res = static_cast<pdu_session_create_sm_context_response&>(msg);

      qos_flow_context_created qos_flow = {};
      qos_flow = sm_context_res.get_qos_flow_context();

      //TODO: for testing purpose - should be removed
      std::string ipv4_addr_str = "127.0.0.1";
      uint32_t key = 0x01020304;
      struct in_addr ipv4_addr;
      IPV4_STR_ADDR_TO_INADDR (util::trim(ipv4_addr_str).c_str(), ipv4_addr, "BAD IPv4 ADDRESS FORMAT !");
      memcpy (&qos_flow.ul_fteid.ipv4_address,&ipv4_addr, sizeof (struct in_addr));
      memcpy (&qos_flow.ul_fteid.teid_gre_key,&key, sizeof (uint32_t));
      pfcp::qfi_t qfi(60);
      arp_5gc_t arp;
      arp.priority_level = 1;
      qos_flow.set_qfi(qfi);
      qos_flow.set_priority_level(1);
      qos_flow.set_arp(arp);
      Logger::smf_app().info("QoS parameters: qfi %d, priority_level %d, arp_priority_level %d", qos_flow.qfi.qfi, qos_flow.priority_level, qos_flow.arp.priority_level);


      //PDUSessionAggregateMaximumBitRate
      Ngap_PDUSessionResourceSetupRequestTransferIEs_t  *pduSessionAggregateMaximumBitRate =  nullptr;
      pduSessionAggregateMaximumBitRate = (Ngap_PDUSessionResourceSetupRequestTransferIEs_t *) calloc(1, sizeof(Ngap_PDUSessionResourceSetupRequestTransferIEs_t));
      pduSessionAggregateMaximumBitRate->id = Ngap_ProtocolIE_ID_id_PDUSessionAggregateMaximumBitRate;
      pduSessionAggregateMaximumBitRate->criticality = Ngap_Criticality_reject;
      pduSessionAggregateMaximumBitRate->value.present = Ngap_PDUSessionResourceSetupRequestTransferIEs__value_PR_PDUSessionAggregateMaximumBitRate;
      pduSessionAggregateMaximumBitRate->value.choice.PDUSessionAggregateMaximumBitRate.pDUSessionAggregateMaximumBitRateDL.size = 1;
      pduSessionAggregateMaximumBitRate->value.choice.PDUSessionAggregateMaximumBitRate.pDUSessionAggregateMaximumBitRateDL.buf = (uint8_t *) calloc(1, sizeof (uint8_t));
      pduSessionAggregateMaximumBitRate->value.choice.PDUSessionAggregateMaximumBitRate.pDUSessionAggregateMaximumBitRateDL.buf[0] = 0x01;
      pduSessionAggregateMaximumBitRate->value.choice.PDUSessionAggregateMaximumBitRate.pDUSessionAggregateMaximumBitRateUL.size = 1;
      pduSessionAggregateMaximumBitRate->value.choice.PDUSessionAggregateMaximumBitRate.pDUSessionAggregateMaximumBitRateUL.buf = (uint8_t *) calloc(1, sizeof (uint8_t));
      pduSessionAggregateMaximumBitRate->value.choice.PDUSessionAggregateMaximumBitRate.pDUSessionAggregateMaximumBitRateUL.buf[0] = 0x02;
      ASN_SEQUENCE_ADD(&ngap_IEs->protocolIEs.list, pduSessionAggregateMaximumBitRate);

      //UPTransportLayerInformation
      unsigned char          buf_in_addr[sizeof (struct in_addr)+1];
      memcpy (buf_in_addr, &qos_flow.ul_fteid.ipv4_address, sizeof (struct in_addr));

      Ngap_PDUSessionResourceSetupRequestTransferIEs_t  *upTransportLayerInformation =  nullptr;
      upTransportLayerInformation = (Ngap_PDUSessionResourceSetupRequestTransferIEs_t *) calloc(1, sizeof(Ngap_PDUSessionResourceSetupRequestTransferIEs_t));
      upTransportLayerInformation->id = Ngap_ProtocolIE_ID_id_UL_NGU_UP_TNLInformation;
      upTransportLayerInformation->criticality = Ngap_Criticality_reject;
      upTransportLayerInformation->value.present = Ngap_PDUSessionResourceSetupRequestTransferIEs__value_PR_UPTransportLayerInformation;
      upTransportLayerInformation->value.choice.UPTransportLayerInformation.present = Ngap_UPTransportLayerInformation_PR_gTPTunnel;
      //TODO: To be completed
      upTransportLayerInformation->value.choice.UPTransportLayerInformation.choice.gTPTunnel = (Ngap_GTPTunnel_t  *) calloc (1, sizeof(Ngap_GTPTunnel_t));
      upTransportLayerInformation->value.choice.UPTransportLayerInformation.choice.gTPTunnel->transportLayerAddress.size = 4;
      upTransportLayerInformation->value.choice.UPTransportLayerInformation.choice.gTPTunnel->transportLayerAddress.buf = (uint8_t *)calloc (4, sizeof (uint8_t));
      //upTransportLayerInformation->value.choice.UPTransportLayerInformation.choice.gTPTunnel->transportLayerAddress.buf[0] = 0x0a;
      //upTransportLayerInformation->value.choice.UPTransportLayerInformation.choice.gTPTunnel->transportLayerAddress.buf[1] = 0x0b;
      //upTransportLayerInformation->value.choice.UPTransportLayerInformation.choice.gTPTunnel->transportLayerAddress.buf[2] = 0x0c;
      //upTransportLayerInformation->value.choice.UPTransportLayerInformation.choice.gTPTunnel->transportLayerAddress.buf[3] = 0x0d;
      memcpy (upTransportLayerInformation->value.choice.UPTransportLayerInformation.choice.gTPTunnel->transportLayerAddress.buf, &qos_flow.ul_fteid.teid_gre_key, 4);
      upTransportLayerInformation->value.choice.UPTransportLayerInformation.choice.gTPTunnel->transportLayerAddress.bits_unused = 0;

      upTransportLayerInformation->value.choice.UPTransportLayerInformation.choice.gTPTunnel->gTP_TEID.size = sizeof (struct in_addr);
      upTransportLayerInformation->value.choice.UPTransportLayerInformation.choice.gTPTunnel->gTP_TEID.buf = (uint8_t *) calloc (sizeof (struct in_addr), sizeof(uint8_t));
      //upTransportLayerInformation->value.choice.UPTransportLayerInformation.choice.gTPTunnel->gTP_TEID.buf[0] = 0x0e;
      //upTransportLayerInformation->value.choice.UPTransportLayerInformation.choice.gTPTunnel->gTP_TEID.buf[1] = 0x0f;
      //upTransportLayerInformation->value.choice.UPTransportLayerInformation.choice.gTPTunnel->gTP_TEID.buf[2] = 0x10;
      //upTransportLayerInformation->value.choice.UPTransportLayerInformation.choice.gTPTunnel->gTP_TEID.buf[3] = 0x11;
      memcpy (upTransportLayerInformation->value.choice.UPTransportLayerInformation.choice.gTPTunnel->gTP_TEID.buf, buf_in_addr, sizeof (struct in_addr));

      ASN_SEQUENCE_ADD(&ngap_IEs->protocolIEs.list, upTransportLayerInformation);

      //DataForwardingNotPossible

      //PDUSessionType
      Ngap_PDUSessionResourceSetupRequestTransferIEs_t  *pduSessionType =  nullptr;
      pduSessionType = (Ngap_PDUSessionResourceSetupRequestTransferIEs_t *) calloc(1, sizeof(Ngap_PDUSessionResourceSetupRequestTransferIEs_t));
      pduSessionType->id = Ngap_ProtocolIE_ID_id_PDUSessionType;
      pduSessionType->criticality = Ngap_Criticality_reject;
      pduSessionType->value.present = Ngap_PDUSessionResourceSetupRequestTransferIEs__value_PR_PDUSessionType;
      pduSessionType->value.choice.PDUSessionType = 1; //PDUSessionType
      ASN_SEQUENCE_ADD(&ngap_IEs->protocolIEs.list, pduSessionType);

      //SecurityIndication
      //TODO: should get from UDM
      //    Ngap_PDUSessionResourceSetupRequestTransferIEs_t  *securityIndication =  nullptr;
      //   securityIndication = (Ngap_PDUSessionResourceSetupRequestTransferIEs_t *) calloc(1, sizeof(Ngap_PDUSessionResourceSetupRequestTransferIEs_t));
      //   securityIndication->value.choice.SecurityIndication.integrityProtectionIndication = Ngap_IntegrityProtectionIndication_not_needed;
      //   securityIndication->value.choice.SecurityIndication.confidentialityProtectionIndication = Ngap_ConfidentialityProtectionIndication_not_needed;

      //NetworkInstance

      //QosFlowSetupRequestList
      Ngap_PDUSessionResourceSetupRequestTransferIEs_t  *qosFlowSetupRequestList =  nullptr;
      qosFlowSetupRequestList = (Ngap_PDUSessionResourceSetupRequestTransferIEs_t *) calloc(1, sizeof(Ngap_PDUSessionResourceSetupRequestTransferIEs_t));
      qosFlowSetupRequestList->id = Ngap_ProtocolIE_ID_id_QosFlowSetupRequestList;
      qosFlowSetupRequestList->criticality = Ngap_Criticality_reject;
      qosFlowSetupRequestList->value.present = Ngap_PDUSessionResourceSetupRequestTransferIEs__value_PR_QosFlowSetupRequestList;

      Ngap_QosFlowSetupRequestItem_t *ngap_QosFlowSetupRequestItem = nullptr;
      ngap_QosFlowSetupRequestItem = (Ngap_QosFlowSetupRequestItem_t *) calloc (1, sizeof(Ngap_QosFlowSetupRequestItem_t));
      ngap_QosFlowSetupRequestItem->qosFlowIdentifier = (uint8_t) qos_flow.qfi.qfi;
      /*
        ngap_QosFlowSetupRequestItem->qosFlowLevelQosParameters.qosCharacteristics.present = Ngap_QosCharacteristics_PR_dynamic5QI;
        //TODO: to be completed
        ngap_QosFlowSetupRequestItem->qosFlowLevelQosParameters.qosCharacteristics.choice.dynamic5QI = (Ngap_Dynamic5QIDescriptor_t *)(calloc (1, sizeof(Ngap_Dynamic5QIDescriptor_t)));
        ngap_QosFlowSetupRequestItem->qosFlowLevelQosParameters.qosCharacteristics.choice.dynamic5QI->priorityLevelQos = 6;
        ngap_QosFlowSetupRequestItem->qosFlowLevelQosParameters.qosCharacteristics.choice.dynamic5QI->packetDelayBudget = 7;
        ngap_QosFlowSetupRequestItem->qosFlowLevelQosParameters.qosCharacteristics.choice.dynamic5QI->packetErrorRate.pERScalar = 8;
        ngap_QosFlowSetupRequestItem->qosFlowLevelQosParameters.qosCharacteristics.choice.dynamic5QI->packetErrorRate.pERExponent = 9;
       */
      ngap_QosFlowSetupRequestItem->qosFlowLevelQosParameters.qosCharacteristics.present = Ngap_QosCharacteristics_PR_nonDynamic5QI;
      //TODO: to be completed
      ngap_QosFlowSetupRequestItem->qosFlowLevelQosParameters.qosCharacteristics.choice.nonDynamic5QI = (Ngap_NonDynamic5QIDescriptor_t *)(calloc (1, sizeof(Ngap_NonDynamic5QIDescriptor_t)));
      ngap_QosFlowSetupRequestItem->qosFlowLevelQosParameters.qosCharacteristics.choice.nonDynamic5QI->fiveQI = (uint8_t) qos_flow.qfi.qfi;

      //TODO: To be completed



      ngap_QosFlowSetupRequestItem->qosFlowLevelQosParameters.allocationAndRetentionPriority.priorityLevelARP = qos_flow.arp.priority_level;
      ngap_QosFlowSetupRequestItem->qosFlowLevelQosParameters.allocationAndRetentionPriority.pre_emptionCapability = Ngap_Pre_emptionCapability_shall_not_trigger_pre_emption;//0, to be updated
      ngap_QosFlowSetupRequestItem->qosFlowLevelQosParameters.allocationAndRetentionPriority.pre_emptionVulnerability = Ngap_Pre_emptionVulnerability_not_pre_emptable ;//0, to be updated

      ASN_SEQUENCE_ADD(&qosFlowSetupRequestList->value.choice.QosFlowSetupRequestList.list, ngap_QosFlowSetupRequestItem);
      ASN_SEQUENCE_ADD(&ngap_IEs->protocolIEs.list, qosFlowSetupRequestList);

    }
    break;
    case PDU_SESSION_UPDATE_SM_CONTEXT_RESPONSE: {
      Logger::smf_app().info("PDU_SESSION_UPDATE_SM_CONTEXT_RESPONSE");
      pdu_session_update_sm_context_response& sm_context_res = static_cast<pdu_session_update_sm_context_response&>(msg);
    }
    break;

    default:
      Logger::smf_app().debug("Unknown message type: %d \n",msg.get_msg_type());
    }

    //encode
    size_t buffer_size = 1024;
    char *buffer = (char *)calloc(1,buffer_size);

    asn_enc_rval_t er = aper_encode_to_buffer(&asn_DEF_Ngap_PDUSessionResourceSetupRequestTransfer, nullptr, ngap_IEs, (void *)buffer, buffer_size);
    if(er.encoded < 0)
    {
      Logger::smf_app().warn("[Create N2 SM Information] NGAP PDU Session Resource Setup Request Transfer encode failed, er.encoded: %d", er.encoded);
      return;
    }

    Logger::smf_app().debug("N2 SM buffer data: ");
    for(int i = 0; i < er.encoded; i++)
      printf("%02x ", (char)buffer[i]);
    std::string ngap_message ((char*) buffer,  er.encoded);
    ngap_msg_str = ngap_message;
    Logger::smf_app().debug("N2 SM Information: %s (%d bytes)\n ", ngap_msg_str.c_str(), er.encoded);
  }
  break;
  default:
    Logger::smf_app().debug("Unknown NGAP IE type: %s \n", n2_sm_info_type_e2str[(uint8_t)ngap_ie_type]);
  }





}

//------------------------------------------------------------------------------
//TODO: should be polished
int smf_n1_n2::decode_n1_sm_container(nas_message_t& nas_msg, std::string& n1_sm_msg)
{
  //TODO: should work with BUPT to finish this function
  Logger::smf_app().info("Decode NAS message from N1 SM Container\n");

  //step 1. Decode NAS  message (for instance, ... only served as an example)
  nas_message_decode_status_t   decode_status = {0};
  int decoder_rc = RETURNok;

  unsigned int n1SmMsgLen = n1_sm_msg.length();//strlen(n1_sm_msg.c_str());
  unsigned char datavalue[512]  = {'\0'}; // = (unsigned char *)malloc(n1SmMsgLen/2 + 1);
#if 1

  unsigned char *data = (unsigned char *)malloc(n1SmMsgLen + 1);//hardcoded for the moment
  memset(data,0,n1SmMsgLen + 1);

  memcpy ((void *)data, (void *)n1_sm_msg.c_str(),n1SmMsgLen);

  Logger::smf_app().debug("Data: %s (%d bytes)", data, n1SmMsgLen);

  for(int i = 0;i<n1SmMsgLen;i++)
    printf(" %02x ",data[i]);

  Logger::smf_app().debug("Data: ");
  for(int i=0;i<n1SmMsgLen;i++)
  {
    char datatmp[3] = {0};
    memcpy(datatmp,&data[i],2);
    // Ensure both characters are hexadecimal
    bool bBothDigits = true;

    for(int j = 0; j < 2; ++j)
    {
      if(!isxdigit(datatmp[j]))
        bBothDigits = false;
    }
    if(!bBothDigits)
      break;
    // Convert two hexadecimal characters into one character
    unsigned int nAsciiCharacter;
    sscanf(datatmp, "%x", &nAsciiCharacter);
    printf("%x ",nAsciiCharacter);
    // Concatenate this character onto the output
    datavalue[i/2] = (unsigned char)nAsciiCharacter;

    // Skip the next character
    i++;
  }
  printf("\n");

  free(data);
  data = nullptr;
#else
  memcpy ((void *)datavalue, (void *)n1_sm_msg.c_str(),n1SmMsgLen);
#endif
  //use a temporary security mechanism
  //construct decode security context
  static uint8_t fivegmm_security_context_flag = 0;
  static fivegmm_security_context_t securitydecode;
  if(!fivegmm_security_context_flag)
  {
    securitydecode.selected_algorithms.encryption = NAS_SECURITY_ALGORITHMS_NEA1;
    securitydecode.dl_count.overflow = 0xffff;
    securitydecode.dl_count.seq_num =  0x23;
    securitydecode.ul_count.overflow = 0xffff;
    securitydecode.ul_count.seq_num =  0x23;
    securitydecode.knas_enc[0] = 0x14;
    securitydecode.selected_algorithms.integrity = NAS_SECURITY_ALGORITHMS_NIA1;
    securitydecode.knas_int[0] = 0x41;
    fivegmm_security_context_flag ++;
  }

  //decode the NAS message (using NAS lib)
  decoder_rc = nas_message_decode (datavalue, &nas_msg, n1SmMsgLen/2, &securitydecode, &decode_status);
  Logger::smf_app().debug("NAS msg type 0x%x ", nas_msg.plain.sm.header.message_type);

  Logger::smf_app().debug("NAS header decode, extended_protocol_discriminator 0x%x, security_header_type:0x%x,sequence_number:0x%x,message_authentication_code:0x%x",
      nas_msg.header.extended_protocol_discriminator,
      nas_msg.header.security_header_type,
      nas_msg.header.sequence_number,
      nas_msg.header.message_authentication_code);

  Logger::smf_app().debug("NAS msg type 0x%x", nas_msg.plain.sm.header.message_type);

  //nas_message_decode test
  switch(nas_msg.plain.sm.header.message_type)
  {
  case PDU_SESSION_ESTABLISHMENT_REQUEST:
    Logger::smf_app().debug("PDU_SESSION_ESTABLISHMENT_REQUEST, start decoding ...");
    Logger::smf_app().debug(
        "NAS msg, extended_protocol_discriminator: 0x%x, pdu_session_identity: 0x%x, procedure_transaction_identity: 0x%x, message type: 0x%x",
        nas_msg.plain.sm.header.extended_protocol_discriminator,
        nas_msg.plain.sm.header.pdu_session_identity,
        nas_msg.plain.sm.header.procedure_transaction_identity,
        nas_msg.plain.sm.header.message_type);
    Logger::smf_app().debug("NAS msg, pdusessiontype bits_3: 0x%x\n",
        nas_msg.plain.sm.specific_msg.pdu_session_establishment_request._pdusessiontype.pdu_session_type_value);

    //TODO: decode the rest
    /*		printf("intergrity buffer:0x%x 0x%x\n",(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_establishment_request.intergrityprotectionmaximumdatarate)->data[0]),(unsigned char )((nas_msg.plain.sm.specific_msg.pdu_session_establishment_request.intergrityprotectionmaximumdatarate)->data[1]));
		Logger::smf_app().debug("_pdusessiontype bits_3:0x%x\n",nas_msg.plain.sm.specific_msg.pdu_session_establishment_request._pdusessiontype.pdu_session_type_value);
		Logger::smf_app().debug("sscmode bits_3:0x%x\n",nas_msg.plain.sm.specific_msg.pdu_session_establishment_request.sscmode.ssc_mode_value);
		Logger::smf_app().debug("_5gsmcapability bits_5 --- MPTCP:0x%x ATS-LL:0x%x EPT-S1:0x%x MH6-PDU:0x%x RqoS:0x%x\n",nas_msg.plain.sm.specific_msg.pdu_session_establishment_request._5gsmcapability.is_MPTCP_supported,nas_msg.plain.sm.specific_msg.pdu_session_establishment_request._5gsmcapability.is_ATSLL_supported,nas_msg.plain.sm.specific_msg.pdu_session_establishment_request._5gsmcapability.is_EPTS1_supported,nas_msg.plain.sm.specific_msg.pdu_session_establishment_request._5gsmcapability.is_MH6PDU_supported,nas_msg.plain.sm.specific_msg.pdu_session_establishment_request._5gsmcapability.is_Rqos_supported);
		Logger::smf_app().debug("maximum bits_11:0x%x\n",nas_msg.plain.sm.specific_msg.pdu_session_establishment_request.maximumnumberofsupportedpacketfilters);
		Logger::smf_app().debug("Always-on bits_1 --- APSR:0x%x\n",nas_msg.plain.sm.specific_msg.pdu_session_establishment_request.alwaysonpdusessionrequested.apsr_requested);
		Logger::smf_app().debug("sm_pdu_dn buffer:0x%x 0x%x 0x%x\n",(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_establishment_request.smpdudnrequestcontainer)->data[0]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_establishment_request.smpdudnrequestcontainer)->data[1]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_establishment_request.smpdudnrequestcontainer)->data[2]));
		Logger::smf_app().debug("extend_options buffer:0x%x 0x%x 0x%x 0x%x\n",(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_establishment_request.extendedprotocolconfigurationoptions)->data[0]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_establishment_request.extendedprotocolconfigurationoptions)->data[1]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_establishment_request.extendedprotocolconfigurationoptions)->data[2]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_establishment_request.extendedprotocolconfigurationoptions)->data[3]));
     */
    Logger::smf_app().debug("PDU_SESSION_ESTABLISHMENT_REQUEST, decode finished");
    break;

  case PDU_SESSION_ESTABLISHMENT_ACCEPT:
    Logger::smf_app().debug("PDU_SESSION_ESTABLISHMENT_ACCEPT, start decoding...");
    Logger::smf_app().debug("sm header,extended_protocol_discriminator: 0x%x,pdu_session_identity: 0x%x,procedure_transaction_identity: 0x%x, message type: 0x%x", nas_msg.plain.sm.header.extended_protocol_discriminator,nas_msg.plain.sm.header.pdu_session_identity,nas_msg.plain.sm.header.procedure_transaction_identity,nas_msg.plain.sm.header.message_type);
    Logger::smf_app().debug("_pdusessiontype bits_3: %#0x",nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept._pdusessiontype.pdu_session_type_value);
    Logger::smf_app().debug("sscmode bits_3: %#0x",nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.sscmode.ssc_mode_value);
    Logger::smf_app().debug("qosrules: %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x",
        nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosrules.lengthofqosrulesie,
        nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[0].qosruleidentifer,
        nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[0].ruleoperationcode,
        nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[0].dqrbit,
        nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[0].numberofpacketfilters,
        nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[0].packetfilterdirection,
        nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[0].packetfilteridentifier,
        nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[0].packetfiltercontents.component_type,
        nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[1].packetfilterdirection,
        nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[1].packetfilteridentifier,
        nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[1].packetfiltercontents.component_type,
        nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[2].packetfilterdirection,
        nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[2].packetfilteridentifier,
        nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[2].packetfiltercontents.component_type,
        nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[0].qosruleprecedence,
        nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[0].segregation,
        nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[0].qosflowidentifer
        /*
				nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[1].qosruleidentifer,
				nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[1].ruleoperationcode,
				nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[1].dqrbit,
				nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[1].numberofpacketfilters,
				nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[1].packetfilterlist.modifyanddelete[0].packetfilteridentifier,
				nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[1].packetfilterlist.modifyanddelete[1].packetfilteridentifier,
				nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[1].packetfilterlist.modifyanddelete[2].packetfilteridentifier,
				nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[1].qosruleprecedence,
				nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[1].segregation,
				nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie[1].qosflowidentifer*/
    );

    Logger::smf_app().debug("sessionambr: %x %x %x %x",nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.sessionambr.uint_for_session_ambr_for_downlink,
        nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.sessionambr.session_ambr_for_downlink,
        nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.sessionambr.uint_for_session_ambr_for_uplink,
        nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.sessionambr.session_ambr_for_uplink);

    Logger::smf_app().debug("_5gsmcause: %#0x",nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept._5gsmcause);

    Logger::smf_app().debug("pduaddress: %x %x %x %x %x",
        nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.pduaddress.pdu_session_type_value,
        (unsigned char)(nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.pduaddress.pdu_address_information->data[0]),
        (unsigned char)(nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.pduaddress.pdu_address_information->data[1]),
        (unsigned char)(nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.pduaddress.pdu_address_information->data[2]),
        (unsigned char)(nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.pduaddress.pdu_address_information->data[3]));

    Logger::smf_app().debug("gprstimer -- unit: %#0x, timeValue: %#0x",
        nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.gprstimer.unit,
        nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.gprstimer.timeValue);

    Logger::smf_app().debug("snssai -- len: %#0x, sst: %#0x, sd: %#0x",
        nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.snssai.len,
        nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.snssai.sst,
        nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.snssai.sd);

    Logger::smf_app().debug("alwaysonpdusessionindication: %#0x",nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.alwaysonpdusessionindication.apsi_indication);
    Logger::smf_app().debug("eapmessage buffer:%x %x",
        (unsigned char)(nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.eapmessage->data[0]),
        (unsigned char)(nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.eapmessage->data[1]));

    Logger::smf_app().debug("qosflowdescriptions: %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x",
        nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionsnumber,
        nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[0].qfi,
        nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[0].operationcode,
        nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[0].e,
        nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[0].numberofparameters,
        nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[0].parameteridentifier,
        nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[0].parametercontents._5qi,
        nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[1].parameteridentifier,
        nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[1].parametercontents.gfbrormfbr_uplinkordownlink.uint,
        nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[1].parametercontents.gfbrormfbr_uplinkordownlink.value,
        nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[2].parameteridentifier,
        nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[2].parametercontents.gfbrormfbr_uplinkordownlink.uint,
        nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[2].parametercontents.gfbrormfbr_uplinkordownlink.value,
        nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[1].qfi,
        nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[1].operationcode,
        nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[1].e,
        nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[1].numberofparameters,
        nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].qfi,
        nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].operationcode,
        nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].e,
        nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].numberofparameters,
        nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[0].parameteridentifier,
        nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[0].parametercontents.gfbrormfbr_uplinkordownlink.uint,
        nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[0].parametercontents.gfbrormfbr_uplinkordownlink.value,
        nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[1].parameteridentifier,
        nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[1].parametercontents.gfbrormfbr_uplinkordownlink.uint,
        nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[1].parametercontents.gfbrormfbr_uplinkordownlink.value,
        nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[2].parameteridentifier,
        nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[2].parametercontents.averagingwindow.uplinkinmilliseconds,
        nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[2].parametercontents.averagingwindow.downlinkinmilliseconds,
        nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[3].parameteridentifier,
        nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[3].parametercontents.epsbeareridentity);

    Logger::smf_app().debug("extend_options buffer:%x %x %x %x",
        (unsigned char)(nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.extendedprotocolconfigurationoptions->data[0]),
        (unsigned char)(nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.extendedprotocolconfigurationoptions->data[1]),
        (unsigned char)(nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.extendedprotocolconfigurationoptions->data[2]),
        (unsigned char)(nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.extendedprotocolconfigurationoptions->data[3]));

    Logger::smf_app().debug("dnn buffer:%x %x %x",
        (unsigned char)(nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.dnn->data[0]),
        (unsigned char)(nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.dnn->data[1]),
        (unsigned char)(nas_msg.plain.sm.specific_msg.pdu_session_establishment_accept.dnn->data[2]));
    Logger::smf_app().debug("PDU_SESSION_ESTABLISHMENT_ACCEPT, decode finished");
    break;
  case PDU_SESSION_ESTABLISHMENT_REJECT:
    Logger::smf_app().debug("PDU_SESSION_ESTABLISHMENT_REJECT, start decoding...");
    Logger::smf_app().debug("sm header,extended_protocol_discriminator:0x%x, pdu_session_identity:0x%x,procedure_transaction_identity: 0x%x, message type: 0x%x", nas_msg.plain.sm.header.extended_protocol_discriminator,nas_msg.plain.sm.header.pdu_session_identity,nas_msg.plain.sm.header.procedure_transaction_identity,nas_msg.plain.sm.header.message_type);
    Logger::smf_app().debug("_5gsmcause: 0x%x",nas_msg.plain.sm.specific_msg.pdu_session_establishment_reject._5gsmcause);
    Logger::smf_app().debug("gprstimer3 --- unit_bits_H3: 0x%x,timeValue_bits_L5: 0x%x\n",nas_msg.plain.sm.specific_msg.pdu_session_establishment_reject.gprstimer3.unit,nas_msg.plain.sm.specific_msg.pdu_session_establishment_reject.gprstimer3.timeValue);
    Logger::smf_app().debug("allowedsscmode --- is_ssc1_allowed: 0x%x, is_ssc2_allowed: 0x%x, is_ssc3_allowed: 0x%x",nas_msg.plain.sm.specific_msg.pdu_session_establishment_reject.allowedsscmode.is_ssc1_allowed,nas_msg.plain.sm.specific_msg.pdu_session_establishment_reject.allowedsscmode.is_ssc2_allowed,nas_msg.plain.sm.specific_msg.pdu_session_establishment_reject.allowedsscmode.is_ssc3_allowed);
    Logger::smf_app().debug("eapmessage buffer:0x%x 0x%x",(unsigned char)(nas_msg.plain.sm.specific_msg.pdu_session_establishment_reject.eapmessage->data[0]),(unsigned char )(nas_msg.plain.sm.specific_msg.pdu_session_establishment_reject.eapmessage->data[1]));
    Logger::smf_app().debug("extend_options buffer:0x%x 0x%x 0x%x 0x%x",(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_establishment_reject.extendedprotocolconfigurationoptions)->data[0]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_establishment_reject.extendedprotocolconfigurationoptions)->data[1]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_establishment_reject.extendedprotocolconfigurationoptions)->data[2]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_establishment_reject.extendedprotocolconfigurationoptions)->data[3]));
    Logger::smf_app().debug("_5gsmcongestionreattemptindicator bits_1 --- abo:0x%x",nas_msg.plain.sm.specific_msg.pdu_session_establishment_reject._5gsmcongestionreattemptindicator.abo);
    Logger::smf_app().debug("PDU_SESSION_ESTABLISHMENT_REJECT, decode finished");
    break;
  case PDU_SESSION_AUTHENTICATION_COMMAND:
    Logger::smf_app().debug("PDU_SESSION_AUTHENTICATION_COMMAND, start decoding...");
    Logger::smf_app().debug("sm header,extended_protocol_discriminator:0x%x,pdu_session_identity:0x%x,procedure_transaction_identity:0x%x, message type:0x%x\n", nas_msg.plain.sm.header.extended_protocol_discriminator,nas_msg.plain.sm.header.pdu_session_identity,nas_msg.plain.sm.header.procedure_transaction_identity,nas_msg.plain.sm.header.message_type);
    Logger::smf_app().debug("eapmessage buffer:0x%x 0x%x\n",(unsigned char)(nas_msg.plain.sm.specific_msg.pdu_session_authentication_command.eapmessage->data[0]),(unsigned char )(nas_msg.plain.sm.specific_msg.pdu_session_authentication_command.eapmessage->data[1]));
    Logger::smf_app().debug("extend_options buffer:0x%x 0x%x 0x%x 0x%x\n",(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_authentication_command.extendedprotocolconfigurationoptions)->data[0]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_authentication_command.extendedprotocolconfigurationoptions)->data[1]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_authentication_command.extendedprotocolconfigurationoptions)->data[2]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_authentication_command.extendedprotocolconfigurationoptions)->data[3]));
    Logger::smf_app().debug("PDU_SESSION_AUTHENTICATION_COMMAND, decode finished");
    break;
  case PDU_SESSION_AUTHENTICATION_COMPLETE:
    Logger::smf_app().debug("PDU_SESSION_AUTHENTICATION_COMPLETE, start decoding...");
    Logger::smf_app().debug("sm header,extended_protocol_discriminator:0x%x,pdu_session_identity:0x%x,procedure_transaction_identity:0x%x, message type:0x%x\n", nas_msg.plain.sm.header.extended_protocol_discriminator,nas_msg.plain.sm.header.pdu_session_identity,nas_msg.plain.sm.header.procedure_transaction_identity,nas_msg.plain.sm.header.message_type);
    Logger::smf_app().debug("eapmessage buffer:0x%x 0x%x\n",(unsigned char)(nas_msg.plain.sm.specific_msg.pdu_session_authentication_complete.eapmessage->data[0]),(unsigned char )(nas_msg.plain.sm.specific_msg.pdu_session_authentication_complete.eapmessage->data[1]));
    Logger::smf_app().debug("extend_options buffer:0x%x 0x%x 0x%x 0x%x\n",(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_authentication_complete.extendedprotocolconfigurationoptions)->data[0]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_authentication_complete.extendedprotocolconfigurationoptions)->data[1]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_authentication_complete.extendedprotocolconfigurationoptions)->data[2]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_authentication_complete.extendedprotocolconfigurationoptions)->data[3]));
    Logger::smf_app().debug("PDU_SESSION_AUTHENTICATION_COMPLETE, decode finished");
    break;
  case PDU_SESSION_AUTHENTICATION_RESULT:
    Logger::smf_app().debug("PDU_SESSION_AUTHENTICATION_RESULT, start decoding...");
    Logger::smf_app().debug("sm header,extended_protocol_discriminator:0x%x,pdu_session_identity:0x%x,procedure_transaction_identity:0x%x, message type:0x%x\n", nas_msg.plain.sm.header.extended_protocol_discriminator,nas_msg.plain.sm.header.pdu_session_identity,nas_msg.plain.sm.header.procedure_transaction_identity,nas_msg.plain.sm.header.message_type);
    Logger::smf_app().debug("eapmessage buffer:0x%x 0x%x\n",(unsigned char)(nas_msg.plain.sm.specific_msg.pdu_session_authentication_result.eapmessage->data[0]),(unsigned char )(nas_msg.plain.sm.specific_msg.pdu_session_authentication_result.eapmessage->data[1]));
    Logger::smf_app().debug("extend_options buffer:0x%x 0x%x 0x%x 0x%x\n",(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_authentication_result.extendedprotocolconfigurationoptions)->data[0]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_authentication_result.extendedprotocolconfigurationoptions)->data[1]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_authentication_result.extendedprotocolconfigurationoptions)->data[2]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_authentication_result.extendedprotocolconfigurationoptions)->data[3]));
    Logger::smf_app().debug("PDU_SESSION_AUTHENTICATION_RESULT, decode finished");
    break;
  case PDU_SESSION_MODIFICATION_REQUEST:
    Logger::smf_app().debug("PDU_SESSION_MODIFICATION_REQUEST, start decoding...");
    Logger::smf_app().debug("sm header,extended_protocol_discriminator:0x%x,pdu_session_identity:0x%x,procedure_transaction_identity:0x%x, message type:0x%x\n", nas_msg.plain.sm.header.extended_protocol_discriminator,nas_msg.plain.sm.header.pdu_session_identity,nas_msg.plain.sm.header.procedure_transaction_identity,nas_msg.plain.sm.header.message_type);
    Logger::smf_app().debug("_5gsmcapability bits_5 --- MPTCP:0x%x ATS-LL:0x%x EPT-S1:0x%x MH6-PDU:0x%x RqoS:0x%x\n",
        nas_msg.plain.sm.specific_msg.pdu_session_modification_request._5gsmcapability.is_MPTCP_supported,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_request._5gsmcapability.is_ATSLL_supported,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_request._5gsmcapability.is_EPTS1_supported,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_request._5gsmcapability.is_MH6PDU_supported,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_request._5gsmcapability.is_Rqos_supported);

    Logger::smf_app().debug("_5gsmcause: %#0x",nas_msg.plain.sm.specific_msg.pdu_session_modification_request._5gsmcause);

    Logger::smf_app().debug("maximum bits_11:0x%x",nas_msg.plain.sm.specific_msg.pdu_session_modification_request.maximumnumberofsupportedpacketfilters);

    Logger::smf_app().debug("Always-on bits_1 --- APSR:0x%x",nas_msg.plain.sm.specific_msg.pdu_session_modification_request.alwaysonpdusessionrequested.apsr_requested);

    Logger::smf_app().debug("intergrity buffer:0x%x 0x%x",
        (unsigned char)(nas_msg.plain.sm.specific_msg.pdu_session_modification_request.intergrityprotectionmaximumdatarate->data[0]),
        (unsigned char)(nas_msg.plain.sm.specific_msg.pdu_session_modification_request.intergrityprotectionmaximumdatarate->data[1]));

    Logger::smf_app().debug("qosrules: %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x",
        nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosrules.lengthofqosrulesie,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosrules.qosrulesie[0].qosruleidentifer,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosrules.qosrulesie[0].ruleoperationcode,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosrules.qosrulesie[0].dqrbit,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosrules.qosrulesie[0].numberofpacketfilters,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[0].packetfilterdirection,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[0].packetfilteridentifier,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[0].packetfiltercontents.component_type,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[1].packetfilterdirection,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[1].packetfilteridentifier,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[1].packetfiltercontents.component_type,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[2].packetfilterdirection,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[2].packetfilteridentifier,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[2].packetfiltercontents.component_type,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosrules.qosrulesie[0].qosruleprecedence,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosrules.qosrulesie[0].segregation,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosrules.qosrulesie[0].qosflowidentifer,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosrules.qosrulesie[1].qosruleidentifer,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosrules.qosrulesie[1].ruleoperationcode,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosrules.qosrulesie[1].dqrbit,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosrules.qosrulesie[1].numberofpacketfilters,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosrules.qosrulesie[1].packetfilterlist.modifyanddelete[0].packetfilteridentifier,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosrules.qosrulesie[1].packetfilterlist.modifyanddelete[1].packetfilteridentifier,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosrules.qosrulesie[1].packetfilterlist.modifyanddelete[2].packetfilteridentifier,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosrules.qosrulesie[1].qosruleprecedence,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosrules.qosrulesie[1].segregation,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosrules.qosrulesie[1].qosflowidentifer);

    Logger::smf_app().debug("qosflowdescriptions: %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x\n",
        nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionsnumber,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[0].qfi,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[0].operationcode,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[0].e,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[0].numberofparameters,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[0].parameteridentifier,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[0].parametercontents._5qi,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[1].parameteridentifier,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[1].parametercontents.gfbrormfbr_uplinkordownlink.uint,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[1].parametercontents.gfbrormfbr_uplinkordownlink.value,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[2].parameteridentifier,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[2].parametercontents.gfbrormfbr_uplinkordownlink.uint,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[2].parametercontents.gfbrormfbr_uplinkordownlink.value,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[1].qfi,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[1].operationcode,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[1].e,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[1].numberofparameters,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[2].qfi,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[2].operationcode,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[2].e,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[2].numberofparameters,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[0].parameteridentifier,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[0].parametercontents.gfbrormfbr_uplinkordownlink.uint,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[0].parametercontents.gfbrormfbr_uplinkordownlink.value,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[1].parameteridentifier,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[1].parametercontents.gfbrormfbr_uplinkordownlink.uint,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[1].parametercontents.gfbrormfbr_uplinkordownlink.value,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[2].parameteridentifier,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[2].parametercontents.averagingwindow.uplinkinmilliseconds,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[2].parametercontents.averagingwindow.downlinkinmilliseconds,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[3].parameteridentifier,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[3].parametercontents.epsbeareridentity);

    //printf("mappedepsbearercontexts");

    Logger::smf_app().debug("extend_options buffer:%x %x %x %x",
        (unsigned char)(nas_msg.plain.sm.specific_msg.pdu_session_modification_request.extendedprotocolconfigurationoptions->data[0]),
        (unsigned char)(nas_msg.plain.sm.specific_msg.pdu_session_modification_request.extendedprotocolconfigurationoptions->data[1]),
        (unsigned char)(nas_msg.plain.sm.specific_msg.pdu_session_modification_request.extendedprotocolconfigurationoptions->data[2]),
        (unsigned char)(nas_msg.plain.sm.specific_msg.pdu_session_modification_request.extendedprotocolconfigurationoptions->data[3]));
    Logger::smf_app().debug("PDU_SESSION_MODIFICATION_REQUEST, decode finished");
    break;
  case PDU_SESSION_MODIFICATION_REJECT:
    Logger::smf_app().debug("PDU_SESSION_MODIFICATION_REJECT, start decoding...");
    Logger::smf_app().debug("sm header,extended_protocol_discriminator:0x%x,pdu_session_identity:0x%x,procedure_transaction_identity:0x%x, message type:0x%x\n", nas_msg.plain.sm.header.extended_protocol_discriminator,nas_msg.plain.sm.header.pdu_session_identity,nas_msg.plain.sm.header.procedure_transaction_identity,nas_msg.plain.sm.header.message_type);
    Logger::smf_app().debug("_5gsmcause: 0x%x",nas_msg.plain.sm.specific_msg.pdu_session_modification_reject._5gsmcause);
    Logger::smf_app().debug("gprstimer3 --- unit_bits_H3: 0x%x,timeValue_bits_L5: 0x%x",nas_msg.plain.sm.specific_msg.pdu_session_modification_reject.gprstimer3.unit,nas_msg.plain.sm.specific_msg.pdu_session_modification_reject.gprstimer3.timeValue);
    Logger::smf_app().debug("extend_options buffer:0x%x 0x%x 0x%x 0x%x\n",(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_modification_reject.extendedprotocolconfigurationoptions)->data[0]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_modification_reject.extendedprotocolconfigurationoptions)->data[1]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_modification_reject.extendedprotocolconfigurationoptions)->data[2]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_modification_reject.extendedprotocolconfigurationoptions)->data[3]));
    Logger::smf_app().debug("_5gsmcongestionreattemptindicator bits_1 --- abo:0x%x",nas_msg.plain.sm.specific_msg.pdu_session_modification_reject._5gsmcongestionreattemptindicator.abo);
    Logger::smf_app().debug("PDU_SESSION_MODIFICATION_REJECT, decode finished");
    break;
  case PDU_SESSION_MODIFICATION_COMMAND:
    Logger::smf_app().debug("PDU_SESSION_MODIFICATION_COMMAND, start decoding...");
    Logger::smf_app().debug("sm header,extended_protocol_discriminator:0x%x,pdu_session_identity:0x%x,procedure_transaction_identity:0x%x, message type:0x%x\n", nas_msg.plain.sm.header.extended_protocol_discriminator,nas_msg.plain.sm.header.pdu_session_identity,nas_msg.plain.sm.header.procedure_transaction_identity,nas_msg.plain.sm.header.message_type);

    Logger::smf_app().debug("_5gsmcause: %#0x\n",nas_msg.plain.sm.specific_msg.pdu_session_modification_command._5gsmcause);

    Logger::smf_app().debug("sessionambr: %x %x %x %x\n",
        nas_msg.plain.sm.specific_msg.pdu_session_modification_command.sessionambr.uint_for_session_ambr_for_downlink,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_command.sessionambr.session_ambr_for_downlink,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_command.sessionambr.uint_for_session_ambr_for_uplink,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_command.sessionambr.session_ambr_for_uplink);

    Logger::smf_app().debug("gprstimer -- unit: %#0x, timeValue: %#0x\n",
        nas_msg.plain.sm.specific_msg.pdu_session_modification_command.gprstimer.unit,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_command.gprstimer.timeValue);

    Logger::smf_app().debug("alwaysonpdusessionindication: %#0x\n",nas_msg.plain.sm.specific_msg.pdu_session_modification_command.alwaysonpdusessionindication.apsi_indication);

    Logger::smf_app().debug("qosrules: %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x",
        nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosrules.lengthofqosrulesie,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosrules.qosrulesie[0].qosruleidentifer,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosrules.qosrulesie[0].ruleoperationcode,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosrules.qosrulesie[0].dqrbit,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosrules.qosrulesie[0].numberofpacketfilters,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[0].packetfilterdirection,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[0].packetfilteridentifier,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[0].packetfiltercontents.component_type,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[1].packetfilterdirection,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[1].packetfilteridentifier,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[1].packetfiltercontents.component_type,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[2].packetfilterdirection,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[2].packetfilteridentifier,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[2].packetfiltercontents.component_type,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosrules.qosrulesie[0].qosruleprecedence,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosrules.qosrulesie[0].segregation,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosrules.qosrulesie[0].qosflowidentifer,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosrules.qosrulesie[1].qosruleidentifer,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosrules.qosrulesie[1].ruleoperationcode,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosrules.qosrulesie[1].dqrbit,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosrules.qosrulesie[1].numberofpacketfilters,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosrules.qosrulesie[1].packetfilterlist.modifyanddelete[0].packetfilteridentifier,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosrules.qosrulesie[1].packetfilterlist.modifyanddelete[1].packetfilteridentifier,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosrules.qosrulesie[1].packetfilterlist.modifyanddelete[2].packetfilteridentifier,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosrules.qosrulesie[1].qosruleprecedence,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosrules.qosrulesie[1].segregation,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosrules.qosrulesie[1].qosflowidentifer);

    //printf("mappedepsbearercontexts");

    Logger::smf_app().debug("qosflowdescriptions: %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x",
        nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionsnumber,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[0].qfi,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[0].operationcode,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[0].e,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[0].numberofparameters,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[0].parameteridentifier,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[0].parametercontents._5qi,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[1].parameteridentifier,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[1].parametercontents.gfbrormfbr_uplinkordownlink.uint,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[1].parametercontents.gfbrormfbr_uplinkordownlink.value,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[2].parameteridentifier,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[2].parametercontents.gfbrormfbr_uplinkordownlink.uint,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[2].parametercontents.gfbrormfbr_uplinkordownlink.value,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[1].qfi,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[1].operationcode,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[1].e,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[1].numberofparameters,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[2].qfi,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[2].operationcode,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[2].e,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[2].numberofparameters,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[0].parameteridentifier,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[0].parametercontents.gfbrormfbr_uplinkordownlink.uint,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[0].parametercontents.gfbrormfbr_uplinkordownlink.value,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[1].parameteridentifier,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[1].parametercontents.gfbrormfbr_uplinkordownlink.uint,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[1].parametercontents.gfbrormfbr_uplinkordownlink.value,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[2].parameteridentifier,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[2].parametercontents.averagingwindow.uplinkinmilliseconds,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[2].parametercontents.averagingwindow.downlinkinmilliseconds,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[3].parameteridentifier,
        nas_msg.plain.sm.specific_msg.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[3].parametercontents.epsbeareridentity);

    Logger::smf_app().debug("extend_options buffer:%x %x %x %x",
        (unsigned char)(nas_msg.plain.sm.specific_msg.pdu_session_modification_command.extendedprotocolconfigurationoptions->data[0]),
        (unsigned char)(nas_msg.plain.sm.specific_msg.pdu_session_modification_command.extendedprotocolconfigurationoptions->data[1]),
        (unsigned char)(nas_msg.plain.sm.specific_msg.pdu_session_modification_command.extendedprotocolconfigurationoptions->data[2]),
        (unsigned char)(nas_msg.plain.sm.specific_msg.pdu_session_modification_command.extendedprotocolconfigurationoptions->data[3]));
    Logger::smf_app().debug("PDU_SESSION_MODIFICATION_COMMAND, decode finished");
    break;
  case PDU_SESSION_MODIFICATION_COMPLETE:
    Logger::smf_app().debug("PDU_SESSION_MODIFICATION_COMPLETE, start decoding...");
    Logger::smf_app().debug("sm header,extended_protocol_discriminator:0x%x,pdu_session_identity:0x%x,procedure_transaction_identity:0x%x, message type:0x%x\n", nas_msg.plain.sm.header.extended_protocol_discriminator,nas_msg.plain.sm.header.pdu_session_identity,nas_msg.plain.sm.header.procedure_transaction_identity,nas_msg.plain.sm.header.message_type);
    Logger::smf_app().debug("extend_options buffer:0x%x 0x%x 0x%x 0x%x\n",(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_modification_complete.extendedprotocolconfigurationoptions)->data[0]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_modification_complete.extendedprotocolconfigurationoptions)->data[1]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_modification_complete.extendedprotocolconfigurationoptions)->data[2]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_modification_complete.extendedprotocolconfigurationoptions)->data[3]));
    Logger::smf_app().debug("PDU_SESSION_MODIFICATION_COMPLETE, decode finished");
    break;
  case PDU_SESSION_MODIFICATION_COMMANDREJECT:
    Logger::smf_app().debug("PDU_SESSION_MODIFICATION_COMMANDREJECT, start decoding...");
    Logger::smf_app().debug("sm header,extended_protocol_discriminator:0x%x,pdu_session_identity:0x%x,procedure_transaction_identity:0x%x, message type:0x%x\n", nas_msg.plain.sm.header.extended_protocol_discriminator,nas_msg.plain.sm.header.pdu_session_identity,nas_msg.plain.sm.header.procedure_transaction_identity,nas_msg.plain.sm.header.message_type);
    Logger::smf_app().debug("_5gsmcause: 0x%x\n",nas_msg.plain.sm.specific_msg.pdu_session_modification_command_reject._5gsmcause);
    Logger::smf_app().debug("extend_options buffer:0x%x 0x%x 0x%x 0x%x\n",(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_modification_command_reject.extendedprotocolconfigurationoptions)->data[0]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_modification_command_reject.extendedprotocolconfigurationoptions)->data[1]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_modification_command_reject.extendedprotocolconfigurationoptions)->data[2]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_modification_command_reject.extendedprotocolconfigurationoptions)->data[3]));
    Logger::smf_app().debug("PDU_SESSION_MODIFICATION_COMMANDREJECT, decode finished");
    break;
  case PDU_SESSION_RELEASE_REQUEST:
    Logger::smf_app().debug("PDU_SESSION_RELEASE_REQUEST, start decoding...");
    Logger::smf_app().debug("sm header,extended_protocol_discriminator:0x%x,pdu_session_identity:0x%x,procedure_transaction_identity:0x%x, message type:0x%x\n", nas_msg.plain.sm.header.extended_protocol_discriminator,nas_msg.plain.sm.header.pdu_session_identity,nas_msg.plain.sm.header.procedure_transaction_identity,nas_msg.plain.sm.header.message_type);
    Logger::smf_app().debug("_5gsmcause: 0x%x\n",nas_msg.plain.sm.specific_msg.pdu_session_release_request._5gsmcause);
    Logger::smf_app().debug("extend_options buffer:0x%x 0x%x 0x%x 0x%x\n",(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_release_request.extendedprotocolconfigurationoptions)->data[0]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_release_request.extendedprotocolconfigurationoptions)->data[1]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_release_request.extendedprotocolconfigurationoptions)->data[2]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_release_request.extendedprotocolconfigurationoptions)->data[3]));
    Logger::smf_app().debug("PDU_SESSION_RELEASE_REQUEST, decode finished");
    break;
  case PDU_SESSION_RELEASE_REJECT:
    Logger::smf_app().debug("PDU_SESSION_RELEASE_REJECT, start decoding...");
    Logger::smf_app().debug("sm header,extended_protocol_discriminator:0x%x,pdu_session_identity:0x%x,procedure_transaction_identity:0x%x, message type:0x%x\n", nas_msg.plain.sm.header.extended_protocol_discriminator,nas_msg.plain.sm.header.pdu_session_identity,nas_msg.plain.sm.header.procedure_transaction_identity,nas_msg.plain.sm.header.message_type);
    Logger::smf_app().debug("_5gsmcause: 0x%x\n",nas_msg.plain.sm.specific_msg.pdu_session_release_reject._5gsmcause);
    Logger::smf_app().debug("extend_options buffer:0x%x 0x%x 0x%x 0x%x\n",(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_release_reject.extendedprotocolconfigurationoptions)->data[0]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_release_reject.extendedprotocolconfigurationoptions)->data[1]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_release_reject.extendedprotocolconfigurationoptions)->data[2]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_release_reject.extendedprotocolconfigurationoptions)->data[3]));
    Logger::smf_app().debug("PDU_SESSION_RELEASE_REJECT, decode finished");
    break;
  case PDU_SESSION_RELEASE_COMMAND:
    Logger::smf_app().debug("PDU_SESSION_RELEASE_COMMAND, start decoding...");
    Logger::smf_app().debug("sm header,extended_protocol_discriminator:0x%x,pdu_session_identity:0x%x,procedure_transaction_identity:0x%x, message type:0x%x\n", nas_msg.plain.sm.header.extended_protocol_discriminator,nas_msg.plain.sm.header.pdu_session_identity,nas_msg.plain.sm.header.procedure_transaction_identity,nas_msg.plain.sm.header.message_type);
    Logger::smf_app().debug("_5gsmcause: 0x%x\n",nas_msg.plain.sm.specific_msg.pdu_session_release_command._5gsmcause);
    Logger::smf_app().debug("gprstimer3 --- unit_bits_H3: 0x%x,timeValue_bits_L5: 0x%x\n",nas_msg.plain.sm.specific_msg.pdu_session_release_command.gprstimer3.unit,nas_msg.plain.sm.specific_msg.pdu_session_release_command.gprstimer3.timeValue);
    Logger::smf_app().debug("eapmessage buffer:0x%x 0x%x\n",(unsigned char)(nas_msg.plain.sm.specific_msg.pdu_session_release_command.eapmessage->data[0]),(unsigned char )(nas_msg.plain.sm.specific_msg.pdu_session_release_command.eapmessage->data[1]));
    Logger::smf_app().debug("_5gsmcongestionreattemptindicator bits_1 --- abo:0x%x\n",nas_msg.plain.sm.specific_msg.pdu_session_release_command._5gsmcongestionreattemptindicator.abo);
    Logger::smf_app().debug("extend_options buffer:0x%x 0x%x 0x%x 0x%x\n",(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_release_command.extendedprotocolconfigurationoptions)->data[0]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_release_command.extendedprotocolconfigurationoptions)->data[1]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_release_command.extendedprotocolconfigurationoptions)->data[2]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_release_command.extendedprotocolconfigurationoptions)->data[3]));
    Logger::smf_app().debug("PDU_SESSION_RELEASE_COMMAND, decode finished");
    break;
  case PDU_SESSION_RELEASE_COMPLETE:
    Logger::smf_app().debug("PDU_SESSION_RELEASE_COMPLETE, start decoding...");
    Logger::smf_app().debug("sm header,extended_protocol_discriminator:0x%x,pdu_session_identity:0x%x,procedure_transaction_identity:0x%x, message type:0x%x\n", nas_msg.plain.sm.header.extended_protocol_discriminator,nas_msg.plain.sm.header.pdu_session_identity,nas_msg.plain.sm.header.procedure_transaction_identity,nas_msg.plain.sm.header.message_type);
    Logger::smf_app().debug("_5gsmcause: 0x%x\n",nas_msg.plain.sm.specific_msg.pdu_session_release_complete._5gsmcause);
    Logger::smf_app().debug("extend_options buffer:0x%x 0x%x 0x%x 0x%x\n",(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_release_complete.extendedprotocolconfigurationoptions)->data[0]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_release_complete.extendedprotocolconfigurationoptions)->data[1]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_release_complete.extendedprotocolconfigurationoptions)->data[2]),(unsigned char)((nas_msg.plain.sm.specific_msg.pdu_session_release_complete.extendedprotocolconfigurationoptions)->data[3]));
    Logger::smf_app().debug("PDU_SESSION_RELEASE_COMPLETE, decode finished");
    break;
  case _5GSM_STATUS:
    Logger::smf_app().debug("_5GSM_STAUS, start decoding...");
    Logger::smf_app().debug("sm header,extended_protocol_discriminator:0x%x,pdu_session_identity:0x%x,procedure_transaction_identity:0x%x, message type:0x%x\n", nas_msg.plain.sm.header.extended_protocol_discriminator,nas_msg.plain.sm.header.pdu_session_identity,nas_msg.plain.sm.header.procedure_transaction_identity,nas_msg.plain.sm.header.message_type);
    Logger::smf_app().debug("_5gsmcause: 0x%x\n",nas_msg.plain.sm.specific_msg._5gsm_status._5gsmcause);
    Logger::smf_app().debug("_5GSM_STAUS, decode finished");
    break;

  }

  return decoder_rc;
}

//---------------------------------------------------------------------------------------------
int smf_n1_n2::decode_n2_sm_information(std::unique_ptr<Ngap_PDUSessionResourceSetupResponseTransfer_t>& ngap_IE, std::string& n2_sm_info, std::string& n2_sm_info_type){
  //TODO: should work with BUPT to finish this function
  Logger::smf_app().info("Decode NGAP message from N2 SM Information\n");

  //step 1. Decode NGAP  message (for instance, ... only served as an example)
  int decoder_rc = RETURNok;

  //decode Ngap_PDUSessionResourceSetupResponseTransfer
  if (n2_sm_info_type.compare(n2_sm_info_type_e2str[(uint8_t)n2_sm_info_type_e::PDU_RES_SETUP_RSP]) == 0){
    // Ngap_PDUSessionResourceSetupResponseTransfer_t   *decoded_msg = nullptr;
    //Decode N2 SM info into decoded nas msg
    asn_dec_rval_t rc  = asn_decode(nullptr,ATS_ALIGNED_CANONICAL_PER, &asn_DEF_Ngap_PDUSessionResourceSetupResponseTransfer, (void **)&ngap_IE, (void *)n2_sm_info.c_str(), n2_sm_info.length());
    if(rc.code == RC_OK){
      Logger::smf_api_server().debug("asn_decode successful %d...\n",rc.code );
      return RETURNok;
    } else

    {
      Logger::smf_api_server().warn("asn_decode failed %d...\n",rc.code );
      //TODO: send error to AMF??
      return RETURNerror;
    }

  }
  return decoder_rc;
}



