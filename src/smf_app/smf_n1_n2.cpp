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

#include <curl/curl.h>
#include <nlohmann/json.hpp>
#include <stdexcept>

#include <pistache/http.h>
#include <pistache/mime.h>
#include <arpa/inet.h>

extern "C" {
#include "nas_message.h"
#include "mmData.h"
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
static std::size_t callback(
    const char* in,
    std::size_t size,
    std::size_t num,
    std::string* out)
{
  const std::size_t totalBytes(size * num);
  out->append(in, totalBytes);
  return totalBytes;
}


//-----------------------------------------------------------------------------------------------------
void smf_n1_n2::create_n1_sm_container(pdu_session_msg& msg, uint8_t n1_msg_type, std::string& nas_msg_str, cause_value_5gsm_e sm_cause)
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
  nas_msg.header.security_header_type = SECURITY_HEADER_TYPE_NOT_PROTECTED;
  //TODO: Should be updated
  uint8_t sequencenumber = 0xfe;
  uint32_t mac = 0xffee;
  nas_msg.header.sequence_number = sequencenumber;
  nas_msg.header.message_authentication_code= mac;

  SM_msg *sm_msg = &nas_msg.plain.sm;
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

  switch (n1_msg_type){
  case PDU_SESSION_ESTABLISHMENT_ACCEPT: {
    //PDU_SESSION_CREATE_SM_CONTEXT_RESPONSE
    if (msg.get_msg_type() != PDU_SESSION_CREATE_SM_CONTEXT_RESPONSE){
      Logger::smf_app().error("Cannot create an PDU Session Establishment Accept for this message (type %d)",msg.get_msg_type());
      return;
    }
    pdu_session_create_sm_context_response& sm_context_res = static_cast<pdu_session_create_sm_context_response&>(msg);

    //get default QoS value
    qos_flow_context_created qos_flow = {};
    qos_flow = sm_context_res.get_qos_flow_context();

    //TODO: to be completed
    //get the default QoS profile and assign to the NAS message

    Logger::smf_app().info("PDU_SESSION_ESTABLISHMENT_ACCEPT, encode starting...");
    sm_msg->header.message_type = PDU_SESSION_ESTABLISHMENT_ACCEPT;

    //Fill the content of PDU Session Establishment Request message with hardcoded values (to be completed)
    //PTI
    Logger::smf_app().debug("Procedure_transaction_id %d",sm_context_res.get_pti().procedure_transaction_id);
    sm_msg->header.procedure_transaction_identity = sm_context_res.get_pti().procedure_transaction_id;
    //PDU Session Type
    sm_msg->pdu_session_establishment_accept._pdusessiontype.pdu_session_type_value = sm_context_res.get_pdu_session_type();
    //SSC Mode
    //TODO: should get from sm_context_res
    sm_msg->pdu_session_establishment_accept.sscmode.ssc_mode_value = SSC_MODE_1;

    //authorized QoS rules of the PDU session: QOSRules
    //Section 6.2.5@3GPP TS 24.501
    //(Section 6.4.1.3@3GPP TS 24.501 V16.1.0) Make sure that the number of the packet filters used in the authorized QoS rules of the PDU Session does not
    // exceed the maximum number of packet filters supported by the UE for the PDU session

    QOSRulesIE qosrulesie[1];
    qosrulesie[0].qosruleidentifer = qos_flow.qos_rule.qosruleidentifer;
    qosrulesie[0].ruleoperationcode = qos_flow.qos_rule.ruleoperationcode;
    qosrulesie[0].dqrbit = qos_flow.qos_rule.dqrbit;
    qosrulesie[0].numberofpacketfilters = qos_flow.qos_rule.numberofpacketfilters;
    //1st rule
    qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace =  (Create_ModifyAndAdd_ModifyAndReplace *)calloc (1, sizeof (Create_ModifyAndAdd_ModifyAndReplace));
    qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace->packetfilterdirection = qos_flow.qos_rule.packetfilterlist.create_modifyandadd_modifyandreplace->packetfilterdirection;
    qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace->packetfilteridentifier = qos_flow.qos_rule.packetfilterlist.create_modifyandadd_modifyandreplace->packetfilteridentifier;
    qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace->packetfiltercontents.component_type = qos_flow.qos_rule.packetfilterlist.create_modifyandadd_modifyandreplace->packetfiltercontents.component_type;
    qosrulesie[0].qosruleprecedence = qos_flow.qos_rule.qosruleprecedence;
    qosrulesie[0].segregation = qos_flow.qos_rule.segregation;
    qosrulesie[0].qosflowidentifer = qos_flow.qfi.qfi;
    sm_msg->pdu_session_establishment_accept.qosrules.lengthofqosrulesie = 1;
    sm_msg->pdu_session_establishment_accept.qosrules.qosrulesie = (QOSRulesIE *)calloc (1, sizeof (QOSRulesIE));
    sm_msg->pdu_session_establishment_accept.qosrules.qosrulesie = qosrulesie;

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
            sm_msg->pdu_session_establishment_accept.sessionambr.uint_for_session_ambr_for_downlink = AMBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_1KBPS;
          if (session_ambr_dl_unit.compare("Mbps"))
            sm_msg->pdu_session_establishment_accept.sessionambr.uint_for_session_ambr_for_downlink = AMBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_1MBPS;
          if (session_ambr_dl_unit.compare("Gbps"))
            sm_msg->pdu_session_establishment_accept.sessionambr.uint_for_session_ambr_for_downlink = AMBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_1GBPS;
          if (session_ambr_dl_unit.compare("Tbps"))
            sm_msg->pdu_session_establishment_accept.sessionambr.uint_for_session_ambr_for_downlink = AMBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_1TBPS;
          if (session_ambr_dl_unit.compare("Pbps"))
            sm_msg->pdu_session_establishment_accept.sessionambr.uint_for_session_ambr_for_downlink = AMBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_1PBPS;
          sm_msg->pdu_session_establishment_accept.sessionambr.session_ambr_for_downlink  = std::stoi((sdc.get()->session_ambr).downlink.substr(0, leng_of_session_ambr_dl-4));
          //Uplink
          size_t leng_of_session_ambr_ul = (sdc.get()->session_ambr).uplink.length();
          std::string session_ambr_ul_unit = (sdc.get()->session_ambr).uplink.substr(leng_of_session_ambr_ul-4); //4 last characters stand for mbps, kbps, ..
          if (session_ambr_ul_unit.compare("Kbps"))
            sm_msg->pdu_session_establishment_accept.sessionambr.uint_for_session_ambr_for_uplink = AMBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_1KBPS;
          if (session_ambr_ul_unit.compare("Mbps"))
            sm_msg->pdu_session_establishment_accept.sessionambr.uint_for_session_ambr_for_uplink = AMBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_1MBPS;
          if (session_ambr_ul_unit.compare("Gbps"))
            sm_msg->pdu_session_establishment_accept.sessionambr.uint_for_session_ambr_for_uplink = AMBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_1GBPS;
          if (session_ambr_ul_unit.compare("Tbps"))
            sm_msg->pdu_session_establishment_accept.sessionambr.uint_for_session_ambr_for_uplink = AMBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_1TBPS;
          if (session_ambr_ul_unit.compare("Pbps"))
            sm_msg->pdu_session_establishment_accept.sessionambr.uint_for_session_ambr_for_uplink = AMBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_1PBPS;
          sm_msg->pdu_session_establishment_accept.sessionambr.session_ambr_for_uplink  = std::stoi((sdc.get()->session_ambr).uplink.substr(0, leng_of_session_ambr_ul-4));
        }
      }

    } else {
      Logger::smf_app().warn(" SMF context with SUPI " SUPI_64_FMT " does not exist!", supi64);
      //TODO:
    }

    sm_msg->pdu_session_establishment_accept.presence = 0xffff;
    sm_msg->pdu_session_establishment_accept._5gsmcause = static_cast<int>(sm_cause);
    sm_msg->pdu_session_establishment_accept.pduaddress.pdu_session_type_value = sm_context_res.get_pdu_session_type();

    //Presence
    //_5GSMCause _5gsmcause;
    sm_msg->pdu_session_establishment_accept._5gsmcause = sm_context_res.get_cause();

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
    sm_msg->pdu_session_establishment_accept.pduaddress.pdu_address_information = pdu_address_information;

    //GPRSTimer
    //sm_msg->pdu_session_establishment_accept.gprstimer.unit = GPRSTIMER_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_2_SECONDS;
    //sm_msg->pdu_session_establishment_accept.gprstimer.timeValue = 0;

    //SNSSAI
    sm_msg->pdu_session_establishment_accept.snssai.len = SST_AND_SD_LENGHT;
    sm_msg->pdu_session_establishment_accept.snssai.sst = sm_context_res.get_snssai().sST;
    sm_msg->pdu_session_establishment_accept.snssai.sd = 0x123456; //TODO: sm_context_res.get_snssai().sD;

    //AlwaysonPDUSessionIndication
    //sm_msg->pdu_session_establishment_accept.alwaysonpdusessionindication.apsi_indication = ALWAYSON_PDU_SESSION_REQUIRED;

    //MappedEPSBearerContexts mappedepsbearercontexts;
    //EAPMessage
    /*    unsigned char bitStream_eapmessage[2] = {0x01,0x02};
    bstring eapmessage_tmp = bfromcstralloc(2, "\0");
    eapmessage_tmp->slen = 2;
    memcpy(eapmessage_tmp->data,bitStream_eapmessage,sizeof(bitStream_eapmessage));
    sm_msg->pdu_session_establishment_accept.eapmessage = eapmessage_tmp;
     */

    //authorized QoS flow descriptions IE: QoSFlowDescritions
    //TODO: remove hardcoded values
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

    qosflowdescriptionscontents[2].qfi = 3;
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

    sm_msg->pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionsnumber = 3;
    sm_msg->pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents = qosflowdescriptionscontents;

    //ExtendedProtocolConfigurationOptions
    /*    unsigned char bitStream_extendedprotocolconfigurationoptions[4];
    bitStream_extendedprotocolconfigurationoptions[0] = 0x12;
    bitStream_extendedprotocolconfigurationoptions[1] = 0x13;
    bitStream_extendedprotocolconfigurationoptions[2] = 0x14;
    bitStream_extendedprotocolconfigurationoptions[3] = 0x15;
    bstring extendedprotocolconfigurationoptions_tmp = bfromcstralloc(4, "\0");
    extendedprotocolconfigurationoptions_tmp->slen = 4;
    memcpy(extendedprotocolconfigurationoptions_tmp->data,bitStream_extendedprotocolconfigurationoptions,sizeof(bitStream_extendedprotocolconfigurationoptions));
    sm_msg->pdu_session_establishment_accept.extendedprotocolconfigurationoptions = extendedprotocolconfigurationoptions_tmp;
     */

    //DNN
    bstring dnn = bfromcstralloc(sm_context_res.get_dnn().length(), "\0");
    dnn->slen = sm_context_res.get_dnn().length();
    memcpy ((void *)dnn->data, (void *)sm_context_res.get_dnn().c_str(), sm_context_res.get_dnn().length());
    sm_msg->pdu_session_establishment_accept.dnn = dnn;

    //assign SM msg to NAS content
    //nas_msg.plain.sm = *sm_msg;

    //Print the logs
    Logger::smf_app().debug("NAS header, encode extended_protocol_discriminator: 0x%x, security_header_type: 0x%x",
        nas_msg.header.extended_protocol_discriminator,
        nas_msg.header.security_header_type);

    Logger::smf_app().debug("SM header, extended_protocol_discriminator: 0x%x, pdu_session_identity: 0x%x, procedure_transaction_identity: 0x%x, message type: 0x%x",
        sm_msg->header.extended_protocol_discriminator,
        sm_msg->header.pdu_session_identity,
        sm_msg->header.procedure_transaction_identity,
        sm_msg->header.message_type);

    Logger::smf_app().debug("PDUSessionType: %#0x",sm_msg->pdu_session_establishment_accept._pdusessiontype.pdu_session_type_value);
    Logger::smf_app().debug("SSC Mode: %#0x",sm_msg->pdu_session_establishment_accept.sscmode.ssc_mode_value);

    Logger::smf_app().debug("QoSRules: %x %x %x %x %x %x %x %x %x %x %x ",
        sm_msg->pdu_session_establishment_accept.qosrules.lengthofqosrulesie,
        sm_msg->pdu_session_establishment_accept.qosrules.qosrulesie[0].qosruleidentifer,
        sm_msg->pdu_session_establishment_accept.qosrules.qosrulesie[0].ruleoperationcode,
        sm_msg->pdu_session_establishment_accept.qosrules.qosrulesie[0].dqrbit,
        sm_msg->pdu_session_establishment_accept.qosrules.qosrulesie[0].numberofpacketfilters,
        sm_msg->pdu_session_establishment_accept.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[0].packetfilterdirection,
        sm_msg->pdu_session_establishment_accept.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[0].packetfilteridentifier,
        sm_msg->pdu_session_establishment_accept.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[0].packetfiltercontents.component_type,
        sm_msg->pdu_session_establishment_accept.qosrules.qosrulesie[0].qosruleprecedence,
        sm_msg->pdu_session_establishment_accept.qosrules.qosrulesie[0].segregation,
        sm_msg->pdu_session_establishment_accept.qosrules.qosrulesie[0].qosflowidentifer);

    Logger::smf_app().debug("SessionAMBR: %x %x %x %x",
        sm_msg->pdu_session_establishment_accept.sessionambr.uint_for_session_ambr_for_downlink,
        sm_msg->pdu_session_establishment_accept.sessionambr.session_ambr_for_downlink,
        sm_msg->pdu_session_establishment_accept.sessionambr.uint_for_session_ambr_for_uplink,
        sm_msg->pdu_session_establishment_accept.sessionambr.session_ambr_for_uplink);

    Logger::smf_app().debug("5GSMCause: %#0x",sm_msg->pdu_session_establishment_accept._5gsmcause);

    struct in_addr  ipv4_address;
    memcpy (&ipv4_address, sm_msg->pdu_session_establishment_accept.pduaddress.pdu_address_information->data, 4);
    Logger::smf_app().debug("PDU Address: %s", conv::toString(ipv4_address).c_str());

    //Logger::smf_app().debug("GPRSTimer, unit: %#0x, timeValue: %#0x",
    //    sm_msg->pdu_session_establishment_accept.gprstimer.unit,
    //    sm_msg->pdu_session_establishment_accept.gprstimer.timeValue);

    Logger::smf_app().debug("SNSSAI, len: %#0x, sst: %#0x, sd: %#0x",
        sm_msg->pdu_session_establishment_accept.snssai.len,
        sm_msg->pdu_session_establishment_accept.snssai.sst,
        sm_msg->pdu_session_establishment_accept.snssai.sd);

    //Logger::smf_app().debug("AlwaysOnPDUSessionIndication: %#0x",sm_msg->pdu_session_establishment_accept.alwaysonpdusessionindication.apsi_indication);

    //Logger::smf_app().debug("EAPMessage buffer:%x %x",
    //    (unsigned char)(sm_msg->pdu_session_establishment_accept.eapmessage->data[0]),
    //    (unsigned char)(sm_msg->pdu_session_establishment_accept.eapmessage->data[1]));

    Logger::smf_app().debug("QosFlowDescriptions: %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x",
        sm_msg->pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionsnumber,
        sm_msg->pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[0].qfi,
        sm_msg->pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[0].operationcode,
        sm_msg->pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[0].e,
        sm_msg->pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[0].numberofparameters,
        sm_msg->pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[0].parameteridentifier,
        sm_msg->pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[0].parametercontents._5qi,
        sm_msg->pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[1].parameteridentifier,
        sm_msg->pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[1].parametercontents.gfbrormfbr_uplinkordownlink.uint,
        sm_msg->pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[1].parametercontents.gfbrormfbr_uplinkordownlink.value,
        sm_msg->pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[2].parameteridentifier,
        sm_msg->pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[2].parametercontents.gfbrormfbr_uplinkordownlink.uint,
        sm_msg->pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[2].parametercontents.gfbrormfbr_uplinkordownlink.value,
        sm_msg->pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[1].qfi,
        sm_msg->pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[1].operationcode,
        sm_msg->pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[1].e,
        sm_msg->pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[1].numberofparameters,
        sm_msg->pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].qfi,
        sm_msg->pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].operationcode,
        sm_msg->pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].e,
        sm_msg->pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].numberofparameters,
        sm_msg->pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[0].parameteridentifier,
        sm_msg->pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[0].parametercontents.gfbrormfbr_uplinkordownlink.uint,
        sm_msg->pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[0].parametercontents.gfbrormfbr_uplinkordownlink.value,
        sm_msg->pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[1].parameteridentifier,
        sm_msg->pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[1].parametercontents.gfbrormfbr_uplinkordownlink.uint,
        sm_msg->pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[1].parametercontents.gfbrormfbr_uplinkordownlink.value,
        sm_msg->pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[2].parameteridentifier,
        sm_msg->pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[2].parametercontents.averagingwindow.uplinkinmilliseconds,
        sm_msg->pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[2].parametercontents.averagingwindow.downlinkinmilliseconds,
        sm_msg->pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[3].parameteridentifier,
        sm_msg->pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[2].parameterslist[3].parametercontents.epsbeareridentity);

    //Logger::smf_app().debug("Extend_options buffer:%x %x %x %x",
    //    (unsigned char)(sm_msg->pdu_session_establishment_accept.extendedprotocolconfigurationoptions->data[0]),
    //    (unsigned char)(sm_msg->pdu_session_establishment_accept.extendedprotocolconfigurationoptions->data[1]),
    //    (unsigned char)(sm_msg->pdu_session_establishment_accept.extendedprotocolconfigurationoptions->data[2]),
    //    (unsigned char)(sm_msg->pdu_session_establishment_accept.extendedprotocolconfigurationoptions->data[3]));

    std::string dnn_str((char*) sm_msg->pdu_session_establishment_accept.dnn->data,  sm_msg->pdu_session_establishment_accept.dnn->slen);
    Logger::smf_app().debug("DNN: %s", dnn_str.c_str());

    //bytes = nas_message_encode (data, &nas_msg, 60/*don't know the size*/, security);
    bytes = nas_message_encode (data, &nas_msg, sizeof(data)/*don't know the size*/, security);

    Logger::smf_app().debug("Buffer Data: ");
    for(int i = 0; i < bytes; i++)
      printf("%02x ", data[i]);
    printf(" (bytes %d)\n", bytes);

    std::string n1Message ((char*) data,  bytes);
    nas_msg_str = n1Message;

  }
  break;
  case PDU_SESSION_ESTABLISHMENT_REJECT: {
    //PDU_SESSION_CREATE_SM_CONTEXT_RESPONSE or  PDU_SESSION_CREATE_SM_CONTEXT_REQUEST

    //TODO: to be completed
    Logger::smf_app().info("PDU_SESSION_CREATE_SM_CONTEXT_RESPONSE, NAS: PDU_SESSION_ESTABLISHMENT_REJECT");

    sm_msg->header.message_type = PDU_SESSION_ESTABLISHMENT_REJECT;
    //TODO: sm_msg->header.procedure_transaction_identity = ;
    sm_msg->pdu_session_establishment_reject._5gsmcause = 0b00001000;
    sm_msg->pdu_session_establishment_reject.presence = 0x1f;
    sm_msg->pdu_session_establishment_reject.gprstimer3.unit = GPRSTIMER3_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_1_HOUR;
    sm_msg->pdu_session_establishment_reject.gprstimer3.timeValue = 0;
    sm_msg->pdu_session_establishment_reject.allowedsscmode.is_ssc1_allowed = SSC_MODE1_ALLOWED;
    sm_msg->pdu_session_establishment_reject.allowedsscmode.is_ssc2_allowed = SSC_MODE2_NOT_ALLOWED;
    sm_msg->pdu_session_establishment_reject.allowedsscmode.is_ssc3_allowed = SSC_MODE3_ALLOWED;

    unsigned char bitStream_eapmessage[2] = {0x01,0x02};
    bstring eapmessage_tmp = bfromcstralloc(2, "\0");
    eapmessage_tmp->slen = 2;
    memcpy(eapmessage_tmp->data,bitStream_eapmessage,sizeof(bitStream_eapmessage));
    sm_msg->pdu_session_establishment_reject.eapmessage = eapmessage_tmp;

    unsigned char bitStream_extendedprotocolconfigurationoptions[4];
    bitStream_extendedprotocolconfigurationoptions[0] = 0x12;
    bitStream_extendedprotocolconfigurationoptions[1] = 0x13;
    bitStream_extendedprotocolconfigurationoptions[2] = 0x14;
    bitStream_extendedprotocolconfigurationoptions[3] = 0x15;
    bstring extendedprotocolconfigurationoptions_tmp = bfromcstralloc(4, "\0");
    extendedprotocolconfigurationoptions_tmp->slen = 4;
    memcpy(extendedprotocolconfigurationoptions_tmp->data,bitStream_extendedprotocolconfigurationoptions,sizeof(bitStream_extendedprotocolconfigurationoptions));
    sm_msg->pdu_session_establishment_reject.extendedprotocolconfigurationoptions = extendedprotocolconfigurationoptions_tmp;
    sm_msg->pdu_session_establishment_reject._5gsmcongestionreattemptindicator.abo = THE_BACKOFF_TIMER_IS_APPLIED_IN_ALL_PLMNS;
    size += MESSAGE_TYPE_MAXIMUM_LENGTH;

    //nas_msg.plain.sm = *sm_msg;

    //complete sm msg content
    if(size <= 0){
      //return -1;
    }

    bstring  info = bfromcstralloc(length, "\0");//info the nas_message_encode result
    /*
		Logger::smf_app().debug("Nas header, extended_protocol_discriminator: %d, security_header_type: %d,sequence_number: %d,message_authentication_code: %d ",
				nas_msg.header.extended_protocol_discriminator,
				nas_msg.header.security_header_type,
				nas_msg.header.sequence_number,
				nas_msg.header.message_authentication_code);
     */
    Logger::smf_app().debug("SM header,extended_protocol_discriminator: %d, pdu_session_identity: %d, procedure_transaction_identity: %d, message type: %d",
        sm_msg->header.extended_protocol_discriminator,
        sm_msg->header.pdu_session_identity,
        sm_msg->header.procedure_transaction_identity,
        sm_msg->header.message_type);

    Logger::smf_app().debug("SM MSG, 5gsmcause: 0x%x",sm_msg->pdu_session_establishment_reject._5gsmcause);
    Logger::smf_app().debug("SM MSG, gprstimer3, unit_bits_H3: 0x%x, timeValue_bits_L5: 0x%x",sm_msg->pdu_session_establishment_reject.gprstimer3.unit,sm_msg->pdu_session_establishment_reject.gprstimer3.timeValue);
    Logger::smf_app().debug("SM MSG, allowedsscmode, is_ssc1_allowed: 0x%x, is_ssc2_allowed: 0x%x, is_ssc3_allowed: 0x%x",sm_msg->pdu_session_establishment_reject.allowedsscmode.is_ssc1_allowed,sm_msg->pdu_session_establishment_reject.allowedsscmode.is_ssc2_allowed,sm_msg->pdu_session_establishment_reject.allowedsscmode.is_ssc3_allowed);
    Logger::smf_app().debug("SM MSG, EAP message buffer: 0x%x 0x%x",(unsigned char)(sm_msg->pdu_session_establishment_reject.eapmessage->data[0]),(unsigned char )(sm_msg->pdu_session_establishment_reject.eapmessage->data[1]));
    Logger::smf_app().debug("SM MSG, extend_options buffer: 0x%x 0x%x 0x%x 0x%x",(unsigned char)((sm_msg->pdu_session_establishment_reject.extendedprotocolconfigurationoptions)->data[0]),(unsigned char)((sm_msg->pdu_session_establishment_reject.extendedprotocolconfigurationoptions)->data[1]),(unsigned char)((sm_msg->pdu_session_establishment_reject.extendedprotocolconfigurationoptions)->data[2]),(unsigned char)((sm_msg->pdu_session_establishment_reject.extendedprotocolconfigurationoptions)->data[3]));
    Logger::smf_app().debug("SM MSG, 5gsmcongestionreattemptindicator bits_1 --- abo: 0x%x",sm_msg->pdu_session_establishment_reject._5gsmcongestionreattemptindicator.abo);

    bytes = nas_message_encode (data, &nas_msg, sizeof(data)/*don't know the size*/, security);

    Logger::smf_app().debug("Buffer Data = ");
    for(int i = 0; i < bytes; i++)
      printf("%02x ",data[i]);
    Logger::smf_app().debug(" (%d bytes)", bytes);
    std::string n1Message ((char*) data,  bytes);
    nas_msg_str = n1Message;


  }
  break;
  case PDU_SESSION_MODIFICATION_COMMAND: {
    Logger::smf_app().debug("[Create N1 SM Message] PDU Session Modification Command");

    /*
    typedef struct pdu_session_modification_command_msg_tag{
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
    }pdu_session_modification_command_msg;
     */

    pdu_session_update_sm_context_response& sm_context_res = static_cast<pdu_session_update_sm_context_response&>(msg);

    //TODO: to be completed
    Logger::smf_app().info("PDU_SESSION_MODIFICATION_COMMAND, encode starting...");
    sm_msg->header.message_type = PDU_SESSION_MODIFICATION_COMMAND;

    //Fill the content of PDU Session Establishment Request message with hardcoded values (to be completed)
    //PTI
    sm_msg->header.procedure_transaction_identity = sm_context_res.get_pti().procedure_transaction_id;
    //PDU Session Type
    sm_msg->pdu_session_modification_command.messagetype = sm_context_res.get_msg_type();
    //Presence
    sm_msg->pdu_session_modification_command.presence = 0xffff; //TODO: to be updated
    //5GSMCause
    sm_msg->pdu_session_modification_command._5gsmcause = sm_context_res.get_cause();

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
          Logger::smf_app().warn("Assign AMBR info from the DNN configuration!");
          //Downlink
          size_t leng_of_session_ambr_dl = (sdc.get()->session_ambr).downlink.length();
          std::string session_ambr_dl_unit = (sdc.get()->session_ambr).downlink.substr(leng_of_session_ambr_dl-4); //4 last characters stand for mbps, kbps, ..
          if (session_ambr_dl_unit.compare("Kbps"))
            sm_msg->pdu_session_modification_command.sessionambr.uint_for_session_ambr_for_downlink = AMBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_1KBPS;
          if (session_ambr_dl_unit.compare("Mbps"))
            sm_msg->pdu_session_modification_command.sessionambr.uint_for_session_ambr_for_downlink = AMBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_1MBPS;
          if (session_ambr_dl_unit.compare("Gbps"))
            sm_msg->pdu_session_modification_command.sessionambr.uint_for_session_ambr_for_downlink = AMBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_1GBPS;
          if (session_ambr_dl_unit.compare("Tbps"))
            sm_msg->pdu_session_modification_command.sessionambr.uint_for_session_ambr_for_downlink = AMBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_1TBPS;
          if (session_ambr_dl_unit.compare("Pbps"))
            sm_msg->pdu_session_modification_command.sessionambr.uint_for_session_ambr_for_downlink = AMBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_1PBPS;
          sm_msg->pdu_session_modification_command.sessionambr.session_ambr_for_downlink  = std::stoi((sdc.get()->session_ambr).downlink.substr(0, leng_of_session_ambr_dl-4));
          //Uplink
          size_t leng_of_session_ambr_ul = (sdc.get()->session_ambr).uplink.length();
          std::string session_ambr_ul_unit = (sdc.get()->session_ambr).uplink.substr(leng_of_session_ambr_ul-4); //4 last characters stand for mbps, kbps, ..
          if (session_ambr_ul_unit.compare("Kbps"))
            sm_msg->pdu_session_modification_command.sessionambr.uint_for_session_ambr_for_uplink = AMBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_1KBPS;
          if (session_ambr_ul_unit.compare("Mbps"))
            sm_msg->pdu_session_modification_command.sessionambr.uint_for_session_ambr_for_uplink = AMBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_1MBPS;
          if (session_ambr_ul_unit.compare("Gbps"))
            sm_msg->pdu_session_modification_command.sessionambr.uint_for_session_ambr_for_uplink = AMBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_1GBPS;
          if (session_ambr_ul_unit.compare("Tbps"))
            sm_msg->pdu_session_modification_command.sessionambr.uint_for_session_ambr_for_uplink = AMBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_1TBPS;
          if (session_ambr_ul_unit.compare("Pbps"))
            sm_msg->pdu_session_modification_command.sessionambr.uint_for_session_ambr_for_uplink = AMBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_1PBPS;
          sm_msg->pdu_session_modification_command.sessionambr.session_ambr_for_uplink  = std::stoi((sdc.get()->session_ambr).uplink.substr(0, leng_of_session_ambr_ul-4));
        } else{
          Logger::smf_app().warn(" Cannot retrieve DNN configuration!");
        }
      }

    } else {
      Logger::smf_app().warn(" SMF context with SUPI " SUPI_64_FMT " does not exist!", supi64);
      //TODO:
    }

    //GPRSTimer gprstimer;
    //TODO:
    //AlwaysonPDUSessionIndication alwaysonpdusessionindication;
    //TODO:

    //QOSRules qosrules;
    QOSRulesIE qosrulesie[1];
    qosrulesie[0].qosruleidentifer=0x01;
    qosrulesie[0].ruleoperationcode = CREATE_NEW_QOS_RULE;
    qosrulesie[0].dqrbit = THE_QOS_RULE_IS_DEFAULT_QOS_RULE;
    qosrulesie[0].numberofpacketfilters = 1;

    Create_ModifyAndAdd_ModifyAndReplace create_modifyandadd_modifyandreplace[1];
    create_modifyandadd_modifyandreplace[0].packetfilterdirection = 0b01;
    create_modifyandadd_modifyandreplace[0].packetfilteridentifier = 1;
    create_modifyandadd_modifyandreplace[0].packetfiltercontents.component_type = QOS_RULE_MATCHALL_TYPE;
    //1st rule
    qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace = (Create_ModifyAndAdd_ModifyAndReplace *) calloc (1, sizeof(Create_ModifyAndAdd_ModifyAndReplace));
    qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace = create_modifyandadd_modifyandreplace;
    qosrulesie[0].qosruleprecedence = 1;
    qosrulesie[0].segregation = SEGREGATION_NOT_REQUESTED;
    qosrulesie[0].qosflowidentifer = 60;//TODO: to be updated

    sm_msg->pdu_session_modification_command.qosrules.lengthofqosrulesie = 1;
    sm_msg->pdu_session_modification_command.qosrules.qosrulesie = (QOSRulesIE *)calloc (1, sizeof (QOSRulesIE));
    sm_msg->pdu_session_modification_command.qosrules.qosrulesie = qosrulesie;

    //     MappedEPSBearerContexts mappedepsbearercontexts;
    //     QOSFlowDescriptions qosflowdescriptions;

    //authorized QoS flow descriptions IE: QoSFlowDescritions
    //TODO: remove hardcoded values
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

    qosflowdescriptionscontents[2].qfi = 3;
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

    sm_msg->pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionsnumber = 3;
    sm_msg->pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents = qosflowdescriptionscontents;

    bytes = nas_message_encode (data, &nas_msg, sizeof(data)/*don't know the size*/, security);

    Logger::smf_app().debug("Buffer Data: ");
    for(int i = 0; i < bytes; i++)
      printf("%02x ", data[i]);
    printf(" (bytes %d)\n", bytes);

    std::string n1Message ((char*) data,  bytes);
    nas_msg_str = n1Message;

  }
  break;
  default:{

  }
  }


}

//------------------------------------------------------------------------------
void smf_n1_n2::create_n2_sm_information(pdu_session_msg& msg, uint8_t ngap_msg_type, n2_sm_info_type_e ngap_ie_type, std::string& ngap_msg_str)
{
  //TODO: To be filled with the correct parameters
  Logger::smf_app().info("Create N2 SM Information, ngap message type %d, ie type %d", ngap_msg_type, ngap_ie_type);

  switch (ngap_ie_type){

  //for Session Establishment procedure
  case n2_sm_info_type_e::PDU_RES_SETUP_REQ: {
    //PDU Session Resource Setup Request Transfer
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
      pdu_session_create_sm_context_response& sm_context_res = static_cast<pdu_session_create_sm_context_response&>(msg);

      qos_flow_context_created qos_flow = {};
      qos_flow = sm_context_res.get_qos_flow_context();


      //TODO: for testing purpose - should be removed
      /*      std::string ipv4_addr_str = "127.0.0.1";
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
       */

      Logger::smf_app().debug("UL F-TEID, Teid" "0x%" PRIx32 "",qos_flow.ul_fteid.teid_gre_key );
      Logger::smf_app().debug("UL F-TEID, IP Addr: %s", conv::toString(qos_flow.ul_fteid.ipv4_address).c_str());
      Logger::smf_app().info("QoS parameters: QFI %d, Priority level %d, ARP priority level %d", qos_flow.qfi.qfi, qos_flow.priority_level, qos_flow.arp.priority_level);

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
      unsigned char buf_in_addr[sizeof (struct in_addr)+1];
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
      pduSessionType->value.choice.PDUSessionType = sm_context_res.get_pdu_session_type(); //PDUSessionType
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
    size_t buffer_size = 512;
    char *buffer = (char *)calloc(1, buffer_size);

    asn_enc_rval_t er = aper_encode_to_buffer(&asn_DEF_Ngap_PDUSessionResourceSetupRequestTransfer, nullptr, ngap_IEs, (void *)buffer, buffer_size);
    if(er.encoded < 0)
    {
      Logger::smf_app().warn("[Create N2 SM Information] NGAP PDU Session Resource Setup Request Transfer encode failed, er.encoded: %d", er.encoded);
      return;
    }

    Logger::smf_app().debug("N2 SM buffer data: ");
    for(int i = 0; i < er.encoded; i++)
      printf("%02x ", (char)buffer[i]);
    printf(" (%d bytes)\n",(int)er.encoded);
    std::string ngap_message ((char*) buffer,  er.encoded);
    ngap_msg_str = ngap_message;
  }
  break;

  //for Session Modification procedure
  case n2_sm_info_type_e::PDU_RES_MOD_REQ: {
    Logger::smf_app().debug("[Create N2 SM Information] NGAP PDU Session Resource Modify Request Transfer");
    //PDU Session Resource Modify Request Transfer
    /*    Ngap_PDUSessionResourceModifyRequestTransfer_t

    typedef struct Ngap_PDUSessionResourceModifyRequestTransferIEs {
      Ngap_ProtocolIE_ID_t   id;
      Ngap_Criticality_t   criticality;
      struct Ngap_PDUSessionResourceModifyRequestTransferIEs__value {
        Ngap_PDUSessionResourceModifyRequestTransferIEs__value_PR present;
        union Ngap_PDUSessionResourceModifyRequestTransferIEs__Ngap_value_u {
          Ngap_PDUSessionAggregateMaximumBitRate_t   PDUSessionAggregateMaximumBitRate;
          Ngap_UL_NGU_UP_TNLModifyList_t   UL_NGU_UP_TNLModifyList;
          Ngap_NetworkInstance_t   NetworkInstance;
          Ngap_QosFlowAddOrModifyRequestList_t   QosFlowAddOrModifyRequestList;
          Ngap_QosFlowList_t   QosFlowList;
          Ngap_UPTransportLayerInformation_t   UPTransportLayerInformation;
        } choice;
        asn_struct_ctx_t _asn_ctx;
      } value;
      asn_struct_ctx_t _asn_ctx;
    } Ngap_PDUSessionResourceModifyRequestTransferIEs_t;
     */

    pdu_session_update_sm_context_request& sm_context_res = static_cast<pdu_session_update_sm_context_request&>(msg);
    pfcp::qfi_t qfi(60); //for testing purpose
    qos_flow_context_modified qos_flow;
    //sm_context_res.get_qos_flow_context_modified (qfi, qos_flow);


    Ngap_PDUSessionResourceModifyRequestTransfer_t *ngap_IEs = nullptr;
    ngap_IEs = (Ngap_PDUSessionResourceModifyRequestTransfer_t *) calloc(1, sizeof(Ngap_PDUSessionResourceModifyRequestTransfer_t));

    //PDUSessionAggregateMaximumBitRate
    Ngap_PDUSessionResourceModifyRequestTransferIEs_t  *pduSessionAggregateMaximumBitRate =  nullptr;
    pduSessionAggregateMaximumBitRate = (Ngap_PDUSessionResourceModifyRequestTransferIEs_t *) calloc(1, sizeof(Ngap_PDUSessionResourceModifyRequestTransferIEs_t));
    pduSessionAggregateMaximumBitRate->id = Ngap_ProtocolIE_ID_id_PDUSessionAggregateMaximumBitRate;
    pduSessionAggregateMaximumBitRate->criticality = Ngap_Criticality_reject;
    pduSessionAggregateMaximumBitRate->value.present = Ngap_PDUSessionResourceModifyRequestTransferIEs__value_PR_PDUSessionAggregateMaximumBitRate;
    pduSessionAggregateMaximumBitRate->value.choice.PDUSessionAggregateMaximumBitRate.pDUSessionAggregateMaximumBitRateDL.size = 1;
    pduSessionAggregateMaximumBitRate->value.choice.PDUSessionAggregateMaximumBitRate.pDUSessionAggregateMaximumBitRateDL.buf = (uint8_t *) calloc(1, sizeof (uint8_t));
    pduSessionAggregateMaximumBitRate->value.choice.PDUSessionAggregateMaximumBitRate.pDUSessionAggregateMaximumBitRateDL.buf[0] = 0x01;
    pduSessionAggregateMaximumBitRate->value.choice.PDUSessionAggregateMaximumBitRate.pDUSessionAggregateMaximumBitRateUL.size = 1;
    pduSessionAggregateMaximumBitRate->value.choice.PDUSessionAggregateMaximumBitRate.pDUSessionAggregateMaximumBitRateUL.buf = (uint8_t *) calloc(1, sizeof (uint8_t));
    pduSessionAggregateMaximumBitRate->value.choice.PDUSessionAggregateMaximumBitRate.pDUSessionAggregateMaximumBitRateUL.buf[0] = 0x02;
    ASN_SEQUENCE_ADD(&ngap_IEs->protocolIEs.list, pduSessionAggregateMaximumBitRate);


    //Ngap_UL_NGU_UP_TNLModifyList_t   UL_NGU_UP_TNLModifyList;
    unsigned char          buf_in_addr[sizeof (struct in_addr)+1];
    memcpy (buf_in_addr, &qos_flow.ul_fteid.ipv4_address, sizeof (struct in_addr));

    Ngap_PDUSessionResourceModifyRequestTransferIEs_t  *ul_NGU_UP_TNLModifyList =  nullptr;
    ul_NGU_UP_TNLModifyList = (Ngap_PDUSessionResourceModifyRequestTransferIEs_t *) calloc(1, sizeof(Ngap_PDUSessionResourceModifyRequestTransferIEs_t));
    ul_NGU_UP_TNLModifyList->id = Ngap_ProtocolIE_ID_id_UL_NGU_UP_TNLModifyList;
    ul_NGU_UP_TNLModifyList->criticality = Ngap_Criticality_reject;
    ul_NGU_UP_TNLModifyList->value.present = Ngap_PDUSessionResourceModifyRequestTransferIEs__value_PR_UL_NGU_UP_TNLModifyList;
    Ngap_UL_NGU_UP_TNLModifyItem_t *ngap_UL_NGU_UP_TNLModifyItem = nullptr;
    ngap_UL_NGU_UP_TNLModifyItem = (Ngap_UL_NGU_UP_TNLModifyItem_t *) calloc (1, sizeof(Ngap_UL_NGU_UP_TNLModifyItem_t));
    ngap_UL_NGU_UP_TNLModifyItem->uL_NGU_UP_TNLInformation.present = Ngap_UPTransportLayerInformation_PR_gTPTunnel;
    ngap_UL_NGU_UP_TNLModifyItem->uL_NGU_UP_TNLInformation.choice.gTPTunnel = (Ngap_GTPTunnel_t  *) calloc (1, sizeof(Ngap_GTPTunnel_t));
    ngap_UL_NGU_UP_TNLModifyItem->uL_NGU_UP_TNLInformation.choice.gTPTunnel->transportLayerAddress.size = 4;
    ngap_UL_NGU_UP_TNLModifyItem->uL_NGU_UP_TNLInformation.choice.gTPTunnel->transportLayerAddress.buf = (uint8_t *)calloc (4, sizeof (uint8_t));
    ngap_UL_NGU_UP_TNLModifyItem->uL_NGU_UP_TNLInformation.choice.gTPTunnel->transportLayerAddress.buf[0] = 0x0a;
    ngap_UL_NGU_UP_TNLModifyItem->uL_NGU_UP_TNLInformation.choice.gTPTunnel->transportLayerAddress.buf[1] = 0x0b;
    ngap_UL_NGU_UP_TNLModifyItem->uL_NGU_UP_TNLInformation.choice.gTPTunnel->transportLayerAddress.buf[2] = 0x0c;
    ngap_UL_NGU_UP_TNLModifyItem->uL_NGU_UP_TNLInformation.choice.gTPTunnel->transportLayerAddress.buf[3] = 0x0d;
    //memcpy (ngap_UL_NGU_UP_TNLModifyItem->uL_NGU_UP_TNLInformation.choice.gTPTunnel->transportLayerAddress.buf, &qos_flow.ul_fteid.teid_gre_key, 4);
    ngap_UL_NGU_UP_TNLModifyItem->uL_NGU_UP_TNLInformation.choice.gTPTunnel->transportLayerAddress.bits_unused = 0;
    ngap_UL_NGU_UP_TNLModifyItem->uL_NGU_UP_TNLInformation.choice.gTPTunnel->gTP_TEID.size = sizeof (struct in_addr);
    ngap_UL_NGU_UP_TNLModifyItem->uL_NGU_UP_TNLInformation.choice.gTPTunnel->gTP_TEID.buf = (uint8_t *) calloc (sizeof (struct in_addr), sizeof(uint8_t));
    ngap_UL_NGU_UP_TNLModifyItem->uL_NGU_UP_TNLInformation.choice.gTPTunnel->gTP_TEID.buf[0] = 0x0e;
    ngap_UL_NGU_UP_TNLModifyItem->uL_NGU_UP_TNLInformation.choice.gTPTunnel->gTP_TEID.buf[1] = 0x0f;
    ngap_UL_NGU_UP_TNLModifyItem->uL_NGU_UP_TNLInformation.choice.gTPTunnel->gTP_TEID.buf[2] = 0x10;
    ngap_UL_NGU_UP_TNLModifyItem->uL_NGU_UP_TNLInformation.choice.gTPTunnel->gTP_TEID.buf[3] = 0x11;
    //memcpy (ngap_UL_NGU_UP_TNLModifyItem->uL_NGU_UP_TNLInformation.choice.gTPTunnel->gTP_TEID.buf, buf_in_addr, sizeof (struct in_addr));

    ngap_UL_NGU_UP_TNLModifyItem->dL_NGU_UP_TNLInformation.present = Ngap_UPTransportLayerInformation_PR_gTPTunnel;
    ngap_UL_NGU_UP_TNLModifyItem->dL_NGU_UP_TNLInformation.choice.gTPTunnel = (Ngap_GTPTunnel_t  *) calloc (1, sizeof(Ngap_GTPTunnel_t));
    ngap_UL_NGU_UP_TNLModifyItem->dL_NGU_UP_TNLInformation.choice.gTPTunnel->transportLayerAddress.size = 4;
    ngap_UL_NGU_UP_TNLModifyItem->dL_NGU_UP_TNLInformation.choice.gTPTunnel->transportLayerAddress.buf = (uint8_t *)calloc (4, sizeof (uint8_t));
    ngap_UL_NGU_UP_TNLModifyItem->dL_NGU_UP_TNLInformation.choice.gTPTunnel->transportLayerAddress.buf[0] = 0x0a;
    ngap_UL_NGU_UP_TNLModifyItem->dL_NGU_UP_TNLInformation.choice.gTPTunnel->transportLayerAddress.buf[1] = 0x0b;
    ngap_UL_NGU_UP_TNLModifyItem->dL_NGU_UP_TNLInformation.choice.gTPTunnel->transportLayerAddress.buf[2] = 0x0c;
    ngap_UL_NGU_UP_TNLModifyItem->dL_NGU_UP_TNLInformation.choice.gTPTunnel->transportLayerAddress.buf[3] = 0x0d;
    //memcpy (ngap_UL_NGU_UP_TNLModifyItem->dL_NGU_UP_TNLInformation.choice.gTPTunnel->transportLayerAddress.buf, &qos_flow.ul_fteid.teid_gre_key, 4);
    ngap_UL_NGU_UP_TNLModifyItem->dL_NGU_UP_TNLInformation.choice.gTPTunnel->transportLayerAddress.bits_unused = 0;
    ngap_UL_NGU_UP_TNLModifyItem->dL_NGU_UP_TNLInformation.choice.gTPTunnel->gTP_TEID.size = sizeof (struct in_addr);
    ngap_UL_NGU_UP_TNLModifyItem->dL_NGU_UP_TNLInformation.choice.gTPTunnel->gTP_TEID.buf = (uint8_t *) calloc (sizeof (struct in_addr), sizeof(uint8_t));
    ngap_UL_NGU_UP_TNLModifyItem->dL_NGU_UP_TNLInformation.choice.gTPTunnel->gTP_TEID.buf[0] = 0x0e;
    ngap_UL_NGU_UP_TNLModifyItem->dL_NGU_UP_TNLInformation.choice.gTPTunnel->gTP_TEID.buf[1] = 0x0f;
    ngap_UL_NGU_UP_TNLModifyItem->dL_NGU_UP_TNLInformation.choice.gTPTunnel->gTP_TEID.buf[2] = 0x10;
    ngap_UL_NGU_UP_TNLModifyItem->dL_NGU_UP_TNLInformation.choice.gTPTunnel->gTP_TEID.buf[3] = 0x11;
    //memcpy (ngap_UL_NGU_UP_TNLModifyItem->dL_NGU_UP_TNLInformation.choice.gTPTunnel->gTP_TEID.buf, buf_in_addr, sizeof (struct in_addr));

    ASN_SEQUENCE_ADD(&ul_NGU_UP_TNLModifyList->value.choice.UL_NGU_UP_TNLModifyList.list, ngap_UL_NGU_UP_TNLModifyItem);
    ASN_SEQUENCE_ADD(&ngap_IEs->protocolIEs.list, ul_NGU_UP_TNLModifyList);

    //Ngap_NetworkInstance_t   NetworkInstance;

    //Ngap_QosFlowAddOrModifyRequestList_t   QosFlowAddOrModifyRequestList;
    //TODO: to be completed
    Ngap_PDUSessionResourceModifyRequestTransferIEs_t  *qosFlowAddOrModifyRequestList =  nullptr;
    qosFlowAddOrModifyRequestList = (Ngap_PDUSessionResourceModifyRequestTransferIEs_t *) calloc(1, sizeof(Ngap_PDUSessionResourceModifyRequestTransferIEs_t));

    qosFlowAddOrModifyRequestList->id = Ngap_ProtocolIE_ID_id_QosFlowAddOrModifyRequestList;
    qosFlowAddOrModifyRequestList->criticality = Ngap_Criticality_reject;
    qosFlowAddOrModifyRequestList->value.present = Ngap_PDUSessionResourceModifyRequestTransferIEs__value_PR_QosFlowAddOrModifyRequestList;
    Ngap_QosFlowAddOrModifyRequestItem  *ngap_QosFlowAddOrModifyRequestItem = nullptr;
    ngap_QosFlowAddOrModifyRequestItem = (Ngap_QosFlowAddOrModifyRequestItem *) calloc(1, sizeof(Ngap_QosFlowAddOrModifyRequestItem));
    ngap_QosFlowAddOrModifyRequestItem->qosFlowIdentifier = 60;//TODO: To be updated

    ngap_QosFlowAddOrModifyRequestItem->qosFlowLevelQosParameters = (struct Ngap_QosFlowLevelQosParameters*) calloc (1, sizeof(struct Ngap_QosFlowLevelQosParameters));
    ngap_QosFlowAddOrModifyRequestItem->qosFlowLevelQosParameters->qosCharacteristics.present = Ngap_QosCharacteristics_PR_nonDynamic5QI;
    ngap_QosFlowAddOrModifyRequestItem->qosFlowLevelQosParameters->qosCharacteristics.choice.nonDynamic5QI = (Ngap_NonDynamic5QIDescriptor_t *)(calloc (1, sizeof(Ngap_NonDynamic5QIDescriptor_t)));
    ngap_QosFlowAddOrModifyRequestItem->qosFlowLevelQosParameters->qosCharacteristics.choice.nonDynamic5QI->fiveQI =  60; //TODO: to be updated

    ngap_QosFlowAddOrModifyRequestItem->qosFlowLevelQosParameters->allocationAndRetentionPriority.priorityLevelARP = 15; //TODO: to be updated
    ngap_QosFlowAddOrModifyRequestItem->qosFlowLevelQosParameters->allocationAndRetentionPriority.pre_emptionCapability = Ngap_Pre_emptionCapability_shall_not_trigger_pre_emption;//0, to be updated
    ngap_QosFlowAddOrModifyRequestItem->qosFlowLevelQosParameters->allocationAndRetentionPriority.pre_emptionVulnerability = Ngap_Pre_emptionVulnerability_not_pre_emptable ;//0, to be updated

    ASN_SEQUENCE_ADD(&qosFlowAddOrModifyRequestList->value.choice.QosFlowAddOrModifyRequestList.list, ngap_QosFlowAddOrModifyRequestItem);
    //Ngap_E_RAB_ID_t *e_RAB_ID;  //optional
    ASN_SEQUENCE_ADD(&ngap_IEs->protocolIEs.list, qosFlowAddOrModifyRequestList);


    //Ngap_QosFlowList_t   QosFlowList;
    //QoS to release list??

    //Ngap_UPTransportLayerInformation_t   UPTransportLayerInformation;

    //encode
    size_t buffer_size = 512;
    char *buffer = (char *)calloc(1, buffer_size);

    asn_enc_rval_t er = aper_encode_to_buffer(&asn_DEF_Ngap_PDUSessionResourceModifyRequestTransfer, nullptr, ngap_IEs, (void *)buffer, buffer_size);
    if(er.encoded < 0)
    {
      Logger::smf_app().warn("[Create N2 SM Information] NGAP PDU Session Resource Modify Request Transfer encode failed, er.encoded: %d", er.encoded);
      return;
    }

    Logger::smf_app().debug("N2 SM buffer data: ");
    for(int i = 0; i < er.encoded; i++)
      printf("%02x ", (char)buffer[i]);
    printf(" (%d bytes)\n",(int)er.encoded);
    std::string ngap_message ((char*) buffer,  er.encoded);
    ngap_msg_str = ngap_message;
  }
  break;

  case n2_sm_info_type_e::PDU_RES_SETUP_RSP: {
    Logger::smf_app().debug("[Create N2 SM Information] NGAP PDU Session Resource Setup Response Transfer");
    //	  Ngap_QosFlowPerTNLInformation_t  qosFlowPerTNLInformation;
    //	  struct Ngap_QosFlowPerTNLInformation  *additionalQosFlowPerTNLInformation;  /* OPTIONAL */
    //	  struct Ngap_SecurityResult  *securityResult;  /* OPTIONAL */
    //	  struct Ngap_QosFlowList *qosFlowFailedToSetupList;  /* OPTIONAL */
    //	  struct Ngap_ProtocolExtensionContainer  *iE_Extensions; /* OPTIONAL */

    Ngap_PDUSessionResourceSetupResponseTransfer_t *ngap_resource_response_transfer = nullptr;
    ngap_resource_response_transfer = (Ngap_PDUSessionResourceSetupResponseTransfer_t *) calloc(1, sizeof(Ngap_PDUSessionResourceSetupResponseTransfer_t));
    ngap_resource_response_transfer->qosFlowPerTNLInformation.uPTransportLayerInformation.present = Ngap_UPTransportLayerInformation_PR_gTPTunnel;
    ngap_resource_response_transfer->qosFlowPerTNLInformation.uPTransportLayerInformation.choice.gTPTunnel = (Ngap_GTPTunnel_t  *) calloc (1, sizeof(Ngap_GTPTunnel_t));

    ngap_resource_response_transfer->qosFlowPerTNLInformation.uPTransportLayerInformation.choice.gTPTunnel->transportLayerAddress.size = 4;
    ngap_resource_response_transfer->qosFlowPerTNLInformation.uPTransportLayerInformation.choice.gTPTunnel->transportLayerAddress.buf = (uint8_t *)calloc (4, sizeof (uint8_t));
    ngap_resource_response_transfer->qosFlowPerTNLInformation.uPTransportLayerInformation.choice.gTPTunnel->transportLayerAddress.buf[0] = 0x0a;
    ngap_resource_response_transfer->qosFlowPerTNLInformation.uPTransportLayerInformation.choice.gTPTunnel->transportLayerAddress.buf[1] = 0x0b;
    ngap_resource_response_transfer->qosFlowPerTNLInformation.uPTransportLayerInformation.choice.gTPTunnel->transportLayerAddress.buf[2] = 0x0c;
    ngap_resource_response_transfer->qosFlowPerTNLInformation.uPTransportLayerInformation.choice.gTPTunnel->transportLayerAddress.buf[3] = 0x0d;
    //memcpy (ngap_resource_response_transfer->qosFlowPerTNLInformation.uPTransportLayerInformation.choice.gTPTunnel->transportLayerAddress.buf, &ul_fteid.teid_gre_key, 4);
    ngap_resource_response_transfer->qosFlowPerTNLInformation.uPTransportLayerInformation.choice.gTPTunnel->transportLayerAddress.bits_unused = 0;

    ngap_resource_response_transfer->qosFlowPerTNLInformation.uPTransportLayerInformation.choice.gTPTunnel->gTP_TEID.size = sizeof (struct in_addr);
    ngap_resource_response_transfer->qosFlowPerTNLInformation.uPTransportLayerInformation.choice.gTPTunnel->gTP_TEID.buf = (uint8_t *) calloc (sizeof (struct in_addr), sizeof(uint8_t));
    ngap_resource_response_transfer->qosFlowPerTNLInformation.uPTransportLayerInformation.choice.gTPTunnel->gTP_TEID.buf[0] = 0x0e;
    ngap_resource_response_transfer->qosFlowPerTNLInformation.uPTransportLayerInformation.choice.gTPTunnel->gTP_TEID.buf[1] = 0x0f;
    ngap_resource_response_transfer->qosFlowPerTNLInformation.uPTransportLayerInformation.choice.gTPTunnel->gTP_TEID.buf[2] = 0x10;
    ngap_resource_response_transfer->qosFlowPerTNLInformation.uPTransportLayerInformation.choice.gTPTunnel->gTP_TEID.buf[3] = 0x11;
    //memcpy (ngap_resource_response_transfer->qosFlowPerTNLInformation.uPTransportLayerInformation.choice.gTPTunnel->gTP_TEID.buf, buf_in_addr, sizeof (struct in_addr));

    Ngap_AssociatedQosFlowItem_t *qos_flow_item = nullptr;
    qos_flow_item = (Ngap_AssociatedQosFlowItem_t *) calloc(1, sizeof(Ngap_AssociatedQosFlowItem_t));
    qos_flow_item->qosFlowIdentifier = 60;

    ASN_SEQUENCE_ADD(&ngap_resource_response_transfer->qosFlowPerTNLInformation.associatedQosFlowList.list, qos_flow_item);

    //encode
    size_t buffer_size = 512;
    char *buffer = (char *)calloc(1,buffer_size);

    asn_enc_rval_t er = aper_encode_to_buffer(&asn_DEF_Ngap_PDUSessionResourceSetupResponseTransfer, nullptr, ngap_resource_response_transfer, (void *)buffer, buffer_size);
    if(er.encoded < 0)
    {
      Logger::smf_app().warn("[Create N2 SM Information] NGAP PDU Session Resource Setup Response Transfer encode failed, er.encoded: %d", er.encoded);
      return;
    }

    Logger::smf_app().debug("N2 SM buffer data: ");
    for(int i = 0; i < er.encoded; i++)
      printf("%02x ", (char)buffer[i]);
    Logger::smf_app().debug(" (%d bytes) \n",er.encoded);
    std::string ngap_message ((char*) buffer,  er.encoded);
    ngap_msg_str = ngap_message;

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
  unsigned char *datavalue = (unsigned char *)malloc(n1SmMsgLen + 1);
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

  Logger::smf_app().debug("NAS header decode, extended_protocol_discriminator 0x%x, security_header_type 0x%x",
      nas_msg.header.extended_protocol_discriminator,
      nas_msg.header.security_header_type);

  switch(nas_msg.plain.sm.header.message_type)
  {
  case PDU_SESSION_ESTABLISHMENT_REQUEST:
    Logger::smf_app().debug("PDU_SESSION_ESTABLISHMENT_REQUEST");
    Logger::smf_app().debug(
        "NAS msg, extended_protocol_discriminator 0x%x, pdu_session_identity 0x%x, procedure_transaction_identity 0x%x, message type 0x%x",
        nas_msg.plain.sm.header.extended_protocol_discriminator,
        nas_msg.plain.sm.header.pdu_session_identity,
        nas_msg.plain.sm.header.procedure_transaction_identity,
        nas_msg.plain.sm.header.message_type);
    // Logger::smf_app().debug("NAS msg, pdusessiontype bits_3: 0x%x\n", nas_msg.plain.sm.pdu_session_establishment_request._pdusessiontype.pdu_session_type_value);
    //TODO: decode the rest
    /*		printf("intergrity buffer:0x%x 0x%x\n",(unsigned char)((nas_msg.plain.sm.pdu_session_establishment_request.intergrityprotectionmaximumdatarate)->data[0]),(unsigned char )((nas_msg.plain.sm.pdu_session_establishment_request.intergrityprotectionmaximumdatarate)->data[1]));
		Logger::smf_app().debug("_pdusessiontype bits_3:0x%x\n",nas_msg.plain.sm.pdu_session_establishment_request._pdusessiontype.pdu_session_type_value);
		Logger::smf_app().debug("sscmode bits_3:0x%x\n",nas_msg.plain.sm.pdu_session_establishment_request.sscmode.ssc_mode_value);
		Logger::smf_app().debug("_5gsmcapability bits_5 --- MPTCP:0x%x ATS-LL:0x%x EPT-S1:0x%x MH6-PDU:0x%x RqoS:0x%x\n",nas_msg.plain.sm.pdu_session_establishment_request._5gsmcapability.is_MPTCP_supported,nas_msg.plain.sm.pdu_session_establishment_request._5gsmcapability.is_ATSLL_supported,nas_msg.plain.sm.pdu_session_establishment_request._5gsmcapability.is_EPTS1_supported,nas_msg.plain.sm.pdu_session_establishment_request._5gsmcapability.is_MH6PDU_supported,nas_msg.plain.sm.pdu_session_establishment_request._5gsmcapability.is_Rqos_supported);
		Logger::smf_app().debug("maximum bits_11:0x%x\n",nas_msg.plain.sm.pdu_session_establishment_request.maximumnumberofsupportedpacketfilters);
		Logger::smf_app().debug("Always-on bits_1 --- APSR:0x%x\n",nas_msg.plain.sm.pdu_session_establishment_request.alwaysonpdusessionrequested.apsr_requested);
		Logger::smf_app().debug("sm_pdu_dn buffer:0x%x 0x%x 0x%x\n",(unsigned char)((nas_msg.plain.sm.pdu_session_establishment_request.smpdudnrequestcontainer)->data[0]),(unsigned char)((nas_msg.plain.sm.pdu_session_establishment_request.smpdudnrequestcontainer)->data[1]),(unsigned char)((nas_msg.plain.sm.pdu_session_establishment_request.smpdudnrequestcontainer)->data[2]));
		Logger::smf_app().debug("extend_options buffer:0x%x 0x%x 0x%x 0x%x\n",(unsigned char)((nas_msg.plain.sm.pdu_session_establishment_request.extendedprotocolconfigurationoptions)->data[0]),(unsigned char)((nas_msg.plain.sm.pdu_session_establishment_request.extendedprotocolconfigurationoptions)->data[1]),(unsigned char)((nas_msg.plain.sm.pdu_session_establishment_request.extendedprotocolconfigurationoptions)->data[2]),(unsigned char)((nas_msg.plain.sm.pdu_session_establishment_request.extendedprotocolconfigurationoptions)->data[3]));
     */
    break;

  case PDU_SESSION_ESTABLISHMENT_ACCEPT:
    Logger::smf_app().debug("PDU_SESSION_ESTABLISHMENT_ACCEPT");
    Logger::smf_app().debug("SM header, extended_protocol_discriminator 0x%x, pdu_session_identity 0x%x, procedure_transaction_identity 0x%x, message type 0x%x", nas_msg.plain.sm.header.extended_protocol_discriminator, nas_msg.plain.sm.header.pdu_session_identity, nas_msg.plain.sm.header.procedure_transaction_identity, nas_msg.plain.sm.header.message_type);
    Logger::smf_app().debug("PDUSessionType %#0x",nas_msg.plain.sm.pdu_session_establishment_accept._pdusessiontype.pdu_session_type_value);
    Logger::smf_app().debug("SSC Mode %#0x",nas_msg.plain.sm.pdu_session_establishment_accept.sscmode.ssc_mode_value);
    /*    Logger::smf_app().debug("QoS Rules: %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x",
        nas_msg.plain.sm.pdu_session_establishment_accept.qosrules.lengthofqosrulesie,
        nas_msg.plain.sm.pdu_session_establishment_accept.qosrules.qosrulesie[0].qosruleidentifer,
        nas_msg.plain.sm.pdu_session_establishment_accept.qosrules.qosrulesie[0].ruleoperationcode,
        nas_msg.plain.sm.pdu_session_establishment_accept.qosrules.qosrulesie[0].dqrbit,
        nas_msg.plain.sm.pdu_session_establishment_accept.qosrules.qosrulesie[0].numberofpacketfilters,
        nas_msg.plain.sm.pdu_session_establishment_accept.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[0].packetfilterdirection,
        nas_msg.plain.sm.pdu_session_establishment_accept.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[0].packetfilteridentifier,
        nas_msg.plain.sm.pdu_session_establishment_accept.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[0].packetfiltercontents.component_type,
        nas_msg.plain.sm.pdu_session_establishment_accept.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[1].packetfilterdirection,
        nas_msg.plain.sm.pdu_session_establishment_accept.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[1].packetfilteridentifier,
        nas_msg.plain.sm.pdu_session_establishment_accept.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[1].packetfiltercontents.component_type,
        nas_msg.plain.sm.pdu_session_establishment_accept.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[2].packetfilterdirection,
        nas_msg.plain.sm.pdu_session_establishment_accept.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[2].packetfilteridentifier,
        nas_msg.plain.sm.pdu_session_establishment_accept.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[2].packetfiltercontents.component_type,
        nas_msg.plain.sm.pdu_session_establishment_accept.qosrules.qosrulesie[0].qosruleprecedence,
        nas_msg.plain.sm.pdu_session_establishment_accept.qosrules.qosrulesie[0].segregation,
        nas_msg.plain.sm.pdu_session_establishment_accept.qosrules.qosrulesie[0].qosflowidentifer);
    Logger::smf_app().debug("SessionAMBR: %x %x %x %x",nas_msg.plain.sm.pdu_session_establishment_accept.sessionambr.uint_for_session_ambr_for_downlink,
        nas_msg.plain.sm.pdu_session_establishment_accept.sessionambr.session_ambr_for_downlink,
        nas_msg.plain.sm.pdu_session_establishment_accept.sessionambr.uint_for_session_ambr_for_uplink,
        nas_msg.plain.sm.pdu_session_establishment_accept.sessionambr.session_ambr_for_uplink);
    Logger::smf_app().debug("5GSM Cause %#0x",nas_msg.plain.sm.pdu_session_establishment_accept._5gsmcause);
    Logger::smf_app().debug("PDU Address: %x %x %x %x %x",
        nas_msg.plain.sm.pdu_session_establishment_accept.pduaddress.pdu_session_type_value,
        (unsigned char)(nas_msg.plain.sm.pdu_session_establishment_accept.pduaddress.pdu_address_information->data[0]),
        (unsigned char)(nas_msg.plain.sm.pdu_session_establishment_accept.pduaddress.pdu_address_information->data[1]),
        (unsigned char)(nas_msg.plain.sm.pdu_session_establishment_accept.pduaddress.pdu_address_information->data[2]),
        (unsigned char)(nas_msg.plain.sm.pdu_session_establishment_accept.pduaddress.pdu_address_information->data[3]));
    Logger::smf_app().debug("GPRS Timer, unit %#0x, timeValue %#0x",
        nas_msg.plain.sm.pdu_session_establishment_accept.gprstimer.unit,
        nas_msg.plain.sm.pdu_session_establishment_accept.gprstimer.timeValue);
    Logger::smf_app().debug("SNSSAI, len %#0x, sst %#0x, sd %#0x",
        nas_msg.plain.sm.pdu_session_establishment_accept.snssai.len,
        nas_msg.plain.sm.pdu_session_establishment_accept.snssai.sst,
        nas_msg.plain.sm.pdu_session_establishment_accept.snssai.sd);
    Logger::smf_app().debug("AlwaysOnPDUSessionIndication %#0x",nas_msg.plain.sm.pdu_session_establishment_accept.alwaysonpdusessionindication.apsi_indication);
    Logger::smf_app().debug("EAPMessage buffer:%x %x",
        (unsigned char)(nas_msg.plain.sm.pdu_session_establishment_accept.eapmessage->data[0]),
        (unsigned char)(nas_msg.plain.sm.pdu_session_establishment_accept.eapmessage->data[1]));
    Logger::smf_app().debug("QoSFlowDescriptions: %x %x %x %x %x %x %x %x %x %x %x %x %x",
        nas_msg.plain.sm.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionsnumber,
        nas_msg.plain.sm.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[0].qfi,
        nas_msg.plain.sm.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[0].operationcode,
        nas_msg.plain.sm.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[0].e,
        nas_msg.plain.sm.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[0].numberofparameters,
        nas_msg.plain.sm.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[0].parameteridentifier,
        nas_msg.plain.sm.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[0].parametercontents._5qi,
        nas_msg.plain.sm.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[1].parameteridentifier,
        nas_msg.plain.sm.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[1].parametercontents.gfbrormfbr_uplinkordownlink.uint,
        nas_msg.plain.sm.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[1].parametercontents.gfbrormfbr_uplinkordownlink.value,
        nas_msg.plain.sm.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[2].parameteridentifier,
        nas_msg.plain.sm.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[2].parametercontents.gfbrormfbr_uplinkordownlink.uint,
        nas_msg.plain.sm.pdu_session_establishment_accept.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[2].parametercontents.gfbrormfbr_uplinkordownlink.value);
    Logger::smf_app().debug("extend_options buffer:%x %x %x %x",
        (unsigned char)(nas_msg.plain.sm.pdu_session_establishment_accept.extendedprotocolconfigurationoptions->data[0]),
        (unsigned char)(nas_msg.plain.sm.pdu_session_establishment_accept.extendedprotocolconfigurationoptions->data[1]),
        (unsigned char)(nas_msg.plain.sm.pdu_session_establishment_accept.extendedprotocolconfigurationoptions->data[2]),
        (unsigned char)(nas_msg.plain.sm.pdu_session_establishment_accept.extendedprotocolconfigurationoptions->data[3]));
    Logger::smf_app().debug("DNN buffer %x %x %x",
        (unsigned char)(nas_msg.plain.sm.pdu_session_establishment_accept.dnn->data[0]),
        (unsigned char)(nas_msg.plain.sm.pdu_session_establishment_accept.dnn->data[1]),
        (unsigned char)(nas_msg.plain.sm.pdu_session_establishment_accept.dnn->data[2]));
     */
    break;

  case PDU_SESSION_ESTABLISHMENT_REJECT:
    Logger::smf_app().debug("PDU_SESSION_ESTABLISHMENT_REJECT");
    Logger::smf_app().debug("SM header, extended_protocol_discriminator 0x%x, pdu_session_identity 0x%x, procedure_transaction_identity 0x%x, message type 0x%x", nas_msg.plain.sm.header.extended_protocol_discriminator, nas_msg.plain.sm.header.pdu_session_identity, nas_msg.plain.sm.header.procedure_transaction_identity, nas_msg.plain.sm.header.message_type);
    /*  Logger::smf_app().debug("5GSM Cause 0x%x",nas_msg.plain.sm.pdu_session_establishment_reject._5gsmcause);
    //Logger::smf_app().debug("GPRS Timer3 unit_bits_H3: 0x%x,timeValue_bits_L5: 0x%x\n",nas_msg.plain.sm.pdu_session_establishment_reject.gprstimer3.unit,nas_msg.plain.sm.pdu_session_establishment_reject.gprstimer3.timeValue);
    Logger::smf_app().debug("AllowedSSCMode is_ssc1_allowed: 0x%x, is_ssc2_allowed: 0x%x, is_ssc3_allowed: 0x%x",nas_msg.plain.sm.pdu_session_establishment_reject.allowedsscmode.is_ssc1_allowed,nas_msg.plain.sm.pdu_session_establishment_reject.allowedsscmode.is_ssc2_allowed,nas_msg.plain.sm.pdu_session_establishment_reject.allowedsscmode.is_ssc3_allowed);
    Logger::smf_app().debug("EAPMessage buffer:0x%x 0x%x",(unsigned char)(nas_msg.plain.sm.pdu_session_establishment_reject.eapmessage->data[0]),(unsigned char )(nas_msg.plain.sm.pdu_session_establishment_reject.eapmessage->data[1]));
    Logger::smf_app().debug("extend_options buffer:0x%x 0x%x 0x%x 0x%x",(unsigned char)((nas_msg.plain.sm.pdu_session_establishment_reject.extendedprotocolconfigurationoptions)->data[0]),(unsigned char)((nas_msg.plain.sm.pdu_session_establishment_reject.extendedprotocolconfigurationoptions)->data[1]),(unsigned char)((nas_msg.plain.sm.pdu_session_establishment_reject.extendedprotocolconfigurationoptions)->data[2]),(unsigned char)((nas_msg.plain.sm.pdu_session_establishment_reject.extendedprotocolconfigurationoptions)->data[3]));
    Logger::smf_app().debug("_5gsmcongestionreattemptindicator bits_1 --- abo:0x%x",nas_msg.plain.sm.pdu_session_establishment_reject._5gsmcongestionreattemptindicator.abo);
     */
    break;

  case PDU_SESSION_AUTHENTICATION_COMMAND:
    Logger::smf_app().debug("PDU_SESSION_AUTHENTICATION_COMMAND");
    Logger::smf_app().debug("SM header, extended_protocol_discriminator 0x%x, pdu_session_identity 0x%x, procedure_transaction_identity 0x%x, message type 0x%x", nas_msg.plain.sm.header.extended_protocol_discriminator, nas_msg.plain.sm.header.pdu_session_identity, nas_msg.plain.sm.header.procedure_transaction_identity, nas_msg.plain.sm.header.message_type);
    //Logger::smf_app().debug("eapmessage buffer:0x%x 0x%x\n",(unsigned char)(nas_msg.plain.sm.pdu_session_authentication_command.eapmessage->data[0]),(unsigned char )(nas_msg.plain.sm.pdu_session_authentication_command.eapmessage->data[1]));
    //Logger::smf_app().debug("extend_options buffer:0x%x 0x%x 0x%x 0x%x\n",(unsigned char)((nas_msg.plain.sm.pdu_session_authentication_command.extendedprotocolconfigurationoptions)->data[0]),(unsigned char)((nas_msg.plain.sm.pdu_session_authentication_command.extendedprotocolconfigurationoptions)->data[1]),(unsigned char)((nas_msg.plain.sm.pdu_session_authentication_command.extendedprotocolconfigurationoptions)->data[2]),(unsigned char)((nas_msg.plain.sm.pdu_session_authentication_command.extendedprotocolconfigurationoptions)->data[3]));
    break;

  case PDU_SESSION_AUTHENTICATION_COMPLETE:
    Logger::smf_app().debug("PDU_SESSION_AUTHENTICATION_COMPLETE");
    Logger::smf_app().debug("SM header, extended_protocol_discriminator 0x%x, pdu_session_identity 0x%x, procedure_transaction_identity 0x%x, message type 0x%x", nas_msg.plain.sm.header.extended_protocol_discriminator, nas_msg.plain.sm.header.pdu_session_identity, nas_msg.plain.sm.header.procedure_transaction_identity, nas_msg.plain.sm.header.message_type);
    //Logger::smf_app().debug("eapmessage buffer:0x%x 0x%x\n",(unsigned char)(nas_msg.plain.sm.pdu_session_authentication_complete.eapmessage->data[0]),(unsigned char )(nas_msg.plain.sm.pdu_session_authentication_complete.eapmessage->data[1]));
    //Logger::smf_app().debug("extend_options buffer:0x%x 0x%x 0x%x 0x%x\n",(unsigned char)((nas_msg.plain.sm.pdu_session_authentication_complete.extendedprotocolconfigurationoptions)->data[0]),(unsigned char)((nas_msg.plain.sm.pdu_session_authentication_complete.extendedprotocolconfigurationoptions)->data[1]),(unsigned char)((nas_msg.plain.sm.pdu_session_authentication_complete.extendedprotocolconfigurationoptions)->data[2]),(unsigned char)((nas_msg.plain.sm.pdu_session_authentication_complete.extendedprotocolconfigurationoptions)->data[3]));
    break;

  case PDU_SESSION_AUTHENTICATION_RESULT:
    Logger::smf_app().debug("PDU_SESSION_AUTHENTICATION_RESULT");
    Logger::smf_app().debug("SM header, extended_protocol_discriminator 0x%x, pdu_session_identity 0x%x, procedure_transaction_identity 0x%x, message type 0x%x", nas_msg.plain.sm.header.extended_protocol_discriminator, nas_msg.plain.sm.header.pdu_session_identity, nas_msg.plain.sm.header.procedure_transaction_identity, nas_msg.plain.sm.header.message_type);
    //Logger::smf_app().debug("eapmessage buffer:0x%x 0x%x\n",(unsigned char)(nas_msg.plain.sm.pdu_session_authentication_result.eapmessage->data[0]),(unsigned char )(nas_msg.plain.sm.pdu_session_authentication_result.eapmessage->data[1]));
    //Logger::smf_app().debug("extend_options buffer:0x%x 0x%x 0x%x 0x%x\n",(unsigned char)((nas_msg.plain.sm.pdu_session_authentication_result.extendedprotocolconfigurationoptions)->data[0]),(unsigned char)((nas_msg.plain.sm.pdu_session_authentication_result.extendedprotocolconfigurationoptions)->data[1]),(unsigned char)((nas_msg.plain.sm.pdu_session_authentication_result.extendedprotocolconfigurationoptions)->data[2]),(unsigned char)((nas_msg.plain.sm.pdu_session_authentication_result.extendedprotocolconfigurationoptions)->data[3]));
    break;

  case PDU_SESSION_MODIFICATION_REQUEST:
    Logger::smf_app().debug("PDU_SESSION_MODIFICATION_REQUEST");
    Logger::smf_app().debug("SM header, extended_protocol_discriminator 0x%x, pdu_session_identity 0x%x, procedure_transaction_identity 0x%x, message type 0x%x", nas_msg.plain.sm.header.extended_protocol_discriminator, nas_msg.plain.sm.header.pdu_session_identity, nas_msg.plain.sm.header.procedure_transaction_identity, nas_msg.plain.sm.header.message_type);
    /*    Logger::smf_app().debug("_5gsmcapability bits_5 --- MPTCP:0x%x ATS-LL:0x%x EPT-S1:0x%x MH6-PDU:0x%x RqoS:0x%x\n",
        nas_msg.plain.sm.pdu_session_modification_request._5gsmcapability.is_MPTCP_supported,
        nas_msg.plain.sm.pdu_session_modification_request._5gsmcapability.is_ATSLL_supported,
        nas_msg.plain.sm.pdu_session_modification_request._5gsmcapability.is_EPTS1_supported,
        nas_msg.plain.sm.pdu_session_modification_request._5gsmcapability.is_MH6PDU_supported,
        nas_msg.plain.sm.pdu_session_modification_request._5gsmcapability.is_Rqos_supported);
    Logger::smf_app().debug("_5gsmcause: %#0x",nas_msg.plain.sm.pdu_session_modification_request._5gsmcause);
    Logger::smf_app().debug("maximum bits_11:0x%x",nas_msg.plain.sm.pdu_session_modification_request.maximumnumberofsupportedpacketfilters);
    Logger::smf_app().debug("Always-on bits_1 --- APSR:0x%x",nas_msg.plain.sm.pdu_session_modification_request.alwaysonpdusessionrequested.apsr_requested);
    Logger::smf_app().debug("intergrity buffer:0x%x 0x%x",
        (unsigned char)(nas_msg.plain.sm.pdu_session_modification_request.intergrityprotectionmaximumdatarate->data[0]),
        (unsigned char)(nas_msg.plain.sm.pdu_session_modification_request.intergrityprotectionmaximumdatarate->data[1]));
    Logger::smf_app().debug("qosrules: %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x",
        nas_msg.plain.sm.pdu_session_modification_request.qosrules.lengthofqosrulesie,
        nas_msg.plain.sm.pdu_session_modification_request.qosrules.qosrulesie[0].qosruleidentifer,
        nas_msg.plain.sm.pdu_session_modification_request.qosrules.qosrulesie[0].ruleoperationcode,
        nas_msg.plain.sm.pdu_session_modification_request.qosrules.qosrulesie[0].dqrbit,
        nas_msg.plain.sm.pdu_session_modification_request.qosrules.qosrulesie[0].numberofpacketfilters,
        nas_msg.plain.sm.pdu_session_modification_request.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[0].packetfilterdirection,
        nas_msg.plain.sm.pdu_session_modification_request.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[0].packetfilteridentifier,
        nas_msg.plain.sm.pdu_session_modification_request.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[0].packetfiltercontents.component_type,
        nas_msg.plain.sm.pdu_session_modification_request.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[1].packetfilterdirection,
        nas_msg.plain.sm.pdu_session_modification_request.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[1].packetfilteridentifier,
        nas_msg.plain.sm.pdu_session_modification_request.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[1].packetfiltercontents.component_type,
        nas_msg.plain.sm.pdu_session_modification_request.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[2].packetfilterdirection,
        nas_msg.plain.sm.pdu_session_modification_request.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[2].packetfilteridentifier,
        nas_msg.plain.sm.pdu_session_modification_request.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[2].packetfiltercontents.component_type,
        nas_msg.plain.sm.pdu_session_modification_request.qosrules.qosrulesie[0].qosruleprecedence,
        nas_msg.plain.sm.pdu_session_modification_request.qosrules.qosrulesie[0].segregation,
        nas_msg.plain.sm.pdu_session_modification_request.qosrules.qosrulesie[0].qosflowidentifer);
    Logger::smf_app().debug("qosflowdescriptions: %x %x %x %x %x %x %x %x %x %x %x %x %x \n",
        nas_msg.plain.sm.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionsnumber,
        nas_msg.plain.sm.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[0].qfi,
        nas_msg.plain.sm.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[0].operationcode,
        nas_msg.plain.sm.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[0].e,
        nas_msg.plain.sm.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[0].numberofparameters,
        nas_msg.plain.sm.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[0].parameteridentifier,
        nas_msg.plain.sm.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[0].parametercontents._5qi,
        nas_msg.plain.sm.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[1].parameteridentifier,
        nas_msg.plain.sm.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[1].parametercontents.gfbrormfbr_uplinkordownlink.uint,
        nas_msg.plain.sm.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[1].parametercontents.gfbrormfbr_uplinkordownlink.value,
        nas_msg.plain.sm.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[2].parameteridentifier,
        nas_msg.plain.sm.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[2].parametercontents.gfbrormfbr_uplinkordownlink.uint,
        nas_msg.plain.sm.pdu_session_modification_request.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[2].parametercontents.gfbrormfbr_uplinkordownlink.value);
    Logger::smf_app().debug("extend_options buffer:%x %x %x %x",
        (unsigned char)(nas_msg.plain.sm.pdu_session_modification_request.extendedprotocolconfigurationoptions->data[0]),
        (unsigned char)(nas_msg.plain.sm.pdu_session_modification_request.extendedprotocolconfigurationoptions->data[1]),
        (unsigned char)(nas_msg.plain.sm.pdu_session_modification_request.extendedprotocolconfigurationoptions->data[2]),
        (unsigned char)(nas_msg.plain.sm.pdu_session_modification_request.extendedprotocolconfigurationoptions->data[3]));
     */
    break;

  case PDU_SESSION_MODIFICATION_REJECT:
    Logger::smf_app().debug("PDU_SESSION_MODIFICATION_REJECT");
    Logger::smf_app().debug("SM header, extended_protocol_discriminator 0x%x, pdu_session_identity 0x%x, procedure_transaction_identity 0x%x, message type 0x%x", nas_msg.plain.sm.header.extended_protocol_discriminator, nas_msg.plain.sm.header.pdu_session_identity, nas_msg.plain.sm.header.procedure_transaction_identity, nas_msg.plain.sm.header.message_type);
    /*    Logger::smf_app().debug("_5gsmcause: 0x%x",nas_msg.plain.sm.pdu_session_modification_reject._5gsmcause);
    Logger::smf_app().debug("gprstimer3 --- unit_bits_H3: 0x%x,timeValue_bits_L5: 0x%x",nas_msg.plain.sm.pdu_session_modification_reject.gprstimer3.unit,nas_msg.plain.sm.pdu_session_modification_reject.gprstimer3.timeValue);
    Logger::smf_app().debug("extend_options buffer:0x%x 0x%x 0x%x 0x%x\n",(unsigned char)((nas_msg.plain.sm.pdu_session_modification_reject.extendedprotocolconfigurationoptions)->data[0]),(unsigned char)((nas_msg.plain.sm.pdu_session_modification_reject.extendedprotocolconfigurationoptions)->data[1]),(unsigned char)((nas_msg.plain.sm.pdu_session_modification_reject.extendedprotocolconfigurationoptions)->data[2]),(unsigned char)((nas_msg.plain.sm.pdu_session_modification_reject.extendedprotocolconfigurationoptions)->data[3]));
    Logger::smf_app().debug("_5gsmcongestionreattemptindicator bits_1 --- abo:0x%x",nas_msg.plain.sm.pdu_session_modification_reject._5gsmcongestionreattemptindicator.abo);
     */
    break;

  case PDU_SESSION_MODIFICATION_COMMAND:
    Logger::smf_app().debug("PDU_SESSION_MODIFICATION_COMMAND, start decoding...");
    Logger::smf_app().debug("SM header, extended_protocol_discriminator 0x%x, pdu_session_identity 0x%x, procedure_transaction_identity 0x%x, message type 0x%x", nas_msg.plain.sm.header.extended_protocol_discriminator, nas_msg.plain.sm.header.pdu_session_identity, nas_msg.plain.sm.header.procedure_transaction_identity, nas_msg.plain.sm.header.message_type);
    /*    Logger::smf_app().debug("_5gsmcause: %#0x\n",nas_msg.plain.sm.pdu_session_modification_command._5gsmcause);
    Logger::smf_app().debug("sessionambr: %x %x %x %x\n",
        nas_msg.plain.sm.pdu_session_modification_command.sessionambr.uint_for_session_ambr_for_downlink,
        nas_msg.plain.sm.pdu_session_modification_command.sessionambr.session_ambr_for_downlink,
        nas_msg.plain.sm.pdu_session_modification_command.sessionambr.uint_for_session_ambr_for_uplink,
        nas_msg.plain.sm.pdu_session_modification_command.sessionambr.session_ambr_for_uplink);
    Logger::smf_app().debug("gprstimer -- unit: %#0x, timeValue: %#0x\n",
        nas_msg.plain.sm.pdu_session_modification_command.gprstimer.unit,
        nas_msg.plain.sm.pdu_session_modification_command.gprstimer.timeValue);
    Logger::smf_app().debug("alwaysonpdusessionindication: %#0x\n",nas_msg.plain.sm.pdu_session_modification_command.alwaysonpdusessionindication.apsi_indication);
    Logger::smf_app().debug("qosrules: %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x",
        nas_msg.plain.sm.pdu_session_modification_command.qosrules.lengthofqosrulesie,
        nas_msg.plain.sm.pdu_session_modification_command.qosrules.qosrulesie[0].qosruleidentifer,
        nas_msg.plain.sm.pdu_session_modification_command.qosrules.qosrulesie[0].ruleoperationcode,
        nas_msg.plain.sm.pdu_session_modification_command.qosrules.qosrulesie[0].dqrbit,
        nas_msg.plain.sm.pdu_session_modification_command.qosrules.qosrulesie[0].numberofpacketfilters,
        nas_msg.plain.sm.pdu_session_modification_command.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[0].packetfilterdirection,
        nas_msg.plain.sm.pdu_session_modification_command.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[0].packetfilteridentifier,
        nas_msg.plain.sm.pdu_session_modification_command.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[0].packetfiltercontents.component_type,
        nas_msg.plain.sm.pdu_session_modification_command.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[1].packetfilterdirection,
        nas_msg.plain.sm.pdu_session_modification_command.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[1].packetfilteridentifier,
        nas_msg.plain.sm.pdu_session_modification_command.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[1].packetfiltercontents.component_type,
        nas_msg.plain.sm.pdu_session_modification_command.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[2].packetfilterdirection,
        nas_msg.plain.sm.pdu_session_modification_command.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[2].packetfilteridentifier,
        nas_msg.plain.sm.pdu_session_modification_command.qosrules.qosrulesie[0].packetfilterlist.create_modifyandadd_modifyandreplace[2].packetfiltercontents.component_type,
        nas_msg.plain.sm.pdu_session_modification_command.qosrules.qosrulesie[0].qosruleprecedence,
        nas_msg.plain.sm.pdu_session_modification_command.qosrules.qosrulesie[0].segregation,
        nas_msg.plain.sm.pdu_session_modification_command.qosrules.qosrulesie[0].qosflowidentifer);
    Logger::smf_app().debug("qosflowdescriptions: %x %x %x %x %x %x %x %x %x %x %x %x %x",
        nas_msg.plain.sm.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionsnumber,
        nas_msg.plain.sm.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[0].qfi,
        nas_msg.plain.sm.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[0].operationcode,
        nas_msg.plain.sm.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[0].e,
        nas_msg.plain.sm.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[0].numberofparameters,
        nas_msg.plain.sm.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[0].parameteridentifier,
        nas_msg.plain.sm.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[0].parametercontents._5qi,
        nas_msg.plain.sm.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[1].parameteridentifier,
        nas_msg.plain.sm.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[1].parametercontents.gfbrormfbr_uplinkordownlink.uint,
        nas_msg.plain.sm.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[1].parametercontents.gfbrormfbr_uplinkordownlink.value,
        nas_msg.plain.sm.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[2].parameteridentifier,
        nas_msg.plain.sm.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[2].parametercontents.gfbrormfbr_uplinkordownlink.uint,
        nas_msg.plain.sm.pdu_session_modification_command.qosflowdescriptions.qosflowdescriptionscontents[0].parameterslist[2].parametercontents.gfbrormfbr_uplinkordownlink.value);
    Logger::smf_app().debug("extend_options buffer:%x %x %x %x",
        (unsigned char)(nas_msg.plain.sm.pdu_session_modification_command.extendedprotocolconfigurationoptions->data[0]),
        (unsigned char)(nas_msg.plain.sm.pdu_session_modification_command.extendedprotocolconfigurationoptions->data[1]),
        (unsigned char)(nas_msg.plain.sm.pdu_session_modification_command.extendedprotocolconfigurationoptions->data[2]),
        (unsigned char)(nas_msg.plain.sm.pdu_session_modification_command.extendedprotocolconfigurationoptions->data[3]));
     */
    break;

  case PDU_SESSION_MODIFICATION_COMPLETE:
    Logger::smf_app().debug("PDU_SESSION_MODIFICATION_COMPLETE");
    Logger::smf_app().debug("SM header, extended_protocol_discriminator 0x%x, pdu_session_identity 0x%x, procedure_transaction_identity 0x%x, message type 0x%x", nas_msg.plain.sm.header.extended_protocol_discriminator, nas_msg.plain.sm.header.pdu_session_identity, nas_msg.plain.sm.header.procedure_transaction_identity, nas_msg.plain.sm.header.message_type);
    //Logger::smf_app().debug("extend_options buffer:0x%x 0x%x 0x%x 0x%x\n",(unsigned char)((nas_msg.plain.sm.pdu_session_modification_complete.extendedprotocolconfigurationoptions)->data[0]),(unsigned char)((nas_msg.plain.sm.pdu_session_modification_complete.extendedprotocolconfigurationoptions)->data[1]),(unsigned char)((nas_msg.plain.sm.pdu_session_modification_complete.extendedprotocolconfigurationoptions)->data[2]),(unsigned char)((nas_msg.plain.sm.pdu_session_modification_complete.extendedprotocolconfigurationoptions)->data[3]));
    break;

  case PDU_SESSION_MODIFICATION_COMMANDREJECT:
    Logger::smf_app().debug("PDU_SESSION_MODIFICATION_COMMAND REJECT");
    Logger::smf_app().debug("SM header, extended_protocol_discriminator 0x%x, pdu_session_identity 0x%x, procedure_transaction_identity 0x%x, message type 0x%x", nas_msg.plain.sm.header.extended_protocol_discriminator, nas_msg.plain.sm.header.pdu_session_identity, nas_msg.plain.sm.header.procedure_transaction_identity, nas_msg.plain.sm.header.message_type);
    //Logger::smf_app().debug("_5gsmcause: 0x%x\n",nas_msg.plain.sm.pdu_session_modification_command_reject._5gsmcause);
    //Logger::smf_app().debug("extend_options buffer:0x%x 0x%x 0x%x 0x%x\n",(unsigned char)((nas_msg.plain.sm.pdu_session_modification_command_reject.extendedprotocolconfigurationoptions)->data[0]),(unsigned char)((nas_msg.plain.sm.pdu_session_modification_command_reject.extendedprotocolconfigurationoptions)->data[1]),(unsigned char)((nas_msg.plain.sm.pdu_session_modification_command_reject.extendedprotocolconfigurationoptions)->data[2]),(unsigned char)((nas_msg.plain.sm.pdu_session_modification_command_reject.extendedprotocolconfigurationoptions)->data[3]));
    break;

  case PDU_SESSION_RELEASE_REQUEST:
    Logger::smf_app().debug("PDU_SESSION_RELEASE_REQUEST");
    Logger::smf_app().debug("SM header, extended_protocol_discriminator 0x%x, pdu_session_identity 0x%x, procedure_transaction_identity 0x%x, message type 0x%x", nas_msg.plain.sm.header.extended_protocol_discriminator, nas_msg.plain.sm.header.pdu_session_identity, nas_msg.plain.sm.header.procedure_transaction_identity, nas_msg.plain.sm.header.message_type);
    //Logger::smf_app().debug("_5gsmcause: 0x%x\n",nas_msg.plain.sm.pdu_session_release_request._5gsmcause);
    //Logger::smf_app().debug("extend_options buffer:0x%x 0x%x 0x%x 0x%x\n",(unsigned char)((nas_msg.plain.sm.pdu_session_release_request.extendedprotocolconfigurationoptions)->data[0]),(unsigned char)((nas_msg.plain.sm.pdu_session_release_request.extendedprotocolconfigurationoptions)->data[1]),(unsigned char)((nas_msg.plain.sm.pdu_session_release_request.extendedprotocolconfigurationoptions)->data[2]),(unsigned char)((nas_msg.plain.sm.pdu_session_release_request.extendedprotocolconfigurationoptions)->data[3]));
    break;

  case PDU_SESSION_RELEASE_REJECT:
    Logger::smf_app().debug("PDU_SESSION_RELEASE_REJECT");
    Logger::smf_app().debug("SM header, extended_protocol_discriminator 0x%x, pdu_session_identity 0x%x, procedure_transaction_identity 0x%x, message type 0x%x", nas_msg.plain.sm.header.extended_protocol_discriminator, nas_msg.plain.sm.header.pdu_session_identity, nas_msg.plain.sm.header.procedure_transaction_identity, nas_msg.plain.sm.header.message_type);
    //Logger::smf_app().debug("_5gsmcause: 0x%x\n",nas_msg.plain.sm.pdu_session_release_reject._5gsmcause);
    //Logger::smf_app().debug("extend_options buffer:0x%x 0x%x 0x%x 0x%x\n",(unsigned char)((nas_msg.plain.sm.pdu_session_release_reject.extendedprotocolconfigurationoptions)->data[0]),(unsigned char)((nas_msg.plain.sm.pdu_session_release_reject.extendedprotocolconfigurationoptions)->data[1]),(unsigned char)((nas_msg.plain.sm.pdu_session_release_reject.extendedprotocolconfigurationoptions)->data[2]),(unsigned char)((nas_msg.plain.sm.pdu_session_release_reject.extendedprotocolconfigurationoptions)->data[3]));
    break;

  case PDU_SESSION_RELEASE_COMMAND:
    Logger::smf_app().debug("PDU_SESSION_RELEASE_COMMAND");
    Logger::smf_app().debug("SM header, extended_protocol_discriminator 0x%x, pdu_session_identity 0x%x, procedure_transaction_identity 0x%x, message type 0x%x", nas_msg.plain.sm.header.extended_protocol_discriminator, nas_msg.plain.sm.header.pdu_session_identity, nas_msg.plain.sm.header.procedure_transaction_identity, nas_msg.plain.sm.header.message_type);
    /*    Logger::smf_app().debug("_5gsmcause: 0x%x\n",nas_msg.plain.sm.pdu_session_release_command._5gsmcause);
    Logger::smf_app().debug("gprstimer3 --- unit_bits_H3: 0x%x,timeValue_bits_L5: 0x%x\n",nas_msg.plain.sm.pdu_session_release_command.gprstimer3.unit,nas_msg.plain.sm.pdu_session_release_command.gprstimer3.timeValue);
    Logger::smf_app().debug("eapmessage buffer:0x%x 0x%x\n",(unsigned char)(nas_msg.plain.sm.pdu_session_release_command.eapmessage->data[0]),(unsigned char )(nas_msg.plain.sm.pdu_session_release_command.eapmessage->data[1]));
    Logger::smf_app().debug("_5gsmcongestionreattemptindicator bits_1 --- abo:0x%x\n",nas_msg.plain.sm.pdu_session_release_command._5gsmcongestionreattemptindicator.abo);
    Logger::smf_app().debug("extend_options buffer:0x%x 0x%x 0x%x 0x%x\n",(unsigned char)((nas_msg.plain.sm.pdu_session_release_command.extendedprotocolconfigurationoptions)->data[0]),(unsigned char)((nas_msg.plain.sm.pdu_session_release_command.extendedprotocolconfigurationoptions)->data[1]),(unsigned char)((nas_msg.plain.sm.pdu_session_release_command.extendedprotocolconfigurationoptions)->data[2]),(unsigned char)((nas_msg.plain.sm.pdu_session_release_command.extendedprotocolconfigurationoptions)->data[3]));
     */
    break;

  case PDU_SESSION_RELEASE_COMPLETE:
    Logger::smf_app().debug("PDU_SESSION_RELEASE_COMPLETE");
    Logger::smf_app().debug("SM header, extended_protocol_discriminator 0x%x, pdu_session_identity 0x%x, procedure_transaction_identity 0x%x, message type 0x%x", nas_msg.plain.sm.header.extended_protocol_discriminator, nas_msg.plain.sm.header.pdu_session_identity, nas_msg.plain.sm.header.procedure_transaction_identity, nas_msg.plain.sm.header.message_type);
    //Logger::smf_app().debug("_5gsmcause: 0x%x\n",nas_msg.plain.sm.pdu_session_release_complete._5gsmcause);
    //Logger::smf_app().debug("extend_options buffer:0x%x 0x%x 0x%x 0x%x\n",(unsigned char)((nas_msg.plain.sm.pdu_session_release_complete.extendedprotocolconfigurationoptions)->data[0]),(unsigned char)((nas_msg.plain.sm.pdu_session_release_complete.extendedprotocolconfigurationoptions)->data[1]),(unsigned char)((nas_msg.plain.sm.pdu_session_release_complete.extendedprotocolconfigurationoptions)->data[2]),(unsigned char)((nas_msg.plain.sm.pdu_session_release_complete.extendedprotocolconfigurationoptions)->data[3]));
    break;

  case _5GSM_STATUS:
    Logger::smf_app().debug("5GSM_STATUS");
    Logger::smf_app().debug("SM header,extended_protocol_discriminator:0x%x,pdu_session_identity:0x%x,procedure_transaction_identity:0x%x, message type:0x%x\n", nas_msg.plain.sm.header.extended_protocol_discriminator,nas_msg.plain.sm.header.pdu_session_identity,nas_msg.plain.sm.header.procedure_transaction_identity,nas_msg.plain.sm.header.message_type);
    //Logger::smf_app().debug("_5gsmcause: 0x%x\n",nas_msg.plain.sm._5gsm_status._5gsmcause);
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



