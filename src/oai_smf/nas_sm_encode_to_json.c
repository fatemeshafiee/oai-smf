#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "nas_message.h"
#include "bstrlib.h"
#include "mmData.h"
#include "common_types.h"
#include "common_defs.h"

#include "nas_sm_encode_to_json.h"

#define DIR_SM_ENCODE "../../build/smf/build/sm_encode_file"
static void creat_dir_sm_encode(void)
{
	if(access(DIR_SM_ENCODE,0) < 0)
    {
    	if(mkdir(DIR_SM_ENCODE,0766) < 0)
		{
			fprintf(stderr,"%s directory doesn't exist.\n",DIR_SM_ENCODE);
    	}
	}
}

#define BUF_LEN 512
int  sm_encode_establishment_request(void)
{
	printf("PDU_SESSION_ESTABLISHMENT_REQUEST------------ encode start\n");
	int size = NAS_MESSAGE_SECURITY_HEADER_SIZE;
	int bytes = 0;

	nas_message_t	nas_msg;
	memset (&nas_msg,		 0, sizeof (nas_message_t));

	nas_msg.header.extended_protocol_discriminator = EPD_5GS_SESSION_MANAGEMENT_MESSAGES;
	nas_msg.header.security_header_type = SECURITY_HEADER_TYPE_INTEGRITY_PROTECTED_CYPHERED;
	uint8_t sequencenumber = 0xfe;
	//uint32_t mac = 0xffffeeee;
	uint32_t mac = 0xffee;
	nas_msg.header.sequence_number = sequencenumber;
	nas_msg.header.message_authentication_code= mac;

	nas_msg.security_protected.header = nas_msg.header;

	SM_msg * sm_msg;
	// memset (&sm_msg->specific_msg.pdu_session_establishment_request,		 0, sizeof (pdu_session_establishment_request_msg));
	sm_msg = &nas_msg.security_protected.plain.sm;
	sm_msg->header.extended_protocol_discriminator = EPD_5GS_SESSION_MANAGEMENT_MESSAGES;
	sm_msg->header.pdu_session_identity = 1;
	sm_msg->header.procedure_transaction_identity = 1;
	sm_msg->header.message_type = PDU_SESSION_ESTABLISHMENT_REQUEST;

	/*********************sm_msg->specific_msg.pdu_session_establishment_request statr******************************/

	//memset (&sm_msg->specific_msg.pdu_session_establishment_request,		 0, sizeof (pdu_session_establishment_request_msg));

#if 0
	sm_msg->specific_msg.pdu_session_establishment_request.extendedprotocoldiscriminator = 0X2E;


	bstring pdusessionidentity_tmp = bfromcstralloc(10, "\0");
	uint8_t bitStream_pdusessionidentity = 0X01;
	pdusessionidentity_tmp->data = (unsigned char *)(&bitStream_pdusessionidentity);
	pdusessionidentity_tmp->slen = 1;
	sm_msg->specific_msg.pdu_session_establishment_request.pdusessionidentity = pdusessionidentity_tmp;

	bstring proceduretransactionidentity_tmp = bfromcstralloc(10, "\0");
	uint8_t bitStream_proceduretransactionidentity = 0X01;
	proceduretransactionidentity_tmp->data = (unsigned char *)(&bitStream_proceduretransactionidentity);
	proceduretransactionidentity_tmp->slen = 1;
	sm_msg->specific_msg.pdu_session_establishment_request.proceduretransactionidentity = proceduretransactionidentity_tmp;

	sm_msg->specific_msg.pdu_session_establishment_request.messagetype = 0XC1;
#endif


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

	unsigned char bitStream_smpdudnrequestcontainer[3];
	bitStream_smpdudnrequestcontainer[0] = 0x11;
	bitStream_smpdudnrequestcontainer[1] = 0x22;
	bitStream_smpdudnrequestcontainer[2] = 0x33;
	bstring smpdudnrequestcontainer_tmp = bfromcstralloc(3, "\0");
	//smpdudnrequestcontainer_tmp->data = bitStream_smpdudnrequestcontainer;
	smpdudnrequestcontainer_tmp->slen = 3;
	memcpy(smpdudnrequestcontainer_tmp->data,bitStream_smpdudnrequestcontainer,sizeof(bitStream_smpdudnrequestcontainer));
	sm_msg->specific_msg.pdu_session_establishment_request.smpdudnrequestcontainer = smpdudnrequestcontainer_tmp;

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

	/*********************sm_msg->specific_msg.pdu_session_establishment_request end******************************/

	size += MESSAGE_TYPE_MAXIMUM_LENGTH;

	//memcpy(&nas_msg.plain.sm,&nas_msg.security_protected.plain.sm,sizeof(nas_msg.security_protected.plain.sm));
	nas_msg.plain.sm = *sm_msg;

	//complete sm msg content
	if(size <= 0){
		return -1;
	}

	//construct security context
	fivegmm_security_context_t * security = (fivegmm_security_context_t *)calloc(1,sizeof(fivegmm_security_context_t));
	security->selected_algorithms.encryption = NAS_SECURITY_ALGORITHMS_NEA1;
	security->dl_count.overflow = 0xffff;
	security->dl_count.seq_num =  0x23;
	security->knas_enc[0] = 0x14;
	security->selected_algorithms.integrity = NAS_SECURITY_ALGORITHMS_NIA1;
	security->knas_int[0] = 0x41;
	//complete sercurity context

	int length = BUF_LEN;
	unsigned char data[BUF_LEN] = {'\0'};
	memset(data,0,sizeof(data));

	bstring  info = bfromcstralloc(length, "\0");//info the nas_message_encode result

#if 0
	printf("1 start nas_message_encode \n");
	printf("security %p\n",security);
	printf("info %p\n",info);
#endif

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

	printf("intergrity buffer:0x%x 0x%x\n",(unsigned char)((sm_msg->specific_msg.pdu_session_establishment_request.intergrityprotectionmaximumdatarate)->data[0]),(unsigned char )((sm_msg->specific_msg.pdu_session_establishment_request.intergrityprotectionmaximumdatarate)->data[1]));
	printf("_pdusessiontype bits_3:0x%x\n",sm_msg->specific_msg.pdu_session_establishment_request._pdusessiontype.pdu_session_type_value);
	printf("sscmode bits_3:0x%x\n",sm_msg->specific_msg.pdu_session_establishment_request.sscmode.ssc_mode_value);
	printf("_5gsmcapability bits_5 --- MPTCP:0x%x ATS-LL:0x%x EPT-S1:0x%x MH6-PDU:0x%x RqoS:0x%x\n",sm_msg->specific_msg.pdu_session_establishment_request._5gsmcapability.is_MPTCP_supported,sm_msg->specific_msg.pdu_session_establishment_request._5gsmcapability.is_ATSLL_supported,sm_msg->specific_msg.pdu_session_establishment_request._5gsmcapability.is_EPTS1_supported,sm_msg->specific_msg.pdu_session_establishment_request._5gsmcapability.is_MH6PDU_supported,sm_msg->specific_msg.pdu_session_establishment_request._5gsmcapability.is_Rqos_supported);
	printf("maximum bits_11:0x%x\n",sm_msg->specific_msg.pdu_session_establishment_request.maximumnumberofsupportedpacketfilters);
	printf("Always-on bits_1 --- APSR:0x%x\n",sm_msg->specific_msg.pdu_session_establishment_request.alwaysonpdusessionrequested.apsr_requested);
	printf("sm_pdu_dn buffer:0x%x 0x%x 0x%x\n",(unsigned char)((sm_msg->specific_msg.pdu_session_establishment_request.smpdudnrequestcontainer)->data[0]),(unsigned char)((sm_msg->specific_msg.pdu_session_establishment_request.smpdudnrequestcontainer)->data[1]),(unsigned char)((sm_msg->specific_msg.pdu_session_establishment_request.smpdudnrequestcontainer)->data[2]));
	printf("extend_options buffer:0x%x 0x%x 0x%x 0x%x\n",(unsigned char)((sm_msg->specific_msg.pdu_session_establishment_request.extendedprotocolconfigurationoptions)->data[0]),(unsigned char)((sm_msg->specific_msg.pdu_session_establishment_request.extendedprotocolconfigurationoptions)->data[1]),(unsigned char)((sm_msg->specific_msg.pdu_session_establishment_request.extendedprotocolconfigurationoptions)->data[2]),(unsigned char)((sm_msg->specific_msg.pdu_session_establishment_request.extendedprotocolconfigurationoptions)->data[3]));

	//bytes = nas_message_encode (data, &nas_msg, 60/*don't know the size*/, security);
	bytes = nas_message_encode (data, &nas_msg, sizeof(data)/*don't know the size*/, security);


	printf("Data = ");

	for(int i = 0;i<bytes;i++)
		printf("%02x ",data[i]);
	printf("\n");

	info->data = data;
	info->slen = bytes;

	/***********creat bin file************************/

	creat_dir_sm_encode();

	char datahex[512];
	for(int i=0;i<bytes;i++)
		sprintf(datahex+i*2,"%02x",data[i]);

	FILE *fp;
	fp = fopen("../../build/smf/build/sm_encode_file/sm_encode_establishment_request.txt","w");
	fwrite(datahex,bytes*2/*sizeof(data)*/,1,fp);

	fclose(fp);
	/*****************  end  ************************/
	printf("PDU_SESSION_ESTABLISHMENT_REQUEST------------ encode end\n");
	return  0;
}

int sm_encode_establishment_accept(void)
{
	printf("PDU_SESSION_ESTABLISHMENT_ACCPET------------ encode start\n");
	int size = NAS_MESSAGE_SECURITY_HEADER_SIZE;
	int bytes = 0;

	nas_message_t	nas_msg;
	memset (&nas_msg,		 0, sizeof (nas_message_t));

	nas_msg.header.extended_protocol_discriminator = EPD_5GS_SESSION_MANAGEMENT_MESSAGES;
	nas_msg.header.security_header_type = SECURITY_HEADER_TYPE_INTEGRITY_PROTECTED_CYPHERED;
	uint8_t sequencenumber = 0xfe;
	//uint32_t mac = 0xffffeeee;
	uint32_t mac = 0xffee;
	nas_msg.header.sequence_number = sequencenumber;
	nas_msg.header.message_authentication_code= mac;

	nas_msg.security_protected.header = nas_msg.header;

	SM_msg * sm_msg;
	// memset (&sm_msg->specific_msg.pdu_session_establishment_request,		 0, sizeof (pdu_session_establishment_request_msg));
	sm_msg = &nas_msg.security_protected.plain.sm;
	sm_msg->header.extended_protocol_discriminator = EPD_5GS_SESSION_MANAGEMENT_MESSAGES;
	sm_msg->header.pdu_session_identity = 1;
	sm_msg->header.procedure_transaction_identity = 1;
	sm_msg->header.message_type = PDU_SESSION_ESTABLISHMENT_ACCPET;

	/*********************sm_msg->specific_msg.pdu_session_establishment_accept statr******************************/

	//memset (&sm_msg->specific_msg.pdu_session_establishment_request,		 0, sizeof (pdu_session_establishment_request_msg));

#if 0
	sm_msg->specific_msg.pdu_session_establishment_accept.extendedprotocoldiscriminator = 0X2E;


	bstring pdusessionidentity_tmp = bfromcstralloc(10, "\0");
	uint8_t bitStream_pdusessionidentity = 0X01;
	pdusessionidentity_tmp->data = (unsigned char *)(&bitStream_pdusessionidentity);
	pdusessionidentity_tmp->slen = 1;
	sm_msg->specific_msg.pdu_session_establishment_accept.pdusessionidentity = pdusessionidentity_tmp;

	bstring proceduretransactionidentity_tmp = bfromcstralloc(10, "\0");
	uint8_t bitStream_proceduretransactionidentity = 0X01;
	proceduretransactionidentity_tmp->data = (unsigned char *)(&bitStream_proceduretransactionidentity);
	proceduretransactionidentity_tmp->slen = 1;
	sm_msg->specific_msg.pdu_session_establishment_accept.proceduretransactionidentity = proceduretransactionidentity_tmp;

	sm_msg->specific_msg.pdu_session_establishment_accept.messagetype = 0XC1;
#endif



	sm_msg->specific_msg.pdu_session_establishment_accept.presence = 0xffff;

	sm_msg->specific_msg.pdu_session_establishment_accept._pdusessiontype.pdu_session_type_value = 0x01;

	sm_msg->specific_msg.pdu_session_establishment_accept.sscmode.ssc_mode_value = 0x01;


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


	sm_msg->specific_msg.pdu_session_establishment_accept.qosrules.lengthofqosrulesie = 2;
	sm_msg->specific_msg.pdu_session_establishment_accept.qosrules.qosrulesie = qosrulesie;

	sm_msg->specific_msg.pdu_session_establishment_accept.sessionambr.uint_for_session_ambr_for_downlink = AMBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_1KBPS;
	sm_msg->specific_msg.pdu_session_establishment_accept.sessionambr.session_ambr_for_downlink = (AMBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_4KBPS << 8) + (AMBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_16KBPS);
	sm_msg->specific_msg.pdu_session_establishment_accept.sessionambr.uint_for_session_ambr_for_uplink = AMBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_64KBPS;
	sm_msg->specific_msg.pdu_session_establishment_accept.sessionambr.session_ambr_for_uplink = (AMBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_256KBPS << 8) + (AMBR_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_1MBPS);

	sm_msg->specific_msg.pdu_session_establishment_accept._5gsmcause = 0b00001000;

	sm_msg->specific_msg.pdu_session_establishment_accept.pduaddress.pdu_session_type_value = PDU_ADDRESS_IPV4;
	unsigned char bitStream_pdu_address_information[4];
	bitStream_pdu_address_information[0] = 0x11;
	bitStream_pdu_address_information[1] = 0x22;
	bitStream_pdu_address_information[2] = 0x33;
	bitStream_pdu_address_information[3] = 0x44;
	bstring pdu_address_information_tmp = bfromcstralloc(4, "\0");
	pdu_address_information_tmp->slen = 4;
	memcpy(pdu_address_information_tmp->data,bitStream_pdu_address_information,sizeof(bitStream_pdu_address_information));
	sm_msg->specific_msg.pdu_session_establishment_accept.pduaddress.pdu_address_information = pdu_address_information_tmp;

	sm_msg->specific_msg.pdu_session_establishment_accept.gprstimer.unit = GPRSTIMER_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_2_SECONDS;
	sm_msg->specific_msg.pdu_session_establishment_accept.gprstimer.timeValue = 0;

	sm_msg->specific_msg.pdu_session_establishment_accept.snssai.len = SST_AND_SD_LENGHT;
	sm_msg->specific_msg.pdu_session_establishment_accept.snssai.sst = 0x66;
	sm_msg->specific_msg.pdu_session_establishment_accept.snssai.sd = 0x123456;

	sm_msg->specific_msg.pdu_session_establishment_accept.alwaysonpdusessionindication.apsi_indication = ALWAYSON_PDU_SESSION_REQUIRED;

	//sm_msg->specific_msg.pdu_session_establishment_accept.mappedepsbearercontexts

	unsigned char bitStream_eapmessage[2] = {0x01,0x02};
    bstring eapmessage_tmp = bfromcstralloc(2, "\0");
    eapmessage_tmp->slen = 2;
    memcpy(eapmessage_tmp->data,bitStream_eapmessage,sizeof(bitStream_eapmessage));
	sm_msg->specific_msg.pdu_session_establishment_accept.eapmessage = eapmessage_tmp;

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
	qosflowdescriptionscontents[1].parameterslist = NULL;

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

	/*********************sm_msg->specific_msg.pdu_session_establishment_accept end******************************/

	size += MESSAGE_TYPE_MAXIMUM_LENGTH;

	//memcpy(&nas_msg.plain.sm,&nas_msg.security_protected.plain.sm,sizeof(nas_msg.security_protected.plain.sm));
	printf("nas_msg.security_protected.plain.sm = %d\n",sizeof(nas_msg.security_protected.plain.sm));
	nas_msg.plain.sm = *sm_msg;

	//complete sm msg content
	if(size <= 0){
		return -1;
	}

	//construct security context
	fivegmm_security_context_t * security = (fivegmm_security_context_t *)calloc(1,sizeof(fivegmm_security_context_t));
	security->selected_algorithms.encryption = NAS_SECURITY_ALGORITHMS_NEA1;
	security->dl_count.overflow = 0xffff;
	security->dl_count.seq_num =  0x23;
	security->knas_enc[0] = 0x14;
	security->selected_algorithms.integrity = NAS_SECURITY_ALGORITHMS_NIA1;
	security->knas_int[0] = 0x41;
	//complete sercurity context

	int length = BUF_LEN;
	unsigned char data[BUF_LEN] = {'\0'};
	memset(data,0,sizeof(data));

	bstring  info = bfromcstralloc(length, "\0");//info the nas_message_encode result

#if 0
	printf("1 start nas_message_encode \n");
	printf("security %p\n",security);
	printf("info %p\n",info);
#endif

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

	printf("_pdusessiontype bits_3: %#0x\n",sm_msg->specific_msg.pdu_session_establishment_accept._pdusessiontype.pdu_session_type_value);
	printf("sscmode bits_3: %#0x\n",sm_msg->specific_msg.pdu_session_establishment_accept.sscmode.ssc_mode_value);
	printf("qosrules: %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x\n",
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

	printf("sessionambr: %x %x %x %x\n",
			sm_msg->specific_msg.pdu_session_establishment_accept.sessionambr.uint_for_session_ambr_for_downlink,
			sm_msg->specific_msg.pdu_session_establishment_accept.sessionambr.session_ambr_for_downlink,
			sm_msg->specific_msg.pdu_session_establishment_accept.sessionambr.uint_for_session_ambr_for_uplink,
			sm_msg->specific_msg.pdu_session_establishment_accept.sessionambr.session_ambr_for_uplink);

	printf("_5gsmcause: %#0x\n",sm_msg->specific_msg.pdu_session_establishment_accept._5gsmcause);

	printf("pduaddress: %x %x %x %x %x\n",
			sm_msg->specific_msg.pdu_session_establishment_accept.pduaddress.pdu_session_type_value,
			(unsigned char)(sm_msg->specific_msg.pdu_session_establishment_accept.pduaddress.pdu_address_information->data[0]),
			(unsigned char)(sm_msg->specific_msg.pdu_session_establishment_accept.pduaddress.pdu_address_information->data[1]),
			(unsigned char)(sm_msg->specific_msg.pdu_session_establishment_accept.pduaddress.pdu_address_information->data[2]),
			(unsigned char)(sm_msg->specific_msg.pdu_session_establishment_accept.pduaddress.pdu_address_information->data[3]));

	printf("gprstimer -- unit: %#0x, timeValue: %#0x\n",
			sm_msg->specific_msg.pdu_session_establishment_accept.gprstimer.unit,
			sm_msg->specific_msg.pdu_session_establishment_accept.gprstimer.timeValue);

	printf("snssai -- len: %#0x, sst: %#0x, sd: %#0x\n",
			sm_msg->specific_msg.pdu_session_establishment_accept.snssai.len,
			sm_msg->specific_msg.pdu_session_establishment_accept.snssai.sst,
			sm_msg->specific_msg.pdu_session_establishment_accept.snssai.sd);

	printf("alwaysonpdusessionindication: %#0x\n",sm_msg->specific_msg.pdu_session_establishment_accept.alwaysonpdusessionindication.apsi_indication);

	//printf("mappedepsbearercontexts");

	printf("eapmessage buffer:%x %x\n",
			(unsigned char)(sm_msg->specific_msg.pdu_session_establishment_accept.eapmessage->data[0]),
			(unsigned char)(sm_msg->specific_msg.pdu_session_establishment_accept.eapmessage->data[1]));

	printf("qosflowdescriptions: %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x\n",
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

	printf("extend_options buffer:%x %x %x %x\n",
			(unsigned char)(sm_msg->specific_msg.pdu_session_establishment_accept.extendedprotocolconfigurationoptions->data[0]),
			(unsigned char)(sm_msg->specific_msg.pdu_session_establishment_accept.extendedprotocolconfigurationoptions->data[1]),
			(unsigned char)(sm_msg->specific_msg.pdu_session_establishment_accept.extendedprotocolconfigurationoptions->data[2]),
			(unsigned char)(sm_msg->specific_msg.pdu_session_establishment_accept.extendedprotocolconfigurationoptions->data[3]));

	printf("dnn buffer:%x %x %x\n",
			(unsigned char)(sm_msg->specific_msg.pdu_session_establishment_accept.dnn->data[0]),
			(unsigned char)(sm_msg->specific_msg.pdu_session_establishment_accept.dnn->data[1]),
			(unsigned char)(sm_msg->specific_msg.pdu_session_establishment_accept.dnn->data[2]));

	//bytes = nas_message_encode (data, &nas_msg, 60/*don't know the size*/, security);
	bytes = nas_message_encode (data, &nas_msg, sizeof(data)/*don't know the size*/, security);


	printf("Data = ");

	for(int i = 0;i<bytes;i++)
		printf("%02x ",data[i]);
	printf("\n");

	info->data = data;
	info->slen = bytes;

	/***********creat bin file************************/

	creat_dir_sm_encode();

	char datahex[512];
	for(int i=0;i<bytes;i++)
		sprintf(datahex+i*2,"%02x",data[i]);

	FILE *fp;
	fp = fopen("../../build/smf/build/sm_encode_file/sm_encode_establishment_accept.txt","w");
	fwrite(datahex,bytes*2/*sizeof(data)*/,1,fp);

	fclose(fp);
	/*****************  end  ************************/

	printf("PDU_SESSION_ESTABLISHMENT_ACCPET------------ encode end\n");
	return  0;
}

int sm_encode_establishment_reject(void)
{
	printf("PDU_SESSION_ESTABLISHMENT_REJECT------------ encode start\n");
	int size = NAS_MESSAGE_SECURITY_HEADER_SIZE;
	int bytes = 0;

	nas_message_t	nas_msg;
	memset (&nas_msg,		 0, sizeof (nas_message_t));
	nas_msg.header.extended_protocol_discriminator = EPD_5GS_SESSION_MANAGEMENT_MESSAGES;
	nas_msg.header.security_header_type = SECURITY_HEADER_TYPE_INTEGRITY_PROTECTED_CYPHERED;
	uint8_t sequencenumber = 0xfe;
	//uint32_t mac = 0xffffeeee;
	uint32_t mac = 0xffee;
	nas_msg.header.sequence_number = sequencenumber;
	nas_msg.header.message_authentication_code= mac;
	nas_msg.security_protected.header = nas_msg.header;
	SM_msg * sm_msg;
	// memset (&sm_msg->specific_msg.pdu_session_establishment_request,		 0, sizeof (pdu_session_establishment_request_msg));
	sm_msg = &nas_msg.security_protected.plain.sm;
	sm_msg->header.extended_protocol_discriminator = EPD_5GS_SESSION_MANAGEMENT_MESSAGES;
	sm_msg->header.pdu_session_identity = 1;
    sm_msg->header.procedure_transaction_identity = 1;
	sm_msg->header.message_type = PDU_SESSION_ESTABLISHMENT_REJECT;

/*********************sm_msg->specific_msg.pdu_session_establishment_reject statr******************************/

    #if 0
	sm_msg->specific_msg.pdu_session_establishment_reject.extendedprotocoldiscriminator = 0X2E;


	bstring pdusessionidentity_tmp = bfromcstralloc(10, "\0");
	uint8_t bitStream_pdusessionidentity = 0X01;
	pdusessionidentity_tmp->data = (unsigned char *)(&bitStream_pdusessionidentity);
	pdusessionidentity_tmp->slen = 1;
	sm_msg->specific_msg.pdu_session_establishment_reject.pdusessionidentity = pdusessionidentity_tmp;

	bstring proceduretransactionidentity_tmp = bfromcstralloc(10, "\0");
	uint8_t bitStream_proceduretransactionidentity = 0X01;
	proceduretransactionidentity_tmp->data = (unsigned char *)(&bitStream_proceduretransactionidentity);
	proceduretransactionidentity_tmp->slen = 1;
    sm_msg->specific_msg.pdu_session_establishment_reject.proceduretransactionidentity = proceduretransactionidentity_tmp;

    sm_msg->specific_msg.pdu_session_establishment_reject.messagetype = 0XC1;
    #endif

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

/*********************sm_msg->specific_msg.pdu_session_establishment_reject end******************************/

	size += MESSAGE_TYPE_MAXIMUM_LENGTH;

	//memcpy(&nas_msg.plain.sm,&nas_msg.security_protected.plain.sm,sizeof(nas_msg.security_protected.plain.sm));
	nas_msg.plain.sm = *sm_msg;

	//complete sm msg content
	if(size <= 0){
		return -1;
	}

	//construct security context
	fivegmm_security_context_t * security = (fivegmm_security_context_t *)calloc(1,sizeof(fivegmm_security_context_t));
	security->selected_algorithms.encryption = NAS_SECURITY_ALGORITHMS_NEA1;
	security->dl_count.overflow = 0xffff;
	security->dl_count.seq_num =  0x23;
	security->knas_enc[0] = 0x14;
	security->selected_algorithms.integrity = NAS_SECURITY_ALGORITHMS_NIA1;
	security->knas_int[0] = 0x41;
	//complete sercurity context

	int length = BUF_LEN;
	unsigned char data[BUF_LEN] = {'\0'};

	bstring  info = bfromcstralloc(length, "\0");//info the nas_message_encode result

	#if 0
	printf("1 start nas_message_encode \n");
	printf("security %p\n",security);
	printf("info %p\n",info);
	#endif

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
	bytes = nas_message_encode (data, &nas_msg, sizeof(data)/*don't know the size*/, security);


	printf("Data = ");

	for(int i = 0;i<bytes;i++)
		printf("%02x ",data[i]);
	printf("\n");

	info->data = data;
	info->slen = bytes;

	/***********creat bin file************************/

	creat_dir_sm_encode();

	char datahex[512];
	for(int i=0;i<bytes;i++)
		sprintf(datahex+i*2,"%02x",data[i]);

	FILE *fp;
	fp = fopen("../../build/smf/build/sm_encode_file/sm_encode_establishment_reject.txt","w");
	fwrite(datahex,bytes*2/*sizeof(data)*/,1,fp);

	fclose(fp);
	/*****************  end  ************************/

    printf("PDU_SESSION_ESTABLISHMENT_REJECT------------ encode end\n");
	return  0;
}

int sm_encode_authentication_command(void)
{
	printf("PDU_SESSION_AUTHENTICATION_COMMAND------------ encode start\n");
	int size = NAS_MESSAGE_SECURITY_HEADER_SIZE;
	int bytes = 0;

	nas_message_t	nas_msg;
	memset (&nas_msg,		 0, sizeof (nas_message_t));
	nas_msg.header.extended_protocol_discriminator = EPD_5GS_SESSION_MANAGEMENT_MESSAGES;
	nas_msg.header.security_header_type = SECURITY_HEADER_TYPE_INTEGRITY_PROTECTED_CYPHERED;
	uint8_t sequencenumber = 0xfe;
	//uint32_t mac = 0xffffeeee;
	uint32_t mac = 0xffee;
	nas_msg.header.sequence_number = sequencenumber;
	nas_msg.header.message_authentication_code= mac;
	nas_msg.security_protected.header = nas_msg.header;
	SM_msg * sm_msg;
	// memset (&sm_msg->specific_msg.pdu_session_establishment_request,		 0, sizeof (pdu_session_establishment_request_msg));
	sm_msg = &nas_msg.security_protected.plain.sm;
	sm_msg->header.extended_protocol_discriminator = EPD_5GS_SESSION_MANAGEMENT_MESSAGES;
	sm_msg->header.pdu_session_identity = 1;
    sm_msg->header.procedure_transaction_identity = 1;
	sm_msg->header.message_type = PDU_SESSION_AUTHENTICATION_COMMAND;

/*********************sm_msg->specific_msg.pdu_session_authentication_command statr******************************/

    #if 0
	sm_msg->specific_msg.pdu_session_authentication_command.extendedprotocoldiscriminator = 0X2E;


	bstring pdusessionidentity_tmp = bfromcstralloc(10, "\0");
	uint8_t bitStream_pdusessionidentity = 0X01;
	pdusessionidentity_tmp->data = (unsigned char *)(&bitStream_pdusessionidentity);
	pdusessionidentity_tmp->slen = 1;
	sm_msg->specific_msg.pdu_session_authentication_command.pdusessionidentity = pdusessionidentity_tmp;

	bstring proceduretransactionidentity_tmp = bfromcstralloc(10, "\0");
	uint8_t bitStream_proceduretransactionidentity = 0X01;
	proceduretransactionidentity_tmp->data = (unsigned char *)(&bitStream_proceduretransactionidentity);
	proceduretransactionidentity_tmp->slen = 1;
    sm_msg->specific_msg.pdu_session_authentication_command.proceduretransactionidentity = proceduretransactionidentity_tmp;

    sm_msg->specific_msg.pdu_session_authentication_command.messagetype = 0XC1;
    #endif

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

	size += MESSAGE_TYPE_MAXIMUM_LENGTH;

	//memcpy(&nas_msg.plain.sm,&nas_msg.security_protected.plain.sm,sizeof(nas_msg.security_protected.plain.sm));
	nas_msg.plain.sm = *sm_msg;

	//complete sm msg content
	if(size <= 0){
		return -1;
	}

	//construct security context
	fivegmm_security_context_t * security = (fivegmm_security_context_t *)calloc(1,sizeof(fivegmm_security_context_t));
	security->selected_algorithms.encryption = NAS_SECURITY_ALGORITHMS_NEA1;
	security->dl_count.overflow = 0xffff;
	security->dl_count.seq_num =  0x23;
	security->knas_enc[0] = 0x14;
	security->selected_algorithms.integrity = NAS_SECURITY_ALGORITHMS_NIA1;
	security->knas_int[0] = 0x41;
	//complete sercurity context

	int length = BUF_LEN;
	unsigned char data[BUF_LEN] = {'\0'};

	bstring  info = bfromcstralloc(length, "\0");//info the nas_message_encode result

	#if 0
	printf("1 start nas_message_encode \n");
	printf("security %p\n",security);
	printf("info %p\n",info);
	#endif

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
	bytes = nas_message_encode (data, &nas_msg, sizeof(data)/*don't know the size*/, security);


	printf("Data = ");

	for(int i = 0;i<bytes;i++)
		printf("%02x ",data[i]);
	printf("\n");

	info->data = data;
	info->slen = bytes;


    /***********creat bin file************************/

	creat_dir_sm_encode();

	char datahex[512];
	for(int i=0;i<bytes;i++)
		sprintf(datahex+i*2,"%02x",data[i]);

	FILE *fp;
	fp = fopen("../../build/smf/build/sm_encode_file/sm_encode_authentication_command.txt","w");
	fwrite(datahex,bytes*2/*sizeof(data)*/,1,fp);

	fclose(fp);
	/*****************  end  ************************/
    printf("PDU_SESSION_AUTHENTICATION_COMMAND------------ encode end\n");
	return  0;
}

int sm_encode_authentication_complete(void)
{
	printf("PDU_SESSION_AUTHENTICATION_COMPLETE------------ encode start\n");
	int size = NAS_MESSAGE_SECURITY_HEADER_SIZE;
	int bytes = 0;

	nas_message_t	nas_msg;
	memset (&nas_msg,		 0, sizeof (nas_message_t));
	nas_msg.header.extended_protocol_discriminator = EPD_5GS_SESSION_MANAGEMENT_MESSAGES;
	nas_msg.header.security_header_type = SECURITY_HEADER_TYPE_INTEGRITY_PROTECTED_CYPHERED;
	uint8_t sequencenumber = 0xfe;
	//uint32_t mac = 0xffffeeee;
	uint32_t mac = 0xffee;
	nas_msg.header.sequence_number = sequencenumber;
	nas_msg.header.message_authentication_code= mac;
	nas_msg.security_protected.header = nas_msg.header;
	SM_msg * sm_msg;
	// memset (&sm_msg->specific_msg.pdu_session_establishment_request,		 0, sizeof (pdu_session_establishment_request_msg));
	sm_msg = &nas_msg.security_protected.plain.sm;
	sm_msg->header.extended_protocol_discriminator = EPD_5GS_SESSION_MANAGEMENT_MESSAGES;
	sm_msg->header.pdu_session_identity = 1;
    sm_msg->header.procedure_transaction_identity = 1;
	sm_msg->header.message_type = PDU_SESSION_AUTHENTICATION_COMPLETE;

/*********************sm_msg->specific_msg.pdu_session_authentication_complete statr******************************/

    #if 0
	sm_msg->specific_msg.pdu_session_authentication_complete.extendedprotocoldiscriminator = 0X2E;


	bstring pdusessionidentity_tmp = bfromcstralloc(10, "\0");
	uint8_t bitStream_pdusessionidentity = 0X01;
	pdusessionidentity_tmp->data = (unsigned char *)(&bitStream_pdusessionidentity);
	pdusessionidentity_tmp->slen = 1;
	sm_msg->specific_msg.pdu_session_authentication_complete.pdusessionidentity = pdusessionidentity_tmp;

	bstring proceduretransactionidentity_tmp = bfromcstralloc(10, "\0");
	uint8_t bitStream_proceduretransactionidentity = 0X01;
	proceduretransactionidentity_tmp->data = (unsigned char *)(&bitStream_proceduretransactionidentity);
	proceduretransactionidentity_tmp->slen = 1;
    sm_msg->specific_msg.pdu_session_authentication_complete.proceduretransactionidentity = proceduretransactionidentity_tmp;

    sm_msg->specific_msg.pdu_session_authentication_complete.messagetype = 0XC1;
    #endif

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

	size += MESSAGE_TYPE_MAXIMUM_LENGTH;

	//memcpy(&nas_msg.plain.sm,&nas_msg.security_protected.plain.sm,sizeof(nas_msg.security_protected.plain.sm));
	nas_msg.plain.sm = *sm_msg;

	//complete sm msg content
	if(size <= 0){
		return -1;
	}

	//construct security context
	fivegmm_security_context_t * security = (fivegmm_security_context_t *)calloc(1,sizeof(fivegmm_security_context_t));
	security->selected_algorithms.encryption = NAS_SECURITY_ALGORITHMS_NEA1;
	security->dl_count.overflow = 0xffff;
	security->dl_count.seq_num =  0x23;
	security->knas_enc[0] = 0x14;
	security->selected_algorithms.integrity = NAS_SECURITY_ALGORITHMS_NIA1;
	security->knas_int[0] = 0x41;
	//complete sercurity context

	int length = BUF_LEN;
	unsigned char data[BUF_LEN] = {'\0'};

	bstring  info = bfromcstralloc(length, "\0");//info the nas_message_encode result

	#if 0
	printf("1 start nas_message_encode \n");
	printf("security %p\n",security);
	printf("info %p\n",info);
	#endif

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
	bytes = nas_message_encode (data, &nas_msg, sizeof(data)/*don't know the size*/, security);


	printf("Data = ");

	for(int i = 0;i<bytes;i++)
		printf("%02x ",data[i]);
	printf("\n");

	info->data = data;
	info->slen = bytes;


    /***********creat bin file************************/

	creat_dir_sm_encode();

	char datahex[512];
	for(int i=0;i<bytes;i++)
		sprintf(datahex+i*2,"%02x",data[i]);

	FILE *fp;
	fp = fopen("../../build/smf/build/sm_encode_file/sm_encode_authentication_complete.txt","w");
	fwrite(datahex,bytes*2/*sizeof(data)*/,1,fp);

	fclose(fp);
	/*****************  end  ************************/
    printf("PDU_SESSION_AUTHENTICATION_COMPLETE------------ encode end\n");
	return  0;
}

int sm_encode_authentication_result(void)
{
	printf("PDU_SESSION_AUTHENTICATION_RESULT------------ encode start\n");
	int size = NAS_MESSAGE_SECURITY_HEADER_SIZE;
	int bytes = 0;

	nas_message_t	nas_msg;
	memset (&nas_msg,		 0, sizeof (nas_message_t));
	nas_msg.header.extended_protocol_discriminator = EPD_5GS_SESSION_MANAGEMENT_MESSAGES;
	nas_msg.header.security_header_type = SECURITY_HEADER_TYPE_INTEGRITY_PROTECTED_CYPHERED;
	uint8_t sequencenumber = 0xfe;
	//uint32_t mac = 0xffffeeee;
	uint32_t mac = 0xffee;
	nas_msg.header.sequence_number = sequencenumber;
	nas_msg.header.message_authentication_code= mac;
	nas_msg.security_protected.header = nas_msg.header;
	SM_msg * sm_msg;
	// memset (&sm_msg->specific_msg.pdu_session_establishment_request,		 0, sizeof (pdu_session_establishment_request_msg));
	sm_msg = &nas_msg.security_protected.plain.sm;
	sm_msg->header.extended_protocol_discriminator = EPD_5GS_SESSION_MANAGEMENT_MESSAGES;
	sm_msg->header.pdu_session_identity = 1;
    sm_msg->header.procedure_transaction_identity = 1;
	sm_msg->header.message_type = PDU_SESSION_AUTHENTICATION_RESULT;

/*********************sm_msg->specific_msg.pdu_session_authentication_result statr******************************/

    #if 0
	sm_msg->specific_msg.pdu_session_authentication_result.extendedprotocoldiscriminator = 0X2E;


	bstring pdusessionidentity_tmp = bfromcstralloc(10, "\0");
	uint8_t bitStream_pdusessionidentity = 0X01;
	pdusessionidentity_tmp->data = (unsigned char *)(&bitStream_pdusessionidentity);
	pdusessionidentity_tmp->slen = 1;
	sm_msg->specific_msg.pdu_session_authentication_result.pdusessionidentity = pdusessionidentity_tmp;

	bstring proceduretransactionidentity_tmp = bfromcstralloc(10, "\0");
	uint8_t bitStream_proceduretransactionidentity = 0X01;
	proceduretransactionidentity_tmp->data = (unsigned char *)(&bitStream_proceduretransactionidentity);
	proceduretransactionidentity_tmp->slen = 1;
    sm_msg->specific_msg.pdu_session_authentication_result.proceduretransactionidentity = proceduretransactionidentity_tmp;

    sm_msg->specific_msg.pdu_session_authentication_result.messagetype = 0XC1;
    #endif

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

	size += MESSAGE_TYPE_MAXIMUM_LENGTH;

	//memcpy(&nas_msg.plain.sm,&nas_msg.security_protected.plain.sm,sizeof(nas_msg.security_protected.plain.sm));
	nas_msg.plain.sm = *sm_msg;

	//complete sm msg content
	if(size <= 0){
		return -1;
	}

	//construct security context
	fivegmm_security_context_t * security = (fivegmm_security_context_t *)calloc(1,sizeof(fivegmm_security_context_t));
	security->selected_algorithms.encryption = NAS_SECURITY_ALGORITHMS_NEA1;
	security->dl_count.overflow = 0xffff;
	security->dl_count.seq_num =  0x23;
	security->knas_enc[0] = 0x14;
	security->selected_algorithms.integrity = NAS_SECURITY_ALGORITHMS_NIA1;
	security->knas_int[0] = 0x41;
	//complete sercurity context

	int length = BUF_LEN;
	unsigned char data[BUF_LEN] = {'\0'};

	bstring  info = bfromcstralloc(length, "\0");//info the nas_message_encode result

	#if 0
	printf("1 start nas_message_encode \n");
	printf("security %p\n",security);
	printf("info %p\n",info);
	#endif

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
	bytes = nas_message_encode (data, &nas_msg, sizeof(data)/*don't know the size*/, security);


	printf("Data = ");

	for(int i = 0;i<bytes;i++)
		printf("%02x ",data[i]);
	printf("\n");

	info->data = data;
	info->slen = bytes;


    /***********creat bin file************************/

	creat_dir_sm_encode();

	char datahex[512];
	for(int i=0;i<bytes;i++)
		sprintf(datahex+i*2,"%02x",data[i]);

	FILE *fp;
	fp = fopen("../../build/smf/build/sm_encode_file/sm_encode_authentication_result.txt","w");
	fwrite(datahex,bytes*2/*sizeof(data)*/,1,fp);

	fclose(fp);
	/*****************  end  ************************/
    printf("PDU_SESSION_AUTHENTICATION_RESULT------------ encode end\n");
	return  0;
}


int sm_encode_modification_request(void)
{
	printf("PDU_SESSION_MODIFICATION_REQUEST------------ encode start\n");
	int size = NAS_MESSAGE_SECURITY_HEADER_SIZE;
	int bytes = 0;

	nas_message_t	nas_msg;
	memset (&nas_msg,		 0, sizeof (nas_message_t));

	nas_msg.header.extended_protocol_discriminator = EPD_5GS_SESSION_MANAGEMENT_MESSAGES;
	nas_msg.header.security_header_type = SECURITY_HEADER_TYPE_INTEGRITY_PROTECTED_CYPHERED;
	uint8_t sequencenumber = 0xfe;
	//uint32_t mac = 0xffffeeee;
	uint32_t mac = 0xffee;
	nas_msg.header.sequence_number = sequencenumber;
	nas_msg.header.message_authentication_code= mac;

	nas_msg.security_protected.header = nas_msg.header;

	SM_msg * sm_msg;
	// memset (&sm_msg->specific_msg.pdu_session_establishment_request,		 0, sizeof (pdu_session_establishment_request_msg));
	sm_msg = &nas_msg.security_protected.plain.sm;
	sm_msg->header.extended_protocol_discriminator = EPD_5GS_SESSION_MANAGEMENT_MESSAGES;
	sm_msg->header.pdu_session_identity = 1;
	sm_msg->header.procedure_transaction_identity = 1;
	sm_msg->header.message_type = PDU_SESSION_MODIFICATION_REQUEST;

	/*********************sm_msg->specific_msg.pdu_session_modification_request statr******************************/

	//memset (&sm_msg->specific_msg.pdu_session_modification_request,		 0, sizeof (pdu_session_establishment_request_msg));

#if 0
	sm_msg->specific_msg.pdu_session_modification_request.extendedprotocoldiscriminator = 0X2E;


	bstring pdusessionidentity_tmp = bfromcstralloc(10, "\0");
	uint8_t bitStream_pdusessionidentity = 0X01;
	pdusessionidentity_tmp->data = (unsigned char *)(&bitStream_pdusessionidentity);
	pdusessionidentity_tmp->slen = 1;
	sm_msg->specific_msg.pdu_session_modification_request.pdusessionidentity = pdusessionidentity_tmp;

	bstring proceduretransactionidentity_tmp = bfromcstralloc(10, "\0");
	uint8_t bitStream_proceduretransactionidentity = 0X01;
	proceduretransactionidentity_tmp->data = (unsigned char *)(&bitStream_proceduretransactionidentity);
	proceduretransactionidentity_tmp->slen = 1;
	sm_msg->specific_msg.pdu_session_modification_request.proceduretransactionidentity = proceduretransactionidentity_tmp;

	sm_msg->specific_msg.pdu_session_modification_request.messagetype = 0XC1;
#endif



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
	qosflowdescriptionscontents[1].parameterslist = NULL;

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

	size += MESSAGE_TYPE_MAXIMUM_LENGTH;

	//memcpy(&nas_msg.plain.sm,&nas_msg.security_protected.plain.sm,sizeof(nas_msg.security_protected.plain.sm));
	printf("nas_msg.security_protected.plain.sm = %d\n",sizeof(nas_msg.security_protected.plain.sm));
	nas_msg.plain.sm = *sm_msg;

	//complete sm msg content
	if(size <= 0){
		return -1;
	}

	//construct security context
	fivegmm_security_context_t * security = (fivegmm_security_context_t *)calloc(1,sizeof(fivegmm_security_context_t));
	security->selected_algorithms.encryption = NAS_SECURITY_ALGORITHMS_NEA1;
	security->dl_count.overflow = 0xffff;
	security->dl_count.seq_num =  0x23;
	security->knas_enc[0] = 0x14;
	security->selected_algorithms.integrity = NAS_SECURITY_ALGORITHMS_NIA1;
	security->knas_int[0] = 0x41;
	//complete sercurity context

	int length = BUF_LEN;
	unsigned char data[BUF_LEN] = {'\0'};
	memset(data,0,sizeof(data));

	bstring  info = bfromcstralloc(length, "\0");//info the nas_message_encode result

#if 0
	printf("1 start nas_message_encode \n");
	printf("security %p\n",security);
	printf("info %p\n",info);
#endif

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
	bytes = nas_message_encode (data, &nas_msg, sizeof(data)/*don't know the size*/, security);

	printf("Data = ");

	for(int i = 0;i<bytes;i++)
		printf("%02x ",data[i]);
	printf("\n");

	info->data = data;
	info->slen = bytes;


    /***********creat bin file************************/

	creat_dir_sm_encode();

	char datahex[512];
	for(int i=0;i<bytes;i++)
		sprintf(datahex+i*2,"%02x",data[i]);

	FILE *fp;
	fp = fopen("../../build/smf/build/sm_encode_file/sm_encode_modification_request.txt","w");
	fwrite(datahex,bytes*2/*sizeof(data)*/,1,fp);

	fclose(fp);
	/*****************  end  ************************/
	printf("PDU_SESSION_MODIFICATION_REQUEST------------ encode end\n");

	return 0;
}

int sm_encode_modification_reject(void)
{
	printf("PDU_SESSION_MODIFICATION_REJECT------------ encode start\n");
	int size = NAS_MESSAGE_SECURITY_HEADER_SIZE;
	int bytes = 0;

	nas_message_t	nas_msg;
	memset (&nas_msg,		 0, sizeof (nas_message_t));
	nas_msg.header.extended_protocol_discriminator = EPD_5GS_SESSION_MANAGEMENT_MESSAGES;
	nas_msg.header.security_header_type = SECURITY_HEADER_TYPE_INTEGRITY_PROTECTED_CYPHERED;
	uint8_t sequencenumber = 0xfe;
	//uint32_t mac = 0xffffeeee;
	uint32_t mac = 0xffee;
	nas_msg.header.sequence_number = sequencenumber;
	nas_msg.header.message_authentication_code= mac;
	nas_msg.security_protected.header = nas_msg.header;
	SM_msg * sm_msg;
	// memset (&sm_msg->specific_msg.pdu_session_establishment_request,		 0, sizeof (pdu_session_establishment_request_msg));
	sm_msg = &nas_msg.security_protected.plain.sm;
	sm_msg->header.extended_protocol_discriminator = EPD_5GS_SESSION_MANAGEMENT_MESSAGES;
	sm_msg->header.pdu_session_identity = 1;
    sm_msg->header.procedure_transaction_identity = 1;
	sm_msg->header.message_type = PDU_SESSION_MODIFICATION_REJECT;

/*********************sm_msg->specific_msg.pdu_session_modification_reject statr******************************/

    #if 0
	sm_msg->specific_msg.pdu_session_modification_reject.extendedprotocoldiscriminator = 0X2E;


	bstring pdusessionidentity_tmp = bfromcstralloc(10, "\0");
	uint8_t bitStream_pdusessionidentity = 0X01;
	pdusessionidentity_tmp->data = (unsigned char *)(&bitStream_pdusessionidentity);
	pdusessionidentity_tmp->slen = 1;
	sm_msg->specific_msg.pdu_session_modification_reject.pdusessionidentity = pdusessionidentity_tmp;

	bstring proceduretransactionidentity_tmp = bfromcstralloc(10, "\0");
	uint8_t bitStream_proceduretransactionidentity = 0X01;
	proceduretransactionidentity_tmp->data = (unsigned char *)(&bitStream_proceduretransactionidentity);
	proceduretransactionidentity_tmp->slen = 1;
    sm_msg->specific_msg.pdu_session_modification_reject.proceduretransactionidentity = proceduretransactionidentity_tmp;

    sm_msg->specific_msg.pdu_session_modification_reject.messagetype = 0XC1;
    #endif

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

	size += MESSAGE_TYPE_MAXIMUM_LENGTH;

	//memcpy(&nas_msg.plain.sm,&nas_msg.security_protected.plain.sm,sizeof(nas_msg.security_protected.plain.sm));
	nas_msg.plain.sm = *sm_msg;

	//complete sm msg content
	if(size <= 0){
		return -1;
	}

	//construct security context
	fivegmm_security_context_t * security = (fivegmm_security_context_t *)calloc(1,sizeof(fivegmm_security_context_t));
	security->selected_algorithms.encryption = NAS_SECURITY_ALGORITHMS_NEA1;
	security->dl_count.overflow = 0xffff;
	security->dl_count.seq_num =  0x23;
	security->knas_enc[0] = 0x14;
	security->selected_algorithms.integrity = NAS_SECURITY_ALGORITHMS_NIA1;
	security->knas_int[0] = 0x41;
	//complete sercurity context

	int length = BUF_LEN;
	unsigned char data[BUF_LEN] = {'\0'};

	bstring  info = bfromcstralloc(length, "\0");//info the nas_message_encode result

	#if 0
	printf("1 start nas_message_encode \n");
	printf("security %p\n",security);
	printf("info %p\n",info);
	#endif

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
	bytes = nas_message_encode (data, &nas_msg, sizeof(data)/*don't know the size*/, security);


	printf("Data = ");

	for(int i = 0;i<bytes;i++)
		printf("%02x ",data[i]);
	printf("\n");

	info->data = data;
	info->slen = bytes;


   /***********creat bin file************************/

	creat_dir_sm_encode();

	char datahex[512];
	for(int i=0;i<bytes;i++)
		sprintf(datahex+i*2,"%02x",data[i]);

	FILE *fp;
	fp = fopen("../../build/smf/build/sm_encode_file/sm_encode_modification_reject.txt","w");
	fwrite(datahex,bytes*2/*sizeof(data)*/,1,fp);

	fclose(fp);
	/*****************  end  ************************/
    printf("PDU_SESSION_MODIFICATION_REJECT------------ encode end\n");
	return  0;
}

int sm_encode_modification_command(void)
{
	printf("PDU_SESSION_MODIFICATION_COMMAND------------ encode start\n");
	int size = NAS_MESSAGE_SECURITY_HEADER_SIZE;
	int bytes = 0;

	nas_message_t	nas_msg;
	memset (&nas_msg,		 0, sizeof (nas_message_t));

	nas_msg.header.extended_protocol_discriminator = EPD_5GS_SESSION_MANAGEMENT_MESSAGES;
	nas_msg.header.security_header_type = SECURITY_HEADER_TYPE_INTEGRITY_PROTECTED_CYPHERED;
	uint8_t sequencenumber = 0xfe;
	//uint32_t mac = 0xffffeeee;
	uint32_t mac = 0xffee;
	nas_msg.header.sequence_number = sequencenumber;
	nas_msg.header.message_authentication_code= mac;

	nas_msg.security_protected.header = nas_msg.header;

	SM_msg * sm_msg;
	// memset (&sm_msg->specific_msg.pdu_session_establishment_request,		 0, sizeof (pdu_session_establishment_request_msg));
	sm_msg = &nas_msg.security_protected.plain.sm;
	sm_msg->header.extended_protocol_discriminator = EPD_5GS_SESSION_MANAGEMENT_MESSAGES;
	sm_msg->header.pdu_session_identity = 1;
	sm_msg->header.procedure_transaction_identity = 1;
	sm_msg->header.message_type = PDU_SESSION_MODIFICATION_COMMAND;

	/*********************sm_msg->specific_msg.pdu_session_modification_command statr******************************/

	//memset (&sm_msg->specific_msg.pdu_session_modification_command,		 0, sizeof (pdu_session_establishment_request_msg));

#if 0
	sm_msg->specific_msg.pdu_session_modification_command.extendedprotocoldiscriminator = 0X2E;


	bstring pdusessionidentity_tmp = bfromcstralloc(10, "\0");
	uint8_t bitStream_pdusessionidentity = 0X01;
	pdusessionidentity_tmp->data = (unsigned char *)(&bitStream_pdusessionidentity);
	pdusessionidentity_tmp->slen = 1;
	sm_msg->specific_msg.pdu_session_modification_command.pdusessionidentity = pdusessionidentity_tmp;

	bstring proceduretransactionidentity_tmp = bfromcstralloc(10, "\0");
	uint8_t bitStream_proceduretransactionidentity = 0X01;
	proceduretransactionidentity_tmp->data = (unsigned char *)(&bitStream_proceduretransactionidentity);
	proceduretransactionidentity_tmp->slen = 1;
	sm_msg->specific_msg.pdu_session_modification_command.proceduretransactionidentity = proceduretransactionidentity_tmp;

	sm_msg->specific_msg.pdu_session_modification_command.messagetype = 0XC1;
#endif



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
	qosflowdescriptionscontents[1].parameterslist = NULL;

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

	size += MESSAGE_TYPE_MAXIMUM_LENGTH;

	//memcpy(&nas_msg.plain.sm,&nas_msg.security_protected.plain.sm,sizeof(nas_msg.security_protected.plain.sm));
	printf("nas_msg.security_protected.plain.sm = %d\n",sizeof(nas_msg.security_protected.plain.sm));
	nas_msg.plain.sm = *sm_msg;

	//complete sm msg content
	if(size <= 0){
		return -1;
	}

	//construct security context
	fivegmm_security_context_t * security = (fivegmm_security_context_t *)calloc(1,sizeof(fivegmm_security_context_t));
	security->selected_algorithms.encryption = NAS_SECURITY_ALGORITHMS_NEA1;
	security->dl_count.overflow = 0xffff;
	security->dl_count.seq_num =  0x23;
	security->knas_enc[0] = 0x14;
	security->selected_algorithms.integrity = NAS_SECURITY_ALGORITHMS_NIA1;
	security->knas_int[0] = 0x41;
	//complete sercurity context

	int length = BUF_LEN;
	unsigned char data[BUF_LEN] = {'\0'};
	memset(data,0,sizeof(data));

	bstring  info = bfromcstralloc(length, "\0");//info the nas_message_encode result

#if 0
	printf("1 start nas_message_encode \n");
	printf("security %p\n",security);
	printf("info %p\n",info);
#endif

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
	bytes = nas_message_encode (data, &nas_msg, sizeof(data)/*don't know the size*/, security);

	printf("Data = ");

	for(int i = 0;i<bytes;i++)
		printf("%02x ",data[i]);
	printf("\n");

	info->data = data;
	info->slen = bytes;


   /***********creat bin file************************/

	creat_dir_sm_encode();

	char datahex[512];
	for(int i=0;i<bytes;i++)
		sprintf(datahex+i*2,"%02x",data[i]);

	FILE *fp;
	fp = fopen("../../build/smf/build/sm_encode_file/sm_encode_modification_command.txt","w");
	fwrite(datahex,bytes*2/*sizeof(data)*/,1,fp);

	fclose(fp);
	/*****************  end  ************************/
	printf("PDU_SESSION_MODIFICATION_COMMAND------------ encode end\n");

	return  0;
}


int sm_encode_modification_complete(void)
{
	printf("PDU_SESSION_MODIFICATION_COMPLETE------------ encode start\n");
	int size = NAS_MESSAGE_SECURITY_HEADER_SIZE;
	int bytes = 0;

	nas_message_t	nas_msg;
	memset (&nas_msg,		 0, sizeof (nas_message_t));
	nas_msg.header.extended_protocol_discriminator = EPD_5GS_SESSION_MANAGEMENT_MESSAGES;
	nas_msg.header.security_header_type = SECURITY_HEADER_TYPE_INTEGRITY_PROTECTED_CYPHERED;
	uint8_t sequencenumber = 0xfe;
	//uint32_t mac = 0xffffeeee;
	uint32_t mac = 0xffee;
	nas_msg.header.sequence_number = sequencenumber;
	nas_msg.header.message_authentication_code= mac;
	nas_msg.security_protected.header = nas_msg.header;
	SM_msg * sm_msg;
	// memset (&sm_msg->specific_msg.pdu_session_establishment_request,		 0, sizeof (pdu_session_establishment_request_msg));
	sm_msg = &nas_msg.security_protected.plain.sm;
	sm_msg->header.extended_protocol_discriminator = EPD_5GS_SESSION_MANAGEMENT_MESSAGES;
	sm_msg->header.pdu_session_identity = 1;
    sm_msg->header.procedure_transaction_identity = 1;
	sm_msg->header.message_type = PDU_SESSION_MODIFICATION_COMPLETE;

/*********************sm_msg->specific_msg.pdu_session_modification_complete statr******************************/

    #if 0
	sm_msg->specific_msg.pdu_session_modification_complete.extendedprotocoldiscriminator = 0X2E;


	bstring pdusessionidentity_tmp = bfromcstralloc(10, "\0");
	uint8_t bitStream_pdusessionidentity = 0X01;
	pdusessionidentity_tmp->data = (unsigned char *)(&bitStream_pdusessionidentity);
	pdusessionidentity_tmp->slen = 1;
	sm_msg->specific_msg.pdu_session_modification_complete.pdusessionidentity = pdusessionidentity_tmp;

	bstring proceduretransactionidentity_tmp = bfromcstralloc(10, "\0");
	uint8_t bitStream_proceduretransactionidentity = 0X01;
	proceduretransactionidentity_tmp->data = (unsigned char *)(&bitStream_proceduretransactionidentity);
	proceduretransactionidentity_tmp->slen = 1;
    sm_msg->specific_msg.pdu_session_modification_complete.proceduretransactionidentity = proceduretransactionidentity_tmp;

    sm_msg->specific_msg.pdu_session_modification_complete.messagetype = 0XC1;
    #endif

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

	size += MESSAGE_TYPE_MAXIMUM_LENGTH;

	//memcpy(&nas_msg.plain.sm,&nas_msg.security_protected.plain.sm,sizeof(nas_msg.security_protected.plain.sm));
	nas_msg.plain.sm = *sm_msg;

	//complete sm msg content
	if(size <= 0){
		return -1;
	}

	//construct security context
	fivegmm_security_context_t * security = (fivegmm_security_context_t *)calloc(1,sizeof(fivegmm_security_context_t));
	security->selected_algorithms.encryption = NAS_SECURITY_ALGORITHMS_NEA1;
	security->dl_count.overflow = 0xffff;
	security->dl_count.seq_num =  0x23;
	security->knas_enc[0] = 0x14;
	security->selected_algorithms.integrity = NAS_SECURITY_ALGORITHMS_NIA1;
	security->knas_int[0] = 0x41;
	//complete sercurity context

	int length = BUF_LEN;
	unsigned char data[BUF_LEN] = {'\0'};

	bstring  info = bfromcstralloc(length, "\0");//info the nas_message_encode result

	#if 0
	printf("1 start nas_message_encode \n");
	printf("security %p\n",security);
	printf("info %p\n",info);
	#endif

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
	bytes = nas_message_encode (data, &nas_msg, sizeof(data)/*don't know the size*/, security);


	printf("Data = ");

	for(int i = 0;i<bytes;i++)
		printf("%02x ",data[i]);
	printf("\n");

	info->data = data;
	info->slen = bytes;


   /***********creat bin file************************/

	creat_dir_sm_encode();

	char datahex[512];
	for(int i=0;i<bytes;i++)
		sprintf(datahex+i*2,"%02x",data[i]);

	FILE *fp;
	fp = fopen("../../build/smf/build/sm_encode_file/sm_encode_modification_complete.txt","w");
	fwrite(datahex,bytes*2/*sizeof(data)*/,1,fp);

	fclose(fp);
	/*****************  end  ************************/
    printf("PDU_SESSION_MODIFICATION_COMPLETE------------ encode end\n");
	return 0;
}


int sm_encode_modification_command_reject(void)
{
	printf("PDU_SESSION_MODIFICATION_COMMANDREJECT------------ encode start\n");
	int size = NAS_MESSAGE_SECURITY_HEADER_SIZE;
	int bytes = 0;

	nas_message_t	nas_msg;
	memset (&nas_msg,		 0, sizeof (nas_message_t));
	nas_msg.header.extended_protocol_discriminator = EPD_5GS_SESSION_MANAGEMENT_MESSAGES;
	nas_msg.header.security_header_type = SECURITY_HEADER_TYPE_INTEGRITY_PROTECTED_CYPHERED;
	uint8_t sequencenumber = 0xfe;
	//uint32_t mac = 0xffffeeee;
	uint32_t mac = 0xffee;
	nas_msg.header.sequence_number = sequencenumber;
	nas_msg.header.message_authentication_code= mac;
	nas_msg.security_protected.header = nas_msg.header;
	SM_msg * sm_msg;
	// memset (&sm_msg->specific_msg.pdu_session_establishment_request,		 0, sizeof (pdu_session_establishment_request_msg));
	sm_msg = &nas_msg.security_protected.plain.sm;
	sm_msg->header.extended_protocol_discriminator = EPD_5GS_SESSION_MANAGEMENT_MESSAGES;
	sm_msg->header.pdu_session_identity = 1;
    sm_msg->header.procedure_transaction_identity = 1;
	sm_msg->header.message_type = PDU_SESSION_MODIFICATION_COMMANDREJECT;

/*********************sm_msg->specific_msg.pdu_session_modification_command_reject statr******************************/

    #if 0
	sm_msg->specific_msg.pdu_session_modification_command_reject.extendedprotocoldiscriminator = 0X2E;


	bstring pdusessionidentity_tmp = bfromcstralloc(10, "\0");
	uint8_t bitStream_pdusessionidentity = 0X01;
	pdusessionidentity_tmp->data = (unsigned char *)(&bitStream_pdusessionidentity);
	pdusessionidentity_tmp->slen = 1;
	sm_msg->specific_msg.pdu_session_modification_command_reject.pdusessionidentity = pdusessionidentity_tmp;

	bstring proceduretransactionidentity_tmp = bfromcstralloc(10, "\0");
	uint8_t bitStream_proceduretransactionidentity = 0X01;
	proceduretransactionidentity_tmp->data = (unsigned char *)(&bitStream_proceduretransactionidentity);
	proceduretransactionidentity_tmp->slen = 1;
    sm_msg->specific_msg.pdu_session_modification_command_reject.proceduretransactionidentity = proceduretransactionidentity_tmp;

    sm_msg->specific_msg.pdu_session_modification_command_reject.messagetype = 0XC1;
    #endif

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

	size += MESSAGE_TYPE_MAXIMUM_LENGTH;

	//memcpy(&nas_msg.plain.sm,&nas_msg.security_protected.plain.sm,sizeof(nas_msg.security_protected.plain.sm));
	nas_msg.plain.sm = *sm_msg;

	//complete sm msg content
	if(size <= 0){
		return -1;
	}

	//construct security context
	fivegmm_security_context_t * security = (fivegmm_security_context_t *)calloc(1,sizeof(fivegmm_security_context_t));
	security->selected_algorithms.encryption = NAS_SECURITY_ALGORITHMS_NEA1;
	security->dl_count.overflow = 0xffff;
	security->dl_count.seq_num =  0x23;
	security->knas_enc[0] = 0x14;
	security->selected_algorithms.integrity = NAS_SECURITY_ALGORITHMS_NIA1;
	security->knas_int[0] = 0x41;
	//complete sercurity context

	int length = BUF_LEN;
	unsigned char data[BUF_LEN] = {'\0'};

	bstring  info = bfromcstralloc(length, "\0");//info the nas_message_encode result

	#if 0
	printf("1 start nas_message_encode \n");
	printf("security %p\n",security);
	printf("info %p\n",info);
	#endif

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
	bytes = nas_message_encode (data, &nas_msg, sizeof(data)/*don't know the size*/, security);


	printf("Data = ");

	for(int i = 0;i<bytes;i++)
		printf("%02x ",data[i]);
	printf("\n");

	info->data = data;
	info->slen = bytes;


   /***********creat bin file************************/

	creat_dir_sm_encode();

	char datahex[512];
	for(int i=0;i<bytes;i++)
		sprintf(datahex+i*2,"%02x",data[i]);

	FILE *fp;
	fp = fopen("../../build/smf/build/sm_encode_file/sm_encode_modification_command_reject.txt","w");
	fwrite(datahex,bytes*2/*sizeof(data)*/,1,fp);

	fclose(fp);
	/*****************  end  ************************/
    printf("PDU_SESSION_MODIFICATION_COMMANDREJECT------------ encode end\n");
	return  0;
}


int sm_encode_release_request(void)
{
	printf("PDU_SESSION_RELEASE_REQUEST------------ encode start\n");
	int size = NAS_MESSAGE_SECURITY_HEADER_SIZE;
	int bytes = 0;

	nas_message_t	nas_msg;
	memset (&nas_msg,		 0, sizeof (nas_message_t));
	nas_msg.header.extended_protocol_discriminator = EPD_5GS_SESSION_MANAGEMENT_MESSAGES;
	nas_msg.header.security_header_type = SECURITY_HEADER_TYPE_INTEGRITY_PROTECTED_CYPHERED;
	uint8_t sequencenumber = 0xfe;
	//uint32_t mac = 0xffffeeee;
	uint32_t mac = 0xffee;
	nas_msg.header.sequence_number = sequencenumber;
	nas_msg.header.message_authentication_code= mac;
	nas_msg.security_protected.header = nas_msg.header;
	SM_msg * sm_msg;
	// memset (&sm_msg->specific_msg.pdu_session_establishment_request,		 0, sizeof (pdu_session_establishment_request_msg));
	sm_msg = &nas_msg.security_protected.plain.sm;
	sm_msg->header.extended_protocol_discriminator = EPD_5GS_SESSION_MANAGEMENT_MESSAGES;
	sm_msg->header.pdu_session_identity = 1;
    sm_msg->header.procedure_transaction_identity = 1;
	sm_msg->header.message_type = PDU_SESSION_RELEASE_REQUEST;

/*********************sm_msg->specific_msg.pdu_session_release_request statr******************************/

    #if 0
	sm_msg->specific_msg.pdu_session_release_request.extendedprotocoldiscriminator = 0X2E;


	bstring pdusessionidentity_tmp = bfromcstralloc(10, "\0");
	uint8_t bitStream_pdusessionidentity = 0X01;
	pdusessionidentity_tmp->data = (unsigned char *)(&bitStream_pdusessionidentity);
	pdusessionidentity_tmp->slen = 1;
	sm_msg->specific_msg.pdu_session_release_request.pdusessionidentity = pdusessionidentity_tmp;

	bstring proceduretransactionidentity_tmp = bfromcstralloc(10, "\0");
	uint8_t bitStream_proceduretransactionidentity = 0X01;
	proceduretransactionidentity_tmp->data = (unsigned char *)(&bitStream_proceduretransactionidentity);
	proceduretransactionidentity_tmp->slen = 1;
    sm_msg->specific_msg.pdu_session_release_request.proceduretransactionidentity = proceduretransactionidentity_tmp;

    sm_msg->specific_msg.pdu_session_release_request.messagetype = 0XC1;
    #endif

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

	size += MESSAGE_TYPE_MAXIMUM_LENGTH;

	//memcpy(&nas_msg.plain.sm,&nas_msg.security_protected.plain.sm,sizeof(nas_msg.security_protected.plain.sm));
	nas_msg.plain.sm = *sm_msg;

	//complete sm msg content
	if(size <= 0){
		return -1;
	}

	//construct security context
	fivegmm_security_context_t * security = (fivegmm_security_context_t *)calloc(1,sizeof(fivegmm_security_context_t));
	security->selected_algorithms.encryption = NAS_SECURITY_ALGORITHMS_NEA1;
	security->dl_count.overflow = 0xffff;
	security->dl_count.seq_num =  0x23;
	security->knas_enc[0] = 0x14;
	security->selected_algorithms.integrity = NAS_SECURITY_ALGORITHMS_NIA1;
	security->knas_int[0] = 0x41;
	//complete sercurity context

	int length = BUF_LEN;
	unsigned char data[BUF_LEN] = {'\0'};

	bstring  info = bfromcstralloc(length, "\0");//info the nas_message_encode result

	#if 0
	printf("1 start nas_message_encode \n");
	printf("security %p\n",security);
	printf("info %p\n",info);
	#endif

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
	bytes = nas_message_encode (data, &nas_msg, sizeof(data)/*don't know the size*/, security);


	printf("Data = ");

	for(int i = 0;i<bytes;i++)
		printf("%02x ",data[i]);
	printf("\n");

	info->data = data;
	info->slen = bytes;


   /***********creat bin file************************/

	creat_dir_sm_encode();

	char datahex[512];
	for(int i=0;i<bytes;i++)
		sprintf(datahex+i*2,"%02x",data[i]);

	FILE *fp;
	fp = fopen("../../build/smf/build/sm_encode_file/sm_encode_release_request.txt","w");
	fwrite(datahex,bytes*2/*sizeof(data)*/,1,fp);

	fclose(fp);
	/*****************  end  ************************/
    printf("PDU_SESSION_RELEASE_REQUEST------------ encode end\n");
	return  0;
}

int sm_encode_release_reject(void)
{
	printf("PDU_SESSION_RELEASE_REJECT------------ encode start\n");
	int size = NAS_MESSAGE_SECURITY_HEADER_SIZE;
	int bytes = 0;

	nas_message_t	nas_msg;
	memset (&nas_msg,		 0, sizeof (nas_message_t));
	nas_msg.header.extended_protocol_discriminator = EPD_5GS_SESSION_MANAGEMENT_MESSAGES;
	nas_msg.header.security_header_type = SECURITY_HEADER_TYPE_INTEGRITY_PROTECTED_CYPHERED;
	uint8_t sequencenumber = 0xfe;
	//uint32_t mac = 0xffffeeee;
	uint32_t mac = 0xffee;
	nas_msg.header.sequence_number = sequencenumber;
	nas_msg.header.message_authentication_code= mac;
	nas_msg.security_protected.header = nas_msg.header;
	SM_msg * sm_msg;
	// memset (&sm_msg->specific_msg.pdu_session_establishment_request,		 0, sizeof (pdu_session_establishment_request_msg));
	sm_msg = &nas_msg.security_protected.plain.sm;
	sm_msg->header.extended_protocol_discriminator = EPD_5GS_SESSION_MANAGEMENT_MESSAGES;
	sm_msg->header.pdu_session_identity = 1;
    sm_msg->header.procedure_transaction_identity = 1;
	sm_msg->header.message_type = PDU_SESSION_RELEASE_REJECT;

/*********************sm_msg->specific_msg.pdu_session_release_reject statr******************************/

    #if 0
	sm_msg->specific_msg.pdu_session_release_reject.extendedprotocoldiscriminator = 0X2E;


	bstring pdusessionidentity_tmp = bfromcstralloc(10, "\0");
	uint8_t bitStream_pdusessionidentity = 0X01;
	pdusessionidentity_tmp->data = (unsigned char *)(&bitStream_pdusessionidentity);
	pdusessionidentity_tmp->slen = 1;
	sm_msg->specific_msg.pdu_session_release_reject.pdusessionidentity = pdusessionidentity_tmp;

	bstring proceduretransactionidentity_tmp = bfromcstralloc(10, "\0");
	uint8_t bitStream_proceduretransactionidentity = 0X01;
	proceduretransactionidentity_tmp->data = (unsigned char *)(&bitStream_proceduretransactionidentity);
	proceduretransactionidentity_tmp->slen = 1;
    sm_msg->specific_msg.pdu_session_release_reject.proceduretransactionidentity = proceduretransactionidentity_tmp;

    sm_msg->specific_msg.pdu_session_release_reject.messagetype = 0XC1;
    #endif

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

	size += MESSAGE_TYPE_MAXIMUM_LENGTH;

	//memcpy(&nas_msg.plain.sm,&nas_msg.security_protected.plain.sm,sizeof(nas_msg.security_protected.plain.sm));
	nas_msg.plain.sm = *sm_msg;

	//complete sm msg content
	if(size <= 0){
		return -1;
	}

	//construct security context
	fivegmm_security_context_t * security = (fivegmm_security_context_t *)calloc(1,sizeof(fivegmm_security_context_t));
	security->selected_algorithms.encryption = NAS_SECURITY_ALGORITHMS_NEA1;
	security->dl_count.overflow = 0xffff;
	security->dl_count.seq_num =  0x23;
	security->knas_enc[0] = 0x14;
	security->selected_algorithms.integrity = NAS_SECURITY_ALGORITHMS_NIA1;
	security->knas_int[0] = 0x41;
	//complete sercurity context

	int length = BUF_LEN;
	unsigned char data[BUF_LEN] = {'\0'};

	bstring  info = bfromcstralloc(length, "\0");//info the nas_message_encode result

	#if 0
	printf("1 start nas_message_encode \n");
	printf("security %p\n",security);
	printf("info %p\n",info);
	#endif

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
	bytes = nas_message_encode (data, &nas_msg, sizeof(data)/*don't know the size*/, security);


	printf("Data = ");

	for(int i = 0;i<bytes;i++)
		printf("%02x ",data[i]);
	printf("\n");

	info->data = data;
	info->slen = bytes;


   /***********creat bin file************************/

	creat_dir_sm_encode();

	char datahex[512];
	for(int i=0;i<bytes;i++)
		sprintf(datahex+i*2,"%02x",data[i]);

	FILE *fp;
	fp = fopen("../../build/smf/build/sm_encode_file/sm_encode_release_reject.txt","w");
	fwrite(datahex,bytes*2/*sizeof(data)*/,1,fp);

	fclose(fp);
	/*****************  end  ************************/
    printf("PDU_SESSION_RELEASE_REJECT------------ encode end\n");
	return  0;
}

int sm_encode_release_command(void)
{
	printf("PDU_SESSION_RELEASE_COMMAND------------ encode start\n");
	int size = NAS_MESSAGE_SECURITY_HEADER_SIZE;
	int bytes = 0;

	nas_message_t	nas_msg;
	memset (&nas_msg,		 0, sizeof (nas_message_t));
	nas_msg.header.extended_protocol_discriminator = EPD_5GS_SESSION_MANAGEMENT_MESSAGES;
	nas_msg.header.security_header_type = SECURITY_HEADER_TYPE_INTEGRITY_PROTECTED_CYPHERED;
	uint8_t sequencenumber = 0xfe;
	//uint32_t mac = 0xffffeeee;
	uint32_t mac = 0xffee;
	nas_msg.header.sequence_number = sequencenumber;
	nas_msg.header.message_authentication_code= mac;
	nas_msg.security_protected.header = nas_msg.header;
	SM_msg * sm_msg;
	// memset (&sm_msg->specific_msg.pdu_session_establishment_request,		 0, sizeof (pdu_session_establishment_request_msg));
	sm_msg = &nas_msg.security_protected.plain.sm;
	sm_msg->header.extended_protocol_discriminator = EPD_5GS_SESSION_MANAGEMENT_MESSAGES;
	sm_msg->header.pdu_session_identity = 1;
    sm_msg->header.procedure_transaction_identity = 1;
	sm_msg->header.message_type = PDU_SESSION_RELEASE_COMMAND;

/*********************sm_msg->specific_msg.pdu_session_release_command statr******************************/

    #if 0
	sm_msg->specific_msg.pdu_session_release_command.extendedprotocoldiscriminator = 0X2E;


	bstring pdusessionidentity_tmp = bfromcstralloc(10, "\0");
	uint8_t bitStream_pdusessionidentity = 0X01;
	pdusessionidentity_tmp->data = (unsigned char *)(&bitStream_pdusessionidentity);
	pdusessionidentity_tmp->slen = 1;
	sm_msg->specific_msg.pdu_session_release_command.pdusessionidentity = pdusessionidentity_tmp;

	bstring proceduretransactionidentity_tmp = bfromcstralloc(10, "\0");
	uint8_t bitStream_proceduretransactionidentity = 0X01;
	proceduretransactionidentity_tmp->data = (unsigned char *)(&bitStream_proceduretransactionidentity);
	proceduretransactionidentity_tmp->slen = 1;
    sm_msg->specific_msg.pdu_session_release_command.proceduretransactionidentity = proceduretransactionidentity_tmp;

    sm_msg->specific_msg.pdu_session_release_command.messagetype = 0XC1;
    #endif

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

	size += MESSAGE_TYPE_MAXIMUM_LENGTH;

	//memcpy(&nas_msg.plain.sm,&nas_msg.security_protected.plain.sm,sizeof(nas_msg.security_protected.plain.sm));
	nas_msg.plain.sm = *sm_msg;

	//complete sm msg content
	if(size <= 0){
		return -1;
	}

	//construct security context
	fivegmm_security_context_t * security = (fivegmm_security_context_t *)calloc(1,sizeof(fivegmm_security_context_t));
	security->selected_algorithms.encryption = NAS_SECURITY_ALGORITHMS_NEA1;
	security->dl_count.overflow = 0xffff;
	security->dl_count.seq_num =  0x23;
	security->knas_enc[0] = 0x14;
	security->selected_algorithms.integrity = NAS_SECURITY_ALGORITHMS_NIA1;
	security->knas_int[0] = 0x41;
	//complete sercurity context

	int length = BUF_LEN;
	unsigned char data[BUF_LEN] = {'\0'};

	bstring  info = bfromcstralloc(length, "\0");//info the nas_message_encode result

	#if 0
	printf("1 start nas_message_encode \n");
	printf("security %p\n",security);
	printf("info %p\n",info);
	#endif

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
	bytes = nas_message_encode (data, &nas_msg, sizeof(data)/*don't know the size*/, security);


	printf("Data = ");

	for(int i = 0;i<bytes;i++)
		printf("%02x ",data[i]);

	info->data = data;
	info->slen = bytes;


   /***********creat bin file************************/

	creat_dir_sm_encode();

	char datahex[512];
	for(int i=0;i<bytes;i++)
		sprintf(datahex+i*2,"%02x",data[i]);
	printf("\n");

	FILE *fp;
	fp = fopen("../../build/smf/build/sm_encode_file/sm_encode_release_command.txt","w");
	fwrite(datahex,bytes*2/*sizeof(data)*/,1,fp);

	fclose(fp);
	/*****************  end  ************************/
	printf("PDU_SESSION_RELEASE_COMMAND------------ encode end\n");
	return  0;
}

int sm_encode_release_complete(void)
{
	printf("PDU_SESSION_RELEASE_COMPLETE------------ encode start\n");
	int size = NAS_MESSAGE_SECURITY_HEADER_SIZE;
	int bytes = 0;

	nas_message_t	nas_msg;
	memset (&nas_msg,		 0, sizeof (nas_message_t));
	nas_msg.header.extended_protocol_discriminator = EPD_5GS_SESSION_MANAGEMENT_MESSAGES;
	nas_msg.header.security_header_type = SECURITY_HEADER_TYPE_INTEGRITY_PROTECTED_CYPHERED;
	uint8_t sequencenumber = 0xfe;
	//uint32_t mac = 0xffffeeee;
	uint32_t mac = 0xffee;
	nas_msg.header.sequence_number = sequencenumber;
	nas_msg.header.message_authentication_code= mac;
	nas_msg.security_protected.header = nas_msg.header;
	SM_msg * sm_msg;
	// memset (&sm_msg->specific_msg.pdu_session_establishment_request,		 0, sizeof (pdu_session_establishment_request_msg));
	sm_msg = &nas_msg.security_protected.plain.sm;
	sm_msg->header.extended_protocol_discriminator = EPD_5GS_SESSION_MANAGEMENT_MESSAGES;
	sm_msg->header.pdu_session_identity = 1;
    sm_msg->header.procedure_transaction_identity = 1;
	sm_msg->header.message_type = PDU_SESSION_RELEASE_COMPLETE;

/*********************sm_msg->specific_msg.pdu_session_release_complete statr******************************/

    #if 0
	sm_msg->specific_msg.pdu_session_release_complete.extendedprotocoldiscriminator = 0X2E;


	bstring pdusessionidentity_tmp = bfromcstralloc(10, "\0");
	uint8_t bitStream_pdusessionidentity = 0X01;
	pdusessionidentity_tmp->data = (unsigned char *)(&bitStream_pdusessionidentity);
	pdusessionidentity_tmp->slen = 1;
	sm_msg->specific_msg.pdu_session_release_complete.pdusessionidentity = pdusessionidentity_tmp;

	bstring proceduretransactionidentity_tmp = bfromcstralloc(10, "\0");
	uint8_t bitStream_proceduretransactionidentity = 0X01;
	proceduretransactionidentity_tmp->data = (unsigned char *)(&bitStream_proceduretransactionidentity);
	proceduretransactionidentity_tmp->slen = 1;
    sm_msg->specific_msg.pdu_session_release_complete.proceduretransactionidentity = proceduretransactionidentity_tmp;

    sm_msg->specific_msg.pdu_session_release_complete.messagetype = 0XC1;
    #endif

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

	size += MESSAGE_TYPE_MAXIMUM_LENGTH;

	//memcpy(&nas_msg.plain.sm,&nas_msg.security_protected.plain.sm,sizeof(nas_msg.security_protected.plain.sm));
	nas_msg.plain.sm = *sm_msg;

	//complete sm msg content
	if(size <= 0){
		return -1;
	}

	//construct security context
	fivegmm_security_context_t * security = (fivegmm_security_context_t *)calloc(1,sizeof(fivegmm_security_context_t));
	security->selected_algorithms.encryption = NAS_SECURITY_ALGORITHMS_NEA1;
	security->dl_count.overflow = 0xffff;
	security->dl_count.seq_num =  0x23;
	security->knas_enc[0] = 0x14;
	security->selected_algorithms.integrity = NAS_SECURITY_ALGORITHMS_NIA1;
	security->knas_int[0] = 0x41;
	//complete sercurity context

	int length = BUF_LEN;
	unsigned char data[BUF_LEN] = {'\0'};

	bstring  info = bfromcstralloc(length, "\0");//info the nas_message_encode result

	#if 0
	printf("1 start nas_message_encode \n");
	printf("security %p\n",security);
	printf("info %p\n",info);
	#endif

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
	bytes = nas_message_encode (data, &nas_msg, sizeof(data)/*don't know the size*/, security);


	printf("Data = ");

	for(int i = 0;i<bytes;i++)
		printf("%02x ",data[i]);
	printf("\n");

	info->data = data;
	info->slen = bytes;


   /***********creat bin file************************/

	creat_dir_sm_encode();

	char datahex[512];
	for(int i=0;i<bytes;i++)
		sprintf(datahex+i*2,"%02x",data[i]);

	FILE *fp;
	fp = fopen("../../build/smf/build/sm_encode_file/sm_encode_release_complete.txt","w");
	fwrite(datahex,bytes*2/*sizeof(data)*/,1,fp);

	fclose(fp);
	/*****************  end  ************************/
	printf("PDU_SESSION_RELEASE_COMPLETE------------ encode end\n");
	return  0;
}

int sm_encode__5gsm_status_(void)
{
	printf("_5GSM_STATUS------------ encode start\n");
	int size = NAS_MESSAGE_SECURITY_HEADER_SIZE;
	int bytes = 0;

	nas_message_t	nas_msg;
	memset (&nas_msg,		 0, sizeof (nas_message_t));
	nas_msg.header.extended_protocol_discriminator = EPD_5GS_SESSION_MANAGEMENT_MESSAGES;
	nas_msg.header.security_header_type = SECURITY_HEADER_TYPE_INTEGRITY_PROTECTED_CYPHERED;
	uint8_t sequencenumber = 0xfe;
	//uint32_t mac = 0xffffeeee;
	uint32_t mac = 0xffee;
	nas_msg.header.sequence_number = sequencenumber;
	nas_msg.header.message_authentication_code= mac;
	nas_msg.security_protected.header = nas_msg.header;
	SM_msg * sm_msg;
	// memset (&sm_msg->specific_msg.pdu_session_establishment_request,		 0, sizeof (pdu_session_establishment_request_msg));
	sm_msg = &nas_msg.security_protected.plain.sm;
	sm_msg->header.extended_protocol_discriminator = EPD_5GS_SESSION_MANAGEMENT_MESSAGES;
	sm_msg->header.pdu_session_identity = 1;
    sm_msg->header.procedure_transaction_identity = 1;
	sm_msg->header.message_type = _5GSM_STATUS;

/*********************sm_msg->specific_msg._5gsm_status statr******************************/

    #if 0
	sm_msg->specific_msg._5gsm_status.extendedprotocoldiscriminator = 0X2E;


	bstring pdusessionidentity_tmp = bfromcstralloc(10, "\0");
	uint8_t bitStream_pdusessionidentity = 0X01;
	pdusessionidentity_tmp->data = (unsigned char *)(&bitStream_pdusessionidentity);
	pdusessionidentity_tmp->slen = 1;
	sm_msg->specific_msg._5gsm_status.pdusessionidentity = pdusessionidentity_tmp;

	bstring proceduretransactionidentity_tmp = bfromcstralloc(10, "\0");
	uint8_t bitStream_proceduretransactionidentity = 0X01;
	proceduretransactionidentity_tmp->data = (unsigned char *)(&bitStream_proceduretransactionidentity);
	proceduretransactionidentity_tmp->slen = 1;
    sm_msg->specific_msg._5gsm_status.proceduretransactionidentity = proceduretransactionidentity_tmp;

    sm_msg->specific_msg._5gsm_status.messagetype = 0XC1;
    #endif

	sm_msg->specific_msg._5gsm_status._5gsmcause = 0b00001000;


/*********************sm_msg->specific_msg._5gsm_status end******************************/

	size += MESSAGE_TYPE_MAXIMUM_LENGTH;

	//memcpy(&nas_msg.plain.sm,&nas_msg.security_protected.plain.sm,sizeof(nas_msg.security_protected.plain.sm));
	nas_msg.plain.sm = *sm_msg;

	//complete sm msg content
	if(size <= 0){
		return -1;
	}

	//construct security context
	fivegmm_security_context_t * security = (fivegmm_security_context_t *)calloc(1,sizeof(fivegmm_security_context_t));
	security->selected_algorithms.encryption = NAS_SECURITY_ALGORITHMS_NEA1;
	security->dl_count.overflow = 0xffff;
	security->dl_count.seq_num =  0x23;
	security->knas_enc[0] = 0x14;
	security->selected_algorithms.integrity = NAS_SECURITY_ALGORITHMS_NIA1;
	security->knas_int[0] = 0x41;
	//complete sercurity context

	int length = BUF_LEN;
	unsigned char data[BUF_LEN] = {'\0'};

	bstring  info = bfromcstralloc(length, "\0");//info the nas_message_encode result

	#if 0
	printf("1 start nas_message_encode \n");
	printf("security %p\n",security);
	printf("info %p\n",info);
	#endif

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
	bytes = nas_message_encode (data, &nas_msg, sizeof(data)/*don't know the size*/, security);


	printf("Data = ");

	for(int i = 0;i<bytes;i++)
		printf("%02x ",data[i]);
	printf("\n");

	info->data = data;
	info->slen = bytes;


   /***********creat bin file************************/

	creat_dir_sm_encode();

	char datahex[512];
	for(int i=0;i<bytes;i++)
		sprintf(datahex+i*2,"%02x",data[i]);

	FILE *fp;
	fp = fopen("../../build/smf/build/sm_encode_file/sm_encode__5gsm_status_.txt","w");
	fwrite(datahex,bytes*2/*sizeof(data)*/,1,fp);

	fclose(fp);
	/*****************  end  ************************/
	printf("_5GSM_STATUS------------ encode end\n");
	return  0;
}


int sm_encode_all(void)
{	
	sm_encode_establishment_request();
	sm_encode_establishment_accept();
	sm_encode_establishment_reject();
	sm_encode_authentication_command();
	sm_encode_authentication_complete();
	sm_encode_authentication_result();
	sm_encode_modification_request();
	sm_encode_modification_reject();
	sm_encode_modification_command();
	sm_encode_modification_complete();
	sm_encode_modification_command_reject();
	sm_encode_release_request();
	sm_encode_release_reject();
	sm_encode_release_command();
	sm_encode_release_complete();
	sm_encode__5gsm_status_();

	return 0;
}
