#include  "ng_pdu_handover_request.h"
#include  "Ngap_HandoverRequest.h"

#include  "Ngap_NGAP-PDU.h"
#include  "Ngap_ProtocolIE-Field.h"
#include  "Ngap_ProcedureCode.h"
#include  "Ngap_InitiatingMessage.h"

#include  "Ngap_BitRate.h"

#include  "Ngap_UEAggregateMaximumBitRate.h"
#include  "Ngap_ProtocolExtensionContainer.h"
#include  "Ngap_PDUSessionResourceSetupListHOReq.h"
#include  "Ngap_PDUSessionResourceSetupItemHOReq.h"


#include  "Ngap_AllowedNSSAI.h"
#include  "Ngap_AllowedNSSAI-Item.h"
#include  "Ngap_S-NSSAI.h"
#include  "Ngap_SD.h"
#include  "Ngap_UEIdentityIndexValue.h"
#include  "Ngap_PagingDRX.h"
#include  "Ngap_PeriodicRegistrationUpdateTimer.h"
#include  "Ngap_MICOModeIndication.h"
#include  "Ngap_TAIListForInactive.h"
#include  "Ngap_TAIListForInactiveItem.h"
#include  "Ngap_ExpectedUEBehaviour.h"
#include  "Ngap_ExpectedUEActivityBehaviour.h"
#include  "Ngap_ExpectedUEMovingTrajectory.h"
#include  "Ngap_ProtocolExtensionContainer.h"
#include  "Ngap_ExpectedActivityPeriod.h"
#include  "Ngap_ExpectedIdlePeriod.h"
#include  "Ngap_SourceOfUEActivityBehaviourInformation.h"
#include  "Ngap_ExpectedHOInterval.h"
#include  "Ngap_ExpectedUEMobility.h"
#include  "Ngap_ExpectedUEMovingTrajectory.h"
#include  "Ngap_ExpectedUEMovingTrajectoryItem.h"
#include  "Ngap_ExpectedUEMovingTrajectory.h"
#include  "Ngap_ExpectedUEMovingTrajectoryItem.h"
#include  "Ngap_NGRAN-CGI.h"
#include  "Ngap_NR-CGI.h"
#include  "Ngap_EUTRA-CGI.h"
#include  "Ngap_TAI.h"
#include  "Ngap_UESecurityCapabilities.h"
#include  "Ngap_PDUSessionID.h"
#include  "Ngap_S-NSSAI.h"
#include  "Ngap_SD.h"
#include  "Ngap_NGRANTraceID.h"
#include  "Ngap_InterfacesToTrace.h"
#include  "Ngap_TraceDepth.h"
#include  "Ngap_TransportLayerAddress.h"


#include  "Ngap_Criticality.h"

#include  "Ngap_HandoverType.h"

#include  "Ngap_CauseRadioNetwork.h"

#include  "Ngap_TargetRANNodeID.h"
#include  "Ngap_TargeteNB-ID.h"
#include  "Ngap_ProtocolIE-SingleContainer.h"
#include  "Ngap_TAI.h"

#include  "common_defs.h"
#include  "common_types.h"
#include  "../common/ngap/ngap_common.h"


#include  "INTEGER.h"
#include  "asn_SEQUENCE_OF.h"
#include  "OCTET_STRING.h"

#define BUF_LEN   1024

Ngap_HandoverRequestIEs_t  *make_handover_request_AMF_UE_NGAP_ID(uint64_t amf_UE_NGAP_ID)
{
    Ngap_HandoverRequestIEs_t *ie = NULL;
	ie                = calloc(1, sizeof(Ngap_HandoverRequestIEs_t));
	
	ie->id            = Ngap_ProtocolIE_ID_id_AMF_UE_NGAP_ID;
	ie->criticality   = Ngap_Criticality_reject;
	ie->value.present = Ngap_HandoverRequestIEs__value_PR_AMF_UE_NGAP_ID;

	asn_ulong2INTEGER(&ie->value.choice.AMF_UE_NGAP_ID, amf_UE_NGAP_ID & AMF_UE_NGAP_ID_MASK_);
	
	printf("AMF_UE_NGAP_ID:0x%x\n",ie->value.choice.AMF_UE_NGAP_ID);
	
	return ie;
}

Ngap_HandoverRequestIEs_t  *make_handover_request_HandoverType(const long handoverType)
{
	Ngap_HandoverRequestIEs_t *ie = NULL;
	ie                             = calloc(1, sizeof(Ngap_HandoverRequestIEs_t));
	
	ie->id                         = Ngap_ProtocolIE_ID_id_HandoverType;
	ie->criticality                = Ngap_Criticality_reject;
	ie->value.present              = Ngap_HandoverRequestIEs__value_PR_HandoverType;
	
    ie->value.choice.HandoverType  = handoverType;
	
	printf("handoverType:0x%x\n",ie->value.choice.HandoverType);
	return ie;
}

Ngap_HandoverRequestIEs_t  *make_handover_request_CauseRadioNetwork(const long radioNetwork)
{
	Ngap_HandoverRequestIEs_t *ie = NULL;
	ie                                          = calloc(1, sizeof(Ngap_HandoverRequestIEs_t));
	
	ie->id                                      = Ngap_ProtocolIE_ID_id_Cause;
	ie->criticality                             = Ngap_Criticality_ignore;
	ie->value.present                           = Ngap_HandoverRequestIEs__value_PR_Cause;


    ie->value.choice.Cause.present              = Ngap_Cause_PR_radioNetwork;
    ie->value.choice.Cause.choice.radioNetwork  = radioNetwork;

	printf("radioNetwork:0x%x\n",ie->value.choice.Cause.choice.radioNetwork);
	return ie;
}


Ngap_HandoverRequestIEs_t  *make_handover_request_UEAggregateMaximumBitRate()
{
	Ngap_HandoverRequestIEs_t *ie = NULL;
	ie                                          = calloc(1, sizeof(Ngap_HandoverRequestIEs_t));
	
	ie->id                                      = Ngap_ProtocolIE_ID_id_UEAggregateMaximumBitRate;
	ie->criticality                             = Ngap_Criticality_ignore;
	ie->value.present                           = Ngap_HandoverRequestIEs__value_PR_UEAggregateMaximumBitRate;

	return ie;
}


Ngap_HandoverRequestIEs_t *  make_handover_request_CoreNetworkAssistanceInformation()
{
	Ngap_HandoverRequestIEs_t *ie = NULL;
	ie	= calloc(1, sizeof(Ngap_HandoverRequestIEs_t));
	memset(ie, 0, sizeof(Ngap_HandoverRequestIEs_t));
			
	ie->id            = Ngap_ProtocolIE_ID_id_CoreNetworkAssistanceInformation; 
	ie->criticality   = Ngap_Criticality_ignore;
	ie->value.present = Ngap_HandoverRequestIEs__value_PR_CoreNetworkAssistanceInformation;
	return ie;

}

Ngap_HandoverRequestIEs_t *  make_handover_request_UESecurityCapabilities()
{
	Ngap_HandoverRequestIEs_t *ie = NULL;
	ie	= calloc(1, sizeof(Ngap_HandoverRequestIEs_t));
	memset(ie, 0, sizeof(Ngap_HandoverRequestIEs_t));
			
	ie->id            = Ngap_ProtocolIE_ID_id_UESecurityCapabilities; 
	ie->criticality   = Ngap_Criticality_ignore;
	ie->value.present = Ngap_HandoverRequestIEs__value_PR_UESecurityCapabilities;
	return ie;

}


Ngap_HandoverRequestIEs_t *make_handover_request_SecurityContext()
{
	Ngap_HandoverRequestIEs_t *ie = NULL;
    ie  = calloc(1, sizeof(Ngap_HandoverRequestIEs_t));
	
	ie->id            = Ngap_ProtocolIE_ID_id_SecurityContext; 
	ie->criticality   = Ngap_Criticality_reject;
	ie->value.present = Ngap_HandoverRequestIEs__value_PR_SecurityContext;

    return ie;
}


Ngap_HandoverRequestIEs_t *make_handover_request_NewSecurityContextInd(const e_Ngap_NewSecurityContextInd ContextInd)
{
	Ngap_HandoverRequestIEs_t *ie = NULL;
    ie  = calloc(1, sizeof(Ngap_HandoverRequestIEs_t));
	
	ie->id            = Ngap_ProtocolIE_ID_id_NewSecurityContextInd; 
	ie->criticality   = Ngap_Criticality_reject;
	ie->value.present = Ngap_HandoverRequestIEs__value_PR_NewSecurityContextInd;
	ie->value.choice.NewSecurityContextInd = ContextInd;
    return ie;
}

Ngap_HandoverRequestIEs_t  *make_handover_request_NAS_PDU(const char *nas_pdu)
{
    Ngap_HandoverRequestIEs_t *ie = NULL;
	ie = calloc(1, sizeof(Ngap_HandoverRequestIEs_t));
	
    memset(ie, 0 , sizeof(Ngap_HandoverRequestIEs_t));
	
	ie->id            = Ngap_ProtocolIE_ID_id_NASC;
	ie->criticality   = Ngap_Criticality_reject;
	ie->value.present = Ngap_HandoverRequestIEs__value_PR_NAS_PDU;
	
	OCTET_STRING_fromBuf (&ie->value.choice.NAS_PDU, nas_pdu, strlen(nas_pdu));
	
    printf("nas_pdu:%s\n", nas_pdu);

	
	return ie;
}

Ngap_HandoverRequestIEs_t  *make_handover_request_PDUSessionResourceSetupListHOReq( )
{
    Ngap_HandoverRequestIEs_t *ie = NULL;
	ie = calloc(1, sizeof(Ngap_HandoverRequestIEs_t));
	
    memset(ie, 0 , sizeof(Ngap_HandoverRequestIEs_t));
	
	ie->id            = Ngap_ProtocolIE_ID_id_PDUSessionResourceSetupListHOReq;
	ie->criticality   = Ngap_Criticality_reject;
	ie->value.present = Ngap_HandoverRequestIEs__value_PR_PDUSessionResourceSetupListHOReq;
	

	return ie;
}

Ngap_HandoverRequestIEs_t *  make_handover_request_AllowedNSSAI_ie()
{
	Ngap_HandoverRequestIEs_t *ie = NULL;
	ie	= calloc(1, sizeof(Ngap_HandoverRequestIEs_t));
	memset(ie, 0, sizeof(Ngap_HandoverRequestIEs_t));
			
	ie->id            = Ngap_ProtocolIE_ID_id_AllowedNSSAI; 
	ie->criticality   = Ngap_Criticality_reject;
	ie->value.present = Ngap_HandoverRequestIEs__value_PR_AllowedNSSAI;
	return ie;
}

Ngap_HandoverRequestIEs_t *  make_handover_request_TraceActivation()
{
	Ngap_HandoverRequestIEs_t *ie = NULL;
	ie	= calloc(1, sizeof(Ngap_HandoverRequestIEs_t));
	memset(ie, 0, sizeof(Ngap_HandoverRequestIEs_t));
			
	ie->id            = Ngap_ProtocolIE_ID_id_TraceActivation; 
	ie->criticality   = Ngap_Criticality_reject;
	ie->value.present = Ngap_HandoverRequestIEs__value_PR_TraceActivation;
	return ie;
}

void add_pdu_handover_request_ie(Ngap_HandoverRequest_t *ngapPDUHandoverRequest, Ngap_HandoverRequestIEs_t *ie) {
    int ret;
	ret = ASN_SEQUENCE_ADD(&ngapPDUHandoverRequest->protocolIEs.list, ie);
    if ( ret != 0 ) {
        fprintf(stderr, "Failed to add ie\n");
		return ;
    }
	return ;
}
Ngap_NGAP_PDU_t *  ngap_generate_ng_handover_request(const char *inputBuf)

{
    Ngap_NGAP_PDU_t * pdu = NULL;
	pdu = calloc(1, sizeof(Ngap_NGAP_PDU_t));
    
	pdu->present = Ngap_NGAP_PDU_PR_initiatingMessage;
	pdu->choice.initiatingMessage = calloc(1, sizeof(Ngap_InitiatingMessage_t));
	pdu->choice.initiatingMessage->procedureCode = Ngap_ProcedureCode_id_HandoverResourceAllocation;
	                                               
	pdu->choice.initiatingMessage->criticality   = Ngap_Criticality_reject;
	pdu->choice.initiatingMessage->value.present = Ngap_InitiatingMessage__value_PR_HandoverRequest;

    Ngap_HandoverRequest_t *ngapPDUHandoverRequest = NULL;
	ngapPDUHandoverRequest = &pdu->choice.initiatingMessage->value.choice.HandoverRequest;
	
	Ngap_HandoverRequestIEs_t  *ie = NULL;

    //Ngap_AMF_UE_NGAP_ID_t
	uint64_t  amf_ue_ngap_id = 0x80;
	ie  = make_handover_request_AMF_UE_NGAP_ID(amf_ue_ngap_id);
    add_pdu_handover_request_ie(ngapPDUHandoverRequest, ie);

	//Ngap_HandoverType
	ie = make_handover_request_HandoverType(Ngap_HandoverType_intra5gs);
	add_pdu_handover_request_ie(ngapPDUHandoverRequest, ie);
   
	//Cause:CauseRadioNetwork
	ie = make_handover_request_CauseRadioNetwork(Ngap_CauseRadioNetwork_unspecified);
    add_pdu_handover_request_ie(ngapPDUHandoverRequest, ie);
	
    //UEAggregateMaximumBitRate
    uint64_t   BitRateDL  = 0x01;
	uint64_t   BitRateUL  = 0x01;
	ie = make_handover_request_UEAggregateMaximumBitRate();
	asn_uint642INTEGER(&ie->value.choice.UEAggregateMaximumBitRate.uEAggregateMaximumBitRateDL, BitRateDL);
	asn_uint642INTEGER(&ie->value.choice.UEAggregateMaximumBitRate.uEAggregateMaximumBitRateUL, BitRateUL);
	add_pdu_handover_request_ie(ngapPDUHandoverRequest, ie);
	printf("BitRateDL:0x%x, BitRateUL:0x%x", BitRateDL, BitRateUL);


	//CoreNetworkAssistanceInformation
	//Ngap_CoreNetworkAssistanceInformation_t	 CoreNetworkAssistanceInformation;
	ie  =  make_handover_request_CoreNetworkAssistanceInformation();

    //uEIdentityIndexValue   10Bits
	//Ngap_UEIdentityIndexValue_t	 uEIdentityIndexValue;
	uint8_t indexValue[2] = {0x01,0x02};
	ie->value.choice.CoreNetworkAssistanceInformation.uEIdentityIndexValue.present = Ngap_UEIdentityIndexValue_PR_indexLength10  ;
	ie->value.choice.CoreNetworkAssistanceInformation.uEIdentityIndexValue.choice.indexLength10.buf  = calloc(2, sizeof(uint8_t));
	memset(ie->value.choice.CoreNetworkAssistanceInformation.uEIdentityIndexValue.choice.indexLength10.buf, indexValue, 2);
	ie->value.choice.CoreNetworkAssistanceInformation.uEIdentityIndexValue.choice.indexLength10.size = 2;
	ie->value.choice.CoreNetworkAssistanceInformation.uEIdentityIndexValue.choice.indexLength10.bits_unused = 0x06;
	printf("uEIdentityIndexValue:0x%x,0x%x\n",indexValue[0],indexValue[1]);

	
	//Ngap_PagingDRX_t	*uESpecificDRX;	/* OPTIONAL */
	Ngap_PagingDRX_t	*puESpecificDRX = calloc(1, sizeof(Ngap_PagingDRX_t));
	*puESpecificDRX  = Ngap_PagingDRX_v32;
	ie->value.choice.CoreNetworkAssistanceInformation.uESpecificDRX  = puESpecificDRX; 
	printf("uESpecificDRX:0x%x\n",*puESpecificDRX);
	
	//Ngap_PeriodicRegistrationUpdateTimer_t	 periodicRegistrationUpdateTimer;
	uint8_t  period[1] = {0x01};
	ie->value.choice.CoreNetworkAssistanceInformation.periodicRegistrationUpdateTimer.buf  = calloc(1, sizeof(uint8_t));
	memset(ie->value.choice.CoreNetworkAssistanceInformation.periodicRegistrationUpdateTimer.buf, period, 1);
	ie->value.choice.CoreNetworkAssistanceInformation.periodicRegistrationUpdateTimer.size = 1;
	ie->value.choice.CoreNetworkAssistanceInformation.periodicRegistrationUpdateTimer.bits_unused = 0;
	printf("periodicRegistrationUpdateTimer:0x%x\n",period[0]);


	
	//Ngap_MICOModeIndication_t	*mICOModeIndication;	/* OPTIONAL */
	Ngap_MICOModeIndication_t	*pmICOModeIndication  = calloc(1, sizeof(Ngap_MICOModeIndication_t));
	*pmICOModeIndication  = Ngap_MICOModeIndication_true;
	ie->value.choice.CoreNetworkAssistanceInformation.mICOModeIndication  =  pmICOModeIndication;
	printf("mICOModeIndication:0x%x\n",*pmICOModeIndication);
	
	
	//Ngap_TAIListForInactive_t	 tAIListForInactive;
	Ngap_TAIListForInactiveItem_t  *pInactiveItem = NULL;
	pInactiveItem  = calloc(1, sizeof(Ngap_TAIListForInactiveItem_t));

	uint8_t plmn[3] = { 0x02, 0xF8, 0x29 };
	OCTET_STRING_fromBuf(&pInactiveItem->tAI.pLMNIdentity, (const char*)plmn, 3);

	uint8_t tac[3] = { 0x01, 0xF8, 0x29 };
	OCTET_STRING_fromBuf(&pInactiveItem->tAI.tAC, (const char*)tac, 3);

	ASN_SEQUENCE_ADD(&ie->value.choice.CoreNetworkAssistanceInformation.tAIListForInactive.list, pInactiveItem);
	
	
	//expectedUEBehaviour
	Ngap_ExpectedUEBehaviour_t	*pexpectedUEBehaviour  = NULL;;	/* OPTIONAL */
    pexpectedUEBehaviour   = calloc(1, sizeof(Ngap_ExpectedUEBehaviour_t));

    //expectedUEActivityBehaviour
    
    Ngap_ExpectedUEActivityBehaviour_t	*pexpectedUEActivityBehaviour  = NULL;
	pexpectedUEActivityBehaviour   = calloc(1, sizeof(Ngap_ExpectedUEActivityBehaviour_t));
	
    Ngap_ExpectedActivityPeriod_t	*expectedActivityPeriod  = NULL;	/* OPTIONAL */
	expectedActivityPeriod         = calloc(1, sizeof(Ngap_ExpectedActivityPeriod_t));
	*expectedActivityPeriod         =  0x01;
    pexpectedUEActivityBehaviour->expectedActivityPeriod  = expectedActivityPeriod;
	
	Ngap_ExpectedIdlePeriod_t	*expectedIdlePeriod = NULL;	/* OPTIONAL */
	expectedIdlePeriod         = calloc(1, sizeof(expectedIdlePeriod));
	*expectedIdlePeriod         =  0x01;
	pexpectedUEActivityBehaviour->expectedIdlePeriod  = expectedIdlePeriod;
	
	Ngap_SourceOfUEActivityBehaviourInformation_t	*sourceOfUEActivityBehaviourInformation = NULL;	/* OPTIONAL */
    sourceOfUEActivityBehaviourInformation   = calloc(1, sizeof(Ngap_SourceOfUEActivityBehaviourInformation_t));
	*sourceOfUEActivityBehaviourInformation  =  0x01;
	pexpectedUEActivityBehaviour->sourceOfUEActivityBehaviourInformation  = sourceOfUEActivityBehaviourInformation;

    pexpectedUEBehaviour->expectedUEActivityBehaviour  = pexpectedUEActivityBehaviour;

    ie->value.choice.CoreNetworkAssistanceInformation.expectedUEBehaviour   =  pexpectedUEBehaviour;



    //Ngap_ExpectedHOInterval_t	*expectedHOInterval;	/* OPTIONAL */
    Ngap_ExpectedHOInterval_t  *pHOInterval = NULL;
	pHOInterval  = calloc(1, sizeof(Ngap_ExpectedHOInterval_t));
	*pHOInterval	  = Ngap_ExpectedHOInterval_sec15;
	ie->value.choice.CoreNetworkAssistanceInformation.expectedUEBehaviour->expectedHOInterval  = pHOInterval;
    
	//Ngap_ExpectedUEMobility_t	*expectedUEMobility;	/* OPTIONAL */
	Ngap_ExpectedUEMobility_t  *pexpectedUEMobility  = NULL;
	pexpectedUEMobility  = calloc(1, sizeof(Ngap_ExpectedUEMobility_t));
	*pexpectedUEMobility  = Ngap_ExpectedUEMobility_stationary;
	ie->value.choice.CoreNetworkAssistanceInformation.expectedUEBehaviour->expectedUEMobility  = pexpectedUEMobility;
	
	
	//Ngap_ExpectedUEMovingTrajectory_t	*expectedUEMovingTrajectory;
	Ngap_ExpectedUEMovingTrajectory_t	*expectedUEMovingTrajectory   = calloc(1, sizeof(Ngap_ExpectedUEMovingTrajectory_t));

	Ngap_ExpectedUEMovingTrajectoryItem_t  *pTrajectoryItem = NULL;
	pTrajectoryItem  = calloc(1, sizeof(Ngap_ExpectedUEMovingTrajectoryItem_t));

	pTrajectoryItem->nGRAN_CGI.present = Ngap_NGRAN_CGI_PR_nR_CGI;
	Ngap_NR_CGI_t *pnR_CGI  = calloc(1, sizeof(Ngap_NR_CGI_t));

    uint8_t nr_plmn[3] = { 0x02, 0xF8, 0x29 };
	OCTET_STRING_fromBuf(&pnR_CGI->pLMNIdentity, (const char*)nr_plmn, 3);

    uint8_t cell[5] = {0x00,0x01,0x02,0x03,0x04};
	pnR_CGI->nRCellIdentity.buf = calloc(5, sizeof(uint8_t));
	pnR_CGI->nRCellIdentity.size = 5;
	memcpy(pnR_CGI->nRCellIdentity.buf, &cell, 5);
	pnR_CGI->nRCellIdentity.bits_unused = 0x04;

	pTrajectoryItem->nGRAN_CGI.choice.nR_CGI   = pnR_CGI;

	long	*timeStayedInCell = calloc(1, sizeof(long));
	*timeStayedInCell   = 0x01;
	pTrajectoryItem->timeStayedInCell  = timeStayedInCell;
	
	ASN_SEQUENCE_ADD(&expectedUEMovingTrajectory->list, pTrajectoryItem);
	
    ie->value.choice.CoreNetworkAssistanceInformation.expectedUEBehaviour->expectedUEMovingTrajectory   = expectedUEMovingTrajectory;
    add_pdu_handover_request_ie(ngapPDUHandoverRequest, ie);



    //UESecurityCapabilities
	ie  = make_handover_request_UESecurityCapabilities();

	//nRencryptionAlgorithms;
	char  nRencryptionAlgorithms[2] = {0x00,0x01};
	ie->value.choice.UESecurityCapabilities.nRencryptionAlgorithms.buf = calloc(2, sizeof(uint8_t));
    ie->value.choice.UESecurityCapabilities.nRencryptionAlgorithms.size = 2;
	memcpy(ie->value.choice.UESecurityCapabilities.nRencryptionAlgorithms.buf , &nRencryptionAlgorithms, 2);
	ie->value.choice.UESecurityCapabilities.nRencryptionAlgorithms.bits_unused = 0;
    
	printf("nRencryptionAlgorithms:0x%x,0x%x\n", 
	ie->value.choice.UESecurityCapabilities.nRencryptionAlgorithms.buf[0],ie->value.choice.UESecurityCapabilities.nRencryptionAlgorithms.buf[1]);
	
	//nRintegrityProtectionAlgorithms;
	char  nRintegrityProtectionAlgorithms[2] = {0x00,0x00};
	ie->value.choice.UESecurityCapabilities.nRintegrityProtectionAlgorithms.buf = calloc(2, sizeof(uint8_t));
    ie->value.choice.UESecurityCapabilities.nRintegrityProtectionAlgorithms.size = 2;
	memcpy(ie->value.choice.UESecurityCapabilities.nRintegrityProtectionAlgorithms.buf , &nRintegrityProtectionAlgorithms, 2);
	ie->value.choice.UESecurityCapabilities.nRintegrityProtectionAlgorithms.bits_unused = 0;

    printf("nRintegrityProtectionAlgorithms:0x%x,0x%x\n", 
	ie->value.choice.UESecurityCapabilities.nRintegrityProtectionAlgorithms.buf[0],ie->value.choice.UESecurityCapabilities.nRintegrityProtectionAlgorithms.buf[1]);
	
	
	//eUTRAencryptionAlgorithms;
	char  eUTRAencryptionAlgorithms[2] = {0x00,0x01};
	ie->value.choice.UESecurityCapabilities.eUTRAencryptionAlgorithms.buf = calloc(2, sizeof(uint8_t));
    ie->value.choice.UESecurityCapabilities.eUTRAencryptionAlgorithms.size = 2;
	memcpy(ie->value.choice.UESecurityCapabilities.eUTRAencryptionAlgorithms.buf , &eUTRAencryptionAlgorithms, 2);
	ie->value.choice.UESecurityCapabilities.eUTRAencryptionAlgorithms.bits_unused = 0;
	printf("eUTRAencryptionAlgorithms:0x%x,0x%x\n", 
	ie->value.choice.UESecurityCapabilities.eUTRAencryptionAlgorithms.buf[0],ie->value.choice.UESecurityCapabilities.eUTRAencryptionAlgorithms.buf[1]);
	
	
	//eUTRAintegrityProtectionAlgorithms
	char  eUTRAintegrityProtectionAlgorithms[2] = {0x00,0x01};
	ie->value.choice.UESecurityCapabilities.eUTRAintegrityProtectionAlgorithms.buf = calloc(2, sizeof(uint8_t));
    ie->value.choice.UESecurityCapabilities.eUTRAintegrityProtectionAlgorithms.size = 2;
	memcpy(ie->value.choice.UESecurityCapabilities.eUTRAintegrityProtectionAlgorithms.buf , &eUTRAintegrityProtectionAlgorithms, 2);
	ie->value.choice.UESecurityCapabilities.eUTRAintegrityProtectionAlgorithms.bits_unused = 0;
	printf("eUTRAintegrityProtectionAlgorithms:0x%x,0x%x\n", 
	ie->value.choice.UESecurityCapabilities.eUTRAintegrityProtectionAlgorithms.buf[0],ie->value.choice.UESecurityCapabilities.eUTRAintegrityProtectionAlgorithms.buf[1]);
	
	add_pdu_handover_request_ie(ngapPDUHandoverRequest, ie);


    //SecurityContext
    ie  = make_handover_request_SecurityContext();
	uint8_t  nextHopNH[32] = {0x00,0x01};

	//Ngap_NextHopChainingCount_t	 nextHopChainingCount;
	ie->value.choice.SecurityContext.nextHopChainingCount =  0x01;
	printf("nextHopChainingCount:0x%x\n",ie->value.choice.SecurityContext.nextHopChainingCount);

	//Ngap_SecurityKey_t	 nextHopNH;
	ie->value.choice.SecurityContext.nextHopNH.buf = calloc(32, sizeof(uint8_t));
	memcpy(ie->value.choice.SecurityContext.nextHopNH.buf, &nextHopNH, 32);
	ie->value.choice.SecurityContext.nextHopNH.size = 32;
	ie->value.choice.SecurityContext.nextHopNH.bits_unused = 0;
	printf("nextHopNH:0x%x,0x%x\n",nextHopNH[0],nextHopNH[1]);
	add_pdu_handover_request_ie(ngapPDUHandoverRequest, ie);

	//NewSecurityContextInd
	ie  =  make_handover_request_NewSecurityContextInd(Ngap_NewSecurityContextInd_true);
	add_pdu_handover_request_ie(ngapPDUHandoverRequest, ie);

	
	//NAS_PDU
	//Ngap_NAS_PDU_t	 NAS_PDU;
	const char  *nas_pdu  =  "nas_pdu";
    ie  = make_handover_request_NAS_PDU(nas_pdu);
    add_pdu_handover_request_ie(ngapPDUHandoverRequest, ie);


	

    //PDUSessionResourceSetupListHOReq
	Ngap_PDUSessionResourceSetupItemHOReq_t  *pSetupItemHOReq  = calloc(1, sizeof(Ngap_PDUSessionResourceSetupItemHOReq_t));
	ie = make_handover_request_PDUSessionResourceSetupListHOReq();

    pSetupItemHOReq->pDUSessionID  =  0x70;
	printf("pSetupItemHOReq->pDUSessionID:0x%x\n", pSetupItemHOReq->pDUSessionID );

	uint8_t sst[1] = {0x80};
	uint8_t sd[3] = {0x01, 0x02,0x03};
	 

    OCTET_STRING_fromBuf(&pSetupItemHOReq->s_NSSAI.sST, &sst, 1);
	printf("NSSAI.sST:0x%x",pSetupItemHOReq->s_NSSAI.sST.buf[0]);

	Ngap_SD_t *sD = calloc(1, sizeof(Ngap_SD_t));
    pSetupItemHOReq->s_NSSAI.sD = sD;
    OCTET_STRING_fromBuf(sD, sd, 3);
    printf("NSSAI.sd:0x%x,0x%x,0x%x",pSetupItemHOReq->s_NSSAI.sD->buf[0],pSetupItemHOReq->s_NSSAI.sD->buf[1],pSetupItemHOReq->s_NSSAI.sD->buf[2]);
    
	uint8_t handoverRequestTransfer[3] = {0x01, 0x02,0x03};
    OCTET_STRING_fromBuf(&pSetupItemHOReq->handoverRequestTransfer, &handoverRequestTransfer, 3);
	
    ASN_SEQUENCE_ADD(&ie->value.choice.PDUSessionResourceSetupListHOReq.list, pSetupItemHOReq);
	add_pdu_handover_request_ie(ngapPDUHandoverRequest, ie);
	

    //AllowedNSSAI
    Ngap_AllowedNSSAI_t	 AllowedNSSAI;
	ie = make_handover_request_AllowedNSSAI_ie();
	uint8_t sstt[1] = {0x80};
	uint8_t sdd[3] = {0x01, 0x02,0x03};
	 
    Ngap_AllowedNSSAI_Item_t *allowitem = NULL;
	allowitem = calloc(1, sizeof(Ngap_AllowedNSSAI_Item_t));

    OCTET_STRING_fromBuf(&allowitem->s_NSSAI.sST, &sstt, 1);
	printf("NSSAI.sST:0x%x",allowitem->s_NSSAI.sST.buf[0]);

	Ngap_SD_t *sDD = calloc(1, sizeof(Ngap_SD_t));
    allowitem->s_NSSAI.sD = sDD;
    OCTET_STRING_fromBuf(sDD, sdd, 3);
    printf("NSSAI.sd:0x%x,0x%x,0x%x",allowitem->s_NSSAI.sD->buf[0],allowitem->s_NSSAI.sD->buf[1],allowitem->s_NSSAI.sD->buf[2]);
	ASN_SEQUENCE_ADD(&ie->value.choice.AllowedNSSAI.list, allowitem);
	add_pdu_handover_request_ie(ngapPDUHandoverRequest, ie);


	//TraceActivation
	//Ngap_TraceActivation_t	 TraceActivation;

	ie  = make_handover_request_TraceActivation();

    uint8_t nGRANTraceID[8] = {0x01};
	OCTET_STRING_fromBuf(&ie->value.choice.TraceActivation.nGRANTraceID, &nGRANTraceID, 8);
	printf("nGRANTraceID:0x%x\n", nGRANTraceID[0]);
	
	uint8_t interfacesToTrace[1] = {0x01};
    ie->value.choice.TraceActivation.interfacesToTrace.buf = calloc(1, sizeof(uint8_t));
	memcpy(ie->value.choice.TraceActivation.interfacesToTrace.buf, &nextHopNH, 1);
	ie->value.choice.TraceActivation.interfacesToTrace.size = 1;
	ie->value.choice.TraceActivation.interfacesToTrace.bits_unused = 0;

	printf("interfacesToTrace:0x%x\n", interfacesToTrace[0]);
    
	
	ie->value.choice.TraceActivation.traceDepth  = Ngap_TraceDepth_minimum;
	
	printf("traceDepth:0x%x\n", ie->value.choice.TraceActivation.traceDepth);

	
	uint8_t traceCollectionEntityIPAddress[1] = {0x01};
    ie->value.choice.TraceActivation.traceCollectionEntityIPAddress.buf = calloc(1, sizeof(uint8_t));
	memcpy(ie->value.choice.TraceActivation.traceCollectionEntityIPAddress.buf, &nextHopNH, 1);
	ie->value.choice.TraceActivation.traceCollectionEntityIPAddress.size = 1;
	ie->value.choice.TraceActivation.traceCollectionEntityIPAddress.bits_unused = 0;

    printf("traceCollectionEntityIPAddress:0x%x\n", traceCollectionEntityIPAddress[0]);
	
	add_pdu_handover_request_ie(ngapPDUHandoverRequest, ie);

	
    return pdu;
}


int
ngap_amf_handle_ng_pdu_handover_request(
    const sctp_assoc_id_t assoc_id,
    const sctp_stream_id_t stream,
	Ngap_NGAP_PDU_t *pdu){

    int rc = RETURNok;

	#if 0
    gnb_description_t   * gnb_association = NULL; 
	//gnb_description_t   * gnb_ref = NULL;
    uint32_t              gnb_id = 0;
    char                 *gnb_name = NULL;
    int				      gnb_name_size = 0;
    int                   ta_ret = 0;
    uint32_t              max_gnb_connected = 0;
    int i = 0;
	
	#endif

	int i  = 0;
    Ngap_HandoverRequest_t                  *container = NULL;
    Ngap_HandoverRequestIEs_t               *ie = NULL;
    Ngap_HandoverRequestIEs_t               *ie_gnb_name = NULL;

    unsigned  long    amf_ue_ngap_id        = 0;
	uint32_t          ran_ue_ngap_id        = 0;
    uint32_t          handoverType          = 0;
	uint32_t          radioNetwork          = 0;
	uint32_t          DirectForwardingPathAvailability = 0;
	
	uint32_t    pDUSessionid   = 0;
	char       *pDUSessionTransfer  = NULL;
	
	uint16_t                                mcc = 0;
    uint16_t                                mnc = 0;
    uint16_t                                mnc_len = 0;
	

    DevAssert (pdu != NULL);
    //OAILOG_INFO(LOG_NGAP,"----------------------- DECODED NG SETUP REQUEST NGAP MSG --------------------------\n");
    //asn_fprint(stdout, &asn_DEF_Ngap_NGAP_PDU, pdu);
    //OAILOG_INFO(LOG_NGAP,"----------------------- DECODED NG SETUP REQUEST NGAP MSG --------------------------\n");

	container = &pdu->choice.initiatingMessage->value.choice.HandoverRequest;
    
    //AMF_UE_NGAP_ID
    NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_HandoverRequestIEs_t, ie, container, Ngap_ProtocolIE_ID_id_AMF_UE_NGAP_ID, false);
    if (ie) 
	{  
	   asn_INTEGER2ulong(&ie->value.choice.AMF_UE_NGAP_ID, &amf_ue_ngap_id);
	   printf("amf_ue_ngap_id, 0x%x\n", amf_ue_ngap_id);
    }

    //Ngap_HandoverType
    NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_HandoverRequestIEs_t, ie, container, Ngap_ProtocolIE_ID_id_HandoverType, false);
    if (ie) 
	{  
	   handoverType = ie->value.choice.HandoverType;
	   printf("HandoverType, 0x%x\n", handoverType);
    }
	
    //cause
	NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_HandoverRequestIEs_t, ie, container, Ngap_ProtocolIE_ID_id_Cause, false);
	if (ie) 
	{  
	    switch(ie->value.choice.Cause.present)
	    {
			case Ngap_Cause_PR_radioNetwork:
			{
             	radioNetwork = ie->value.choice.Cause.choice.radioNetwork ;
		        printf("radioNetwork, 0x%x\n", radioNetwork);
			}
			break;
			case Ngap_Cause_PR_transport:
			{
			}
			break;
	        case Ngap_Cause_PR_nas:
			{
			}
			break;
	        case Ngap_Cause_PR_protocol:
			{
			}
		    break;
	        case Ngap_Cause_PR_misc:
			{
			}
			break;
			default:
				printf("don't know cause type:%d\n", ie->value.choice.Cause.present);
	    }
	}


    //UEAggregateMaximumBitRate
	NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_HandoverRequestIEs_t, ie, container, Ngap_ProtocolIE_ID_id_UEAggregateMaximumBitRate, false);
	if (ie) 
	{ 
		unsigned long   BitRateDL  = 0;
	 	unsigned long   BitRateUL  = 0;
	 	asn_INTEGER2ulong(&ie->value.choice.UEAggregateMaximumBitRate.uEAggregateMaximumBitRateDL, &BitRateDL);
	 	asn_INTEGER2ulong(&ie->value.choice.UEAggregateMaximumBitRate.uEAggregateMaximumBitRateUL, &BitRateUL);
		
	    printf("BitRateDL:0x%x, BitRateUL:0x%x\n", BitRateDL, BitRateUL);
	}

    //CoreNetworkAssistanceInformation
    NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_HandoverRequestIEs_t, ie, container, Ngap_ProtocolIE_ID_id_CoreNetworkAssistanceInformation, false);
	if (ie) 
	{
	    //uEIdentityIndexValue   10Bits
		//Ngap_UEIdentityIndexValue_t	 uEIdentityIndexValue;
		printf("uEIdentityIndexValue:0x%x\n",
			(uint16_t)((*(ie->value.choice.CoreNetworkAssistanceInformation.uEIdentityIndexValue.choice.indexLength10.buf)	& 0x3FF)));


		//Ngap_PagingDRX_t	*uESpecificDRX;	/* OPTIONAL */
		printf("uESpecificDRX:0x%x\n",*(ie->value.choice.CoreNetworkAssistanceInformation.uESpecificDRX));
		
		//Ngap_PeriodicRegistrationUpdateTimer_t	 periodicRegistrationUpdateTimer;
		printf("periodicRegistrationUpdateTimer:0x%x\n",(uint8_t)(*ie->value.choice.CoreNetworkAssistanceInformation.periodicRegistrationUpdateTimer.buf));

		//Ngap_MICOModeIndication_t	*mICOModeIndication;	/* OPTIONAL */
		printf("mICOModeIndication:0x%x\n",*(ie->value.choice.CoreNetworkAssistanceInformation.mICOModeIndication ));
		
		
		//Ngap_TAIListForInactive_t	 tAIListForInactive;
		
		Ngap_TAIListForInactive_t	 *ptAIListForInactive   = &ie->value.choice.CoreNetworkAssistanceInformation.tAIListForInactive;
		int i  = 0;
		for(i; i<ptAIListForInactive->list.count; i++)
		{
        	Ngap_TAIListForInactiveItem_t  *pInactiveItem = ptAIListForInactive->list.array[i]; 
			if(!pInactiveItem)
			   continue;

            nr_tai_t         nr_tai = {.plmn = {0}, .tac = INVALID_TAC};
            const Ngap_TAI_t* const  tAI = &pInactiveItem->tAI;

			//tac
		    nr_tai.tac = asn1str_to_u24(&tAI->tAC);
			printf("tac:0x%x,\n",nr_tai.tac);
		    //pLMNIdentity
		    TBCD_TO_PLMN_T(&tAI->pLMNIdentity, &nr_tai.plmn);
		}
		
		//expectedUEBehaviour
		
		printf("expectedActivityPeriod:0x%x\n", 
		*(ie->value.choice.CoreNetworkAssistanceInformation.expectedUEBehaviour->expectedUEActivityBehaviour->expectedActivityPeriod));
		
		printf("expectedIdlePeriod:0x%x\n", 
		*(ie->value.choice.CoreNetworkAssistanceInformation.expectedUEBehaviour->expectedUEActivityBehaviour->expectedIdlePeriod));
		
		
		printf("sourceOfUEActivityBehaviourInformation:0x%x\n", 
		*(ie->value.choice.CoreNetworkAssistanceInformation.expectedUEBehaviour->expectedUEActivityBehaviour->sourceOfUEActivityBehaviourInformation));
		


	    //Ngap_ExpectedHOInterval_t	*expectedHOInterval;	/* OPTIONAL */
	  
		printf("expectedHOInterval:0x%x\n", 
		*(ie->value.choice.CoreNetworkAssistanceInformation.expectedUEBehaviour->expectedHOInterval));
		
	   
        printf("expectedUEMobility:0x%x\n", 
		*(ie->value.choice.CoreNetworkAssistanceInformation.expectedUEBehaviour->expectedUEMobility));
		
      
		Ngap_ExpectedUEMovingTrajectory_t	*expectedUEMovingTrajectory  = ie->value.choice.CoreNetworkAssistanceInformation.expectedUEBehaviour->expectedUEMovingTrajectory ;
        for(i  = 0; i <expectedUEMovingTrajectory->list.count; i++)
        {
        	Ngap_ExpectedUEMovingTrajectoryItem_t  *pjectoryItem  = NULL;
			pjectoryItem   = expectedUEMovingTrajectory->list.array[i];
			
			if(pjectoryItem)
				continue;

			
			//CGI mandator
		    const Ngap_NGRAN_CGI_t * const nnR_CGI = &pjectoryItem->nGRAN_CGI;
			if(nnR_CGI)
				continue;
			switch(nnR_CGI->present)
			{
			    case Ngap_NGRAN_CGI_PR_NOTHING:
				{
				}
				break;
            	case Ngap_NGRAN_CGI_PR_nR_CGI:
				{
                    nr_cgi_t         nr_cgi = {.plmn = {0}, .cell_identity = {0}};
					const Ngap_NR_CGI_t * const nR_CGI = &nnR_CGI->choice.nR_CGI;
					
					TBCD_TO_PLMN_T(&nR_CGI->pLMNIdentity, &nr_cgi.plmn);
									 
					//nRCellIdentity
					//DevAssert(nR_CGI->nRCellIdentity.size == 36);
					BIT_STRING_TO_CELL_IDENTITY (&nR_CGI->nRCellIdentity, nr_cgi.cell_identity);
				}
				break;
	            case Ngap_NGRAN_CGI_PR_eUTRA_CGI:
				{
				}
				break;
				default:
					printf("don't know type:0x%x\n",nnR_CGI->present);
				break;

			}			
		}
	}


    //UESecurityCapabilities
    NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_HandoverRequestIEs_t, ie, container, Ngap_ProtocolIE_ID_id_UESecurityCapabilities, false);
	if (ie) 
	{ 
	    uint16_t nRencryptionAlgorithms = BIT_STRING_to_uint16(&ie->value.choice.UESecurityCapabilities.nRencryptionAlgorithms);
		printf("nRencryptionAlgorithms:0x%x\n",nRencryptionAlgorithms);

        uint16_t nRintegrityProtectionAlgorithms = BIT_STRING_to_uint16(&ie->value.choice.UESecurityCapabilities.nRintegrityProtectionAlgorithms);
		printf("nRintegrityProtectionAlgorithms:0x%x\n",nRintegrityProtectionAlgorithms);

		
		uint16_t eUTRAencryptionAlgorithms = BIT_STRING_to_uint16(&ie->value.choice.UESecurityCapabilities.eUTRAencryptionAlgorithms);
		printf("eUTRAencryptionAlgorithms:0x%x\n",eUTRAencryptionAlgorithms);

	    
		uint16_t eUTRAintegrityProtectionAlgorithms = BIT_STRING_to_uint16(&ie->value.choice.UESecurityCapabilities.eUTRAintegrityProtectionAlgorithms);
		printf("eUTRAintegrityProtectionAlgorithms:0x%x\n",eUTRAintegrityProtectionAlgorithms);
	}
	//SecurityContext
    NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_HandoverRequestIEs_t, ie, container, Ngap_ProtocolIE_ID_id_SecurityContext, false);
    if (ie) 
	{ 
		printf("nextHopChainingCount:0x%x\n",ie->value.choice.SecurityContext.nextHopChainingCount);
		printf("nextHopNH:0x%x,0x%x\n",ie->value.choice.SecurityContext.nextHopNH.buf[0],ie->value.choice.SecurityContext.nextHopNH.buf[1]);
			
    }

	//NewSecurityContextInd
    NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_HandoverRequestIEs_t, ie, container, Ngap_ProtocolIE_ID_id_NewSecurityContextInd, false);
    if (ie) 
	{ 
		printf("NewSecurityContextInd:0x%x\n", ie->value.choice.NewSecurityContextInd);
    }


    //NAS_PDU
	NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_HandoverRequestIEs_t, ie, container, Ngap_ProtocolIE_ID_id_NASC, false);
	if (ie) 
	{  
	   const char *nas_pdu      = (char *) ie->value.choice.NAS_PDU.buf;
       int nas_pdu_size = (int) ie->value.choice.NAS_PDU.size;
	  
	   printf("RANNodeName, nas_pdu_size:%d, nas_pdu:%s,\n", nas_pdu_size, nas_pdu);
	}

    //PDUSessionResourceSetupListHOReq
    NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_HandoverRequestIEs_t, ie, container, Ngap_ProtocolIE_ID_id_PDUSessionResourceSetupListHOReq, false);
	if (ie) 
	{  
        Ngap_PDUSessionResourceSetupListHOReq_t	 *pHOReq_container = &ie->value.choice.PDUSessionResourceSetupListHOReq;
			
	    int i  = 0;
		for(;i <pHOReq_container->list.count; i++)
		{
			Ngap_PDUSessionResourceSetupItemHOReq_t *item = pHOReq_container->list.array[i];
			if(!item)
				continue;
			
			printf("pSetupItemHOReq->pDUSessionID:0x%x\n", item->pDUSessionID );
			

            allowed_nssai *s_nssai = calloc(1, sizeof(allowed_nssai));
			
			OCTET_STRING_TO_INT8(&item->s_NSSAI.sST, s_nssai->sST);
			printf("sa.sST:0x%x\n", s_nssai->sST);
		    if(item->s_NSSAI.sD)
		    {
	            s_nssai->sD = asn1str_to_u24(item->s_NSSAI.sD);  
			    printf("NSSAI.sd:0x%x\n", s_nssai->sD); 
		    }   

			const char *transfer =  item->handoverRequestTransfer.buf;
			printf("transfer:0x%x,0x%x,0x%x\n", transfer[0],transfer[1],transfer[2]);
		}	  
	}
	

    
	//AllowedNSSAI
	NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_HandoverRequestIEs_t, ie, container, Ngap_ProtocolIE_ID_id_AllowedNSSAI, false);
	if (ie) 
	{ 
			//init	nr_allowed_nssai.s_nssai  ?
			Ngap_AllowedNSSAI_t  *pAllowedNSSAI = &ie->value.choice.AllowedNSSAI;
			
			int i = 0;
			for(; i < pAllowedNSSAI->list.count; i++)
			{
				 Ngap_AllowedNSSAI_Item_t *pNgap_AllowedNSSAI_p = pAllowedNSSAI->list.array[i];
				 if(!pNgap_AllowedNSSAI_p)
					 continue;
				  
				 allowed_nssai_t  allowed_nssai_tmp = {.s_nssai = NULL, .count = 0};
				 allowed_nssai_tmp.s_nssai = calloc(1, sizeof(allowed_nssai));
				 OCTET_STRING_TO_INT8(&pNgap_AllowedNSSAI_p->s_NSSAI.sST, allowed_nssai_tmp.s_nssai->sST);
				 if(pNgap_AllowedNSSAI_p->s_NSSAI.sD)
				 {
					 allowed_nssai_tmp.s_nssai->sD = asn1str_to_u24(pNgap_AllowedNSSAI_p->s_NSSAI.sD);	
					 printf("NSSAI.sd:0x%x\n", allowed_nssai_tmp.s_nssai->sD); 
				 }
				 
				 free(allowed_nssai_tmp.s_nssai);
				 allowed_nssai_tmp.s_nssai = NULL;
			}
	}

    //TraceActivation
    NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_HandoverRequestIEs_t, ie, container, Ngap_ProtocolIE_ID_id_TraceActivation, false);
	if (ie) 
	{ 
		printf("nGRANTraceID:0x%x\n", ie->value.choice.TraceActivation.nGRANTraceID.buf[0]);
		printf("interfacesToTrace:0x%x\n", ie->value.choice.TraceActivation.interfacesToTrace.buf[0]);
		printf("traceDepth:0x%x\n", ie->value.choice.TraceActivation.traceDepth);
	    printf("traceCollectionEntityIPAddress:0x%x\n", ie->value.choice.TraceActivation.traceCollectionEntityIPAddress.buf[0]);
	}
    
	
	return rc;
}


int  make_NGAP_PduHandOverRequest(const char *inputBuf, const char *OutputBuf)
{

    printf("pdu session hand over request, start--------------------\n\n");

    int ret = 0;
	int rc  = RETURNok;
	const sctp_assoc_id_t assoc_id  = 0;
    const sctp_stream_id_t stream   = 0;
	Ngap_NGAP_PDU_t  message = {0};

	//wys:  1024 ?
	size_t buffer_size = 4096;  
	void *buffer = calloc(1, buffer_size);
	asn_enc_rval_t er;	
	
	Ngap_NGAP_PDU_t * pdu =  ngap_generate_ng_handover_request(inputBuf);
	if(!pdu)
		goto ERROR;

    asn_fprint(stderr, &asn_DEF_Ngap_NGAP_PDU, pdu);

    ret  =  check_NGAP_pdu_constraints(pdu);
    if(ret < 0) 
	{
		printf("ng hand over request  Constraint validation  failed\n");
		rc = RETURNerror;
		goto ERROR; 
	}

	//encode
	er = aper_encode_to_buffer(&asn_DEF_Ngap_NGAP_PDU, NULL, pdu, buffer, buffer_size);
	if(er.encoded < 0)
	{
		printf("ng hand over request encode failed,er.encoded:%d\n",er.encoded);
		rc = RETURNerror;
		goto ERROR; 
	}
  		 
	bstring msgBuf = blk2bstr(buffer, er.encoded);

    //decode
    ngap_amf_decode_pdu(&message, msgBuf);
	ngap_amf_handle_ng_pdu_handover_request(0,0, &message);


    //Free pdu
    ASN_STRUCT_FREE(asn_DEF_Ngap_NGAP_PDU, pdu);
	if(buffer)
	{
		free(buffer);
		buffer = NULL;
	}
	printf("pdu session  hand over request, finish--------------------\n\n");
    return rc;

ERROR:
	//Free pdu
	if(pdu)
        ASN_STRUCT_FREE(asn_DEF_Ngap_NGAP_PDU, pdu);
	if(buffer)
	{
		free(buffer);
		buffer = NULL;
	}
 	return rc;  
}


