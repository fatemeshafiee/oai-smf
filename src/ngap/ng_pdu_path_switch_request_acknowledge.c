#include  "3gpp_23.003.h"
#include  "Ngap_TAI.h"
#include  "Ngap_NR-CGI.h"

//#include  "asn1_conversions.h"
//#include  "conversions.h"


#include  "ng_pdu_path_switch_request_acknowledge.h"
#include  "Ngap_PathSwitchRequestAcknowledge.h"

#include  "Ngap_SecurityContext.h"
#include  "Ngap_SecurityKey.h"


#include  "Ngap_SuccessfulOutcome.h"
#include  "Ngap_NGAP-PDU.h"
#include  "Ngap_ProtocolIE-Field.h"
#include  "Ngap_ProcedureCode.h"
#include  "Ngap_Criticality.h"

#include  "Ngap_NewSecurityContextInd.h"
#include  "Ngap_PDUSessionResourceSwitchedList.h"
#include  "Ngap_PDUSessionResourceSwitchedItem.h"
#include  "Ngap_PDUSessionResourceReleasedListPSAck.h"
#include  "Ngap_PDUSessionResourceReleasedItemPSAck.h"
#include  "Ngap_RRCInactiveTransitionReportRequest.h"
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




#include  "Ngap_CriticalityDiagnostics.h"
#include  "Ngap_CriticalityDiagnostics-IE-List.h"
#include  "Ngap_CriticalityDiagnostics-IE-Item.h"

#include  "Ngap_TimeStamp.h"

#include  "common_defs.h"
#include  "common_types.h"
#include  "../common/ngap/ngap_common.h"
#include  "INTEGER.h"
#include  "asn_SEQUENCE_OF.h"
#include  "OCTET_STRING.h"




#define BUF_LEN   1024

Ngap_PathSwitchRequestAcknowledgeIEs_t  * make_path_switch_req_ack_CriticalityDiagnostics()
{
	Ngap_PathSwitchRequestAcknowledgeIEs_t *ie;
	ie = calloc(1, sizeof(Ngap_PathSwitchRequestAcknowledgeIEs_t));
	
	ie->id            = Ngap_ProtocolIE_ID_id_CriticalityDiagnostics;
	ie->criticality   = Ngap_Criticality_ignore;
	ie->value.present = Ngap_PathSwitchRequestAcknowledgeIEs__value_PR_CriticalityDiagnostics;
	
    return ie;
}

Ngap_PathSwitchRequestAcknowledgeIEs_t  *make_path_switch_req_ack_RAN_UE_NGAP_ID(uint32_t rAN_UE_NGAP_ID)
{
	Ngap_PathSwitchRequestAcknowledgeIEs_t *ie;
	ie = calloc(1, sizeof(Ngap_PathSwitchRequestAcknowledgeIEs_t));

	ie->id            = Ngap_ProtocolIE_ID_id_RAN_UE_NGAP_ID;
	ie->criticality   = Ngap_Criticality_ignore;
	ie->value.present = Ngap_PathSwitchRequestAcknowledgeIEs__value_PR_RAN_UE_NGAP_ID;
	ie->value.choice.RAN_UE_NGAP_ID = rAN_UE_NGAP_ID ;

	printf("RAN_UE_NGAP_ID:0x%x\n",ie->value.choice.RAN_UE_NGAP_ID);
	return ie;
}

Ngap_PathSwitchRequestAcknowledgeIEs_t  *make_path_switch_req_ack_AMF_UE_NGAP_ID(uint64_t amf_UE_NGAP_ID)
{
    Ngap_PathSwitchRequestAcknowledgeIEs_t *ie = NULL;
	ie = calloc(1, sizeof(Ngap_PathSwitchRequestAcknowledgeIEs_t));
	
	ie->id            = Ngap_ProtocolIE_ID_id_AMF_UE_NGAP_ID;
	ie->criticality   = Ngap_Criticality_ignore;
	ie->value.present = Ngap_PathSwitchRequestAcknowledgeIEs__value_PR_AMF_UE_NGAP_ID;

	asn_ulong2INTEGER(&ie->value.choice.AMF_UE_NGAP_ID, amf_UE_NGAP_ID & AMF_UE_NGAP_ID_MASK_);
	
	printf("AMF_UE_NGAP_ID:0x%x\n",amf_UE_NGAP_ID);
	return ie;
}


Ngap_PathSwitchRequestAcknowledgeIEs_t *make_path_sw_req_ack_UESecurityCapabilities()
{
	Ngap_PathSwitchRequestAcknowledgeIEs_t *ie = NULL;
    ie  = calloc(1, sizeof(Ngap_PathSwitchRequestAcknowledgeIEs_t));
	
	ie->id            = Ngap_ProtocolIE_ID_id_UESecurityCapabilities; 
	ie->criticality   = Ngap_Criticality_reject;
	ie->value.present = Ngap_PathSwitchRequestAcknowledgeIEs__value_PR_UESecurityCapabilities;

    return ie;
}

Ngap_PathSwitchRequestAcknowledgeIEs_t *make_path_switch_req_ack_SecurityContext()
{
	Ngap_PathSwitchRequestAcknowledgeIEs_t *ie = NULL;
    ie  = calloc(1, sizeof(Ngap_PathSwitchRequestAcknowledgeIEs_t));
	
	ie->id            = Ngap_ProtocolIE_ID_id_SecurityContext; 
	ie->criticality   = Ngap_Criticality_reject;
	ie->value.present = Ngap_PathSwitchRequestAcknowledgeIEs__value_PR_SecurityContext;

    return ie;
}


Ngap_PathSwitchRequestAcknowledgeIEs_t *make_path_sw_req_ack_NewSecurityContextInd(const e_Ngap_NewSecurityContextInd ContextInd)
{
	Ngap_PathSwitchRequestAcknowledgeIEs_t *ie = NULL;
    ie  = calloc(1, sizeof(Ngap_PathSwitchRequestAcknowledgeIEs_t));
	
	ie->id            = Ngap_ProtocolIE_ID_id_NewSecurityContextInd; 
	ie->criticality   = Ngap_Criticality_reject;
	ie->value.present = Ngap_PathSwitchRequestAcknowledgeIEs__value_PR_NewSecurityContextInd;
	ie->value.choice.NewSecurityContextInd = ContextInd;

    return ie;
}


Ngap_PathSwitchRequestAcknowledgeIEs_t *make_path_sw_req_ack_PDUSessionResourceSwitchedList()
{
	Ngap_PathSwitchRequestAcknowledgeIEs_t *ie = NULL;
    ie  = calloc(1, sizeof(Ngap_PathSwitchRequestAcknowledgeIEs_t));
	
	ie->id            = Ngap_ProtocolIE_ID_id_PDUSessionResourceSwitchedList; 
	ie->criticality   = Ngap_Criticality_reject;
	ie->value.present = Ngap_PathSwitchRequestAcknowledgeIEs__value_PR_PDUSessionResourceSwitchedList;

    return ie;
}


Ngap_PDUSessionResourceSwitchedItem_t *make_path_sw_req_ack_PDUSessionResourceSwitchedItem(const long pd, const char *transfer)
{
	Ngap_PDUSessionResourceSwitchedItem_t *item = NULL;
    item  = calloc(1, sizeof(Ngap_PDUSessionResourceSwitchedItem_t));
	
	item->pDUSessionID = pd ;
	OCTET_STRING_fromBuf (&item->pathSwitchRequestAcknowledgeTransfer, transfer, strlen(transfer));
	
	printf("SwitchedItem, pDUSessionID:0x%x, tranfer:%s\n",pd, transfer);

	return item;
}


Ngap_PathSwitchRequestAcknowledgeIEs_t *make_path_sw_req_ack_PDUSessionResourceReleasedListPSAck()
{
	Ngap_PathSwitchRequestAcknowledgeIEs_t *ie = NULL;
    ie  = calloc(1, sizeof(Ngap_PathSwitchRequestAcknowledgeIEs_t));
	
	ie->id            = Ngap_ProtocolIE_ID_id_PDUSessionResourceReleasedListPSAck; 
	ie->criticality   = Ngap_Criticality_reject;
	ie->value.present = Ngap_PathSwitchRequestAcknowledgeIEs__value_PR_PDUSessionResourceReleasedListPSAck;

    return ie;
}


Ngap_PDUSessionResourceReleasedItemPSAck_t *make_path_sw_req_ack_PDUSessionResourceReleasedItemPSAck(const long pd, const char *transfer)
{
	Ngap_PDUSessionResourceReleasedItemPSAck_t *item = NULL;
	item	= calloc(1, sizeof(Ngap_PDUSessionResourceReleasedItemPSAck_t));
		
	item->pDUSessionID = pd ;
	OCTET_STRING_fromBuf (&item->pathSwitchRequestUnsuccessfulTransfer, transfer, strlen(transfer));
		
	printf("ResourceSwitchedItemACK, pDUSessionID:0x%x, tranfer:%s\n",pd, transfer);
	
	return item;
}

Ngap_PathSwitchRequestAcknowledgeIEs_t  *make_path_switch_req_ack_RRRCInactiveTransitionReportRequest(const e_Ngap_RRCInactiveTransitionReportRequest reqid)
{
	Ngap_PathSwitchRequestAcknowledgeIEs_t *ie;
	ie = calloc(1, sizeof(Ngap_PathSwitchRequestAcknowledgeIEs_t));

	ie->id            = Ngap_ProtocolIE_ID_id_RRCInactiveTransitionReportRequest;
	ie->criticality   = Ngap_Criticality_ignore;
	ie->value.present = Ngap_PathSwitchRequestAcknowledgeIEs__value_PR_RRCInactiveTransitionReportRequest;
	ie->value.choice.RRCInactiveTransitionReportRequest = reqid ;

	printf("RRCInactiveTransitionReportRequest:0x%x\n",ie->value.choice.RRCInactiveTransitionReportRequest);
	return ie;
}


Ngap_PathSwitchRequestAcknowledgeIEs_t *  make_path_switch_req_ack_AllowedNSSAI_ie()
{
	Ngap_PathSwitchRequestAcknowledgeIEs_t *ie = NULL;
	ie	= calloc(1, sizeof(Ngap_PathSwitchRequestAcknowledgeIEs_t));
	memset(ie, 0, sizeof(Ngap_PathSwitchRequestAcknowledgeIEs_t));
			
	ie->id            = Ngap_ProtocolIE_ID_id_AllowedNSSAI; 
	ie->criticality   = Ngap_Criticality_reject;
	ie->value.present = Ngap_PathSwitchRequestAcknowledgeIEs__value_PR_AllowedNSSAI;
	return ie;
}


Ngap_PathSwitchRequestAcknowledgeIEs_t *  make_path_switch_req_ack_CoreNetworkAssistanceInformation()
{
	Ngap_PathSwitchRequestAcknowledgeIEs_t *ie = NULL;
	ie	= calloc(1, sizeof(Ngap_PathSwitchRequestAcknowledgeIEs_t));
	memset(ie, 0, sizeof(Ngap_PathSwitchRequestAcknowledgeIEs_t));
			
	ie->id            = Ngap_ProtocolIE_ID_id_CoreNetworkAssistanceInformation; 
	ie->criticality   = Ngap_Criticality_ignore;
	ie->value.present = Ngap_PathSwitchRequestAcknowledgeIEs__value_PR_CoreNetworkAssistanceInformation;
	return ie;

}

void add_pdu_path_switch_req_ack_ie(Ngap_PathSwitchRequestAcknowledge_t *ngapPDUHandoverReqAck, Ngap_PathSwitchRequestAcknowledgeIEs_t *ie) {
    int ret;
	ret = ASN_SEQUENCE_ADD(&ngapPDUHandoverReqAck->protocolIEs.list, ie);
    if ( ret != 0 ) {
        fprintf(stderr, "Failed to add ie\n");
		return ;
    }
	return ;
}
Ngap_NGAP_PDU_t *  ngap_generate_ng_path_switch_req_ack(const char *inputBuf)
{
    Ngap_NGAP_PDU_t * pdu = NULL;
	pdu = calloc(1, sizeof(Ngap_NGAP_PDU_t));
    
	pdu->present = Ngap_NGAP_PDU_PR_successfulOutcome;
	pdu->choice.successfulOutcome = calloc(1, sizeof(Ngap_SuccessfulOutcome_t));
	pdu->choice.successfulOutcome->procedureCode = Ngap_ProcedureCode_id_PathSwitchRequest;
	pdu->choice.successfulOutcome->criticality   = Ngap_Criticality_reject;
	pdu->choice.successfulOutcome->value.present = Ngap_SuccessfulOutcome__value_PR_PathSwitchRequestAcknowledge;

    Ngap_PathSwitchRequestAcknowledge_t *ngapPDUPathSwitchRequestAcknowledge = NULL;
	ngapPDUPathSwitchRequestAcknowledge = &pdu->choice.successfulOutcome->value.choice.PathSwitchRequestAcknowledge;
	
	Ngap_PathSwitchRequestAcknowledgeIEs_t  *ie = NULL;

    //Ngap_AMF_UE_NGAP_ID_t
	uint64_t  amf_ue_ngap_id = 0x77;
	ie  = make_path_switch_req_ack_AMF_UE_NGAP_ID(amf_ue_ngap_id);
    add_pdu_path_switch_req_ack_ie(ngapPDUPathSwitchRequestAcknowledge, ie);

	//Ngap_AMF_UE_NGAP_ID_t
    uint32_t  ran_ue_ngap_id = 0x78;
	ie  = make_path_switch_req_ack_RAN_UE_NGAP_ID(ran_ue_ngap_id);
	add_pdu_path_switch_req_ack_ie(ngapPDUPathSwitchRequestAcknowledge, ie);


    //SecurityContext
    ie  = make_path_switch_req_ack_SecurityContext();
	uint8_t  nextHopNH[32] = {0x00,0x01};

	//Ngap_NextHopChainingCount_t	 nextHopChainingCount;
	ie->value.choice.SecurityContext.nextHopChainingCount =  0x01;

	//Ngap_SecurityKey_t	 nextHopNH;
	ie->value.choice.SecurityContext.nextHopNH.buf = calloc(32, sizeof(uint8_t));
	memcpy(ie->value.choice.SecurityContext.nextHopNH.buf, &nextHopNH, 32);
	ie->value.choice.SecurityContext.nextHopNH.size = 32;
	ie->value.choice.SecurityContext.nextHopNH.bits_unused = 0;
	printf("nextHopNH:0x%x,0x%x\n",nextHopNH[0],nextHopNH[1]);
	add_pdu_path_switch_req_ack_ie(ngapPDUPathSwitchRequestAcknowledge, ie);

	//NewSecurityContextInd
	ie  =  make_path_sw_req_ack_NewSecurityContextInd(Ngap_NewSecurityContextInd_true);
	add_pdu_path_switch_req_ack_ie(ngapPDUPathSwitchRequestAcknowledge, ie);



	//PDUSessionResourceSwitchedList
	Ngap_PDUSessionResourceSwitchedItem_t     *pswItem  = NULL;
	ie      = make_path_sw_req_ack_PDUSessionResourceSwitchedList();
	pswItem = make_path_sw_req_ack_PDUSessionResourceSwitchedItem(0x80, "test_sw_item");
	ASN_SEQUENCE_ADD(&ie->value.choice.PDUSessionResourceSwitchedList.list, pswItem);
	add_pdu_path_switch_req_ack_ie(ngapPDUPathSwitchRequestAcknowledge, ie);


	//PDUSessionResourceReleasedListPSAck
	Ngap_PDUSessionResourceReleasedItemPSAck_t   *peleasedItemPSAck = NULL;
	ie  = make_path_sw_req_ack_PDUSessionResourceReleasedListPSAck();
	peleasedItemPSAck  = make_path_sw_req_ack_PDUSessionResourceReleasedItemPSAck(0x81, "test_re_item");
	ASN_SEQUENCE_ADD(&ie->value.choice.PDUSessionResourceReleasedListPSAck.list, peleasedItemPSAck);
	add_pdu_path_switch_req_ack_ie(ngapPDUPathSwitchRequestAcknowledge, ie);

    //AllowedNSSAI
	//Ngap_AllowedNSSAI_t	 AllowedNSSAI;
    ie = make_path_switch_req_ack_AllowedNSSAI_ie();
	uint8_t sst[1] = {0x80};
	uint8_t sd[3] = {0x01, 0x02,0x03};
	 
    Ngap_AllowedNSSAI_Item_t *item = NULL;
	item = calloc(1, sizeof(Ngap_AllowedNSSAI_Item_t));

    OCTET_STRING_fromBuf(&item->s_NSSAI.sST, &sst, 1);
	printf("NSSAI.sST:0x%x",item->s_NSSAI.sST.buf[0]);

	Ngap_SD_t *sD = calloc(1, sizeof(Ngap_SD_t));
    item->s_NSSAI.sD = sD;
    OCTET_STRING_fromBuf(sD, sd, 3);
    printf("NSSAI.sd:0x%x,0x%x,0x%x",item->s_NSSAI.sD->buf[0],item->s_NSSAI.sD->buf[1],item->s_NSSAI.sD->buf[2]);
	ASN_SEQUENCE_ADD(&ie->value.choice.AllowedNSSAI.list, item);
	add_pdu_path_switch_req_ack_ie(ngapPDUPathSwitchRequestAcknowledge, ie);

    //CoreNetworkAssistanceInformation
	//Ngap_CoreNetworkAssistanceInformation_t	 CoreNetworkAssistanceInformation;
	ie  =  make_path_switch_req_ack_CoreNetworkAssistanceInformation();

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
    add_pdu_path_switch_req_ack_ie(ngapPDUPathSwitchRequestAcknowledge, ie);
	
	//UESecurityCapabilities;
    ie  = make_path_sw_req_ack_UESecurityCapabilities();
    
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
	
	add_pdu_path_switch_req_ack_ie(ngapPDUPathSwitchRequestAcknowledge, ie);

    //RRCInactiveTransitionReportRequest
	ie  = make_path_switch_req_ack_RRRCInactiveTransitionReportRequest(Ngap_RRCInactiveTransitionReportRequest_subsequent_state_transition_report);
	add_pdu_path_switch_req_ack_ie(ngapPDUPathSwitchRequestAcknowledge, ie);
    
	
	//CriticalityDiagnostics
    ie = make_path_switch_req_ack_CriticalityDiagnostics();

	Ngap_ProcedureCode_t  *procedureCode = calloc(1, sizeof(Ngap_ProcedureCode_t));
	*procedureCode = 0x81;
    ie ->value.choice.CriticalityDiagnostics.procedureCode  = procedureCode;

	Ngap_TriggeringMessage_t  *triggeringMessage = calloc(1, sizeof(Ngap_TriggeringMessage_t));
	*triggeringMessage = 0x01;
    ie ->value.choice.CriticalityDiagnostics.triggeringMessage = triggeringMessage;

	Ngap_Criticality_t  *procedureCriticality = calloc(1, sizeof(Ngap_Criticality_t));
	*procedureCriticality = 0x01;
	ie ->value.choice.CriticalityDiagnostics.procedureCriticality = procedureCriticality;

    printf("procedureCode:0x%x,triggeringMessage:0x%x,procedureCriticality:0x%x\n", *procedureCode, *triggeringMessage,*procedureCriticality);	


    Ngap_CriticalityDiagnostics_IE_List_t   *pCriticalityDiagnostics_IE_List  = calloc(1, sizeof(Ngap_CriticalityDiagnostics_IE_List_t));
    Ngap_CriticalityDiagnostics_IE_Item_t   *critiDiagIEsItem = calloc(1, sizeof(Ngap_CriticalityDiagnostics_IE_Item_t));
	critiDiagIEsItem->iECriticality = 0x01;
	critiDiagIEsItem->iE_ID = 0x01;
	critiDiagIEsItem->typeOfError = 0x00;


    printf("iECriticality:0x%x,iE_ID:0x%x,typeOfError:0x%x\n", 
	critiDiagIEsItem->iECriticality,
	critiDiagIEsItem->iE_ID,
	critiDiagIEsItem->typeOfError);


	ie->value.choice.CriticalityDiagnostics.iEsCriticalityDiagnostics = pCriticalityDiagnostics_IE_List;
    
    ASN_SEQUENCE_ADD(&pCriticalityDiagnostics_IE_List->list, critiDiagIEsItem);
	add_pdu_path_switch_req_ack_ie(ngapPDUPathSwitchRequestAcknowledge, ie);
  
	return pdu;
}



int
ngap_amf_handle_ng_pdu_path_switch_req_ack(
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
    Ngap_PathSwitchRequestAcknowledge_t             *container = NULL;
    Ngap_PathSwitchRequestAcknowledgeIEs_t          *ie = NULL;
    Ngap_PathSwitchRequestAcknowledgeIEs_t          *ie_gnb_name = NULL;

    unsigned  long    amf_ue_ngap_id        = 0;
	uint32_t          ran_ue_ngap_id        = 0;
	uint32_t          handoverType          = 0;

    long	  pDUSessionID = 0;
	char 	  *handoverCommandTransfer = NULL;
	int       pDUFailedSessionResourceModifyResponseTransfer_size  =  0;

	long	  procedureCode         = 0;	
	long	  triggeringMessage     = 0;	
	long	  procedureCriticality  = 0;
	long	  iECriticality         = 0;
	long	  iE_ID                 = 0;
	long 	  typeOfError           = 0;

    DevAssert (pdu != NULL);
    //OAILOG_INFO(LOG_NGAP,"----------------------- DECODED NG SETUP RESPONSE NGAP MSG --------------------------\n");
    //asn_fprint(stdout, &asn_DEF_Ngap_NGAP_PDU, pdu);
    //OAILOG_INFO(LOG_NGAP,"----------------------- DECODED NG SETUP RESPONSE NGAP MSG --------------------------\n");

	container = &pdu->choice.successfulOutcome->value.choice.PathSwitchRequestAcknowledge;
    
    //AMF_UE_NGAP_ID
    NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_PathSwitchRequestAcknowledgeIEs_t, ie, container, Ngap_ProtocolIE_ID_id_AMF_UE_NGAP_ID, false);
    if (ie) 
	{  
	    asn_INTEGER2ulong(&ie->value.choice.AMF_UE_NGAP_ID, &amf_ue_ngap_id);
	    printf("amf_ue_ngap_id, 0x%x\n", amf_ue_ngap_id);
    }

    //Ngap_AMF_UE_NGAP_ID_t
    NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_PathSwitchRequestAcknowledgeIEs_t, ie, container, Ngap_ProtocolIE_ID_id_RAN_UE_NGAP_ID, false);
    if (ie) 
	{  
	    ran_ue_ngap_id = ie->value.choice.RAN_UE_NGAP_ID;
	    printf("ran_ue_ngap_id, 0x%x\n", ran_ue_ngap_id);
    }

    //UESecurityCapabilities
    NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_PathSwitchRequestAcknowledgeIEs_t, ie, container, Ngap_ProtocolIE_ID_id_UESecurityCapabilities, false);
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

	//NewSecurityContextInd
    NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_PathSwitchRequestAcknowledgeIEs_t, ie, container, Ngap_ProtocolIE_ID_id_NewSecurityContextInd, false);
    if (ie) 
	{ 
		printf("NewSecurityContextInd:0x%x\n", ie->value.choice.NewSecurityContextInd);
    }

    //PDUSessionResourceSwitchedList
    NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_PathSwitchRequestAcknowledgeIEs_t, ie, container, Ngap_ProtocolIE_ID_id_PDUSessionResourceSwitchedList, false);
	if (ie) 
	{ 
	    Ngap_PDUSessionResourceSwitchedList_t	 *sw_container  =  &ie->value.choice.PDUSessionResourceSwitchedList;
        for (i  = 0;i < sw_container->list.count; i++)
	    {
            Ngap_PDUSessionResourceSwitchedItem_t *swItemIes_p = NULL;
            swItemIes_p = sw_container->list.array[i];
			
			if(!swItemIes_p)
			{
				  continue;
        	}

		    const long pDUSessionID    = swItemIes_p->pDUSessionID;
	 	    const char *Transfer       = swItemIes_p->pathSwitchRequestAcknowledgeTransfer.buf;
	       

			printf("switchItem,pDUSessionID:0x%x, Transfer:%s\n", pDUSessionID, Transfer);
		}
	}

	//PDUSessionResourceReleasedListPSAck
	NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_PathSwitchRequestAcknowledgeIEs_t, ie, container, Ngap_ProtocolIE_ID_id_PDUSessionResourceReleasedListPSAck, false);
	if (ie) 
	{ 
	    Ngap_PDUSessionResourceReleasedListPSAck_t	 *swACK_container  =  &ie->value.choice.PDUSessionResourceReleasedListPSAck;
        for (i  = 0;i < swACK_container->list.count; i++)
	    {
            Ngap_PDUSessionResourceReleasedItemPSAck_t *swItemACKIes_p = NULL;
            swItemACKIes_p = swACK_container->list.array[i];
			
			if(!swItemACKIes_p)
			{
				  continue;
        	}

		    const long pDUSessionID  = swItemACKIes_p->pDUSessionID;
	 	    const char *Transfer     = swItemACKIes_p->pathSwitchRequestUnsuccessfulTransfer.buf;
	       

			printf("switchItemACK,pDUSessionID:0x%x, Transfer:%s\n", pDUSessionID, Transfer);
		}
	}
	
    //AllowedNSSAI
    NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_PathSwitchRequestAcknowledgeIEs_t, ie, container, Ngap_ProtocolIE_ID_id_AllowedNSSAI, false);
	if (ie) 
	{ 
	    //init  nr_allowed_nssai.s_nssai  ?
	    Ngap_AllowedNSSAI_t	 *pAllowedNSSAI = &ie->value.choice.AllowedNSSAI;
		
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
				 printf("NSSAI.sd:0x%x", allowed_nssai_tmp.s_nssai->sD); 
			 }
			 
			 free(allowed_nssai_tmp.s_nssai);
			 allowed_nssai_tmp.s_nssai = NULL;
		}
	}

    //SecurityContext
	NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_PathSwitchRequestAcknowledgeIEs_t, ie, container, Ngap_ProtocolIE_ID_id_SecurityContext, false);
	if (ie) 
	{ 
		printf("nextHopChainingCount:0x%x\n,nextHopNH:0x%x,0x%x\n", ie->value.choice.SecurityContext.nextHopChainingCount,
		ie->value.choice.SecurityContext.nextHopNH.buf[0],ie->value.choice.SecurityContext.nextHopNH.buf[1]);
	}

    //CoreNetworkAssistanceInformation
    NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_PathSwitchRequestAcknowledgeIEs_t, ie, container, Ngap_ProtocolIE_ID_id_CoreNetworkAssistanceInformation, false);
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

    //RRCInactiveTransitionReportRequest
	NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_PathSwitchRequestAcknowledgeIEs_t, ie, container, Ngap_ProtocolIE_ID_id_RRCInactiveTransitionReportRequest, false);
	if (ie) 
	{ 
		printf("RRCInactiveTransitionReportRequest:0x%x\n", ie->value.choice.RRCInactiveTransitionReportRequest);
	  
	}
   
	//CriticalityDiagnostics
    NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_PathSwitchRequestAcknowledgeIEs_t, ie, container, Ngap_ProtocolIE_ID_id_CriticalityDiagnostics, false);
	if (ie) 
	{ 
	   procedureCode         = *ie->value.choice.CriticalityDiagnostics.procedureCode;	
	   triggeringMessage     = *ie->value.choice.CriticalityDiagnostics.triggeringMessage;	
	   procedureCriticality  = *ie->value.choice.CriticalityDiagnostics.procedureCriticality;

	   printf("procedureCode:0x%x,triggeringMessage:0x%x,procedureCriticality:0x%x\n", procedureCode, triggeringMessage,procedureCriticality);  

	   Ngap_CriticalityDiagnostics_IE_List_t   *criticality_container  = ie->value.choice.CriticalityDiagnostics.iEsCriticalityDiagnostics; 
       for (i  = 0;i < criticality_container->list.count; i++)
	   {
           Ngap_CriticalityDiagnostics_IE_Item_t  *criticalityIes_p = criticality_container->list.array[i];
		   if(!criticalityIes_p)
		      continue;
		   
		    iECriticality         = criticalityIes_p->iECriticality;
	        iE_ID                 = criticalityIes_p->iE_ID;
	        typeOfError           = criticalityIes_p->typeOfError;

			printf("iECriticality:0x%x,iE_ID:0x%x,typeOfError:0x%x\n", iECriticality, iE_ID, typeOfError);
	   }  
	}
	
	return rc;
}


int  make_NGAP_PduPathSwitchRequestAck(const char *inputBuf, const char *OutputBuf)
{

    printf("pdu path switch req ack, start--------------------\n\n");

    int ret = 0;
	int rc  = RETURNok;
	const sctp_assoc_id_t assoc_id  = 0;
    const sctp_stream_id_t stream   = 0;
	Ngap_NGAP_PDU_t  message = {0};

	//wys:  1024 ?
	size_t buffer_size = 4096;  
	void *buffer = calloc(1,buffer_size);
	asn_enc_rval_t er;	
	
	Ngap_NGAP_PDU_t * pdu =  ngap_generate_ng_path_switch_req_ack(inputBuf);
	if(!pdu)
		goto ERROR;

    asn_fprint(stderr, &asn_DEF_Ngap_NGAP_PDU, pdu);

    ret  =  check_NGAP_pdu_constraints(pdu);
    if(ret < 0) 
	{
		printf("ng pdu path switch req ack Constraint validation  failed\n");
		rc = RETURNerror;
		goto ERROR; 
	}

	//encode
	er = aper_encode_to_buffer(&asn_DEF_Ngap_NGAP_PDU, NULL, pdu, buffer, buffer_size);
	if(er.encoded < 0)
	{
		printf("ng pdu path switch req ack encode failed,er.encoded:%d\n",er.encoded);
		rc = RETURNerror;
		goto ERROR; 
	}
  		 
	bstring msgBuf = blk2bstr(buffer, er.encoded);

    //decode
    ngap_amf_decode_pdu(&message, msgBuf);
	ngap_amf_handle_ng_pdu_path_switch_req_ack(0,0, &message);

    //Free pdu
    if(pdu)
       ASN_STRUCT_FREE(asn_DEF_Ngap_NGAP_PDU, pdu);
    
	if(buffer)
	{
		free(buffer);
		buffer = NULL;
	}
	
	printf("pdu path switch req ack, finish--------------------\n\n");
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



