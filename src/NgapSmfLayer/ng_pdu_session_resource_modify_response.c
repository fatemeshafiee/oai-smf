#include  "3gpp_23.003.h"
#include  "Ngap_TAI.h"
#include  "Ngap_NR-CGI.h"

//#include  "asn1_conversions.h"
//#include  "conversions.h"


#include  "ng_pdu_session_resource_modify_response.h"

#include  "Ngap_SuccessfulOutcome.h"
#include  "Ngap_NGAP-PDU.h"
#include  "Ngap_ProtocolIE-Field.h"
#include  "Ngap_ProcedureCode.h"
#include  "Ngap_Criticality.h"
#include  "Ngap_PDUSessionResourceModifyResponse.h"
#include  "Ngap_PDUSessionResourceModifyItemModRes.h"




#include  "Ngap_UserLocationInformationNR.h"


#include  "Ngap_UserLocationInformation.h"
#include  "Ngap_UserLocationInformationNR.h"

#include  "Ngap_CriticalityDiagnostics.h"
#include  "Ngap_CriticalityDiagnostics-IE-List.h"
#include  "Ngap_CriticalityDiagnostics-IE-Item.h"

#include "Ngap_PDUSessionResourceFailedToModifyListModRes.h"
#include "Ngap_PDUSessionResourceFailedToModifyItemModRes.h"


#include  "Ngap_TimeStamp.h"

#include  "common_defs.h"
#include  "common_types.h"
#include  "../common/ngap/ngap_common.h"
#include  "INTEGER.h"
#include  "asn_SEQUENCE_OF.h"
#include  "OCTET_STRING.h"


#define BUF_LEN   1024
Ngap_PDUSessionResourceModifyResponseIEs_t  * make_modify_resp_CriticalityDiagnostics()
{
	Ngap_PDUSessionResourceModifyResponseIEs_t *ie;
	ie = calloc(1, sizeof(Ngap_PDUSessionResourceModifyResponseIEs_t));
	
	ie->id = Ngap_ProtocolIE_ID_id_CriticalityDiagnostics;
	ie->criticality = Ngap_Criticality_ignore;
	ie->value.present = Ngap_PDUSessionResourceModifyResponseIEs__value_PR_CriticalityDiagnostics;
	
    return ie;
}

Ngap_PDUSessionResourceModifyResponseIEs_t  *make_modify_resp_RAN_UE_NGAP_ID(uint32_t rAN_UE_NGAP_ID)
{
	Ngap_PDUSessionResourceModifyResponseIEs_t *ie;
	ie = calloc(1, sizeof(Ngap_PDUSessionResourceModifyResponseIEs_t));

	ie->id = Ngap_ProtocolIE_ID_id_RAN_UE_NGAP_ID;
	ie->criticality = Ngap_Criticality_ignore;
	ie->value.present = Ngap_PDUSessionResourceModifyResponseIEs__value_PR_RAN_UE_NGAP_ID;
	ie->value.choice.RAN_UE_NGAP_ID = rAN_UE_NGAP_ID ;

	printf("RAN_UE_NGAP_ID:0x%x",ie->value.choice.RAN_UE_NGAP_ID);
	return ie;
}

Ngap_PDUSessionResourceModifyResponseIEs_t  *make_modify_resp_AMF_UE_NGAP_ID(uint64_t amf_UE_NGAP_ID)
{
    Ngap_PDUSessionResourceModifyResponseIEs_t *ie = NULL;
	ie = calloc(1, sizeof(Ngap_PDUSessionResourceModifyResponseIEs_t));
	
	ie->id = Ngap_ProtocolIE_ID_id_AMF_UE_NGAP_ID;
	ie->criticality = Ngap_Criticality_ignore;
	ie->value.present = Ngap_PDUSessionResourceModifyResponseIEs__value_PR_AMF_UE_NGAP_ID;

	asn_ulong2INTEGER(&ie->value.choice.AMF_UE_NGAP_ID, amf_UE_NGAP_ID & AMF_UE_NGAP_ID_MASK_);
	
	size_t i  = 0;
	for(i ; i<ie->value.choice.AMF_UE_NGAP_ID.size;i++)
	{
	    printf("0x%x",ie->value.choice.AMF_UE_NGAP_ID.buf[i]);
	}
	return ie;
}

Ngap_PDUSessionResourceModifyItemModRes_t  *make_modify_resp_PDUSessionResourceModifyItemModRes (
	long	         pDUSessionID,
	const char *	 pDUSRModifyResponseTransfer)
{  
	Ngap_PDUSessionResourceModifyItemModRes_t  *item = NULL;
	item  = calloc(1, sizeof(Ngap_PDUSessionResourceModifyItemModRes_t));

	item->pDUSessionID =  pDUSessionID;

    OCTET_STRING_t	*pDUSessionResourceModifyResponseTransfer   = calloc(1, sizeof(OCTET_STRING_t));
	
	item->pDUSessionResourceModifyResponseTransfer = pDUSessionResourceModifyResponseTransfer;
	OCTET_STRING_fromBuf (pDUSessionResourceModifyResponseTransfer, pDUSRModifyResponseTransfer, strlen(pDUSRModifyResponseTransfer));
	return item;
}

Ngap_PDUSessionResourceModifyResponseIEs_t  * make_modify_resp_PDUSessionResourceModifyListModRes()
{
	Ngap_PDUSessionResourceModifyResponseIEs_t *ie;
	ie = calloc(1, sizeof(Ngap_PDUSessionResourceModifyResponseIEs_t));
	
	ie->id            = Ngap_ProtocolIE_ID_id_PDUSessionResourceModifyListModRes;
	ie->criticality   = Ngap_Criticality_ignore;
	ie->value.present = Ngap_PDUSessionResourceModifyResponseIEs__value_PR_PDUSessionResourceModifyListModRes;
	
    return ie;
}

//PDUSessionResourceFailedToModifyListModRes
Ngap_PDUSessionResourceFailedToModifyItemModRes_t *make_PDUSessionResourceFailedToModifyItemModRes(
	const long  pDUSessionID, const char	 *pDUSessionResourceModify)
{
    Ngap_PDUSessionResourceFailedToModifyItemModRes_t  *item = NULL;
    item =  calloc(1, sizeof(Ngap_PDUSessionResourceFailedToModifyItemModRes_t));
	
    item->pDUSessionID = pDUSessionID;
	OCTET_STRING_fromBuf(&item->pDUSessionResourceModifyUnsuccessfulTransfer, pDUSessionResourceModify, strlen(pDUSessionResourceModify));
	
    return item;
}

Ngap_PDUSessionResourceModifyResponseIEs_t  * make_PDUSessionResourceFailedToModifyListModRes()
{
	Ngap_PDUSessionResourceModifyResponseIEs_t *ie;
	ie = calloc(1, sizeof(Ngap_PDUSessionResourceModifyResponseIEs_t));
	
	ie->id = Ngap_ProtocolIE_ID_id_PDUSessionResourceFailedToModifyListModRes;
	ie->criticality = Ngap_Criticality_reject;
	ie->value.present = Ngap_PDUSessionResourceModifyResponseIEs__value_PR_PDUSessionResourceFailedToModifyListModRes;
	
    return ie;
}

//UserLocationInformation
Ngap_PDUSessionResourceModifyResponseIEs_t *make_modify_resp_UserLocationInformation()
{
	Ngap_PDUSessionResourceModifyResponseIEs_t *ie = NULL;
    ie  = calloc(1, sizeof(Ngap_PDUSessionResourceModifyResponseIEs_t));
	
	ie->id            = Ngap_ProtocolIE_ID_id_UserLocationInformation; 
	ie->criticality   = Ngap_Criticality_ignore;
	ie->value.present = Ngap_PDUSessionResourceModifyResponseIEs__value_PR_UserLocationInformation;

    return ie;
}

Ngap_UserLocationInformationNR_t * make_modify_resp_UserLocationInformationNR()
{
	Ngap_UserLocationInformationNR_t * nr = NULL;
	nr =  calloc(1, sizeof(Ngap_UserLocationInformationNR_t));
	
}


void add_pdu_session_resource_modify_response_ie(Ngap_PDUSessionResourceModifyResponse_t *ngapPDUSessionResourceModifyResponse, Ngap_PDUSessionResourceModifyResponseIEs_t *ie) {
    int ret;
	ret = ASN_SEQUENCE_ADD(&ngapPDUSessionResourceModifyResponse->protocolIEs.list, ie);
    if ( ret != 0 ) {
        fprintf(stderr, "Failed to add ie\n");
		return ;
    }
	return ;
}
Ngap_NGAP_PDU_t *make_NGAP_pdu_session_resource_modify_response()
{
    Ngap_NGAP_PDU_t * pdu = NULL;
	pdu = calloc(1, sizeof(Ngap_NGAP_PDU_t));
    
	pdu->present = Ngap_NGAP_PDU_PR_successfulOutcome;
	pdu->choice.successfulOutcome = calloc(1, sizeof(Ngap_SuccessfulOutcome_t));
	pdu->choice.successfulOutcome->procedureCode = Ngap_ProcedureCode_id_PDUSessionResourceModify;
	pdu->choice.successfulOutcome->criticality = Ngap_Criticality_reject;
	pdu->choice.successfulOutcome->value.present = Ngap_SuccessfulOutcome__value_PR_PDUSessionResourceModifyResponse;

    Ngap_PDUSessionResourceModifyResponse_t *ngapPDUSessionResourceModifyResponse = NULL;
	ngapPDUSessionResourceModifyResponse = &pdu->choice.successfulOutcome->value.choice.PDUSessionResourceModifyResponse;
	
	Ngap_PDUSessionResourceModifyResponseIEs_t  *ie = NULL;

    //Ngap_AMF_UE_NGAP_ID_t
	uint64_t  amf_ue_ngap_id = 0x77;
	ie  = make_modify_resp_AMF_UE_NGAP_ID(amf_ue_ngap_id);
    add_pdu_session_resource_modify_response_ie(ngapPDUSessionResourceModifyResponse, ie);

	//Ngap_AMF_UE_NGAP_ID_t
    uint32_t  ran_ue_ngap_id = 0x78;
	ie  = make_modify_resp_RAN_UE_NGAP_ID(ran_ue_ngap_id);
	add_pdu_session_resource_modify_response_ie(ngapPDUSessionResourceModifyResponse, ie);
    
    //PDUSessionResourceModifyListModRes;
    Ngap_PDUSessionResourceModifyItemModRes_t  *modifyItem  = NULL;
	
    ie           =  make_modify_resp_PDUSessionResourceModifyListModRes();
    modifyItem   =  make_modify_resp_PDUSessionResourceModifyItemModRes(0x79, "test_modify_item");
	ASN_SEQUENCE_ADD(&ie->value.choice.PDUSessionResourceModifyListModRes.list, modifyItem);
	add_pdu_session_resource_modify_response_ie(ngapPDUSessionResourceModifyResponse, ie);


    //PDUSessionResourceFailedToModifyListModRes;
    Ngap_PDUSessionResourceFailedToModifyItemModRes_t  *modifyFailedItem = NULL;
    ie               = make_PDUSessionResourceFailedToModifyListModRes();
    modifyFailedItem = make_PDUSessionResourceFailedToModifyItemModRes(0x80, "test_modify_failed_item");
	ASN_SEQUENCE_ADD(&ie->value.choice.PDUSessionResourceFailedToModifyListModRes.list, modifyFailedItem);
	add_pdu_session_resource_modify_response_ie(ngapPDUSessionResourceModifyResponse, ie);
	

    //UserLocationInformation
	ie = make_modify_resp_UserLocationInformation();
    //userLocationInformationEUTRA;
	//userLocationInformationNR;
	ie->value.choice.UserLocationInformation.present =  Ngap_UserLocationInformation_PR_userLocationInformationNR;

	Ngap_UserLocationInformationNR_t * nr = make_UserLocationInformationNR();
    ie->value.choice.UserLocationInformation.choice.userLocationInformationNR =  nr;
	
    //nR_CGI;
    //pLMNIdentity;
    char plmn[3] = {0x01,0x02,0x03};
	OCTET_STRING_fromBuf(&nr->nR_CGI.pLMNIdentity, (const char*)plmn, sizeof(plmn));
    
	//CellIdentity;
	int cellIden =  0x79;
	uint32_t cellIdentity = htonl(cellIden);
	nr->nR_CGI.nRCellIdentity.buf = calloc(4, sizeof(uint8_t));
	nr->nR_CGI.nRCellIdentity.size = 4;
	memcpy(nr->nR_CGI.nRCellIdentity.buf, &cellIdentity, 4);
	nr->nR_CGI.nRCellIdentity.bits_unused = 0x04;
	
	
	//Ngap_TAI_t	 tAI;
    //pLMNIdentity;
    char tai_pLMNIdentity[3] = {0x00,0x01,0x02};
	OCTET_STRING_fromBuf(&nr->tAI.pLMNIdentity, (const char*)tai_pLMNIdentity, sizeof(tai_pLMNIdentity));
	//tAC;
	char tai_tAC[3] = {0x00,0x01,0x02};
	OCTET_STRING_fromBuf(&nr->tAI.tAC, (const char*)tai_tAC, sizeof(tai_tAC));
	
	//Ngap_TimeStamp_t	*timeStamp;	/* OPTIONAL */

    uint8_t timeStamp[4] = { 0x02, 0xF8, 0x29, 0x06 };
	OCTET_STRING_fromBuf(nr->timeStamp, (const char*)timeStamp, 4);	
	
	//userLocationInformationN3IWF;

	add_pdu_session_resource_modify_response_ie(ngapPDUSessionResourceModifyResponse, ie);
	
    
	//CriticalityDiagnostics
	Ngap_CriticalityDiagnostics_t	 CriticalityDiagnostics;
    ie = make_modify_resp_CriticalityDiagnostics();

    Ngap_ProcedureCode_t  *procedureCode = calloc(1, sizeof(Ngap_ProcedureCode_t));
	*procedureCode = 0x81;
    ie ->value.choice.CriticalityDiagnostics.procedureCode  = procedureCode;

	Ngap_TriggeringMessage_t  *triggeringMessage = calloc(1, sizeof(Ngap_TriggeringMessage_t));
	*triggeringMessage = 0x82;
    ie ->value.choice.CriticalityDiagnostics.triggeringMessage = triggeringMessage;

	Ngap_Criticality_t  *procedureCriticality = calloc(1, sizeof(Ngap_Criticality_t));
	*procedureCriticality = 0x83;
	ie ->value.choice.CriticalityDiagnostics.procedureCriticality = procedureCriticality;


    Ngap_CriticalityDiagnostics_IE_Item_t  *criticalityDiagnosticsIEsItem = calloc(1, sizeof(Ngap_CriticalityDiagnostics_IE_Item_t));
	criticalityDiagnosticsIEsItem->iECriticality = 0x85;
	criticalityDiagnosticsIEsItem->iE_ID = 0x86;
	criticalityDiagnosticsIEsItem->typeOfError = 0x87;

    ASN_SEQUENCE_ADD(&ie->value.choice.CriticalityDiagnostics.iEsCriticalityDiagnostics->list, &criticalityDiagnosticsIEsItem);
	add_pdu_session_resource_modify_response_ie(ngapPDUSessionResourceModifyResponse, ie);

	
  
	printf("0000000000000, make_NGAP_pdu_session_resource_modify_response\n");
    return pdu;
}



int
ngap_amf_handle_ng_pdu_session_resource_modify_response(
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
    Ngap_PDUSessionResourceModifyResponse_t             *container = NULL;
    Ngap_PDUSessionResourceModifyResponseIEs_t          *ie = NULL;
    Ngap_PDUSessionResourceModifyResponseIEs_t          *ie_gnb_name = NULL;

    unsigned  long    amf_ue_ngap_id        = 0;
	uint32_t          ran_ue_ngap_id        = 0;

	long	  pDUSessionID = 0;
	char 	  *pDUSessionResourceModifyResponseTransfer = NULL;
	int       pDUSessionResourceModifyResponseTransfer_size  =  0;


    long	  pFailedDUSessionID = 0;
	char 	  *pDUFailedSessionResourceModifyResponseTransfer = NULL;
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

	container = &pdu->choice.successfulOutcome->value.choice.PDUSessionResourceModifyResponse;
    
    //AMF_UE_NGAP_ID
    NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_PDUSessionResourceModifyResponseIEs_t, ie, container, Ngap_ProtocolIE_ID_id_AMF_UE_NGAP_ID, false);
    if (ie) 
	{  
	    asn_INTEGER2ulong(&ie->value.choice.AMF_UE_NGAP_ID, &amf_ue_ngap_id);
	    printf("amf_ue_ngap_id, 0x%x\n", amf_ue_ngap_id);
    }

    //Ngap_AMF_UE_NGAP_ID_t
    NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_PDUSessionResourceModifyResponseIEs_t, ie, container, Ngap_ProtocolIE_ID_id_RAN_UE_NGAP_ID, false);
    if (ie) 
	{  
	    ran_ue_ngap_id = ie->value.choice.RAN_UE_NGAP_ID;
	    printf("ran_ue_ngap_id, 0x%x\n", ran_ue_ngap_id);
    }

	
	//PDUSessionResourceSetupListSURes
	NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_PDUSessionResourceModifyResponseIEs_t, ie, container, Ngap_ProtocolIE_ID_id_PDUSessionResourceModifyListModRes, false);
    if (ie) 
	{ 
	    Ngap_PDUSessionResourceModifyListModRes_t	 *modify_resp_container  =  &ie->value.choice.PDUSessionResourceModifyListModRes;
        for (i  = 0;i < modify_resp_container->list.count; i++)
	    {
            Ngap_PDUSessionResourceModifyItemModRes_t *modifyRespIes_p = NULL;
            modifyRespIes_p = modify_resp_container->list.array[i];
			
			if(!modifyRespIes_p)
			{
				  continue;
        	}

		    pDUSessionID                                   = modifyRespIes_p->pDUSessionID;
	 	    pDUSessionResourceModifyResponseTransfer       = modifyRespIes_p->pDUSessionResourceModifyResponseTransfer->buf;
	        pDUSessionResourceModifyResponseTransfer_size  = modifyRespIes_p->pDUSessionResourceModifyResponseTransfer->size;
		}
    }

	//PDUSessionResourceFailedToModifyListModRes
    NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_PDUSessionResourceModifyResponseIEs_t, ie, container, Ngap_ProtocolIE_ID_id_PDUSessionResourceFailedToModifyListModRes, false);
    if (ie) 
	{ 
	    Ngap_PDUSessionResourceFailedToModifyListModRes_t	 *modify_failed_container  =  &ie->value.choice.PDUSessionResourceFailedToModifyListModRes;
        for (i  = 0;i < modify_failed_container->list.count; i++)
	    {
            Ngap_PDUSessionResourceFailedToModifyItemModRes_t *modifyFailedIes_p = NULL;
            modifyFailedIes_p = modify_failed_container->list.array[i];
			
			if(!modifyFailedIes_p)
			{
				  continue;
        	}
        	
		    pFailedDUSessionID                                   = modifyFailedIes_p->pDUSessionID;
	 	    pDUFailedSessionResourceModifyResponseTransfer       = modifyFailedIes_p->pDUSessionResourceModifyUnsuccessfulTransfer.buf;
	        pDUFailedSessionResourceModifyResponseTransfer_size  = modifyFailedIes_p->pDUSessionResourceModifyUnsuccessfulTransfer.size;
		}
    }
	

	//UserLocationInformation
	NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_PDUSessionResourceModifyResponseIEs_t, ie, container, Ngap_ProtocolIE_ID_id_UserLocationInformation, false);
    if (ie) 
	{
		switch(ie->value.choice.UserLocationInformation.present)
		{
	            case Ngap_UserLocationInformation_PR_userLocationInformationEUTRA:
				break;
				case Ngap_UserLocationInformation_PR_userLocationInformationNR:
				{
					nr_tai_t         nr_tai = {.plmn = {0}, .tac = INVALID_TAC};
					nr_cgi_t         nr_cgi = {.plmn = {0}, .cell_identity = {0}};

					Ngap_UserLocationInformationNR_t  *pUserLocationInformationNR = ie->value.choice.UserLocationInformation.choice.userLocationInformationNR;

					DevAssert(pUserLocationInformationNR != NULL);
		            const Ngap_TAI_t	  * const  tAI = &pUserLocationInformationNR->tAI;
				     
		            //TAC
		            DevAssert(tAI != NULL);
		            DevAssert(tAI->tAC.size == 3);
              
		            nr_tai.tac = asn1str_to_u24(&tAI->tAC);
				  
		             //pLMNIdentity
		            DevAssert (tAI->pLMNIdentity.size == 3);
		            TBCD_TO_PLMN_T(&tAI->pLMNIdentity, &nr_tai.plmn);
	       				
		            //CGI mandator
		            const Ngap_NR_CGI_t * const nR_CGI = &pUserLocationInformationNR->nR_CGI;
                    //pLMNIdentity
		            DevAssert(nR_CGI != NULL);
		            DevAssert(nR_CGI->pLMNIdentity.size == 3);
		            TBCD_TO_PLMN_T(&nR_CGI->pLMNIdentity, &nr_cgi.plmn);
						 
		            //nRCellIdentity
		            //DevAssert(nR_CGI->nRCellIdentity.size == 36);
		            BIT_STRING_TO_CELL_IDENTITY (&nR_CGI->nRCellIdentity, nr_cgi.cell_identity);
   
					
				}
				break;
				case Ngap_UserLocationInformation_PR_userLocationInformationN3IWF:
				break;
				default:
					printf(" don't known :%u\n",ie->value.choice.UserLocationInformation.present);
				break; 
		}
    }

	
	//CriticalityDiagnostics
    NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_PDUSessionResourceModifyResponseIEs_t, ie, container, Ngap_ProtocolIE_ID_id_CriticalityDiagnostics, false);
	if (ie) 
	{ 
	     
       procedureCode         = *ie->value.choice.CriticalityDiagnostics.procedureCode;	
	   triggeringMessage     = *ie->value.choice.CriticalityDiagnostics.triggeringMessage;	
	   procedureCriticality  = *ie->value.choice.CriticalityDiagnostics.procedureCriticality;


	   Ngap_CriticalityDiagnostics_IE_List_t   *criticality_container  = ie->value.choice.CriticalityDiagnostics.iEsCriticalityDiagnostics; 
       for (i  = 0;i < criticality_container->list.count; i++)
	   {
           Ngap_CriticalityDiagnostics_IE_Item_t  *criticalityIes_p = criticality_container->list.array[i];
		   if(!criticalityIes_p)
		        continue;
		   
		    iECriticality         = criticalityIes_p->iECriticality;
	        iE_ID                 = criticalityIes_p->iE_ID;
	        typeOfError           = criticalityIes_p->typeOfError;
	   }
	   
	   
	}
	
	return rc;
}


