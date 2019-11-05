#include  "3gpp_23.003.h"
#include  "Ngap_TAI.h"
#include  "Ngap_NR-CGI.h"

#include  "asn1_conversions.h"
#include  "conversions.h"


#include  "ng_pdu_session_resource_release_response.h"

#include  "Ngap_SuccessfulOutcome.h"
#include  "Ngap_NGAP-PDU.h"
#include  "Ngap_ProtocolIE-Field.h"
#include  "Ngap_ProcedureCode.h"
#include  "Ngap_Criticality.h"
#include  "Ngap_PDUSessionResourceReleaseResponse.h"

#include  "Ngap_PDUSessionResourceReleasedItemRelRes.h"

#include  "Ngap_PDUSessionResourceReleasedListRelRes.h"
#include  "Ngap_PDUSessionResourceReleasedItemRelRes.h"


#include  "Ngap_UserLocationInformationNR.h"


#include  "Ngap_UserLocationInformation.h"
#include  "Ngap_UserLocationInformationNR.h"

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
Ngap_PDUSessionResourceReleaseResponseIEs_t  * make_release_resp_CriticalityDiagnostics()
{
	Ngap_PDUSessionResourceReleaseResponseIEs_t *ie;
	ie = calloc(1, sizeof(Ngap_PDUSessionResourceReleaseResponseIEs_t));
	
	ie->id            = Ngap_ProtocolIE_ID_id_CriticalityDiagnostics;
	ie->criticality   = Ngap_Criticality_ignore;
	ie->value.present = Ngap_PDUSessionResourceReleaseResponseIEs__value_PR_CriticalityDiagnostics;
	
    return ie;
}

Ngap_PDUSessionResourceReleaseResponseIEs_t  *make_release_resp_RAN_UE_NGAP_ID(uint32_t rAN_UE_NGAP_ID)
{
	Ngap_PDUSessionResourceReleaseResponseIEs_t *ie;
	ie = calloc(1, sizeof(Ngap_PDUSessionResourceReleaseResponseIEs_t));

	ie->id = Ngap_ProtocolIE_ID_id_RAN_UE_NGAP_ID;
	ie->criticality = Ngap_Criticality_ignore;
	ie->value.present = Ngap_PDUSessionResourceReleaseResponseIEs__value_PR_RAN_UE_NGAP_ID;
	ie->value.choice.RAN_UE_NGAP_ID = rAN_UE_NGAP_ID ;

	printf("RAN_UE_NGAP_ID:0x%x",ie->value.choice.RAN_UE_NGAP_ID);
	return ie;
}

Ngap_PDUSessionResourceReleaseResponseIEs_t  *make_release_resp_AMF_UE_NGAP_ID(uint64_t amf_UE_NGAP_ID)
{
    Ngap_PDUSessionResourceReleaseResponseIEs_t *ie = NULL;
	ie = calloc(1, sizeof(Ngap_PDUSessionResourceReleaseResponseIEs_t));
	
	ie->id = Ngap_ProtocolIE_ID_id_AMF_UE_NGAP_ID;
	ie->criticality = Ngap_Criticality_ignore;
	ie->value.present = Ngap_PDUSessionResourceReleaseResponseIEs__value_PR_AMF_UE_NGAP_ID;

	asn_ulong2INTEGER(&ie->value.choice.AMF_UE_NGAP_ID, amf_UE_NGAP_ID & AMF_UE_NGAP_ID_MASK_);
	
	size_t i  = 0;
	for(i ; i<ie->value.choice.AMF_UE_NGAP_ID.size;i++)
	{
	    printf("0x%x",ie->value.choice.AMF_UE_NGAP_ID.buf[i]);
	}
	return ie;
}

Ngap_PDUSessionResourceReleasedItemRelRes_t  *make_release_resp_PDUSessionResourceReleasedItemRelRes(
	long	         pDUSessionID,
	const char *	 pDUSessionResourceReleaseResponseTransfer)
{  
	Ngap_PDUSessionResourceReleasedItemRelRes_t  *item = NULL;
	item  = calloc(1, sizeof(Ngap_PDUSessionResourceReleasedItemRelRes_t));

	item->pDUSessionID =  pDUSessionID;
	OCTET_STRING_fromBuf (&item->pDUSessionResourceReleaseResponseTransfer, pDUSessionResourceReleaseResponseTransfer, strlen(pDUSessionResourceReleaseResponseTransfer));

	printf("ReleaseResponse,pDUSessionID:0x%x,Transfer:%s\n",pDUSessionID , pDUSessionResourceReleaseResponseTransfer);

	return item;
}
Ngap_PDUSessionResourceReleaseResponseIEs_t  * make_release_resp_PDUSessionResourceReleasedListRelRes()
{
	Ngap_PDUSessionResourceReleaseResponseIEs_t *ie;
	ie = calloc(1, sizeof(Ngap_PDUSessionResourceReleaseResponseIEs_t));
	
	ie->id = Ngap_ProtocolIE_ID_id_PDUSessionResourceReleasedListRelRes;
	ie->criticality = Ngap_Criticality_ignore;
	ie->value.present = Ngap_PDUSessionResourceReleaseResponseIEs__value_PR_PDUSessionResourceReleasedListRelRes;
	
    return ie;
}


//make_userLocationInformationEUTRA()
Ngap_PDUSessionResourceReleaseResponseIEs_t *make_release_resp_UserLocationInformation()
{
	Ngap_PDUSessionResourceReleaseResponseIEs_t *ie = NULL;
    ie  = calloc(1, sizeof(Ngap_PDUSessionResourceReleaseResponseIEs_t));
	
	ie->id            = Ngap_ProtocolIE_ID_id_UserLocationInformation; 
	ie->criticality   = Ngap_Criticality_ignore;
	ie->value.present = Ngap_PDUSessionResourceReleaseResponseIEs__value_PR_UserLocationInformation;

    return ie;
}

Ngap_UserLocationInformationNR_t * make_UserLocationInformationNR()
{
	Ngap_UserLocationInformationNR_t * nr = NULL;
	nr =  calloc(1, sizeof(Ngap_UserLocationInformationNR_t));
	
}


void add_pdu_session_resource_release_response_ie(Ngap_PDUSessionResourceReleaseResponse_t *ngapPDUSessionResourceReleaseResponse, Ngap_PDUSessionResourceReleaseResponseIEs_t *ie) {
    int ret;
	ret = ASN_SEQUENCE_ADD(&ngapPDUSessionResourceReleaseResponse->protocolIEs.list, ie);
    if ( ret != 0 ) {
        fprintf(stderr, "Failed to add ie\n");
		return ;
    }
	return ;
}
Ngap_NGAP_PDU_t *  ngap_generate_ng_release_response(const char *inputBuf)
{
    Ngap_NGAP_PDU_t * pdu = NULL;
	pdu = calloc(1, sizeof(Ngap_NGAP_PDU_t));
    
	pdu->present = Ngap_NGAP_PDU_PR_successfulOutcome;
	pdu->choice.successfulOutcome = calloc(1, sizeof(Ngap_SuccessfulOutcome_t));
	pdu->choice.successfulOutcome->procedureCode = Ngap_ProcedureCode_id_PDUSessionResourceRelease;
	pdu->choice.successfulOutcome->criticality = Ngap_Criticality_reject;
	pdu->choice.successfulOutcome->value.present = Ngap_SuccessfulOutcome__value_PR_PDUSessionResourceReleaseResponse;

    Ngap_PDUSessionResourceReleaseResponse_t *ngapPDUSessionResourceReleaseResponse = NULL;
	ngapPDUSessionResourceReleaseResponse = &pdu->choice.successfulOutcome->value.choice.PDUSessionResourceReleaseResponse;
	
	Ngap_PDUSessionResourceReleaseResponseIEs_t  *ie = NULL;

    //Ngap_AMF_UE_NGAP_ID_t
	uint64_t  amf_ue_ngap_id = 0x77;
	ie  = make_release_resp_AMF_UE_NGAP_ID(amf_ue_ngap_id);
    add_pdu_session_resource_release_response_ie(ngapPDUSessionResourceReleaseResponse, ie);

	//Ngap_AMF_UE_NGAP_ID_t
    uint32_t  ran_ue_ngap_id = 0x78;
	ie  = make_release_resp_RAN_UE_NGAP_ID(ran_ue_ngap_id);
	add_pdu_session_resource_release_response_ie(ngapPDUSessionResourceReleaseResponse, ie);
    
    //PDUSessionResourceSetupListSURes;
    Ngap_PDUSessionResourceReleasedItemRelRes_t  *releaseItem  = NULL;
	
    ie           =  make_release_resp_PDUSessionResourceReleasedListRelRes();
    releaseItem  =  make_release_resp_PDUSessionResourceReleasedItemRelRes(0x79, "test_release_item");
	ASN_SEQUENCE_ADD(&ie->value.choice.PDUSessionResourceReleasedListRelRes.list, releaseItem);
	add_pdu_session_resource_release_response_ie(ngapPDUSessionResourceReleaseResponse, ie);
    

    //UserLocationInformation
	ie = make_release_resp_UserLocationInformation();
    //userLocationInformationEUTRA;
	//userLocationInformationNR;
	ie->value.choice.UserLocationInformation.present =  Ngap_UserLocationInformation_PR_userLocationInformationNR;

	Ngap_UserLocationInformationNR_t * nr = make_UserLocationInformationNR();
    ie->value.choice.UserLocationInformation.choice.userLocationInformationNR =  nr;
	
    //nR_CGI;
    //pLMNIdentity;
    char plmn[3] = {0x01,0x02,0x03};
	OCTET_STRING_fromBuf(&nr->nR_CGI.pLMNIdentity, (const char*)plmn, sizeof(plmn));
	
	printf("nr->nR_CGI.pLMNIdentity:0x%x,0x%x,0x%x\n",
	nr->nR_CGI.pLMNIdentity.buf[0],nr->nR_CGI.pLMNIdentity.buf[1], nr->nR_CGI.pLMNIdentity.buf[2]);
	
    
	//CellIdentity;
	char  cellIdentity[5] = {0x00,0x01,0x02,0x03,0x04};   //36bits
	nr->nR_CGI.nRCellIdentity.buf = calloc(5, sizeof(uint8_t));
	nr->nR_CGI.nRCellIdentity.size = 5;
	memcpy(nr->nR_CGI.nRCellIdentity.buf, &cellIdentity, 5);
	nr->nR_CGI.nRCellIdentity.bits_unused = 0x04;


    printf("nR_CGI->nRCellIdentity:0x%x,0x%x,0x%x,0x%x,0x%x\n", 
	nr->nR_CGI.nRCellIdentity.buf[0],nr->nR_CGI.nRCellIdentity.buf[1],nr->nR_CGI.nRCellIdentity.buf[2],
	nr->nR_CGI.nRCellIdentity.buf[3],nr->nR_CGI.nRCellIdentity.buf[4]);

   
	//Ngap_TAI_t	 tAI;
    //pLMNIdentity;
    char tai_pLMNIdentity[3] = {0x00,0x01,0x02};
	OCTET_STRING_fromBuf(&nr->tAI.pLMNIdentity, (const char*)tai_pLMNIdentity, sizeof(tai_pLMNIdentity));
    printf("tAI.pLMNIdentity:0x%x,0x%x,0x%x,\n",
	nr->tAI.pLMNIdentity.buf[0],nr->tAI.pLMNIdentity.buf[1],nr->tAI.pLMNIdentity.buf[2]);
  
	//tAC;
	char tai_tAC[3] = {0x00,0x01,0x02};
	OCTET_STRING_fromBuf(&nr->tAI.tAC, (const char*)tai_tAC, sizeof(tai_tAC));
	
	printf("tAI.tAC:0x%x,0x%x,0x%x,\n",
	nr->tAI.tAC.buf[0],nr->tAI.tAC.buf[1],nr->tAI.tAC.buf[2]);
	
	
	//Ngap_TimeStamp_t	*timeStamp;	/* OPTIONAL */

    Ngap_TimeStamp_t	*ptimeStamp = calloc(1, sizeof(Ngap_TimeStamp_t));
	nr->timeStamp = ptimeStamp;
	
    uint8_t timeStamp[4] = { 0x02, 0xF8, 0x29, 0x06 };
	OCTET_STRING_fromBuf(ptimeStamp, (const char*)timeStamp, 4);
	printf("timestamp:0x%x,0x%x,0x%x,0x%x\n", 
	ptimeStamp->buf[0],ptimeStamp->buf[1],ptimeStamp->buf[2],ptimeStamp->buf[3]);
	
	//userLocationInformationN3IWF;

	add_pdu_session_resource_release_response_ie(ngapPDUSessionResourceReleaseResponse, ie);
	
    
	//CriticalityDiagnostics
    ie = make_release_resp_CriticalityDiagnostics();

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
	add_pdu_session_resource_release_response_ie(ngapPDUSessionResourceReleaseResponse, ie);
  
    return pdu;
}




int
ngap_amf_handle_ng_pdu_session_resource_release_response(
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
    Ngap_PDUSessionResourceReleaseResponse_t             *container = NULL;
    Ngap_PDUSessionResourceReleaseResponseIEs_t          *ie = NULL;
    Ngap_PDUSessionResourceReleaseResponseIEs_t          *ie_gnb_name = NULL;

    unsigned  long    amf_ue_ngap_id        = 0;
	uint32_t          ran_ue_ngap_id        = 0;

	long	  pDUSessionID = 0;
	char 	  *pDUSessionResourceReleaseResponseTransfer = NULL;
	int       pDUSessionResourceReleaseResponseTransfer_size  =  0;



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

	container = &pdu->choice.successfulOutcome->value.choice.PDUSessionResourceReleaseResponse;
    
    //AMF_UE_NGAP_ID
    NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_PDUSessionResourceSetupResponseIEs_t, ie, container, Ngap_ProtocolIE_ID_id_AMF_UE_NGAP_ID, false);
    if (ie) 
	{  
	    asn_INTEGER2ulong(&ie->value.choice.AMF_UE_NGAP_ID, &amf_ue_ngap_id);
	    printf("amf_ue_ngap_id, 0x%x\n", amf_ue_ngap_id);
    }

    //Ngap_AMF_UE_NGAP_ID_t
    NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_PDUSessionResourceReleaseResponseIEs_t, ie, container, Ngap_ProtocolIE_ID_id_RAN_UE_NGAP_ID, false);
    if (ie) 
	{  
	    ran_ue_ngap_id = ie->value.choice.RAN_UE_NGAP_ID;
	    printf("ran_ue_ngap_id, 0x%x\n", ran_ue_ngap_id);
    }

	//PDUSessionResourceSetupListSURes
	NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_PDUSessionResourceReleaseResponseIEs_t, ie, container, Ngap_ProtocolIE_ID_id_PDUSessionResourceReleasedListRelRes, false);
    if (ie) 
	{ 
	    Ngap_PDUSessionResourceReleasedListRelRes_t	 *release_resp_container  =  &ie->value.choice.PDUSessionResourceReleasedListRelRes;
        for (i  = 0;i < release_resp_container->list.count; i++)
	    {
            Ngap_PDUSessionResourceReleasedItemRelRes_t *releaseRespIes_p = NULL;
            releaseRespIes_p = release_resp_container->list.array[i];
			
			if(!releaseRespIes_p)
			{
				  continue;
        	}

		    pDUSessionID                                    = releaseRespIes_p->pDUSessionID;
	 	    pDUSessionResourceReleaseResponseTransfer       = releaseRespIes_p->pDUSessionResourceReleaseResponseTransfer.buf;
	        pDUSessionResourceReleaseResponseTransfer_size  = releaseRespIes_p->pDUSessionResourceReleaseResponseTransfer.size;

			printf("ReleaseResponse,pDUSessionID:0x%x,Transfer:%s\n",pDUSessionID , pDUSessionResourceReleaseResponseTransfer);
		}
    }

	//UserLocationInformation
	NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_PDUSessionResourceReleaseResponseIEs_t, ie, container, Ngap_ProtocolIE_ID_id_UserLocationInformation, false);
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


                     //CGI mandator
		            const Ngap_NR_CGI_t * const nR_CGI = &pUserLocationInformationNR->nR_CGI;
                    //pLMNIdentity
		            DevAssert(nR_CGI != NULL);
		            DevAssert(nR_CGI->pLMNIdentity.size == 3);
		            TBCD_TO_PLMN_T(&nR_CGI->pLMNIdentity, &nr_cgi.plmn);
					
					printf("nnR_CGI->pLMNIdentity:0x%x,0x%x,0x%x\n", 
					nR_CGI->pLMNIdentity.buf[0],nR_CGI->pLMNIdentity.buf[1],nR_CGI->pLMNIdentity.buf[2]);

		            //nRCellIdentity
		            //DevAssert(nR_CGI->nRCellIdentity.size == 36);
		            BIT_STRING_TO_CELL_IDENTITY (&nR_CGI->nRCellIdentity, nr_cgi.cell_identity);
					
                    printf("nR_CGI->nRCellIdentity:0x%x,0x%x,0x%x,0x%x,0x%x\n", 
					nR_CGI->nRCellIdentity.buf[0],nR_CGI->nRCellIdentity.buf[1],nR_CGI->nRCellIdentity.buf[2],
					nR_CGI->nRCellIdentity.buf[3],nR_CGI->nRCellIdentity.buf[4]);

                    //Tai
		            const Ngap_TAI_t	  * const  tAI = &pUserLocationInformationNR->tAI;
				     
		            //TAC
		            DevAssert(tAI != NULL);
		            DevAssert(tAI->tAC.size == 3);
              
		            nr_tai.tac = asn1str_to_u24(&tAI->tAC);
					
					printf("tAI->tAC:0x%x,0x%x,0x%x\n", 
					tAI->tAC.buf[0],tAI->tAC.buf[1],tAI->tAC.buf[2]);
				  
		             //pLMNIdentity
		            DevAssert (tAI->pLMNIdentity.size == 3);
		            TBCD_TO_PLMN_T(&tAI->pLMNIdentity, &nr_tai.plmn);

					printf("tAI->pLMNIdentity:0x%x,0x%x,0x%x\n", 
					tAI->pLMNIdentity.buf[0],tAI->pLMNIdentity.buf[1],tAI->pLMNIdentity.buf[2]);
		           
                    
					//timeStamp
					if(pUserLocationInformationNR->timeStamp)
					{
					     char *timeStamp   = pUserLocationInformationNR->timeStamp->buf;
					     int   size        = pUserLocationInformationNR->timeStamp->size;

						 for(int i = 0; i < size; i++)
					         printf("timeStamp:0x%x\n", timeStamp[i]);
					}
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
    NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_PDUSessionResourceReleaseResponseIEs_t, ie, container, Ngap_ProtocolIE_ID_id_CriticalityDiagnostics, false);
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


int  make_NGAP_PduSessionResourceReleaseResponse(const char *inputBuf, const char *OutputBuf)
{

    printf("pdu session  resource release response, start--------------------\n\n");

    int ret = 0;
	int rc  = RETURNok;
	const sctp_assoc_id_t assoc_id  = 0;
    const sctp_stream_id_t stream   = 0;
	Ngap_NGAP_PDU_t  message = {0};

	//wys:  1024 ?
	size_t buffer_size = 1024;  
	void *buffer = calloc(1,buffer_size);
	asn_enc_rval_t er;	
	
	Ngap_NGAP_PDU_t * pdu =  ngap_generate_ng_release_response(inputBuf);
	if(!pdu)
		goto ERROR;

    asn_fprint(stderr, &asn_DEF_Ngap_NGAP_PDU, pdu);

    ret  =  check_NGAP_pdu_constraints(pdu);
    if(ret < 0) 
	{
		printf("ng setup response Constraint validation  failed\n");
		rc = RETURNerror;
		goto ERROR; 
	}

	//encode
	er = aper_encode_to_buffer(&asn_DEF_Ngap_NGAP_PDU, NULL, pdu, buffer, buffer_size);
	if(er.encoded < 0)
	{
		printf("ng setup response encode failed,er.encoded:%d\n",er.encoded);
		rc = RETURNerror;
		goto ERROR; 
	}
  		 
	bstring msgBuf = blk2bstr(buffer, er.encoded);

    //decode
    ngap_amf_decode_pdu(&message, msgBuf);
	ngap_amf_handle_ng_pdu_session_resource_release_response(0,0, &message);


    //Free pdu
    ASN_STRUCT_FREE(asn_DEF_Ngap_NGAP_PDU, pdu);
	if(buffer)
	{
		free(buffer);
		buffer = NULL;
	}
	printf("pdu session  resource release response, finish--------------------\n\n");
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

