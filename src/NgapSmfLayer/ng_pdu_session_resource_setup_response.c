#include  "ng_pdu_session_resource_setup_response.h"

#include  "Ngap_SuccessfulOutcome.h"
#include  "Ngap_NGAP-PDU.h"
#include  "Ngap_ProtocolIE-Field.h"
#include  "Ngap_ProcedureCode.h"
#include  "Ngap_Criticality.h"
#include  "Ngap_PDUSessionResourceSetupResponse.h"
#include  "Ngap_PDUSessionResourceSetupListSURes.h"
#include  "Ngap_PDUSessionResourceSetupItemSURes.h"
#include  "Ngap_PDUSessionResourceFailedToSetupListSURes.h"
#include  "Ngap_PDUSessionResourceFailedToSetupItemSURes.h"
#include  "Ngap_CriticalityDiagnostics.h"
#include  "Ngap_CriticalityDiagnostics-IE-List.h"
#include  "Ngap_CriticalityDiagnostics-IE-Item.h"

#include  "common_defs.h"
#include  "common_types.h"
#include  "../common/ngap/ngap_common.h"
#include  "INTEGER.h"
#include  "asn_SEQUENCE_OF.h"
#include  "OCTET_STRING.h"


#define BUF_LEN   1024
Ngap_PDUSessionResourceSetupResponseIEs_t  * make_CriticalityDiagnostics()
{
	Ngap_PDUSessionResourceSetupResponseIEs_t *ie;
	ie = calloc(1, sizeof(Ngap_PDUSessionResourceSetupResponseIEs_t));
	
	ie->id            = Ngap_ProtocolIE_ID_id_CriticalityDiagnostics;
	ie->criticality   = Ngap_Criticality_ignore;
	ie->value.present = Ngap_PDUSessionResourceSetupResponseIEs__value_PR_CriticalityDiagnostics;
	
    return ie;
}

Ngap_PDUSessionResourceFailedToSetupItemSURes_t *make_PDUSessionResourceFailedToSetupItemSURes(
	const long  pDUSessionID, const char	 *pDUSessionResourceSetup)
{
    Ngap_PDUSessionResourceFailedToSetupItemSURes_t  *item = NULL;
    item =  calloc(1, sizeof(Ngap_PDUSessionResourceFailedToSetupItemSURes_t));
    item->pDUSessionID = pDUSessionID;
	OCTET_STRING_fromBuf(&item->pDUSessionResourceSetupUnsuccessfulTransfer,pDUSessionResourceSetup,strlen(pDUSessionResourceSetup));

	printf("ResourceFailed, pDUSessionID:0x%x, tranfer:%s\n",pDUSessionID, pDUSessionResourceSetup);
    return item;
}

Ngap_PDUSessionResourceSetupResponseIEs_t  * make_PDUSessionResourceFailedToSetupListSURes()
{
	Ngap_PDUSessionResourceSetupResponseIEs_t *ie;
	ie = calloc(1, sizeof(Ngap_PDUSessionResourceSetupResponseIEs_t));
	
	ie->id = Ngap_ProtocolIE_ID_id_PDUSessionResourceFailedToSetupListSURes;
	ie->criticality = Ngap_Criticality_ignore;
	ie->value.present = Ngap_PDUSessionResourceSetupResponseIEs__value_PR_PDUSessionResourceFailedToSetupListSURes;
	
    return ie;
}
Ngap_PDUSessionResourceSetupItemSURes_t  *make_PDUSessionResourceSetupItemSURes(
	long	         pDUSessionID,
	const char *	 pDUSessionResourceSetupResponseTransfer)
{  
	Ngap_PDUSessionResourceSetupItemSURes_t  *item = NULL;
	item  = calloc(1, sizeof(Ngap_PDUSessionResourceSetupItemSURes_t));

	item->pDUSessionID = pDUSessionID ;
	OCTET_STRING_fromBuf (&item->pDUSessionResourceSetupResponseTransfer, pDUSessionResourceSetupResponseTransfer, strlen(pDUSessionResourceSetupResponseTransfer));

	printf("ResourceSetupItem, pDUSessionID:0x%x, tranfer:%s\n",pDUSessionID, pDUSessionResourceSetupResponseTransfer);

	return item;
}
Ngap_PDUSessionResourceSetupResponseIEs_t  * make_PDUSessionResourceSetupListSURes()
{
	Ngap_PDUSessionResourceSetupResponseIEs_t *ie;
	ie = calloc(1, sizeof(Ngap_PDUSessionResourceSetupResponseIEs_t));
	
	ie->id = Ngap_ProtocolIE_ID_id_PDUSessionResourceSetupListSURes;
	ie->criticality = Ngap_Criticality_ignore;
	ie->value.present = Ngap_PDUSessionResourceSetupResponseIEs__value_PR_PDUSessionResourceSetupListSURes;
	
    return ie;
}

Ngap_PDUSessionResourceSetupResponseIEs_t  *make_resp_RAN_UE_NGAP_ID(uint32_t rAN_UE_NGAP_ID)
{
	Ngap_PDUSessionResourceSetupResponseIEs_t *ie;
	ie = calloc(1, sizeof(Ngap_PDUSessionResourceSetupResponseIEs_t));

	ie->id = Ngap_ProtocolIE_ID_id_RAN_UE_NGAP_ID;
	ie->criticality = Ngap_Criticality_ignore;
	ie->value.present = Ngap_PDUSessionResourceSetupResponseIEs__value_PR_RAN_UE_NGAP_ID;
	ie->value.choice.RAN_UE_NGAP_ID = rAN_UE_NGAP_ID ;

	printf("RAN_UE_NGAP_ID:0x%x",ie->value.choice.RAN_UE_NGAP_ID);
	return ie;
}

Ngap_PDUSessionResourceSetupResponseIEs_t  *make_resp_AMF_UE_NGAP_ID(uint64_t amf_UE_NGAP_ID)
{
    Ngap_PDUSessionResourceSetupResponseIEs_t *ie = NULL;
	ie = calloc(1, sizeof(Ngap_PDUSessionResourceSetupResponseIEs_t));
	
	ie->id = Ngap_ProtocolIE_ID_id_AMF_UE_NGAP_ID;
	ie->criticality = Ngap_Criticality_ignore;
	ie->value.present = Ngap_PDUSessionResourceSetupResponseIEs__value_PR_AMF_UE_NGAP_ID;

	asn_ulong2INTEGER(&ie->value.choice.AMF_UE_NGAP_ID, amf_UE_NGAP_ID & AMF_UE_NGAP_ID_MASK_);
	
	printf("AMF_UE_NGAP_ID: 0x%x\n",amf_UE_NGAP_ID);
	return ie;
}


void add_pdu_session_resource_setup_response_ie(Ngap_PDUSessionResourceSetupResponse_t *ngapPDUSessionResourceSetupResponse, Ngap_PDUSessionResourceSetupResponseIEs_t *ie) {
    int ret;
	ret = ASN_SEQUENCE_ADD(&ngapPDUSessionResourceSetupResponse->protocolIEs.list, ie);
    if ( ret != 0 ) {
        fprintf(stderr, "Failed to add ie\n");
		return ;
    }
	return ;
}
Ngap_NGAP_PDU_t *ngap_generate_ng_setup_response(const char *inputBuf)
{
    Ngap_NGAP_PDU_t * pdu = NULL;
	pdu = calloc(1, sizeof(Ngap_NGAP_PDU_t));
    
	pdu->present = Ngap_NGAP_PDU_PR_successfulOutcome;
	pdu->choice.successfulOutcome = calloc(1, sizeof(Ngap_SuccessfulOutcome_t));
	pdu->choice.successfulOutcome->procedureCode = Ngap_ProcedureCode_id_PDUSessionResourceSetup;
	pdu->choice.successfulOutcome->criticality = Ngap_Criticality_reject;
	pdu->choice.successfulOutcome->value.present = Ngap_SuccessfulOutcome__value_PR_PDUSessionResourceSetupResponse;

    Ngap_PDUSessionResourceSetupResponse_t *ngapPDUSessionResourceSetupResponse = NULL;
	ngapPDUSessionResourceSetupResponse = &pdu->choice.successfulOutcome->value.choice.PDUSessionResourceSetupResponse;
	
	Ngap_PDUSessionResourceSetupResponseIEs_t  *ie = NULL;

    //Ngap_AMF_UE_NGAP_ID_t
	uint64_t  amf_ue_ngap_id = 0x77;
	ie  = make_resp_AMF_UE_NGAP_ID(amf_ue_ngap_id);
    add_pdu_session_resource_setup_response_ie(ngapPDUSessionResourceSetupResponse, ie);

	//Ngap_AMF_UE_NGAP_ID_t
    uint32_t  ran_ue_ngap_id = 0x78;
	ie  = make_resp_RAN_UE_NGAP_ID(ran_ue_ngap_id);
	add_pdu_session_resource_setup_response_ie(ngapPDUSessionResourceSetupResponse, ie);

	
    //PDUSessionResourceSetupListSURes;
    Ngap_PDUSessionResourceSetupItemSURes_t  *setupItem  = NULL;
	
    ie         =  make_PDUSessionResourceSetupListSURes();
    setupItem  =  make_PDUSessionResourceSetupItemSURes(0x79, "test_setup_item");
	ASN_SEQUENCE_ADD(&ie->value.choice.PDUSessionResourceSetupListSURes.list, setupItem);
	add_pdu_session_resource_setup_response_ie(ngapPDUSessionResourceSetupResponse, ie);

    
	
    //PDUSessionResourceFailedToSetupListSURes
	Ngap_PDUSessionResourceFailedToSetupItemSURes_t	 *failedItem = NULL;
	ie          =  make_PDUSessionResourceFailedToSetupListSURes();
	failedItem  =  make_PDUSessionResourceFailedToSetupItemSURes(0x80, "test_failed_setup");
	ASN_SEQUENCE_ADD(&ie->value.choice.PDUSessionResourceFailedToSetupListSURes.list, failedItem);
    add_pdu_session_resource_setup_response_ie(ngapPDUSessionResourceSetupResponse, ie);

	
	//CriticalityDiagnostics
    ie = make_CriticalityDiagnostics();

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
    
    int tret = ASN_SEQUENCE_ADD(&pCriticalityDiagnostics_IE_List->list, critiDiagIEsItem);
    printf("ret:%d\n", tret);
	add_pdu_session_resource_setup_response_ie(ngapPDUSessionResourceSetupResponse, ie);
  
    return pdu;
}


int
ngap_amf_handle_ng_pdu_session_resource_setup_response(
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
    Ngap_PDUSessionResourceSetupResponse_t             *container = NULL;
    Ngap_PDUSessionResourceSetupResponseIEs_t          *ie = NULL;
    Ngap_PDUSessionResourceSetupResponseIEs_t          *ie_gnb_name = NULL;

    unsigned  long    amf_ue_ngap_id        = 0;
	uint32_t          ran_ue_ngap_id        = 0;

	long	  pDUSessionID = 0;
	char 	  *pDUSessionResourceSetupUnsuccessfulTransfer = NULL;
	int       pDUSessionResourceSetupUnsuccessfulTransfer_size  =  0;



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

	container = &pdu->choice.successfulOutcome->value.choice.PDUSessionResourceSetupResponse;
    
    //AMF_UE_NGAP_ID
    NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_PDUSessionResourceSetupResponseIEs_t, ie, container, Ngap_ProtocolIE_ID_id_AMF_UE_NGAP_ID, false);
    if (ie) 
	{  
	    asn_INTEGER2ulong(&ie->value.choice.AMF_UE_NGAP_ID, &amf_ue_ngap_id);
	    printf("amf_ue_ngap_id, 0x%x\n", amf_ue_ngap_id);
    }

    //Ngap_AMF_UE_NGAP_ID_t
    NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_PDUSessionResourceSetupResponseIEs_t, ie, container, Ngap_ProtocolIE_ID_id_RAN_UE_NGAP_ID, false);
    if (ie) 
	{  
	    ran_ue_ngap_id = ie->value.choice.RAN_UE_NGAP_ID;
	    printf("ran_ue_ngap_id, 0x%x\n", ran_ue_ngap_id);
    }

	//PDUSessionResourceSetupListSURes
	NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_PDUSessionResourceSetupResponseIEs_t, ie, container, Ngap_ProtocolIE_ID_id_PDUSessionResourceSetupListSURes, false);
    if (ie) 
	{ 
	    Ngap_PDUSessionResourceSetupListSURes_t	 *response_container  =  &ie->value.choice.PDUSessionResourceSetupListSURes;
        for (i  = 0;i < response_container->list.count; i++)
	    {
            Ngap_PDUSessionResourceSetupItemSURes_t *setupResponseIes_p = NULL;
            setupResponseIes_p = response_container->list.array[i];
			
			if(!setupResponseIes_p)
			{
				  continue;
        	}

		    pDUSessionID                                      = setupResponseIes_p->pDUSessionID;
	 	    pDUSessionResourceSetupUnsuccessfulTransfer       = setupResponseIes_p->pDUSessionResourceSetupResponseTransfer.buf;
	        pDUSessionResourceSetupUnsuccessfulTransfer_size  = setupResponseIes_p->pDUSessionResourceSetupResponseTransfer.size;

            printf("ResourceSetupItem, pDUSessionID:0x%x, tranfer:%s\n",pDUSessionID, pDUSessionResourceSetupUnsuccessfulTransfer);
		}
	   
    }

    //PDUSessionResourceFailedToSetupListSURes
	NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_PDUSessionResourceSetupResponseIEs_t, ie, container, Ngap_ProtocolIE_ID_id_PDUSessionResourceFailedToSetupListSURes, false);
	if (ie) 
	{  
	    Ngap_PDUSessionResourceFailedToSetupListSURes_t	 *failed_container  =  &ie->value.choice.PDUSessionResourceFailedToSetupListSURes;
        for (i  = 0;i < failed_container->list.count; i++)
	    {
            Ngap_PDUSessionResourceFailedToSetupItemSURes_t *setupFailedIes_p = NULL;
            setupFailedIes_p = failed_container->list.array[i];
			
			if(!setupFailedIes_p)
			{
				  continue;
        	}

		    pDUSessionID                                      = setupFailedIes_p->pDUSessionID;
	 	    pDUSessionResourceSetupUnsuccessfulTransfer       = setupFailedIes_p->pDUSessionResourceSetupUnsuccessfulTransfer.buf;
	        pDUSessionResourceSetupUnsuccessfulTransfer_size  = setupFailedIes_p->pDUSessionResourceSetupUnsuccessfulTransfer.size;

            printf("ResourceFailed, pDUSessionID:0x%x, tranfer:%s\n",pDUSessionID, pDUSessionResourceSetupUnsuccessfulTransfer);
		}
	}
	ie = NULL;
	//CriticalityDiagnostics
    NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_PDUSessionResourceSetupResponseIEs_t, ie, container, Ngap_ProtocolIE_ID_id_CriticalityDiagnostics, false);
	if (ie) 
	{ 
	     
       procedureCode         = *ie->value.choice.CriticalityDiagnostics.procedureCode;	
	   triggeringMessage     = *ie->value.choice.CriticalityDiagnostics.triggeringMessage;	
	   procedureCriticality  = *ie->value.choice.CriticalityDiagnostics.procedureCriticality;

       printf("procedureCode:0x%x,triggeringMessage:0x%x,procedureCriticality:0x%x\n", procedureCode, triggeringMessage,procedureCriticality);
       
	   Ngap_CriticalityDiagnostics_IE_List_t  *criticality_container  = ie->value.choice.CriticalityDiagnostics.iEsCriticalityDiagnostics; 
       for (i  = 0;i < criticality_container->list.count; i++)
	   {
           Ngap_CriticalityDiagnostics_IE_Item_t  *criticalityIes_p = criticality_container->list.array[i];
		   if(!criticalityIes_p)
		        continue;
		   
		    iECriticality         = criticalityIes_p->iECriticality;
	        iE_ID                 = criticalityIes_p->iE_ID;
	        typeOfError           = criticalityIes_p->typeOfError;


			printf("iECriticality:0x%x,iE_ID:0x%x,typeOfError:0x%x\n", iECriticality, iE_ID,typeOfError);
	   }
	   
	   
	}
	
	return rc;
}

int  make_NGAP_PduSessionResourceSetupResponse(const char *inputBuf, const char *OutputBuf)
{

    printf("pdu session  resource setup response, start--------------------\n\n");

    int ret = 0;
	int rc  = RETURNok;
	const sctp_assoc_id_t assoc_id  = 0;
    const sctp_stream_id_t stream   = 0;
	Ngap_NGAP_PDU_t  message = {0};

	//wys:  1024 ?
	size_t buffer_size = 1024;  
	void *buffer = calloc(1,buffer_size);
	asn_enc_rval_t er;	
	
	Ngap_NGAP_PDU_t * pdu =  ngap_generate_ng_setup_response(inputBuf);
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
	ngap_amf_handle_ng_pdu_session_resource_setup_response(0,0, &message);

    //Free pdu
    ASN_STRUCT_FREE(asn_DEF_Ngap_NGAP_PDU, pdu);
	if(buffer)
	{
		free(buffer);
		buffer = NULL;
	}
	printf("pdu session  resource setup response, finish--------------------\n\n");
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



