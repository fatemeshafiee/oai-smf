#include  "ng_pdu_session_resource_setup_response.h"

#include  "Ngap_SuccessfulOutcome.h"

#include  "Ngap_NGAP-PDU.h"
#include  "Ngap_ProtocolIE-Field.h"
#include  "Ngap_ProcedureCode.h"


#include  "Ngap_Criticality.h"

#include  "Ngap_PDUSessionResourceSetupRequest.h"

#include  "Ngap_PDUSessionResourceSetupListSURes.h"
#include  "Ngap_PDUSessionResourceSetupItemSURes.h"

#include "Ngap_PDUSessionResourceFailedToSetupListSURes.h"
#include "Ngap_PDUSessionResourceFailedToSetupItemSURes.h"

#include "Ngap_CriticalityDiagnostics.h"
#include "Ngap_CriticalityDiagnostics-IE-List.h"


#include  "common_defs.h"
#include  "common_types.h"
#include  "../common/ngap/ngap_common.h"


#include  "INTEGER.h"
#include  "asn_SEQUENCE_OF.h"
#include  "OCTET_STRING.h"

#define BUF_LEN   1024


Ngap_PDUSessionResourceSetupRequestIEs_t  * make_CriticalityDiagnostics()
{
	Ngap_PDUSessionResourceSetupRequestIEs_t *ie;
	ie = calloc(1, sizeof(Ngap_PDUSessionResourceSetupRequestIEs_t));
	
	ie->id = Ngap_ProtocolIE_ID_id_CriticalityDiagnostics;
	ie->criticality = Ngap_Criticality_reject;
	ie->value.present = Ngap_PDUSessionResourceSetupResponseIEs__value_PR_CriticalityDiagnostics;
	
    return ie;
}

Ngap_PDUSessionResourceSetupRequestIEs_t  * make_PDUSessionResourceFailedToSetupListSURes()
{
	Ngap_PDUSessionResourceSetupRequestIEs_t *ie;
	ie = calloc(1, sizeof(Ngap_PDUSessionResourceSetupRequestIEs_t));
	
	ie->id = Ngap_ProtocolIE_ID_id_PDUSessionResourceFailedToSetupListSURes;
	ie->criticality = Ngap_Criticality_reject;
	ie->value.present = Ngap_PDUSessionResourceSetupResponseIEs__value_PR_PDUSessionResourceFailedToSetupListSURes;
	
    return ie;
}
Ngap_PDUSessionResourceSetupItemSURes_t  *make_PDUSessionResourceSetupItemSURes(
	long	         pDUSessionID,
	const char *	 pDUSessionResourceSetupResponseTransfer)
{  
	Ngap_PDUSessionResourceSetupItemSURes_t  *item = NULL;
	item  = calloc(1, sizeof(Ngap_PDUSessionResourceSetupItemSURes_t));

	item->pDUSessionID =  pDUSessionID;
	//OCTET_STRING_fromBuf (&item->pDUSessionResourceSetupResponseTransfer, pDUSessionResourceSetupResponseTransfer, strlen(pDUSessionResourceSetupResponseTransfer));
	return item;
}
Ngap_PDUSessionResourceSetupRequestIEs_t  * make_PDUSessionResourceSetupListSURes()
{
	Ngap_PDUSessionResourceSetupRequestIEs_t *ie;
	ie = calloc(1, sizeof(Ngap_PDUSessionResourceSetupRequestIEs_t));
	
	ie->id = Ngap_ProtocolIE_ID_id_PDUSessionResourceSetupListSURes;
	ie->criticality = Ngap_Criticality_reject;
	ie->value.present = Ngap_PDUSessionResourceSetupResponseIEs__value_PR_PDUSessionResourceSetupListSURes;
	
    return ie;
}

Ngap_PDUSessionResourceSetupRequestIEs_t  *make_RAN_UE_NGAP_ID(uint32_t rAN_UE_NGAP_ID)
{
	Ngap_PDUSessionResourceSetupRequestIEs_t *ie;
	ie = calloc(1, sizeof(Ngap_PDUSessionResourceSetupRequestIEs_t));

	ie->id = Ngap_ProtocolIE_ID_id_RAN_UE_NGAP_ID;
	ie->criticality = Ngap_Criticality_reject;
	ie->value.present = Ngap_PDUSessionResourceSetupResponseIEs__value_PR_RAN_UE_NGAP_ID;
	ie->value.choice.RAN_UE_NGAP_ID = rAN_UE_NGAP_ID ;

	printf("RAN_UE_NGAP_ID:0x%x",ie->value.choice.RAN_UE_NGAP_ID);
	return ie;
}

Ngap_PDUSessionResourceSetupRequestIEs_t  *make_AMF_UE_NGAP_ID(uint64_t amf_UE_NGAP_ID)
{
    Ngap_PDUSessionResourceSetupRequestIEs_t *ie = NULL;
	ie = calloc(1, sizeof(Ngap_PDUSessionResourceSetupRequestIEs_t));
	
	ie->id = Ngap_ProtocolIE_ID_id_AMF_UE_NGAP_ID;
	ie->criticality = Ngap_Criticality_reject;
	ie->value.present = Ngap_PDUSessionResourceSetupResponseIEs__value_PR_AMF_UE_NGAP_ID;

	//asn_ulong2INTEGER(&ie->value.choice.AMF_UE_NGAP_ID, amf_UE_NGAP_ID & AMF_UE_NGAP_ID_MASK_);
	
	size_t i  = 0;
	for(i ; i<ie->value.choice.AMF_UE_NGAP_ID.size;i++)
	{
	    printf("0x%x",ie->value.choice.AMF_UE_NGAP_ID.buf[i]);
	}
	return ie;
}

#if 0
void add_pdu_session_resource_setup_response_ie(Ngap_PDUSessionResourceSetupResponse_t *ngapPDUSessionResourceSetupRequest, Ngap_PDUSessionResourceSetupRequestIEs_t *ie) {
    int ret;
	ret = ASN_SEQUENCE_ADD(&ngapPDUSessionResourceSetupResponse->protocolIEs.list, ie);
    if ( ret != 0 ) {
        fprintf(stderr, "Failed to add ie\n");
		return ;
    }
	return ;
}
#endif

Ngap_NGAP_PDU_t *make_NGAP_pdu_session_resource_setup_response()
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
	uint64_t  amf_ue_ngap_id = 0x80;
	ie  = make_AMF_UE_NGAP_ID(amf_ue_ngap_id);
    //add_pdu_session_resource_setup_response_ie(ngapPDUSessionResourceSetupResponse, ie);

	//Ngap_AMF_UE_NGAP_ID_t
    uint32_t  ran_ue_ngap_id = 0x81;
	ie  = make_RAN_UE_NGAP_ID(ran_ue_ngap_id);
	//add_pdu_session_resource_setup_response_ie(ngapPDUSessionResourceSetupResponse, ie);
    
    //PDUSessionResourceSetupListSURes;
    Ngap_PDUSessionResourceSetupItemSURes_t  *item  = NULL;
	
    ie    =  make_PDUSessionResourceSetupListSURes();
    item  =  make_PDUSessionResourceSetupItemSURes(0x80, "test_item");
	//ASN_SEQUENCE_ADD(&ie->value.choice.PDUSessionResourceSetupListSURes.list, item);
	//add_pdu_session_resource_setup_response_ie(ngapPDUSessionResourceSetupResponse, ie);
	
    //PDUSessionResourceFailedToSetupListSURes
	Ngap_PDUSessionResourceFailedToSetupListSURes_t	 PDUSessionResourceFailedToSetupListSURes;
	ie =  make_PDUSessionResourceFailedToSetupListSURes();
    //add_pdu_session_resource_setup_response_ie(ngapPDUSessionResourceSetupResponse, ie);
    
	//CriticalityDiagnostics
	Ngap_CriticalityDiagnostics_t	 CriticalityDiagnostics;
    ie = make_CriticalityDiagnostics();
	//add_pdu_session_resource_setup_response_ie(ngapPDUSessionResourceSetupResponse, ie);
  
	printf("0000000000000, make_NGAP_pdu_session_resource_setup_response\n");
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
 

    DevAssert (pdu != NULL);
    //OAILOG_INFO(LOG_NGAP,"----------------------- DECODED NG SETUP RESPONSE NGAP MSG --------------------------\n");
    //asn_fprint(stdout, &asn_DEF_Ngap_NGAP_PDU, pdu);
    //OAILOG_INFO(LOG_NGAP,"----------------------- DECODED NG SETUP RESPONSE NGAP MSG --------------------------\n");

	container = &pdu->choice.successfulOutcome->value.choice.PDUSessionResourceSetupResponse;
    
    //AMF_UE_NGAP_ID
    NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_PDUSessionResourceSetupResponseIEs_t, ie, container, Ngap_ProtocolIE_ID_id_AMF_UE_NGAP_ID, false);
    if (ie) 
	{  
	   //asn_INTEGER2ulong(&ie->value.choice.AMF_UE_NGAP_ID, &amf_ue_ngap_id);
	   //printf("amf_ue_ngap_id, 0x%x\n", amf_ue_ngap_id);
    }

    //Ngap_AMF_UE_NGAP_ID_t
    NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_PDUSessionResourceSetupResponseIEs_t, ie, container, Ngap_ProtocolIE_ID_id_RAN_UE_NGAP_ID, false);
    if (ie) 
	{  
	   ran_ue_ngap_id = ie->value.choice.RAN_UE_NGAP_ID;
	   //printf("ran_ue_ngap_id, 0x%x\n", ran_ue_ngap_id);
    }

	//PDUSessionResourceSetupListSURes
	NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_PDUSessionResourceSetupResponseIEs_t, ie, container, Ngap_ProtocolIE_ID_id_PDUSessionResourceSetupListSURes, false);
    if (ie) 
	{ 
	    Ngap_PDUSessionResourceFailedToSetupListSURes_t	 *response_container  =  &ie->value.choice.PDUSessionResourceSetupListSURes;
        for (i  = 0;i < response_container->list.count; i++)
	    {
            Ngap_PDUSessionResourceFailedToSetupItemSURes_t *setupResponseIes_p = NULL;
            setupResponseIes_p = response_container->list.array[i];
			
			if(!setupResponseIes_p)
			{
				  continue;
        	}

		    pDUSessionID                                      = setupResponseIes_p->pDUSessionID;
	 	    pDUSessionResourceSetupUnsuccessfulTransfer       = setupResponseIes_p->pDUSessionResourceSetupUnsuccessfulTransfer.buf;
	        pDUSessionResourceSetupUnsuccessfulTransfer_size  = setupResponseIes_p->pDUSessionResourceSetupUnsuccessfulTransfer.size;
		}
	   
    }

    //PDUSessionResourceFailedToSetupListSURes
	NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_PDUSessionResourceSetupResponseIEs_t, ie, container, Ngap_ProtocolIE_ID_id_PDUSessionResourceFailedToSetupListSURes, false);
	if (ie) 
	{  
	  
	}
	
	//CriticalityDiagnostics
    NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_PDUSessionResourceSetupResponseIEs_t, ie, container, Ngap_ProtocolIE_ID_id_CriticalityDiagnostics, false);
	if (ie) 
	{ 
	     
      
	}
	
	return rc;
}



