#include  "ng_pdu_session_resource_setup_request.h"

#include  "Ngap_NGAP-PDU.h"
#include  "Ngap_ProtocolIE-Field.h"
#include  "Ngap_ProcedureCode.h"
#include  "Ngap_InitiatingMessage.h"

#include  "Ngap_Criticality.h"

#include  "Ngap_PDUSessionResourceSetupRequest.h"
#include  "Ngap_PDUSessionResourceSetupListSUReq.h"
#include  "Ngap_PDUSessionResourceSetupItemSUReq.h"

#include  "common_defs.h"
#include  "common_types.h"
#include  "../common/ngap/ngap_common.h"


#include  "INTEGER.h"
#include  "asn_SEQUENCE_OF.h"
#include  "OCTET_STRING.h"

#define BUF_LEN   1024
Ngap_PDUSessionResourceSetupRequestIEs_t  *make_RAN_UE_NGAP_ID(uint32_t rAN_UE_NGAP_ID)
{
	Ngap_PDUSessionResourceSetupRequestIEs_t *ie;
	ie = calloc(1, sizeof(Ngap_PDUSessionResourceSetupRequestIEs_t));

	ie->id = Ngap_ProtocolIE_ID_id_RAN_UE_NGAP_ID;
	ie->criticality = Ngap_Criticality_reject;
	ie->value.present = Ngap_PDUSessionResourceSetupRequestIEs__value_PR_RAN_UE_NGAP_ID;
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
	ie->value.present = Ngap_PDUSessionResourceSetupRequestIEs__value_PR_AMF_UE_NGAP_ID;

	asn_ulong2INTEGER(&ie->value.choice.AMF_UE_NGAP_ID, amf_UE_NGAP_ID & AMF_UE_NGAP_ID_MASK_);
	
	size_t i  = 0;
	for(i ; i<ie->value.choice.AMF_UE_NGAP_ID.size;i++)
	{
	    printf("0x%x",ie->value.choice.AMF_UE_NGAP_ID.buf[i]);
	}
	return ie;
}
Ngap_PDUSessionResourceSetupRequestIEs_t  *make_RANPagingPriority(const long  ranPagingPriority)
{
    Ngap_PDUSessionResourceSetupRequestIEs_t *ie = NULL;
	ie = calloc(1, sizeof(Ngap_PDUSessionResourceSetupRequestIEs_t));
	
	ie->id = Ngap_ProtocolIE_ID_id_RANPagingPriority;
	ie->criticality = Ngap_Criticality_ignore;
	ie->value.present = Ngap_PDUSessionResourceSetupRequestIEs__value_PR_RANPagingPriority;
    ie->value.choice.RANPagingPriority  = ranPagingPriority;

    printf("RANPagingPriority:0x%x",ie->value.choice.RANPagingPriority);
	return ie;
}

Ngap_PDUSessionResourceSetupRequestIEs_t  *make_NAS_PDU(const char *nas_pdu)
{
    Ngap_PDUSessionResourceSetupRequestIEs_t *ie = NULL;
	ie = calloc(1, sizeof(Ngap_PDUSessionResourceSetupRequestIEs_t));
	
	ie->id = Ngap_ProtocolIE_ID_id_NAS_PDU;
	ie->criticality = Ngap_Criticality_reject;
	ie->value.present = Ngap_PDUSessionResourceSetupRequestIEs__value_PR_NAS_PDU;
	OCTET_STRING_fromBuf (&ie->value.choice.NAS_PDU, nas_pdu, strlen(nas_pdu));

	return ie;
}

Ngap_PDUSessionResourceSetupRequestIEs_t  *make_PDUSessionResourceSetupListSUReq()
{
    Ngap_PDUSessionResourceSetupRequestIEs_t *ie = NULL;
	ie = calloc(1, sizeof(Ngap_PDUSessionResourceSetupRequestIEs_t));
	
	ie->id            = Ngap_ProtocolIE_ID_id_PDUSessionResourceSetupListSUReq;
	ie->criticality   = Ngap_Criticality_reject;
	ie->value.present = Ngap_PDUSessionResourceSetupRequestIEs__value_PR_PDUSessionResourceSetupListSUReq;

	return ie;
}


typedef struct {
    int sst;
    int sd;
} snssai_t;

Ngap_PDUSessionResourceSetupItemSUReq_t * make_PDUSessionResourceSetupItemSUReq(
	long pDUSessionID,
	const char *pDUSessionNAS_PDU,
	const snssai_t slice,
	const char 	*pDUSessionResourceSetupRequestTransfer
	)
{
	Ngap_PDUSessionResourceSetupItemSUReq_t *item = NULL;
	item = calloc(1, sizeof(Ngap_PDUSessionResourceSetupItemSUReq_t));

	item->pDUSessionID =  pDUSessionID;


    Ngap_NAS_PDU_t  *nas_pdu =  calloc(1, sizeof(Ngap_NAS_PDU_t));
	item->pDUSessionNAS_PDU  =  nas_pdu;
	OCTET_STRING_fromBuf(nas_pdu, pDUSessionNAS_PDU, strlen(pDUSessionNAS_PDU));

	
	const char sst = slice.sst;
    OCTET_STRING_fromBuf(&item->s_NSSAI.sST, &sst, 1);
	if (slice.sd >= 0 )
    {
        uint32_t sd = ntohl(slice.sd);
		
        const char *sd_ptr = (const char *)&sd + 1;
        Ngap_SD_t *sD = calloc(1, sizeof(Ngap_SD_t));
        item->s_NSSAI.sD = sD;
		
        //OCTET_STRING_fromBuf(sD, sd_ptr, 3);
		//OAILOG_DEBUG (LOG_NGAP,"s_NSSAI.sD:0x%x,0x%x,0x%x",item->s_NSSAI.sD->buf[0],item->s_NSSAI.sD->buf[1],item->s_NSSAI.sD->buf[2]);
    }
	
    //OCTET_STRING_fromBuf(item->pDUSessionResourceSetupRequestTransfer, pDUSessionResourceSetupRequestTransfer, strlen(pDUSessionResourceSetupRequestTransfer));
    return item;
}


void add_pdu_session_resource_setup_request_ie(Ngap_PDUSessionResourceSetupRequest_t *ngapPDUSessionResourceSetupRequest, Ngap_PDUSessionResourceSetupRequestIEs_t *ie) {
    int ret;
	ret = ASN_SEQUENCE_ADD(&ngapPDUSessionResourceSetupRequest->protocolIEs.list, ie);
    if ( ret != 0 ) {
        fprintf(stderr, "Failed to add ie\n");
		return ;
    }
	return ;
}
Ngap_NGAP_PDU_t *make_NGAP_pdu_session_resource_setup_request()
{
    Ngap_NGAP_PDU_t * pdu = NULL;
	pdu = calloc(1, sizeof(Ngap_NGAP_PDU_t));
    
	pdu->present = Ngap_NGAP_PDU_PR_initiatingMessage;
	pdu->choice.initiatingMessage = calloc(1, sizeof(Ngap_InitiatingMessage_t));
	pdu->choice.initiatingMessage->procedureCode = Ngap_ProcedureCode_id_PDUSessionResourceSetup;
	pdu->choice.initiatingMessage->criticality = Ngap_Criticality_reject;
	pdu->choice.initiatingMessage->value.present = Ngap_InitiatingMessage__value_PR_NGSetupRequest;

    Ngap_PDUSessionResourceSetupRequest_t *ngapPDUSessionResourceSetupRequest = NULL;
	ngapPDUSessionResourceSetupRequest = &pdu->choice.initiatingMessage->value.choice.PDUSessionResourceSetupRequest;
	
	Ngap_PDUSessionResourceSetupRequestIEs_t  *ie;

    //Ngap_AMF_UE_NGAP_ID_t

	uint64_t  amf_ue_ngap_id = 0x80;
	ie  = make_AMF_UE_NGAP_ID(amf_ue_ngap_id);
    add_pdu_session_resource_setup_request_ie(ngapPDUSessionResourceSetupRequest, ie);

	//Ngap_AMF_UE_NGAP_ID_t
    uint32_t  ran_ue_ngap_id = 0x81;
	ie  = make_RAN_UE_NGAP_ID(ran_ue_ngap_id);
	//add_pdu_session_resource_setup_request_ie(ngapPDUSessionResourceSetupRequest, ie);

     
	//Ngap_RANPagingPriority_t
	long ranPagingPriority  = 0x82;
    ie  = make_RANPagingPriority(ranPagingPriority);
	//add_pdu_session_resource_setup_request_ie(ngapPDUSessionResourceSetupRequest, ie);
	
	//Ngap_NAS_PDU_t
	const char  *nas_pdu  =  "nas_pdu";
    ie  = make_NAS_PDU(nas_pdu);
    //add_pdu_session_resource_setup_request_ie(ngapPDUSessionResourceSetupRequest, ie);
     
	//Ngap_PDUSessionResourceSetupListSUReq_t
	ie  = make_PDUSessionResourceSetupListSUReq();

    long               pDUSessionID                      = 0x83;
	const char	*pDUSessionNAS_PDU                       =  "pDUSessionNAS_PDU";	/* OPTIONAL */
	const snssai_t  slice  = {.sst = 0x01,.sd = 0x02};
	const char 	 *pDUSessionResourceSetupRequestTransfer =  "pDUSessionResourceSetupRequestTransfer";
	
    Ngap_PDUSessionResourceSetupItemSUReq_t *item = make_PDUSessionResourceSetupItemSUReq(
		pDUSessionID,
		pDUSessionNAS_PDU,
		slice,
		pDUSessionResourceSetupRequestTransfer);
	
    //ASN_SEQUENCE_ADD(&ie->value.choice.SupportedTAList.list, item);

	
  
	printf("0000000000000, make_NGAP_pdu_session_resource_setup_request\n");
    return pdu;
}




int
ngap_amf_handle_ng_pdu_session_resource_setup_request(
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
    Ngap_PDUSessionResourceSetupRequest_t                  *container = NULL;
    Ngap_PDUSessionResourceSetupRequestIEs_t               *ie = NULL;
    Ngap_PDUSessionResourceSetupRequestIEs_t               *ie_gnb_name = NULL;

    unsigned  long    amf_ue_ngap_id        = 0;
	uint32_t          ran_ue_ngap_id        = 0;
    long              ranPagingPriority     = 0;
	
	char              *nas_pdu              = NULL;
	int                nas_pdu_size         = 0;


	long 	 pDUSessionID  = 0;
	char 	*pDUSessionNAS_PDU  = NULL;	/* OPTIONAL */
	int      pDUSessionNAS_PDU_SIZE =  0;

    typedef struct {
	    int sst;
	    int sd;
    } snssai_t;

	snssai_t  slice  = {.sst = 0x00, .sd = 0x00};
	
	char *	 pDUSessionResourceSetupRequestTransfer = NULL;
	int      pDUSessionResourceSetupRequestTransfer_SIZE =  0;
	

    DevAssert (pdu != NULL);
    //OAILOG_INFO(LOG_NGAP,"----------------------- DECODED NG SETUP REQUEST NGAP MSG --------------------------\n");
    //asn_fprint(stdout, &asn_DEF_Ngap_NGAP_PDU, pdu);
    //OAILOG_INFO(LOG_NGAP,"----------------------- DECODED NG SETUP REQUEST NGAP MSG --------------------------\n");

	container = &pdu->choice.initiatingMessage->value.choice.PDUSessionResourceSetupRequest;
    
    //AMF_UE_NGAP_ID
    NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_PDUSessionResourceSetupRequestIEs_t, ie, container, Ngap_ProtocolIE_ID_id_AMF_UE_NGAP_ID, false);
    if (ie) 
	{  
	   //asn_INTEGER2ulong(&ie->value.choice.AMF_UE_NGAP_ID, &amf_ue_ngap_id);
	   //printf("amf_ue_ngap_id, 0x%x\n", amf_ue_ngap_id);
    }

    //Ngap_AMF_UE_NGAP_ID_t
    NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_PDUSessionResourceSetupRequestIEs_t, ie, container, Ngap_ProtocolIE_ID_id_RAN_UE_NGAP_ID, false);
    if (ie) 
	{  
	   ran_ue_ngap_id = ie->value.choice.RAN_UE_NGAP_ID;
	   //printf("ran_ue_ngap_id, 0x%x\n", ran_ue_ngap_id);
    }

	//RANPagingPriority
	NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_PDUSessionResourceSetupRequestIEs_t, ie, container, Ngap_ProtocolIE_ID_id_RANPagingPriority, false);
    if (ie) 
	{  
	   ranPagingPriority = ie->value.choice.RANPagingPriority;
	   //printf("ranPagingPriority, 0x%x\n", ranPagingPriority);
    }

    //NAS_PDU
	NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_PDUSessionResourceSetupRequestIEs_t, ie, container, Ngap_ProtocolIE_ID_id_NAS_PDU, false);
	if (ie) 
	{  
	   nas_pdu      = (char *) ie->value.choice.NAS_PDU.buf;
       nas_pdu_size = (int) ie->value.choice.NAS_PDU.size;
	  
	   //printf("RANNodeName, nas_pdu_size:%d, nas_pdu:%s,\n", nas_pdu_size, nas_pdu);
	}
	

	//PDUSessionResourceSetupListSUReq
    NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_PDUSessionResourceSetupRequestIEs_t, ie, container, Ngap_ProtocolIE_ID_id_PDUSessionResourceSetupListSUReq, false);
	if (ie) 
	{ 
	    Ngap_PDUSessionResourceSetupListSUReq_t	 *setup_container  =  &ie->value.choice.PDUSessionResourceSetupListSUReq;
        for (i  = 0;i < setup_container->list.count; i++)
	    {
            Ngap_PDUSessionResourceSetupItemSUReq_t *setupRequestIes_p = NULL;
            setupRequestIes_p = setup_container->list.array[i];
			
			if(!setupRequestIes_p)
				  continue;
				

		    pDUSessionID  = setupRequestIes_p->pDUSessionID;

			if(setupRequestIes_p->pDUSessionNAS_PDU)
			{
	        	pDUSessionNAS_PDU      = setupRequestIes_p->pDUSessionNAS_PDU->buf;	/* OPTIONAL */
	        	pDUSessionNAS_PDU_SIZE = setupRequestIes_p->pDUSessionNAS_PDU->size;
			}

		    OCTET_STRING_TO_INT8(&setupRequestIes_p->s_NSSAI.sST, slice.sst);
			if(setupRequestIes_p->s_NSSAI.sD)
			{
                 slice.sd = asn1str_to_u24(setupRequestIes_p->s_NSSAI.sD);  
			}
				
	        pDUSessionResourceSetupRequestTransfer      =  setupRequestIes_p->pDUSessionResourceSetupRequestTransfer.buf;
	        pDUSessionResourceSetupRequestTransfer_SIZE =  setupRequestIes_p->pDUSessionResourceSetupRequestTransfer.size;
			
        }
	}
	
	return rc;
}



