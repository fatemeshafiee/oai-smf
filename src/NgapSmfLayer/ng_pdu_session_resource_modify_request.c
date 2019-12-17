#include  "ng_pdu_session_resource_modify_request.h"

#include  "Ngap_NGAP-PDU.h"
#include  "Ngap_ProtocolIE-Field.h"
#include  "Ngap_ProcedureCode.h"
#include  "Ngap_InitiatingMessage.h"

#include  "Ngap_Criticality.h"

#include  "Ngap_PDUSessionResourceModifyRequest.h"
#include "Ngap_PDUSessionResourceModifyItemModReq.h"


#include  "Ngap_PDUSessionResourceToReleaseListRelCmd.h"
#include  "Ngap_PDUSessionResourceToReleaseItemRelCmd.h"


#include  "common_defs.h"
#include  "common_types.h"
#include  "../common/ngap/ngap_common.h"


#include  "INTEGER.h"
#include  "asn_SEQUENCE_OF.h"
#include  "OCTET_STRING.h"

#define BUF_LEN   1024
Ngap_PDUSessionResourceModifyRequestIEs_t  *make_modify_request_RAN_UE_NGAP_ID(uint32_t rAN_UE_NGAP_ID)
{
	Ngap_PDUSessionResourceModifyRequestIEs_t *ie;
	ie = calloc(1, sizeof(Ngap_PDUSessionResourceModifyRequestIEs_t));

	ie->id = Ngap_ProtocolIE_ID_id_RAN_UE_NGAP_ID;
	ie->criticality = Ngap_Criticality_reject;
	ie->value.present = Ngap_PDUSessionResourceModifyRequestIEs__value_PR_RAN_UE_NGAP_ID;
	ie->value.choice.RAN_UE_NGAP_ID = rAN_UE_NGAP_ID ;

	printf("RAN_UE_NGAP_ID:0x%x",ie->value.choice.RAN_UE_NGAP_ID);
	return ie;
}
Ngap_PDUSessionResourceModifyRequestIEs_t  *make_modify_request_AMF_UE_NGAP_ID(uint64_t amf_UE_NGAP_ID)
{
    Ngap_PDUSessionResourceModifyRequestIEs_t *ie = NULL;
	ie = calloc(1, sizeof(Ngap_PDUSessionResourceModifyRequestIEs_t));
	
	ie->id = Ngap_ProtocolIE_ID_id_AMF_UE_NGAP_ID;
	ie->criticality = Ngap_Criticality_reject;
	ie->value.present = Ngap_PDUSessionResourceModifyRequestIEs__value_PR_AMF_UE_NGAP_ID;

	asn_ulong2INTEGER(&ie->value.choice.AMF_UE_NGAP_ID, amf_UE_NGAP_ID & AMF_UE_NGAP_ID_MASK_);
	
	size_t i  = 0;
	for(i ; i<ie->value.choice.AMF_UE_NGAP_ID.size;i++)
	{
	    printf("0x%x",ie->value.choice.AMF_UE_NGAP_ID.buf[i]);
	}
	return ie;
}
Ngap_PDUSessionResourceModifyRequestIEs_t  *make_modify_request_RANPagingPriority(const long  ranPagingPriority)
{
    Ngap_PDUSessionResourceModifyRequestIEs_t *ie = NULL;
	ie = calloc(1, sizeof(Ngap_PDUSessionResourceModifyRequestIEs_t));
	
	ie->id = Ngap_ProtocolIE_ID_id_RANPagingPriority;
	ie->criticality = Ngap_Criticality_ignore;
	ie->value.present = Ngap_PDUSessionResourceModifyRequestIEs__value_PR_RANPagingPriority;
    ie->value.choice.RANPagingPriority  = ranPagingPriority;

    printf("RANPagingPriority:0x%x",ie->value.choice.RANPagingPriority);
	return ie;
}


Ngap_PDUSessionResourceModifyItemModReq_t *make_PDUSessionResourceModifyItemModReq(
const long  pDUSessionID, 
const char *pDUSessionNAS_PDU,  
const char *pDUSessionResourceModifyRequestTransfer)
{
    Ngap_PDUSessionResourceModifyItemModReq_t  *item = NULL;
    item =  calloc(1, sizeof(Ngap_PDUSessionResourceModifyItemModReq_t));
	
    item->pDUSessionID = pDUSessionID;

	Ngap_NAS_PDU_t  *nas_pdu =  calloc(1, sizeof(Ngap_NAS_PDU_t));
	item->nAS_PDU  =  nas_pdu;
	OCTET_STRING_fromBuf(nas_pdu, pDUSessionNAS_PDU, strlen(pDUSessionNAS_PDU));
	
	OCTET_STRING_fromBuf(&item->pDUSessionResourceModifyRequestTransfer,pDUSessionResourceModifyRequestTransfer,strlen(pDUSessionResourceModifyRequestTransfer));
	
    return item;
}

Ngap_PDUSessionResourceModifyRequestIEs_t  * make_PDUSessionResourceModifyListModReq()
{
	Ngap_PDUSessionResourceModifyRequestIEs_t *ie;
	ie = calloc(1, sizeof(Ngap_PDUSessionResourceModifyRequestIEs_t));
	
	ie->id            = Ngap_ProtocolIE_ID_id_PDUSessionResourceModifyListModReq;
	ie->criticality   = Ngap_Criticality_reject;
	ie->value.present = Ngap_PDUSessionResourceModifyRequestIEs__value_PR_PDUSessionResourceModifyListModReq;
	
    return ie;
}

void add_pdu_session_resource_modify_request_ie(Ngap_PDUSessionResourceModifyRequest_t *ngapPDUSessionResourceModifyRequest, Ngap_PDUSessionResourceModifyRequestIEs_t *ie) {
    int ret;
	ret = ASN_SEQUENCE_ADD(&ngapPDUSessionResourceModifyRequest->protocolIEs.list, ie);
    if ( ret != 0 ) {
        fprintf(stderr, "Failed to add ie\n");
		return ;
    }
	return ;
}
Ngap_NGAP_PDU_t *make_NGAP_pdu_session_resource_modify_request()
{
    Ngap_NGAP_PDU_t * pdu = NULL;
	pdu = calloc(1, sizeof(Ngap_NGAP_PDU_t));
    
	pdu->present = Ngap_NGAP_PDU_PR_initiatingMessage;
	pdu->choice.initiatingMessage = calloc(1, sizeof(Ngap_InitiatingMessage_t));
	pdu->choice.initiatingMessage->procedureCode = Ngap_ProcedureCode_id_PDUSessionResourceModify;
	pdu->choice.initiatingMessage->criticality = Ngap_Criticality_reject;
	pdu->choice.initiatingMessage->value.present = Ngap_InitiatingMessage__value_PR_PDUSessionResourceModifyRequest;

    Ngap_PDUSessionResourceModifyRequest_t *ngapPDUSessionResourceModifyRequest = NULL;
	ngapPDUSessionResourceModifyRequest = &pdu->choice.initiatingMessage->value.choice.PDUSessionResourceModifyRequest;
	
	Ngap_PDUSessionResourceModifyRequestIEs_t  *ie = NULL;

    //Ngap_AMF_UE_NGAP_ID_t
	uint64_t  amf_ue_ngap_id = 0x80;
	ie  = make_modify_request_AMF_UE_NGAP_ID(amf_ue_ngap_id);
    add_pdu_session_resource_release_command_ie(ngapPDUSessionResourceModifyRequest, ie);

	//Ngap_AMF_UE_NGAP_ID_t
    uint32_t  ran_ue_ngap_id = 0x81;
	ie  = make_modify_request_RAN_UE_NGAP_ID(ran_ue_ngap_id);
	add_pdu_session_resource_release_command_ie(ngapPDUSessionResourceModifyRequest, ie);

     
	//Ngap_RANPagingPriority_t
	long ranPagingPriority  = 0x82;
    ie  = make_modify_request_RANPagingPriority(ranPagingPriority);
	add_pdu_session_resource_release_command_ie(ngapPDUSessionResourceModifyRequest, ie);
	
	
    //PDUSessionResourceToReleaseListRelCmd
    Ngap_PDUSessionResourceModifyItemModReq_t	 *modReqItem = NULL;
	ie          =  make_PDUSessionResourceModifyListModReq();
	modReqItem  =  make_PDUSessionResourceModifyItemModReq(0x80, "test_nas_pdu", "test_mod_req");
	ASN_SEQUENCE_ADD(&ie->value.choice.PDUSessionResourceModifyListModReq.list, modReqItem);
	add_pdu_session_resource_release_command_ie(ngapPDUSessionResourceModifyRequest, ie);
	 

	printf("0000000000000, make_NGAP_pdu_session_resource_modify_request\n");
    return pdu;
}


int
ngap_amf_handle_ng_pdu_session_resource_modify_request(
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
    Ngap_PDUSessionResourceModifyRequest_t                  *container = NULL;
    Ngap_PDUSessionResourceModifyRequestIEs_t               *ie = NULL;
    Ngap_PDUSessionResourceModifyRequestIEs_t               *ie_gnb_name = NULL;

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
	
	
	char 	  *nAS_PDU = NULL;
	int       nAS_PDU_size  =  0;

	char      *pDUSessionResourceModifyRequestTransfer = NULL;
	int       pDUSessionResourceModifyRequestTransfer_size  = 0;
	

    DevAssert (pdu != NULL);
    //OAILOG_INFO(LOG_NGAP,"----------------------- DECODED NG SETUP REQUEST NGAP MSG --------------------------\n");
    //asn_fprint(stdout, &asn_DEF_Ngap_NGAP_PDU, pdu);
    //OAILOG_INFO(LOG_NGAP,"----------------------- DECODED NG SETUP REQUEST NGAP MSG --------------------------\n");

	container = &pdu->choice.initiatingMessage->value.choice.PDUSessionResourceModifyRequest;
    
    //AMF_UE_NGAP_ID
    NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_PDUSessionResourceModifyRequestIEs_t, ie, container, Ngap_ProtocolIE_ID_id_AMF_UE_NGAP_ID, false);
    if (ie) 
	{  
	   asn_INTEGER2ulong(&ie->value.choice.AMF_UE_NGAP_ID, &amf_ue_ngap_id);
	   printf("amf_ue_ngap_id, 0x%x\n", amf_ue_ngap_id);
    }

    //Ngap_AMF_UE_NGAP_ID_t
    NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_PDUSessionResourceModifyRequestIEs_t, ie, container, Ngap_ProtocolIE_ID_id_RAN_UE_NGAP_ID, false);
    if (ie) 
	{  
	   ran_ue_ngap_id = ie->value.choice.RAN_UE_NGAP_ID;
	   printf("ran_ue_ngap_id, 0x%x\n", ran_ue_ngap_id);
    }

	//RANPagingPriority
	NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_PDUSessionResourceModifyRequestIEs_t, ie, container, Ngap_ProtocolIE_ID_id_RANPagingPriority, false);
    if (ie) 
	{  
	   ranPagingPriority = ie->value.choice.RANPagingPriority;
	   printf("ranPagingPriority, 0x%x\n", ranPagingPriority);
    }

	//PDUSessionResourceModifyListModReq
    NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_PDUSessionResourceModifyRequestIEs_t, ie, container, Ngap_ProtocolIE_ID_id_PDUSessionResourceModifyListModReq, false);
	if (ie) 
	{ 
	    Ngap_PDUSessionResourceModifyListModReq_t	 *modreq_container  =  &ie->value.choice.PDUSessionResourceModifyListModReq;
        for (i  = 0;i < modreq_container->list.count; i++)
	    {
            Ngap_PDUSessionResourceModifyItemModReq_t *modreqIes_p = NULL;
            modreqIes_p = modreq_container->list.array[i];
			
			if(!modreqIes_p)
			{
				  continue;
        	}

		    pDUSessionID  = modreqIes_p->pDUSessionID;

			if(nAS_PDU)
			{
		 	    nAS_PDU       = modreqIes_p->nAS_PDU->buf;
		        nAS_PDU_size  = modreqIes_p->nAS_PDU->size;
			}

			pDUSessionResourceModifyRequestTransfer      = modreqIes_p->pDUSessionResourceModifyRequestTransfer.buf;
			pDUSessionResourceModifyRequestTransfer_size = modreqIes_p->pDUSessionResourceModifyRequestTransfer.size;
				
		}
	}
	
	return rc;
}


