#include  "ng_pdu_session_resource_modify_indication.h"

#include  "Ngap_NGAP-PDU.h"
#include  "Ngap_ProtocolIE-Field.h"
#include  "Ngap_ProcedureCode.h"
#include  "Ngap_InitiatingMessage.h"

#include  "Ngap_Criticality.h"

#include "Ngap_PDUSessionResourceModifyListModInd.h"
#include "Ngap_PDUSessionResourceModifyItemModInd.h"


#include  "Ngap_PDUSessionResourceToReleaseListRelCmd.h"
#include  "Ngap_PDUSessionResourceToReleaseItemRelCmd.h"


#include  "common_defs.h"
#include  "common_types.h"
#include  "../common/ngap/ngap_common.h"


#include  "INTEGER.h"
#include  "asn_SEQUENCE_OF.h"
#include  "OCTET_STRING.h"

#define BUF_LEN   1024
Ngap_PDUSessionResourceModifyIndicationIEs_t  *make_modify_incication_RAN_UE_NGAP_ID(uint32_t rAN_UE_NGAP_ID)
{
	Ngap_PDUSessionResourceModifyIndicationIEs_t *ie;
	ie = calloc(1, sizeof(Ngap_PDUSessionResourceModifyIndicationIEs_t));

	ie->id = Ngap_ProtocolIE_ID_id_RAN_UE_NGAP_ID;
	ie->criticality = Ngap_Criticality_reject;
	ie->value.present = Ngap_PDUSessionResourceModifyIndicationIEs__value_PR_RAN_UE_NGAP_ID;
	ie->value.choice.RAN_UE_NGAP_ID = rAN_UE_NGAP_ID ;

	printf("RAN_UE_NGAP_ID:0x%x",ie->value.choice.RAN_UE_NGAP_ID);
	return ie;
}
Ngap_PDUSessionResourceModifyIndicationIEs_t  *make_modify_incication_AMF_UE_NGAP_ID(uint64_t amf_UE_NGAP_ID)
{
    Ngap_PDUSessionResourceModifyIndicationIEs_t *ie = NULL;
	ie = calloc(1, sizeof(Ngap_PDUSessionResourceModifyIndicationIEs_t));
	
	ie->id = Ngap_ProtocolIE_ID_id_AMF_UE_NGAP_ID;
	ie->criticality = Ngap_Criticality_reject;
	ie->value.present = Ngap_PDUSessionResourceModifyIndicationIEs__value_PR_AMF_UE_NGAP_ID;

	asn_ulong2INTEGER(&ie->value.choice.AMF_UE_NGAP_ID, amf_UE_NGAP_ID & AMF_UE_NGAP_ID_MASK_);
	
	size_t i  = 0;
	for(i ; i<ie->value.choice.AMF_UE_NGAP_ID.size;i++)
	{
	    printf("0x%x",ie->value.choice.AMF_UE_NGAP_ID.buf[i]);
	}
	return ie;
}

Ngap_PDUSessionResourceModifyItemModInd_t *make_PDUSessionResourceModifyItemModInd(
const long  pDUSessionID, 
const char *pDUSRModifyIndicationTransfer)
{
    Ngap_PDUSessionResourceModifyItemModInd_t  *item = NULL;
    item =  calloc(1, sizeof(Ngap_PDUSessionResourceModifyItemModInd_t));
	
    item->pDUSessionID = pDUSessionID;
	OCTET_STRING_fromBuf(&item->pDUSessionResourceModifyIndicationTransfer,pDUSRModifyIndicationTransfer,strlen(pDUSRModifyIndicationTransfer));

	printf("ModifyIndication, pDUSessionID:0x%x,Transfer:%s\n", pDUSessionID,  pDUSRModifyIndicationTransfer);
	
    return item;
}

Ngap_PDUSessionResourceModifyIndicationIEs_t  * make_PDUSessionResourceModifyListModInd()
{
	Ngap_PDUSessionResourceModifyRequestIEs_t *ie;
	ie = calloc(1, sizeof(Ngap_PDUSessionResourceModifyIndicationIEs_t));
	
	ie->id            = Ngap_ProtocolIE_ID_id_PDUSessionResourceModifyListModInd;
	ie->criticality   = Ngap_Criticality_reject;
	ie->value.present = Ngap_PDUSessionResourceModifyIndicationIEs__value_PR_PDUSessionResourceModifyListModInd;
	
    return ie;
}

void add_pdu_session_resource_modify_indication_ie(Ngap_PDUSessionResourceModifyIndication_t *ngapPDUSessionResourceModifyIndication, Ngap_PDUSessionResourceModifyIndicationIEs_t *ie) {
    int ret;
	ret = ASN_SEQUENCE_ADD(&ngapPDUSessionResourceModifyIndication->protocolIEs.list, ie);
    if ( ret != 0 ) {
        fprintf(stderr, "Failed to add ie\n");
		return ;
    }
	return ;
}
Ngap_NGAP_PDU_t *  ngap_generate_ng_modify_indication(const char *inputBuf)
{
    Ngap_NGAP_PDU_t * pdu = NULL;
	pdu = calloc(1, sizeof(Ngap_NGAP_PDU_t));
    
	pdu->present = Ngap_NGAP_PDU_PR_initiatingMessage;
	pdu->choice.initiatingMessage = calloc(1, sizeof(Ngap_InitiatingMessage_t));
	pdu->choice.initiatingMessage->procedureCode = Ngap_ProcedureCode_id_PDUSessionResourceModifyIndication;
	pdu->choice.initiatingMessage->criticality = Ngap_Criticality_reject;
	pdu->choice.initiatingMessage->value.present = Ngap_InitiatingMessage__value_PR_PDUSessionResourceModifyIndication;

    Ngap_PDUSessionResourceModifyIndication_t *ngapPDUSessionResourceModifyIndication = NULL;
	ngapPDUSessionResourceModifyIndication = &pdu->choice.initiatingMessage->value.choice.PDUSessionResourceModifyIndication;
	
	Ngap_PDUSessionResourceModifyIndicationIEs_t  *ie = NULL;

    //Ngap_AMF_UE_NGAP_ID_t
	uint64_t  amf_ue_ngap_id = 0x80;
	ie  = make_modify_incication_AMF_UE_NGAP_ID(amf_ue_ngap_id);
    add_pdu_session_resource_modify_indication_ie(ngapPDUSessionResourceModifyIndication, ie);

	//Ngap_AMF_UE_NGAP_ID_t
    uint32_t  ran_ue_ngap_id = 0x81;
	ie  = make_modify_incication_RAN_UE_NGAP_ID(ran_ue_ngap_id);
	add_pdu_session_resource_modify_indication_ie(ngapPDUSessionResourceModifyIndication, ie);

    //Ngap_PDUSessionResourceModifyItemModInd_t
    Ngap_PDUSessionResourceModifyItemModInd_t	 *modIndItem = NULL;
	ie          =  make_PDUSessionResourceModifyListModInd();
	modIndItem  =  make_PDUSessionResourceModifyItemModInd(0x80, "test_mod_ind");
	ASN_SEQUENCE_ADD(&ie->value.choice.PDUSessionResourceModifyListModInd.list, modIndItem);
	add_pdu_session_resource_modify_indication_ie(ngapPDUSessionResourceModifyIndication, ie);
	
    return pdu;
}


int
ngap_amf_handle_ng_pdu_session_resource_modify_incication(
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
    Ngap_PDUSessionResourceModifyIndication_t                  *container = NULL;
    Ngap_PDUSessionResourceModifyIndicationIEs_t               *ie = NULL;
    Ngap_PDUSessionResourceModifyIndicationIEs_t               *ie_gnb_name = NULL;

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

	char      *pDUSessionResourceModifyIndicationTransfer = NULL;
	int       pDUSessionResourceModifyIndicationTransfer_size  = 0;
	

    DevAssert (pdu != NULL);
    //OAILOG_INFO(LOG_NGAP,"----------------------- DECODED NG SETUP REQUEST NGAP MSG --------------------------\n");
    //asn_fprint(stdout, &asn_DEF_Ngap_NGAP_PDU, pdu);
    //OAILOG_INFO(LOG_NGAP,"----------------------- DECODED NG SETUP REQUEST NGAP MSG --------------------------\n");

	container = &pdu->choice.initiatingMessage->value.choice.PDUSessionResourceModifyIndication;
    
    //AMF_UE_NGAP_ID
    NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_PDUSessionResourceModifyIndicationIEs_t, ie, container, Ngap_ProtocolIE_ID_id_AMF_UE_NGAP_ID, false);
    if (ie) 
	{  
	   asn_INTEGER2ulong(&ie->value.choice.AMF_UE_NGAP_ID, &amf_ue_ngap_id);
	   printf("amf_ue_ngap_id, 0x%x\n", amf_ue_ngap_id);
    }

    //Ngap_AMF_UE_NGAP_ID_t
    NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_PDUSessionResourceModifyIndicationIEs_t, ie, container, Ngap_ProtocolIE_ID_id_RAN_UE_NGAP_ID, false);
    if (ie) 
	{  
	   ran_ue_ngap_id = ie->value.choice.RAN_UE_NGAP_ID;
	   printf("ran_ue_ngap_id, 0x%x\n", ran_ue_ngap_id);
    }

	
	//PDUSessionResourceModifyListModReq
    NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_PDUSessionResourceModifyIndicationIEs_t, ie, container, Ngap_ProtocolIE_ID_id_PDUSessionResourceModifyListModInd, false);
	if (ie) 
	{ 
	    Ngap_PDUSessionResourceModifyListModInd_t	 *modind_container  =  &ie->value.choice.PDUSessionResourceModifyListModInd;
        for (i  = 0;i < modind_container->list.count; i++)
	    {
            Ngap_PDUSessionResourceModifyItemModInd_t *modindIes_p = NULL;
            modindIes_p = modind_container->list.array[i];
			
			if(!modindIes_p)
			{
				  continue;
        	}

		    pDUSessionID  = modindIes_p->pDUSessionID;
			pDUSessionResourceModifyIndicationTransfer      = modindIes_p->pDUSessionResourceModifyIndicationTransfer.buf;
			pDUSessionResourceModifyIndicationTransfer_size = modindIes_p->pDUSessionResourceModifyIndicationTransfer.size;

			printf("ModifyIndication, pDUSessionID:0x%x,Transfer:%s\n",
			pDUSessionID,  pDUSessionResourceModifyIndicationTransfer);
		}
	}


	return rc;
}

int  make_NGAP_PduSessionResourceModifyIndication(const char *inputBuf, const char *OutputBuf)
{
    printf("pdu session  resource modify indication, start--------------------\n\n");

    int ret = 0;
	int rc  = RETURNok;
	const sctp_assoc_id_t assoc_id  = 0;
    const sctp_stream_id_t stream   = 0;
	Ngap_NGAP_PDU_t  message = {0};

	//wys:  1024 ?
	size_t buffer_size = 1024;  
	void *buffer = calloc(1,buffer_size);
	asn_enc_rval_t er;	
	
	Ngap_NGAP_PDU_t * pdu =  ngap_generate_ng_modify_indication(inputBuf);
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
	ngap_amf_handle_ng_pdu_session_resource_modify_incication(0, 0, &message);


    //Free pdu
    ASN_STRUCT_FREE(asn_DEF_Ngap_NGAP_PDU, pdu);
	if(buffer)
	{
		free(buffer);
		buffer = NULL;
	}
	printf("pdu session  resource modify indication, finish--------------------\n\n");
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



