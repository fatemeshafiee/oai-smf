
#include  <BIT_STRING.h>

#include  "ng_pdu_downlink_ran_status_transfer.h"
#include  "Ngap_DownlinkRANStatusTransfer.h"

#include  "Ngap_DRBsSubjectToStatusTransferList.h"
#include  "Ngap_DRBsSubjectToStatusTransferItem.h"
#include  "Ngap_RANStatusTransfer-TransparentContainer.h"

#include  "Ngap_DRBsSubjectToStatusTransferList.h"

#include  "Ngap_DRBsSubjectToStatusTransferItem.h"


#include  "Ngap_DRB-ID.h"
#include  "Ngap_DRBStatusUL.h"
#include  "Ngap_DRBStatusDL.h"
#include  "Ngap_DRBStatusDL12.h"

#include  "Ngap_DRBStatusUL12.h"
#include  "Ngap_DRBStatusUL18.h"
#include  "Ngap_COUNTValueForPDCP-SN12.h"



#include  "Ngap_NGAP-PDU.h"
#include  "Ngap_ProtocolIE-Field.h"
#include  "Ngap_ProcedureCode.h"
#include  "Ngap_InitiatingMessage.h"

#include  "common_defs.h"
#include  "common_types.h"
#include  "../common/ngap/ngap_common.h"

#include  "INTEGER.h"
#include  "asn_SEQUENCE_OF.h"
#include  "OCTET_STRING.h"

#define BUF_LEN   1024
Ngap_DownlinkRANStatusTransferIEs_t  *make_downlink_ran_RAN_UE_NGAP_ID(uint32_t rAN_UE_NGAP_ID)
{
	Ngap_DownlinkRANStatusTransferIEs_t *ie;
	ie                              = calloc(1, sizeof(Ngap_DownlinkRANStatusTransferIEs_t));

	ie->id                          = Ngap_ProtocolIE_ID_id_RAN_UE_NGAP_ID;
	ie->criticality                 = Ngap_Criticality_reject;
	ie->value.present               = Ngap_DownlinkRANStatusTransferIEs__value_PR_RAN_UE_NGAP_ID;
	ie->value.choice.RAN_UE_NGAP_ID = rAN_UE_NGAP_ID ;

	printf("RAN_UE_NGAP_ID:0x%x\n",ie->value.choice.RAN_UE_NGAP_ID);
	return ie;
}
Ngap_DownlinkRANStatusTransferIEs_t  *make_downlink_ran_AMF_UE_NGAP_ID(uint64_t amf_UE_NGAP_ID)
{
    Ngap_DownlinkRANStatusTransferIEs_t *ie = NULL;
	ie                = calloc(1, sizeof(Ngap_DownlinkRANStatusTransferIEs_t));
	
	ie->id            = Ngap_ProtocolIE_ID_id_AMF_UE_NGAP_ID;
	ie->criticality   = Ngap_Criticality_reject;
	ie->value.present = Ngap_DownlinkRANStatusTransferIEs__value_PR_AMF_UE_NGAP_ID;

	asn_ulong2INTEGER(&ie->value.choice.AMF_UE_NGAP_ID, amf_UE_NGAP_ID & AMF_UE_NGAP_ID_MASK_);
	
	printf("AMF_UE_NGAP_ID:0x%x\n",ie->value.choice.AMF_UE_NGAP_ID);
	return ie;
}

Ngap_DownlinkRANStatusTransferIEs_t  *make_downlink_ran_RANStatusTransfer_TransparentContainer()
{
	Ngap_DownlinkRANStatusTransferIEs_t *ie = NULL;
	ie				  = calloc(1, sizeof(Ngap_DownlinkRANStatusTransferIEs_t));
		
	ie->id			  = Ngap_ProtocolIE_ID_id_RANStatusTransfer_TransparentContainer;
	ie->criticality   = Ngap_Criticality_reject;
	ie->value.present = Ngap_DownlinkRANStatusTransferIEs__value_PR_RANStatusTransfer_TransparentContainer;
	
	return ie;
}


void add_pdu_downlink_ran_ie(Ngap_DownlinkRANStatusTransfer_t *ngapDownlinkRANStatusTransfer, Ngap_DownlinkRANStatusTransferIEs_t *ie) {
    int ret;
	ret = ASN_SEQUENCE_ADD(&ngapDownlinkRANStatusTransfer->protocolIEs.list, ie);
    if ( ret != 0 ) {
        fprintf(stderr, "Failed to add ie\n");
		return ;
    }
	return ;
}
Ngap_NGAP_PDU_t *  ngap_generate_ng_downlink_ran(const char *inputBuf)

{
    Ngap_NGAP_PDU_t * pdu = NULL;
	pdu = calloc(1, sizeof(Ngap_NGAP_PDU_t));
	memset(pdu, 0,  sizeof(sizeof(Ngap_NGAP_PDU_t)));
    
	pdu->present = Ngap_NGAP_PDU_PR_initiatingMessage;
	pdu->choice.initiatingMessage = calloc(1, sizeof(Ngap_InitiatingMessage_t));
	pdu->choice.initiatingMessage->procedureCode = Ngap_ProcedureCode_id_DownlinkRANStatusTransfer;                 
	pdu->choice.initiatingMessage->criticality   = Ngap_Criticality_ignore;
	pdu->choice.initiatingMessage->value.present = Ngap_InitiatingMessage__value_PR_DownlinkNASTransport;

    Ngap_DownlinkRANStatusTransfer_t *ngapDownlinkRANStatusTransfer = NULL;
	ngapDownlinkRANStatusTransfer = &pdu->choice.initiatingMessage->value.choice.DownlinkRANStatusTransfer;
	Ngap_DownlinkRANStatusTransferIEs_t *ie = NULL;

  
    //Ngap_AMF_UE_NGAP_ID_t
	uint64_t  amf_ue_ngap_id = 0x80;
	ie  = make_downlink_ran_AMF_UE_NGAP_ID(amf_ue_ngap_id);
    add_pdu_downlink_ran_ie(ngapDownlinkRANStatusTransfer, ie);

	//Ngap_AMF_UE_NGAP_ID_t
    uint32_t  ran_ue_ngap_id = 0x81;
	ie  = make_downlink_ran_RAN_UE_NGAP_ID(ran_ue_ngap_id);
	add_pdu_downlink_ran_ie(ngapDownlinkRANStatusTransfer, ie);
    
    
	#if 0 
	//failed print 
	//RANStatusTransfer_TransparentContainer
	Ngap_DRBsSubjectToStatusTransferItem_t  *pTransferItem = NULL;
	ie =  make_downlink_ran_RANStatusTransfer_TransparentContainer();
	pTransferItem = calloc(1, sizeof(Ngap_DRBsSubjectToStatusTransferItem_t));
	
    //dRB_ID
    uint32_t  dRB_ID       =  1;
    pTransferItem->dRB_ID  =  dRB_ID;

	//dRBStatusUL
    //Ngap_DRBStatusUL_t	 dRBStatusUL;
    uint16_t pDCP_SN12     = 0x01;
	uint32_t hFN_PDCP_SN12 = 0x02;
    char recvStatus[11] = {0x011,0x012,0x011,0x012,0x011,0x012,0x011,0x012,0x011,0x012,0x011}; /*1-2048 BITS*/
	
    pTransferItem->dRBStatusUL.present  =  Ngap_DRBStatusUL_PR_NOTHING;

	Ngap_DRBStatusUL12_t *dRBStatusUL12 =  calloc(1, sizeof(Ngap_DRBStatusUL12_t));
    pTransferItem->dRBStatusUL.choice.dRBStatusUL12  = dRBStatusUL12;
	
   
	//dRBStatusUL12->uL_COUNTValue.pDCP_SN12      = pDCP_SN12     & 0x0FFF; //12BITS
    //dRBStatusUL12->uL_COUNTValue.hFN_PDCP_SN12  = hFN_PDCP_SN12 & 0x000FFFFF;//20BITS

	dRBStatusUL12->uL_COUNTValue.pDCP_SN12      = 1 ;   
    dRBStatusUL12->uL_COUNTValue.hFN_PDCP_SN12  = 2;

	printf("dRBStatusUL12,pDCP_SN12:0x%x,hFN_PDCP_SN12:0x%x\n",
	dRBStatusUL12->uL_COUNTValue.pDCP_SN12,
	dRBStatusUL12->uL_COUNTValue.hFN_PDCP_SN12);

	
	//BIT_STRING_t	*receiveStatusOfUL_PDCP_SDUs
	dRBStatusUL12->receiveStatusOfUL_PDCP_SDUs  = calloc(1, sizeof(BIT_STRING_t));
	
    dRBStatusUL12->receiveStatusOfUL_PDCP_SDUs->buf     = calloc(11, sizeof(uint8_t));
	dRBStatusUL12->receiveStatusOfUL_PDCP_SDUs->size    = 11;
	memcpy(dRBStatusUL12->receiveStatusOfUL_PDCP_SDUs->buf, recvStatus, 11);
	dRBStatusUL12->receiveStatusOfUL_PDCP_SDUs->bits_unused = 0;
    
   
	//dRBStatusDL
	//Ngap_DRBStatusDL_t	 dRBStatusDL;
    pTransferItem->dRBStatusDL.present  =  Ngap_DRBStatusDL_PR_dRBStatusDL12;
	
	Ngap_DRBStatusDL12_t *dRBStatusDL12 =  calloc(1, sizeof(Ngap_DRBStatusDL12_t));
	//dRBStatusDL12->dL_COUNTValue.pDCP_SN12      = pDCP_SN12     & 0x0FFF;  //12BITS
    //dRBStatusDL12->dL_COUNTValue.hFN_PDCP_SN12  = hFN_PDCP_SN12 & 0x000FFFFF;//18BITS

	dRBStatusDL12->dL_COUNTValue.pDCP_SN12      = 3;  //12BITS
    dRBStatusDL12->dL_COUNTValue.hFN_PDCP_SN12  = 4;//18BITS

    pTransferItem->dRBStatusDL.choice.dRBStatusDL12  = dRBStatusDL12;
	
    printf("dRBStatusDL12,pDCP_SN12:0x%x,hFN_PDCP_SN12:0x%x\n",
	dRBStatusDL12->dL_COUNTValue.pDCP_SN12,
	dRBStatusDL12->dL_COUNTValue.hFN_PDCP_SN12);


    //Ngap_RANStatusTransfer_TransparentContainer_t	 RANStatusTransfer_TransparentContainer;
    //Ngap_DRBsSubjectToStatusTransferList_t   *pStatusTransferList = calloc(1, sizeof(Ngap_DRBsSubjectToStatusTransferList_t));
	//ASN_SEQUENCE_ADD(&pStatusTransferList->list, pTransferItem);
	//ie->value.choice.RANStatusTransfer_TransparentContainer.dRBsSubjectToStatusTransferList = *pStatusTransferList;
	
	ASN_SEQUENCE_ADD(&ie->value.choice.RANStatusTransfer_TransparentContainer.dRBsSubjectToStatusTransferList.list, pTransferItem);
	add_pdu_downlink_ran_ie(ngapDownlinkRANStatusTransfer, ie);
	#endif
	
    return pdu;
}


int
ngap_amf_handle_ng_pdu_downlink_ran(
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
    Ngap_DownlinkRANStatusTransfer_t                     *container = NULL;
    Ngap_DownlinkRANStatusTransferIEs_t                  *ie = NULL;
    Ngap_DownlinkRANStatusTransferIEs_t                  *ie_gnb_name = NULL;

    unsigned  long    amf_ue_ngap_id        = 0;
	uint32_t          ran_ue_ngap_id        = 0;
	uint32_t          radioNetwork          = 0;
	uint32_t          DirectForwardingPathAvailability = 0;
	

    DevAssert (pdu != NULL);
    //OAILOG_INFO(LOG_NGAP,"----------------------- DECODED NG SETUP REQUEST NGAP MSG --------------------------\n");
    //asn_fprint(stdout, &asn_DEF_Ngap_NGAP_PDU, pdu);
    //OAILOG_INFO(LOG_NGAP,"----------------------- DECODED NG SETUP REQUEST NGAP MSG --------------------------\n");

	container = &pdu->choice.initiatingMessage->value.choice.DownlinkRANStatusTransfer;
    
    //AMF_UE_NGAP_ID
    NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_DownlinkRANStatusTransferIEs_t, ie, container, Ngap_ProtocolIE_ID_id_AMF_UE_NGAP_ID, false);
    if (ie) 
	{  
	   asn_INTEGER2ulong(&ie->value.choice.AMF_UE_NGAP_ID, &amf_ue_ngap_id);
	   printf("amf_ue_ngap_id, 0x%x\n", amf_ue_ngap_id);
    }

    //Ngap_AMF_UE_NGAP_ID_t
    NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_DownlinkRANStatusTransferIEs_t, ie, container, Ngap_ProtocolIE_ID_id_RAN_UE_NGAP_ID, false);
    if (ie) 
	{  
	   ran_ue_ngap_id = ie->value.choice.RAN_UE_NGAP_ID;
	   printf("ran_ue_ngap_id, 0x%x\n", ran_ue_ngap_id);
    }

    #if 0
	//RANStatusTransfer_TransparentContainer
    NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_DownlinkRANStatusTransferIEs_t, ie, container, Ngap_ProtocolIE_ID_id_RANStatusTransfer_TransparentContainer, false);
    if (ie) 
	{  
	  
    }
	#endif

}

int  make_NGAP_PduDownlinkRanStatusTransfer(const char *inputBuf, const char *OutputBuf)
{

    printf("pdu session downlink ran status transfer, start--------------------\n\n");

    int ret = 0;
	int rc  = RETURNok;
	const sctp_assoc_id_t assoc_id  = 0;
    const sctp_stream_id_t stream   = 0;
	Ngap_NGAP_PDU_t  message = {0};

	//wys:  1024 ?
	size_t buffer_size = 1024;  
	void *buffer = calloc(1,buffer_size);
	asn_enc_rval_t er;	
	
	Ngap_NGAP_PDU_t * pdu = ngap_generate_ng_downlink_ran(inputBuf);
	if(!pdu)
		goto ERROR;
	
    asn_fprint(stderr, &asn_DEF_Ngap_NGAP_PDU, pdu);
  
    ret  =  check_NGAP_pdu_constraints(pdu);
    if(ret < 0) 
	{
		printf("ng downlink ran status transfer  Constraint validation  failed\n");
		rc = RETURNerror;
		goto ERROR; 
	}

	//encode
	er = aper_encode_to_buffer(&asn_DEF_Ngap_NGAP_PDU, NULL, pdu, buffer, buffer_size);
	if(er.encoded < 0)
	{
		printf("ng downlink ran status transfer encode failed,er.encoded:%d\n",er.encoded);
		rc = RETURNerror;
		goto ERROR; 
	}
  		 
	bstring msgBuf = blk2bstr(buffer, er.encoded);

    //decode
    ngap_amf_decode_pdu(&message, msgBuf);
	ngap_amf_handle_ng_pdu_downlink_ran(0,0, &message);

    //Free pdu
    ASN_STRUCT_FREE(asn_DEF_Ngap_NGAP_PDU, pdu);
	if(buffer)
	{
		free(buffer);
		buffer = NULL;
	}
	printf("pdu session downlink ran status transfer, finish--------------------\n\n");
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


