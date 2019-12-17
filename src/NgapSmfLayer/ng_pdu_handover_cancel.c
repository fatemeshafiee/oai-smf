#include  "ng_pdu_handover_cancel.h"

#include  "Ngap_NGAP-PDU.h"
#include  "Ngap_ProtocolIE-Field.h"
#include  "Ngap_ProcedureCode.h"
#include  "Ngap_InitiatingMessage.h"

#include  "Ngap_HandoverCancel.h"


#include  "Ngap_CauseRadioNetwork.h"
#include  "Ngap_DirectForwardingPathAvailability.h"


#include  "common_defs.h"
#include  "common_types.h"
#include  "../common/ngap/ngap_common.h"



#include  "INTEGER.h"
#include  "asn_SEQUENCE_OF.h"
#include  "OCTET_STRING.h"

#define BUF_LEN   1024
Ngap_HandoverCancelIEs_t  *make_handover_cancel_RAN_UE_NGAP_ID(uint32_t rAN_UE_NGAP_ID)
{
	Ngap_HandoverCancelIEs_t *ie;
	ie                              = calloc(1, sizeof(Ngap_HandoverCancelIEs_t));

	ie->id                          = Ngap_ProtocolIE_ID_id_RAN_UE_NGAP_ID;
	ie->criticality                 = Ngap_Criticality_reject;
	ie->value.present               = Ngap_HandoverCancelIEs__value_PR_RAN_UE_NGAP_ID;
	ie->value.choice.RAN_UE_NGAP_ID = rAN_UE_NGAP_ID ;

	printf("RAN_UE_NGAP_ID:0x%x\n",ie->value.choice.RAN_UE_NGAP_ID);
	return ie;
}
Ngap_HandoverCancelIEs_t  *make_handover_cancel_AMF_UE_NGAP_ID(uint64_t amf_UE_NGAP_ID)
{
    Ngap_HandoverCancelIEs_t *ie = NULL;
	ie                = calloc(1, sizeof(Ngap_HandoverCancelIEs_t));
	
	ie->id            = Ngap_ProtocolIE_ID_id_AMF_UE_NGAP_ID;
	ie->criticality   = Ngap_Criticality_reject;
	ie->value.present = Ngap_HandoverCancelIEs__value_PR_AMF_UE_NGAP_ID;

	asn_ulong2INTEGER(&ie->value.choice.AMF_UE_NGAP_ID, amf_UE_NGAP_ID & AMF_UE_NGAP_ID_MASK_);
	
	printf("AMF_UE_NGAP_ID:0x%x\n",ie->value.choice.AMF_UE_NGAP_ID);
	return ie;
}

Ngap_HandoverCancelIEs_t  *make_handover_cancel_CauseRadioNetwork(const long radioNetwork)
{
	Ngap_HandoverCancelIEs_t *ie = NULL;
	ie                                          = calloc(1, sizeof(Ngap_HandoverCancelIEs_t));
	
	ie->id                                      = Ngap_ProtocolIE_ID_id_Cause;
	ie->criticality                             = Ngap_Criticality_ignore;
	ie->value.present                           = Ngap_HandoverCancelIEs__value_PR_Cause;


    ie->value.choice.Cause.present              = Ngap_Cause_PR_radioNetwork;
    ie->value.choice.Cause.choice.radioNetwork  = radioNetwork;

	printf("radioNetwork:0x%x\n",ie->value.choice.Cause.choice.radioNetwork);
	return ie;
}

void add_pdu_handover_cancel_ie(Ngap_HandoverCancel_t *ngapPDUHandoverCancel, Ngap_HandoverCancelIEs_t *ie) {
    int ret;
	ret = ASN_SEQUENCE_ADD(&ngapPDUHandoverCancel->protocolIEs.list, ie);
    if ( ret != 0 ) {
        fprintf(stderr, "Failed to add ie\n");
		return ;
    }
	return ;
}
Ngap_NGAP_PDU_t *  ngap_generate_ng_handover_cancel(const char *inputBuf)

{
    Ngap_NGAP_PDU_t * pdu = NULL;
	pdu = calloc(1, sizeof(Ngap_NGAP_PDU_t));
    
	pdu->present = Ngap_NGAP_PDU_PR_initiatingMessage;
	pdu->choice.initiatingMessage = calloc(1, sizeof(Ngap_InitiatingMessage_t));
	pdu->choice.initiatingMessage->procedureCode = Ngap_ProcedureCode_id_HandoverCancel;
	                                               
	pdu->choice.initiatingMessage->criticality   = Ngap_Criticality_reject;
	pdu->choice.initiatingMessage->value.present = Ngap_InitiatingMessage__value_PR_HandoverCancel;

    Ngap_HandoverCancel_t *ngapHandoverCancel= NULL;
	ngapHandoverCancel = &pdu->choice.initiatingMessage->value.choice.HandoverCancel;
	
	Ngap_HandoverCancelIEs_t  *ie = NULL;

    //Ngap_AMF_UE_NGAP_ID_t
	uint64_t  amf_ue_ngap_id = 0x80;
	ie  = make_handover_cancel_AMF_UE_NGAP_ID(amf_ue_ngap_id);
    add_pdu_handover_cancel_ie(ngapHandoverCancel, ie);

	//Ngap_AMF_UE_NGAP_ID_t
    uint32_t  ran_ue_ngap_id = 0x81;
	ie  = make_handover_cancel_RAN_UE_NGAP_ID(ran_ue_ngap_id);
	add_pdu_handover_cancel_ie(ngapHandoverCancel, ie);

	//Cause:CauseRadioNetwork
	ie = make_handover_cancel_CauseRadioNetwork(Ngap_CauseRadioNetwork_unspecified);
    add_pdu_handover_cancel_ie(ngapHandoverCancel, ie);

    return pdu;
}


int
ngap_amf_handle_ng_pdu_handover_cancel(
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
    Ngap_HandoverCancel_t                     *container = NULL;
    Ngap_HandoverCancelIEs_t                  *ie = NULL;
    Ngap_HandoverCancelIEs_t                  *ie_gnb_name = NULL;

    unsigned  long    amf_ue_ngap_id        = 0;
	uint32_t          ran_ue_ngap_id        = 0;
	uint32_t          radioNetwork          = 0;
	uint32_t          DirectForwardingPathAvailability = 0;
	

    DevAssert (pdu != NULL);
    //OAILOG_INFO(LOG_NGAP,"----------------------- DECODED NG SETUP REQUEST NGAP MSG --------------------------\n");
    //asn_fprint(stdout, &asn_DEF_Ngap_NGAP_PDU, pdu);
    //OAILOG_INFO(LOG_NGAP,"----------------------- DECODED NG SETUP REQUEST NGAP MSG --------------------------\n");

	container = &pdu->choice.initiatingMessage->value.choice.HandoverCancel;
    
    //AMF_UE_NGAP_ID
    NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_HandoverCancelIEs_t, ie, container, Ngap_ProtocolIE_ID_id_AMF_UE_NGAP_ID, false);
    if (ie) 
	{  
	   asn_INTEGER2ulong(&ie->value.choice.AMF_UE_NGAP_ID, &amf_ue_ngap_id);
	   printf("amf_ue_ngap_id, 0x%x\n", amf_ue_ngap_id);
    }

    //Ngap_AMF_UE_NGAP_ID_t
    NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_HandoverCancelIEs_t, ie, container, Ngap_ProtocolIE_ID_id_RAN_UE_NGAP_ID, false);
    if (ie) 
	{  
	   ran_ue_ngap_id = ie->value.choice.RAN_UE_NGAP_ID;
	   printf("ran_ue_ngap_id, 0x%x\n", ran_ue_ngap_id);
    }

    //cause
	NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_HandoverCancelIEs_t, ie, container, Ngap_ProtocolIE_ID_id_Cause, false);
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
			break;
	    }
	}
}

int  make_NGAP_PduHandOverCancel(const char *inputBuf, const char *OutputBuf)
{

    printf("pdu session hand over cancel, start--------------------\n\n");

    int ret = 0;
	int rc  = RETURNok;
	const sctp_assoc_id_t assoc_id  = 0;
    const sctp_stream_id_t stream   = 0;
	Ngap_NGAP_PDU_t  message = {0};

	//wys:  1024 ?
	size_t buffer_size = 1024;  
	void *buffer = calloc(1,buffer_size);
	asn_enc_rval_t er;	
	
	Ngap_NGAP_PDU_t * pdu =  ngap_generate_ng_handover_cancel(inputBuf);
	if(!pdu)
		goto ERROR;

    asn_fprint(stderr, &asn_DEF_Ngap_NGAP_PDU, pdu);

    ret  =  check_NGAP_pdu_constraints(pdu);
    if(ret < 0) 
	{
		printf("ng hand over cancel  Constraint validation  failed\n");
		rc = RETURNerror;
		goto ERROR; 
	}

	//encode
	er = aper_encode_to_buffer(&asn_DEF_Ngap_NGAP_PDU, NULL, pdu, buffer, buffer_size);
	if(er.encoded < 0)
	{
		printf("ng hand over cancel encode failed,er.encoded:%d\n",er.encoded);
		rc = RETURNerror;
		goto ERROR; 
	}
  		 
	bstring msgBuf = blk2bstr(buffer, er.encoded);

    //decode
    ngap_amf_decode_pdu(&message, msgBuf);
	ngap_amf_handle_ng_pdu_handover_cancel(0,0, &message);


    //Free pdu
    ASN_STRUCT_FREE(asn_DEF_Ngap_NGAP_PDU, pdu);
	if(buffer)
	{
		free(buffer);
		buffer = NULL;
	}
	printf("pdu session  hand over cancel, finish--------------------\n\n");
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


