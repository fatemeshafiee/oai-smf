#include  "ng_pdu_handover_required.h"

#include  "Ngap_NGAP-PDU.h"
#include  "Ngap_ProtocolIE-Field.h"
#include  "Ngap_ProcedureCode.h"
#include  "Ngap_InitiatingMessage.h"

#include  "Ngap_Criticality.h"

#include  "Ngap_HandoverRequired.h"
#include  "Ngap_HandoverType.h"

#include  "Ngap_CauseRadioNetwork.h"
#include  "Ngap_DirectForwardingPathAvailability.h"

#include  "Ngap_PDUSessionResourceListHORqd.h"
#include  "Ngap_PDUSessionResourceItemHORqd.h"


#include  "Ngap_TargetID.h"

#include  "Ngap_TargetRANNodeID.h"
#include  "Ngap_TargeteNB-ID.h"
#include  "Ngap_ProtocolIE-SingleContainer.h"
#include  "Ngap_TAI.h"



#include  "common_defs.h"
#include  "common_types.h"
#include  "../common/ngap/ngap_common.h"



#include  "INTEGER.h"
#include  "asn_SEQUENCE_OF.h"
#include  "OCTET_STRING.h"

#define BUF_LEN   1024
Ngap_HandoverRequiredIEs_t  *make_handover_required_RAN_UE_NGAP_ID(uint32_t rAN_UE_NGAP_ID)
{
	Ngap_HandoverRequiredIEs_t *ie;
	ie                              = calloc(1, sizeof(Ngap_HandoverRequiredIEs_t));

	ie->id                          = Ngap_ProtocolIE_ID_id_RAN_UE_NGAP_ID;
	ie->criticality                 = Ngap_Criticality_reject;
	ie->value.present               = Ngap_HandoverRequiredIEs__value_PR_RAN_UE_NGAP_ID;
	ie->value.choice.RAN_UE_NGAP_ID = rAN_UE_NGAP_ID ;

	printf("RAN_UE_NGAP_ID:0x%x\n",ie->value.choice.RAN_UE_NGAP_ID);
	return ie;
}
Ngap_HandoverRequiredIEs_t  *make_handover_required_AMF_UE_NGAP_ID(uint64_t amf_UE_NGAP_ID)
{
    Ngap_HandoverRequiredIEs_t *ie = NULL;
	ie                = calloc(1, sizeof(Ngap_HandoverRequiredIEs_t));
	
	ie->id            = Ngap_ProtocolIE_ID_id_AMF_UE_NGAP_ID;
	ie->criticality   = Ngap_Criticality_reject;
	ie->value.present = Ngap_HandoverRequiredIEs__value_PR_AMF_UE_NGAP_ID;

	asn_ulong2INTEGER(&ie->value.choice.AMF_UE_NGAP_ID, amf_UE_NGAP_ID & AMF_UE_NGAP_ID_MASK_);
	
	printf("AMF_UE_NGAP_ID:0x%x\n",ie->value.choice.AMF_UE_NGAP_ID);
	return ie;
}

Ngap_HandoverRequiredIEs_t  *make_handover_required_HandoverType(const long handoverType)
{
	Ngap_HandoverRequiredIEs_t *ie = NULL;
	ie                             = calloc(1, sizeof(Ngap_HandoverRequiredIEs_t));
	
	ie->id                         = Ngap_ProtocolIE_ID_id_HandoverType;
	ie->criticality                = Ngap_Criticality_reject;
	ie->value.present              = Ngap_HandoverRequiredIEs__value_PR_HandoverType;
	
    ie->value.choice.HandoverType  = handoverType;
	printf("handoverType:0x%x\n",ie->value.choice.HandoverType);
	return ie;
}

Ngap_HandoverRequiredIEs_t  *make_handover_required_CauseRadioNetwork(const long radioNetwork)
{
	Ngap_HandoverRequiredIEs_t *ie = NULL;
	ie                                          = calloc(1, sizeof(Ngap_HandoverRequiredIEs_t));
	
	ie->id                                      = Ngap_ProtocolIE_ID_id_Cause;
	ie->criticality                             = Ngap_Criticality_ignore;
	ie->value.present                           = Ngap_HandoverRequiredIEs__value_PR_Cause;


    ie->value.choice.Cause.present              = Ngap_Cause_PR_radioNetwork;
    ie->value.choice.Cause.choice.radioNetwork  = radioNetwork;

	printf("radioNetwork:0x%x\n",ie->value.choice.Cause.choice.radioNetwork);
	return ie;
}

Ngap_HandoverRequiredIEs_t  * make_TargetID()
{
	Ngap_HandoverRequiredIEs_t *ie = NULL;
	ie											= calloc(1, sizeof(Ngap_HandoverRequiredIEs_t));
		
	ie->id										= Ngap_ProtocolIE_ID_id_TargetID;
	ie->criticality 							= Ngap_Criticality_reject;
	ie->value.present							= Ngap_HandoverRequiredIEs__value_PR_TargetID;

    return ie;
}
Ngap_HandoverRequiredIEs_t  *make_handover_required_DirectForwardingPathAvailability(const long DirectForwarding)
{
	Ngap_HandoverRequiredIEs_t *ie              = NULL;
	ie                                          = calloc(1, sizeof(Ngap_HandoverRequiredIEs_t));
	
	ie->id                                      = Ngap_ProtocolIE_ID_id_DirectForwardingPathAvailability;
	ie->criticality                             = Ngap_Criticality_ignore;
	ie->value.present                           = Ngap_HandoverRequiredIEs__value_PR_DirectForwardingPathAvailability;
	ie->value.choice.DirectForwardingPathAvailability = DirectForwarding;
    printf("DirectForwardingPathAvailability:0x%x\n",ie->value.choice.DirectForwardingPathAvailability);
	
	return ie;
}

Ngap_PDUSessionResourceItemHORqd_t *make_handover_required_PDUSessionResourceItemHORqd(const long psid, const char *transfer)
{
	Ngap_PDUSessionResourceItemHORqd_t *item    = NULL;
	item                                        = calloc(1, sizeof(Ngap_PDUSessionResourceItemHORqd_t));
    
	item->pDUSessionID =  psid;
	OCTET_STRING_fromBuf (&item->handoverRequiredTransfer, transfer, strlen(transfer));

    printf("psid:0x%x,transfer:%s\n",psid,transfer);

    return item;
}


Ngap_HandoverCancelIEs_t *make_handover_required_PDUSessionResourceListHORqd()
{
	
	Ngap_HandoverRequiredIEs_t *ie				= NULL;
	ie											= calloc(1, sizeof(Ngap_HandoverRequiredIEs_t));
		
	ie->id										= Ngap_ProtocolIE_ID_id_PDUSessionResourceListHORqd;
	ie->criticality 							= Ngap_Criticality_reject;
	ie->value.present							= Ngap_HandoverRequiredIEs__value_PR_PDUSessionResourceListHORqd;

	return ie;
}
	
void add_pdu_handover_required_ie(Ngap_HandoverRequired_t *ngapPDUHandoverRequired, Ngap_HandoverRequiredIEs_t *ie) {
    int ret;
	ret = ASN_SEQUENCE_ADD(&ngapPDUHandoverRequired->protocolIEs.list, ie);
    if ( ret != 0 ) {
        fprintf(stderr, "Failed to add ie\n");
		return ;
    }
	return ;
}
Ngap_NGAP_PDU_t *  ngap_generate_ng_handover_required(const char *inputBuf)

{
    Ngap_NGAP_PDU_t * pdu = NULL;
	pdu = calloc(1, sizeof(Ngap_NGAP_PDU_t));
    
	pdu->present = Ngap_NGAP_PDU_PR_initiatingMessage;
	pdu->choice.initiatingMessage = calloc(1, sizeof(Ngap_InitiatingMessage_t));
	pdu->choice.initiatingMessage->procedureCode = Ngap_ProcedureCode_id_HandoverPreparation;
	                                               
	pdu->choice.initiatingMessage->criticality   = Ngap_Criticality_reject;
	pdu->choice.initiatingMessage->value.present = Ngap_InitiatingMessage__value_PR_HandoverRequired;

    Ngap_HandoverRequired_t *ngapPDUHandoverRequired = NULL;
	ngapPDUHandoverRequired = &pdu->choice.initiatingMessage->value.choice.HandoverRequired;
	
	Ngap_HandoverRequiredIEs_t  *ie = NULL;

    //Ngap_AMF_UE_NGAP_ID_t
	uint64_t  amf_ue_ngap_id = 0x80;
	ie  = make_handover_required_AMF_UE_NGAP_ID(amf_ue_ngap_id);
    add_pdu_handover_required_ie(ngapPDUHandoverRequired, ie);

	//Ngap_AMF_UE_NGAP_ID_t
    uint32_t  ran_ue_ngap_id = 0x81;
	ie  = make_handover_required_RAN_UE_NGAP_ID(ran_ue_ngap_id);
	add_pdu_handover_required_ie(ngapPDUHandoverRequired, ie);

    
    //Ngap_HandoverType
    ie = make_handover_required_HandoverType(Ngap_HandoverType_intra5gs);
	add_pdu_handover_required_ie(ngapPDUHandoverRequired, ie);

	//Cause:CauseRadioNetwork
	ie = make_handover_required_CauseRadioNetwork(Ngap_CauseRadioNetwork_unspecified);
    add_pdu_handover_required_ie(ngapPDUHandoverRequired, ie);


	//TargetID
	ie =  make_TargetID();
	ie->value.choice.TargetID.present = Ngap_TargetID_PR_targetRANNodeID;
	
    Ngap_TargetRANNodeID_t  * pTargetRANodeID  = NULL;
	pTargetRANodeID  = calloc(1, sizeof(Ngap_TargetRANNodeID_t));
	ie->value.choice.TargetID.choice.targetRANNodeID = pTargetRANodeID;

	//Ngap_GlobalRANNodeID_t	 globalRANNodeID;
    pTargetRANodeID->globalRANNodeID.present  = Ngap_GlobalRANNodeID_PR_globalGNB_ID;
	
	Ngap_GlobalGNB_ID_t   *pGlobalGNB_ID = NULL;
	pGlobalGNB_ID = calloc(1, sizeof(Ngap_GlobalGNB_ID_t));
    pTargetRANodeID->globalRANNodeID.choice.globalGNB_ID  = pGlobalGNB_ID;

    //Ngap_PLMNIdentity_t	 pLMNIdentity;
    char global_pLMNIdentity[3] = {0x00,0x01,0x02};
	OCTET_STRING_fromBuf(&pGlobalGNB_ID->pLMNIdentity, (const char*)global_pLMNIdentity, sizeof(global_pLMNIdentity));
    printf("tAI.pLMNIdentity:0x%x,0x%x,0x%x,\n",
	pGlobalGNB_ID->pLMNIdentity.buf[0],pGlobalGNB_ID->pLMNIdentity.buf[1],pGlobalGNB_ID->pLMNIdentity.buf[2]);
  
	
	//Ngap_GNB_ID_t	 gNB_ID;
	pGlobalGNB_ID->gNB_ID.present =  Ngap_GNB_ID_PR_gNB_ID;

	//CellIdentity;
	char  cellIdentity[4] = {0x00,0x01,0x02,0x03};   //36bits
	pGlobalGNB_ID->gNB_ID.choice.gNB_ID.buf = calloc(4, sizeof(uint8_t));
	
	pGlobalGNB_ID->gNB_ID.choice.gNB_ID.size = 4;
	memcpy(pGlobalGNB_ID->gNB_ID.choice.gNB_ID.buf, &cellIdentity, 4);
	//pGlobalGNB_ID->gNB_ID.choice.gNB_ID.bits_unused = 0x04;


    printf("pGlobalGNB_ID->gNB_ID:0x%x,0x%x,0x%x\n", 
	pGlobalGNB_ID->gNB_ID.choice.gNB_ID.buf[0],pGlobalGNB_ID->gNB_ID.choice.gNB_ID.buf[1],
    pGlobalGNB_ID->gNB_ID.choice.gNB_ID.buf[2]);

	
	//Ngap_TAI_t	 selectedTAI;

	//pLMNIdentity;
    char tai_pLMNIdentity[3] = {0x00,0x01,0x02};
	OCTET_STRING_fromBuf(&pTargetRANodeID->selectedTAI.pLMNIdentity, (const char*)tai_pLMNIdentity, sizeof(tai_pLMNIdentity));
    printf("tAI.pLMNIdentity:0x%x,0x%x,0x%x,\n",
	pTargetRANodeID->selectedTAI.pLMNIdentity.buf[0],pTargetRANodeID->selectedTAI.pLMNIdentity.buf[1],pTargetRANodeID->selectedTAI.pLMNIdentity.buf[2]);
  
	//tAC;
	char tai_tAC[3] = {0x00,0x01,0x02};
	OCTET_STRING_fromBuf(&pTargetRANodeID->selectedTAI.tAC, (const char*)tai_tAC, sizeof(tai_tAC));
	
	printf("tAI.tAC:0x%x,0x%x,0x%x,\n",
	pTargetRANodeID->selectedTAI.tAC.buf[0],pTargetRANodeID->selectedTAI.tAC.buf[1],pTargetRANodeID->selectedTAI.tAC.buf[2]);
	
    add_pdu_handover_required_ie(ngapPDUHandoverRequired, ie);
    
	
    //DirectForwardingPathAvailability
    ie  = make_handover_required_DirectForwardingPathAvailability(Ngap_DirectForwardingPathAvailability_direct_path_available);
	add_pdu_handover_required_ie(ngapPDUHandoverRequired, ie);


	//PDUSessionResourceListHORqd
	Ngap_PDUSessionResourceItemHORqd_t   *sourceItem = NULL;  
	ie         =  make_handover_required_PDUSessionResourceListHORqd();
    sourceItem =  make_handover_required_PDUSessionResourceItemHORqd(0x01, "test_resource_item");
	ASN_SEQUENCE_ADD(&ie->value.choice.PDUSessionResourceListHORqd.list, sourceItem);
	add_pdu_handover_required_ie(ngapPDUHandoverRequired, ie);
	
	//SourceToTarget_TransparentContainer
	 
    return pdu;
}


int
ngap_amf_handle_ng_pdu_handover_required(
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
    Ngap_HandoverRequired_t                  *container = NULL;
    Ngap_HandoverRequiredIEs_t               *ie = NULL;
    Ngap_HandoverRequiredIEs_t               *ie_gnb_name = NULL;

    unsigned  long    amf_ue_ngap_id        = 0;
	uint32_t          ran_ue_ngap_id        = 0;
    uint32_t          handoverType          = 0;
	uint32_t          radioNetwork          = 0;
	uint32_t          DirectForwardingPathAvailability = 0;
	
	uint32_t    pDUSessionid   = 0;
	char       *pDUSessionTransfer  = NULL;
	
	uint16_t                                mcc = 0;
    uint16_t                                mnc = 0;
    uint16_t                                mnc_len = 0;
	

    DevAssert (pdu != NULL);
    //OAILOG_INFO(LOG_NGAP,"----------------------- DECODED NG SETUP REQUEST NGAP MSG --------------------------\n");
    //asn_fprint(stdout, &asn_DEF_Ngap_NGAP_PDU, pdu);
    //OAILOG_INFO(LOG_NGAP,"----------------------- DECODED NG SETUP REQUEST NGAP MSG --------------------------\n");

	container = &pdu->choice.initiatingMessage->value.choice.HandoverRequired;
    
    //AMF_UE_NGAP_ID
    NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_HandoverRequiredIEs_t, ie, container, Ngap_ProtocolIE_ID_id_AMF_UE_NGAP_ID, false);
    if (ie) 
	{  
	   asn_INTEGER2ulong(&ie->value.choice.AMF_UE_NGAP_ID, &amf_ue_ngap_id);
	   printf("amf_ue_ngap_id, 0x%x\n", amf_ue_ngap_id);
    }

    //Ngap_AMF_UE_NGAP_ID_t
    NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_HandoverRequiredIEs_t, ie, container, Ngap_ProtocolIE_ID_id_RAN_UE_NGAP_ID, false);
    if (ie) 
	{  
	   ran_ue_ngap_id = ie->value.choice.RAN_UE_NGAP_ID;
	   printf("ran_ue_ngap_id, 0x%x\n", ran_ue_ngap_id);
    }

    //Ngap_HandoverType
    NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_HandoverRequiredIEs_t, ie, container, Ngap_ProtocolIE_ID_id_HandoverType, false);
    if (ie) 
	{  
	   handoverType = ie->value.choice.HandoverType;
	   printf("HandoverType, 0x%x\n", handoverType);
    }

    //cause
	NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_HandoverRequiredIEs_t, ie, container, Ngap_ProtocolIE_ID_id_Cause, false);
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
	    }
	}

     //target_ID
	NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_HandoverRequiredIEs_t, ie, container, Ngap_ProtocolIE_ID_id_TargetID, false);
	if (ie) 
	{ 
		Ngap_TargetID_t	 *pTargetID = &ie->value.choice.TargetID;
		if(pTargetID)
		{
        	switch(pTargetID->present)
        	{
            	case Ngap_TargetID_PR_targetRANNodeID:
				{
					Ngap_TargetRANNodeID_t  *pTargetRANNodeID = pTargetID->choice.targetRANNodeID;
					if(pTargetRANNodeID)
					{
                        switch(pTargetRANNodeID->globalRANNodeID.present)
                        {
	                        case Ngap_GlobalRANNodeID_PR_globalGNB_ID:
							{
								Ngap_GlobalGNB_ID_t  *pGlobalGNB_ID  = pTargetRANNodeID->globalRANNodeID.choice.globalGNB_ID;
								if(pGlobalGNB_ID)
								{
									 const Ngap_PLMNIdentity_t * const plmn = &pGlobalGNB_ID->pLMNIdentity;
                                     DevAssert (plmn != NULL);
                                     TBCD_TO_MCC_MNC (plmn, mcc, mnc, mnc_len);
			   
                                     printf("pLMNIdentity, mcc:0x%x,mnc:0x%x,mnc_len:0x%x\n",  mcc, mnc, mnc_len);
			   
									
	                                 uint32_t gNB_ID = 0;
									 gNB_ID  = BIT_STRING_to_uint32(&pGlobalGNB_ID->gNB_ID.choice.gNB_ID);  
									 printf("gnt_id:0x%x\n", gNB_ID);
								}

                                
							    //Tai
		                        const Ngap_TAI_t * const  tAI = &pTargetRANNodeID->selectedTAI;
								if(tAI)
								{
	                                nr_tai_t         nr_tai = {.plmn = {0}, .tac = INVALID_TAC};
						            //TAC
						            DevAssert(tAI->tAC.size == 3);
						            nr_tai.tac = asn1str_to_u24(&tAI->tAC);
									
									printf("tAI->tAC:0x%x,0x%x,0x%x\n", 
									tAI->tAC.buf[0],tAI->tAC.buf[1],tAI->tAC.buf[2]);
								  
						             //pLMNIdentity
						            DevAssert (tAI->pLMNIdentity.size == 3);
						            TBCD_TO_PLMN_T(&tAI->pLMNIdentity, &nr_tai.plmn);

									printf("tAI->pLMNIdentity:0x%x,0x%x,0x%x\n", 
									tAI->pLMNIdentity.buf[0],tAI->pLMNIdentity.buf[1],tAI->pLMNIdentity.buf[2]);
								}
								
							}
							break;
		                    case Ngap_GlobalRANNodeID_PR_globalNgENB_ID:
		                    {
							}
							break;
		                    case Ngap_GlobalRANNodeID_PR_globalN3IWF_ID:
							{
							}
							break;
							default:
					        	printf("dont't know GlobalRANNodeID present:%d\n",pTargetID->present);
				            break;
						}
					}
				}
				break;
				case Ngap_TargetID_PR_targeteNB_ID:
				{
				}
				break;
				default:
					printf("dont't know TargetID present:%d\n",pTargetID->present);
				break;
				
			}
		}
	               
	}

    NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_HandoverRequiredIEs_t, ie, container, Ngap_ProtocolIE_ID_id_DirectForwardingPathAvailability, false);
	if (ie) 
	{
    	DirectForwardingPathAvailability = ie->value.choice.DirectForwardingPathAvailability;
	    printf("DirectForwardingPathAvailability, 0x%x\n", DirectForwardingPathAvailability);
	}

    NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_HandoverRequiredIEs_t, ie, container, Ngap_ProtocolIE_ID_id_PDUSessionResourceListHORqd, false);
	if (ie) 
	{
    	
		Ngap_PDUSessionResourceListHORqd_t	 *resourceListHORqd_container  =	&ie->value.choice.PDUSessionResourceListHORqd;
		for (i	= 0;i < resourceListHORqd_container->list.count; i++)
		{
			Ngap_PDUSessionResourceItemHORqd_t *resourceItemHIes_p = NULL;
			resourceItemHIes_p = resourceListHORqd_container->list.array[i];
					
			if(!resourceItemHIes_p)
			{
				continue;
			}
	
			pDUSessionid		   = resourceItemHIes_p->pDUSessionID;
			pDUSessionTransfer	   = resourceItemHIes_p->handoverRequiredTransfer.buf;
			
			printf("ResourceItem, pDUSessionID:0x%x,transfer:%s\n", pDUSessionid, pDUSessionTransfer);
	     }
	}
	return rc;
}


int  make_NGAP_PduHandOverRequired(const char *inputBuf, const char *OutputBuf)
{

    printf("pdu session hand over required, start--------------------\n\n");

    int ret = 0;
	int rc  = RETURNok;
	const sctp_assoc_id_t assoc_id  = 0;
    const sctp_stream_id_t stream   = 0;
	Ngap_NGAP_PDU_t  message = {0};

	//wys:  1024 ?
	size_t buffer_size = 1024;  
	void *buffer = calloc(1,buffer_size);
	asn_enc_rval_t er;	
	
	Ngap_NGAP_PDU_t * pdu =  ngap_generate_ng_handover_required(inputBuf);
	if(!pdu)
		goto ERROR;

    asn_fprint(stderr, &asn_DEF_Ngap_NGAP_PDU, pdu);

    ret  =  check_NGAP_pdu_constraints(pdu);
    if(ret < 0) 
	{
		printf("ng hand over required  Constraint validation  failed\n");
		rc = RETURNerror;
		goto ERROR; 
	}

	//encode
	er = aper_encode_to_buffer(&asn_DEF_Ngap_NGAP_PDU, NULL, pdu, buffer, buffer_size);
	if(er.encoded < 0)
	{
		printf("ng hand over required encode failed,er.encoded:%d\n",er.encoded);
		rc = RETURNerror;
		goto ERROR; 
	}
  		 
	bstring msgBuf = blk2bstr(buffer, er.encoded);

    //decode
    ngap_amf_decode_pdu(&message, msgBuf);
	ngap_amf_handle_ng_pdu_handover_required(0,0, &message);


    //Free pdu
    ASN_STRUCT_FREE(asn_DEF_Ngap_NGAP_PDU, pdu);
	if(buffer)
	{
		free(buffer);
		buffer = NULL;
	}
	printf("pdu session  hand over required, finish--------------------\n\n");
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


