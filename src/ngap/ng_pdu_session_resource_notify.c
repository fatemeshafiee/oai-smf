#include  "3gpp_23.003.h"
#include  "Ngap_TAI.h"
#include  "Ngap_NR-CGI.h"

#include  "asn1_conversions.h"
#include  "conversions.h"


#include  "ng_pdu_session_resource_notify.h"

#include  "Ngap_InitiatingMessage.h"
#include  "Ngap_NGAP-PDU.h"
#include  "Ngap_ProtocolIE-Field.h"
#include  "Ngap_ProcedureCode.h"
#include  "Ngap_Criticality.h"
#include  "Ngap_PDUSessionResourceNotify.h"


#include  "Ngap_PDUSessionResourceNotifyItem.h"
#include  "Ngap_PDUSessionResourceReleasedListNot.h"
#include  "Ngap_PDUSessionResourceReleasedItemNot.h"


#include  "Ngap_UserLocationInformationNR.h"
#include  "Ngap_UserLocationInformation.h"

#include  "Ngap_TimeStamp.h"

#include  "common_defs.h"
#include  "common_types.h"
#include  "../common/ngap/ngap_common.h"
#include  "INTEGER.h"
#include  "asn_SEQUENCE_OF.h"
#include  "OCTET_STRING.h"

#define BUF_LEN   1024
Ngap_PDUSessionResourceNotifyIEs_t  *make_notify_RAN_UE_NGAP_ID(uint32_t rAN_UE_NGAP_ID)
{
	Ngap_PDUSessionResourceNotifyIEs_t *ie;
	ie = calloc(1, sizeof(Ngap_PDUSessionResourceNotifyIEs_t));

	ie->id = Ngap_ProtocolIE_ID_id_RAN_UE_NGAP_ID;
	ie->criticality = Ngap_Criticality_reject;
	ie->value.present = Ngap_PDUSessionResourceNotifyIEs__value_PR_RAN_UE_NGAP_ID;
	ie->value.choice.RAN_UE_NGAP_ID = rAN_UE_NGAP_ID ;

	printf("RAN_UE_NGAP_ID:0x%x",ie->value.choice.RAN_UE_NGAP_ID);
	return ie;
}

Ngap_PDUSessionResourceNotifyIEs_t  *make_notify_AMF_UE_NGAP_ID(uint64_t amf_UE_NGAP_ID)
{
    Ngap_PDUSessionResourceNotifyIEs_t *ie = NULL;
	ie = calloc(1, sizeof(Ngap_PDUSessionResourceNotifyIEs_t));
	
	ie->id = Ngap_ProtocolIE_ID_id_AMF_UE_NGAP_ID;
	ie->criticality = Ngap_Criticality_reject;
	ie->value.present = Ngap_PDUSessionResourceNotifyIEs__value_PR_AMF_UE_NGAP_ID;

	asn_ulong2INTEGER(&ie->value.choice.AMF_UE_NGAP_ID, amf_UE_NGAP_ID & AMF_UE_NGAP_ID_MASK_);
	
	size_t i  = 0;
	for(i ; i<ie->value.choice.AMF_UE_NGAP_ID.size;i++)
	{
	    printf("0x%x",ie->value.choice.AMF_UE_NGAP_ID.buf[i]);
	}
	return ie;
}

//Ngap_PDUSessionResourceNotifyItem_t
Ngap_PDUSessionResourceNotifyItem_t  *make_notify_PDUSessionResourceNotifyItem (
	long	         pDUSessionID,
	const char *	 pDUSRModifyNotifyTransfer)
{  
	Ngap_PDUSessionResourceNotifyItem_t  *item = NULL;
	item  = calloc(1, sizeof(Ngap_PDUSessionResourceNotifyItem_t));

	item->pDUSessionID =  pDUSessionID;
	OCTET_STRING_fromBuf (&item->pDUSessionResourceNotifyTransfer, pDUSRModifyNotifyTransfer, strlen(pDUSRModifyNotifyTransfer));

	printf("notifyItem, pDUSessionID:0x%x,transfer:%s\n", pDUSessionID, pDUSRModifyNotifyTransfer);

	return item;
}

//PDUSessionResourceNotifyList
Ngap_PDUSessionResourceNotifyIEs_t  * make_notify_PDUSessionResourceNotifyList()
{
	Ngap_PDUSessionResourceNotifyIEs_t *ie;
	ie = calloc(1, sizeof(Ngap_PDUSessionResourceNotifyIEs_t));
	
	ie->id            = Ngap_ProtocolIE_ID_id_PDUSessionResourceNotifyList;
	ie->criticality   = Ngap_Criticality_reject;
	ie->value.present = Ngap_PDUSessionResourceNotifyIEs__value_PR_PDUSessionResourceNotifyList;
	
    return ie;
}

//PDUSessionResourceFailedToModifyListModRes
Ngap_PDUSessionResourceReleasedItemNot_t *make_notify_PDUSessionResourceReleasedItemNot(
	const long  pDUSessionID, const char *pDUSessionResourceNotify)
{
    Ngap_PDUSessionResourceReleasedItemNot_t  *item = NULL;
    item =  calloc(1, sizeof(Ngap_PDUSessionResourceReleasedItemNot_t));
	
    item->pDUSessionID = pDUSessionID;
	OCTET_STRING_fromBuf(&item->pDUSessionResourceNotifyReleasedTransfer, pDUSessionResourceNotify, strlen(pDUSessionResourceNotify));

	printf("ItemNot_t, pDUSessionID:0x%x,transfer:%s\n", pDUSessionID, pDUSessionResourceNotify);
    return item;
}

Ngap_PDUSessionResourceNotifyIEs_t  * make_notify_PDUSessionResourceReleasedListNot()
{
	Ngap_PDUSessionResourceNotifyIEs_t *ie;
	ie = calloc(1, sizeof(Ngap_PDUSessionResourceNotifyIEs_t));
	
	ie->id = Ngap_ProtocolIE_ID_id_PDUSessionResourceReleasedListNot;
	ie->criticality = Ngap_Criticality_ignore;
	ie->value.present = Ngap_PDUSessionResourceNotifyIEs__value_PR_PDUSessionResourceReleasedListNot;
	
    return ie;
}

//UserLocationInformation
Ngap_PDUSessionResourceNotifyIEs_t *make_notify_UserLocationInformation()
{
	Ngap_PDUSessionResourceNotifyIEs_t *ie = NULL;
    ie  = calloc(1, sizeof(Ngap_PDUSessionResourceNotifyIEs_t));
	
	ie->id            = Ngap_ProtocolIE_ID_id_UserLocationInformation; 
	ie->criticality   = Ngap_Criticality_ignore;
	ie->value.present = Ngap_PDUSessionResourceNotifyIEs__value_PR_UserLocationInformation;

    return ie;
}

Ngap_UserLocationInformationNR_t * make_notify_UserLocationInformationNR()
{
	Ngap_UserLocationInformationNR_t * nr = NULL;
	nr =  calloc(1, sizeof(Ngap_UserLocationInformationNR_t));
	return nr;
}

void add_pdu_session_resource_notify_ie(Ngap_PDUSessionResourceNotify_t *ngapPDUSessionResourceNotify, Ngap_PDUSessionResourceNotifyIEs_t *ie) {
    int ret;
	ret = ASN_SEQUENCE_ADD(&ngapPDUSessionResourceNotify->protocolIEs.list, ie);
    if ( ret != 0 ) {
        fprintf(stderr, "Failed to add ie\n");
		return ;
    }
	return ;
}
Ngap_NGAP_PDU_t *  ngap_generate_ng_notify(const char *inputBuf)

{
    Ngap_NGAP_PDU_t * pdu = NULL;
	pdu = calloc(1, sizeof(Ngap_NGAP_PDU_t));
    
	pdu->present = Ngap_NGAP_PDU_PR_initiatingMessage;
	pdu->choice.initiatingMessage = calloc(1, sizeof(Ngap_InitiatingMessage_t));
	pdu->choice.initiatingMessage->procedureCode = Ngap_ProcedureCode_id_PDUSessionResourceNotify;
	pdu->choice.initiatingMessage->criticality   = Ngap_Criticality_ignore;
	pdu->choice.initiatingMessage->value.present = Ngap_InitiatingMessage__value_PR_PDUSessionResourceNotify;

    Ngap_PDUSessionResourceNotify_t *ngapPDUSessionResourceNotify = NULL;
	ngapPDUSessionResourceNotify  = &pdu->choice.initiatingMessage->value.choice.PDUSessionResourceNotify;
	
	Ngap_PDUSessionResourceNotifyIEs_t  *ie = NULL;

    //Ngap_AMF_UE_NGAP_ID_t
	uint64_t  amf_ue_ngap_id = 0x77;
	ie  = make_notify_AMF_UE_NGAP_ID(amf_ue_ngap_id);
    add_pdu_session_resource_notify_ie(ngapPDUSessionResourceNotify, ie);

	//Ngap_AMF_UE_NGAP_ID_t
    uint32_t  ran_ue_ngap_id = 0x78;
	ie  = make_notify_RAN_UE_NGAP_ID(ran_ue_ngap_id);
	add_pdu_session_resource_notify_ie(ngapPDUSessionResourceNotify, ie);
    
    //PDUSessionResourceNotifyList;
    Ngap_PDUSessionResourceNotifyItem_t  *notifyItem  = NULL;
	
    ie           =  make_notify_PDUSessionResourceNotifyList();
    notifyItem   =  make_notify_PDUSessionResourceNotifyItem(0x79, "test_notify_item");
	ASN_SEQUENCE_ADD(&ie->value.choice.PDUSessionResourceNotifyList.list, notifyItem);
	add_pdu_session_resource_notify_ie(ngapPDUSessionResourceNotify, ie);

   
    //PDUSessionResourceReleasedListNot;
    Ngap_PDUSessionResourceReleasedItemNot_t  *source_Release_Item = NULL;
    ie                  = make_notify_PDUSessionResourceReleasedListNot();
    source_Release_Item = make_notify_PDUSessionResourceReleasedItemNot(0x80, "test_source_release_item");
	ASN_SEQUENCE_ADD(&ie->value.choice.PDUSessionResourceReleasedListNot.list, source_Release_Item);
	add_pdu_session_resource_notify_ie(ngapPDUSessionResourceNotify, ie);
	

	//UserLocationInformation
	ie = make_notify_UserLocationInformation();
    //userLocationInformationEUTRA;
	//userLocationInformationNR;
	ie->value.choice.UserLocationInformation.present =  Ngap_UserLocationInformation_PR_userLocationInformationNR;

	Ngap_UserLocationInformationNR_t * nr = make_notify_UserLocationInformationNR();
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
	add_pdu_session_resource_notify_ie(ngapPDUSessionResourceNotify, ie);
	
    return pdu;
}

int
ngap_amf_handle_ng_pdu_session_resource_notify(
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
    Ngap_PDUSessionResourceNotify_t             *container = NULL;
    Ngap_PDUSessionResourceNotifyIEs_t          *ie = NULL;
    Ngap_PDUSessionResourceNotifyIEs_t          *ie_gnb_name = NULL;

    unsigned  long    amf_ue_ngap_id        = 0;
	uint32_t          ran_ue_ngap_id        = 0;

	long	  pDUSessionID = 0;
	char 	  *pDUSessionResourceNotifyTransfer = NULL;
	int       pDUSessionResourceNotifyTransfer_size  =  0;


    long	  pDUReleaseSessionID = 0;
	char 	  *pDUSessionResourceNotifyReleasedTransfer = NULL;
	int       pDUSessionResourceNotifyReleasedTransfer_size  =  0;

    DevAssert (pdu != NULL);
    //OAILOG_INFO(LOG_NGAP,"----------------------- DECODED NG SETUP RESPONSE NGAP MSG --------------------------\n");
    //asn_fprint(stdout, &asn_DEF_Ngap_NGAP_PDU, pdu);
    //OAILOG_INFO(LOG_NGAP,"----------------------- DECODED NG SETUP RESPONSE NGAP MSG --------------------------\n");

	container = &pdu->choice.initiatingMessage->value.choice.PDUSessionResourceNotify;
    
    //AMF_UE_NGAP_ID
    NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_PDUSessionResourceNotifyIEs_t, ie, container, Ngap_ProtocolIE_ID_id_AMF_UE_NGAP_ID, false);
    if (ie) 
	{  
	    asn_INTEGER2ulong(&ie->value.choice.AMF_UE_NGAP_ID, &amf_ue_ngap_id);
	    printf("amf_ue_ngap_id, 0x%x\n", amf_ue_ngap_id);
    }

    //Ngap_AMF_UE_NGAP_ID_t
    NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_PDUSessionResourceNotifyIEs_t, ie, container, Ngap_ProtocolIE_ID_id_RAN_UE_NGAP_ID, false);
    if (ie) 
	{  
	    ran_ue_ngap_id = ie->value.choice.RAN_UE_NGAP_ID;
	    printf("ran_ue_ngap_id, 0x%x\n", ran_ue_ngap_id);
    }

	
	//PDUSessionResourceNotifyList
	NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_PDUSessionResourceNotifyIEs_t, ie, container, Ngap_ProtocolIE_ID_id_PDUSessionResourceNotifyList, false);
    if (ie) 
	{ 
	    Ngap_PDUSessionResourceNotifyList_t	 *notify_container  =  &ie->value.choice.PDUSessionResourceNotifyList;
        for (i  = 0;i < notify_container->list.count; i++)
	    {
            Ngap_PDUSessionResourceNotifyItem_t *notifyIes_p = NULL;
            notifyIes_p = notify_container->list.array[i];
			
			if(!notifyIes_p)
			{
				  continue;
        	}

		    pDUSessionID                               = notifyIes_p->pDUSessionID;
	 	    pDUSessionResourceNotifyTransfer           = notifyIes_p->pDUSessionResourceNotifyTransfer.buf;
	        pDUSessionResourceNotifyTransfer_size      = notifyIes_p->pDUSessionResourceNotifyTransfer.size;

		    printf("NotifyItem, pDUSessionID:0x%x,transfer:%s\n", pDUSessionID, pDUSessionResourceNotifyTransfer);

		}
    }

	//PDUSessionResourceReleasedListNot
    NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_PDUSessionResourceNotifyIEs_t, ie, container, Ngap_ProtocolIE_ID_id_PDUSessionResourceReleasedListNot, false);
    if (ie) 
	{ 
	    Ngap_PDUSessionResourceReleasedListNot_t	 *source_release_container  =  &ie->value.choice.PDUSessionResourceReleasedListNot;
        for (i  = 0;i < source_release_container->list.count; i++)
	    {
            Ngap_PDUSessionResourceReleasedItemNot_t *source_releaseIes_p = NULL;
            source_releaseIes_p = source_release_container->list.array[i];
			
			if(!source_releaseIes_p)
		         continue;
        	
        	
		    pDUReleaseSessionID                            = source_releaseIes_p->pDUSessionID;
	 	    pDUSessionResourceNotifyReleasedTransfer       = source_releaseIes_p->pDUSessionResourceNotifyReleasedTransfer.buf;
	        pDUSessionResourceNotifyReleasedTransfer_size  = source_releaseIes_p->pDUSessionResourceNotifyReleasedTransfer.size;

	        printf("ItemNot_t, pDUSessionID:0x%x,transfer:%s\n", pDUSessionID, pDUSessionResourceNotifyReleasedTransfer);
		}
    }
	
	//UserLocationInformation
	NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_PDUSessionResourceNotifyIEs_t, ie, container, Ngap_ProtocolIE_ID_id_UserLocationInformation, false);
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
	
	return rc;
}

int  make_NGAP_PduSessionResourceNotify(const char *inputBuf, const char *OutputBuf)
{

    printf("pdu session  resource notify, start--------------------\n\n");

    int ret = 0;
	int rc  = RETURNok;
	const sctp_assoc_id_t assoc_id  = 0;
    const sctp_stream_id_t stream   = 0;
	Ngap_NGAP_PDU_t  message = {0};

	//wys:  1024 ?
	size_t buffer_size = 1024;  
	void *buffer = calloc(1,buffer_size);
	asn_enc_rval_t er;	
	
	Ngap_NGAP_PDU_t * pdu =  ngap_generate_ng_notify(inputBuf);
	if(!pdu)
		goto ERROR;

    asn_fprint(stderr, &asn_DEF_Ngap_NGAP_PDU, pdu);

    ret  =  check_NGAP_pdu_constraints(pdu);
    if(ret < 0) 
	{
		printf("ng notify Constraint validation  failed\n");
		rc = RETURNerror;
		goto ERROR; 
	}

	//encode
	er = aper_encode_to_buffer(&asn_DEF_Ngap_NGAP_PDU, NULL, pdu, buffer, buffer_size);
	if(er.encoded < 0)
	{
		printf("ng notify encode failed,er.encoded:%d\n",er.encoded);
		rc = RETURNerror;
		goto ERROR; 
	}
  		 
	bstring msgBuf = blk2bstr(buffer, er.encoded);

    //decode
    ngap_amf_decode_pdu(&message, msgBuf);
	ngap_amf_handle_ng_pdu_session_resource_notify(0,0, &message);


    //Free pdu
    ASN_STRUCT_FREE(asn_DEF_Ngap_NGAP_PDU, pdu);
	if(buffer)
	{
		free(buffer);
		buffer = NULL;
	}
	printf("pdu session  resource notify, finish--------------------\n\n");
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



