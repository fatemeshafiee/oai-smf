#include  "3gpp_23.003.h"
#include  "Ngap_TAI.h"
#include  "Ngap_NR-CGI.h"

#include  "asn1_conversions.h"
#include  "conversions.h"

#include  "ng_pdu_path_switch_request.h"
#include  "Ngap_PathSwitchRequest.h"

#include  "Ngap_HandoverNotify.h"

#include  "Ngap_InitiatingMessage.h"
#include  "Ngap_NGAP-PDU.h"
#include  "Ngap_ProtocolIE-Field.h"
#include  "Ngap_ProcedureCode.h"
#include  "Ngap_Criticality.h"

#include  "Ngap_UserLocationInformationNR.h"
#include  "Ngap_UserLocationInformation.h"

#include  "Ngap_PDUSessionResourceToBeSwitchedDLList.h"
#include  "Ngap_PDUSessionResourceToBeSwitchedDLItem.h"

#include  "Ngap_PDUSessionResourceFailedToSetupListPSReq.h"
#include  "Ngap_PDUSessionResourceFailedToSetupItemPSReq.h"

#include  "Ngap_TimeStamp.h"

#include  "common_defs.h"
#include  "common_types.h"
#include  "../common/ngap/ngap_common.h"
#include  "INTEGER.h"
#include  "asn_SEQUENCE_OF.h"
#include  "OCTET_STRING.h"

#define BUF_LEN   1024
Ngap_PathSwitchRequestIEs_t  *make_path_sw_req_RAN_UE_NGAP_ID(uint32_t rAN_UE_NGAP_ID)
{
	Ngap_PathSwitchRequestIEs_t *ie = NULL;
	ie = calloc(1, sizeof(Ngap_PathSwitchRequestIEs_t));

	ie->id                          = Ngap_ProtocolIE_ID_id_RAN_UE_NGAP_ID;
	ie->criticality                 = Ngap_Criticality_reject;
	ie->value.present               = Ngap_PathSwitchRequestIEs__value_PR_RAN_UE_NGAP_ID;
	ie->value.choice.RAN_UE_NGAP_ID = rAN_UE_NGAP_ID ;

	printf("RAN_UE_NGAP_ID:0x%x\n",ie->value.choice.RAN_UE_NGAP_ID);
	return ie;
}

//AMF_UE_NGAP_ID
Ngap_PathSwitchRequestIEs_t  *make_path_sw_req_SourceAMF_UE_NGAP_ID(uint64_t amf_UE_NGAP_ID)
{
    Ngap_PathSwitchRequestIEs_t *ie = NULL;
	ie                = calloc(1, sizeof(Ngap_PathSwitchRequestIEs_t));
	
	ie->id            = Ngap_ProtocolIE_ID_id_SourceAMF_UE_NGAP_ID;
	ie->criticality   = Ngap_Criticality_reject;
	ie->value.present = Ngap_PathSwitchRequestIEs__value_PR_AMF_UE_NGAP_ID;

	asn_ulong2INTEGER(&ie->value.choice.AMF_UE_NGAP_ID, amf_UE_NGAP_ID & AMF_UE_NGAP_ID_MASK_);
	
	printf("AMF_UE_NGAP_ID:0x%x\n",ie->value.choice.AMF_UE_NGAP_ID);

	return ie;
}

//UserLocationInformation
Ngap_PathSwitchRequestIEs_t *make_path_sw_req_UserLocationInformation()
{
	Ngap_PathSwitchRequestIEs_t *ie = NULL;
    ie  = calloc(1, sizeof(Ngap_PathSwitchRequestIEs_t));
	
	ie->id            = Ngap_ProtocolIE_ID_id_UserLocationInformation; 
	ie->criticality   = Ngap_Criticality_ignore;
	ie->value.present = Ngap_PathSwitchRequestIEs__value_PR_UserLocationInformation;

    return ie;
}
Ngap_UserLocationInformationNR_t * make_path_sw_req_UserLocationInformationNR()
{
	Ngap_UserLocationInformationNR_t * nr = NULL;
	nr =  calloc(1, sizeof(Ngap_UserLocationInformationNR_t));
	return nr;
}


Ngap_PathSwitchRequestIEs_t *make_path_sw_req_UESecurityCapabilities()
{
	Ngap_PathSwitchRequestIEs_t *ie = NULL;
    ie  = calloc(1, sizeof(Ngap_PathSwitchRequestIEs_t));
	
	ie->id            = Ngap_ProtocolIE_ID_id_UESecurityCapabilities; 
	ie->criticality   = Ngap_Criticality_ignore;
	ie->value.present = Ngap_PathSwitchRequestIEs__value_PR_UESecurityCapabilities;

    return ie;
}

Ngap_PDUSessionResourceToBeSwitchedDLItem_t *make_path_sw_req_PDUSessionResourceToBeSwitchedDLItem(
const long  pDUSessionID,  
const char *pDUTransfer)
{
    Ngap_PDUSessionResourceToBeSwitchedDLItem_t  *item = NULL;
    item =  calloc(1, sizeof(Ngap_PDUSessionResourceToBeSwitchedDLItem_t));
	
    item->pDUSessionID = pDUSessionID;
	OCTET_STRING_fromBuf(&item->pathSwitchRequestTransfer, pDUTransfer,strlen(pDUTransfer));
		
	printf("AdmittedItem,pDUSessionID:0x%x,Transfer:%s\n", item->pDUSessionID,item->pathSwitchRequestTransfer.buf);
	
    return item;
}

Ngap_PathSwitchRequestIEs_t  *make_path_sw_req_PDUSessionResourceToBeSwitchedDLList()
{
    Ngap_PathSwitchRequestIEs_t *ie = NULL;
	ie = calloc(1, sizeof(Ngap_PathSwitchRequestIEs_t));
	
	ie->id            = Ngap_ProtocolIE_ID_id_PDUSessionResourceToBeSwitchedDLList;
	ie->criticality   = Ngap_Criticality_ignore;
	ie->value.present = Ngap_PathSwitchRequestIEs__value_PR_PDUSessionResourceToBeSwitchedDLList;
	
	return ie;
}


Ngap_PDUSessionResourceFailedToSetupItemPSReq_t *make_path_sw_req_PDUSessionResourceFailedToSetupItemPSReq(
const long  pDUSessionID,  
const char *pDUTransfer)
{
    Ngap_PDUSessionResourceFailedToSetupItemPSReq_t  *item = NULL;
    item =  calloc(1, sizeof(Ngap_PDUSessionResourceFailedToSetupItemPSReq_t));
	
    item->pDUSessionID = pDUSessionID;
	OCTET_STRING_fromBuf(&item->pathSwitchRequestSetupFailedTransfer, pDUTransfer,strlen(pDUTransfer));
		
	printf("failedItem,pDUSessionID:0x%x,Transfer:%s\n", item->pDUSessionID,item->pathSwitchRequestSetupFailedTransfer.buf);
	
    return item;
}

Ngap_PathSwitchRequestIEs_t  *make_pdu_path_sw_req_PDUSessionResourceFailedToSetupListPSReq()
{
    Ngap_PathSwitchRequestIEs_t *ie = NULL;
	ie = calloc(1, sizeof(Ngap_PathSwitchRequestIEs_t));
	
	ie->id            = Ngap_ProtocolIE_ID_id_PDUSessionResourceFailedToSetupListPSReq;
	ie->criticality   = Ngap_Criticality_ignore;
	ie->value.present = Ngap_PathSwitchRequestIEs__value_PR_PDUSessionResourceFailedToSetupListPSReq;
	
	return ie;
}


void add_pdu_path_sw_req_ie(Ngap_PathSwitchRequest_t *ngapPathSwitchRequest, Ngap_PathSwitchRequestIEs_t *ie) {
    int ret;
	ret = ASN_SEQUENCE_ADD(&ngapPathSwitchRequest->protocolIEs.list, ie);
    if ( ret != 0 ) {
        fprintf(stderr, "Failed to add ie\n");
		return ;
    }
	return ;
}
Ngap_NGAP_PDU_t *  ngap_generate_ng_path_sw_req(const char *inputBuf)

{
    
    Ngap_NGAP_PDU_t * pdu = NULL;
	pdu = calloc(1, sizeof(Ngap_NGAP_PDU_t));
    
	pdu->present                                 = Ngap_NGAP_PDU_PR_initiatingMessage;
	pdu->choice.initiatingMessage                = calloc(1, sizeof(Ngap_InitiatingMessage_t));
	pdu->choice.initiatingMessage->procedureCode = Ngap_ProcedureCode_id_PathSwitchRequest;
	pdu->choice.initiatingMessage->criticality   = Ngap_Criticality_reject;
	pdu->choice.initiatingMessage->value.present = Ngap_InitiatingMessage__value_PR_PathSwitchRequest;

    Ngap_PathSwitchRequest_t *ngapPathSwitchRequest = NULL;
	ngapPathSwitchRequest  = &pdu->choice.initiatingMessage->value.choice.PathSwitchRequest;
	
	Ngap_PathSwitchRequestIEs_t  *ie = NULL;

	//RAN_UE_NGAP_ID
    uint32_t  ran_ue_ngap_id = 0x76;
	ie  = make_path_sw_req_RAN_UE_NGAP_ID(ran_ue_ngap_id);
	add_pdu_path_sw_req_ie(ngapPathSwitchRequest, ie);
   
	//AMF_UE_NGAP_ID
	uint64_t  amf_ue_ngap_id = 0x80;
	ie  = make_path_sw_req_SourceAMF_UE_NGAP_ID(amf_ue_ngap_id);
    add_pdu_path_sw_req_ie(ngapPathSwitchRequest, ie);
   

	//UserLocationInformation
	ie = make_path_sw_req_UserLocationInformation();
    //userLocationInformationEUTRA;
	//userLocationInformationNR;
	ie->value.choice.UserLocationInformation.present =  Ngap_UserLocationInformation_PR_userLocationInformationNR;

	Ngap_UserLocationInformationNR_t * nr = make_path_sw_req_UserLocationInformationNR();
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
	add_pdu_path_sw_req_ie(ngapPathSwitchRequest, ie);


    //UESecurityCapabilities;
    ie  = make_path_sw_req_UESecurityCapabilities();
    
	//nRencryptionAlgorithms;
	char  nRencryptionAlgorithms[2] = {0x00,0x01};
	ie->value.choice.UESecurityCapabilities.nRencryptionAlgorithms.buf = calloc(2, sizeof(uint8_t));
    ie->value.choice.UESecurityCapabilities.nRencryptionAlgorithms.size = 2;
	memcpy(ie->value.choice.UESecurityCapabilities.nRencryptionAlgorithms.buf , &nRencryptionAlgorithms, 2);
	ie->value.choice.UESecurityCapabilities.nRencryptionAlgorithms.bits_unused = 0;
    
	printf("nRencryptionAlgorithms:0x%x,0x%x\n", 
	ie->value.choice.UESecurityCapabilities.nRencryptionAlgorithms.buf[0],ie->value.choice.UESecurityCapabilities.nRencryptionAlgorithms.buf[1]);
	
	//nRintegrityProtectionAlgorithms;
	char  nRintegrityProtectionAlgorithms[2] = {0x00,0x00};
	ie->value.choice.UESecurityCapabilities.nRintegrityProtectionAlgorithms.buf = calloc(2, sizeof(uint8_t));
    ie->value.choice.UESecurityCapabilities.nRintegrityProtectionAlgorithms.size = 2;
	memcpy(ie->value.choice.UESecurityCapabilities.nRintegrityProtectionAlgorithms.buf , &nRintegrityProtectionAlgorithms, 2);
	ie->value.choice.UESecurityCapabilities.nRintegrityProtectionAlgorithms.bits_unused = 0;

    printf("nRintegrityProtectionAlgorithms:0x%x,0x%x\n", 
	ie->value.choice.UESecurityCapabilities.nRintegrityProtectionAlgorithms.buf[0],ie->value.choice.UESecurityCapabilities.nRintegrityProtectionAlgorithms.buf[1]);
	
	
	//eUTRAencryptionAlgorithms;
	char  eUTRAencryptionAlgorithms[2] = {0x00,0x01};
	ie->value.choice.UESecurityCapabilities.eUTRAencryptionAlgorithms.buf = calloc(2, sizeof(uint8_t));
    ie->value.choice.UESecurityCapabilities.eUTRAencryptionAlgorithms.size = 2;
	memcpy(ie->value.choice.UESecurityCapabilities.eUTRAencryptionAlgorithms.buf , &eUTRAencryptionAlgorithms, 2);
	ie->value.choice.UESecurityCapabilities.eUTRAencryptionAlgorithms.bits_unused = 0;
	printf("eUTRAencryptionAlgorithms:0x%x,0x%x\n", 
	ie->value.choice.UESecurityCapabilities.eUTRAencryptionAlgorithms.buf[0],ie->value.choice.UESecurityCapabilities.eUTRAencryptionAlgorithms.buf[1]);
	
	
	//eUTRAintegrityProtectionAlgorithms
	char  eUTRAintegrityProtectionAlgorithms[2] = {0x00,0x01};
	ie->value.choice.UESecurityCapabilities.eUTRAintegrityProtectionAlgorithms.buf = calloc(2, sizeof(uint8_t));
    ie->value.choice.UESecurityCapabilities.eUTRAintegrityProtectionAlgorithms.size = 2;
	memcpy(ie->value.choice.UESecurityCapabilities.eUTRAintegrityProtectionAlgorithms.buf , &eUTRAintegrityProtectionAlgorithms, 2);
	ie->value.choice.UESecurityCapabilities.eUTRAintegrityProtectionAlgorithms.bits_unused = 0;
	printf("eUTRAintegrityProtectionAlgorithms:0x%x,0x%x\n", 
	ie->value.choice.UESecurityCapabilities.eUTRAintegrityProtectionAlgorithms.buf[0],ie->value.choice.UESecurityCapabilities.eUTRAintegrityProtectionAlgorithms.buf[1]);
	
	add_pdu_path_sw_req_ie(ngapPathSwitchRequest, ie);

	//PDUSessionResourceToBeSwitchedDLList
	Ngap_PDUSessionResourceToBeSwitchedDLItem_t      *pSwitchedDLItem = NULL;
	ie = make_path_sw_req_PDUSessionResourceToBeSwitchedDLList();
	pSwitchedDLItem  = make_path_sw_req_PDUSessionResourceToBeSwitchedDLItem(0x80,"test_sw_dl");
	ASN_SEQUENCE_ADD(&ie->value.choice.PDUSessionResourceToBeSwitchedDLList.list, pSwitchedDLItem);
	add_pdu_path_sw_req_ie(ngapPathSwitchRequest, ie);
	
    //Ngap_PDUSessionResourceFailedToSetupListPSReq_t	 PDUSessionResourceFailedToSetupListPSReq;
    Ngap_PDUSessionResourceFailedToSetupItemPSReq_t  *failedItem = NULL;
	ie = make_pdu_path_sw_req_PDUSessionResourceFailedToSetupListPSReq();
	failedItem  = make_path_sw_req_PDUSessionResourceFailedToSetupItemPSReq(0x80,"test_failed_dl");
	ASN_SEQUENCE_ADD(&ie->value.choice.PDUSessionResourceFailedToSetupListPSReq.list, failedItem);
	add_pdu_path_sw_req_ie(ngapPathSwitchRequest, ie);
	
    return pdu;
}

int
ngap_amf_handle_ng_pdu_path_sw_req(
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
    Ngap_PathSwitchRequest_t             *container = NULL;
    Ngap_PathSwitchRequestIEs_t          *ie = NULL;
    Ngap_PathSwitchRequestIEs_t          *ie_gnb_name = NULL;

    unsigned  long    amf_ue_ngap_id        = 0;
	uint32_t          ran_ue_ngap_id        = 0;



    DevAssert (pdu != NULL);
    //OAILOG_INFO(LOG_NGAP,"----------------------- DECODED NG SETUP RESPONSE NGAP MSG --------------------------\n");
    //asn_fprint(stdout, &asn_DEF_Ngap_NGAP_PDU, pdu);
    //OAILOG_INFO(LOG_NGAP,"----------------------- DECODED NG SETUP RESPONSE NGAP MSG --------------------------\n");

	container = &pdu->choice.initiatingMessage->value.choice.PathSwitchRequest;
    
    //AMF_UE_NGAP_ID
    NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_PathSwitchRequestIEs_t, ie, container, Ngap_ProtocolIE_ID_id_SourceAMF_UE_NGAP_ID, false);
    if (ie) 
	{  
	    asn_INTEGER2ulong(&ie->value.choice.AMF_UE_NGAP_ID, &amf_ue_ngap_id);
	    printf("amf_ue_ngap_id, 0x%x\n", amf_ue_ngap_id);
    }

    //RAN_UE_NGAP_ID
    NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_PathSwitchRequestIEs_t, ie, container, Ngap_ProtocolIE_ID_id_RAN_UE_NGAP_ID, false);
    if (ie) 
	{  
	    ran_ue_ngap_id = ie->value.choice.RAN_UE_NGAP_ID;
	    printf("ran_ue_ngap_id, 0x%x\n", ran_ue_ngap_id);
    }

	//UserLocationInformation
	NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_PathSwitchRequestIEs_t, ie, container, Ngap_ProtocolIE_ID_id_UserLocationInformation, false);
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


   //UESecurityCapabilities
   NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_PathSwitchRequestIEs_t, ie, container, Ngap_ProtocolIE_ID_id_UESecurityCapabilities, false);
	if (ie) 
	{ 
	    uint16_t nRencryptionAlgorithms = BIT_STRING_to_uint16(&ie->value.choice.UESecurityCapabilities.nRencryptionAlgorithms);
		printf("nRencryptionAlgorithms:0x%x\n",nRencryptionAlgorithms);

        uint16_t nRintegrityProtectionAlgorithms = BIT_STRING_to_uint16(&ie->value.choice.UESecurityCapabilities.nRintegrityProtectionAlgorithms);
		printf("nRintegrityProtectionAlgorithms:0x%x\n",nRintegrityProtectionAlgorithms);

		
		uint16_t eUTRAencryptionAlgorithms = BIT_STRING_to_uint16(&ie->value.choice.UESecurityCapabilities.eUTRAencryptionAlgorithms);
		printf("eUTRAencryptionAlgorithms:0x%x\n",eUTRAencryptionAlgorithms);

	    
		uint16_t eUTRAintegrityProtectionAlgorithms = BIT_STRING_to_uint16(&ie->value.choice.UESecurityCapabilities.eUTRAintegrityProtectionAlgorithms);
		printf("eUTRAintegrityProtectionAlgorithms:0x%x\n",eUTRAintegrityProtectionAlgorithms);
	}


	//DUSessionResourceToBeSwitchedDLList
	NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_PathSwitchRequestIEs_t, ie, container, Ngap_ProtocolIE_ID_id_PDUSessionResourceToBeSwitchedDLList, false);
	if (ie) 
	{ 
		Ngap_PDUSessionResourceToBeSwitchedDLList_t	 *pSwDlList_container  =  &ie->value.choice.PDUSessionResourceToBeSwitchedDLList;
		for (i	= 0;i < pSwDlList_container->list.count; i++)
		{
			Ngap_PDUSessionResourceToBeSwitchedDLItem_t *pAdmitItemIes_p = NULL;
			pAdmitItemIes_p = pSwDlList_container->list.array[i];
				
			if(!pAdmitItemIes_p)
			{
				continue;
			}
				
			long  pDUSessionID			     = pAdmitItemIes_p->pDUSessionID;
			char *pathSwitchRequestTransfer  = pAdmitItemIes_p->pathSwitchRequestTransfer.buf;
				
			printf("sw_dl_list, pDUSessionID:0x%x,transfer:%s\n", pDUSessionID, pathSwitchRequestTransfer);
	
		}
	}
    //PDUSessionResourceFailedToSetupListPSReq
	NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_PathSwitchRequestIEs_t, ie, container, Ngap_ProtocolIE_ID_id_PDUSessionResourceFailedToSetupListPSReq, false);
	if (ie) 
	{ 
		Ngap_PDUSessionResourceFailedToSetupListPSReq_t	 *pFailedList_container  =  &ie->value.choice.PDUSessionResourceFailedToSetupListPSReq;
		for (i	= 0;i < pFailedList_container->list.count; i++)
		{
			Ngap_PDUSessionResourceFailedToSetupItemPSReq_t *pFailedItemIes_p = NULL;
			pFailedItemIes_p = pFailedList_container->list.array[i];
				
			if(!pFailedItemIes_p)
			{
				continue;
			}
				
			long  pDUSessionID			     = pFailedItemIes_p->pDUSessionID;
			char *pathSwitchRequestSetupFailedTransfer  = pFailedItemIes_p->pathSwitchRequestSetupFailedTransfer.buf;
				
			printf("failed_setup_list, pDUSessionID:0x%x,transfer:%s\n", pDUSessionID, pathSwitchRequestSetupFailedTransfer);
		}
	}
	
	return rc;
}

int  make_NGAP_PduPathSwitchRequest(const char *inputBuf, const char *OutputBuf)
{

    printf("pdu session  path switch request, start--------------------\n\n");

    int ret = 0;
	int rc  = RETURNok;
	const sctp_assoc_id_t assoc_id  = 0;
    const sctp_stream_id_t stream   = 0;
	Ngap_NGAP_PDU_t  message = {0};

	//wys:  1024 ?
	size_t buffer_size = 1024;  
	void *buffer = calloc(1,buffer_size);
	asn_enc_rval_t er;	
	
	Ngap_NGAP_PDU_t * pdu =  ngap_generate_ng_path_sw_req(inputBuf);
	if(!pdu)
		goto ERROR;

    asn_fprint(stderr, &asn_DEF_Ngap_NGAP_PDU, pdu);

    ret  =  check_NGAP_pdu_constraints(pdu);
    if(ret < 0) 
	{
		printf("ng path switch request Constraint validation  failed\n");
		rc = RETURNerror;
		goto ERROR; 
	}

	//encode
	er = aper_encode_to_buffer(&asn_DEF_Ngap_NGAP_PDU, NULL, pdu, buffer, buffer_size);
	if(er.encoded < 0)
	{
		printf("ng path switch request encode failed,er.encoded:%d\n",er.encoded);
		rc = RETURNerror;
		goto ERROR; 
	}
  		 
	bstring msgBuf = blk2bstr(buffer, er.encoded);

    //decode
    ngap_amf_decode_pdu(&message, msgBuf);
	ngap_amf_handle_ng_pdu_path_sw_req(0, 0, &message);


    //Free pdu
    ASN_STRUCT_FREE(asn_DEF_Ngap_NGAP_PDU, pdu);
	if(buffer)
	{
		free(buffer);
		buffer = NULL;
	}
	printf("pdu path switch request, finish--------------------\n\n");
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



