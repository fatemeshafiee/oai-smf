#include  "ng_pdu_session_resource_release_command.h"

#include  "Ngap_NGAP-PDU.h"
#include  "Ngap_ProtocolIE-Field.h"
#include  "Ngap_ProcedureCode.h"
#include  "Ngap_InitiatingMessage.h"

#include  "Ngap_Criticality.h"

#include  "Ngap_PDUSessionResourceReleaseCommand.h"
#include  "Ngap_PDUSessionResourceToReleaseListRelCmd.h"
#include  "Ngap_PDUSessionResourceToReleaseItemRelCmd.h"


#include  "common_defs.h"
#include  "common_types.h"
#include  "../common/ngap/ngap_common.h"


#include  "INTEGER.h"
#include  "asn_SEQUENCE_OF.h"
#include  "OCTET_STRING.h"

#define BUF_LEN   1024
Ngap_PDUSessionResourceReleaseCommandIEs_t  *make_release_command_RAN_UE_NGAP_ID(uint32_t rAN_UE_NGAP_ID)
{
	Ngap_PDUSessionResourceReleaseCommandIEs_t *ie;
	ie = calloc(1, sizeof(Ngap_PDUSessionResourceReleaseCommandIEs_t));

	ie->id = Ngap_ProtocolIE_ID_id_RAN_UE_NGAP_ID;
	ie->criticality = Ngap_Criticality_reject;
	ie->value.present = Ngap_PDUSessionResourceReleaseCommandIEs__value_PR_RAN_UE_NGAP_ID;
	ie->value.choice.RAN_UE_NGAP_ID = rAN_UE_NGAP_ID ;

	printf("RAN_UE_NGAP_ID:0x%x",ie->value.choice.RAN_UE_NGAP_ID);
	return ie;
}
Ngap_PDUSessionResourceReleaseCommandIEs_t  *make_release_command_AMF_UE_NGAP_ID(uint64_t amf_UE_NGAP_ID)
{
    Ngap_PDUSessionResourceReleaseCommandIEs_t *ie = NULL;
	ie = calloc(1, sizeof(Ngap_PDUSessionResourceReleaseCommandIEs_t));
	
	ie->id = Ngap_ProtocolIE_ID_id_AMF_UE_NGAP_ID;
	ie->criticality = Ngap_Criticality_reject;
	ie->value.present = Ngap_PDUSessionResourceReleaseCommandIEs__value_PR_AMF_UE_NGAP_ID;

	asn_ulong2INTEGER(&ie->value.choice.AMF_UE_NGAP_ID, amf_UE_NGAP_ID & AMF_UE_NGAP_ID_MASK_);
	
	size_t i  = 0;
	for(i ; i<ie->value.choice.AMF_UE_NGAP_ID.size;i++)
	{
	    printf("0x%x",ie->value.choice.AMF_UE_NGAP_ID.buf[i]);
	}
	return ie;
}
Ngap_PDUSessionResourceReleaseCommandIEs_t  *make_release_command_RANPagingPriority(const long  ranPagingPriority)
{
    Ngap_PDUSessionResourceReleaseCommandIEs_t *ie = NULL;
	ie = calloc(1, sizeof(Ngap_PDUSessionResourceReleaseCommandIEs_t));
	
	ie->id = Ngap_ProtocolIE_ID_id_RANPagingPriority;
	ie->criticality = Ngap_Criticality_ignore;
	ie->value.present = Ngap_PDUSessionResourceReleaseCommandIEs__value_PR_RANPagingPriority;
    ie->value.choice.RANPagingPriority  = ranPagingPriority;

    printf("RANPagingPriority:0x%x",ie->value.choice.RANPagingPriority);
	return ie;
}

Ngap_PDUSessionResourceReleaseCommandIEs_t  *make_release_command_NAS_PDU(const char *nas_pdu)
{
    Ngap_PDUSessionResourceReleaseCommandIEs_t *ie = NULL;
	ie = calloc(1, sizeof(Ngap_PDUSessionResourceReleaseCommandIEs_t));
	
	ie->id = Ngap_ProtocolIE_ID_id_NAS_PDU;
	ie->criticality = Ngap_Criticality_reject;
	ie->value.present = Ngap_PDUSessionResourceReleaseCommandIEs__value_PR_NAS_PDU;
	OCTET_STRING_fromBuf (&ie->value.choice.NAS_PDU, nas_pdu, strlen(nas_pdu));

	return ie;
}

Ngap_PDUSessionResourceReleaseCommandIEs_t *make_PDUSessionResourceToReleaseItemRelCmd(
	const long  pDUSessionID, const char	 *pDUSessionResourceSetup)
{
    Ngap_PDUSessionResourceToReleaseItemRelCmd_t  *item = NULL;
    item =  calloc(1, sizeof(Ngap_PDUSessionResourceToReleaseItemRelCmd_t));
    item->pDUSessionID = pDUSessionID;
	OCTET_STRING_fromBuf(&item->pDUSessionResourceReleaseCommandTransfer,pDUSessionResourceSetup,strlen(pDUSessionResourceSetup));
	
    return item;
}

Ngap_PDUSessionResourceReleaseCommandIEs_t  * make_PDUSessionResourceToReleaseListRelCmd()
{
	Ngap_PDUSessionResourceReleaseCommandIEs_t *ie;
	ie = calloc(1, sizeof(Ngap_PDUSessionResourceReleaseCommandIEs_t));
	
	ie->id            = Ngap_ProtocolIE_ID_id_PDUSessionResourceToReleaseListRelCmd;
	ie->criticality   = Ngap_Criticality_reject;
	ie->value.present = Ngap_PDUSessionResourceReleaseCommandIEs__value_PR_PDUSessionResourceToReleaseListRelCmd;
	
    return ie;
}

void add_pdu_session_resource_release_command_ie(Ngap_PDUSessionResourceReleaseCommand_t *ngapPDUSessionResourceReleaseCommand, Ngap_PDUSessionResourceReleaseCommandIEs_t *ie) {
    int ret;
	ret = ASN_SEQUENCE_ADD(&ngapPDUSessionResourceReleaseCommand->protocolIEs.list, ie);
    if ( ret != 0 ) {
        fprintf(stderr, "Failed to add ie\n");
		return ;
    }
	return ;
}
Ngap_NGAP_PDU_t *make_NGAP_pdu_session_resource_release_command()
{
    Ngap_NGAP_PDU_t * pdu = NULL;
	pdu = calloc(1, sizeof(Ngap_NGAP_PDU_t));
    
	pdu->present = Ngap_NGAP_PDU_PR_initiatingMessage;
	pdu->choice.initiatingMessage = calloc(1, sizeof(Ngap_InitiatingMessage_t));
	pdu->choice.initiatingMessage->procedureCode = Ngap_ProcedureCode_id_PDUSessionResourceRelease;
	pdu->choice.initiatingMessage->criticality = Ngap_Criticality_reject;
	pdu->choice.initiatingMessage->value.present = Ngap_InitiatingMessage__value_PR_PDUSessionResourceReleaseCommand;

    Ngap_PDUSessionResourceReleaseCommand_t *ngapPDUSessionResourceReleaseCommand = NULL;
	ngapPDUSessionResourceReleaseCommand = &pdu->choice.initiatingMessage->value.choice.PDUSessionResourceReleaseCommand;
	
	Ngap_PDUSessionResourceReleaseCommandIEs_t  *ie = NULL;

    //Ngap_AMF_UE_NGAP_ID_t
	uint64_t  amf_ue_ngap_id = 0x80;
	ie  = make_release_command_AMF_UE_NGAP_ID(amf_ue_ngap_id);
    add_pdu_session_resource_release_command_ie(ngapPDUSessionResourceReleaseCommand, ie);

	//Ngap_AMF_UE_NGAP_ID_t
    uint32_t  ran_ue_ngap_id = 0x81;
	ie  = make_release_command_RAN_UE_NGAP_ID(ran_ue_ngap_id);
	add_pdu_session_resource_release_command_ie(ngapPDUSessionResourceReleaseCommand, ie);

     
	//Ngap_RANPagingPriority_t
	long ranPagingPriority  = 0x82;
    ie  = make_release_command_RANPagingPriority(ranPagingPriority);
	add_pdu_session_resource_release_command_ie(ngapPDUSessionResourceReleaseCommand, ie);
	
	//Ngap_NAS_PDU_t
	const char  *nas_pdu  =  "nas_pdu";
    ie  = make_release_command_NAS_PDU(nas_pdu);
    add_pdu_session_resource_release_command_ie(ngapPDUSessionResourceReleaseCommand, ie);


    //PDUSessionResourceToReleaseListRelCmd
    Ngap_PDUSessionResourceToReleaseItemRelCmd_t	 *relCmdItem = NULL;
	ie          =  make_PDUSessionResourceToReleaseListRelCmd();
	relCmdItem  =  make_PDUSessionResourceToReleaseItemRelCmd(0x80, "test_relcmd_setup");
	ASN_SEQUENCE_ADD(&ie->value.choice.PDUSessionResourceToReleaseListRelCmd.list, relCmdItem);
	add_pdu_session_resource_release_command_ie(ngapPDUSessionResourceReleaseCommand, ie);
	 

	printf("0000000000000, make_NGAP_pdu_session_resource_release_command\n");
    return pdu;
}

int
ngap_amf_handle_ng_pdu_session_resource_release_command(
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
    Ngap_PDUSessionResourceReleaseCommand_t                  *container = NULL;
    Ngap_PDUSessionResourceReleaseCommandIEs_t               *ie = NULL;
    Ngap_PDUSessionResourceReleaseCommandIEs_t               *ie_gnb_name = NULL;

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
	
	
	char 	  *pDUSessionResourceReleaseCommandTransfer = NULL;
	int       pDUSessionResourceReleaseCommandTransfer_size  =  0;
	

    DevAssert (pdu != NULL);
    //OAILOG_INFO(LOG_NGAP,"----------------------- DECODED NG SETUP REQUEST NGAP MSG --------------------------\n");
    //asn_fprint(stdout, &asn_DEF_Ngap_NGAP_PDU, pdu);
    //OAILOG_INFO(LOG_NGAP,"----------------------- DECODED NG SETUP REQUEST NGAP MSG --------------------------\n");

	container = &pdu->choice.initiatingMessage->value.choice.PDUSessionResourceReleaseCommand;
    
    //AMF_UE_NGAP_ID
    NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_PDUSessionResourceReleaseCommandIEs_t, ie, container, Ngap_ProtocolIE_ID_id_AMF_UE_NGAP_ID, false);
    if (ie) 
	{  
	   asn_INTEGER2ulong(&ie->value.choice.AMF_UE_NGAP_ID, &amf_ue_ngap_id);
	   printf("amf_ue_ngap_id, 0x%x\n", amf_ue_ngap_id);
    }

    //Ngap_AMF_UE_NGAP_ID_t
    NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_PDUSessionResourceReleaseCommandIEs_t, ie, container, Ngap_ProtocolIE_ID_id_RAN_UE_NGAP_ID, false);
    if (ie) 
	{  
	   ran_ue_ngap_id = ie->value.choice.RAN_UE_NGAP_ID;
	   printf("ran_ue_ngap_id, 0x%x\n", ran_ue_ngap_id);
    }

	//RANPagingPriority
	NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_PDUSessionResourceReleaseCommandIEs_t, ie, container, Ngap_ProtocolIE_ID_id_RANPagingPriority, false);
    if (ie) 
	{  
	   ranPagingPriority = ie->value.choice.RANPagingPriority;
	   printf("ranPagingPriority, 0x%x\n", ranPagingPriority);
    }

    //NAS_PDU
	NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_PDUSessionResourceReleaseCommandIEs_t, ie, container, Ngap_ProtocolIE_ID_id_NAS_PDU, false);
	if (ie) 
	{  
	   nas_pdu      = (char *) ie->value.choice.NAS_PDU.buf;
       nas_pdu_size = (int) ie->value.choice.NAS_PDU.size;
	  
	   printf("RANNodeName, nas_pdu_size:%d, nas_pdu:%s,\n", nas_pdu_size, nas_pdu);
	}
	

	//PDUSessionResourceToReleaseListRelCmd
    NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_PDUSessionResourceReleaseCommandIEs_t, ie, container, Ngap_ProtocolIE_ID_id_PDUSessionResourceToReleaseListRelCmd, false);
	if (ie) 
	{ 
	    Ngap_PDUSessionResourceToReleaseListRelCmd_t	 *relcmd_container  =  &ie->value.choice.PDUSessionResourceToReleaseListRelCmd;
        for (i  = 0;i < relcmd_container->list.count; i++)
	    {
            Ngap_PDUSessionResourceToReleaseItemRelCmd_t *relcmdIes_p = NULL;
            relcmdIes_p = relcmd_container->list.array[i];
			
			if(!relcmdIes_p)
			{
				  continue;
        	}

		    pDUSessionID                                   = relcmdIes_p->pDUSessionID;
	 	    pDUSessionResourceReleaseCommandTransfer       = relcmdIes_p->pDUSessionResourceReleaseCommandTransfer.buf;
	        pDUSessionResourceReleaseCommandTransfer_size  = relcmdIes_p->pDUSessionResourceReleaseCommandTransfer.size;
		}
	}
	
	return rc;
}



