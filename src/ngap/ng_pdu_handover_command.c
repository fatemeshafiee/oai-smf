#include  "3gpp_23.003.h"
#include  "Ngap_TAI.h"
#include  "Ngap_NR-CGI.h"

//#include  "asn1_conversions.h"
//#include  "conversions.h"


#include  "ng_pdu_handover_command.h"

#include  "Ngap_SuccessfulOutcome.h"
#include  "Ngap_NGAP-PDU.h"
#include  "Ngap_ProtocolIE-Field.h"
#include  "Ngap_ProcedureCode.h"
#include  "Ngap_Criticality.h"

#include  "Ngap_CriticalityDiagnostics.h"
#include  "Ngap_CriticalityDiagnostics-IE-List.h"
#include  "Ngap_CriticalityDiagnostics-IE-Item.h"

#include  "Ngap_PDUSessionResourceHandoverList.h"
#include  "Ngap_PDUSessionResourceHandoverItem.h"
#include  "Ngap_PDUSessionResourceToReleaseListHOCmd.h"
#include  "Ngap_PDUSessionResourceToReleaseItemHOCmd.h"


#include  "Ngap_TimeStamp.h"

#include  "common_defs.h"
#include  "common_types.h"
#include  "../common/ngap/ngap_common.h"
#include  "INTEGER.h"
#include  "asn_SEQUENCE_OF.h"
#include  "OCTET_STRING.h"


#define BUF_LEN   1024

Ngap_HandoverCommandIEs_t  * make_handover_command_CriticalityDiagnostics()
{
	Ngap_HandoverCommandIEs_t *ie;
	ie = calloc(1, sizeof(Ngap_HandoverCommandIEs_t));
	
	ie->id            = Ngap_ProtocolIE_ID_id_CriticalityDiagnostics;
	ie->criticality   = Ngap_Criticality_ignore;
	ie->value.present = Ngap_HandoverCommandIEs__value_PR_CriticalityDiagnostics;
	
    return ie;
}

Ngap_HandoverCommandIEs_t  *make_handover_command_RAN_UE_NGAP_ID(uint32_t rAN_UE_NGAP_ID)
{
	Ngap_HandoverCommandIEs_t *ie;
	ie = calloc(1, sizeof(Ngap_HandoverCommandIEs_t));

	ie->id            = Ngap_ProtocolIE_ID_id_RAN_UE_NGAP_ID;
	ie->criticality   = Ngap_Criticality_reject;
	ie->value.present = Ngap_HandoverCommandIEs__value_PR_RAN_UE_NGAP_ID;
	ie->value.choice.RAN_UE_NGAP_ID = rAN_UE_NGAP_ID ;

	printf("RAN_UE_NGAP_ID:0x%x\n",ie->value.choice.RAN_UE_NGAP_ID);
	return ie;
}

Ngap_HandoverCommandIEs_t  *make_handover_command_AMF_UE_NGAP_ID(uint64_t amf_UE_NGAP_ID)
{
    Ngap_HandoverCommandIEs_t *ie = NULL;
	ie = calloc(1, sizeof(Ngap_HandoverCommandIEs_t));
	
	ie->id            = Ngap_ProtocolIE_ID_id_AMF_UE_NGAP_ID;
	ie->criticality   = Ngap_Criticality_reject;
	ie->value.present = Ngap_HandoverCommandIEs__value_PR_AMF_UE_NGAP_ID;

	asn_ulong2INTEGER(&ie->value.choice.AMF_UE_NGAP_ID, amf_UE_NGAP_ID & AMF_UE_NGAP_ID_MASK_);
	
	printf("AMF_UE_NGAP_ID:0x%x\n",amf_UE_NGAP_ID);
	return ie;
}
Ngap_HandoverCommandIEs_t  * make_handover_command_HandoverType(const long handoverType)
{
	Ngap_HandoverCommandIEs_t *ie = NULL;
	ie                             = calloc(1, sizeof(Ngap_HandoverCommandIEs_t));
	
	ie->id                         = Ngap_ProtocolIE_ID_id_HandoverType;
	ie->criticality                = Ngap_Criticality_reject;
	ie->value.present              = Ngap_HandoverCommandIEs__value_PR_HandoverType;
	
    ie->value.choice.HandoverType  = handoverType;
	printf("handoverType:0x%x\n",ie->value.choice.HandoverType);
	return ie;
}

Ngap_HandoverCommandIEs_t  *make_handover_command_NASSecurityParametersFromNGRAN(const char *nas_pdu)
{
    Ngap_HandoverCommandIEs_t *ie = NULL;
	ie                = calloc(1, sizeof(Ngap_HandoverCommandIEs_t));
	
	ie->id            = Ngap_ProtocolIE_ID_id_NASSecurityParametersFromNGRAN;
	ie->criticality   = Ngap_Criticality_reject;
	ie->value.present = Ngap_HandoverCommandIEs__value_PR_NASSecurityParametersFromNGRAN;
	OCTET_STRING_fromBuf (&ie->value.choice.NASSecurityParametersFromNGRAN, nas_pdu, strlen(nas_pdu));

    printf("nas_pdu, nas_pdu_size:%d, nas_pdu:%s,\n", strlen(nas_pdu), nas_pdu);

	return ie;
}

Ngap_HandoverCommandIEs_t  *make_handover_command_TargetToSource_TransparentContainer(const char *target_to_source)
{
    Ngap_HandoverCommandIEs_t *ie = NULL;
	ie                = calloc(1, sizeof(Ngap_HandoverCommandIEs_t));
	
	ie->id            = Ngap_ProtocolIE_ID_id_TargetToSource_TransparentContainer;
	ie->criticality   = Ngap_Criticality_reject;
	ie->value.present = Ngap_HandoverCommandIEs__value_PR_TargetToSource_TransparentContainer;
	OCTET_STRING_fromBuf (&ie->value.choice.TargetToSource_TransparentContainer, target_to_source, strlen(target_to_source));

    printf("target_to_source, nas_pdu_size:%d, nas_pdu:%s,\n", strlen(target_to_source), target_to_source);

	return ie;
}

Ngap_HandoverCommandIEs_t  * make_handover_command_PDUSessionResourceHandoverList()
{
	Ngap_HandoverCommandIEs_t *ie;
	ie = calloc(1, sizeof(Ngap_HandoverCommandIEs_t));
	
	ie->id            = Ngap_ProtocolIE_ID_id_PDUSessionResourceHandoverList;
	ie->criticality   = Ngap_Criticality_ignore;
	ie->value.present = Ngap_HandoverCommandIEs__value_PR_PDUSessionResourceHandoverList;
	
    return ie;
}

Ngap_PDUSessionResourceHandoverItem_t *make_handover_command_PDUSessionResourceHandoverItem(
const long  pDUSessionID,  
const char *pDUTransfer)
{
    Ngap_PDUSessionResourceHandoverItem_t  *item = NULL;
    item =  calloc(1, sizeof(Ngap_PDUSessionResourceHandoverItem_t));
	
    item->pDUSessionID = pDUSessionID;
	OCTET_STRING_fromBuf(&item->handoverCommandTransfer, pDUTransfer,strlen(pDUTransfer));
		
	printf("pDUSessionID:0x%x,Transfer:%s\n", item->pDUSessionID,item->handoverCommandTransfer.buf);
	
    return item;
}


Ngap_HandoverCommandIEs_t  * make_handover_command_PDUSessionResourceToReleaseListHOCmd()
{
	Ngap_HandoverCommandIEs_t *ie;
	ie = calloc(1, sizeof(Ngap_HandoverCommandIEs_t));
	
	ie->id            = Ngap_ProtocolIE_ID_id_PDUSessionResourceToReleaseListHOCmd;
	ie->criticality   = Ngap_Criticality_ignore;
	ie->value.present = Ngap_HandoverCommandIEs__value_PR_PDUSessionResourceToReleaseListHOCmd;
	
    return ie;
}

Ngap_PDUSessionResourceToReleaseItemHOCmd_t *make_handover_command_PDUSessionResourceToReleaseItemHOCmd(
const long  pDUSessionID,  
const char *pDUTransfer)
{
    Ngap_PDUSessionResourceToReleaseItemHOCmd_t  *item = NULL;
    item =  calloc(1, sizeof(Ngap_PDUSessionResourceToReleaseItemHOCmd_t));
	
    item->pDUSessionID = pDUSessionID;
	OCTET_STRING_fromBuf(&item->handoverPreparationUnsuccessfulTransfer, pDUTransfer,strlen(pDUTransfer));
		
	printf("pDUSessionID:0x%x,Transfer:%s\n", item->pDUSessionID,item->handoverPreparationUnsuccessfulTransfer.buf);
	
    return item;
}


void add_pdu_handover_command_ie(Ngap_HandoverCommand_t *ngapPDUHandoverCommand, Ngap_HandoverCommandIEs_t *ie) {
    int ret;
	ret = ASN_SEQUENCE_ADD(&ngapPDUHandoverCommand->protocolIEs.list, ie);
    if ( ret != 0 ) {
        fprintf(stderr, "Failed to add ie\n");
		return ;
    }
	return ;
}
Ngap_NGAP_PDU_t *  ngap_generate_ng_handover_command(const char *inputBuf)
{
    Ngap_NGAP_PDU_t * pdu = NULL;
	pdu = calloc(1, sizeof(Ngap_NGAP_PDU_t));
    
	pdu->present = Ngap_NGAP_PDU_PR_successfulOutcome;
	pdu->choice.successfulOutcome = calloc(1, sizeof(Ngap_SuccessfulOutcome_t));
	pdu->choice.successfulOutcome->procedureCode = Ngap_ProcedureCode_id_HandoverPreparation;
	pdu->choice.successfulOutcome->criticality   = Ngap_Criticality_reject;
	pdu->choice.successfulOutcome->value.present = Ngap_SuccessfulOutcome__value_PR_HandoverCommand;

    Ngap_HandoverCommand_t *ngapPDUHandoverCommand = NULL;
	ngapPDUHandoverCommand = &pdu->choice.successfulOutcome->value.choice.HandoverCommand;
	
	Ngap_HandoverCommandIEs_t  *ie = NULL;

    //Ngap_AMF_UE_NGAP_ID_t
	uint64_t  amf_ue_ngap_id = 0x77;
	ie  = make_handover_command_AMF_UE_NGAP_ID(amf_ue_ngap_id);
    add_pdu_handover_command_ie(ngapPDUHandoverCommand, ie);

	//Ngap_AMF_UE_NGAP_ID_t
    uint32_t  ran_ue_ngap_id = 0x78;
	ie  = make_handover_command_RAN_UE_NGAP_ID(ran_ue_ngap_id);
	add_pdu_handover_command_ie(ngapPDUHandoverCommand, ie);

	//Ngap_HandoverType
    ie = make_handover_command_HandoverType(Ngap_HandoverType_intra5gs);
	add_pdu_handover_command_ie(ngapPDUHandoverCommand, ie);

    //NASSecurityParametersFromNGRAN
	ie = make_handover_command_NASSecurityParametersFromNGRAN("test_nas_pdu");
	add_pdu_handover_command_ie(ngapPDUHandoverCommand, ie);

    //PDUSessionResourceHandoverList
	Ngap_PDUSessionResourceHandoverItem_t    *pHandoverItem = NULL;
	ie             =  make_handover_command_PDUSessionResourceHandoverList();
	pHandoverItem  =  make_handover_command_PDUSessionResourceHandoverItem(0x80,"test_handover_item");
	ASN_SEQUENCE_ADD(&ie->value.choice.PDUSessionResourceHandoverList.list, pHandoverItem);
	add_pdu_handover_command_ie(ngapPDUHandoverCommand, ie);


	//PDUSessionResourceToReleaseListHOCmd
    Ngap_PDUSessionResourceToReleaseItemHOCmd_t  *pourceToReleaseItem = NULL;
	ie                   =  make_handover_command_PDUSessionResourceToReleaseListHOCmd();
	pourceToReleaseItem  =  make_handover_command_PDUSessionResourceToReleaseItemHOCmd(0x81,"test_release_item");
	ASN_SEQUENCE_ADD(&ie->value.choice.PDUSessionResourceToReleaseListHOCmd.list, pourceToReleaseItem);
	add_pdu_handover_command_ie(ngapPDUHandoverCommand, ie);

	//TargetToSource_TransparentContainer
	ie = make_handover_command_TargetToSource_TransparentContainer("test_targettosource");
	add_pdu_handover_command_ie(ngapPDUHandoverCommand, ie);
   
	//CriticalityDiagnostics
    ie = make_handover_command_CriticalityDiagnostics();

	Ngap_ProcedureCode_t  *procedureCode = calloc(1, sizeof(Ngap_ProcedureCode_t));
	*procedureCode = 0x81;
    ie ->value.choice.CriticalityDiagnostics.procedureCode  = procedureCode;

	Ngap_TriggeringMessage_t  *triggeringMessage = calloc(1, sizeof(Ngap_TriggeringMessage_t));
	*triggeringMessage = 0x01;
    ie ->value.choice.CriticalityDiagnostics.triggeringMessage = triggeringMessage;

	Ngap_Criticality_t  *procedureCriticality = calloc(1, sizeof(Ngap_Criticality_t));
	*procedureCriticality = 0x01;
	ie ->value.choice.CriticalityDiagnostics.procedureCriticality = procedureCriticality;

    printf("procedureCode:0x%x,triggeringMessage:0x%x,procedureCriticality:0x%x\n", *procedureCode, *triggeringMessage,*procedureCriticality);	


    Ngap_CriticalityDiagnostics_IE_List_t   *pCriticalityDiagnostics_IE_List  = calloc(1, sizeof(Ngap_CriticalityDiagnostics_IE_List_t));
    Ngap_CriticalityDiagnostics_IE_Item_t   *critiDiagIEsItem = calloc(1, sizeof(Ngap_CriticalityDiagnostics_IE_Item_t));
	critiDiagIEsItem->iECriticality = 0x01;
	critiDiagIEsItem->iE_ID = 0x01;
	critiDiagIEsItem->typeOfError = 0x00;


    printf("iECriticality:0x%x,iE_ID:0x%x,typeOfError:0x%x\n", 
	critiDiagIEsItem->iECriticality,
	critiDiagIEsItem->iE_ID,
	critiDiagIEsItem->typeOfError);


	ie->value.choice.CriticalityDiagnostics.iEsCriticalityDiagnostics = pCriticalityDiagnostics_IE_List;
    
    ASN_SEQUENCE_ADD(&pCriticalityDiagnostics_IE_List->list, critiDiagIEsItem);
	add_pdu_handover_command_ie(ngapPDUHandoverCommand, ie);
  
	return pdu;
}



int
ngap_amf_handle_ng_pdu_handover_command(
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
    Ngap_HandoverCommand_t             *container = NULL;
    Ngap_HandoverCommandIEs_t          *ie = NULL;
    Ngap_HandoverCommandIEs_t          *ie_gnb_name = NULL;

    unsigned  long    amf_ue_ngap_id        = 0;
	uint32_t          ran_ue_ngap_id        = 0;
	uint32_t          handoverType          = 0;

    long	  pDUSessionID = 0;
	char 	  *handoverCommandTransfer = NULL;
	int       pDUFailedSessionResourceModifyResponseTransfer_size  =  0;

	long	  procedureCode         = 0;	
	long	  triggeringMessage     = 0;	
	long	  procedureCriticality  = 0;
	long	  iECriticality         = 0;
	long	  iE_ID                 = 0;
	long 	  typeOfError           = 0;

    DevAssert (pdu != NULL);
    //OAILOG_INFO(LOG_NGAP,"----------------------- DECODED NG SETUP RESPONSE NGAP MSG --------------------------\n");
    //asn_fprint(stdout, &asn_DEF_Ngap_NGAP_PDU, pdu);
    //OAILOG_INFO(LOG_NGAP,"----------------------- DECODED NG SETUP RESPONSE NGAP MSG --------------------------\n");

	container = &pdu->choice.successfulOutcome->value.choice.HandoverCommand;
    
    //AMF_UE_NGAP_ID
    NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_HandoverCommandIEs_t, ie, container, Ngap_ProtocolIE_ID_id_AMF_UE_NGAP_ID, false);
    if (ie) 
	{  
	    asn_INTEGER2ulong(&ie->value.choice.AMF_UE_NGAP_ID, &amf_ue_ngap_id);
	    printf("amf_ue_ngap_id, 0x%x\n", amf_ue_ngap_id);
    }

    //Ngap_AMF_UE_NGAP_ID_t
    NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_HandoverCommandIEs_t, ie, container, Ngap_ProtocolIE_ID_id_RAN_UE_NGAP_ID, false);
    if (ie) 
	{  
	    ran_ue_ngap_id = ie->value.choice.RAN_UE_NGAP_ID;
	    printf("ran_ue_ngap_id, 0x%x\n", ran_ue_ngap_id);
    }
	//Ngap_HandoverType
	NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_HandoverCommandIEs_t, ie, container, Ngap_ProtocolIE_ID_id_HandoverType, false);
	if (ie) 
	{  
		handoverType = ie->value.choice.HandoverType;
		printf("HandoverType, 0x%x\n", handoverType);
	}
	//NASSecurityParametersFromNGRAN
	NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_HandoverCommandIEs_t, ie, container, Ngap_ProtocolIE_ID_id_NASSecurityParametersFromNGRAN, false);
	if (ie) 
	{  
		printf("NASSecurityParametersFromNGRAN:%s\n", ie->value.choice.NASSecurityParametersFromNGRAN.buf);
	}

    //PDUSessionResourceHandoverList
    NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_HandoverCommandIEs_t, ie, container, Ngap_ProtocolIE_ID_id_PDUSessionResourceHandoverList, false);
    if (ie) 
	{ 
	    Ngap_PDUSessionResourceHandoverList_t		 *resourceHandover_container  =  &ie->value.choice.PDUSessionResourceHandoverList;
        for (i  = 0;i < resourceHandover_container->list.count; i++)
	    {
            Ngap_PDUSessionResourceHandoverItem_t *pHandoverItemIes_p = NULL;
            pHandoverItemIes_p = resourceHandover_container->list.array[i];
			
			if(!pHandoverItemIes_p)
			{
				  continue;
        	}
        	
		    pDUSessionID        = pHandoverItemIes_p->pDUSessionID;
	 	    handoverCommandTransfer   = pHandoverItemIes_p->handoverCommandTransfer.buf;
	        
			printf("PDUSessionResourceHandoverList, pDUSessionID:0x%x,transfer:%s\n", pDUSessionID, handoverCommandTransfer);

		}
    }
  
	//PDUSessionResourceToReleaseListHOCmd
	NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_HandoverCommandIEs_t, ie, container, Ngap_ProtocolIE_ID_id_PDUSessionResourceToReleaseListHOCmd, false);
    if (ie) 
	{ 
	    Ngap_PDUSessionResourceToReleaseListHOCmd_t		 *resourceList_container  =  &ie->value.choice.PDUSessionResourceToReleaseListHOCmd;
        for (i  = 0;i < resourceList_container->list.count; i++)
	    {
            Ngap_PDUSessionResourceToReleaseItemHOCmd_t *preleasesItemIes_p = NULL;
            preleasesItemIes_p = resourceList_container->list.array[i];
			
			if(!preleasesItemIes_p)
			{
				  continue;
        	}
        	
		    pDUSessionID              = preleasesItemIes_p->pDUSessionID;
	 	    handoverCommandTransfer   = preleasesItemIes_p->handoverPreparationUnsuccessfulTransfer.buf;
	        
			printf("PDUSessionResourceToReleaseListHOCmd, pDUSessionID:0x%x,transfer:%s\n", pDUSessionID, handoverCommandTransfer);

		}
    }
    
    //TargetToSource_TransparentContainer
    NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_HandoverCommandIEs_t, ie, container, Ngap_ProtocolIE_ID_id_TargetToSource_TransparentContainer, false);
	if (ie) 
	{  
		printf("TargetToSource_TransparentContainer:%s\n", ie->value.choice.TargetToSource_TransparentContainer.buf);
	}
	
	//CriticalityDiagnostics
    NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_HandoverCommandIEs_t, ie, container, Ngap_ProtocolIE_ID_id_CriticalityDiagnostics, false);
	if (ie) 
	{ 
	   procedureCode         = *ie->value.choice.CriticalityDiagnostics.procedureCode;	
	   triggeringMessage     = *ie->value.choice.CriticalityDiagnostics.triggeringMessage;	
	   procedureCriticality  = *ie->value.choice.CriticalityDiagnostics.procedureCriticality;

	   printf("procedureCode:0x%x,triggeringMessage:0x%x,procedureCriticality:0x%x\n", procedureCode, triggeringMessage,procedureCriticality);  

	   Ngap_CriticalityDiagnostics_IE_List_t   *criticality_container  = ie->value.choice.CriticalityDiagnostics.iEsCriticalityDiagnostics; 
       for (i  = 0;i < criticality_container->list.count; i++)
	   {
           Ngap_CriticalityDiagnostics_IE_Item_t  *criticalityIes_p = criticality_container->list.array[i];
		   if(!criticalityIes_p)
		      continue;
		   
		    iECriticality         = criticalityIes_p->iECriticality;
	        iE_ID                 = criticalityIes_p->iE_ID;
	        typeOfError           = criticalityIes_p->typeOfError;

			printf("iECriticality:0x%x,iE_ID:0x%x,typeOfError:0x%x\n", iECriticality, iE_ID, typeOfError);
	   }  
	}
	
	return rc;
}


int  make_NGAP_PduHandOverCommand(const char *inputBuf, const char *OutputBuf)
{

    printf("pdu handover  command, start--------------------\n\n");

    int ret = 0;
	int rc  = RETURNok;
	const sctp_assoc_id_t assoc_id  = 0;
    const sctp_stream_id_t stream   = 0;
	Ngap_NGAP_PDU_t  message = {0};

	//wys:  1024 ?
	size_t buffer_size = 1024;  
	void *buffer = calloc(1,buffer_size);
	asn_enc_rval_t er;	
	
	Ngap_NGAP_PDU_t * pdu =  ngap_generate_ng_handover_command(inputBuf);
	if(!pdu)
		goto ERROR;

    asn_fprint(stderr, &asn_DEF_Ngap_NGAP_PDU, pdu);

    ret  =  check_NGAP_pdu_constraints(pdu);
    if(ret < 0) 
	{
		printf("ng modify response Constraint validation  failed\n");
		rc = RETURNerror;
		goto ERROR; 
	}

	//encode
	er = aper_encode_to_buffer(&asn_DEF_Ngap_NGAP_PDU, NULL, pdu, buffer, buffer_size);
	if(er.encoded < 0)
	{
		printf("ng modify response encode failed,er.encoded:%d\n",er.encoded);
		rc = RETURNerror;
		goto ERROR; 
	}
  		 
	bstring msgBuf = blk2bstr(buffer, er.encoded);

    //decode
    ngap_amf_decode_pdu(&message, msgBuf);
	ngap_amf_handle_ng_pdu_handover_command(0,0, &message);


    //Free pdu
    ASN_STRUCT_FREE(asn_DEF_Ngap_NGAP_PDU, pdu);
	if(buffer)
	{
		free(buffer);
		buffer = NULL;
	}
	printf("pdu handover  command, finish--------------------\n\n");
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



