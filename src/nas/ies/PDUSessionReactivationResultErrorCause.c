#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>

#include "TLVEncoder.h"
#include "TLVDecoder.h"
#include "PDUSessionReactivationResultErrorCause.h"

int encode_pdu_session_reactivation_result_error_cause ( PDUSessionReactivationResultErrorCause pdusessionreactivationresulterrorcause, uint8_t iei, uint8_t * buffer, uint32_t len  ) 
{
    uint8_t *lenPtr;
    uint32_t encoded = 0;
    int elementIndex = 0;
    CHECK_PDU_POINTER_AND_LENGTH_ENCODER (buffer,PDU_SESSION_REACTIVATION_RESULT_ERROR_CAUSE_MINIMUM_LENGTH , len);
    
    if( iei >0  ){
      *buffer=iei;
      encoded++;
    }

    lenPtr = (buffer + encoded);
    encoded++;
    encoded++;
    struct PduSessionID_CauseValue * ptr = pdusessionreactivationresulterrorcause.element;
    if(!ptr)
	   return encoded;
	ENCODE_U16(buffer+encoded,pdusessionreactivationresulterrorcause.size,encoded);
    for(;elementIndex<pdusessionreactivationresulterrorcause.size;elementIndex++){
      if(!ptr)
        break;
      ENCODE_U8(buffer+encoded,ptr->pduSessionID,encoded);
      ENCODE_U8(buffer+encoded,ptr->causeValue,encoded);
      ptr = ptr->next;
    }

    uint32_t res = encoded - 1 - ((iei > 0) ? 1 : 0);
    *lenPtr =res/(1<<8);
    lenPtr++;
    *lenPtr = res%(1<<8);

    return encoded;
}

int decode_pdu_session_reactivation_result_error_cause ( PDUSessionReactivationResultErrorCause * pdusessionreactivationresulterrorcause, uint8_t iei, uint8_t * buffer, uint32_t len  ) 
{
    int decoded=0;
    uint16_t ielen=0;
    int elementIndex = 0;

    if (iei > 0)
    {
        CHECK_IEI_DECODER (iei, *buffer);
        decoded++;
    }

	//encode ´úÂëdecoded;
	
    decoded++;
	decoded++;
	DECODE_U16(buffer+decoded,ielen,decoded);
   
	
    CHECK_LENGTH_DECODER (len - decoded, ielen);

    pdusessionreactivationresulterrorcause->size = ielen;
    struct PduSessionID_CauseValue * lastPtr = NULL;
    //for(;elementIndex<ielen/2;elementIndex++){
    for(;elementIndex<ielen;elementIndex++){
      struct PduSessionID_CauseValue * ptr = (struct PduSessionID_CauseValue * )calloc(1,sizeof(struct PduSessionID_CauseValue));
      DECODE_U8(buffer+decoded,ptr->pduSessionID,decoded);
      DECODE_U8(buffer+decoded,ptr->causeValue,decoded);
      if(lastPtr)
        lastPtr->next = ptr;
      else
        pdusessionreactivationresulterrorcause->element = ptr;
      lastPtr = ptr;
    }
    if(lastPtr)
      lastPtr->next = NULL;

    return decoded;
}

