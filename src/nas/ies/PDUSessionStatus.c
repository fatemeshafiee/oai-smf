#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>

#include "TLVEncoder.h"
#include "TLVDecoder.h"
#include "PDUSessionStatus.h"

int encode_pdu_session_status ( PDUSessionStatus pdusessionstatus, uint8_t iei, uint8_t * buffer, uint32_t len  ) 
{
    printf("encode_pdu_session_status\n");
    uint8_t *lenPtr;
    uint32_t encoded = 0;
    CHECK_PDU_POINTER_AND_LENGTH_ENCODER (buffer,PDU_SESSION_STATUS_MINIMUM_LENGTH , len);
    
    if( iei >0  ){
      *buffer=iei;
      encoded++;
    }

    lenPtr = (buffer + encoded);
    encoded++;

    ENCODE_U16(buffer+encoded, pdusessionstatus, encoded);

    *lenPtr = encoded - 1 - ((iei > 0) ? 1 : 0);    
    return encoded;
}

int decode_pdu_session_status ( PDUSessionStatus * pdusessionstatus, uint8_t iei, uint8_t * buffer, uint32_t len  ) 
{
    int decoded=0;
    uint8_t ielen=0;

    if (iei > 0)
    {
        CHECK_IEI_DECODER (iei, *buffer);
        decoded++;
    }

    ielen = *(buffer + decoded);
    decoded++;
    CHECK_LENGTH_DECODER (len - decoded, ielen);

    DECODE_U16(buffer+decoded, *pdusessionstatus,decoded);

    return decoded;
}
