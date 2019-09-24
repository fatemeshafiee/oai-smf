#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>

#include "TLVEncoder.h"
#include "TLVDecoder.h"
#include "UEStatus.h"

int encode_ue_status ( UEStatus uestatus, uint8_t iei, uint8_t * buffer, uint32_t len  ) 
{
    uint8_t *lenPtr;
    uint32_t encoded = 0;
    uint8_t bitStream = 0x0;
    CHECK_PDU_POINTER_AND_LENGTH_ENCODER (buffer,UE_STATUS_MINIMUM_LENGTH , len);
    
    if( iei >0  ){
      *buffer=iei;
      encoded++;
    }

    lenPtr = (buffer + encoded);
    encoded++;

    if(uestatus.n1_mode_reg)
      bitStream |= 0x02;
    if(uestatus.s1_mode_reg)
      bitStream |= 0x01;

    ENCODE_U8(buffer+encoded,bitStream,encoded);

    *lenPtr = encoded - 1 - ((iei > 0) ? 1 : 0);    
    return encoded;
}

int decode_ue_status ( UEStatus * uestatus, uint8_t iei, uint8_t * buffer, uint32_t len  ) 
{
    int decoded=0;
    uint8_t ielen=0;
    int bitStream = 0x0;

    if (iei > 0)
    {
        CHECK_IEI_DECODER (iei, *buffer);
        decoded++;
    }

    ielen = *(buffer + decoded);
    decoded++;
    CHECK_LENGTH_DECODER (len - decoded, ielen);

    DECODE_U8(buffer+decoded,bitStream,decoded);
    if(bitStream & 0x02)
      uestatus->n1_mode_reg = true;
    else
      uestatus->n1_mode_reg = false;

    if(bitStream & 0x01)
      uestatus->s1_mode_reg = true;
    else
      uestatus->s1_mode_reg = false;

    return decoded;
}

