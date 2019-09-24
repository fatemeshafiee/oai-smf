#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>

#include "TLVEncoder.h"
#include "TLVDecoder.h"
#include "UESecurityCapability.h"

int encode_ue_security_capability ( UESecurityCapability uesecuritycapability, uint8_t iei, uint8_t * buffer, uint32_t len  ) 
{
    uint8_t *lenPtr;
    uint32_t encoded = 0;
    int encode_result;
    CHECK_PDU_POINTER_AND_LENGTH_ENCODER (buffer,UE_SECURITY_CAPABILITY_MINIMUM_LENGTH , len);
    
    if( iei >0  ){
      *buffer=iei;
      encoded++;
    }

    lenPtr = (buffer + encoded);
    encoded++;

    ENCODE_U8(buffer+encoded, uesecuritycapability.nea, encoded);
    ENCODE_U8(buffer+encoded, uesecuritycapability.nia, encoded);

    *lenPtr = encoded - 1 - ((iei > 0) ? 1 : 0);    
    return encoded;
}

int decode_ue_security_capability ( UESecurityCapability * uesecuritycapability, uint8_t iei, uint8_t * buffer, uint32_t len  ) 
{
    int decoded=0;
    uint8_t ielen=0;
    int decode_result;

    if (iei > 0)
    {
        CHECK_IEI_DECODER (iei, *buffer);
        decoded++;
    }

    ielen = *(buffer + decoded);
    decoded++;
    CHECK_LENGTH_DECODER (len - decoded, ielen);

    DECODE_U8(buffer+decoded, uesecuritycapability->nea, decoded);
    DECODE_U8(buffer+decoded, uesecuritycapability->nia, decoded);

    return decoded;
}

