#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>

#include "TLVEncoder.h"
#include "TLVDecoder.h"
#include "Additional5GSecurityInformation.h"

int encode_additional_5g_security_information ( Additional5GSecurityInformation additional5gsecurityinformation, uint8_t iei, uint8_t * buffer, uint32_t len  ) 
{
    uint8_t *lenPtr;
    uint32_t encoded = 0;
    uint8_t bitStream = 0x0;
    CHECK_PDU_POINTER_AND_LENGTH_ENCODER (buffer,ADDITIONAL_5G_SECURITY_INFORMATION_MINIMUM_LENGTH , len);
    
    if( iei >0  ){
      *buffer=iei;
      encoded++;
    }

    lenPtr = (buffer + encoded);
    encoded++;

    if(additional5gsecurityinformation.rinmr)
      bitStream |= 0x02;
    if(additional5gsecurityinformation.hdp)
      bitStream |= 0x01;

    ENCODE_U8(buffer+encoded,bitStream,encoded);

    *lenPtr = encoded - 1 - ((iei > 0) ? 1 : 0);    
    return encoded;
}

int decode_additional_5g_security_information ( Additional5GSecurityInformation * additional5gsecurityinformation, uint8_t iei, uint8_t * buffer, uint32_t len  ) 
{
    int decoded=0;
    uint8_t ielen=0;
    uint8_t bitStream = 0x0;

    if (iei > 0)
    {
        CHECK_IEI_DECODER (iei, *buffer);
        decoded++;
    }

    ielen = *(buffer + decoded);
    decoded++;
    CHECK_LENGTH_DECODER (len - decoded, ielen);

    DECODE_U8(buffer+decoded,bitStream,decoded);
    if(bitStream&0x02)
      additional5gsecurityinformation->rinmr = true;
    else
      additional5gsecurityinformation->rinmr = false;

    if(bitStream&0x01)
      additional5gsecurityinformation->hdp = true;
    else
      additional5gsecurityinformation->rinmr = false;

    return decoded;
}

