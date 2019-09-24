#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>

#include "TLVEncoder.h"
#include "TLVDecoder.h"
#include "_5GSIdentityType.h"

int encode__5gs_identity_type ( _5GSIdentityType _5gsidentitytype, uint8_t iei, uint8_t * buffer, uint32_t len  ) 
{
    uint32_t encoded = 0;
    uint8_t bitStream = 0x0;
    CHECK_PDU_POINTER_AND_LENGTH_ENCODER (buffer,_5GS_IDENTITY_TYPE_MINIMUM_LENGTH , len);

    bitStream = ((iei&0x0f) <<4)|_5gsidentitytype.typeOfIdentity;
    ENCODE_U8(buffer+encoded,bitStream,encoded);    

    return encoded;
}

int decode__5gs_identity_type ( _5GSIdentityType * _5gsidentitytype, uint8_t iei, uint8_t * buffer, uint32_t len  ) 
{
    int decoded=0;
    uint8_t bitStream = 0x0;

    DECODE_U8(buffer+decoded,bitStream,decoded);
    _5gsidentitytype->typeOfIdentity = bitStream&0x07;

    return decoded;
}

