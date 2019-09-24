#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>

#include "TLVEncoder.h"
#include "TLVDecoder.h"
#include "PayloadContainerType.h"

int encode_payload_container_type ( PayloadContainerType payloadcontainertype, uint8_t iei, uint8_t * buffer, uint32_t len  ) 
{
    uint32_t encoded = 0;
    uint8_t bitStream = 0x0;
    CHECK_PDU_POINTER_AND_LENGTH_ENCODER (buffer,PAYLOAD_CONTAINER_TYPE_MINIMUM_LENGTH , len);
    
    if(iei>0)
      bitStream |= (iei&0xf0);
    bitStream |= (payloadcontainertype&0x0f);
    
    ENCODE_U8(buffer+encoded,bitStream,encoded);
    return encoded;
}

int decode_payload_container_type ( PayloadContainerType * payloadcontainertype, uint8_t iei, uint8_t * buffer, uint32_t len  ) 
{
    int decoded=0;
    uint8_t bitStream = 0x0;
	
    DECODE_U8(buffer+decoded,bitStream,decoded);
	
    if(iei != (bitStream&0xf0))
      return -1;
    *payloadcontainertype = bitStream & 0x0f;
	
	
    return decoded;
}

