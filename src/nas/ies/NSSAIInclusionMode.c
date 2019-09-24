#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>

#include "TLVEncoder.h"
#include "TLVDecoder.h"
#include "NSSAIInclusionMode.h"

int encode_nssai_inclusion_mode ( NSSAIInclusionMode nssaiinclusionmode, uint8_t iei, uint8_t * buffer, uint32_t len  ) 
{
    uint32_t encoded = 0;
    uint8_t bitStream = 0x0;
     CHECK_PDU_POINTER_AND_LENGTH_ENCODER (buffer,NSSAI_INCLUSION_MODE_MINIMUM_LENGTH , len);
    
    if(iei>0)
      bitStream |= (iei&0xf0);
    bitStream |= (nssaiinclusionmode&0x0f);
    
    ENCODE_U8(buffer+encoded,bitStream,encoded);
    return encoded;
    
    #if 0
    uint32_t encoded = 0;
    CHECK_PDU_POINTER_AND_LENGTH_ENCODER (buffer,NSSAI_INCLUSION_MODE_MINIMUM_LENGTH , len);

	
    ENCODE_U8(buffer+encoded,((iei&0x0f)<<4)|0x00|(nssaiinclusionmode&0x03),encoded);
    //ENCODE_U8(buffer+encoded,((iei&0x0f)<<4)|0x00|(nssaiinclusionmode&0x03),encoded);
    printf("encode_nssai_inclusion_mode-------------buffer:0x%x,bitStream:0x%x\n", *buffer,((iei&0x0f)<<4)|0x00|(nssaiinclusionmode&0x03));
    return encoded;
	#endif
}

int decode_nssai_inclusion_mode ( NSSAIInclusionMode * nssaiinclusionmode, uint8_t iei, uint8_t * buffer, uint32_t len  ) 
{
    int decoded=0;
    uint8_t bitStream = 0x0;
	
    DECODE_U8(buffer+decoded,bitStream,decoded);
	
    if(iei != (bitStream&0xf0))
      return -1;
    *nssaiinclusionmode = bitStream & 0x0f;
    return decoded;
    #if 0
    int decoded=0;
    uint8_t bitStream = 0;
 
    DECODE_U8(buffer+decoded,bitStream,decoded);
    printf("decode_nssai_inclusion_mode-------------buffer:0x%x,bitStream:0x%x\n", *buffer,bitStream);
   if(iei != ((bitStream&0xf0)>>4))
     return -1;
   *nssaiinclusionmode = bitStream&0x03;

    return decoded;
	#endif
}

