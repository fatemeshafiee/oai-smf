#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>

#include "TLVEncoder.h"
#include "TLVDecoder.h"
#include "NetworkSlicingIndication.h"

int encode_network_slicing_indication ( NetworkSlicingIndication networkslicingindication, uint8_t iei, uint8_t * buffer, uint32_t len  ) 
{
    uint32_t encoded = 0;
    uint8_t bitStream = 0x0;
    CHECK_PDU_POINTER_AND_LENGTH_ENCODER (buffer,NETWORK_SLICING_INDICATION_MINIMUM_LENGTH , len);
    
    if(iei > 0){
      bitStream |= (iei & 0xf0);
    }

    bitStream |= ((networkslicingindication.dcni&0x01)<<1);
    bitStream |= ((networkslicingindication.nssci&0x01));
    ENCODE_U8(buffer+encoded,bitStream,encoded);
	

    return encoded;
}

int decode_network_slicing_indication ( NetworkSlicingIndication * networkslicingindication, uint8_t iei, uint8_t * buffer, uint32_t len  ) 
{
    int decoded=0;
    uint8_t bitStream = 0x0;

	
    DECODE_U8(buffer+decoded,bitStream,decoded);
   
    if(iei != bitStream&0xf0){
      return -1;
    }

    if(iei > 0){
        bitStream = (bitStream & 0x0f);
    }
	
	
    //networkslicingindication->dcni = bitStream&0x02;
    networkslicingindication->dcni = (bitStream &0x02)>>1;
    networkslicingindication->nssci = bitStream&0x01;
	
    return decoded;
}

