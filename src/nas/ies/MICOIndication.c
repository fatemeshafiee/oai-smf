#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>

#include "TLVEncoder.h"
#include "TLVDecoder.h"
#include "MICOIndication.h"

int encode_mico_indication ( MICOIndication micoindication, uint8_t iei, uint8_t * buffer, uint32_t len  ) 
{

  uint32_t encoded = 0;
  uint8_t bitStream = 0x0;
  CHECK_PDU_POINTER_AND_LENGTH_ENCODER (buffer,MICO_INDICATION_MINIMUM_LENGTH , len);

  if(iei >0){
    bitStream |= (iei&0xf0);
  }
  if(micoindication.raai){
    bitStream |= 0x01;
  }
  ENCODE_U8(buffer+encoded,bitStream,encoded);

  return encoded;
}

int decode_mico_indication ( MICOIndication * micoindication, uint8_t iei, uint8_t * buffer, uint32_t len  ) 
{
  int decoded=0;
  uint8_t bitStream;
  DECODE_U8(buffer+decoded,bitStream,decoded);
  if(iei != (bitStream&0xf0))
    return -1;
  if(bitStream&0x01)
    micoindication->raai = true;

  return decoded;
}

