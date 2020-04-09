#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>

#include "TLVEncoder.h"
#include "TLVDecoder.h"
#include "S1UENetworkCapability.h"

int encode_s1_ue_network_capability ( S1UENetworkCapability s1uenetworkcapability, uint8_t iei, uint8_t * buffer, uint32_t len  ) 
{
  uint8_t *lenPtr;
  uint32_t encoded = 0;
  CHECK_PDU_POINTER_AND_LENGTH_ENCODER (buffer,S1_UE_NETWORK_CAPABILITY_MINIMUM_LENGTH , len);

  if( iei >0  ){
    *buffer=iei;
    encoded++;
  }

  lenPtr = (buffer + encoded);
  encoded++;

  ENCODE_U8(buffer+encoded,s1uenetworkcapability.eea,encoded);
  ENCODE_U8(buffer+encoded,s1uenetworkcapability.eia,encoded);

  *lenPtr = encoded - 1 - ((iei > 0) ? 1 : 0);
  return encoded;
}

int decode_s1_ue_network_capability ( S1UENetworkCapability * s1uenetworkcapability, uint8_t iei, uint8_t * buffer, uint32_t len  ) 
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

  DECODE_U8(buffer+decoded,s1uenetworkcapability->eea,decoded);
  DECODE_U8(buffer+decoded,s1uenetworkcapability->eia,decoded);

  return decoded;
}

