#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>

#include "TLVEncoder.h"
#include "TLVDecoder.h"
#include "NASKeySetIdentifier.h"

int
encode_nas_key_set_identifier (
  NASKeySetIdentifier * naskeysetidentifier,
  uint8_t iei,
  uint8_t * buffer,
  uint32_t len)
{
  
  uint8_t                                 encoded = 0;

  /*
   * Checking length and pointer
   */
  CHECK_PDU_POINTER_AND_LENGTH_ENCODER (buffer, NAS_KEY_SET_IDENTIFIER_MINIMUM_LENGTH, len);
  *(buffer + encoded) = 0x00 | (iei & 0xf0) | ((naskeysetidentifier->tsc & 0x1) << 3) | (naskeysetidentifier->naskeysetidentifier & 0x7);
  encoded++;
  return encoded;
 

}

int encode_u8_nas_key_set_identifier ( NASKeySetIdentifier * naskeysetidentifier) 
{
  uint8_t                                 bufferReturn;
  uint8_t                                *buffer = &bufferReturn;
  uint8_t                                 encoded = 0;
  uint8_t                                 iei = 0;
  
  *(buffer + encoded) = 0x00 | (iei & 0xf0) | ((naskeysetidentifier->tsc & 0x1) << 3) | (naskeysetidentifier->naskeysetidentifier & 0x7);
  encoded++;
  return bufferReturn;    
}

int
decode_nas_key_set_identifier (
  NASKeySetIdentifier * naskeysetidentifier,
  uint8_t iei,
  uint8_t * buffer,
  uint32_t len)
{
  int                                     decoded = 0;

  CHECK_PDU_POINTER_AND_LENGTH_DECODER (buffer, NAS_KEY_SET_IDENTIFIER_MINIMUM_LENGTH, len);

  if (iei > 0) {
    CHECK_IEI_DECODER ((*buffer & 0xf0), iei);
  }

  naskeysetidentifier->tsc = (*(buffer + decoded) >> 3) & 0x1;
  naskeysetidentifier->naskeysetidentifier = *(buffer + decoded) & 0x7;
  decoded++;
  return decoded;
 
}


int decode_u8_nas_key_set_identifier (NASKeySetIdentifier * naskeysetidentifier, uint8_t iei, uint8_t value, uint32_t len  ) 
{
  int                                     decoded = 0;
  uint8_t                                *buffer = &value;

  naskeysetidentifier->tsc = (*(buffer + decoded) >> 3) & 0x1;
  naskeysetidentifier->naskeysetidentifier = *(buffer + decoded) & 0x7;
  decoded++;
  return decoded;
}

