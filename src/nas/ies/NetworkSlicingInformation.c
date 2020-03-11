#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>

#include "TLVEncoder.h"
#include "TLVDecoder.h"
#include "NetworkSlicingInformation.h"

int encode_network_slicing_information ( NetworkSlicingInformation networkslicinginformation, uint8_t iei, uint8_t * buffer, uint32_t len  ) 
{
  uint32_t encoded = 0;
  int encode_result;
  CHECK_PDU_POINTER_AND_LENGTH_ENCODER (buffer,NETWORK_SLICING_INFORMATION_MINIMUM_LENGTH , len);

  if ((encode_result = encode_bstring (networkslicinginformation, buffer + encoded, len - encoded)) < 0)//加密,实体,首地址,长度
    return encode_result;
  else
    encoded += encode_result;

  return encoded;
}

int decode_network_slicing_information ( NetworkSlicingInformation * networkslicinginformation, uint8_t iei, uint8_t * buffer, uint32_t len  ) 
{
  int decoded=0;
  uint8_t ielen=0;
  int decode_result;

  if((decode_result = decode_bstring (networkslicinginformation, ielen, buffer + decoded, len - decoded)) < 0)
    return decode_result;
  else
    decoded += decode_result;
  return decoded;
}

