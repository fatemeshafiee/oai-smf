#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>

#include "TLVEncoder.h"
#include "TLVDecoder.h"
#include "DNN.h"

int encode_dnn ( DNN dnn, uint8_t iei, uint8_t * buffer, uint32_t len  ) 
{
  uint8_t *lenPtr = NULL;
  uint8_t len_pos = 0;
  uint32_t encoded = 0;
  int encode_result = 0;
  CHECK_PDU_POINTER_AND_LENGTH_ENCODER (buffer,((iei > 0) ? DNN_MINIMUM_LENGTH_TLV : DNN_MINIMUM_LENGTH_TLV-1) , len);

  if(iei > 0 )
  {
    *buffer = iei;
    encoded++;
  }

  lenPtr = (buffer + encoded);
  encoded++; //ENCODE_U8(buffer + encoded, dnn.length, encoded);
  len_pos = encoded;

  if ((encode_result = encode_bstring (dnn, buffer + encoded, len - encoded)) < 0)
    return encode_result;
  else
    encoded += encode_result;

  //set length
  *(uint8_t*)(lenPtr) = encoded - len_pos;

  return encoded;
}

int decode_dnn ( DNN * dnn, uint8_t iei, uint8_t * buffer, uint32_t len  ) 
{
  int decoded = 0;
  uint8_t ielen = 0;
  int decode_result = 0;

  if (iei > 0)
  {
    CHECK_IEI_DECODER (iei, *buffer);
    decoded++;
  }

  ielen = *(buffer + decoded);
  decoded++;
  CHECK_LENGTH_DECODER (len - decoded, ielen);

  if((decode_result = decode_bstring (dnn, ielen, buffer + decoded, len - decoded)) < 0)
  {
    return decode_result;
  } else{
    decoded += decode_result;
  }
  return decoded;
}

