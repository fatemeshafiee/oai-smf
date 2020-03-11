#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>

#include "TLVEncoder.h"
#include "TLVDecoder.h"
#include "PDUSessionIdentity.h"

int encode_pdu_session_identity ( PDUSessionIdentity pdusessionidentity, uint8_t iei, uint8_t * buffer, uint32_t len  ) 
{
  uint32_t encoded = 0;
  int encode_result;
  CHECK_PDU_POINTER_AND_LENGTH_ENCODER (buffer,PDU_SESSION_IDENTITY_MINIMUM_LENGTH , len);

  if ((encode_result = encode_bstring (pdusessionidentity, buffer + encoded, len - encoded)) < 0)//加密,实体,首地址,长度
    return encode_result;
  else
    encoded += encode_result;

  return encoded;
}

int decode_pdu_session_identity ( PDUSessionIdentity * pdusessionidentity, uint8_t iei, uint8_t * buffer, uint32_t len  ) 
{
  int decoded=0;
  uint8_t ielen=0;
  int decode_result;

  if((decode_result = decode_bstring (pdusessionidentity, ielen, buffer + decoded, len - decoded)) < 0)
    return decode_result;
  else
    decoded += decode_result;
  return decoded;
}

