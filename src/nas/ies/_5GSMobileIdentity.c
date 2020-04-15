#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>

#include "TLVEncoder.h"
#include "TLVDecoder.h"
#include "_5GSMobileIdentity.h"

int encode__5gs_mobile_identity ( _5GSMobileIdentity  _5gsmobileidentity, uint8_t iei, uint8_t * buffer, uint32_t len  ) 
{
  uint8_t *lenPtr;
  uint32_t encoded = 0;

  CHECK_PDU_POINTER_AND_LENGTH_ENCODER (buffer,_5GS_MOBILE_IDENTITY_MINIMUM_LENGTH , len);

  lenPtr = (buffer + encoded);
  encoded++;
  encoded++;

  switch(_5gsmobileidentity.IdentityType){
  case _5G_GUTI:
    break;
  case IMEI:
  case IMEISV:
    break;
  case SUCI:
  case IMSI:
    break;
  }

  uint32_t res = encoded - 1 - ((iei > 0) ? 1 : 0);
  *lenPtr =res/(1<<8);
  lenPtr++;
  *lenPtr = res%(1<<8);

  return encoded;
}

int decode__5gs_mobile_identity ( _5GSMobileIdentity * _5gsmobileidentity, uint8_t iei, uint8_t * buffer, uint32_t len  ) 
{
  int decoded=0;
  uint8_t ielen=0;
  int decode_result;

  if (iei > 0)
  {
    CHECK_IEI_DECODER (iei, *buffer);
    decoded++;
  }


  ielen = *(buffer + decoded);
  decoded++;
  ielen = ( ielen << 8)+*(buffer + decoded);
  decoded++;
  CHECK_LENGTH_DECODER (len - decoded, ielen);


  if((decode_result = decode_bstring (_5gsmobileidentity, ielen, buffer + decoded, len - decoded)) < 0)
    return decode_result;
  else
    decoded += decode_result;
  return decoded;
}

