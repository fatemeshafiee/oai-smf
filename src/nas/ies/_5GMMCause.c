#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>

#include "TLVEncoder.h"
#include "TLVDecoder.h"
#include "_5GMMCause.h"

int encode__5gmm_cause ( _5GMMCause  _5gmmcause, uint8_t iei, uint8_t * buffer, uint32_t len  ) 
{
  uint32_t                                encoded = 0;

  /*
   * Checking IEI and pointer
   */
  CHECK_PDU_POINTER_AND_LENGTH_ENCODER (buffer, _5GMM_CAUSE_MINIMUM_LENGTH, len);

  if (iei > 0) {
    *buffer = iei;
    encoded++;
  }

  *(buffer + encoded) = _5gmmcause;
  encoded++;
  return encoded;
}

int decode__5gmm_cause ( _5GMMCause * _5gmmcause, uint8_t iei, uint8_t * buffer, uint32_t len  ) 
{
  int                                     decoded = 0;

  if (iei > 0) {
    CHECK_IEI_DECODER (iei, *buffer);
    decoded++;
  }

  *_5gmmcause = *(buffer + decoded);
  decoded++;
  return decoded;
}

