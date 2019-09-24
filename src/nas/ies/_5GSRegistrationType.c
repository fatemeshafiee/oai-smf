#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>

#include "TLVEncoder.h"
#include "TLVDecoder.h"
#include "_5GSRegistrationType.h"

int encode__5gs_registration_type ( _5GSRegistrationType * _5gsregistrationtype, uint8_t iei, uint8_t * buffer, uint32_t len  ) 
{
    uint32_t encoded = 0;
    
    CHECK_PDU_POINTER_AND_LENGTH_ENCODER (buffer,_5GS_REGISTRATION_TYPE_MINIMUM_LENGTH , len);
    uint8_t registration_type = 0;
    if(_5gsregistrationtype->is_for)
      registration_type |= 0x08;

    registration_type |= _5gsregistrationtype->registration_type & 0x07;
    ENCODE_U8(buffer,registration_type,encoded);

    return encoded;
}

int decode__5gs_registration_type ( _5GSRegistrationType * _5gsregistrationtype, uint8_t iei, uint8_t * buffer, uint32_t len  ) 
{
    int decoded=0;
    uint8_t registration_type = 0;

    DECODE_U8(buffer,registration_type,decoded);
	//if(!(registration_type & 0x80))
    if(!(registration_type & 0x08))
      _5gsregistrationtype->is_for = false;
    else
      _5gsregistrationtype->is_for = true;
    _5gsregistrationtype->registration_type = registration_type & 0x07;
    

    return decoded;
}

