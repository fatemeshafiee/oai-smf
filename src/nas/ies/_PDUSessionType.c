#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>

#include "TLVEncoder.h"
#include "TLVDecoder.h"
#include "_PDUSessionType.h"



int encode__pdu_session_type ( _PDUSessionType _pdusessiontype, uint8_t iei, uint8_t * buffer, uint32_t len  ) 
{
    uint8_t *lenPtr;
    uint32_t encoded = 0;
    int encode_result;
    CHECK_PDU_POINTER_AND_LENGTH_ENCODER (buffer,_PDU_SESSION_TYPE_MINIMUM_LENGTH , len);
    





/*
    if ((encode_result = encode_bstring (_pdusessiontype, buffer + encoded, len - encoded)) < 0)//加密,实体,首地址,长度
        return encode_result;
    else
        encoded += encode_result;


    return encoded;

*/
    *(buffer + encoded) = 0x00 | (iei & 0xf0) | (_pdusessiontype & 0x7);
    encoded++;
    return encoded;

}


int decode__pdu_session_type ( _PDUSessionType * _pdusessiontype, uint8_t iei, uint8_t * buffer, uint32_t len  ) 
{
	/*
	int decoded=0;
	uint8_t ielen=0;
	int decode_result;





    if((decode_result = decode_bstring (_pdusessiontype, ielen, buffer + decoded, len - decoded)) < 0)
        return decode_result;
    else
        decoded += decode_result;
            return decoded;
*/
	  int                                     decoded = 0;

	  *_pdusessiontype = *buffer & 0x7;
	  decoded++;
	  return decoded;
}

