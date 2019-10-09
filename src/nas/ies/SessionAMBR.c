#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>

#include "TLVEncoder.h"
#include "TLVDecoder.h"
#include "SessionAMBR.h"

int encode_session_ambr ( SessionAMBR sessionambr, uint8_t iei, uint8_t * buffer, uint32_t len  ) 
{
    uint8_t *lenPtr = NULL;
    uint32_t encoded = 0;
    int encode_result;
    CHECK_PDU_POINTER_AND_LENGTH_ENCODER (buffer,SESSION_AMBR_MINIMUM_LENGTH , len);
    
	if( iei >0  )
	{
		*buffer=iei;
		encoded++;
	}

    lenPtr = (buffer + encoded);
    encoded++;

	ENCODE_U8(buffer+encoded,sessionambr.uint_for_session_ambr_for_downlink,encoded);
	ENCODE_U8(buffer+encoded,(uint8_t)(sessionambr.session_ambr_for_downlink&0x00ff),encoded);
	ENCODE_U8(buffer+encoded,(uint8_t)(sessionambr.session_ambr_for_downlink&0xff00),encoded);
	ENCODE_U8(buffer+encoded,sessionambr.uint_for_session_ambr_for_uplink,encoded);
	ENCODE_U8(buffer+encoded,(uint8_t)(sessionambr.session_ambr_for_uplink&0x00ff),encoded);
	ENCODE_U8(buffer+encoded,(uint8_t)(sessionambr.session_ambr_for_uplink&0xff00),encoded);

    *lenPtr = encoded - 1 - ((iei > 0) ? 1 : 0);
	
    return encoded;
}

int decode_session_ambr ( SessionAMBR * sessionambr, uint8_t iei, uint8_t * buffer, uint32_t len  ) 
{
	int decoded=0;
	uint8_t ielen=0;
	uint8_t bit8Stream = 0;
	uint16_t bit16Stream = 0;

    if (iei > 0)
    {
        CHECK_IEI_DECODER (iei, *buffer);
        decoded++;
    }

    ielen = *(buffer + decoded);
    decoded++;
    CHECK_LENGTH_DECODER (len - decoded, ielen);


	DECODE_U8(buffer+decoded,bit8Stream,decoded);
	sessionambr->uint_for_session_ambr_for_downlink = bit8Stream;

	DECODE_U8(buffer+decoded,bit8Stream,decoded);
	bit16Stream = (uint16_t)bit8Stream & 0xff;
	DECODE_U8(buffer+decoded,bit8Stream,decoded);
	bit16Stream |= (uint16_t)(bit8Stream << 8);
	sessionambr->session_ambr_for_downlink = bit16Stream;

	DECODE_U8(buffer+decoded,bit8Stream,decoded);
	sessionambr->uint_for_session_ambr_for_uplink = bit8Stream;

	DECODE_U8(buffer+decoded,bit8Stream,decoded);
	bit16Stream = (uint16_t)bit8Stream & 0xff;
	DECODE_U8(buffer+decoded,bit8Stream,decoded);
	bit16Stream |= (uint16_t)(bit8Stream << 8);
	sessionambr->session_ambr_for_uplink = bit16Stream;

	return decoded;
}

