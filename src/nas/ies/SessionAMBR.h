#ifndef _SESSIONAMBR_H_
#define _SESSIONAMBR_H_

#include <stdint.h>
#include "bstrlib.h"

#define SESSION_AMBR_MINIMUM_LENGTH 8
#define SESSION_AMBR_MAXIMUM_LENGTH 8

//typedef bstring SessionAMBR;
typedef struct{
	uint8_t uint_for_session_ambr_for_downlink;
	uint16_t session_ambr_for_downlink;
	uint8_t uint_for_session_ambr_for_uplink;
	uint16_t session_ambr_for_uplink;
}SessionAMBR;


int encode_session_ambr ( SessionAMBR sessionambr, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;
int decode_session_ambr ( SessionAMBR * sessionambr, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;

#endif
