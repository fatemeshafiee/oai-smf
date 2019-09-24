#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>

#include "TLVEncoder.h"
#include "TLVDecoder.h"
#include "_5GSUpdateType.h"

int encode__5gs_update_type ( _5GSUpdateType _5gsupdatetype, uint8_t iei, uint8_t * buffer, uint32_t len  ) 
{

    uint8_t *lenPtr;
    uint32_t encoded = 0;
    int encode_result;
    CHECK_PDU_POINTER_AND_LENGTH_ENCODER (buffer,_5GS_UPDATE_TYPE_MINIMUM_LENGTH , len);
    
    if( iei >0  ){
      *buffer=iei;
      encoded++;
    }

    lenPtr = (buffer + encoded);
    encoded++;

    ENCODE_U8(buffer+encoded, _5gsupdatetype.ng_ran_rcu, encoded);
    ENCODE_U8(buffer+encoded, _5gsupdatetype.sms_requested,  encoded);

    *lenPtr = encoded - 1 - ((iei > 0) ? 1 : 0);    
    return encoded;

    #if 0
    uint8_t *lenPtr;
    uint32_t encoded = 0;
    uint8_t bitStream = 0x0;
    CHECK_PDU_POINTER_AND_LENGTH_ENCODER (buffer,_5GS_UPDATE_TYPE_MINIMUM_LENGTH , len);
    
    if( iei >0 ){
      *buffer=iei;
      encoded++;
    }
    
    lenPtr = (buffer + encoded);
    encoded++;

    bitStream |= ((_5gsupdatetype.ng_ran_rcu&0x01)<<1);
    bitStream |= (_5gsupdatetype.sms_requested&0x01); 
    ENCODE_U8(buffer+encoded,bitStream,encoded);

    *lenPtr = encoded - 1 - ((iei > 0) ? 1 : 0);    
    return encoded;
	#endif
}

int decode__5gs_update_type ( _5GSUpdateType * _5gsupdatetype, uint8_t iei, uint8_t * buffer, uint32_t len  ) 
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
    CHECK_LENGTH_DECODER (len - decoded, ielen);

    DECODE_U8(buffer+decoded, _5gsupdatetype->ng_ran_rcu, decoded);
    DECODE_U8(buffer+decoded, _5gsupdatetype->sms_requested,  decoded);
	return decoded;
	
    #if 0
    int decoded=0;
    uint8_t ielen=0;
    uint8_t bitStream = 0x0;
	
	
    if (iei > 0)
    {
        CHECK_IEI_DECODER (iei, *buffer);
        decoded++;
    }
    
    ielen = *(buffer + decoded);
    decoded++;
    CHECK_LENGTH_DECODER (len - decoded, ielen);
    DECODE_U8(buffer+decoded,bitStream,decoded);
	
    _5gsupdatetype->ng_ran_rcu = bitStream&0x02;
    _5gsupdatetype->sms_requested = bitStream&0x01;
    return decoded;
    #endif
}

