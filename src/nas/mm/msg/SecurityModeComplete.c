#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "TLVEncoder.h"
#include "TLVDecoder.h"
#include "SecurityModeComplete.h"

int decode_security_mode_complete( security_mode_complete_msg *security_mode_complete, uint8_t* buffer, uint32_t len)
{
    uint32_t decoded = 0;
    int decoded_result = 0;

    // Check if we got a NULL pointer and if buffer length is >= minimum length expected for the message.
    CHECK_PDU_POINTER_AND_LENGTH_DECODER (buffer, SECURITY_MODE_COMPLETE_MINIMUM_LENGTH, len);

    while(len-decoded>0){
      uint8_t ieiDecoded = *(buffer+decoded);
      if(!ieiDecoded)
        break;
      switch(ieiDecoded){
        case SECURITY_MODE_COMPLETE_NAS_MESSAGE_CONTAINER_IEI:
          if((decoded_result = decode_nas_message_container (&security_mode_complete->nasmessagecontainer, SECURITY_MODE_COMPLETE_NAS_MESSAGE_CONTAINER_IEI, buffer+decoded,len-decoded))<0)
            return decoded_result;
          else{
            decoded+=decoded_result;
            security_mode_complete->presence |= SECURITY_MODE_COMPLETE_NAS_MESSAGE_CONTAINER_PRESENT;
          }
        break;
      }
    }
/*
    if((decoded_result = decode__5gs_mobile_identity (&security_mode_complete->_5gsmobileidentity, 0, buffer+decoded,len-decoded))<0)
        return decoded_result;
    else
        decoded+=decoded_result;

    if((decoded_result = decode_nas_message_container (&security_mode_complete->nasmessagecontainer, 0, buffer+decoded,len-decoded))<0)
        return decoded_result;
    else
        decoded+=decoded_result;
*/

    return decoded;
}


int encode_security_mode_complete( security_mode_complete_msg *security_mode_complete, uint8_t* buffer, uint32_t len)
{
    uint32_t encoded = 0;
    int encoded_result = 0;
    
    // Check if we got a NULL pointer and if buffer length is >= minimum length expected for the message.
    CHECK_PDU_POINTER_AND_LENGTH_ENCODER (buffer, SECURITY_MODE_COMPLETE_MINIMUM_LENGTH, len);
/*
    if((encoded_result = encode__5gs_mobile_identity (security_mode_complete->_5gsmobileidentity, 0, buffer+encoded,len-encoded))<0)
        return encoded_result;
    else
        encoded+=encoded_result;
*/
    if((security_mode_complete->presence & SECURITY_MODE_COMPLETE_NAS_MESSAGE_CONTAINER_PRESENT)
       ==SECURITY_MODE_COMPLETE_NAS_MESSAGE_CONTAINER_PRESENT){
      if((encoded_result = encode_nas_message_container (security_mode_complete->nasmessagecontainer, SECURITY_MODE_COMPLETE_NAS_MESSAGE_CONTAINER_IEI, buffer+encoded,len-encoded))<0)
        return encoded_result;
      else
        encoded+=encoded_result;
    }


    return encoded;
}
