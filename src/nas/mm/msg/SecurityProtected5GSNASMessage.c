#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "TLVEncoder.h"
#include "TLVDecoder.h"
#include "SecurityProtected5GSNASMessage.h"

int decode_security_protected5_gsnas_message( security_protected5_gsnas_message_msg *security_protected5_gsnas_message, uint8_t* buffer, uint32_t len)
{
    uint32_t decoded = 0;
    int decoded_result = 0;

    // Check if we got a NULL pointer and if buffer length is >= minimum length expected for the message.
    CHECK_PDU_POINTER_AND_LENGTH_DECODER (buffer, SECURITY_PROTECTED5_GSNAS_MESSAGE_MINIMUM_LENGTH, len);

    if((decoded_result = decode_extended_protocol_discriminator (&security_protected5_gsnas_message->extendedprotocoldiscriminator, 0, buffer+decoded,len-decoded))<0)
        return decoded_result;
    else
        decoded+=decoded_result;

    if((decoded_result = decode_security_header_type (&security_protected5_gsnas_message->securityheadertype, 0, buffer+decoded,len-decoded))<0)
        return decoded_result;
    else
        decoded+=decoded_result;

    if((decoded_result = decode_message_authentication_code (&security_protected5_gsnas_message->messageauthenticationcode, 0, buffer+decoded,len-decoded))<0)
        return decoded_result;
    else
        decoded+=decoded_result;

    if((decoded_result = decode_sequence_number (&security_protected5_gsnas_message->sequencenumber, 0, buffer+decoded,len-decoded))<0)
        return decoded_result;
    else
        decoded+=decoded_result;

    if((decoded_result = decode_plain_5gsnas_message (&security_protected5_gsnas_message->plain5gsnasmessage, 0, buffer+decoded,len-decoded))<0)
        return decoded_result;
    else
        decoded+=decoded_result;


    return decoded;
}


int encode_security_protected5_gsnas_message( security_protected5_gsnas_message_msg *security_protected5_gsnas_message, uint8_t* buffer, uint32_t len)
{
    uint32_t encoded = 0;
    int encoded_result = 0;
    
    // Check if we got a NULL pointer and if buffer length is >= minimum length expected for the message.
    CHECK_PDU_POINTER_AND_LENGTH_ENCODER (buffer, SECURITY_PROTECTED5_GSNAS_MESSAGE_MINIMUM_LENGTH, len);

    if((encoded_result = encode_extended_protocol_discriminator (security_protected5_gsnas_message->extendedprotocoldiscriminator, 0, buffer+encoded,len-encoded))<0)
        return encoded_result;
    else
        encoded+=encoded_result;

    if((encoded_result = encode_security_header_type (security_protected5_gsnas_message->securityheadertype, 0, buffer+encoded,len-encoded))<0)
        return encoded_result;
    else
        encoded+=encoded_result;

    if((encoded_result = encode_message_authentication_code (security_protected5_gsnas_message->messageauthenticationcode, 0, buffer+encoded,len-encoded))<0)
        return encoded_result;
    else
        encoded+=encoded_result;

    if((encoded_result = encode_sequence_number (security_protected5_gsnas_message->sequencenumber, 0, buffer+encoded,len-encoded))<0)
        return encoded_result;
    else
        encoded+=encoded_result;

    if((encoded_result = encode_plain_5gsnas_message (security_protected5_gsnas_message->plain5gsnasmessage, 0, buffer+encoded,len-encoded))<0)
        return encoded_result;
    else
        encoded+=encoded_result;


    return encoded;
}
