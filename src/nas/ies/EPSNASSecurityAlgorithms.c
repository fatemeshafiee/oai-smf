#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>

#include "TLVEncoder.h"
#include "TLVDecoder.h"
#include "EPSNASSecurityAlgorithms.h"

int encode_epsnas_security_algorithms ( EPSNASSecurityAlgorithms epsnassecurityalgorithms, uint8_t iei, uint8_t * buffer, uint32_t len  ) 
{
    uint32_t encoded = 0;
    uint8_t securityAlgorithm = 0x0;
    CHECK_PDU_POINTER_AND_LENGTH_ENCODER (buffer,EPSNAS_SECURITY_ALGORITHMS_MINIMUM_LENGTH , len);
    
    if( iei >0  ){
      *buffer=iei;
      encoded++;
    }

    securityAlgorithm = ((epsnassecurityalgorithms.typeOfCipheringAlgoithm)<<4) | (epsnassecurityalgorithms.typeOfIntegrityProtectionAlgoithm);
    ENCODE_U8(buffer+encoded,securityAlgorithm,encoded);

    return encoded;
}

int decode_epsnas_security_algorithms ( EPSNASSecurityAlgorithms * epsnassecurityalgorithms, uint8_t iei, uint8_t * buffer, uint32_t len  ) 
{
    int decoded=0;
    uint8_t securityAlgorithm = 0x0;;

    if (iei > 0)
    {
        CHECK_IEI_DECODER (iei, *buffer);
        decoded++;
    }

    DECODE_U8(buffer+decoded,securityAlgorithm,decoded);
    epsnassecurityalgorithms->typeOfCipheringAlgoithm = ((securityAlgorithm&0x70)>>4);
    epsnassecurityalgorithms->typeOfIntegrityProtectionAlgoithm = (securityAlgorithm&0x07);
  
    return decoded;
}

