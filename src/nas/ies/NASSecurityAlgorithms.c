#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>

#include "TLVEncoder.h"
#include "TLVDecoder.h"
#include "NASSecurityAlgorithms.h"

int encode_nas_security_algorithms ( NASSecurityAlgorithms nassecurityalgorithms, uint8_t iei, uint8_t * buffer, uint32_t len  ) 
{
    uint8_t encoded = 0;
    uint8_t selectedAlgorithm = 0x0;
    CHECK_PDU_POINTER_AND_LENGTH_ENCODER (buffer,NAS_SECURITY_ALGORITHMS_MINIMUM_LENGTH , len);
    
    if( iei >0  ){
      *buffer=iei;
      encoded++;
    }

    selectedAlgorithm = (nassecurityalgorithms.typeOfCipheringAlgorithm << 4) | (nassecurityalgorithms.typeOfIntegrityProtectionAlgorithm);
    ENCODE_U8(buffer+encoded,selectedAlgorithm,encoded);
    
    return encoded;
}

int decode_nas_security_algorithms ( NASSecurityAlgorithms * nassecurityalgorithms, uint8_t iei, uint8_t * buffer, uint32_t len  ) 
{
    int decoded=0;
    uint8_t selectedAlgorithm = 0x0;	

    if (iei > 0)
    {
        CHECK_IEI_DECODER (iei, *buffer);
        decoded++;
    }

    DECODE_U8(buffer+decoded,selectedAlgorithm,decoded);
    nassecurityalgorithms->typeOfCipheringAlgorithm = ((selectedAlgorithm & 0xf0)>>4);
    nassecurityalgorithms->typeOfIntegrityProtectionAlgorithm = (selectedAlgorithm & 0x0f);

    return decoded;
}

