#ifndef NAS_KEY_SET_IDENTIFIER_H_
#define NAS_KEY_SET_IDENTIFIER_H_


#include <stdint.h>
#include "bstrlib.h"

#define NAS_KEY_SET_IDENTIFIER_MINIMUM_LENGTH 1
#define NAS_KEY_SET_IDENTIFIER_MAXIMUM_LENGTH 1

typedef struct nasKeySetIdentifier {
#define NAS_KEY_SET_IDENTIFIER_NATIVE 0
#define NAS_KEY_SET_IDENTIFIER_MAPPED 1   
  uint8_t  tsc:1; //type of security context flag                       
#define NAS_KEY_SET_IDENTIFIER_NOT_AVAILABLE 0b111
  uint8_t  naskeysetidentifier:3;         
} NASKeySetIdentifier;

int encode_nas_key_set_identifier ( NASKeySetIdentifier * naskeysetidentifier, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;
int encode_u8_nas_key_set_identifier (NASKeySetIdentifier * naskeysetidentifier) ;
int decode_nas_key_set_identifier ( NASKeySetIdentifier * naskeysetidentifier, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;
int decode_u8_nas_key_set_identifier(NASKeySetIdentifier*naskeysetidentifier, uint8_t iei, uint8_t value, uint32_t len);

#endif
