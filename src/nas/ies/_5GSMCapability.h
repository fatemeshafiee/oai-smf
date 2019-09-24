#include <stdint.h>
#include "bstrlib.h"

#define _5GSM_CAPABILITY_MINIMUM_LENGTH 3
#define _5GSM_CAPABILITY_MAXIMUM_LENGTH 15

typedef bstring _5GSMCapability;

int encode__5gsm_capability ( _5GSMCapability _5gsmcapability, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;
int decode__5gsm_capability ( _5GSMCapability * _5gsmcapability, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;

