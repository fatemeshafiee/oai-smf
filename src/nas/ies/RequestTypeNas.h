#include <stdint.h>
#include "bstrlib.h"

#define REQUEST_TYPE_MINIMUM_LENGTH 1
#define REQUEST_TYPE_MAXIMUM_LENGTH 1

typedef bstring RequestType;

int encode_request_type ( RequestType requesttype, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;
int decode_request_type ( RequestType * requesttype, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;

