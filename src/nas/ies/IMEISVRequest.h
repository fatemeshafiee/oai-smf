#include <stdint.h>
#include "bstrlib.h"

#define IMEISV_REQUEST_MINIMUM_LENGTH 1
#define IMEISV_REQUEST_MAXIMUM_LENGTH 1

#define SECURITY_MODE_COMMAND_IMEISV_NOT_REQUESTED 0b000
#define SECURITY_MODE_COMMAND_IMEISV_REQUESTED 0b001

typedef uint8_t IMEISVRequest;

int encode_imeisv_request ( IMEISVRequest imeisvrequest, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;
int decode_imeisv_request ( IMEISVRequest * imeisvrequest, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;

