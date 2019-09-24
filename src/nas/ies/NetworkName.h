#include <stdint.h>
#include "bstrlib.h"

#define NETWORK_NAME_MINIMUM_LENGTH 3
#define NETWORK_NAME_MAXIMUM_LENGTH 9999

typedef bstring NetworkName;

int encode_network_name ( NetworkName networkname, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;
int decode_network_name ( NetworkName * networkname, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;

