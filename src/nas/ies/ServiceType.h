#include <stdint.h>
#include "bstrlib.h"

#define SERVICE_TYPE_MINIMUM_LENGTH 1
#define SERVICE_TYPE_MAXIMUM_LENGTH 1

typedef bstring ServiceType;

int encode_service_type ( ServiceType servicetype, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;
int decode_service_type ( ServiceType * servicetype, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;

