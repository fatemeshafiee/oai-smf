#include <stdint.h>
#include "bstrlib.h"

#define TIME_ZONE_MINIMUM_LENGTH 2
#define TIME_ZONE_MAXIMUM_LENGTH 2

typedef bstring TimeZone;

int encode_time_zone ( TimeZone timezone, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;
int decode_time_zone ( TimeZone * timezone, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;

