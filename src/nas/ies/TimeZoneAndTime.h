#include <stdint.h>
#include "bstrlib.h"

#define TIME_ZONE_AND_TIME_MINIMUM_LENGTH 8
#define TIME_ZONE_AND_TIME_MAXIMUM_LENGTH 8

typedef bstring TimeZoneAndTime;

int encode_time_zone_and_time ( TimeZoneAndTime timezoneandtime, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;
int decode_time_zone_and_time ( TimeZoneAndTime * timezoneandtime, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;

