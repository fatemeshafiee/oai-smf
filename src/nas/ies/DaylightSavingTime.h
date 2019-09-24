#include <stdint.h>
#include "bstrlib.h"

#define DAYLIGHT_SAVING_TIME_MINIMUM_LENGTH 3
#define DAYLIGHT_SAVING_TIME_MAXIMUM_LENGTH 3

typedef bstring DaylightSavingTime;

int encode_daylight_saving_time ( DaylightSavingTime daylightsavingtime, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;
int decode_daylight_saving_time ( DaylightSavingTime * daylightsavingtime, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;

