#include <stdint.h>
#include "bstrlib.h"

#define EMERGENCY_NUMBER_LIST_MINIMUM_LENGTH 5
#define EMERGENCY_NUMBER_LIST_MAXIMUM_LENGTH 50

typedef bstring EmergencyNumberList;

int encode_emergency_number_list ( EmergencyNumberList emergencynumberlist, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;
int decode_emergency_number_list ( EmergencyNumberList * emergencynumberlist, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;

