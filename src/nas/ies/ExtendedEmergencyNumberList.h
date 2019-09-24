#include <stdint.h>
#include "bstrlib.h"

#define EXTENDED_EMERGENCY_NUMBER_LIST_MINIMUM_LENGTH 6
#define EXTENDED_EMERGENCY_NUMBER_LIST_MAXIMUM_LENGTH 65538

typedef bstring ExtendedEmergencyNumberList;

int encode_extended_emergency_number_list ( ExtendedEmergencyNumberList extendedemergencynumberlist, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;
int decode_extended_emergency_number_list ( ExtendedEmergencyNumberList * extendedemergencynumberlist, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;

