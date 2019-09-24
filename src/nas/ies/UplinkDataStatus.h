#include <stdint.h>
#include "bstrlib.h"

#define UPLINK_DATA_STATUS_MINIMUM_LENGTH 4
#define UPLINK_DATA_STATUS_MAXIMUM_LENGTH 34

typedef uint16_t UplinkDataStatus;

int encode_uplink_data_status ( UplinkDataStatus uplinkdatastatus, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;
int decode_uplink_data_status ( UplinkDataStatus * uplinkdatastatus, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;

