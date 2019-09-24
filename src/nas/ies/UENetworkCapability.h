#include <stdint.h>
#include "bstrlib.h"

#define UE_NETWORK_CAPABILITY_MINIMUM_LENGTH 4
#define UE_NETWORK_CAPABILITY_MAXIMUM_LENGTH 15

typedef bstring UENetworkCapability;

int encode_ue_network_capability ( UENetworkCapability uenetworkcapability, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;
int decode_ue_network_capability ( UENetworkCapability * uenetworkcapability, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;

