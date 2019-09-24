#include <stdint.h>
#include "bstrlib.h"

#define S1_UE_NETWORK_CAPABILITY_MINIMUM_LENGTH 4
#define S1_UE_NETWORK_CAPABILITY_MAXIMUM_LENGTH 15

typedef struct{
  uint8_t eea;
  uint8_t eia;
} S1UENetworkCapability;

int encode_s1_ue_network_capability ( S1UENetworkCapability s1uenetworkcapability, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;
int decode_s1_ue_network_capability ( S1UENetworkCapability * s1uenetworkcapability, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;

