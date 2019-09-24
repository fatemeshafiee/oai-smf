#include <stdint.h>
#include "bstrlib.h"

#define S1_UE_SECURITY_CAPABILITY_MINIMUM_LENGTH 4
#define S1_UE_SECURITY_CAPABILITY_MAXIMUM_LENGTH 7

typedef bstring S1UESecurityCapability;

int encode_s1_ue_security_capability ( S1UESecurityCapability s1uesecuritycapability, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;
int decode_s1_ue_security_capability ( S1UESecurityCapability * s1uesecuritycapability, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;

