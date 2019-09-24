#ifndef _UE_SECURITY_CAPABILITY_H_
#define _UE_SECURITY_CAPABILITY_H_

#include <stdint.h>
#include "bstrlib.h"
#include <stdbool.h>

#define UE_SECURITY_CAPABILITY_MINIMUM_LENGTH 4
#define UE_SECURITY_CAPABILITY_MAXIMUM_LENGTH 10

typedef struct{
  uint8_t nea;
  uint8_t nia;
} UESecurityCapability;

int encode_ue_security_capability ( UESecurityCapability uesecuritycapability, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;
int decode_ue_security_capability ( UESecurityCapability * uesecuritycapability, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;

#endif
