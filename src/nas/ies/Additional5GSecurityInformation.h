#ifndef _ADDITIONAL_5G_SECURITY_INFORMATION_H_
#define _ADDITIONAL_5G_SECURITY_INFORMATION_H_

#include <stdint.h>
#include "bstrlib.h"
#include <stdbool.h>

#define ADDITIONAL_5G_SECURITY_INFORMATION_MINIMUM_LENGTH 3
#define ADDITIONAL_5G_SECURITY_INFORMATION_MAXIMUM_LENGTH 3

#define KAMF_DERIVATION_IS_NOT_REQUIRED 0
#define KAMF_DERIVATION_IS_REQUIRED 1

#define RETRANSMISSION_OF_THE_INITIAL_NAS_MESSAGE_NOT_REQUESTED 0
#define RETRANSMISSION_OF_THE_INITIAL_NAS_MESSAGE_REQUESTED 1

typedef struct{
  bool hdp;
  bool rinmr;
} Additional5GSecurityInformation;

int encode_additional_5g_security_information ( Additional5GSecurityInformation additional5gsecurityinformation, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;
int decode_additional_5g_security_information ( Additional5GSecurityInformation * additional5gsecurityinformation, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;

#endif
