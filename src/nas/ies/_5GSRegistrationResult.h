#include <stdint.h>
#include "bstrlib.h"
#include <stdbool.h>

#define _5GS_REGISTRATION_RESULT_MINIMUM_LENGTH 3
#define _5GS_REGISTRATION_RESULT_MAXIMUM_LENGTH 3

#define _3GPP_ACCESS 0b001
#define NON_3GPP_ACCESS 0b010
#define _3GPP_AND_NON_3GPP_ACCESS 0b011
#define SMS_OVER_NAS_NOT_ALLOWED 0
#define SMS_OVER_NAS_ALLOWED 1

typedef struct{
  bool is_SMS_allowed;
  uint8_t registration_result_value:3;
} _5GSRegistrationResult;

int encode__5gs_registration_result ( _5GSRegistrationResult _5gsregistrationresult, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;
int decode__5gs_registration_result ( _5GSRegistrationResult * _5gsregistrationresult, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;

