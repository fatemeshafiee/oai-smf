#include <stdint.h>
#include "bstrlib.h"
#include <stdbool.h>


#define _5GS_REGISTRATION_TYPE_MINIMUM_LENGTH 1
#define _5GS_REGISTRATION_TYPE_MAXIMUM_LENGTH 1

#define NO_FOLLOW_ON_REQUEST_PENDING 0
#define FOLLOW_ON_REQUEST_PENDING    1
#define INITIAL_REGISTRATION         0b001
#define MOBILITY_REGISTRATION_UPDATING 0b010
#define PERIODIC_REGISTRATION_UPDATING 0b011
#define EMERGENCY_REGISTRATION 0b100

typedef struct{
  bool is_for;
  uint8_t registration_type;
} _5GSRegistrationType;

int encode__5gs_registration_type ( _5GSRegistrationType * _5gsregistrationtype, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;
int decode__5gs_registration_type ( _5GSRegistrationType * _5gsregistrationtype, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;

