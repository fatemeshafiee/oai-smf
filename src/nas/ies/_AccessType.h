#include <stdint.h>
#include "bstrlib.h"

#define _ACCESS_TYPE_MINIMUM_LENGTH 1
#define _ACCESS_TYPE_MAXIMUM_LENGTH 1

typedef bstring _AccessType;

int encode__access_type ( _AccessType _accesstype, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;
int decode__access_type ( _AccessType * _accesstype, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;

