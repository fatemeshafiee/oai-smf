#include <stdint.h>
#include "bstrlib.h"

#define _5GSDRX_PARAMETERS_MINIMUM_LENGTH 3
#define _5GSDRX_PARAMETERS_MAXIMUM_LENGTH 3

#define DRX_VALUE_NOT_SPECIFIED 0b0000
#define DRX_CYCLE_PARAMETER_T_32 0b0001
#define DRX_CYCLE_PARAMETER_T_64 0b0010
#define DRX_CYCLE_PARAMETER_T_128 0b0011
#define DRX_CYCLE_PARAMETER_T_256 0b0100

typedef uint8_t _5GSDRXParameters;

int encode__5gsdrx_parameters ( _5GSDRXParameters _5gsdrxparameters, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;
int decode__5gsdrx_parameters ( _5GSDRXParameters * _5gsdrxparameters, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;

