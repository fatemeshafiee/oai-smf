#include <stdint.h>
#include "bstrlib.h"

#define _5GMM_CAUSE_MINIMUM_LENGTH 2
#define _5GMM_CAUSE_MAXIMUM_LENGTH 2

typedef uint8_t _5GMMCause;

int encode__5gmm_cause ( _5GMMCause  _5gmmcause, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;
int decode__5gmm_cause ( _5GMMCause * _5gmmcause, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;

