#include <stdint.h>
#include "bstrlib.h"
#include <stdbool.h>

#define _5GMM_CAPABILITY_MINIMUM_LENGTH 3
#define _5GMM_CAPABILITY_MAXIMUM_LENGTH 15

#define S1_MODE_NOT_SUPPORTED 0
#define S1_MODE_SUPPORTED     1
#define HANDEROVER_TRANSFER_PDU_SESSION_NOT_SUPPORTED 0
#define HANDEROVER_TRANSFER_PDU_SESSION_SUPPORTED     1
#define LPP_IN_N1_MODE_NOT_SUPPORTED 0
#define LPP_IN_N1_MODE_SUPPORTED 1

typedef struct{
  bool is_LPP_supported;
  bool is_HO_supported;
  bool is_S1_mode_supported;
} _5GMMCapability;

int encode__5gmm_capability ( _5GMMCapability _5gmmcapability, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;
int decode__5gmm_capability ( _5GMMCapability * _5gmmcapability, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;

