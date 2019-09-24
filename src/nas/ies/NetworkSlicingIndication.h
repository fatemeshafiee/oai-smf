#ifndef _NETWORK_SLICING_INDICATION_H_
#define _NETWORK_SLICING_INDICATION_H_

#include <stdint.h>
#include "bstrlib.h"

#define NETWORK_SLICING_INDICATION_MINIMUM_LENGTH 1
#define NETWORK_SLICING_INDICATION_MAXIMUM_LENGTH 1

typedef struct{
  uint8_t dcni:1;
  uint8_t nssci:1;
} NetworkSlicingIndication;

int encode_network_slicing_indication ( NetworkSlicingIndication networkslicingindication, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;
int decode_network_slicing_indication ( NetworkSlicingIndication * networkslicingindication, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;

#endif

