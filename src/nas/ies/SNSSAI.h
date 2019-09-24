#ifndef _SNSSAI_H_
#define _SNSSAI_H_

#include <stdint.h>
#include "bstrlib.h"

#define SNSSAI_MINIMUM_LENGTH 3
#define SNSSAI_MAXIMUM_LENGTH 10

typedef struct{
  uint8_t iei;
  uint8_t len;
  uint32_t snssai;
  uint32_t mapped_nssai;
} SNSSAI;

int encode_snssai ( SNSSAI snssai, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;
int decode_snssai ( SNSSAI * snssai, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;

#endif
