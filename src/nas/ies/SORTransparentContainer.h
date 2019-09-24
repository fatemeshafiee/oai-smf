#ifndef _SOR_TRANSPARENT_CONTAINER_H_
#define _SOR_TRANSPARENT_CONTAINER_H_

#include <stdint.h>
#include "bstrlib.h"

#define SOR_TRANSPARENT_CONTAINER_MINIMUM_LENGTH 20
#define SOR_TRANSPARENT_CONTAINER_MAXIMUM_LENGTH 2048

typedef struct{
  uint8_t sorHeader;
  
} SORTransparentContainer;

int encode_sor_transparent_container ( SORTransparentContainer sortransparentcontainer, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;
int decode_sor_transparent_container ( SORTransparentContainer * sortransparentcontainer, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;


#endif
