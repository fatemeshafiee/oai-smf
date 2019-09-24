#include <stdint.h>
#include "bstrlib.h"

#define NETWORK_SLICING_INFORMATION_MINIMUM_LENGTH 1
#define NETWORK_SLICING_INFORMATION_MAXIMUM_LENGTH 1

typedef bstring NetworkSlicingInformation;

int encode_network_slicing_information ( NetworkSlicingInformation networkslicinginformation, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;
int decode_network_slicing_information ( NetworkSlicingInformation * networkslicinginformation, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;

