#include <stdint.h>
#include "bstrlib.h"

#define PAYLOAD_CONTAINER_MINIMUM_LENGTH 4
#define PAYLOAD_CONTAINER_MAXIMUM_LENGTH 65538

typedef bstring PayloadContainer;

int encode_payload_container ( PayloadContainer payloadcontainer, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;
int decode_payload_container ( PayloadContainer * payloadcontainer, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;

