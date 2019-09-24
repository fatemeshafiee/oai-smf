#include <stdint.h>
#include "bstrlib.h"

#define PAYLOAD_CONTAINER_TYPE_MINIMUM_LENGTH 1
#define PAYLOAD_CONTAINER_TYPE_MAXIMUM_LENGTH 1

typedef uint8_t PayloadContainerType;

int encode_payload_container_type ( PayloadContainerType payloadcontainertype, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;
int decode_payload_container_type ( PayloadContainerType * payloadcontainertype, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;

