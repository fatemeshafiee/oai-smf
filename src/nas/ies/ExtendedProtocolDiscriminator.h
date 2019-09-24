#ifndef EXTENDED_PROTOCOL_DISCRIMINATOR_H_
#define EXTENDED_PROTOCOL_DISCRIMINATOR_H_

#include <stdint.h>
#include "bstrlib.h"

#define EXTENDED_PROTOCOL_DISCRIMINATOR_MINIMUM_LENGTH 1
#define EXTENDED_PROTOCOL_DISCRIMINATOR_MAXIMUM_LENGTH 1

typedef uint8_t  ExtendedProtocolDiscriminator;

int encode_extended_protocol_discriminator ( ExtendedProtocolDiscriminator  extendedprotocoldiscriminator, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;
int decode_extended_protocol_discriminator ( ExtendedProtocolDiscriminator * extendedprotocoldiscriminator, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;

#endif
