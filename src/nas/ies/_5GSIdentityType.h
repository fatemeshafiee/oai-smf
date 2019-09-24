#include <stdint.h>
#include "bstrlib.h"

#define _5GS_IDENTITY_TYPE_MINIMUM_LENGTH 1
#define _5GS_IDENTITY_TYPE_MAXIMUM_LENGTH 1

#define IDENTITY_REQUEST_SUCI 0x01
#define IDENTITY_REQUEST_5G_GUTI 0x02
#define IDENTITY_REQUEST_IMEI 0x03
#define IDENTITY_REQUEST_5G_S_TMSI 0x04
#define IDENTITY_REQUEST_IMEISV 0x05

typedef struct{
  uint8_t typeOfIdentity:3;
} _5GSIdentityType;

int encode__5gs_identity_type ( _5GSIdentityType _5gsidentitytype, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;
int decode__5gs_identity_type ( _5GSIdentityType * _5gsidentitytype, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;

