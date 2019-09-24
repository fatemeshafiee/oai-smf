#include <stdint.h>
#include "bstrlib.h"

#define _5GS_UPDATE_TYPE_MINIMUM_LENGTH 3
#define _5GS_UPDATE_TYPE_MAXIMUM_LENGTH 3

#define SMS_OVER_NAS_NOT_SUPPORTED 0
#define SMS_OVER_NAS_SUPPORTED 1

#define NG_RAN_RADIO_CAPABILITY_UPDATE_NOT_NEEDED 0
#define NG_RAN_RADIO_CAPABILITY_UPDATE_NEEDED 1

typedef struct{
  uint8_t ng_ran_rcu;
  uint8_t sms_requested;
} _5GSUpdateType;

int encode__5gs_update_type ( _5GSUpdateType _5gsupdatetype, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;
int decode__5gs_update_type ( _5GSUpdateType * _5gsupdatetype, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;

