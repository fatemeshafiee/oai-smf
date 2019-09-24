#include <stdint.h>
#include "bstrlib.h"

#define UES_USAGE_SETTING_MINIMUM_LENGTH 3
#define UES_USAGE_SETTING_MAXIMUM_LENGTH 3

#define VOICE_CENTRIC 0
#define DATA_CENTRIC  1

typedef uint8_t UESUsageSetting;

int encode_ues_usage_setting ( UESUsageSetting uesusagesetting, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;
int decode_ues_usage_setting ( UESUsageSetting * uesusagesetting, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;

