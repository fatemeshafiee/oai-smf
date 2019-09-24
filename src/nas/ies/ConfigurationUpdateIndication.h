#include <stdint.h>
#include "bstrlib.h"

#define CONFIGURATION_UPDATE_INDICATION_MINIMUM_LENGTH 1
#define CONFIGURATION_UPDATE_INDICATION_MAXIMUM_LENGTH 1

typedef bstring ConfigurationUpdateIndication;

int encode_configuration_update_indication ( ConfigurationUpdateIndication configurationupdateindication, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;
int decode_configuration_update_indication ( ConfigurationUpdateIndication * configurationupdateindication, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;

