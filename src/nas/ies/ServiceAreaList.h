#ifndef _SERVICE_AREA_LIST_H_
#define _SERVICE_AREA_LIST_H_

#include <stdint.h>
#include "bstrlib.h"
#include "_5GSTrackingAreaIdentityList.h"
#include <stdbool.h>

#define SERVICE_AREA_LIST_MINIMUM_LENGTH 6
#define SERVICE_AREA_LIST_MAXIMUM_LENGTH 114

#define ALL_TAIS_BELONGING_TO_THE_PLMNS_IN_THE_REGISTRATION_AREA_ARE_IN_THE_ALLOWED_AREA 0b11

struct PartialServiceAreaList{
  bool is_allowed;
  uint8_t typeOfList;
  uint8_t numberOfElements;
  struct MccMnc * mcc_mnc;
  struct TrackingAreaIdentity *tai;
  struct PartialServiceAreaList * next;
};

typedef struct{
  int listSize;
  struct PartialServiceAreaList * partialServiceAreaList;
} ServiceAreaList;

int encode_service_area_list ( ServiceAreaList servicearealist, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;
int decode_service_area_list ( ServiceAreaList * servicearealist, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;

#endif
