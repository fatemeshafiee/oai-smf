#include <stdint.h>
#include "bstrlib.h"

#define OPERATOR_DEFINED_ACCESS_CATEGORY_DEFINITIONS_MINIMUM_LENGTH 3
#define OPERATOR_DEFINED_ACCESS_CATEGORY_DEFINITIONS_MAXIMUM_LENGTH 9999

typedef bstring OperatorDefinedAccessCategoryDefinitions;

int encode_operator_defined_access_category_definitions ( OperatorDefinedAccessCategoryDefinitions operatordefinedaccesscategorydefinitions, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;
int decode_operator_defined_access_category_definitions ( OperatorDefinedAccessCategoryDefinitions * operatordefinedaccesscategorydefinitions, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;

