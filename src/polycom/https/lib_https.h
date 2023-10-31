
#ifndef __POLYCOM_HTTPS_H
#define __POLYCOM_HTTPS_H
#include <switch.h>
#include <curl/curl.h>
#include "./lib_types.h"

//SWITCH_DECLARE(switch_bool_t) polycom_htts_init(const PolycomInitParam* param);
//SWITCH_DECLARE(switch_bool_t) polycom_htts_create(const PolycomCreateParam* param, PolycomCreateResult* result);
//SWITCH_DECLARE(switch_bool_t) polycom_htts_join(const PolycomJoinParam* param, PolycomJoinResult* result);
//SWITCH_DECLARE(switch_bool_t) polycom_https_destroy(void);
//


SWITCH_BEGIN_EXTERN_C

switch_status_t polycom_htts_init(const PolycomInitParam* param);
switch_status_t polycom_htts_create(const PolycomCreateParam* param, PolycomCreateResult* result);
switch_status_t polycom_htts_join(const PolycomJoinParam* param, PolycomJoinResult* result);
switch_status_t polycom_https_destroy(void);

SWITCH_END_EXTERN_C
#endif
