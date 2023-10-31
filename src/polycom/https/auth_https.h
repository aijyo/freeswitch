#pragma once
#ifndef __X_AUTH_HTTPS_H__
#define __X_AUTH_HTTPS_H__

#include <switch.h>
#include <curl/curl.h>

#include "./lib_types.h"

switch_status_t curl_initialize(long flags);
switch_status_t curl_uninitialize();

switch_status_t auth_session_create(const PolycomCreateParam* param, PolycomCreateResult* out, const char* macUrl);
switch_status_t auth_conference_join(const PolycomJoinParam* param, PolycomJoinResult* out, const char* macUrl);

#endif