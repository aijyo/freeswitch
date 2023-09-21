#pragma once
#ifndef __X_AUTH_HTTPS_H__
#define __X_AUTH_HTTPS_H__

#include <switch.h>
#include <curl/curl.h>

switch_status_t curl_initialize(long flags);
switch_status_t curl_uninitialize();

const char* auth_session_create(switch_core_session_t* session, const char* clientId);
switch_status_t auth_conference_join(switch_core_session_t* session, const char* str_account
	, const char* str_passwd, const char* token);

#endif