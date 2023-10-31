#include "auth_https.h"
//#include <switch_cJSON.h>
//#include <switch_cJSON_Utils.h>
#include <switch_curl.h>
#include <switch_json.h>
#include <libks/ks.h>

#define HTTPS_TIMEOUT_SEC (30)

#ifndef WIN32
#include <sys/utsname.h>
#endif

//#ifdef WIN32
//void sslLoadWindowsCACertificate();
//void sslUnLoadWindowsCACertificate();
//int sslContextFunction(void* curl, void* sslctx, void* userdata);
//#endif

struct response_data {
	char* data;
	size_t size;
};

static size_t response_data_handler(void* contents, size_t size, size_t nmemb, void* userp)
{
	size_t received = size * nmemb;
	struct response_data* rd = (struct response_data*)userp;

	if (!rd->data) rd->data = (char*)ks_pool_alloc(NULL, received + 1);
	else rd->data = (char*)ks_pool_resize(rd->data, rd->size + received + 1);

	memcpy(rd->data + rd->size, contents, received);
	rd->size += received;
	rd->data[rd->size] = 0;

	return received;
}

switch_status_t curl_initialize(long flags)
{
	switch_status_t result = SWITCH_STATUS_SUCCESS;

	if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) 
	{
		result = SWITCH_STATUS_FALSE;
	}

	return result;
}

switch_status_t curl_uninitialize()
{
	switch_status_t result = SWITCH_STATUS_SUCCESS;

	curl_global_cleanup();

	return result;
}

switch_status_t parse_create_json(const char* jsonstr, PolycomCreateResult* out)
{
	switch_status_t result = SWITCH_STATUS_FALSE;
	ks_json_t* json = NULL;
	do
	{

		json = ks_json_parse(jsonstr);
		if (!json)
		{
			break;
		}
		ks_bool_t suc = ks_json_get_object_bool(json, "success", KS_FALSE);
		const char* message = ks_json_get_object_string(json, "message", "");
		if (message)
		{
			//*desc = strdup(message);
			sprintf(out->desc, message, max(strlen(message), 128 - 1));
		}

		if (!suc)
		{
			break;
		}
		ks_json_t* result_obj = ks_json_get_object_item(json, "result");

		if (!result_obj)
		{
			break;
		}
		const char* token = ks_json_get_object_string(result_obj, "sessionToken", "");

		if (!token)
		{
			break;
		}

		//result = strdup(token);
		strcpy(out->token, token);
		result = SWITCH_STATUS_SUCCESS;
	} while (SWITCH_FALSE);

	if (json)
	{
		ks_json_delete(&json);
	}
	return result;
}


static switch_status_t parse_join_json(const char* jsonstr, PolycomJoinResult* out)
{
	switch_status_t result = SWITCH_STATUS_FALSE;
	ks_json_t* json = NULL;
	do
	{

		json = ks_json_parse(jsonstr);
		if (!json)
		{
			break;
		}

		ks_bool_t suc = ks_json_get_object_bool(json, "success", KS_FALSE);

		const char* message = ks_json_get_object_string(json, "message", "");
		if (message)
		{
			int len = strlen(message);
			memcpy(out->desc, message, max(len, 128 - 1));
		}

		if (!suc)
		{
			break;
		}
		ks_json_t* result_obj = ks_json_get_object_item(json, "result");

		if (!result_obj)
		{
			break;
		}
		ks_json_t* participant_obj = ks_json_get_object_item(result_obj, "participant");
		ks_json_t* rtc_obj = ks_json_get_object_item(result_obj, "rtc");

		if (!participant_obj || !rtc_obj)
		{
			break;
		}

		const char* clientId = ks_json_get_object_string(participant_obj, "clientId", "");
		const char* displayName = ks_json_get_object_string(participant_obj, "displayName", "");


		//memcpy(out->id, clientId, max(strlen(clientId), 256 - 1));
		//memcpy(out->displayName, displayName, max(strlen(displayName), 128 - 1));

		strcpy(out->id, clientId);
		strcpy(out->displayName, displayName);

		const char* meetingToken = ks_json_get_object_string(rtc_obj, "meetingToken", "");
		const char* clientToken = ks_json_get_object_string(rtc_obj, "clientToken", "");

		//memcpy(out->token, clientToken, max(strlen(clientToken), 128 - 1));
		//memcpy(out->roomToken, meetingToken, max(strlen(meetingToken), 128 - 1));
		strcpy(out->token, clientToken);
		strcpy(out->roomToken, meetingToken);

		//switch_channel_set_variable(channel, "iris_clientId", clientId);
		//switch_channel_set_variable(channel, "iris_displayName", displayName);
		//switch_channel_set_variable(channel, "iris_meetingToken", meetingToken);
		//switch_channel_set_variable(channel, "iris_clientToken", clientToken);

		result = SWITCH_STATUS_SUCCESS;
	} while (SWITCH_FALSE);

	if (json)
	{
		ks_json_delete(&json);
	}
	return result;
}
//curl - X 'POST' \
//'https://dev-one-api.whaleon.naver.com/v2/session' \
//- H 'accept: application/json' \
//- H 'Content-Type: application/json' \
//- d '{
//"clientId": "hahah"
//}'
//{
//	"success": true,
//		"message" : "SUCCESS",
//		"result" : {
//		"sessionToken": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJzdWIiOiI1NTkxZjVjYy1jZTE2LTQyYzgtODU5YS04YWQ1NThkM2I5NTciLCJpc3MiOiJ3aGFsZW9uLW9uZSIsImV4cCI6MTY5NDUxNjcwMCwiaWF0IjoxNjk0NDgwNzAwfQ.RWZrDZToTxApLa0MwRYz3b8-9wORxAGhS7KFJ-b4oGWUNpl8dCnfAlcs-Emn-1fZcxbizcznGWWhU7Q-aLprEA",
//			"expiresAt" : 1694516700000,
//			"refreshToken" : "74bbae37-7f3d-47fa-b7df-e1ad5c341b88",
//			"refreshTokenExpiresAt" : 1694523900000
//	}
//}
switch_status_t auth_session_create(const PolycomCreateParam* param, PolycomCreateResult* out, const char* macUrl)
{
	switch_status_t result = SWITCH_STATUS_FALSE;
	//const char* result = NULL;
	struct response_data rd = { 0 };
	char* jsonstr = NULL;
	char* ssl_cacert = NULL;
	switch_curl_slist_t* headers = NULL;
	char content[512] = { 0 };
	char* desc = NULL;

	switch_CURL* curl = switch_curl_easy_init();
	do
	{
		if (!param)
		{
			break;
		}

		if (!curl)
		{
			break;
		}

		sprintf(content, "{\"clientId\": \"%s\"}", param->id);
		switch_curl_easy_setopt(curl, CURLOPT_URL, macUrl);
		switch_curl_easy_setopt(curl, CURLOPT_POST, 1);

		headers = switch_curl_slist_append(headers, "Accept: application/json");
		headers = switch_curl_slist_append(headers, "Accept-Charset: utf-8");
		headers = switch_curl_slist_append(headers, "Content-Type: application/json");
		headers = switch_curl_slist_append(headers, "X-Auth-SigninType: POLYCOM");
		switch_curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

		switch_curl_easy_setopt(curl, CURLOPT_POSTFIELDS, content);

		switch_curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0); // if want to use https
		switch_curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0); // set peer and host verify false
		switch_curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);

		switch_curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, response_data_handler);
		switch_curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)&rd);
		switch_curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, HTTPS_TIMEOUT_SEC);
		switch_curl_easy_setopt(curl, CURLOPT_TIMEOUT, HTTPS_TIMEOUT_SEC);
		
		//switch_curl_easy_setopt(curl, CURLOPT_CAINFO, ssl_cacert);


		switch_CURLcode res = switch_curl_easy_perform(curl);
		if (res != CURLE_OK)
		{
			break;
		}


		long http_code = 0;
		switch_curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

		out->code = http_code;
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE,
			"create session[%s] result[%d] response[%s]\n",
			param->id, http_code, rd.data ? rd.data : "");

		if (http_code == 200)
		{
			result = parse_create_json(rd.data,out);

			if (result)
			{
				int len = strlen(desc);
				memcpy(out->desc, desc, max(len, 128 - 1));
				free(desc);
			}
		}
		else
		{
			//result = SWITCH_STATUS_FALSE;
		}


	} while (SWITCH_FALSE);

	if (headers)
	{
		curl_slist_free_all(headers);
	}

	if (curl)
	{
		switch_curl_easy_cleanup(curl);
	}

	if (rd.data)
	{
		ks_pool_free(&rd.data);
	}

	return result;
}

//curl - X 'POST' \
//'https://dev-one-api.whaleon.naver.com/v2/meetings/hahah/join' \
//- H 'accept: application/json' \
//- H 'Content-Type: application/json' \
//- d '{
//"password": "650480",
//"inviteCode" : "string",
//"displayName" : "Tremendous whale",
//"profileImageUrl" : "string",
//"overlayFrame" : "string",
//"enableBreakoutRoomsFeature" : false,
//"mediaServer" : "PK"
//}'
// 
//{
//	"success": false,
//		"message" : "SESSION_REQUIRED",
//		"result" : null
//}
//switch_status_t auth_conference_join(switch_core_session_t* session, const char* meetingId
//	, const char* str_passwd, const char* token, uint32_t* out_code, char** out_desc)
switch_status_t auth_conference_join(const PolycomJoinParam* param, PolycomJoinResult* out, const char* macUrl)
{
	switch_status_t result = SWITCH_STATUS_FALSE;
	struct response_data rd = { 0 };
	char* jsonstr = NULL;
	char content[256] = { 0 };
	char auth_header[512] = { 0 };
	switch_curl_slist_t* headers = NULL;

	switch_CURL* curl = switch_curl_easy_init();

	do
	{
		if (!param || !out)
		{
			break;
		}
		if (!curl)
		{
			break;
		}

		//const char* token = switch_channel_get_variable(channel, "auth_token");

		//const char* auth_header = switch_core_sprintf(pool, "X-Auth-Token: %s", param->token);
		//const char* content = switch_core_sprintf(pool, "{ \"password\":\"%s\", \"inviteCode\" :null, \"displayName\" : \"Tremendous whale\", \"profileImageUrl\" : \"string\", \"overlayFrame\" : \"REMOVE\", \"enableBreakoutRoomsFeature\" : false, \"mediaServer\" : \"I:1.0\" }"
		//	, str_passwd);
		sprintf(auth_header, "X-Auth-Token: %s", param->token);
		sprintf(content, "{ \"password\":\"%s\", \"inviteCode\" :null, \"displayName\" : \"Tremendous whale\", \"profileImageUrl\" : \"string\", \"overlayFrame\" : \"REMOVE\", \"enableBreakoutRoomsFeature\" : false, \"mediaServer\" : \"I:1.0\" }"
			, param->passwd);

		//ssl_cacert = switch_core_sprintf(pool, "%s%s", SWITCH_GLOBAL_dirs.certs_dir, "/cacert.pem");

		curl_easy_setopt(curl, CURLOPT_URL, macUrl);
		switch_curl_easy_setopt(curl, CURLOPT_POST, 1);

		headers = switch_curl_slist_append(headers, "Accept: application/json");
		headers = switch_curl_slist_append(headers, "Accept-Charset: utf-8");
		headers = switch_curl_slist_append(headers, "Content-Type: application/json");
		headers = switch_curl_slist_append(headers, auth_header);
		headers = switch_curl_slist_append(headers, "X-Auth-SigninType: POLYCOM");
		switch_curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

		switch_curl_easy_setopt(curl, CURLOPT_POSTFIELDS, content);

		switch_curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0); // if want to use https
		switch_curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0); // set peer and host verify false
		switch_curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);

		switch_curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, response_data_handler);
		switch_curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)&rd);
		switch_curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, HTTPS_TIMEOUT_SEC);
		switch_curl_easy_setopt(curl, CURLOPT_TIMEOUT, HTTPS_TIMEOUT_SEC);

		//switch_curl_easy_setopt(curl, CURLOPT_CAINFO, ssl_cacert);


		switch_CURLcode res = switch_curl_easy_perform(curl);
		if (res != CURLE_OK)
		{
			break;
		}


		long http_code = 0;
		switch_curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

		out->code = http_code;

		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE,
			"join room[%s] result[%d] response[%s]\n",
			param->id, http_code, rd.data? rd.data : "");

		if (http_code == 200)
		{
			result = parse_join_json(rd.data, out);

		}
		else
		{
			result = SWITCH_STATUS_FALSE;
			break;
		}

		//result = SWITCH_STATUS_SUCCESS;

	} while (SWITCH_FALSE);

	if (headers)
	{
		curl_slist_free_all(headers);
	}

	if (curl)
	{
		switch_curl_easy_cleanup(curl);
	}

	if (rd.data)
	{
		ks_pool_free(&rd.data);
	}

	return result;
}