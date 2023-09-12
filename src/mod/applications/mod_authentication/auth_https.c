#include "auth_https.h"
//#include <switch_cJSON.h>
//#include <switch_cJSON_Utils.h>
#include <switch_curl.h>
#include <switch_json.h>
#include <libks/ks.h>

#ifndef WIN32
#include <sys/utsname.h>
#endif

#ifdef WIN32
void sslLoadWindowsCACertificate();
void sslUnLoadWindowsCACertificate();
int sslContextFunction(void* curl, void* sslctx, void* userdata);
#endif

struct response_data {
	char* data;
	size_t size;
};

static size_t response_data_handler(void* contents, size_t size, size_t nmemb, void* userp)
{
	size_t received = size * nmemb;
	struct response_data* rd = (struct response_data*)userp;

	if (!rd->data) rd->data = ks_pool_alloc(NULL, received + 1);
	else rd->data = ks_pool_resize(rd->data, rd->size + received + 1);

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

//SWITCH_DECLARE(switch_CURL*) switch_curl_easy_init(void);
//SWITCH_DECLARE(switch_CURLcode) switch_curl_easy_perform(switch_CURL* handle);
//SWITCH_DECLARE(switch_CURLcode) switch_curl_easy_getinfo(switch_CURL* curl, switch_CURLINFO info, ...);
//SWITCH_DECLARE(void) switch_curl_easy_cleanup(switch_CURL* handle);
//SWITCH_DECLARE(switch_curl_slist_t*) switch_curl_slist_append(switch_curl_slist_t* list, const char* string);
//SWITCH_DECLARE(void) switch_curl_slist_free_all(switch_curl_slist_t* list);
//SWITCH_DECLARE(switch_CURLcode) switch_curl_easy_setopt(CURL* handle, switch_CURLoption option, ...);
//SWITCH_DECLARE(const char*) switch_curl_easy_strerror(switch_CURLcode errornum);
//SWITCH_DECLARE(void) switch_curl_init(void);
//SWITCH_DECLARE(void) switch_curl_destroy(void);
//SWITCH_DECLARE(switch_status_t) switch_curl_process_mime(switch_event_t* event, switch_CURL* curl_handle, switch_curl_mime** mimep);
//SWITCH_DECLARE(void) switch_curl_mime_free(switch_curl_mime** mimep);
//SWITCH_DECLARE(switch_CURLcode) switch_curl_easy_setopt_mime(switch_CURL* curl_handle, switch_curl_mime* mime);
//#define switch_curl_easy_setopt curl_easy_setopt


static char* auth_token_from_json(const char* jsonstr)
{
	char* result = NULL;
	ks_json_t* json = NULL;
	do
	{

		json = ks_json_parse(jsonstr);
		if (!json)
		{
			break;
		}

		BOOL suc = ks_json_get_object_bool(json, "success", FALSE);

		if (!suc)
		{
			break;
		}
		ks_json_t* result_obj = ks_json_get_object_item(json, "result");

		if (!result_obj)
		{
			break;
		}
		char* token = ks_json_get_object_string(result_obj, "sessionToken", "");

		if (!token)
		{
			break;
		}

		result = strdup(token);
	} while (FALSE);

	if (json)
	{
		ks_json_delete(&json);
	}
	return result;
}


static switch_status_t auth_update_session_info(switch_core_session_t* session, const char* jsonstr)
{
	switch_status_t result = SWITCH_STATUS_FALSE;
	switch_channel_t* channel = switch_core_session_get_channel(session);
	ks_json_t* json = NULL;
	do
	{

		json = ks_json_parse(jsonstr);
		if (!json)
		{
			break;
		}

		BOOL suc = ks_json_get_object_bool(json, "success", FALSE);

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

		char* clientId = ks_json_get_object_string(participant_obj, "clientId", "");
		char* displayName = ks_json_get_object_string(participant_obj, "displayName", "");

		switch_channel_set_variable(channel, "iris_clientId", clientId);
		switch_channel_set_variable(channel, "iris_displayName", displayName);

		char* meetingToken = ks_json_get_object_string(rtc_obj, "meetingToken", "");
		char* clientToken = ks_json_get_object_string(rtc_obj, "clientToken", "");

		switch_channel_set_variable(channel, "iris_meetingToken", meetingToken);
		switch_channel_set_variable(channel, "iris_clientToken", clientToken);

		result = SWITCH_STATUS_SUCCESS;
	} while (FALSE);

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
const char* auth_session_create(switch_core_session_t* session, const char* clientId)
{
	const char* result = NULL;
	struct response_data rd = { 0 };
	char* jsonstr = NULL;
	char* ssl_cacert = NULL;
	switch_curl_slist_t* headers = NULL;
	const char* content = NULL /*"{\"clientId\": \"hahah\"}"*/;

	switch_memory_pool_t* pool = switch_core_session_get_pool(session);
	switch_CURL* curl = switch_curl_easy_init();

	do
	{
		if (!curl)
		{
			break;
		}

		content = switch_core_sprintf(pool, "{\"clientId\": \"%s\"}", clientId);

		ssl_cacert = switch_core_sprintf(pool, "%s%s", SWITCH_GLOBAL_dirs.certs_dir, "/cacert.pem");

		//curl_easy_setopt(curl, CURLOPT_URL, "https://dev-one-api.whaleon.naver.com/v2/meetings/001/join");
		//switch_curl_easy_setopt(curl, CURLOPT_URL, "https://dev-one-api.whaleon.naver.com/v2/session");
		switch_curl_easy_setopt(curl, CURLOPT_URL, "https://one-api.whaleon.naver.com/v2/session");
		//switch_curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "POST");
		switch_curl_easy_setopt(curl, CURLOPT_POST, 1);

		headers = switch_curl_slist_append(headers, "Accept: application/json");
		headers = switch_curl_slist_append(headers, "Accept-Charset: utf-8");
		headers = switch_curl_slist_append(headers, "Content-Type: application/json");
		switch_curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

		//const char* post_data = "{ \"password\": \"724037\", \"inviteCode\": \"string\", \"displayName\": \"Tremendous whale\", \"profileImageUrl\": \"string\", \"overlayFrame\": \"string\", \"enableBreakoutRoomsFeature\": false, \"mediaServer\": \"PK\" }";

		switch_curl_easy_setopt(curl, CURLOPT_POSTFIELDS, content);

		switch_curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0); // if want to use https
		switch_curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0); // set peer and host verify false
		switch_curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);

		switch_curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, response_data_handler);
		switch_curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)&rd);
		
		//switch_curl_easy_setopt(curl, CURLOPT_CAINFO, ssl_cacert);


		switch_CURLcode res = switch_curl_easy_perform(curl);
		if (res != CURLE_OK)
		{
			break;
		}


		long http_code = 0;
		switch_curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

		if (http_code == 200)
		{

			char* token = auth_token_from_json(rd.data);
			if (!token)
			{
				break;
			}

			//switch_channel_t* channel = switch_core_session_get_channel(session);
			//switch_channel_set_variable(channel, "auth_token", token);

			result = token;
			//result = SWITCH_STATUS_SUCCESS;
		}
		else
		{
			//result = SWITCH_STATUS_FALSE;
		}


	} while (FALSE);

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
switch_status_t auth_conference_join(switch_core_session_t* session, const char* meetingId
	, const char* passwd, const char* token)
{
	switch_status_t result = SWITCH_STATUS_FALSE;
	struct response_data rd = { 0 };
	char* jsonstr = NULL;
	char* ssl_cacert = NULL;
	//char* meetingId = "8003289905";
	//char* passwd = "586617";
	//char* inviteCode = "5f22794e08774f2a8a28fa066745f849";
	switch_curl_slist_t* headers = NULL;
	switch_channel_t* channel = switch_core_session_get_channel(session);

	switch_memory_pool_t* pool = switch_core_session_get_pool(session);
	switch_CURL* curl = switch_curl_easy_init();

	do
	{
		if (!curl)
		{
			break;
		}

		//const char* token = switch_channel_get_variable(channel, "auth_token");

		const char* uri = switch_core_sprintf(pool, "https://one-api.whaleon.naver.com/v2/meetings/%s/join", meetingId);
		const char* auth_header = switch_core_sprintf(pool, "X-Auth-Token: %s", token);
		const char* content = switch_core_sprintf(pool, "{ \"password\": %s, \"inviteCode\" :null, \"displayName\" : \"Tremendous whale\", \"profileImageUrl\" : \"string\", \"overlayFrame\" : \"REMOVE\", \"enableBreakoutRoomsFeature\" : false, \"mediaServer\" : \"I:1.0\" }"
			, passwd);
		//ssl_cacert = switch_core_sprintf(pool, "%s%s", SWITCH_GLOBAL_dirs.certs_dir, "/cacert.pem");

		curl_easy_setopt(curl, CURLOPT_URL, uri);
		switch_curl_easy_setopt(curl, CURLOPT_POST, 1);

		headers = switch_curl_slist_append(headers, "Accept: application/json");
		headers = switch_curl_slist_append(headers, "Accept-Charset: utf-8");
		headers = switch_curl_slist_append(headers, "Content-Type: application/json");
		headers = switch_curl_slist_append(headers, auth_header);
		switch_curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

		switch_curl_easy_setopt(curl, CURLOPT_POSTFIELDS, content);

		switch_curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0); // if want to use https
		switch_curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0); // set peer and host verify false
		switch_curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);

		switch_curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, response_data_handler);
		switch_curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)&rd);

		//switch_curl_easy_setopt(curl, CURLOPT_CAINFO, ssl_cacert);


		switch_CURLcode res = switch_curl_easy_perform(curl);
		if (res != CURLE_OK)
		{
			break;
		}


		long http_code = 0;
		switch_curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

		if (http_code == 200)
		{
			auth_update_session_info(session, rd.data);
		}

		result = SWITCH_STATUS_SUCCESS;

	} while (FALSE);

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


//
//static ks_status_t load_credentials_from_json(ks_json_t* json)
//{
//	ks_status_t result = KS_STATUS_SUCCESS;
//	ks_json_t* authentication = NULL;
//	char* authentication_str = NULL;
//	const char* bootstrap = NULL;
//	const char* relay_connector_id = NULL;
//
//#if SIGNALWIRE_CLIENT_C_VERSION_MAJOR >= 2
//	if ((bootstrap = ks_json_get_object_string(json, "bootstrap", NULL)) == NULL) {
//#else
//	if ((bootstrap = ks_json_get_object_cstr(json, "bootstrap")) == NULL) {
//#endif
//		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Unable to connect to SignalWire: missing bootstrap URL\n");
//		result = KS_STATUS_FAIL;
//		goto done;
//	}
//
//#if SIGNALWIRE_CLIENT_C_VERSION_MAJOR >= 2
//	if ((relay_connector_id = ks_json_get_object_string(json, "relay_connector_id", NULL)) == NULL) {
//#else
//	if ((relay_connector_id = ks_json_get_object_cstr(json, "relay_connector_id")) == NULL) {
//#endif
//		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Unable to connect to SignalWire: missing relay_connector_id\n");
//		result = KS_STATUS_FAIL;
//		goto done;
//	}
//
//	if ((authentication = ks_json_get_object_item(json, "authentication")) == NULL) {
//		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Unable to connect to SignalWire: missing authentication\n");
//		result = KS_STATUS_FAIL;
//		goto done;
//	}
//
//	// update the internal connection target, which is normally assigned in swclt_sess_create()
//	if (swclt_sess_target_set(globals.signalwire_session, bootstrap) != KS_STATUS_SUCCESS) {
//		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Unable to connect to SignalWire at %s\n", bootstrap);
//		result = KS_STATUS_FAIL;
//		goto done;
//	}
//
//	// update the relay_connector_id passed to profile configuration
//	strncpy(globals.relay_connector_id, relay_connector_id, sizeof(globals.relay_connector_id) - 1);
//	strncpy(globals.blade_bootstrap, bootstrap, sizeof(globals.blade_bootstrap) - 1);
//
//	// got adopted, update the client config authentication
//#if SIGNALWIRE_CLIENT_C_VERSION_MAJOR >= 2
//	authentication_str = ks_json_print_unformatted(authentication);
//#else
//	authentication_str = ks_json_pprint_unformatted(NULL, authentication);
//#endif
//	swclt_config_set_authentication(globals.config, authentication_str);
//
//#if SIGNALWIRE_CLIENT_C_VERSION_MAJOR >= 2
//	switch_safe_free(authentication_str);
//#else
//	ks_pool_free(&authentication_str);
//#endif
//done:
//
//	return result;
//	}
//
//static ks_status_t mod_signalwire_adoption_post(void)
//{
//	ks_status_t result = KS_STATUS_SUCCESS;
//	switch_memory_pool_t* pool = NULL;
//	switch_CURL* curl = NULL;
//	switch_curl_slist_t* headers = NULL;
//	char url[1024];
//	char errbuf[CURL_ERROR_SIZE];
//	CURLcode res;
//	long rescode;
//	ks_json_t* json = ks_json_create_object();
//	struct response_data rd = { 0 };
//	char* jsonstr = NULL;
//
//	// Determine and cache adoption data values that are heavier to figure out
//	if (!globals.adoption_data_local_ip[0]) {
//		switch_find_local_ip(globals.adoption_data_local_ip, sizeof(globals.adoption_data_local_ip), NULL, AF_INET);
//	}
//
//	if (!globals.adoption_data_external_ip[0]) {
//		switch_port_t local_port = 6050;
//		char* error = NULL;
//		char* external_ip;
//		switch_port_t external_port;
//
//		if (switch_core_new_memory_pool(&pool) != SWITCH_STATUS_SUCCESS) {
//			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT, "SignalWire adoption failed: could not allocate memory pool\n");
//			result = KS_STATUS_FAIL;
//			goto done;
//		}
//		if (switch_find_available_port(&local_port, globals.adoption_data_local_ip, SOCK_STREAM) != SWITCH_STATUS_SUCCESS) {
//			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "SignalWire adoption failed: could not get available local port\n");
//			result = KS_STATUS_FAIL;
//			goto done;
//		}
//
//		external_ip = globals.adoption_data_local_ip;
//		external_port = local_port;
//		if (switch_stun_lookup(&external_ip, &external_port, globals.stun_server, globals.stun_port, &error, pool) != SWITCH_STATUS_SUCCESS) {
//			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "SignalWire adoption failed: stun [%s] lookup error: %s\n", globals.stun_server, error);
//			result = KS_STATUS_FAIL;
//			goto done;
//		}
//		snprintf(globals.adoption_data_external_ip, sizeof(globals.adoption_data_external_ip), "%s", external_ip);
//	}
//
//	if (!globals.adoption_data_uname[0]) {
//#ifndef WIN32
//		struct utsname buf;
//		if (uname(&buf)) {
//			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "SignalWire adoption failed: could not get uname\n");
//			result = KS_STATUS_FAIL;
//			goto done;
//		}
//		switch_snprintf(globals.adoption_data_uname,
//			sizeof(globals.adoption_data_uname),
//			"%s %s %s %s %s",
//			buf.sysname,
//			buf.nodename,
//			buf.release,
//			buf.version,
//			buf.machine);
//#else
//		// @todo set globals.adoption_data_uname from GetVersion Win32API
//#endif
//	}
//
//
//	ks_json_add_string_to_object(json, "client_uuid", globals.adoption_token);
//	ks_json_add_string_to_object(json, "hostname", switch_core_get_hostname());
//	ks_json_add_string_to_object(json, "ip", globals.adoption_data_local_ip);
//	ks_json_add_string_to_object(json, "ext_ip", globals.adoption_data_external_ip);
//	ks_json_add_string_to_object(json, "version", switch_version_full());
//	ks_json_add_string_to_object(json, "uname", globals.adoption_data_uname);
//
//	jsonstr = ks_json_print_unformatted(json);
//	ks_json_delete(&json);
//
//	switch_snprintf(url, sizeof(url), "%s/%s", globals.adoption_service, globals.adoption_token);
//
//	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG10, "Checking %s for SignalWire adoption of this FreeSWITCH\n", url);
//
//	curl = switch_curl_easy_init();
//
//	headers = switch_curl_slist_append(headers, "Accept: application/json");
//	headers = switch_curl_slist_append(headers, "Accept-Charset: utf-8");
//	headers = switch_curl_slist_append(headers, "Content-Type: application/json");
//
//	switch_curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5);
//	switch_curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5);
//
//	if (!strncasecmp(url, "https", 5)) {
//		switch_curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, globals.ssl_verify);
//		switch_curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, globals.ssl_verify);
//	}
//
//	switch_curl_easy_setopt(curl, CURLOPT_URL, url);
//	switch_curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
//	switch_curl_easy_setopt(curl, CURLOPT_USERAGENT, "mod_signalwire/1");
//	switch_curl_easy_setopt(curl, CURLOPT_POSTFIELDS, jsonstr);
//	switch_curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errbuf);
//	switch_curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)&rd);
//	switch_curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, response_data_handler);
//#ifdef WIN32
//	curl_easy_setopt(curl, CURLOPT_SSL_CTX_FUNCTION, sslContextFunction);
//#endif
//
//	if ((res = switch_curl_easy_perform(curl))) {
//		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Curl Result %d, Error: %s\n", res, errbuf);
//		result = KS_STATUS_FAIL;
//		goto done;
//	}
//
//	switch_curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &rescode);
//
//	if (rescode == 404) {
//		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE,
//			"Go to https://signalwire.com to set up your Connector now! Enter connection token %s\n", globals.adoption_token);
//		result = KS_STATUS_FAIL;
//		goto done;
//	}
//
//	if (rescode != 200) {
//		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "SignalWire adoption failed with HTTP code %ld, %s\n", rescode, rd.data);
//		result = KS_STATUS_FAIL;
//		goto done;
//	}
//
//	json = ks_json_parse(rd.data);
//	if (!json) {
//		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Received bad SignalWire adoption response\n%s\n", rd.data);
//		result = KS_STATUS_FAIL;
//		goto done;
//	}
//
//	if ((result = load_credentials_from_json(json)) != KS_STATUS_SUCCESS) {
//		goto done;
//	}
//
//	ks_json_delete(&json);
//
//	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "SignalWire adoption of this FreeSWITCH completed\n");
//
//	// write out the data to save it for reloading in the future
//	{
//		char authpath[1024];
//		FILE* fp = NULL;
//
//		switch_snprintf(authpath, sizeof(authpath), "%s%s%s", SWITCH_GLOBAL_dirs.storage_dir, SWITCH_PATH_SEPARATOR, "adoption-auth.dat");
//		fp = fopen(authpath, "w");
//		if (!fp) {
//			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Unable to open %s to save SignalWire creds\n", authpath);
//			result = KS_STATUS_FAIL;
//			goto done;
//		}
//
//		fputs(rd.data, fp);
//		fclose(fp);
//	}
//
//	globals.state = SW_STATE_OFFLINE;
//	swclt_sess_connect(globals.signalwire_session);
//
//done:
//	if (rd.data) ks_pool_free(&rd.data);
//#if SIGNALWIRE_CLIENT_C_VERSION_MAJOR >= 2
//	switch_safe_free(jsonstr);
//#else
//	if (jsonstr) ks_json_free_ex((void**)&jsonstr);
//#endif
//	if (json) ks_json_delete(&json);
//	if (curl) {
//		curl_easy_cleanup(curl);
//		if (headers) curl_slist_free_all(headers);
//	}
//	if (pool) switch_core_destroy_memory_pool(&pool);
//	return result;
//}