
#include "./lib_https.h"
SWITCH_BEGIN_EXTERN_C
#include <switch.h>
#include <curl/curl.h>
#include <switch_curl.h>
#include <switch_json.h>
#include <libks/ks.h>
#include "./auth_https.h"


SWITCH_END_EXTERN_C

#include <MACManager/IMACManager.h>

#ifndef WIN32
#include <sys/utsname.h>
#endif

#define HTTPS_TIMEOUT_SEC (30)

const char* mackey = "";

IMACManager* pManager = nullptr;

switch_status_t polycom_htts_init(const PolycomInitParam* param)
{
	switch_status_t result = SWITCH_STATUS_FALSE;

	do
	{
		if (!param) break;

		if (!pManager)
		{
			pManager = createMacManager(param->hmacKey);
		}

		//if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK)
		if (curl_global_init(param->curlFlags) != CURLE_OK)
		{
			break;
		}
		result = SWITCH_STATUS_SUCCESS;
	} while (false);


	return result;
}

switch_status_t polycom_htts_create(const PolycomCreateParam* param, PolycomCreateResult* rt)
{
	switch_status_t result = SWITCH_STATUS_FALSE;

	do
	{
		if (!param || !pManager)
		{
			break;
		}

		const char* URL = param->url;

		char* macUrl = NULL;
		size_t encryptedStrBufferSize = 0; 
		 
		pManager->getEncryptUrl(URL, NULL, &encryptedStrBufferSize);
		macUrl = new char[encryptedStrBufferSize]();

		pManager->getEncryptUrl(URL, macUrl, &encryptedStrBufferSize);

		//TCHAR szFilePath[MAX_PATH] = { 0, };
		//MultiByteToWideChar(CP_ACP, 0, (LPSTR)macUrl, -1, szFilePath, encryptedStrBufferSize);

		//SetDlgItemText(IDC_EDIT_HMAC, szFilePath);
		result = auth_session_create(param, rt, macUrl);
		delete macUrl;

	} while (false);
	return result;
}

switch_status_t polycom_htts_join(const PolycomJoinParam* param, PolycomJoinResult* out)
{
	switch_status_t result = SWITCH_STATUS_FALSE;

	do
	{
		if (!param || !pManager)
		{
			break;
		}

		const char* URL = param->url;

		char* macUrl = NULL;
		size_t encryptedStrBufferSize = 0;

		pManager->getEncryptUrl(URL, NULL, &encryptedStrBufferSize);
		macUrl = new char[encryptedStrBufferSize]();

		pManager->getEncryptUrl(URL, macUrl, &encryptedStrBufferSize);

		//TCHAR szFilePath[MAX_PATH] = { 0, };
		//MultiByteToWideChar(CP_ACP, 0, (LPSTR)macUrl, -1, szFilePath, encryptedStrBufferSize);

		//SetDlgItemText(IDC_EDIT_HMAC, szFilePath);
		result = auth_conference_join(param, out, macUrl);

		delete macUrl;

	} while (false);
	return result;
}

switch_status_t polycom_https_destroy(void)
{
	switch_status_t result = SWITCH_STATUS_FALSE;

	do
	{
		curl_global_cleanup();

		destroyMacManager(pManager);
		pManager = nullptr;

		result = SWITCH_STATUS_SUCCESS;
	} while (false);

	return result;
}