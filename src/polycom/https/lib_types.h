
#ifndef __POLYCOM_TYPES_H
#define __POLYCOM_TYPES_H
#include <switch.h>

typedef struct tagPolycomInitParam
{
	long curlFlags; // default CURL_GLOBAL_DEFAULT
	char hmacKey[128];
} PolycomInitParam;

typedef struct tagPolycomCreateParam
{
	switch_core_session_t* session;
	char id[128];
	char url[1024];
}PolycomCreateParam;


typedef struct tagPolycomCreateResult
{
	switch_int32_t code;
	char desc[128];
	char token[512];
}PolycomCreateResult;


typedef struct tagPolycomJoinParam
{
	switch_core_session_t* session;
	char id[128];
	char passwd[128];
	char token[512];
	char url[1024];
}PolycomJoinParam;

typedef struct tagPolycomJoinResult
{
	switch_int32_t code;
	char displayName[128];
	char desc[128];
	char id[256];
	char token[512];		// clientToken
	char roomToken[512];	// meetingToken
}PolycomJoinResult;

#endif
