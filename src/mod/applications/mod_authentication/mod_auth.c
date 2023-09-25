
#include <stdio.h>
#include <stdint.h>

#if defined(_WIN32) || defined(_WIN64)
#include <windows.h>
#else
#include <time.h>
#endif

#include <switch.h>
#include <switch_curl.h>

#include "mod_auth.h"
#include "auth_https.h"

#define AUTH_DTMF_ACCOUNT (1)
#define AUTH_DTMF_PASSWD (2)
#define AUTH_DTMF_ACCOUNT_CHANGED (4)
#define AUTH_DTMF_PASSWD_CHANGED (8)
#define AUTH_DTMF_FAILED (16)
#define AUTH_DTMF_FAILED_CHANGED (32)
//#define AUTH_APP_USAGE "<realm>,<digits|~regex>,<string>[,<value>][,<dtmf target leg>][,<event target leg>]"
#define AUTH_APP_USAGE ""

SWITCH_MODULE_LOAD_FUNCTION(mod_auth_load);
SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_auth_shutdown);
SWITCH_MODULE_DEFINITION(mod_auth, mod_auth_load, mod_auth_shutdown, NULL);

SWITCH_STANDARD_APP(conference_function);


typedef struct auth_session_data {
	switch_core_session_t* session;
	uint32_t flags;
	uint32_t failed_code;
	char str_account[32];
	char str_passwd[32];
	char str_account_present[32];
	char str_passwd_present[32];
	const char* str_failed_desc;
	switch_frame_t* account_bk_image;
	switch_frame_t* passwd_bk_image;
	switch_frame_t* failed_bk_image;
} auth_session_data_t;

typedef enum {
	AUTH_INPUT_TYPE_ACCOUNT,
	AUTH_INPUT_TYPE_PASSWD,
} auth_dtmf_type_t;

typedef switch_status_t(*input_callback_function_t) (switch_file_handle_t* vfh, void* input,
	auth_dtmf_type_t input_type, void* buf, unsigned int buflen);

typedef struct auth_config
{
	switch_memory_pool_t* pool;
	uint32_t retry_count;
	uint32_t first_timeout;
	uint32_t digit_timeout;
	uint32_t abs_timeout;
	uint32_t min_account_count;
	uint32_t max_account_count;
	uint32_t min_passwd_count;
	uint32_t max_passwd_count;

	uint32_t text_x;
	uint32_t text_y;
	uint32_t text_w;
	uint32_t text_h;

	uint32_t failed_text_x;
	uint32_t failed_text_y;
	uint32_t failed_text_w;
	uint32_t failed_text_h;
	//(% s ==> text)
	const char* str_auth_text_format;
	//(%s ==> desc, %s ==> error code)
	const char* str_auth_failed_format;
	const char* str_account_bk_image;
	const char* str_passwd_bk_image;
	const char* str_failed_bk_image;

	switch_frame_t* account_bk_image;
	switch_frame_t* passwd_bk_image;
	switch_frame_t* failed_bk_image;
} auth_config_t;


static auth_config_t gconfig;

static char* auth_file_supported_formats[SWITCH_MAX_CODECS] = { 0 };
static const char del_char = '*';

static switch_bool_t init_auth_session_data(auth_session_data_t* pThis)
{
	switch_bool_t result = SWITCH_TRUE;
	memset(pThis, 0, sizeof(auth_session_data_t));
	return result;
}

static switch_bool_t init_auth_config_data(auth_config_t* pThis)
{
	switch_bool_t result = SWITCH_TRUE;
	memset(pThis, 0, sizeof(auth_session_data_t));

	pThis->retry_count = 3;
	pThis->first_timeout = 300000;
	pThis->digit_timeout = 200000;
	pThis->abs_timeout = 0;

	pThis->min_account_count = 5;
	pThis->max_account_count = 15;
	pThis->min_passwd_count = 5;
	pThis->max_passwd_count = 15;
	return result;
}

static void destroy_auth_session_data(auth_session_data_t* pThis)
{
	do
	{
		if (!pThis) break;

		if (pThis->account_bk_image)
		{
			switch_img_free(&(pThis->account_bk_image));
			pThis->account_bk_image = NULL;
		}

		if (pThis->passwd_bk_image)
		{
			switch_img_free(&(pThis->passwd_bk_image));
			pThis->passwd_bk_image = NULL;
		}

		if (pThis->failed_bk_image)
		{
			switch_img_free(&(pThis->failed_bk_image));
			pThis->failed_bk_image = NULL;
		}

		switch_safe_free(pThis->str_failed_desc);
	} while (SWITCH_FALSE);
}

static void destroy_auth_config(auth_config_t* pThis)
{
	do
	{
		if (!pThis) break;

		if (pThis->account_bk_image)
		{
			switch_img_free(&(pThis->account_bk_image));
			pThis->account_bk_image = NULL;
		}

		if (pThis->passwd_bk_image)
		{
			switch_img_free(&(pThis->passwd_bk_image));
			pThis->passwd_bk_image = NULL;
		}

		if (pThis->failed_bk_image)
		{
			switch_img_free(&(pThis->failed_bk_image));
			pThis->failed_bk_image = NULL;
		}

		switch_safe_free(pThis->str_auth_text_format);
		switch_safe_free(pThis->str_auth_failed_format);
		switch_safe_free(pThis->str_account_bk_image);
		switch_safe_free(pThis->str_passwd_bk_image);
	} while (SWITCH_FALSE);
}

static switch_status_t do_config(auth_config_t* config)
{
	char* cf = "auth.conf";
	switch_xml_t cfg, xml, param, settings, profiles;
	switch_status_t status = SWITCH_STATUS_SUCCESS;
	int max_urls;
	switch_time_t default_max_age_sec;


	if (!(xml = switch_xml_open_cfg(cf, &cfg, NULL))) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "open of %s failed\n", cf);
		return SWITCH_STATUS_TERM;
	}

	/* set default config */
	/* get params */
	settings = switch_xml_child(cfg, "settings");
	if (settings) {
		for (param = switch_xml_child(settings, "param"); param; param = param->next) {
			char* var = (char*)switch_xml_attr_soft(param, "name");
			char* val = (char*)switch_xml_attr_soft(param, "value");
			if (!strcasecmp(var, "account_bk_image"))
			{
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Setting account_bk_image to %s\n", val);
				config->str_account_bk_image = switch_core_strdup(config->pool, val);
				continue;
			}
			
			if (!strcasecmp(var, "passwd_bk_image"))
			{
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Setting passwd_bk_image to %s\n", val);
				config->str_passwd_bk_image = switch_core_strdup(config->pool, val);
				continue;
			}

			if (!strcasecmp(var, "failed_bk_image"))
			{
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Setting failed_bk_image to %s\n", val);
				config->str_failed_bk_image = switch_core_strdup(config->pool, val);
				continue;
			}
			
			if (!strcasecmp(var, "auth_text_format"))
			{
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Setting passwd_bk_image to %s\n", val);
				config->str_auth_text_format = switch_core_strdup(config->pool, val);
				continue;
			}
			
			if (!strcasecmp(var, "auth_failed_format"))
			{
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Setting auth_failed_format to %s\n", val);
				config->str_auth_failed_format = switch_core_strdup(config->pool, val);
				continue;
			}
			
			if (!strcasecmp(var, "text_x"))
			{
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Setting text_x to %s\n", val);
				config->text_x = atoi(val);
				continue;
			}
			
			if (!strcasecmp(var, "text_y"))
			{
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Setting text_y to %s\n", val);
				config->text_y = atoi(val);
				continue;
			}
			
			if (!strcasecmp(var, "text_w"))
			{
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Setting text_w to %s\n", val);
				config->text_w = atoi(val);
				continue;
			}
			
			if (!strcasecmp(var, "text_h"))
			{
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Setting text_h to %s\n", val);
				config->text_h = atoi(val);
				continue;
			}

			if (!strcasecmp(var, "failed_text_x"))
			{
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Setting failed_text_x to %s\n", val);
				config->failed_text_x = atoi(val);
				continue;
			}

			if (!strcasecmp(var, "failed_text_y"))
			{
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Setting failed_text_y to %s\n", val);
				config->failed_text_y = atoi(val);
				continue;
			}

			if (!strcasecmp(var, "failed_text_w"))
			{
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Setting failed_text_w to %s\n", val);
				config->failed_text_w = atoi(val);
				continue;
			}

			if (!strcasecmp(var, "failed_text_h"))
			{
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Setting failed_text_h to %s\n", val);
				config->failed_text_h = atoi(val);
				continue;
			}

			if (!strcasecmp(var, "retry_count"))
			{
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Setting retry_count to %s\n", val);
				config->retry_count = atoi(val);
				continue;
			}
			
			if (!strcasecmp(var, "first_timeout"))
			{
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Setting first_timeout to %s\n", val);
				config->first_timeout = atoi(val);
				continue;
			}
			
			if (!strcasecmp(var, "digit_timeout"))
			{
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Setting digit_timeout to %s\n", val);
				config->first_timeout = atoi(val);
				continue;
			}
			
			if (!strcasecmp(var, "abs_timeout"))
			{
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Setting abs_timeout to %s\n", val);
				config->abs_timeout = atoi(val);
				continue;
			}
			
			if (!strcasecmp(var, "min_account_count"))
			{
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Setting min_account_count to %s\n", val);
				config->min_account_count = atoi(val);
				continue;
			}
			
			if (!strcasecmp(var, "max_account_count"))
			{
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Setting max_account_count to %s\n", val);
				config->max_account_count = atoi(val);
				continue;
			}
			
			if (!strcasecmp(var, "min_passwd_count"))
			{
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Setting min_passwd_count to %s\n", val);
				config->min_passwd_count = atoi(val);
				continue;
			}
			if (!strcasecmp(var, "max_passwd_count"))
			{
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Setting max_passwd_count to %s\n", val);
				config->max_passwd_count = atoi(val);
				continue;
			}
			
			{
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "Unsupported param: %s\n", var);
			}
		}
	}

	if (zstr(config->str_account_bk_image) 
		|| zstr(config->str_passwd_bk_image)
		|| zstr(config->str_failed_bk_image))
	{
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "bk_image must not be empty\n");
		status = SWITCH_STATUS_TERM;
		goto done;
	}
done:
	switch_xml_free(xml);

	return status;
}

SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_auth_shutdown)
{
	destroy_auth_config(&gconfig);
	return SWITCH_STATUS_SUCCESS;
}

static switch_status_t auth_file_open(switch_core_session_t* session, const char* modname
	, const char* file, switch_file_handle_t* vfh)
{
	switch_status_t result = SWITCH_STATUS_SUCCESS;

	do
	{
		//switch_memory_pool_t* pool = switch_get_memory;
		//vfh->modname = switch_core_strdup(session, modname);
		const char* modname = "mod_auth";
		const char* name = auth_file_supported_formats[0];
		switch_memory_pool_t* pool = switch_core_session_get_pool(session);
		vfh->modname = modname;
		vfh->flags = SWITCH_FILE_OPEN | SWITCH_FILE_FLAG_VIDEO;
		//vfh->fd = (switch_file_t*)new_image;

		switch_mutex_init(&vfh->flag_mutex, SWITCH_MUTEX_NESTED, pool);

		vfh->private_info = (void*)session;
		if ((vfh->file_interface = switch_loadable_module_get_file_interface(name, NULL)) == 0) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Invalid file format [%s] for [%s]!\n", modname, file);
			result = SWITCH_STATUS_FALSE;
			break;
		}
	} while (SWITCH_FALSE);

	return result;
}

static switch_status_t auth_file_close(switch_core_session_t* session, const char* modname
	, const char* file, switch_file_handle_t* vfh)
{
	switch_status_t result = SWITCH_STATUS_SUCCESS;

	if (vfh)
	{

		switch_mutex_lock(vfh->flag_mutex);
		vfh->flags = SWITCH_FILE_DONE;

		if (vfh->file)
		{
			free(vfh->file);
			vfh->file = NULL;
		}

		switch_mutex_unlock(vfh->flag_mutex);
	}
	if (vfh->flag_mutex)
	{
		switch_mutex_destroy(vfh->flag_mutex);
	}

	return result;
}

static switch_image_t* get_auth_backimage(auth_session_data_t* userdata)
{
	switch_image_t* result = NULL;

	do
	{
		if (!userdata) break;

		//switch_bool_t is_data_changed = userdata->flags & (AUTH_DTMF_ACCOUNT_CHANGED | AUTH_DTMF_PASSWD_CHANGED);
		if (userdata->flags & AUTH_DTMF_FAILED)
		{
			result = userdata->failed_bk_image;
			break;
		}else if (userdata->flags & AUTH_DTMF_PASSWD)
		{
			result = userdata->passwd_bk_image;
			break;
		}
		else
		{
			result = userdata->account_bk_image;
		}
	} while (SWITCH_FALSE);
	return result;
}

// write handle image to frame
static switch_status_t auth_file_write(switch_file_handle_t* handle, switch_frame_t* frame)
{
	switch_status_t result = SWITCH_STATUS_SUCCESS;
	uint32_t center_x = 0;
	uint32_t center_y = 0;
	uint32_t width = gconfig.text_w? gconfig.text_w : 400;
	uint32_t height = gconfig.text_h? gconfig.text_h : 100;
	uint32_t failed_width = gconfig.failed_text_w? gconfig.failed_text_w : 800;
	uint32_t failed_height = gconfig.failed_text_h? gconfig.failed_text_h : 100;

	switch_bool_t is_account = SWITCH_FALSE;
	switch_bool_t is_passwd = SWITCH_FALSE;
	switch_bool_t is_failed = SWITCH_FALSE;
	switch_bool_t is_data_changed = SWITCH_FALSE;
	char* dtmf_account = NULL;
	char* dtmf_passwd = NULL;
	char* dtmf_failed = NULL;
	char buf[256] = { 0 };

	switch_image_t* auth_account_text = NULL;
	switch_image_t* auth_passwd_text = NULL;
	switch_image_t* auth_failed_text = NULL;
	auth_session_data_t* userdata = (auth_session_data_t*)handle->private_info;

	switch_core_session_t* session = (switch_core_session_t*)userdata->session;
	switch_image_t* img = NULL;
	const char* text_format = gconfig.str_auth_text_format ? gconfig.str_auth_text_format : "#daffff:transparent::20:%s:";
	const char* failed_text_format = gconfig.str_auth_failed_format ? gconfig.str_auth_failed_format 
		: "#fca454:transparent::20:auth failed,code[%d], desc[%s]:";

	if (userdata)
	{

		switch_core_media_lock_video_file(userdata->session, SWITCH_RW_READ);

		is_data_changed = userdata->flags & (AUTH_DTMF_ACCOUNT_CHANGED | AUTH_DTMF_PASSWD_CHANGED | AUTH_DTMF_FAILED_CHANGED);
		is_account = userdata->flags & AUTH_DTMF_ACCOUNT;
		is_passwd = userdata->flags & AUTH_DTMF_PASSWD;
		is_failed = userdata->flags & AUTH_DTMF_FAILED;

		// clear flags
		userdata->flags &= ~(AUTH_DTMF_ACCOUNT_CHANGED | AUTH_DTMF_PASSWD_CHANGED | AUTH_DTMF_FAILED_CHANGED);

		img = get_auth_backimage(userdata);

		if (is_account && is_data_changed)
		{
			dtmf_account = switch_mprintf(text_format, userdata->str_account_present);
			is_account = SWITCH_TRUE;
		}
		else if (is_passwd && is_data_changed)
		{
			dtmf_passwd = switch_mprintf(text_format, userdata->str_passwd_present);
		}
		else if (is_failed && is_data_changed)
		{
			dtmf_failed = switch_mprintf(failed_text_format
				, userdata->failed_code
				, userdata->str_failed_desc? userdata->str_failed_desc : "empty");
		}
		else
		{
			// error?
		}
		switch_core_media_unlock_video_file(userdata->session, SWITCH_RW_READ);
	}

	if (dtmf_account/* && dtmf_account[0] != '\0'*/)
	{
		auth_account_text = switch_img_write_text_img(width, height, SWITCH_TRUE, dtmf_account);
	}

	switch_safe_free(dtmf_account);

	if (is_failed)
	{
		center_x = gconfig.failed_text_x ? gconfig.failed_text_x : (20);
		center_y = gconfig.failed_text_y ? gconfig.failed_text_y : (-failed_height - 20 + img->h);

		failed_width = gconfig.failed_text_w ? gconfig.failed_text_w : img->w - 40;
		failed_height = gconfig.failed_text_h ? gconfig.failed_text_h : 100;
	}
	else
	{
		center_x = gconfig.text_x ? gconfig.text_x : (-20 + img->w / 2);
		center_y = gconfig.text_y ? gconfig.text_y : (-20 + img->h / 2);
	}

	if (dtmf_passwd/* && dtmf_passwd[0] != '\0'*/)
	{
		auth_passwd_text = switch_img_write_text_img(width, height, SWITCH_TRUE, dtmf_passwd);
	}
	switch_safe_free(dtmf_passwd);

	if (dtmf_failed/* && dtmf_failed[0] != '\0'*/)
	{
		auth_failed_text = switch_img_write_text_img(failed_width, failed_height, SWITCH_TRUE, dtmf_failed);
	}
	switch_safe_free(dtmf_failed);


	if (is_account && auth_account_text)
	{
		switch_img_patch(img, auth_account_text, center_x - width/2, center_y - height/2 );
		switch_img_free(&auth_account_text);
	}
	
	if(is_passwd && auth_passwd_text)
	{
		//switch_img_patch(img, auth_passwd_text, center_x - width / 2, center_y + height/2);
		switch_img_patch(img, auth_passwd_text, center_x - width / 2, center_y - height / 2);
		switch_img_free(&auth_passwd_text);
	}
	
	if (is_failed && auth_failed_text)
	{
		//switch_img_patch(img, auth_passwd_text, center_x - width / 2, center_y + height/2);
		switch_img_patch(img, auth_failed_text, center_x, center_y);
		switch_img_free(&auth_failed_text);
	}

	frame->img = img;
	return result;
}

// format: xxx xxx xxxx
static void update_account_present_buf(char* buf, const char* input_buf, uint32_t input_len, char input_char)
{
	int space_count = 0;
	char space = ' ';
	if (input_len > 6)
	{
		//xxx xxx x
		space_count = 2;
		//buf[space_count * 3] = space;
		buf[6] = space;
	}
	else if (input_len > 3)
	{
		//xxx x
		space_count = 1;
		//buf[space_count * 3] = space;
		buf[3] = space;
	}
	else
	{
		// x
		space_count = 0;
	}
	if (input_len > 0 && input_char != del_char)
	{
		buf[input_len + space_count - 1] = input_char;
	}
	buf[input_len + space_count] = '\0';
}

static void update_passwd_present_buf(char* buf, const char* input_buf, uint32_t input_len, char input_char)
{
	if (input_len > 0)
	{
		buf[input_len - 1] = input_buf[input_len-1];
	}
	if (input_len > 1)
	{
		buf[input_len - 2] = '*';
	}
	buf[input_len] = '\0';
}

static switch_status_t input_callback_function(switch_file_handle_t* vfh, void* input,
	auth_dtmf_type_t input_type, void* buf, unsigned int buflen)
{
	switch_status_t result = SWITCH_STATUS_SUCCESS;
	char input_char = *((char*)input);
	const char* input_buf = (const char*)buf;
	unsigned int input_len = buflen;

	auth_session_data_t* user_data = (auth_session_data_t*)vfh->private_info;
	switch_core_session_t* session = (switch_core_session_t*)user_data->session;
	switch_channel_t* channel = switch_core_session_get_channel(session);

	switch_bool_t is_input_del = input_char == del_char;
	if (vfh)
	{
		auth_session_data_t* user_data = (auth_session_data_t*)vfh->private_info;
		switch_core_media_lock_video_file(session, SWITCH_RW_READ);

		if (input_type == AUTH_INPUT_TYPE_ACCOUNT)
		{
			user_data->flags |= (AUTH_DTMF_ACCOUNT | AUTH_DTMF_ACCOUNT_CHANGED);
			// remove failed tips
			user_data->flags &= ~(AUTH_DTMF_FAILED | AUTH_DTMF_FAILED_CHANGED);

			if (buflen > 0)
			{
				user_data->str_account[buflen - 1] = input_char;
			}
			user_data->str_account[buflen] = '\0';

			update_account_present_buf(user_data->str_account_present
				, input_buf, input_len, input_char);
		}
		else if(input_type == AUTH_INPUT_TYPE_PASSWD)
		{

			user_data->flags |= AUTH_DTMF_PASSWD_CHANGED;
			// remove failed tips
			user_data->flags &= ~(AUTH_DTMF_FAILED);

			if (buflen > 0)
			{
				user_data->str_passwd[buflen - 1] = input_char;
			}
			user_data->str_passwd[buflen] = '\0';

			update_passwd_present_buf(user_data->str_passwd_present
				, input_buf, input_len, input_char);

		}

		switch_core_media_unlock_video_file(session, SWITCH_RW_READ);
	}

	return result;
}

static switch_status_t collect_input(switch_file_handle_t* vfh,
	auth_dtmf_type_t input_type,
	char* buf,
	switch_size_t buflen,
	switch_size_t maxdigits,
	const char* terminators, char* terminator,
	uint32_t first_timeout, uint32_t digit_timeout, 
	uint32_t abs_timeout, input_callback_function_t callback)
{
	auth_session_data_t* user_data = (auth_session_data_t*)vfh->private_info;
	switch_core_session_t* session = (switch_core_session_t*)user_data->session;
	switch_channel_t* channel = switch_core_session_get_channel(session);
	switch_bool_t is_account = input_type == AUTH_INPUT_TYPE_ACCOUNT;

	switch_size_t i = 0, x = strlen(buf);
	switch_status_t result = SWITCH_STATUS_FALSE;
	switch_time_t started = 0, digit_started = 0;
	uint32_t abs_elapsed = 0, digit_elapsed = 0;
	uint32_t eff_timeout = 0;
	switch_frame_t write_frame = { 0 };
	unsigned char* abuf = NULL;
	switch_codec_implementation_t imp = { 0 };
	switch_codec_t codec = { 0 };
	int sval = 0;
	const char* var;

	// already exist?
	if (x >= buflen || x >= maxdigits) {
		return SWITCH_STATUS_FALSE;
	}

	// init send silence data
	if ((var = switch_channel_get_variable(channel, SWITCH_SEND_SILENCE_WHEN_IDLE_VARIABLE)) && (sval = atoi(var))) 
	{
		switch_core_session_get_read_impl(session, &imp);

		if (switch_core_codec_init(&codec,
			"L16",
			NULL,
			NULL,
			imp.samples_per_second,
			imp.microseconds_per_packet / 1000,
			imp.number_of_channels,
			SWITCH_CODEC_FLAG_ENCODE | SWITCH_CODEC_FLAG_DECODE, NULL,
			switch_core_session_get_pool(session)) != SWITCH_STATUS_SUCCESS) 
		{
			switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "Codec Error L16@%uhz %u channels %dms\n",
				imp.samples_per_second, imp.number_of_channels, imp.microseconds_per_packet / 1000);
			return SWITCH_STATUS_FALSE;
		}


		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "Codec Activated L16@%uhz %u channels %dms\n",
			imp.samples_per_second, imp.number_of_channels, imp.microseconds_per_packet / 1000);

		write_frame.codec = &codec;
		switch_zmalloc(abuf, SWITCH_RECOMMENDED_BUFFER_SIZE);
		write_frame.data = abuf;
		write_frame.buflen = SWITCH_RECOMMENDED_BUFFER_SIZE;
		write_frame.datalen = imp.decoded_bytes_per_packet;
		write_frame.samples = write_frame.datalen / sizeof(int16_t);
	}

	// default terminator
	if (terminator != NULL) 
	{
		*terminator = '\0';
	}

	// buf has terminator?
	if (!zstr(terminators)) 
	{
		for (i = 0; i < x; i++) 
		{
			if (strchr(terminators, buf[i]) && terminator != NULL) 
			{
				*terminator = buf[i];
				buf[i] = '\0';
				switch_safe_free(abuf);
				return SWITCH_STATUS_SUCCESS;
			}
		}
	}

	if (abs_timeout) 
	{
		started = switch_micro_time_now();
	}

	if (digit_timeout && first_timeout) 
	{
		eff_timeout = first_timeout;
	}
	else if (digit_timeout && !first_timeout) 
	{
		eff_timeout = digit_timeout;
	}
	else if (first_timeout) 
	{
		digit_timeout = eff_timeout = first_timeout;
	}


	if (eff_timeout) 
	{
		digit_started = switch_micro_time_now();
	}

	while (switch_channel_ready(channel)) 
	{
		switch_frame_t* read_frame;

		if (abs_timeout) 
		{
			abs_elapsed = (uint32_t)((switch_micro_time_now() - started) / 1000);
			// input timeout
			if (abs_elapsed >= abs_timeout) 
			{
				result = SWITCH_STATUS_TIMEOUT;
				break;
			}
		}

		switch_ivr_parse_all_events(session);

		if (eff_timeout) 
		{
			digit_elapsed = (uint32_t)((switch_micro_time_now() - digit_started) / 1000);

			// input timeout
			if (digit_elapsed >= eff_timeout) 
			{
				result = SWITCH_STATUS_TIMEOUT;
				break;
			}
		}

		if (switch_channel_has_dtmf(channel)) 
		{
			switch_dtmf_t dtmf = { 0 };
			switch_size_t y;
			switch_status_t end_status = SWITCH_STATUS_FALSE;

			if (eff_timeout) 
			{
				eff_timeout = digit_timeout;
				digit_started = switch_micro_time_now();
			}

			for (y = 0; y <= maxdigits; y++) 
			{
				if (switch_channel_dequeue_dtmf(channel, &dtmf) != SWITCH_STATUS_SUCCESS) 
				{
					break;
				}

				// input terminator
				if (!zstr(terminators) && strchr(terminators, dtmf.digit) && terminator != NULL) 
				{
					*terminator = dtmf.digit;
					switch_safe_free(abuf);
					//return SWITCH_STATUS_SUCCESS;
					end_status = SWITCH_STATUS_SUCCESS;
					break;
				}

				if (dtmf.digit == del_char && x > 0)
				{
					buf[--x] = '\0';
				}
				else if(dtmf.digit == del_char && x < 1)
				{
					// ignore
				}
				else
				{
					buf[x++] = dtmf.digit;
					buf[x] = '\0';
				}

				if (callback)
				{
					callback(vfh, (void*)&dtmf, input_type, buf, x);
				}

				if (x >= buflen || x >= maxdigits) 
				{
					switch_safe_free(abuf);
					//return SWITCH_STATUS_SUCCESS;
					end_status = SWITCH_STATUS_SUCCESS;
					break;
				}
			}

			if (end_status == SWITCH_STATUS_SUCCESS)
			{
				break;
			}
		}

		if (switch_channel_test_flag(channel, CF_SERVICE)) 
		{
			switch_cond_next();
		}
		else 
		{
			result = switch_core_session_read_frame(session, &read_frame, SWITCH_IO_FLAG_NONE, 0);
			if (!SWITCH_READ_ACCEPTABLE(result)) 
			{
				break;
			}

			if (write_frame.data) 
			{
				switch_generate_sln_silence((int16_t*)write_frame.data, write_frame.samples, imp.number_of_channels, sval);
				switch_core_session_write_frame(session, &write_frame, SWITCH_IO_FLAG_NONE, 0);
			}

		}
	}

	if (write_frame.codec) 
	{
		switch_core_codec_destroy(&codec);
	}

	switch_safe_free(abuf);

	return result;
}

static switch_status_t on_auth_result(switch_core_session_t* session, switch_status_t status)
{
	switch_status_t result = SWITCH_STATUS_FALSE;

	return result;
}

SWITCH_STANDARD_APP(conference_function)
{
	switch_status_t result = SWITCH_STATUS_FALSE;
	switch_file_handle_t vfh = { 0 };
	switch_bool_t done = SWITCH_FALSE;
	int cur = 0;
	int retryCount = gconfig.retry_count? gconfig.retry_count : 3;
	uint32_t http_code = 200;
	char buf_account[256] = { 0 };
	char buf_passwd[256] = { 0 };
	char terminator = ' ';
	const char* token = NULL;
	char* http_desc = NULL;
	
	switch_image_t* new_account_image = NULL;
	switch_image_t* new_passwd_image = NULL;
	switch_image_t* new_failed_image = NULL;
	switch_core_session_t* s = session;
	switch_channel_t* channel = switch_core_session_get_channel(session);
	auth_session_data_t user_data = { 0 };

	do
	{
		const char* session_type = switch_channel_get_variable(channel, "session_type");
		if (session_type && (0 == strcmp(session_type, "iris")))
		{
			result = SWITCH_STATUS_SUCCESS;
			break;
		}

		if (!switch_channel_test_flag(channel, CF_VIDEO))
		{
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "switch_channel_test_flag(channel, CF_VIDEO) failed\n");
			break;
		}

		if (!switch_channel_media_ready(channel))
		{
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "switch_channel_media_ready(channel) failed\n");
			break;
		}

		switch_channel_set_flag(channel, CF_VIDEO_ECHO);

		result = switch_channel_wait_for_flag(channel, CF_VIDEO_READY, SWITCH_TRUE, 10000, NULL);
		if (result != SWITCH_STATUS_SUCCESS)
		{
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "switch_channel_wait_for_flag %d failed\n", result);
		}

		result = auth_file_open(session, "auth", "", &vfh);

		if (result)
		{
			break;
		}

		switch_img_copy(gconfig.account_bk_image, &new_account_image);
		switch_img_copy(gconfig.passwd_bk_image, &new_passwd_image);
		switch_img_copy(gconfig.failed_bk_image, &new_failed_image);

		user_data.session = session;
		user_data.account_bk_image = (switch_file_t*)new_account_image;
		user_data.passwd_bk_image = (switch_file_t*)new_passwd_image;
		user_data.failed_bk_image = (switch_file_t*)new_failed_image;

		vfh.private_info = (void*)&user_data;

		switch_core_media_set_video_file(session, &vfh, SWITCH_RW_READ);

		switch_bool_t auth_suc = SWITCH_FALSE;


		for (int i = 0; !auth_suc && i < retryCount; i++)
		{
			memset(buf_account, 0, sizeof(buf_account));
			memset(buf_passwd, 0, sizeof(buf_passwd));
			if(i > 0)
			{
				switch_core_media_lock_video_file(session, SWITCH_RW_READ);

				// reset image
				if (user_data.account_bk_image)
				{
					switch_img_free(&(user_data.account_bk_image));
					user_data.account_bk_image = NULL;
				}

				if (user_data.passwd_bk_image)
				{
					switch_img_free(&(user_data.passwd_bk_image));
					user_data.passwd_bk_image = NULL;
				}

				if (user_data.failed_bk_image)
				{
					switch_img_free(&(user_data.failed_bk_image));
					user_data.failed_bk_image = NULL;
				}
				switch_img_copy(gconfig.account_bk_image, &user_data.account_bk_image);
				switch_img_copy(gconfig.passwd_bk_image, &user_data.passwd_bk_image);
				switch_img_copy(gconfig.failed_bk_image, &user_data.failed_bk_image);

				// reset data
				memset(user_data.str_account, 0, sizeof(user_data.str_account));
				memset(user_data.str_account_present, 0, sizeof(user_data.str_account_present));
				memset(user_data.str_passwd, 0, sizeof(user_data.str_passwd));
				memset(user_data.str_passwd_present, 0, sizeof(user_data.str_passwd_present));

				switch_core_media_unlock_video_file(session, SWITCH_RW_READ);
			}

			char terminator = ' ';
			auth_dtmf_type_t input_type = AUTH_INPUT_TYPE_ACCOUNT;

			//{
			//	switch_core_media_lock_video_file(session, SWITCH_RW_READ);
			//	user_data.flags |= (AUTH_DTMF_ACCOUNT | AUTH_DTMF_ACCOUNT_CHANGED);

			//	switch_core_media_unlock_video_file(session, SWITCH_RW_READ);
			//}
			result = collect_input(&vfh, input_type, buf_account, 256, 25, "#", &terminator
				, 300000, 200000, 0, input_callback_function);

			//send_image_response(session, imagePath);
			switch_channel_set_variable(channel, "conference_id", buf_account);
			{
				switch_core_media_lock_video_file(session, SWITCH_RW_READ);

				user_data.flags &= ~(AUTH_DTMF_ACCOUNT);
				user_data.flags |= (AUTH_DTMF_PASSWD | AUTH_DTMF_ACCOUNT_CHANGED);

				switch_core_media_unlock_video_file(session, SWITCH_RW_READ);
			}

			input_type = AUTH_INPUT_TYPE_PASSWD;

			result = collect_input(&vfh, input_type, buf_passwd, 256, 25, "#", &terminator
				, 300000, 200000, 0, input_callback_function);

			//{
			//	switch_core_media_lock_video_file(session, SWITCH_RW_READ);

			//	user_data.flags &= ~(AUTH_DTMF_PASSWD);

			//	switch_core_media_unlock_video_file(session, SWITCH_RW_READ);
			//}
			switch_channel_set_variable(channel, "conference_passwd", buf_passwd);

			switch_memory_pool_t* pool = switch_core_session_get_pool(session);
			uint64_t timestamp = switch_micro_time_now();
			const char* clientId = switch_core_sprintf(pool, "sip-test-0001_%"SWITCH_UINT64_T_FMT"", timestamp);
			token = auth_session_create(session, clientId, &http_code, &http_desc);

			{
				switch_core_media_lock_video_file(session, SWITCH_RW_READ);
				user_data.failed_code = http_code;
				switch_safe_free(user_data.str_failed_desc);
				user_data.str_failed_desc = http_desc;
				http_desc = NULL;
				if (!token)
				{
					user_data.flags &= ~(AUTH_DTMF_PASSWD);
					user_data.flags |= (AUTH_DTMF_FAILED & AUTH_DTMF_FAILED_CHANGED);
				}
				switch_core_media_unlock_video_file(session, SWITCH_RW_READ);
			}

			if (!token)
			{
				continue;
			}

			//const char* tmp_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJhNGYwYjQwOS00NTYwLTQzYTQtYjZlMi05NmNkNTRjMjNlYjAiLCJpc3MiOiJ3aGFsZW9uLW9uZSIsImV4cCI6MTY5NDUzODQ3NCwiaWF0IjoxNjk0NTAyNDc0fQ.hOAPOU3wzotwFXrHmPJmpZr0sniDgUuDEK79agyACVh5x1sOq1vaiG5Fm1i21aTC0hNVO6kWrTwIpytRYsQDPw";
			result = auth_conference_join(session, buf_account, buf_passwd, token, &http_code, &http_desc);


			{
				switch_core_media_lock_video_file(session, SWITCH_RW_READ);
				user_data.failed_code = http_code;
				switch_safe_free(user_data.str_failed_desc);
				user_data.str_failed_desc = http_desc;
				http_desc = NULL;
				if (result != SWITCH_STATUS_SUCCESS)
				{
					user_data.flags &= ~(AUTH_DTMF_PASSWD);
					user_data.flags |= (AUTH_DTMF_FAILED | AUTH_DTMF_FAILED_CHANGED);
				}
				switch_core_media_unlock_video_file(session, SWITCH_RW_READ);
			}
			//switch_core_media_lock_video_file(session, SWITCH_RW_READ);

			//userdata->flags |= is_account ? AUTH_DTMF_ACCOUNT : AUTH_DTMF_PASSWD;

			//switch_core_media_unlock_video_file(session, SWITCH_RW_READ);

			auth_suc = result == SWITCH_STATUS_SUCCESS;
		}


		auth_file_close(session, modname, "", &vfh);
		switch_core_media_set_video_file(session, NULL, SWITCH_RW_READ);

	} while (SWITCH_FALSE);

	if (result != SWITCH_STATUS_SUCCESS)
	{
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "auth failed: %d\n",
			result);
		switch_channel_hangup(channel, SWITCH_CAUSE_NORMAL_CLEARING);
	}

	switch_core_media_lock_video_file(session, SWITCH_RW_READ);
	destroy_auth_session_data(&user_data);
	switch_core_media_unlock_video_file(session, SWITCH_RW_READ);

	switch_safe_free(token);

	return /*result*/;
}

SWITCH_MODULE_LOAD_FUNCTION(mod_auth_load)
{
	switch_api_interface_t *api_interface = NULL;
	switch_application_interface_t* app_interface = NULL;
	switch_file_interface_t* file_interface;

	init_auth_config_data(&gconfig);
	gconfig.pool = pool;

	do_config(&gconfig);
	if (gconfig.str_account_bk_image)
	{
		gconfig.account_bk_image = switch_img_read_png(gconfig.str_account_bk_image, SWITCH_IMG_FMT_I420);
	}

	if (gconfig.str_account_bk_image)
	{
		gconfig.passwd_bk_image = switch_img_read_png(gconfig.str_passwd_bk_image, SWITCH_IMG_FMT_I420);
	}

	if (gconfig.str_failed_bk_image)
	{
		gconfig.failed_bk_image = switch_img_read_png(gconfig.str_failed_bk_image, SWITCH_IMG_FMT_I420);
	}
	/* connect my internal structure to the blank pointer passed to me */
	*module_interface = switch_loadable_module_create_module_interface(pool, modname);

	auth_file_supported_formats[0] = "auth_file";
	file_interface = switch_loadable_module_create_interface(*module_interface, SWITCH_FILE_INTERFACE);
	file_interface->extens = auth_file_supported_formats;
	file_interface->interface_name = modname;
	file_interface->file_write_video = auth_file_write;
	// API
	//SWITCH_ADD_API(api_interface, "auth", "Sip auth commands", auth_function, AUTH_APP_USAGE);

	//switch_console_set_complete("add av debug on");
	//switch_console_set_complete("add av debug off");
	//switch_console_set_complete("add av debug 0");
	//switch_console_set_complete("add av debug 1");
	//switch_console_set_complete("add av debug 2");
	//switch_console_set_complete("add av show formats");
	//switch_console_set_complete("add av show codecs");

	//*module_interface = switch_loadable_module_create_module_interface(pool, modname);

	// APP
	SWITCH_ADD_APP(app_interface, "auth", "Conference auth App", "Conference auth App Description"
		, conference_function, AUTH_APP_USAGE, SAF_NONE);

	return SWITCH_STATUS_SUCCESS;
}
