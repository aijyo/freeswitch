/*
 * FreeSWITCH Modular Media Switching Software Library / Soft-Switch Application
 * Copyright (C) 2005-2015, Anthony Minessale II <anthm@freeswitch.org>
 *
 * Version: MPL 1.1
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is FreeSWITCH Modular Media Switching Software Library / Soft-Switch Application
 *
 * The Initial Developer of the Original Code is
 * Seven Du <dujinfang@gmail.com>
 * Portions created by the Initial Developer are Copyright (C)
 * the Initial Developer. All Rights Reserved.
 *
 * Contributor(s):
 *
 * Seven Du <dujinfang@gmail.com>
 * Anthony Minessale <anthm@freeswitch.org>
 * Jakub Karolczyk <jakub.karolczyk@signalwire.com>
 *
 * mod_av -- FS Video Codec / File Format using libav.org
 *
 */

#include <switch.h>

#include "mod_auth.h"

#define AUTH_DTMF_ACCOUNT (1)
#define AUTH_DTMF_PASSWD (2)
//#define AUTH_APP_USAGE "<realm>,<digits|~regex>,<string>[,<value>][,<dtmf target leg>][,<event target leg>]"
#define AUTH_APP_USAGE ""

SWITCH_MODULE_LOAD_FUNCTION(mod_auth_load);
SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_auth_shutdown);
SWITCH_MODULE_DEFINITION(mod_auth, mod_auth_load, mod_auth_shutdown, NULL);

SWITCH_STANDARD_APP(conference_function);

struct mod_av_globals mod_av_globals;
switch_frame_t* g_bk_image = NULL;
switch_frame_t* g_auth_image = NULL;
static char* auth_file_supported_formats[SWITCH_MAX_CODECS] = { 0 };

typedef struct auth_session_data {
	switch_core_session_t* session;
	uint32_t flags;
	char* account;
	char* passwd;
} auth_session_data_t;

typedef enum {
	AUTH_INPUT_TYPE_ACCOUNT,
	AUTH_INPUT_TYPE_PASSWD,
} auth_dtmf_type_t;

typedef switch_status_t(*input_callback_function_t) (switch_file_handle_t* vfh, void* input,
	auth_dtmf_type_t input_type, void* buf, unsigned int buflen);

SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_auth_shutdown)
{

	return SWITCH_STATUS_SUCCESS;
}

static switch_status_t auth_file_open(switch_core_session_t* session, const char* modname
	, const char* file, switch_file_handle_t* vfh)
{
	switch_status_t status = SWITCH_STATUS_SUCCESS;

	do
	{
		switch_image_t* new_image = NULL;

		switch_img_copy(g_bk_image, &new_image);
		//switch_memory_pool_t* pool = switch_get_memory;
		//vfh->modname = switch_core_strdup(session, modname);
		const char* modname = "mod_auth";
		const char* name = auth_file_supported_formats[0];
		switch_memory_pool_t* pool = switch_core_session_get_pool(session);
		vfh->modname = modname;
		vfh->flags = SWITCH_FILE_OPEN | SWITCH_FILE_FLAG_VIDEO;
		vfh->fd = (switch_file_t*)new_image;
		
		
		switch_mutex_init(&vfh->flag_mutex, SWITCH_MUTEX_NESTED, pool);

		vfh->private_info = (void*)session;
		if ((vfh->file_interface = switch_loadable_module_get_file_interface(name, NULL)) == 0) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Invalid file format [%s] for [%s]!\n", modname, file);
			status = SWITCH_STATUS_FALSE;
			break;
		}
	} while (FALSE);

	return status;
}

static switch_status_t auth_file_close(switch_core_session_t* session, const char* modname
	, const char* file, switch_file_handle_t* vfh)
{
	switch_status_t status = SWITCH_STATUS_SUCCESS;

	if (vfh)
	{

		switch_mutex_lock(vfh->flag_mutex);
		vfh->flags = SWITCH_FILE_DONE;

		if (vfh->fd)
		{
			switch_image_t* img = (switch_image_t*)vfh->fd;
			switch_img_free(&img);
		}

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

	return status;
}

//// B线程中监听事件并执行逻辑
//static switch_status_t custom_event_handler(switch_event_t* event) {
//	// 处理自定义事件的逻辑，在B线程中执行
//	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Custom event received in B thread\n");
//	return SWITCH_STATUS_SUCCESS;
//}

// write handle image to frame
static switch_status_t auth_file_write(switch_file_handle_t* handle, switch_frame_t* frame)
{
	switch_status_t status = SWITCH_STATUS_SUCCESS;
	uint32_t center_x = 0;
	uint32_t center_y = 0;
	uint32_t width = 400;
	uint32_t height = 100;

	char* dtmf_account = NULL;
	char* dtmf_passwd = NULL;
	char buf[256] = { 0 };
	switch_image_t* img = (switch_image_t*)handle->fd;
	switch_image_t* auth_image = NULL;
	switch_image_t* auth_account = NULL;
	switch_image_t* auth_passwd = NULL;
	auth_session_data_t* user_data = (auth_session_data_t*)handle->private_info;

	switch_core_session_t* session = (switch_core_session_t*)user_data->session;
	//switch_channel_t* channel = switch_core_session_get_channel(session);

	if (user_data)
	{

		switch_core_media_lock_video_file(user_data->session, SWITCH_RW_READ);

		if ((user_data->flags & AUTH_DTMF_ACCOUNT)
			&& user_data->account != NULL)
		{
			dtmf_account = switch_mprintf("#cccccc:#142e55::20:acccount[%s]:", user_data->account);
			user_data->flags &= ~AUTH_DTMF_ACCOUNT;
		}

		if ((user_data->flags & AUTH_DTMF_PASSWD)
			&& user_data->passwd != NULL)
		{
			dtmf_passwd = switch_mprintf("#cccccc:#142e55::20:passwd[%s]:", user_data->passwd);
			user_data->flags &= ~AUTH_DTMF_PASSWD;
		}
		switch_core_media_unlock_video_file(user_data->session, SWITCH_RW_READ);
	}

	if (dtmf_account && dtmf_account[0] != '\0')
	{
		auth_account = switch_img_write_text_img(width, height, SWITCH_TRUE, dtmf_account);
	}

	switch_safe_free(dtmf_account);
	if (dtmf_passwd && dtmf_passwd[0] != '\0')
	{
		auth_passwd = switch_img_write_text_img(width, height, SWITCH_TRUE, dtmf_passwd);
	}
	switch_safe_free(dtmf_passwd);
	
	if (auth_account)
	{
		center_x = img->w / 2;
		center_y = img->h / 2;
		switch_img_patch(img, auth_account, center_x - width/2, center_y - height/2 );
		switch_img_free(&auth_account);
	}

	if (auth_passwd)
	{
		center_x = img->w / 2;
		center_y = img->h / 2;
		switch_img_patch(img, auth_passwd, center_x - width / 2, center_y + height/2);
		switch_img_free(&auth_passwd);
	}

	frame->img = img;
	return status;
}

//static switch_status_t send_image(switch_core_session_t* session, switch_image_t* image)
//{
//	switch_frame_t fr = { 0 };
//	unsigned char* buf = NULL;
//	int buflen = SWITCH_RTP_MAX_BUF_LEN;
//
//	buf = switch_core_session_alloc(session, buflen);
//	fr.packet = buf;
//	fr.packetlen = buflen;
//	fr.data = buf + 12;
//	fr.buflen = buflen - 12;
//	fr.img = image;
//	switch_core_session_write_video_frame(session, &fr, SWITCH_IO_FLAG_FORCE, 0);
//}

switch_status_t input_callback_function(switch_file_handle_t* vfh, void* input,
	auth_dtmf_type_t input_type, void* buf, unsigned int buflen)
{
	switch_status_t result = SWITCH_STATUS_SUCCESS;

	char input_char = *((char*)input);
	const char* input_buf = (const char*)buf;
	unsigned int input_len = buflen;

	auth_session_data_t* user_data = (auth_session_data_t*)vfh->private_info;
	switch_core_session_t* session = (switch_core_session_t*)user_data->session;
	switch_channel_t* channel = switch_core_session_get_channel(session);

	if (vfh)
	{
		auth_session_data_t* user_data = (auth_session_data_t*)vfh->private_info;
		switch_core_media_lock_video_file(session, SWITCH_RW_READ);

		if (input_type == AUTH_INPUT_TYPE_ACCOUNT)
		{
			user_data->flags |= AUTH_DTMF_ACCOUNT;

			if (user_data->account && user_data->account[0] != '\0')
			{
				free(user_data->account);
			}

			user_data->account = strdup(input_buf);
		}
		else
		{

			user_data->flags |= AUTH_DTMF_PASSWD;


			if (user_data->passwd && user_data->passwd[0] != '\0')
			{
				free(user_data->passwd);
			}

			user_data->passwd = strdup(input_buf);
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

	switch_size_t i = 0, x = strlen(buf);
	switch_status_t status = SWITCH_STATUS_FALSE;
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
				status = SWITCH_STATUS_TIMEOUT;
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
				status = SWITCH_STATUS_TIMEOUT;
				break;
			}
		}

		if (switch_channel_has_dtmf(channel)) 
		{
			switch_dtmf_t dtmf = { 0 };
			switch_size_t y;

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
					return SWITCH_STATUS_SUCCESS;
				}


				buf[x++] = dtmf.digit;
				buf[x] = '\0';

				if (callback)
				{
					callback(vfh, (void*)&dtmf, input_type, buf, x);
				}

				if (x >= buflen || x >= maxdigits) 
				{
					switch_safe_free(abuf);
					return SWITCH_STATUS_SUCCESS;
				}
			}
		}

		if (switch_channel_test_flag(channel, CF_SERVICE)) 
		{
			switch_cond_next();
		}
		else 
		{
			status = switch_core_session_read_frame(session, &read_frame, SWITCH_IO_FLAG_NONE, 0);
			if (!SWITCH_READ_ACCEPTABLE(status)) 
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

	if (g_bk_image)
	{
		switch_img_free(&g_bk_image);
		g_bk_image = NULL;
	}
	return status;
}

SWITCH_STANDARD_APP(conference_function)
{
	switch_status_t result = SWITCH_STATUS_FALSE;
	switch_file_handle_t vfh = { 0 };
	BOOL done = FALSE;
	int cur = 0;
	int maxCount = 100;
	char* imagePath = "C:\\Users\\Administrator\\Desktop\\001.png";
	char buf_account[256] = { 0 };
	char buf_passwd[256] = { 0 };
	char terminator = ' ';

	do
	{
		switch_core_session_t* s = session;
		switch_channel_t* channel = switch_core_session_get_channel(session);
		if (!switch_channel_test_flag(channel, CF_VIDEO))
		{
			break;
		}

		if (!switch_channel_media_ready(channel))
		{
			break;
		}

		switch_channel_set_flag(channel, CF_VIDEO_ECHO);

		for (cur = 0; switch_channel_ready(channel) && !done && cur < maxCount; cur++)
		{

		}

		switch_channel_wait_for_flag(channel, CF_VIDEO_READY, SWITCH_TRUE, 10000, NULL);

		const char* bk_image = "C:\\Users\\Administrator\\Desktop\\001.png";
		//g_bk_image = switch_img_read_from_file(bk_image, SWITCH_IMG_FMT_ARGB);
		g_bk_image = switch_img_read_png(bk_image, SWITCH_IMG_FMT_I420);

		result = auth_file_open(session, "auth", "", &vfh);
		auth_session_data_t user_data = { 0 };
		user_data.session = session;
		user_data.flags = AUTH_DTMF_ACCOUNT;
		vfh.private_info = (void*)&user_data;

		//switch_core_session_set_private_class(session, (void*)&user_data, SWITCH_PVT_SECONDARY);
		//switch_core_session_set_private_class(session, (void*)&vfh, SWITCH_PVT_PRIMARY);

		if (result)
		{
			break;
		}
		switch_core_media_set_video_file(session, &vfh, SWITCH_RW_READ);

		//if (!(smh = session->media_handle)) 
		char terminator = ' ';
		auth_dtmf_type_t input_type = AUTH_INPUT_TYPE_ACCOUNT;
		result = collect_input(&vfh, input_type, buf_account, 256, 10, "#", &terminator
			, 10000000, 100000, 0, input_callback_function);
		//send_image_response(session, imagePath);

		user_data.flags = AUTH_DTMF_PASSWD;
		input_type = AUTH_INPUT_TYPE_PASSWD;
		result = collect_input(&vfh, input_type, buf_passwd, 256, 10, "#", &terminator
			, 10000000, 100000, 0, input_callback_function);

		switch_core_media_set_video_file(session, NULL, SWITCH_RW_READ);

		result = SWITCH_STATUS_SUCCESS;
	} while (FALSE);

	if (g_bk_image)
	{
		switch_img_free(&g_bk_image);
		g_bk_image = NULL;
	}
	auth_file_close(session, modname, "", &vfh);

	return result;
}

SWITCH_MODULE_LOAD_FUNCTION(mod_auth_load)
{
	switch_api_interface_t *api_interface = NULL;
	switch_application_interface_t* app_interface = NULL;
	switch_file_interface_t* file_interface;

	//av_log_set_callback(log_callback);
	//av_log_set_level(AV_LOG_INFO);

	//av_log(NULL, AV_LOG_INFO, "%s %d\n", "av_log callback installed, level=", av_log_get_level());

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
