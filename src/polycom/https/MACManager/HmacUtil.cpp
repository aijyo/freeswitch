#include "stdafx.h"
#include "HmacUtil.h"

const int HmacUtil::MAX_URL_LENGTH = 255;
const std::string HmacUtil::MSGPAD_KEY = "msgpad";
const std::string HmacUtil::MD_KEY = "md";

std::string HmacUtil::getMessage(const std::string& url, const std::string& msgpad)
{
	const std::string concatUrl = url.substr(0, HmacUtil::MAX_URL_LENGTH);
	return HelperUtil::concatenateString(concatUrl, msgpad);
}

std::string HmacUtil::appendMsgPadAndMd(const std::string& url, const std::string& msgpad, const std::string& md)
{
	std::ostringstream oss;
	oss << url;

	size_t foundIndex = url.find(HelperUtil::QUESTION);
	if (foundIndex == std::string::npos || url.empty())
	{
		oss << HelperUtil::QUESTION;
	}
	else
	{
		oss << HelperUtil::AMPERSAND;
	}
	oss << MSGPAD_KEY << HelperUtil::EQUAL << msgpad;
	oss << HelperUtil::AMPERSAND;
	oss << MD_KEY << HelperUtil::EQUAL << md;
	return oss.str();
}

std::string HmacUtil::createHmac(const std::string& key, const std::string& message)
{
	MacEngine macEngine;
	std::string md = macEngine.getMdString((unsigned char*)message.c_str(), message.length(), (unsigned char*)key.c_str(), key.length());
	
	return md;	
}

std::string HmacUtil::makeEncryptUrl(const std::string& key, const std::string& url, const std::string& curTime)
{
	const std::string msgpad = curTime;
	const std::string message = getMessage(url, msgpad);

	std::string md = createHmac(key, message);
	md = HelperUtil::urlEncode(md);

	std::string encryptedUrl = appendMsgPadAndMd(url, msgpad, md);

	return encryptedUrl;
}