#pragma once

//#pragma comment(lib,"Crypt32.lib")

#include <iostream>
#include <vector>
#include <string>
//#include <Windows.h>
//#include <wincrypt.h>
//#include <stdexcept>

#include "MacEngine.h"
#include "HelperUtil.h"

class HmacUtil
{
private:
	const static int MAX_URL_LENGTH;
	const static std::string MSGPAD_KEY;
	const static std::string MD_KEY;
	static std::string getMessage(const std::string& url, const std::string& msgpad);
	static std::string appendMsgPadAndMd(const std::string& url, const std::string& msgpad, const std::string& md);
	static std::string createHmac(const std::string& key, const std::string& message);

public:
	static std::string makeEncryptUrl(const std::string& key, const std::string& url, const std::string& curTime);
};

