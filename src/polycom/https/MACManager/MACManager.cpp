// MACManager.cpp : DLL 응용 프로그램을 위해 내보낸 함수를 정의합니다.
//

#include "MACManager.h"
#include "HmacUtil.h"
#include "HelperUtil.h"

#include <iostream>
#include <fstream>

static IMACManager* gManager = nullptr;

IMACManager* createMacManager(const char* const key)
{
	if (!gManager)
	{
		gManager = new MACManager(key);
	}
	return gManager;
}

void destroyMacManager(IMACManager* pThis)
{
	if (gManager)
	{
		delete gManager;
		gManager = nullptr;
	}

}

int MACManager::getEncryptUrl(const char* const url, char* pszString, size_t* pcchString, const char * const curTime)
{
	if (pszString == NULL)
	{
		this->sEncryptedUrl = HmacUtil::makeEncryptUrl(m_key, url, curTime);
		*pcchString = this->sEncryptedUrl.length() + 1;
		return 0;
	}
	else {
		return strcpy_s(pszString, *pcchString, this->sEncryptedUrl.c_str());
	}
}

int MACManager::getEncryptUrl(const char* const url, char* pszString, size_t* pcchString)
{
	if (pszString == NULL)
	{
		const std::string curTime = HelperUtil::getTimeInMillis();
		this->sEncryptedUrl = HmacUtil::makeEncryptUrl(m_key, url, curTime);
		*pcchString = this->sEncryptedUrl.length()+1;
		return 0;
	} else {
		return strcpy_s(pszString, *pcchString, this->sEncryptedUrl.c_str());
	}
}

int MACManager::getKeyFromFile(char* pszString, size_t* pcchString)
{
	const char* const filePath = "NHNAPIGatewayKey.properties";
	return MACManager::getKeyFromFile(filePath, pszString, pcchString);
}

int MACManager::getKeyFromFile(const char* const filePath, char* pszString, size_t* pcchString)
{
	std::string line;
	std::string result;
	std::ifstream ifs(filePath);
	if (ifs.good())	{
		std::getline(ifs, line);
	} else {
		HelperUtil::logErr("File Not Found [" + std::string(filePath) + "]");
		return -1;
	}
	std::size_t lastIndexOfEqual = line.find_last_of(HelperUtil::EQUAL);
	if (lastIndexOfEqual != std::string::npos) {
		std::istringstream iss(line.substr(lastIndexOfEqual+1));
		iss >> std::skipws >> result;
	} else {
		HelperUtil::logErr("Invalid Key File");
		return -1;
	}
	if (pszString == NULL) {
		*pcchString = result.length()+1;
		return 0;
	} else {
		return strcpy_s(pszString, *pcchString, result.c_str());
	}
}