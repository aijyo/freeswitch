#include <string>

#include "IMACManager.h"

class MACManager : public IMACManager
{
private:
	const std::string m_key;
	std::string sEncryptedUrl;
public:
	MACManager(const char* const key) : m_key(key) {}
	void Release() { delete this; }
	int getEncryptUrl(const char* const url, char* pszString, size_t* pcchString);
	int getEncryptUrl(const char* const url, char* pszString, size_t* pcchString, const char* const curTime);
	int getKeyFromFile(char* pszString, size_t* pcchString);
	int getKeyFromFile(const char* const filePath, char* pszString, size_t* pcchString);
};