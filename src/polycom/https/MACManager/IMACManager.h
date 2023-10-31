#ifdef MACMANAGER_EXPORTS
	#define MACMANAGER_API __declspec(dllexport)
#else
	#define MACMANAGER_API __declspec(dllimport)
#endif

struct IMACManager
{
	virtual int getEncryptUrl(const char* const url, char* pszString, size_t* pcchString) = 0;
	virtual int getEncryptUrl(const char* const url, char* pszString, size_t* pcchString, const char* const curTime) = 0;
	virtual int getKeyFromFile(char* pszString, size_t* pcchString) = 0;
	virtual int getKeyFromFile(const char* const filePath, char* pszString, size_t* pcchString) = 0;
	virtual void Release() = 0;
};

IMACManager* createMacManager(const char* const key);
void destroyMacManager(IMACManager* pThis);