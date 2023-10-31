/*
100% free public domain implementation of the HMAC-SHA1 algorithm
by Chien-Chung, Chung (Jim Chung) <jimchung1221@gmail.com>
*/


#ifndef __MAC_ENGINE_H__
#define __MAC_ENGINE_H__

#include "SHA1.h"
#include <string>
typedef unsigned char BYTE;

class MacEngine : public CSHA1
{
private:
	BYTE m_ipad[64];
	BYTE m_opad[64];

	char * szReport;
	char * SHA1_Key;
	char * AppendBuf1;
	char * AppendBuf2;


public:

	enum {
		SHA1_DIGEST_LENGTH = 20,
		SHA1_BLOCK_SIZE = 64,
		HMAC_BUF_LEN = 4096
	};

	MacEngine()
		:szReport(new char[HMAC_BUF_LEN]),
		SHA1_Key(new char[HMAC_BUF_LEN]),
		AppendBuf1(new char[HMAC_BUF_LEN]),
		AppendBuf2(new char[HMAC_BUF_LEN])
	{}

	~MacEngine()
	{
		delete[] szReport;
		delete[] AppendBuf1;
		delete[] AppendBuf2;
		delete[] SHA1_Key;
	}

	std::string getMdString(BYTE *text, int text_len, BYTE *key, int key_len);
};


#endif /* __MAC_ENGINE_H__ */
