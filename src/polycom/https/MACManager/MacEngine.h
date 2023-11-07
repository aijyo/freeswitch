#ifndef NATIVE_MACENGINE_H
#define NATIVE_MACENGINE_H
#include <string>
#include "SHA1.h"
namespace native {
typedef unsigned char BYTE;
class MacEngine : public CSHA1 {
   private:
    BYTE m_ipad[64];
    BYTE m_opad[64];

    char *szReport;
    char *SHA1_Key;
    char *AppendBuf1;
    char *AppendBuf2;

   public:
    enum { SHA1_DIGEST_LENGTH = 20, SHA1_BLOCK_SIZE = 64, HMAC_BUF_LEN = 4096 };

    MacEngine()
        : szReport(new char[HMAC_BUF_LEN]),
          SHA1_Key(new char[HMAC_BUF_LEN]),
          AppendBuf1(new char[HMAC_BUF_LEN]),
          AppendBuf2(new char[HMAC_BUF_LEN]) {}

    ~MacEngine() {
        delete[] szReport;
        delete[] AppendBuf1;
        delete[] AppendBuf2;
        delete[] SHA1_Key;
    }

    std::string getMdString(BYTE *text, int text_len, BYTE *key, int key_len);
};

}  // namespace native
#endif