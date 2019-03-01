#include <stdio.h>
#include <dlfcn.h>
#include "../CpComm/Comm_Export/CpCommExport.h"
#include <unistd.h>
#include <iostream>
#include <limits.h>
#include "../Tool_Common/CpRsString.h"
#include "../Tool_Common/CpRsFuncBase.h"
#include "../CPISPPlugIn/CPISPExport/CpIspExport.h"
#include "CpFlashDat.h"
#include "UnixParseArgs.h"
#include <fstream>
using namespace std;
/*-------------------------------------------------------------------------*/

STRUCT_WAITING_STRUCT gStWaiting = {_WAITING_NONE, 0};
//#define DLL_FILE_NAME "../lib/libbin/libRTUsb.so"
#define DLL_FILE_NAME_COMM "libComm.so"
BYTE g_ucszVersion[3] = {1,0,0};

void ShowToolVersion()
{
    printf("\033[33mRealtek Linux ISP Utility V%d.%d.%d (C) 2019\r\n\033[m", g_ucszVersion[0], g_ucszVersion[1], g_ucszVersion[2]);  
}


/*
--ispcopysw --fw ./test/1.bin --sig ./test/LENOVO_RTD2181S_180531v0.bin.sig --pubkey ./test/lenovopubkey.pem --subcert ./test/sub_symantec.pem --bank 0
*/

int main (int argc, char* argv[])
{
    // parse arguments
    CCpParseArgsBase *pcpBaseArgs;
    CUnixParseArgs cUnixArgs;
    BYTE ucbuf[10] = {0};
    CCpRsString strCurrentPath;
    CCpRsString strDllName;
    CCpRsComm rsComm;
    STRUCT_ENUM_ERROR_TYPE enumError = _ERROR_SUCCESS;
    CCpIsp rsIsp;

    pcpBaseArgs = (CCpParseArgsBase *)&cUnixArgs;
    if(!pcpBaseArgs->ParseArgs(argc, (char *const*)argv))
    {
        printf("argument is illegal.\n");
        return 0;
    }
    ShowToolVersion();

    // software digital signature verify
    if(IS_Digital_SW_Verify(pcpBaseArgs->m_stCmd.stIspSetting.enumFuncType))
    {
        printf("software digital signature verify progress...\n");
        std::map<DWORD, STRUCT_FW_BANK_SETTING, sortAscending<DWORD> >::const_iterator it;
        it = pcpBaseArgs->m_stCmd.stIspSetting.mapFw.begin();
        string strFw = it->second.strFwPath;
        char cCmdBuf[1024] = {0};
        sprintf(cCmdBuf, "./rs_digital_sign --verify --fw %s --sig %s --pubkey %s --subcert %s",
         strFw.c_str(), pcpBaseArgs->m_stCmd.strSig.c_str(), pcpBaseArgs->m_stCmd.strPublic.c_str(), pcpBaseArgs->m_stCmd.strSubCert.c_str());
        remove("VerifyRet.txt");
        system(cCmdBuf);
        // check verify result
        ifstream file;
        file.open("VerifyRet.txt");
        char cRet[100] = {0};
        file>>cRet;
        string strRet;
        strRet = cRet;
        if(strRet.compare("Pass") == 0)
        {
            printf("software digital signature verify success...\n");
        }
        else if(strRet.compare("Fail") == 0)
        {
            printf("software digital signature verify fail...\n");
            return 0;
        }
        else
        {
            printf("software digital signature verify invaild...\n");
            return 0;
        }
    }
    
    strCurrentPath = GetCurrentProcessDir();
    strDllName = strCurrentPath + DLL_FILE_NAME_COMM;
    rsComm.LoadCommDllFile((TCHAR*)strDllName.c_str());
    rsComm.Initiallize();
    if(rsComm.GetCommCount() == 0)
    {
        printf("\033[31m ISP Fail! No available communication type!\033[31m\n");
        return _ERROR_COMM_NOTEXIST;
    }
    if(pcpBaseArgs->m_stCmd.stIspSetting.enumCommID == _ENUM_COMM_UNKNOWN)
    {
        enumError = rsComm.SetCommByID(_ENUM_COMM_USBHUBI2C);
    }
    else
    {
        enumError = rsComm.SetCommByID(pcpBaseArgs->m_stCmd.stIspSetting.enumCommID);
    }

    strDllName = strCurrentPath;
    strDllName +=  "libIsp.so";
    rsIsp.LoadIspDllFile((TCHAR*)strDllName.c_str());
    rsIsp.SetCommInterface(&rsComm);
    enumError = rsIsp.IspFlash(pcpBaseArgs->m_stCmd.stIspSetting);
    if(enumError != _ERROR_SUCCESS)
    {
        printf("\033[31mFail! Error Code: 0x%X\n\033[m", enumError);

    }
    else
    {
        printf( "\033[32mSuccess\n\033[m");  
    }

	return enumError;
}

