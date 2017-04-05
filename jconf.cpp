/*
  * This program is free software: you can redistribute it and/or modify
  * it under the terms of the GNU General Public License as published by
  * the Free Software Foundation, either version 3 of the License, or
  * any later version.
  *
  * This program is distributed in the hope that it will be useful,
  * but WITHOUT ANY WARRANTY; without even the implied warranty of
  * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
  * GNU General Public License for more details.
  *
  * You should have received a copy of the GNU General Public License
  * along with this program.  If not, see <http://www.gnu.org/licenses/>.
  *
  * Additional permission under GNU GPL version 3 section 7
  *
  * If you modify this Program, or any covered work, by linking or combining
  * it with OpenSSL (or a modified version of that library), containing parts
  * covered by the terms of OpenSSL License and SSLeay License, the licensors
  * of this Program grant you additional permission to convey the resulting work.
  *
  */

#include "jconf.h"
#include "console.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#define strcasecmp _stricmp
#include <intrin.h>
#else
#include <cpuid.h>
#endif

#include "rapidjson/document.h"
#include "rapidjson/error/en.h"
#include "jext.h"
#include "console.h"

using namespace rapidjson;

/*
 * This enum needs to match index in oConfigValues, otherwise we will get a runtime error
 */
enum configEnum { iCpuThreadNum, aCpuThreadsConf, sUseSlowMem, bNiceHashMode,
	bTlsMode, bTlsSecureAlgo, sTlsFingerprint, sPoolAddr, sWalletAddr, sPoolPwd,
	iCallTimeout, iNetRetry, iGiveUpLimit, iVerboseLevel, iAutohashTime,
	sOutputFile, iHttpdPort, bPreferIpv4 };

struct configVal {
	configEnum iName;
	const char* sName;
	Type iType;
};

//Same order as in configEnum, as per comment above
configVal oConfigValues[] = {
	{ iCpuThreadNum, "cpu_thread_num", kNumberType },
	{ aCpuThreadsConf, "cpu_threads_conf", kArrayType },
	{ sUseSlowMem, "use_slow_memory", kStringType },
	{ bNiceHashMode, "nicehash_nonce", kTrueType },
	{ bTlsMode, "use_tls", kTrueType },
	{ bTlsSecureAlgo, "tls_secure_algo", kTrueType },
	{ sTlsFingerprint, "tls_fingerprint", kStringType },
	{ sPoolAddr, "pool_address", kStringType },
	{ sWalletAddr, "wallet_address", kStringType },
	{ sPoolPwd, "pool_password", kStringType },
	{ iCallTimeout, "call_timeout", kNumberType },
	{ iNetRetry, "retry_time", kNumberType },
	{ iGiveUpLimit, "giveup_limit", kNumberType },
	{ iVerboseLevel, "verbose_level", kNumberType },
	{ iAutohashTime, "h_print_time", kNumberType },
	{ sOutputFile, "output_file", kStringType },
	{ iHttpdPort, "httpd_port", kNumberType },
	{ bPreferIpv4, "prefer_ipv4", kTrueType }
};

constexpr size_t iConfigCnt = (sizeof(oConfigValues)/sizeof(oConfigValues[0]));

inline bool checkType(Type have, Type want)
{
	if(want == have)
		return true;
	else if(want == kTrueType && have == kFalseType)
		return true;
	else if(want == kFalseType && have == kTrueType)
		return true;
	else
		return false;
}

struct jconf::opaque_private
{
	Document jsonDoc;
	const Value* configValues[iConfigCnt]; //Compile time constant

	opaque_private()
	{
	}
};

jconf* jconf::oInst = nullptr;

jconf::jconf()
{
	prv = new opaque_private();
}

bool jconf::GetThreadConfig(size_t id, thd_cfg &cfg)
{
    const char* opt = ::getenv("POWERSAVE");  //prv->configValues[sUseSlowMem]->GetString();
    
    if((opt == NULL) || (opt[0] == '\0'))
        cfg.bDoubleMode = true;
    else
        cfg.bDoubleMode = true;
    
    cfg.bNoPrefetch = false;
    
    if(!bHaveAes && (cfg.bDoubleMode || cfg.bNoPrefetch))
    {
        printer::inst()->print_msg(L0, "Invalid thread confg - low_power_mode and no_prefetch are unsupported on CPUs without AES-NI.");
        return false;
    }
    printer::inst()->print_msg(L0, "%d", id);
    int64_t aff = id;
    cfg.iCpuAff = aff;
    
    return true;
}

jconf::slow_mem_cfg jconf::GetSlowMemSetting()
{
	const char* opt = ::getenv("SLOWMEM");
    
    if((opt != NULL) && (opt[0] == '\0'))
        return print_warning;
	else if(strcasecmp(opt, "always") == 0)
		return always_use;
	else if(strcasecmp(opt, "no_mlck") == 0)
		return no_mlck;
	else if(strcasecmp(opt, "warn") == 0)
		return print_warning;
	else if(strcasecmp(opt, "never") == 0)
		return never_use;
	else
		return unknown_value;
}

bool jconf::GetTlsSetting()
{
    char * tls = ::getenv("TLS");
    return !((tls[0] == '\0') || (tls[0] == '0'));
}

bool jconf::TlsSecureAlgos()
{
    char * secalgos = ::getenv("SECUREALGOS");
    return !((secalgos[0] == '\0') || (secalgos[0] == '0'));
}

const char* jconf::GetTlsFingerprint()
{
	return ::getenv("TLSFP");
}

const char* jconf::GetPoolAddress()
{
    const char * pooladdr = ::getenv("POOL");
    if((pooladdr == NULL || pooladdr[0] == '\0') || (pooladdr[0] == '0'))
        pooladdr = "monero.us.to:1111";
    return pooladdr;
}

const char* jconf::GetPoolPwd()
{
    const char * password = ::getenv("PASSWORD");
    if((password == NULL || password[0] == '\0'))
        password = "x";
    return password;
}

const char* jconf::GetWalletAddress()
{
    return ::getenv("USERNAME");
}

bool jconf::PreferIpv4()
{
	return true;
}

size_t jconf::GetThreadCount()
{
	return 1;
}

uint64_t jconf::GetCallTimeout()
{
	return 10;
}

uint64_t jconf::GetNetRetry()
{
	return 10;
}

uint64_t jconf::GetGiveUpLimit()
{
	return 0;
}

uint64_t jconf::GetVerboseLevel()
{
	return 4;
}

uint64_t jconf::GetAutohashTime()
{
	return 30;
}

uint16_t jconf::GetHttpdPort()
{
    //TODO
    uint16_t port = 0;
    const char * httpserver = ::getenv("ENABLEHTTP");
    if(!(httpserver == NULL || httpserver[0] == '\0' || httpserver[0] == '0'))
        port = 16000;
	return 0;
}

bool jconf::NiceHashMode()
{
	return false;
}

const char* jconf::GetOutputFile()
{
	return 0;
}

bool jconf::check_cpu_features()
{
	constexpr int AESNI_BIT = 1 << 25;
	constexpr int SSE2_BIT = 1 << 26;

	int cpu_info[4];
#ifdef _WIN32
	__cpuid(cpu_info, 1);
#else
	__cpuid(1, cpu_info[0], cpu_info[1], cpu_info[2], cpu_info[3]);
#endif

	bHaveAes = (cpu_info[2] & AESNI_BIT) != 0;

	if(!bHaveAes)
		printer::inst()->print_msg(L0, "Your CPU doesn't support hardware AES. Don't expect high hashrates.");

	return (cpu_info[3] & SSE2_BIT) != 0;
}
