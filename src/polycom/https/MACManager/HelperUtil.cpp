#include "stdafx.h"
#include "HelperUtil.h"

const std::string HelperUtil::PERCENT = "%";
const std::string HelperUtil::QUESTION = "?";
const std::string HelperUtil::AMPERSAND = "&";
const std::string HelperUtil::EQUAL = "=";

LONGLONG HelperUtil::convertFileTimeToPosix(FILETIME& ft)
{
	const LONGLONG UNIX_EPOCH_DIFF = 116444736000000000LL;
	LARGE_INTEGER date, adjust;
	date.HighPart = ft.dwHighDateTime;
	date.LowPart = ft.dwLowDateTime;
	adjust.QuadPart = UNIX_EPOCH_DIFF;

	// Remove the diff between 1970 and 1601
	date.QuadPart -= adjust.QuadPart;
	// Convert back from 100-nanoseconds to milliseconds
	return date.QuadPart / 10000;
}

std::string HelperUtil::convertToString(DWORD& value)
{
	std::stringstream ss;
	ss << value;
	return ss.str();
}

void HelperUtil::throwErrorWithMessage(std::string& message)
{
	std::runtime_error exception(message);
	throw (exception);
}

void HelperUtil::throwErrorFromMethod(std::string& methodName)
{
	DWORD error = GetLastError();
	std::string message = "Error in " + methodName + " 0x" + HelperUtil::convertToString(error);
	HelperUtil::throwErrorWithMessage(message);
}

std::string HelperUtil::getTimeInMillis()
{
	FILETIME ft_now;
	GetSystemTimeAsFileTime(&ft_now);
	LONGLONG ll_now = HelperUtil::convertFileTimeToPosix(ft_now);
	std::ostringstream oss;
	oss << ll_now;
	return oss.str();
}

std::string HelperUtil::concatenateString(const std::string& prefix, const std::string& suffix)
{
	std::string result = prefix + suffix;
	return result;
}

std::string HelperUtil::urlEncode(const std::string& str)
{
	const std::string unreserved = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~";

	std::ostringstream oss;
	for (size_t i = 0; i < str.length(); ++i) 
	{
		const char ch = str[i];
		if (unreserved.find_first_of(ch) != std::string::npos) 
		{
			oss << ch;
		} 
		else 
		{
			if (ch == ' ')
			{
				oss << "+";
			}
			else
			{
				oss << PERCENT << std::hex << std::uppercase << (unsigned int)ch;
			}
		}
	}
	return oss.str();
}

void HelperUtil::logErr(const std::string message)
{
	SYSTEMTIME st;
	GetLocalTime(&st);
	std::ostringstream oss;
	oss << std::dec << st.wYear;
	oss << std::setfill('0') << std::setw(2) << st.wMonth;
	oss << std::setfill('0') << std::setw(2) << st.wDay;
	const std::string FILE_NAME = "error_" + oss.str() + ".log";
	oss.str("");
	oss << std::dec << st.wYear << "-";
	oss << std::setfill('0') << std::setw(2) << st.wMonth << "-";
	oss << std::setfill('0') << std::setw(2) << st.wDay << " ";
	oss << std::setfill('0') << std::setw(2) << st.wHour << ":";
	oss << std::setfill('0') << std::setw(2) << st.wMinute << ":";
	oss << std::setfill('0') << std::setw(2) << st.wSecond << " ";
	oss << std::setfill('0') << std::setw(3) << st.wMilliseconds;
	const std::string TIME_STRING = oss.str();
	std::ofstream ofs(FILE_NAME.c_str(), std::ios::app);
	if (ofs.good())
	{
		ofs << "[" << TIME_STRING << "] " << message << std::endl;
	}
	ofs.close();
}