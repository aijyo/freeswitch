#pragma once

#include <iostream>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <string>
#include <map>


class HelperUtil
{
public:
	static const std::string PERCENT;
	static const std::string QUESTION;
	static const std::string AMPERSAND;
	static const std::string EQUAL;

	static std::string convertToString(std::uint32_t& value);

	//static void throwErrorWithMessage(std::string& message);
	//static void throwErrorFromMethod(std::string& methodName);

	/**
	 * Returns the current time in millisecond.
	 * @return string representing the current time in millisecond
	 */
	static std::string getTimeInMillis();

	/**
	 * Concatenates the prefix and the suffix and returns the result.
	 * @param prefix a string reference to the prefix
	 * @param suffix a string reference to the suffix
	 * @return concatednated string of prefix and suffix
	 */
	static std::string concatenateString(const std::string& prefix, const std::string& suffix);

	/**
	 * Translates a string into application/x-www-form-urlencoded format.
	 * @param str string to translate
	 * @return translated string
	 */
	static std::string urlEncode(const std::string& str);

	static void logErr(const std::string message);
};

