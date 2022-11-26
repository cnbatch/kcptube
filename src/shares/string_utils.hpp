#pragma once
#include <algorithm> 
#include <cctype>
#include <string>

namespace str_utils
{
	template<typename T>
	constexpr inline uint64_t strhash(const T* str, int h = 0)
	{
		return str[h] ? (strhash(str, h + 1) * 5) ^ static_cast<uint64_t>(str[h]) : 4096;
	}

	// trim from start (in place)
	inline void ltrim(std::string &s)
	{
		s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](auto ch)
			{
				return !std::isspace(ch);
			}));
	}

	// trim from end (in place)
	inline void rtrim(std::string &s)
	{
		s.erase(std::find_if(s.rbegin(), s.rend(), [](auto ch)
			{
				return !std::isspace(ch);
			}).base(), s.end());
	}

	// trim from both ends (in place)
	inline void trim(std::string &s)
	{
		ltrim(s);
		rtrim(s);
	}

	// trim from start (copying)
	inline std::string ltrim_copy(std::string s)
	{
		ltrim(s);
		return s;
	}

	// trim from end (copying)
	inline std::string rtrim_copy(std::string s)
	{
		rtrim(s);
		return s;
	}

	// trim from both ends (copying)
	inline std::string trim_copy(std::string s)
	{
		trim(s);
		return s;
	}

	inline void to_lower(std::string &s)
	{
		std::transform(s.begin(), s.end(), s.begin(),
			[](auto c) { return tolower(c); });
	}

	inline std::string to_lower_copy(std::string s)
	{
		std::transform(s.begin(), s.end(), s.begin(),
			[](auto c) { return tolower(c); });
		return s;
	}

	inline void to_upper(std::string &s)
	{
		std::transform(s.begin(), s.end(), s.begin(),
			[](auto c) { return toupper(c); });
	}

	inline std::string to_upper_copy(std::string s)
	{
		std::transform(s.begin(), s.end(), s.begin(),
			[](auto c) { return tolower(c); });
		return s;
	}
}