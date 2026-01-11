#include <sstream>
#include <vector>
#include <iostream>
#include "dns_helper.hpp"
#include "../shares/string_utils.hpp"

using namespace str_utils;

dns_helper::dnstxt_results_t dns_helper::dns_split_address(const std::string &input_address, std::vector<std::string> &error_msg)
{
	dnstxt_results_t dnstxt_result;
	auto colon = input_address.rfind(':');
	if (colon == input_address.npos)
	{
		error_msg.emplace_back("Format Incorrect");
		return dnstxt_result;
	}

	bool correct_address = false;
	bool correct_port = false;

	std::string address_name = input_address.substr(0, colon);
	std::string input_port = input_address.substr(colon + 1);

	trim(address_name);
	trim(input_port);

	try
	{
		int32_t port_number = std::stoi(input_port);
		if (port_number > 0 && port_number < 65536)
		{
			correct_port = true;
			dnstxt_result.port_number = (asio::ip::port_type)port_number;
		}
	}
	catch (...)
	{
		correct_port = false;
	}

	if (address_name.empty())
	{
		correct_address = false;
		error_msg.emplace_back("Address is empty");
	}
	else
	{
		if (address_name.front() == '[' || address_name.back() == ']')
		{
			if (address_name.front() == '[' && address_name.back() == ']')
			{
				address_name = address_name.substr(1);
				address_name.pop_back();

				asio::error_code ec;
				dnstxt_result.ip_address = asio::ip::make_address_v6(address_name, ec);
				correct_address = !ec;
			}
		}
		else
		{
			asio::error_code ec;
			dnstxt_result.ip_address = asio::ip::make_address_v4(address_name, ec);
			correct_address = !ec;
		}
		dnstxt_result.host_address = address_name;
	}

	if (!correct_address)
		error_msg.emplace_back("Address Incorrect");

	if (!correct_port)
		error_msg.emplace_back("Port Number Incorrect");

	return dnstxt_result;
}


#if defined(__FreeBSD__) || defined(__NetBSD__ )|| defined(__OpenBSD__ ) || defined(__DragonFly__ ) || defined(__APPLE__ ) || defined(__linux__)
#include <cstdio>
#include <cstdlib>
#include <string>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <unistd.h>
#include <spawn.h>
#include <sys/wait.h>

extern char **environ;

void dns_helper::save_ddns_result(const std::string &exe_path, asio::ip::address input_address, asio::ip::port_type port_number)
{
	std::stringstream ss;
	if (input_address.is_v4())
		ss << input_address << ":" << port_number;
	else
		ss << "[" << input_address << "]:" << port_number;

	std::string arg = ss.str();
	pid_t pid;
	const char *path = exe_path.c_str();
	const char *argv[] = { path, arg.c_str(), NULL };

	int status = posix_spawn(&pid, path, NULL, NULL, const_cast<char *const *>(argv), environ);

	if (status != 0)
		std::cerr << "posix_spawn failed with error: " << strerror(status) << "\n";

	int wait_status;
	if (waitpid(pid, &wait_status, 0) == -1)
		std::cerr << "waitpid failed\n";

	if (WIFEXITED(wait_status))
	{
		int exit_code = WEXITSTATUS(wait_status);
		if (exit_code != 0)
			 std::cout << exe_path << " exited with code " << exit_code << std::endl;
	}
}

std::string dns_helper::query_dns_txt(const std::string &fqdn, std::vector<std::string> &error_msg)
{
	std::string host_address;
	if (fqdn.empty())
	{
		error_msg.emplace_back("empty domain");
		return host_address;
	}

#ifdef __OpenBSD__
	rrsetinfo *rrset = nullptr;
	int result = getrrsetbyname(fqdn.c_str(), C_IN, T_TXT, 0, &rrset);

	if (result != 0)
	{
		error_msg.emplace_back(std::string("getrrsetbyname: ") + hstrerror(h_errno));
		return host_address;
	}

	std::unique_ptr<rrsetinfo, decltype(&freerrset)> rrset_ptr(rrset, &freerrset);

	if (rrset_ptr->rri_nrdatas == 0)
	{
		error_msg.emplace_back("No TXT records found.");
		return host_address;
	}

	for (unsigned int i = 0; i < rrset_ptr->rri_nrdatas; ++i)
	{
		rdatainfo *rdata = &rrset_ptr->rri_rdatas[i];

		const unsigned char *ptr = rdata->rdi_data;
		const unsigned char *end = rdata->rdi_data + rdata->rdi_length;

		if (ptr < end)
		{
			int txt_len = *ptr;
			ptr++;
			if (ptr + txt_len <= end)
			{
				std::string ip_address_and_port((const char *)(ptr), txt_len);
				host_address = std::move(ip_address_and_port);
			}
		}
	}

#else

	if (res_init() != 0)
	{
		error_msg.emplace_back(std::string("res_init: ") + strerror(errno));
		return host_address;
	}

	unsigned char answer_buffer[NS_PACKETSZ] = {};

	int response_len = res_query(fqdn.c_str(), C_IN, T_TXT, answer_buffer, sizeof(answer_buffer));

	if (response_len < 0)
	{
		error_msg.emplace_back(std::string("res_query: ") + strerror(errno));
		return host_address;
	}

	ns_msg handle;
	if (ns_initparse(answer_buffer, response_len, &handle) < 0)
	{
		error_msg.emplace_back(std::string("ns_initparse: ") + strerror(errno));
		return host_address;
	}

	int answer_count = ns_msg_count(handle, ns_s_an);
	if (answer_count == 0)
	{
		error_msg.emplace_back("No TXT records found.");
		return host_address;
	}

	ns_rr rr;
	for (int i = 0; i < answer_count; i++)
	{
		if (ns_parserr(&handle, ns_s_an, i, &rr) < 0)
			continue;

		if (ns_rr_type(rr) == T_TXT)
		{
			const unsigned char *rdata = ns_rr_rdata(rr);
			int rdlen = ns_rr_rdlen(rr);

			const unsigned char *ptr = rdata;
			if (ptr < rdata + rdlen)
			{
				int txt_len = *ptr;
				ptr++;
				std::string ip_address_and_port = std::string((const char *)ptr, txt_len);
				ptr += txt_len;
				host_address = std::move(ip_address_and_port);
			}
		}
	}
#endif
	return host_address;
}
#endif

#if defined (_WIN32)
#pragma comment(lib, "Dnsapi.lib")
#include <windns.h>
#include <windnsdef.h>
#include <memory>

std::wstring string_to_wstring(const std::string &str);
std::string wstring_to_string(const std::wstring &wstr);

std::wstring string_to_wstring(const std::string &str)
{
	if (str.empty())
		return {};

	int required_size = MultiByteToWideChar(CP_ACP, 0, str.c_str(), static_cast<int>(str.length()), nullptr, 0);
	if (required_size == 0)
		return {};

	std::unique_ptr<wchar_t[]> result = std::make_unique<wchar_t[]>(required_size + 1);
	int bytes_converted = MultiByteToWideChar(CP_ACP, 0, str.c_str(), static_cast<int>(str.length()), result.get(), required_size);
	if (bytes_converted == 0)
		return {};
	std::wstring output = result.get();
	return output;
}

std::string wstring_to_string(const std::wstring &wstr)
{
	if (wstr.empty())
		return {};

	int required_size = WideCharToMultiByte(CP_ACP, 0, wstr.c_str(), static_cast<int>(wstr.length()), nullptr, 0, nullptr, nullptr);
	if (required_size == 0)
		return {};

	std::unique_ptr<char[]> result = std::make_unique<char[]>(required_size + 1);
	int bytes_converted = WideCharToMultiByte(CP_ACP, 0, wstr.c_str(), static_cast<int>(wstr.length()), result.get(), required_size, nullptr, nullptr);
	if (bytes_converted == 0)
		return {};
	
	std::string output = result.get();
	return output;
}

void dns_helper::save_ddns_result(const std::string &exe_path, asio::ip::address input_address, asio::ip::port_type port_number)
{
	std::stringstream ss;
	if (input_address.is_v4())
		ss << input_address << ":" << port_number;
	else
		ss << "[" << input_address << "]:" << port_number;

	std::string command = "\"" + exe_path + "\" " + ss.str();

	STARTUPINFOA si = {};
	PROCESS_INFORMATION pi = {};

	if (!CreateProcessA(NULL, command.data(), NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
	{
		std::cerr << "CreateProcess failed with error: " << std::to_string(GetLastError()) << "\n";
		if (pi.hProcess)
			CloseHandle(pi.hProcess);
		if (pi.hThread)
			CloseHandle(pi.hThread);
		return;
	}

	WaitForSingleObject(pi.hProcess, INFINITE);

	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
}

std::string dns_helper::query_dns_txt(const std::string &fqdn, std::vector<std::string> &error_msg)
{
	std::string host_address;
	if (fqdn.empty())
	{
		error_msg.emplace_back("empty domain");
		return host_address;
	}

	std::wstring fqdn_w = string_to_wstring(fqdn);
	if (fqdn_w.empty())
	{
		error_msg.emplace_back("empty domain");
		return host_address;
	}

	PDNS_RECORD pDnsRecord = NULL; 
	DNS_STATUS status;

	status = DnsQuery_W(fqdn_w.c_str(), DNS_TYPE_TEXT, DNS_QUERY_STANDARD, NULL, &pDnsRecord, NULL);

	if (status != ERROR_SUCCESS)
	{
		error_msg.emplace_back("Dns Query failure, error code: " + std::to_string(status));
		return host_address;
	}

	PDNS_RECORD pRecord = pDnsRecord;
	while (pRecord)
	{
		if (pRecord->wType == DNS_TYPE_TEXT)
		{
			for (DWORD i = 0; i < pRecord->Data.Txt.dwStringCount; i++)
			{
				std::wstring ip_address_and_port = pRecord->Data.Txt.pStringArray[i];
				host_address = wstring_to_string(ip_address_and_port);
			}
			break;
		}
		pRecord = pRecord->pNext;
	}

	if (pDnsRecord)
		DnsRecordListFree(pDnsRecord, DnsFreeRecordList);

	return host_address;
}
#endif

