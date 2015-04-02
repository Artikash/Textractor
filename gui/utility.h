#pragma once
#include "ITH.h"

struct HookParam;
struct ProcessRecord;

DWORD Hash(const std::wstring& module, int length = -1);
DWORD ProcessCommand(const std::wstring& cmd, DWORD pid);
std::wstring GetProcessPath(DWORD pid);
void ConsoleOutput(LPCWSTR);
void ConsoleOutput(LPCSTR text);
std::wstring GetProcessTitle(DWORD pid);
std::wstring GetCode(const HookParam& hp, DWORD pid = 0);

// http://codesequoia.wordpress.com/2012/08/26/stdunique_ptr-for-windows-handles/
struct HandleDeleter
{
	typedef HANDLE pointer;
	void operator() (HANDLE h)
	{
		if (h != INVALID_HANDLE_VALUE) {
			CloseHandle(h);
		}
	}
};

typedef std::unique_ptr<HANDLE, HandleDeleter> UniqueHandle;

class FileWriter : public pugi::xml_writer
{
	HANDLE hFile;
public:
	FileWriter(HANDLE hFile) : hFile(hFile) {};
	~FileWriter() {};

	virtual void write(const void* data, size_t size)
	{
		DWORD dwNumberOfBytesWritten;
		WriteFile(hFile, data, size, &dwNumberOfBytesWritten, NULL);
	}
};

class WindowsError : public std::exception
{
private:
	std::string msg;
	DWORD error_code;
public:
	WindowsError(DWORD error_code);
	virtual const char *what() const;
};

HANDLE IthCreateThread(LPVOID start_addr, DWORD param);
bool IthCreateDirectory(LPCWSTR name);
HANDLE IthCreateFile(LPCWSTR name, DWORD option, DWORD share, DWORD disposition);
int MB_WC(const char* mb, wchar_t* wc, int wc_length);
int MB_WC_count(const char* mb, int mb_length);
int WC_MB(const wchar_t *wc, char* mb, int mb_length);
bool Parse(const std::wstring& cmd, HookParam& hp);

template <typename T>
std::wstring ToHexString(T i) {
	std::wstringstream ss;
	ss << std::uppercase << std::hex << i;
	return ss.str();
}

// http://jrdodds.blogs.com/blog/2004/08/raii_in_c.html
class CriticalSection
{
public:
	CriticalSection()
	{
		::InitializeCriticalSection(&m_rep);
	}
	~CriticalSection()
	{
		::DeleteCriticalSection(&m_rep);
	}
	void Enter()
	{
		::EnterCriticalSection(&m_rep);
	}
	void Leave()
	{
		::LeaveCriticalSection(&m_rep);
	}
private:
	CriticalSection(const CriticalSection&);
	CriticalSection& operator=(const CriticalSection&);

	CRITICAL_SECTION m_rep;
};

class CSLock
{
public:
	CSLock(CriticalSection& a_section)
		: m_section(a_section)
	{
		m_section.Enter();
	}
	~CSLock()
	{
		m_section.Leave();
	}
private:
	CSLock(const CSLock&);
	CSLock& operator=(const CSLock&);

	CriticalSection& m_section;
};
