#define NOMINMAX
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#pragma warning(push)
#pragma warning(disable: 4005) 

#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <psapi.h>



#pragma warning(pop)
#include <vector>
#include <string>
#include <algorithm>
#include <array>
#include <cmath>
#include <thread>
#include <sstream>
#include <iomanip>
#include <locale>
#include <codecvt>
#include <unordered_set>
#include <map>
#include <set>
#include <mutex>
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "psapi.lib")
#ifdef _WIN64
typedef IMAGE_NT_HEADERS64 IMAGE_NT_HEADERS_ARCH;
#else
typedef IMAGE_NT_HEADERS32 IMAGE_NT_HEADERS_ARCH;
#endif
#ifndef THREAD_QUERY_LIMITED_INFORMATION
#define THREAD_QUERY_LIMITED_INFORMATION 0x0800
#endif
#ifndef ThreadQuerySetWin32StartAddress
#define ThreadQuerySetWin32StartAddress ((THREADINFOCLASS)3)
#endif

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif
#ifndef STATUS_UNSUCCESSFUL
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)
#endif
#ifndef STATUS_ACCESS_DENIED
#define STATUS_ACCESS_DENIED ((NTSTATUS)0xC0000022L)
#endif

typedef enum _MEMORY_INFO_CLASS {
    MemoryBasicInformationEx = 0,
    MemoryWorkingSetInformationEx = 1,
    MemoryMappedFilenameInformationEx = 2,
    MemoryRegionInformationEx = 3,
    MemoryWorkingSetExInformationEx = 4
} MEMORY_INFO_CLASS;
typedef NTSTATUS(NTAPI* PFN_NtQueryInformationThread)(
    HANDLE ThreadHandle,
    THREADINFOCLASS ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength,
    PULONG ReturnLength
    );
typedef NTSTATUS(NTAPI* PFN_NtQueryVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    MEMORY_INFO_CLASS MemoryInformationClass,
    PVOID MemoryInformation,
    SIZE_T MemoryInformationLength,
    PSIZE_T ReturnLength
    );
typedef NTSTATUS(NTAPI* PFN_NtTerminateProcess)(
    HANDLE ProcessHandle,
    NTSTATUS ExitStatus
    );
typedef NTSTATUS(NTAPI* PFN_NtQueryInformationProcess)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
    );
struct FoundPE {
    uintptr_t base;
    size_t sizeOfImage;
    bool is_dll;
    bool has_exports;
    bool has_imports;
    bool has_tls;
    double section_entropy;
    bool valid_sections;
    bool vad_anomaly;
    bool rpm_section_error;
    bool no_header_high_entropy;
    bool mismatched_base_no_reloc;
    bool fragmented_hint;
    bool suspicious_imports;
};
struct FoundCodeCave {
    uintptr_t module_base = 0;
    std::string module_name;
    std::string section_name;
    uintptr_t cave_start = 0;
    size_t cave_size = 0;
    double entropy = 0.0;
};
struct SuspiciousThread {
    DWORD threadId;
    uintptr_t startAddress;
    bool suspicious;
};
struct RegionEntropy {
    uintptr_t base;
    size_t size;
    double prevEntropy;
    double currEntropy;
    bool entropyChange;
};
static std::string WStringToUtf8(const std::wstring& w) {
    if (w.empty()) return std::string();
    int size = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), static_cast<int>(w.length()), nullptr, 0, nullptr, nullptr);
    if (size == 0) {
        std::string s;
        s.reserve(w.size());
        for (wchar_t c : w) s.push_back(static_cast<char>(c & 0xFF));
        return s;
    }
    std::string result(size, 0);
    int converted = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), static_cast<int>(w.length()), &result[0], size, nullptr, nullptr);
    if (converted == 0) {
        std::string s;
        s.reserve(w.size());
        for (wchar_t c : w) s.push_back(static_cast<char>(c & 0xFF));
        return s;
    }
    return result;
}
static std::wstring CanonicalPath(const std::wstring& path) {
    wchar_t full[MAX_PATH] = { 0 };
    if (GetFullPathNameW(path.c_str(), MAX_PATH, full, nullptr) == 0) return path;
    wchar_t longPath[MAX_PATH] = { 0 };
    if (GetLongPathNameW(full, longPath, MAX_PATH) == 0) return full;
    return longPath;
}
static bool IsCaseInsensitiveEqual(const std::string& a, const std::string& b) {
    if (a.length() != b.length()) return false;
    return std::equal(a.begin(), a.end(), b.begin(),
        [](char c1, char c2) { return std::tolower(c1) == std::tolower(c2); });
}
double compute_entropy(const std::vector<BYTE>& data) {
    if (data.empty()) return 0.0;
    std::array<int, 256> freq = {};
    for (BYTE b : data) {
        ++freq[b];
    }
    double entropy = 0.0;
    size_t total = data.size();
    for (int f : freq) {
        if (f > 0) {
            double p = static_cast<double>(f) / total;
            entropy -= p * std::log2(p);
        }
    }
    return entropy;
}
bool is_executable_protection(DWORD prot) {
    return (prot & PAGE_EXECUTE) ||
        (prot & PAGE_EXECUTE_READ) ||
        (prot & PAGE_EXECUTE_READWRITE) ||
        (prot & PAGE_EXECUTE_WRITECOPY);
}
bool is_stack_or_heap(uintptr_t addr, bool& isStack, bool& isHeap) {
    isStack = (addr < 0x00010000) || (addr > 0x7FFE0000 && addr < 0x7FFF0000);
    isHeap = (addr > 0x10000000 && addr < 0x7FFE0000);
    return isStack || isHeap;
}
std::vector<FoundPE> scan_process_memory_for_pe(
    DWORD pid,
    HANDLE hProcess,
    PFN_NtQueryVirtualMemory NtQVM,
    std::map<uintptr_t, RegionEntropy>& entropyTracker,
    double& fragmentedSuspicious
) {
    std::vector<FoundPE> found;
    found.reserve(64);  
    MEMORY_BASIC_INFORMATION mbi = {};
    uintptr_t addr = 0;
    const size_t max_read = 16384;
    const size_t sample_size = 4096;
    const double code_entropy_threshold = 5.0;
    const double low_entropy_threshold = 2.0;
    const double entropy_change_threshold = 3.0;
    int small_exec_count = 0;
    while (VirtualQueryEx(hProcess, reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (mbi.State == MEM_COMMIT) {
            bool exec = is_executable_protection(mbi.Protect);
            bool writable = (mbi.Protect & PAGE_READWRITE) || (mbi.Protect & PAGE_EXECUTE_READWRITE);
            bool rwx_remnant = (mbi.Protect == PAGE_EXECUTE_READWRITE || mbi.Protect == PAGE_EXECUTE_WRITECOPY) && (mbi.Type == MEM_PRIVATE);
            bool prot_anomaly = (mbi.Protect & PAGE_GUARD) || ((mbi.Protect & PAGE_NOACCESS) && (mbi.Type == MEM_PRIVATE) && exec);
            bool read_only = (mbi.Protect == PAGE_READONLY);
            bool stack_heap = false;
            bool isStack, isHeap;
            if (is_stack_or_heap(addr, isStack, isHeap)) stack_heap = true;
            if ((exec || writable || rwx_remnant || prot_anomaly || read_only) &&
                (mbi.Type == MEM_PRIVATE || mbi.Type == MEM_IMAGE)) {
                bool vad_suspicious = false;
                if (NtQVM) {
                    MEMORY_BASIC_INFORMATION vad_info = {};
                    SIZE_T ret_len = 0;
                    NTSTATUS vad_status = NtQVM(
                        hProcess,
                        reinterpret_cast<PVOID>(addr),
                        MemoryRegionInformationEx,
                        &vad_info,
                        sizeof(vad_info),
                        &ret_len
                    );
                    if (vad_status == 0 && vad_info.AllocationBase == 0 && mbi.Type == MEM_PRIVATE) {
                        vad_suspicious = true;
                    }
                }
                if (mbi.RegionSize < sample_size) {
                    addr += mbi.RegionSize;
                    continue;
                }
                size_t read_size = (std::min)(static_cast<size_t>(mbi.RegionSize), max_read);
                std::vector<BYTE> buf(read_size);
                SIZE_T read = 0;
                if (addr == 0 || !ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(addr), buf.data(), read_size, &read)) {
                    addr += mbi.RegionSize;
                    continue;
                }
                if (read < sizeof(IMAGE_DOS_HEADER)) {
                    if (exec) {
                        double ent = compute_entropy(buf);
                        if (ent > code_entropy_threshold) {
                            FoundPE f = {};
                            f.base = addr;
                            f.sizeOfImage = mbi.RegionSize;
                            f.no_header_high_entropy = true;
                            f.vad_anomaly = vad_suspicious || prot_anomaly || stack_heap;
                            found.push_back(f);
                        }
                    }
                    addr += mbi.RegionSize;
                    continue;
                }
                IMAGE_DOS_HEADER* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(buf.data());
                bool hasPE = (dos->e_magic == IMAGE_DOS_SIGNATURE);
                LONG ntOffset = hasPE ? dos->e_lfanew : 0;
                if (hasPE && (ntOffset < 0 || static_cast<size_t>(ntOffset) > read - sizeof(IMAGE_NT_HEADERS_ARCH))) {
                    addr += mbi.RegionSize;
                    continue;
                }
                IMAGE_NT_HEADERS_ARCH* nt = hasPE ? reinterpret_cast<IMAGE_NT_HEADERS_ARCH*>(buf.data() + ntOffset) : nullptr;
                bool validNT = hasPE && (nt->Signature == IMAGE_NT_SIGNATURE);
                if (validNT) {
                    FoundPE f = {};
                    f.base = addr;
                    f.sizeOfImage = nt->OptionalHeader.SizeOfImage;
                    f.is_dll = (nt->FileHeader.Characteristics & IMAGE_FILE_DLL) != 0;
                    f.has_exports = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size > 0;
                    f.has_imports = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size > 0;
                    f.has_tls = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size > 0;
                    f.section_entropy = 0.0;
                    f.valid_sections = true;
                    f.vad_anomaly = vad_suspicious || prot_anomaly || stack_heap;
                    f.rpm_section_error = false;
                    uintptr_t imageBase = nt->OptionalHeader.ImageBase;
                    if (imageBase != addr && nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size == 0) {
                        f.mismatched_base_no_reloc = true;
                    }
                    if (!f.has_imports && exec) {
                        double ent = compute_entropy(buf);
                        if (ent > code_entropy_threshold) {
                            f.suspicious_imports = true;
                        }
                    }
                    if (f.sizeOfImage < 0x10000) {
                        small_exec_count++;
                        f.fragmented_hint = true;
                    }
                    if (nt->FileHeader.NumberOfSections > 0) {
                        IMAGE_SECTION_HEADER* sections = reinterpret_cast<IMAGE_SECTION_HEADER*>(
                            buf.data() + ntOffset + sizeof(IMAGE_NT_HEADERS_ARCH)
                            );
                        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
                            size_t sec_offset = static_cast<size_t>(i) * sizeof(IMAGE_SECTION_HEADER);
                            if (sec_offset >= read - (ntOffset + sizeof(IMAGE_NT_HEADERS_ARCH))) {
                                break;
                            }
                            IMAGE_SECTION_HEADER* sec = &sections[i];
                            if (sec->VirtualAddress % nt->OptionalHeader.SectionAlignment != 0 || sec->Misc.VirtualSize == 0) {
                                f.valid_sections = false;
                                break;
                            }
                            if ((sec->Characteristics & IMAGE_SCN_CNT_CODE) && sec->Misc.VirtualSize > 0) {
                                size_t sec_start = addr + sec->VirtualAddress;
                                size_t sec_size = (std::min)(static_cast<size_t>(sec->Misc.VirtualSize), sample_size);
                                std::vector<BYTE> sec_data(sec_size);
                                SIZE_T sec_read = 0;
                                if (ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(sec_start), sec_data.data(), sec_data.size(), &sec_read)) {
                                    sec_data.resize(sec_read);
                                    f.section_entropy = compute_entropy(sec_data);
                                }
                                else {
                                    f.rpm_section_error = true;
                                }
                            }
                        }
                    }
                    found.push_back(f);
                }
                else if (exec && (rwx_remnant || prot_anomaly || vad_suspicious || stack_heap)) {
                    FoundPE f = {};
                    f.base = addr;
                    f.sizeOfImage = static_cast<size_t>(mbi.RegionSize);
                    double ent = compute_entropy(buf);
                    f.section_entropy = ent;
                    f.valid_sections = false;
                    f.vad_anomaly = vad_suspicious || prot_anomaly || stack_heap;
                    f.rpm_section_error = false;
                    f.is_dll = false;
                    f.has_exports = false;
                    f.has_imports = false;
                    f.has_tls = false;
                    auto it = entropyTracker.find(addr);
                    if (it != entropyTracker.end()) {
                        RegionEntropy& re = it->second;
                        re.currEntropy = ent;
                        if (std::abs(re.currEntropy - re.prevEntropy) > entropy_change_threshold &&
                            re.prevEntropy < low_entropy_threshold && re.currEntropy > code_entropy_threshold) {
                            re.entropyChange = true;
                            f.vad_anomaly = true;
                        }
                        re.prevEntropy = re.currEntropy;
                    }
                    else {
                        RegionEntropy re;
                        re.base = addr;
                        re.size = mbi.RegionSize;
                        re.prevEntropy = ent;
                        re.currEntropy = ent;
                        re.entropyChange = false;
                        entropyTracker[addr] = re;
                    }
                    if (mbi.RegionSize < 0x10000) small_exec_count++;
                    f.no_header_high_entropy = (ent > code_entropy_threshold);
                    if (mbi.RegionSize > 0x5000 && exec) {
                        f.no_header_high_entropy = true;
                    }
                    found.push_back(f);
                }
            }
        }
        addr += mbi.RegionSize;
        if (addr == 0) break;
    }
    fragmentedSuspicious = (small_exec_count > 5);
    return found;
}
std::vector<FoundCodeCave> scan_for_code_caves(
    HANDLE hProcess
) {
    std::vector<FoundCodeCave> found;
    const double entropy_threshold = 4.0;
    MEMORY_BASIC_INFORMATION mbi;
    uintptr_t addr = 0;
    while (VirtualQueryEx(hProcess, reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (mbi.State == MEM_COMMIT && is_executable_protection(mbi.Protect)) {
            size_t read_size = (std::min)(static_cast<size_t>(mbi.RegionSize), static_cast<size_t>(4096));
            std::vector<BYTE> buf(read_size);
            SIZE_T read_bytes = 0;
            if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(addr), buf.data(), read_size, &read_bytes)) {
                addr += mbi.RegionSize;
                continue;
            }
            if (read_bytes < sizeof(IMAGE_DOS_HEADER)) {
                addr += mbi.RegionSize;
                continue;
            }
            IMAGE_DOS_HEADER* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(buf.data());
            if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
                addr += mbi.RegionSize;
                continue;
            }
            IMAGE_NT_HEADERS_ARCH nt;
            LONG ntOffset = dos->e_lfanew;
            if (addr == 0 || ntOffset < 0 || !ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(addr + ntOffset), &nt, sizeof(nt), &read_bytes) || read_bytes != sizeof(nt)) {
                addr += mbi.RegionSize;
                continue;
            }
            if (nt.Signature != IMAGE_NT_SIGNATURE) {
                addr += mbi.RegionSize;
                continue;
            }
            uintptr_t section_start = addr + dos->e_lfanew + sizeof(IMAGE_NT_HEADERS_ARCH);
            for (WORD i = 0; i < nt.FileHeader.NumberOfSections; ++i) {
                IMAGE_SECTION_HEADER sec;
                if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(section_start + i * sizeof(IMAGE_SECTION_HEADER)), &sec, sizeof(sec), &read_bytes) || read_bytes != sizeof(sec)) {
                    break;
                }
                if (sec.Misc.VirtualSize > sec.SizeOfRawData && sec.SizeOfRawData > 0) {
                    size_t padding_size = sec.Misc.VirtualSize - sec.SizeOfRawData;
                    uintptr_t padding_addr = addr + sec.VirtualAddress + sec.SizeOfRawData;
                    std::vector<BYTE> padding(padding_size);
                    if (padding_addr != 0 && ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(padding_addr), padding.data(), padding_size, &read_bytes) && read_bytes == padding_size) {
                        bool all_zero = true;
                        for (BYTE b : padding) {
                            if (b != 0) {
                                all_zero = false;
                                break;
                            }
                        }
                        if (!all_zero) {
                            double ent = compute_entropy(padding);
                            if (ent > entropy_threshold) {
                                FoundCodeCave cc;
                                cc.module_base = addr;
                                cc.module_name = "unknown";
                                cc.section_name = std::string(reinterpret_cast<char*>(sec.Name), strnlen(reinterpret_cast<char*>(sec.Name), 8));
                                cc.cave_start = padding_addr;
                                cc.cave_size = padding_size;
                                cc.entropy = ent;
                                found.push_back(cc);
                            }
                        }
                    }
                }
            }
        }
        addr += mbi.RegionSize;
        if (addr == 0) break;
    }
    return found;
}
std::vector<SuspiciousThread> scan_threads_for_hijacking(HANDLE hProc, PFN_NtQueryInformationThread NtQIT) {
    std::vector<SuspiciousThread> suspiciousThreads;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, GetCurrentProcessId());
    if (snap == INVALID_HANDLE_VALUE) return suspiciousThreads;
    THREADENTRY32 te;
    te.dwSize = sizeof(te);
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == GetCurrentProcessId()) {
                HANDLE hThread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, te.th32ThreadID);
                if (hThread) {
                    ULONG retLen = 0;
                    PVOID startAddr = nullptr;
                    if (NtQIT) {
                        NTSTATUS st = NtQIT(hThread, ThreadQuerySetWin32StartAddress, &startAddr, sizeof(PVOID), &retLen);
                        if (st == 0 && startAddr) {
                            uintptr_t addr = reinterpret_cast<uintptr_t>(startAddr);
                            SuspiciousThread sthr;
                            sthr.threadId = te.th32ThreadID;
                            sthr.startAddress = addr;
                            sthr.suspicious = true;
                            suspiciousThreads.push_back(sthr);
                        }
                    }
                    CloseHandle(hThread);
                }
            }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    return suspiciousThreads;
}

static std::wstring ToLowerW(const std::wstring& str) {
    std::wstring result = str;
    std::transform(result.begin(), result.end(), result.begin(), ::towlower);
    return result;
}

static std::unordered_set<std::wstring> g_allowed_dlls;
static std::mutex g_allowed_dlls_mutex;
static bool g_whitelist_initialized = false;

static std::wstring g_exe_directory;
static bool g_exe_directory_initialized = false;

static void InitializeExeDirectory() {
    if (g_exe_directory_initialized) return;
    wchar_t path[MAX_PATH] = { 0 };
    if (GetModuleFileNameW(NULL, path, MAX_PATH)) {
        std::wstring full = ToLowerW(path);
        size_t lastSlash = full.find_last_of(L"\\/");
        if (lastSlash != std::wstring::npos) {
            g_exe_directory = full.substr(0, lastSlash + 1); 
        } else {
            g_exe_directory = L"";
        }
    }
    g_exe_directory_initialized = true;
}

static void InitializeWhitelist() {
    std::lock_guard<std::mutex> lock(g_allowed_dlls_mutex);
    if (g_whitelist_initialized) return;
    
    HMODULE hMods[1024];
    DWORD cbNeeded;
    if (EnumProcessModules(GetCurrentProcess(), hMods, sizeof(hMods), &cbNeeded)) {
        for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            wchar_t szModName[MAX_PATH] = {0};
            if (GetModuleFileNameW(hMods[i], szModName, MAX_PATH)) {
                std::wstring modPath = ToLowerW(szModName);
                size_t lastSlash = modPath.find_last_of(L"\\/");
                std::wstring filename = (lastSlash != std::wstring::npos) ? 
                    modPath.substr(lastSlash + 1) : modPath;
                g_allowed_dlls.insert(filename);
            }
        }
    }
    g_whitelist_initialized = true;
}

static bool IsAllowedDLL(const std::wstring& dllPath) {
    if (!g_whitelist_initialized) {
        InitializeWhitelist();
    }
    
    std::wstring lowerPath = ToLowerW(dllPath);
    size_t lastSlash = lowerPath.find_last_of(L"\\/");
    std::wstring filename = (lastSlash != std::wstring::npos) ? 
        lowerPath.substr(lastSlash + 1) : lowerPath;
    
    std::lock_guard<std::mutex> lock(g_allowed_dlls_mutex);
    return g_allowed_dlls.find(filename) != g_allowed_dlls.end();
}

static PVOID GetLoadLibraryAddress() {
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (!hKernel32) return nullptr;
    FARPROC pLoadLibraryA = GetProcAddress(hKernel32, "LoadLibraryA");
    FARPROC pLoadLibraryW = GetProcAddress(hKernel32, "LoadLibraryW");
    return (pLoadLibraryA) ? (PVOID)pLoadLibraryA : (PVOID)pLoadLibraryW;
}

typedef HANDLE(WINAPI* PFN_CreateRemoteThread)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
static PFN_CreateRemoteThread g_pfnCreateRemoteThread = nullptr;

static HANDLE WINAPI Hooked_CreateRemoteThread(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, 
    LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId) {
    DWORD currentPid = GetCurrentProcessId();
    HANDLE hCurrentProcess = GetCurrentProcess();
    bool isTargetingUs = false;
    
    if (hProcess && hProcess != INVALID_HANDLE_VALUE) {
        DWORD targetPid = 0;
        bool isValidHandle = true;
        try {
            targetPid = GetProcessId(hProcess);
        } catch (...) {
            isValidHandle = false;
        }
        
        if (!isValidHandle || targetPid == 0) {
            return (g_pfnCreateRemoteThread) ? g_pfnCreateRemoteThread(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId) : nullptr;
        }
        
        isTargetingUs = (targetPid == currentPid && targetPid != 0);
    }
    
    if (lpStartAddress) {
        PVOID loadLibAddr = GetLoadLibraryAddress();
        if (loadLibAddr && lpStartAddress == (LPTHREAD_START_ROUTINE)loadLibAddr) {
            TerminateProcess(GetCurrentProcess(), 0xDEADBEEF);
            ExitProcess(0xDEADBEEF);
            return nullptr;
        }
        
        MEMORY_BASIC_INFORMATION mbi = {};
        if (VirtualQuery(lpStartAddress, &mbi, sizeof(mbi)) == sizeof(mbi)) {
            if (mbi.Type == MEM_PRIVATE && is_executable_protection(mbi.Protect)) {
                HMODULE hMod = nullptr;
                if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCWSTR)lpStartAddress, &hMod)) {
                    TerminateProcess(GetCurrentProcess(), 0xDEADBEEF);
                    ExitProcess(0xDEADBEEF);
                    return nullptr;
                }
            }
            if (mbi.Type == MEM_PRIVATE && is_executable_protection(mbi.Protect) && mbi.RegionSize > 0x1000) {
                std::vector<BYTE> sample(0x1000);
                SIZE_T bytesRead = 0;
                if (ReadProcessMemory(GetCurrentProcess(), lpStartAddress, sample.data(), 0x1000, &bytesRead) && bytesRead > 0) {
                    sample.resize(bytesRead);
                    double entropy = compute_entropy(sample);
                    if (entropy > 6.5) {
                        TerminateProcess(GetCurrentProcess(), 0xDEADBEEF);
                        ExitProcess(0xDEADBEEF);
                        return nullptr;
                    }
                }
            }
        }
    }
    
    if (isTargetingUs && hProcess != hCurrentProcess) {
        TerminateProcess(GetCurrentProcess(), 0xDEADBEEF);
        ExitProcess(0xDEADBEEF);
        return nullptr;
    }
    
    return (g_pfnCreateRemoteThread) ? g_pfnCreateRemoteThread(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId) : nullptr;
}

typedef NTSTATUS(NTAPI* PFN_NtCreateThreadEx)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID, ULONG, ULONG_PTR, SIZE_T, SIZE_T, PVOID);
static PFN_NtCreateThreadEx g_pfnNtCreateThreadEx = nullptr;

static NTSTATUS NTAPI Hooked_NtCreateThreadEx(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument, ULONG CreateFlags, ULONG_PTR ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize, PVOID AttributeList) {
    DWORD currentPid = GetCurrentProcessId();
    HANDLE hCurrentProcess = GetCurrentProcess();
    bool isTargetingUs = false;
    
    if (ProcessHandle && ProcessHandle != INVALID_HANDLE_VALUE) {
        DWORD targetPid = 0;
        bool isValidHandle = true;
        try {
            targetPid = GetProcessId(ProcessHandle);
        } catch (...) {
            isValidHandle = false;
        }
        
        if (!isValidHandle || targetPid == 0) {
            return (g_pfnNtCreateThreadEx) ? g_pfnNtCreateThreadEx(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine, Argument, CreateFlags, ZeroBits, StackSize, MaximumStackSize, AttributeList) : STATUS_UNSUCCESSFUL;
        }
        
        isTargetingUs = (targetPid == currentPid && targetPid != 0);
    }
    
    if (StartRoutine) {
        PVOID loadLibAddr = GetLoadLibraryAddress();
        if (loadLibAddr && StartRoutine == loadLibAddr) {
            TerminateProcess(GetCurrentProcess(), 0xDEADBEEF);
            ExitProcess(0xDEADBEEF);
            return STATUS_ACCESS_DENIED;
        }
        
        MEMORY_BASIC_INFORMATION mbi = {};
        if (VirtualQuery(StartRoutine, &mbi, sizeof(mbi)) == sizeof(mbi)) {
            if (mbi.Type == MEM_PRIVATE && is_executable_protection(mbi.Protect)) {
                HMODULE hMod = nullptr;
                if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCWSTR)StartRoutine, &hMod)) {
                    TerminateProcess(GetCurrentProcess(), 0xDEADBEEF);
                    ExitProcess(0xDEADBEEF);
                    return STATUS_ACCESS_DENIED;
                }
            }
            if (mbi.Type == MEM_PRIVATE && is_executable_protection(mbi.Protect) && mbi.RegionSize > 0x1000) {
                std::vector<BYTE> sample(0x1000);
                SIZE_T bytesRead = 0;
                if (ReadProcessMemory(GetCurrentProcess(), StartRoutine, sample.data(), 0x1000, &bytesRead) && bytesRead > 0) {
                    sample.resize(bytesRead);
                    double entropy = compute_entropy(sample);
                    if (entropy > 6.5) {
                        TerminateProcess(GetCurrentProcess(), 0xDEADBEEF);
                        ExitProcess(0xDEADBEEF);
                        return STATUS_ACCESS_DENIED;
                    }
                }
            }
        }
    }
    
    if (isTargetingUs && ProcessHandle != hCurrentProcess) {
        TerminateProcess(GetCurrentProcess(), 0xDEADBEEF);
        ExitProcess(0xDEADBEEF);
        return STATUS_ACCESS_DENIED;
    }
    
    return (g_pfnNtCreateThreadEx) ? g_pfnNtCreateThreadEx(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine, Argument, CreateFlags, ZeroBits, StackSize, MaximumStackSize, AttributeList) : STATUS_UNSUCCESSFUL;
}


typedef HHOOK(WINAPI* PFN_SetWindowsHookExW)(int, HOOKPROC, HINSTANCE, DWORD);
static PFN_SetWindowsHookExW g_pfnSetWindowsHookExW = nullptr;

static HHOOK WINAPI Hooked_SetWindowsHookExW(int idHook, HOOKPROC lpfn, HINSTANCE hMod, DWORD dwThreadId) {
    if (hMod) {
        wchar_t szModName[MAX_PATH] = {0};
        if (GetModuleFileNameW(hMod, szModName, MAX_PATH)) {
            std::wstring modPath = ToLowerW(szModName);
            bool isSystemDll = (modPath.find(L"c:\\windows\\system32\\") == 0 ||
                               modPath.find(L"c:\\windows\\syswow64\\") == 0 ||
                               modPath.find(L"c:\\windows\\winsxs\\") == 0);
            
            if (!isSystemDll && !IsAllowedDLL(modPath)) {
                TerminateProcess(GetCurrentProcess(), 0xDEADBEEF);
                ExitProcess(0xDEADBEEF);
                return nullptr;
            }
        }
    }
    
    return (g_pfnSetWindowsHookExW) ? g_pfnSetWindowsHookExW(idHook, lpfn, hMod, dwThreadId) : nullptr;
}

static std::set<HMODULE> g_known_modules;
static std::mutex g_modules_mutex;
static bool g_modules_tracked = false;

static void TrackModuleLoad(HMODULE hModule) {
    if (!hModule) return;
    std::lock_guard<std::mutex> lock(g_modules_mutex);
    g_known_modules.insert(hModule);
}

static bool IsKnownModule(HMODULE hModule) {
    std::lock_guard<std::mutex> lock(g_modules_mutex);
    return g_known_modules.find(hModule) != g_known_modules.end();
}

typedef NTSTATUS(NTAPI* PFN_LdrLoadDll)(PWCHAR, PULONG, PUNICODE_STRING, PHANDLE);
static PFN_LdrLoadDll g_pfnLdrLoadDll = nullptr;
static PFN_LdrLoadDll g_pfnLdrLoadDllStub = nullptr;

static NTSTATUS NTAPI Hooked_LdrLoadDll(PWCHAR PathToFile, PULONG DllCharacteristics, PUNICODE_STRING ModuleFileName, PHANDLE ModuleHandle) {
    std::wstring dllPath;
    
    if (ModuleFileName && ModuleFileName->Buffer) {
        dllPath = ToLowerW(ModuleFileName->Buffer);
    } else if (PathToFile) {
        dllPath = ToLowerW(PathToFile);
    }
    
    if (!dllPath.empty()) {
        bool isSystemDll = (dllPath.find(L"c:\\windows\\system32\\") == 0 ||
                           dllPath.find(L"c:\\windows\\syswow64\\") == 0 ||
                           dllPath.find(L"c:\\windows\\winsxs\\") == 0);
        
        if (!isSystemDll && !IsAllowedDLL(dllPath)) {
            TerminateProcess(GetCurrentProcess(), 0xDEADBEEF);
            ExitProcess(0xDEADBEEF);
            return STATUS_ACCESS_DENIED;
        }
    }
    
    NTSTATUS status = (g_pfnLdrLoadDll) ? g_pfnLdrLoadDll(PathToFile, DllCharacteristics, ModuleFileName, ModuleHandle) : STATUS_UNSUCCESSFUL;
    
    if (NT_SUCCESS(status) && ModuleHandle && *ModuleHandle) {
        HMODULE loadedModule = (HMODULE)*ModuleHandle;
        TrackModuleLoad(loadedModule);
        std::thread([loadedModule]() {
            for (int i = 0; i < 20; ++i) {
                Sleep(10);
                HMODULE hModCheck = nullptr;
                if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, 
                    reinterpret_cast<LPCWSTR>(loadedModule), &hModCheck) || !hModCheck) {
                    HMODULE hModsCheck[1024];
                    DWORD cbNeededCheck = 0;
                    bool foundInEnum = false;
                    if (EnumProcessModules(GetCurrentProcess(), hModsCheck, sizeof(hModsCheck), &cbNeededCheck)) {
                        for (unsigned int j = 0; j < (cbNeededCheck / sizeof(HMODULE)); j++) {
                            if (hModsCheck[j] == loadedModule) {
                                foundInEnum = true;
                                break;
                            }
                        }
                    }
                    if (!foundInEnum) {
                        TerminateProcess(GetCurrentProcess(), 0xDEADBEEF);
                        ExitProcess(0xDEADBEEF);
                        return;
                    }
                }
            }
        }).detach();
    }
    
    return status;
}

typedef FARPROC(WINAPI* PFN_GetProcAddress)(HMODULE, LPCSTR);
static PFN_GetProcAddress g_pfnGetProcAddress = nullptr;

static FARPROC WINAPI Hooked_GetProcAddress(HMODULE hModule, LPCSTR lpProcName) {
    return (g_pfnGetProcAddress) ? g_pfnGetProcAddress(hModule, lpProcName) : nullptr;
}

typedef HMODULE(WINAPI* PFN_LoadLibraryA)(LPCSTR);
typedef HMODULE(WINAPI* PFN_LoadLibraryW)(LPCWSTR);
typedef HMODULE(WINAPI* PFN_LoadLibraryExA)(LPCSTR, HANDLE, DWORD);
typedef HMODULE(WINAPI* PFN_LoadLibraryExW)(LPCWSTR, HANDLE, DWORD);
static PFN_LoadLibraryA g_pfnLoadLibraryA = nullptr;
static PFN_LoadLibraryW g_pfnLoadLibraryW = nullptr;
static PFN_LoadLibraryExA g_pfnLoadLibraryExA = nullptr;
static PFN_LoadLibraryExW g_pfnLoadLibraryExW = nullptr;

static HMODULE WINAPI Hooked_LoadLibraryA(LPCSTR lpLibFileName) {
    if (lpLibFileName) {
        int len = MultiByteToWideChar(CP_ACP, 0, lpLibFileName, -1, nullptr, 0);
        if (len > 0) {
            std::vector<wchar_t> wstr(len);
            MultiByteToWideChar(CP_ACP, 0, lpLibFileName, -1, wstr.data(), len);
            std::wstring dllPath = ToLowerW(wstr.data());
            
            bool isSystemDll = (dllPath.find(L"c:\\windows\\system32\\") == 0 ||
                               dllPath.find(L"c:\\windows\\syswow64\\") == 0 ||
                               dllPath.find(L"c:\\windows\\winsxs\\") == 0);
            
            if (!isSystemDll && !IsAllowedDLL(dllPath)) {
                TerminateProcess(GetCurrentProcess(), 0xDEADBEEF);
                ExitProcess(0xDEADBEEF);
                return nullptr;
            }
        }
    }
    
    HMODULE result = (g_pfnLoadLibraryA) ? g_pfnLoadLibraryA(lpLibFileName) : nullptr;
    if (result) {
        TrackModuleLoad(result);
        std::thread([result]() {
            for (int i = 0; i < 20; ++i) {
                Sleep(10);
                HMODULE hModCheck = nullptr;
                if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, 
                    reinterpret_cast<LPCWSTR>(result), &hModCheck) || !hModCheck) {
                    HMODULE hModsCheck[1024];
                    DWORD cbNeededCheck = 0;
                    bool foundInEnum = false;
                    if (EnumProcessModules(GetCurrentProcess(), hModsCheck, sizeof(hModsCheck), &cbNeededCheck)) {
                        for (unsigned int j = 0; j < (cbNeededCheck / sizeof(HMODULE)); j++) {
                            if (hModsCheck[j] == result) {
                                foundInEnum = true;
                                break;
                            }
                        }
                    }
                    if (!foundInEnum) {
                        TerminateProcess(GetCurrentProcess(), 0xDEADBEEF);
                        ExitProcess(0xDEADBEEF);
                        return;
                    }
                }
            }
        }).detach();
    }
    return result;
}

static HMODULE WINAPI Hooked_LoadLibraryW(LPCWSTR lpLibFileName) {
    if (lpLibFileName) {
        std::wstring dllPath = ToLowerW(lpLibFileName);
        
        bool isSystemDll = (dllPath.find(L"c:\\windows\\system32\\") == 0 ||
                           dllPath.find(L"c:\\windows\\syswow64\\") == 0 ||
                           dllPath.find(L"c:\\windows\\winsxs\\") == 0);
        
        if (!isSystemDll && !IsAllowedDLL(dllPath)) {
            TerminateProcess(GetCurrentProcess(), 0xDEADBEEF);
            ExitProcess(0xDEADBEEF);
            return nullptr;
        }
    }
    
    HMODULE result = (g_pfnLoadLibraryW) ? g_pfnLoadLibraryW(lpLibFileName) : nullptr;
    if (result) {
        TrackModuleLoad(result);
        std::thread([result]() {
            for (int i = 0; i < 20; ++i) {
                Sleep(10);
                HMODULE hModCheck = nullptr;
                if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, 
                    reinterpret_cast<LPCWSTR>(result), &hModCheck) || !hModCheck) {
                    HMODULE hModsCheck[1024];
                    DWORD cbNeededCheck = 0;
                    bool foundInEnum = false;
                    if (EnumProcessModules(GetCurrentProcess(), hModsCheck, sizeof(hModsCheck), &cbNeededCheck)) {
                        for (unsigned int j = 0; j < (cbNeededCheck / sizeof(HMODULE)); j++) {
                            if (hModsCheck[j] == result) {
                                foundInEnum = true;
                                break;
                            }
                        }
                    }
                    if (!foundInEnum) {
                        TerminateProcess(GetCurrentProcess(), 0xDEADBEEF);
                        ExitProcess(0xDEADBEEF);
                        return;
                    }
                }
            }
        }).detach();
    }
    return result;
}

static HMODULE WINAPI Hooked_LoadLibraryExA(LPCSTR lpLibFileName, HANDLE hFile, DWORD dwFlags) {
    if (lpLibFileName) {
        int len = MultiByteToWideChar(CP_ACP, 0, lpLibFileName, -1, nullptr, 0);
        if (len > 0) {
            std::vector<wchar_t> wstr(len);
            MultiByteToWideChar(CP_ACP, 0, lpLibFileName, -1, wstr.data(), len);
            std::wstring dllPath = ToLowerW(wstr.data());
            
            bool isSystemDll = (dllPath.find(L"c:\\windows\\system32\\") == 0 ||
                               dllPath.find(L"c:\\windows\\syswow64\\") == 0 ||
                               dllPath.find(L"c:\\windows\\winsxs\\") == 0);
            
            if (!isSystemDll && !IsAllowedDLL(dllPath)) {
                TerminateProcess(GetCurrentProcess(), 0xDEADBEEF);
                ExitProcess(0xDEADBEEF);
                return nullptr;
            }
        }
    }
    
    HMODULE result = (g_pfnLoadLibraryExA) ? g_pfnLoadLibraryExA(lpLibFileName, hFile, dwFlags) : nullptr;
    if (result) {
        TrackModuleLoad(result);
        std::thread([result]() {
            for (int i = 0; i < 20; ++i) {
                Sleep(10);
                HMODULE hModCheck = nullptr;
                if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, 
                    reinterpret_cast<LPCWSTR>(result), &hModCheck) || !hModCheck) {
                    HMODULE hModsCheck[1024];
                    DWORD cbNeededCheck = 0;
                    bool foundInEnum = false;
                    if (EnumProcessModules(GetCurrentProcess(), hModsCheck, sizeof(hModsCheck), &cbNeededCheck)) {
                        for (unsigned int j = 0; j < (cbNeededCheck / sizeof(HMODULE)); j++) {
                            if (hModsCheck[j] == result) {
                                foundInEnum = true;
                                break;
                            }
                        }
                    }
                    if (!foundInEnum) {
                        TerminateProcess(GetCurrentProcess(), 0xDEADBEEF);
                        ExitProcess(0xDEADBEEF);
                        return;
                    }
                }
            }
        }).detach();
    }
    return result;
}

static HMODULE WINAPI Hooked_LoadLibraryExW(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags) {
    if (lpLibFileName) {
        std::wstring dllPath = ToLowerW(lpLibFileName);
        
        bool isSystemDll = (dllPath.find(L"c:\\windows\\system32\\") == 0 ||
                           dllPath.find(L"c:\\windows\\syswow64\\") == 0 ||
                           dllPath.find(L"c:\\windows\\winsxs\\") == 0);
        
        if (!isSystemDll && !IsAllowedDLL(dllPath)) {
            TerminateProcess(GetCurrentProcess(), 0xDEADBEEF);
            ExitProcess(0xDEADBEEF);
            return nullptr;
        }
    }
    
    HMODULE result = (g_pfnLoadLibraryExW) ? g_pfnLoadLibraryExW(lpLibFileName, hFile, dwFlags) : nullptr;
    if (result) {
        TrackModuleLoad(result);
        std::thread([result]() {
            for (int i = 0; i < 20; ++i) {
                Sleep(10);
                HMODULE hModCheck = nullptr;
                if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, 
                    reinterpret_cast<LPCWSTR>(result), &hModCheck) || !hModCheck) {
                    HMODULE hModsCheck[1024];
                    DWORD cbNeededCheck = 0;
                    bool foundInEnum = false;
                    if (EnumProcessModules(GetCurrentProcess(), hModsCheck, sizeof(hModsCheck), &cbNeededCheck)) {
                        for (unsigned int j = 0; j < (cbNeededCheck / sizeof(HMODULE)); j++) {
                            if (hModsCheck[j] == result) {
                                foundInEnum = true;
                                break;
                            }
                        }
                    }
                    if (!foundInEnum) {
                        TerminateProcess(GetCurrentProcess(), 0xDEADBEEF);
                        ExitProcess(0xDEADBEEF);
                        return;
                    }
                }
            }
        }).detach();
    }
    return result;
}

typedef LPVOID(WINAPI* PFN_VirtualAllocEx)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
static PFN_VirtualAllocEx g_pfnVirtualAllocEx = nullptr;

static std::set<LPVOID> g_legitimate_allocations;
static std::mutex g_allocations_mutex;

static LPVOID WINAPI Hooked_VirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) {
    DWORD currentPid = GetCurrentProcessId();
    HANDLE hCurrentProcess = GetCurrentProcess();
    bool isTargetingUs = false;
    DWORD targetPid = 0;
    
    if (hProcess && hProcess != INVALID_HANDLE_VALUE) {
        bool isValidHandle = true;
        try {
            targetPid = GetProcessId(hProcess);
        } catch (...) {
            isValidHandle = false;
        }
        
        if (!isValidHandle || targetPid == 0) {
            return (g_pfnVirtualAllocEx) ? g_pfnVirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect) : nullptr;
        }
        
        isTargetingUs = (targetPid == currentPid && targetPid != 0);
    }
    
    if (isTargetingUs) {
        if (flProtect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) {
            if (hProcess != hCurrentProcess) {
                TerminateProcess(GetCurrentProcess(), 0xDEADBEEF);
                ExitProcess(0xDEADBEEF);
                return nullptr;
            }
            if (dwSize > 0x4000) {  
            }
        }
        if (flProtect == PAGE_READWRITE && dwSize > 0x4000 && hProcess != hCurrentProcess) {
            TerminateProcess(GetCurrentProcess(), 0xDEADBEEF);
            ExitProcess(0xDEADBEEF);
            return nullptr;
        }
    }
    
    LPVOID result = (g_pfnVirtualAllocEx) ? g_pfnVirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect) : nullptr;
    
    if (result && hProcess == hCurrentProcess) {
        std::lock_guard<std::mutex> lock(g_allocations_mutex);
        g_legitimate_allocations.insert(result);
    }
    
    return result;
}

typedef BOOL(WINAPI* PFN_WriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
static PFN_WriteProcessMemory g_pfnWriteProcessMemory = nullptr;

typedef BOOL(WINAPI* PFN_VirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
static PFN_VirtualProtect g_pfnVirtualProtect = nullptr;

static BOOL WINAPI Hooked_VirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect) {
    if (is_executable_protection(flNewProtect)) {
        HMODULE hMod = nullptr;
        if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCWSTR)lpAddress, &hMod)) {
            MEMORY_BASIC_INFORMATION mbi = {};
            if (VirtualQuery(lpAddress, &mbi, sizeof(mbi)) == sizeof(mbi)) {
                if (mbi.Type == MEM_PRIVATE) {
                    if (mbi.Protect == PAGE_READWRITE || mbi.Protect == PAGE_READONLY || mbi.Protect == PAGE_NOACCESS) {
                        if (dwSize > 0x1000) {  
                            TerminateProcess(GetCurrentProcess(), 0xDEADBEEF);
                            ExitProcess(0xDEADBEEF);
                            return FALSE;
                        }
                    }
                }
            }
        }
    }
    
    return (g_pfnVirtualProtect) ? g_pfnVirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect) : FALSE;
}

typedef BOOL(WINAPI* PFN_VirtualProtectEx)(HANDLE, LPVOID, SIZE_T, DWORD, PDWORD);
static PFN_VirtualProtectEx g_pfnVirtualProtectEx = nullptr;

static BOOL WINAPI Hooked_VirtualProtectEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect) {
    DWORD currentPid = GetCurrentProcessId();
    HANDLE hCurrentProcess = GetCurrentProcess();
    
    if (hProcess && hProcess != hCurrentProcess && hProcess != INVALID_HANDLE_VALUE) {
        DWORD targetPid = 0;
        bool isValidHandle = true;
        try {
            targetPid = GetProcessId(hProcess);
        } catch (...) {
            isValidHandle = false;
        }
        
        if (!isValidHandle || targetPid == 0) {
            return (g_pfnVirtualProtectEx) ? g_pfnVirtualProtectEx(hProcess, lpAddress, dwSize, flNewProtect, lpflOldProtect) : FALSE;
        }
        
        if (targetPid == currentPid && targetPid != 0) {
            if (is_executable_protection(flNewProtect)) {
                TerminateProcess(GetCurrentProcess(), 0xDEADBEEF);
                ExitProcess(0xDEADBEEF);
                return FALSE;
            }
        }
    }
    
    return (g_pfnVirtualProtectEx) ? g_pfnVirtualProtectEx(hProcess, lpAddress, dwSize, flNewProtect, lpflOldProtect) : FALSE;
}

static BOOL WINAPI Hooked_WriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten) {
    DWORD currentPid = GetCurrentProcessId();
    HANDLE hCurrentProcess = GetCurrentProcess();
    bool isTargetingUs = false;
    DWORD targetPid = 0;
    
    if (hProcess && hProcess != INVALID_HANDLE_VALUE) {
        bool isValidHandle = true;
        try {
            targetPid = GetProcessId(hProcess);
        } catch (...) {
            isValidHandle = false;
        }
        
        if (!isValidHandle || targetPid == 0) {
            return (g_pfnWriteProcessMemory) ? g_pfnWriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten) : FALSE;
        }
        
        isTargetingUs = (targetPid == currentPid && targetPid != 0);
    }
    
    if (isTargetingUs) {
        if (hProcess != hCurrentProcess) {
            if (nSize > 0x100) {  
                TerminateProcess(GetCurrentProcess(), 0xDEADBEEF);
                ExitProcess(0xDEADBEEF);
                return FALSE;
            }
        }
        
        MEMORY_BASIC_INFORMATION mbi = {};
        if (VirtualQueryEx(hProcess, lpBaseAddress, &mbi, sizeof(mbi)) == sizeof(mbi)) {
            if (nSize > 0x1000 && (is_executable_protection(mbi.Protect) || mbi.Protect == PAGE_READWRITE)) {
                bool isLegitimate = false;
                {
                    std::lock_guard<std::mutex> lock(g_allocations_mutex);
                    isLegitimate = (g_legitimate_allocations.find(lpBaseAddress) != g_legitimate_allocations.end());
                }
                
                if (!isLegitimate) {
                    TerminateProcess(GetCurrentProcess(), 0xDEADBEEF);
                    ExitProcess(0xDEADBEEF);
                    return FALSE;
                }
            }
        }
    }
    
    return (g_pfnWriteProcessMemory) ? g_pfnWriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten) : FALSE;
}

static void MonitorLoadedModules() {
    std::thread([]() {
        Sleep(1000);
        
        std::set<std::wstring> initialModules;
        HMODULE hMods[1024];
        DWORD cbNeeded;
        
        if (EnumProcessModules(GetCurrentProcess(), hMods, sizeof(hMods), &cbNeeded)) {
            for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
                wchar_t szModName[MAX_PATH] = {0};
                if (GetModuleFileNameW(hMods[i], szModName, MAX_PATH)) {
                    std::wstring modPath = ToLowerW(szModName);
                    initialModules.insert(modPath);
                    std::lock_guard<std::mutex> lock(g_allowed_dlls_mutex);
                    size_t lastSlash = modPath.find_last_of(L"\\/");
                    std::wstring filename = (lastSlash != std::wstring::npos) ? 
                        modPath.substr(lastSlash + 1) : modPath;
                    g_allowed_dlls.insert(filename);
                }
            }
        }
        
        std::set<std::wstring> systemPaths = {
            L"c:\\windows\\system32\\",
            L"c:\\windows\\syswow64\\",
            L"c:\\windows\\winsxs\\"
        };
        
        while (true) {
            Sleep(50);  
            
            std::set<HMODULE> currentModuleHandles;
            if (EnumProcessModules(GetCurrentProcess(), hMods, sizeof(hMods), &cbNeeded)) {
                for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
                    currentModuleHandles.insert(hMods[i]);
                    wchar_t szModName[MAX_PATH] = {0};
                    if (GetModuleFileNameW(hMods[i], szModName, MAX_PATH)) {
                        std::wstring modPath = ToLowerW(szModName);
                        
                        if (initialModules.find(modPath) == initialModules.end()) {
                            bool isSystemDll = false;
                            for (const auto& sysPath : systemPaths) {
                                if (modPath.find(sysPath) == 0) {
                                    isSystemDll = true;
                                    break;
                                }
                            }
                            
                            if (!isSystemDll && !IsAllowedDLL(modPath)) {
                                Sleep(100);
                                if (!IsAllowedDLL(modPath)) {
                                    TerminateProcess(GetCurrentProcess(), 0xDEADBEEF);
                                    ExitProcess(0xDEADBEEF);
                                    return;
                                }
                            }
                            
                            initialModules.insert(modPath);
                        }
                    }
                }
            }
            
            std::lock_guard<std::mutex> lock(g_modules_mutex);
            for (auto it = g_known_modules.begin(); it != g_known_modules.end();) {
                if (currentModuleHandles.find(*it) == currentModuleHandles.end()) {
                    HMODULE hModCheck = nullptr;
                    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                        reinterpret_cast<LPCWSTR>(*it), &hModCheck) || !hModCheck) {
                        wchar_t szModName[MAX_PATH] = {0};
                        if (GetModuleFileNameW(*it, szModName, MAX_PATH)) {
                            std::wstring modPath = ToLowerW(szModName);
                            bool isSystemDll = false;
                            for (const auto& sysPath : systemPaths) {
                                if (modPath.find(sysPath) == 0) {
                                    isSystemDll = true;
                                    break;
                                }
                            }
                            if (!isSystemDll && !IsAllowedDLL(modPath)) {
                                TerminateProcess(GetCurrentProcess(), 0xDEADBEEF);
                                ExitProcess(0xDEADBEEF);
                                return;
                            }
                        } else {
                            TerminateProcess(GetCurrentProcess(), 0xDEADBEEF);
                            ExitProcess(0xDEADBEEF);
                            return;
                        }
                    }
                }
                ++it;
            }
        }
    }).detach();
}

static void MonitorThreadCreation() {
    std::thread([]() {
        Sleep(1000);
        
        PVOID loadLibAddr = GetLoadLibraryAddress();
        if (!loadLibAddr) return;
        
        std::map<DWORD, PVOID> initialThreads;
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (!hNtdll) {
            if (hSnapshot != INVALID_HANDLE_VALUE) CloseHandle(hSnapshot);
            return;
        }
        
        PFN_NtQueryInformationThread NtQIT =
            reinterpret_cast<PFN_NtQueryInformationThread>(GetProcAddress(hNtdll, "NtQueryInformationThread"));
        if (!NtQIT) {
            if (hSnapshot != INVALID_HANDLE_VALUE) CloseHandle(hSnapshot);
            return;
        }
        
        if (hSnapshot != INVALID_HANDLE_VALUE) {
            THREADENTRY32 te32;
            te32.dwSize = sizeof(THREADENTRY32);
            DWORD currentPid = GetCurrentProcessId();
            
            if (Thread32First(hSnapshot, &te32)) {
                do {
                    if (te32.th32OwnerProcessID == currentPid) {
                        HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te32.th32ThreadID);
                        if (hThread) {
                            PVOID startAddr = nullptr;
                            ULONG retLen = 0;
                            NTSTATUS status = NtQIT(hThread, ThreadQuerySetWin32StartAddress, &startAddr, sizeof(PVOID), &retLen);
                            if (NT_SUCCESS(status) && startAddr) {
                                initialThreads[te32.th32ThreadID] = startAddr;
                            }
                            CloseHandle(hThread);
                        }
                    }
                } while (Thread32Next(hSnapshot, &te32));
            }
            CloseHandle(hSnapshot);
        }
        
        while (true) {
            Sleep(50);  
            
            hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if (hSnapshot == INVALID_HANDLE_VALUE) continue;
            
            THREADENTRY32 te32;
            te32.dwSize = sizeof(THREADENTRY32);
            DWORD currentPid = GetCurrentProcessId();
            
            if (Thread32First(hSnapshot, &te32)) {
                do {
                    if (te32.th32OwnerProcessID == currentPid) {
                        HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te32.th32ThreadID);
                        if (hThread) {
                            PVOID startAddr = nullptr;
                            ULONG retLen = 0;
                            NTSTATUS status = NtQIT(hThread, ThreadQuerySetWin32StartAddress, &startAddr, sizeof(PVOID), &retLen);
                            if (NT_SUCCESS(status) && startAddr) {
                                if (initialThreads.find(te32.th32ThreadID) == initialThreads.end()) {
                                    if (startAddr == loadLibAddr) {
                                        TerminateProcess(GetCurrentProcess(), 0xDEADBEEF);
                                        ExitProcess(0xDEADBEEF);
                                        CloseHandle(hThread);
                                        CloseHandle(hSnapshot);
                                        return;
                                    }
                                    
                                    MEMORY_BASIC_INFORMATION mbi = {};
                                    if (VirtualQuery(startAddr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
                                        if (mbi.Type == MEM_PRIVATE && is_executable_protection(mbi.Protect)) {
                                            HMODULE hMod = nullptr;
                                            if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCWSTR)startAddr, &hMod)) {
                                                TerminateProcess(GetCurrentProcess(), 0xDEADBEEF);
                                                ExitProcess(0xDEADBEEF);
                                                CloseHandle(hThread);
                                                CloseHandle(hSnapshot);
                                                return;
                                            }
                                            if (mbi.RegionSize > 0x1000) {
                                                std::vector<BYTE> sample(0x1000);
                                                SIZE_T bytesRead = 0;
                                                if (ReadProcessMemory(GetCurrentProcess(), startAddr, sample.data(), 0x1000, &bytesRead) && bytesRead > 0) {
                                                    sample.resize(bytesRead);
                                                    double entropy = compute_entropy(sample);
                                                    if (entropy > 6.5) {
                                                        TerminateProcess(GetCurrentProcess(), 0xDEADBEEF);
                                                        ExitProcess(0xDEADBEEF);
                                                        CloseHandle(hThread);
                                                        CloseHandle(hSnapshot);
                                                        return;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    
                                    initialThreads[te32.th32ThreadID] = startAddr;
                                } else {
                                    PVOID originalAddr = initialThreads[te32.th32ThreadID];
                                    if (originalAddr != startAddr) {
                                        TerminateProcess(GetCurrentProcess(), 0xDEADBEEF);
                                        ExitProcess(0xDEADBEEF);
                                        CloseHandle(hThread);
                                        CloseHandle(hSnapshot);
                                        return;
                                    }
                                }
                            }
                            CloseHandle(hThread);
                        }
                    }
                } while (Thread32Next(hSnapshot, &te32));
            }
            CloseHandle(hSnapshot);
        }
    }).detach();
}

static void InstallExportTableHook(HMODULE hModule, const char* funcName, PVOID newFunc) {
    if (!hModule || !funcName || !newFunc) return;
    
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return;
    
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return;
    
    PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hModule + 
        ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    
    if (!ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size) return;
    
    DWORD* nameRVA = (DWORD*)((BYTE*)hModule + exportDir->AddressOfNames);
    WORD* ordinals = (WORD*)((BYTE*)hModule + exportDir->AddressOfNameOrdinals);
    DWORD* functions = (DWORD*)((BYTE*)hModule + exportDir->AddressOfFunctions);
    
    for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
        const char* name = (const char*)((BYTE*)hModule + nameRVA[i]);
        if (strcmp(name, funcName) == 0) {
            DWORD funcRVA = functions[ordinals[i]];
            PVOID funcAddr = (PVOID)((BYTE*)hModule + funcRVA);
            
            DWORD oldProtect;
            if (VirtualProtect(funcAddr, sizeof(PVOID), PAGE_EXECUTE_READWRITE, &oldProtect)) {
                memcpy(funcAddr, &newFunc, sizeof(PVOID));
                VirtualProtect(funcAddr, sizeof(PVOID), oldProtect, &oldProtect);
            }
            break;
        }
    }
}

static void InstallIATHooks() {
    HMODULE hModule = GetModuleHandleW(NULL);
    if (!hModule) return;
    
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return;
    
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return;
    
    PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)hModule + 
        ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    
    if (!ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) return;
    
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    HMODULE hUser32 = GetModuleHandleW(L"user32.dll");
    
    if (hKernel32) {
        g_pfnCreateRemoteThread = (PFN_CreateRemoteThread)GetProcAddress(hKernel32, "CreateRemoteThread");
        g_pfnLoadLibraryA = (PFN_LoadLibraryA)GetProcAddress(hKernel32, "LoadLibraryA");
        g_pfnLoadLibraryW = (PFN_LoadLibraryW)GetProcAddress(hKernel32, "LoadLibraryW");
        g_pfnLoadLibraryExA = (PFN_LoadLibraryExA)GetProcAddress(hKernel32, "LoadLibraryExA");
        g_pfnLoadLibraryExW = (PFN_LoadLibraryExW)GetProcAddress(hKernel32, "LoadLibraryExW");
        g_pfnGetProcAddress = (PFN_GetProcAddress)GetProcAddress(hKernel32, "GetProcAddress");
        g_pfnVirtualAllocEx = (PFN_VirtualAllocEx)GetProcAddress(hKernel32, "VirtualAllocEx");
        g_pfnWriteProcessMemory = (PFN_WriteProcessMemory)GetProcAddress(hKernel32, "WriteProcessMemory");
        g_pfnVirtualProtect = (PFN_VirtualProtect)GetProcAddress(hKernel32, "VirtualProtect");
        g_pfnVirtualProtectEx = (PFN_VirtualProtectEx)GetProcAddress(hKernel32, "VirtualProtectEx");
    }
    if (hNtdll) {
        g_pfnNtCreateThreadEx = (PFN_NtCreateThreadEx)GetProcAddress(hNtdll, "NtCreateThreadEx");
        g_pfnLdrLoadDll = (PFN_LdrLoadDll)GetProcAddress(hNtdll, "LdrLoadDll");
        g_pfnLdrLoadDllStub = (PFN_LdrLoadDll)GetProcAddress(hNtdll, "LdrLoadDllStub");
        
        if (g_pfnLdrLoadDllStub) {
            InstallExportTableHook(hNtdll, "LdrLoadDllStub", Hooked_LdrLoadDll);
        }
    }
    if (hUser32) {
        g_pfnSetWindowsHookExW = (PFN_SetWindowsHookExW)GetProcAddress(hUser32, "SetWindowsHookExW");
    }
    
    DWORD oldProtect;
    
    while (importDesc->Name) {
        char* moduleName = (char*)((BYTE*)hModule + importDesc->Name);
        PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((BYTE*)hModule + importDesc->FirstThunk);
        
        while (thunk->u1.Function) {
            if (IsCaseInsensitiveEqual(moduleName, "kernel32.dll")) {
                if (g_pfnCreateRemoteThread && (void*)thunk->u1.Function == (void*)g_pfnCreateRemoteThread) {
                    VirtualProtect(&thunk->u1.Function, sizeof(void*), PAGE_READWRITE, &oldProtect);
                    thunk->u1.Function = (ULONG_PTR)Hooked_CreateRemoteThread;
                    VirtualProtect(&thunk->u1.Function, sizeof(void*), oldProtect, &oldProtect);
                }
                if (g_pfnLoadLibraryA && (void*)thunk->u1.Function == (void*)g_pfnLoadLibraryA) {
                    VirtualProtect(&thunk->u1.Function, sizeof(void*), PAGE_READWRITE, &oldProtect);
                    thunk->u1.Function = (ULONG_PTR)Hooked_LoadLibraryA;
                    VirtualProtect(&thunk->u1.Function, sizeof(void*), oldProtect, &oldProtect);
                }
                if (g_pfnLoadLibraryW && (void*)thunk->u1.Function == (void*)g_pfnLoadLibraryW) {
                    VirtualProtect(&thunk->u1.Function, sizeof(void*), PAGE_READWRITE, &oldProtect);
                    thunk->u1.Function = (ULONG_PTR)Hooked_LoadLibraryW;
                    VirtualProtect(&thunk->u1.Function, sizeof(void*), oldProtect, &oldProtect);
                }
                if (g_pfnLoadLibraryExA && (void*)thunk->u1.Function == (void*)g_pfnLoadLibraryExA) {
                    VirtualProtect(&thunk->u1.Function, sizeof(void*), PAGE_READWRITE, &oldProtect);
                    thunk->u1.Function = (ULONG_PTR)Hooked_LoadLibraryExA;
                    VirtualProtect(&thunk->u1.Function, sizeof(void*), oldProtect, &oldProtect);
                }
                if (g_pfnLoadLibraryExW && (void*)thunk->u1.Function == (void*)g_pfnLoadLibraryExW) {
                    VirtualProtect(&thunk->u1.Function, sizeof(void*), PAGE_READWRITE, &oldProtect);
                    thunk->u1.Function = (ULONG_PTR)Hooked_LoadLibraryExW;
                    VirtualProtect(&thunk->u1.Function, sizeof(void*), oldProtect, &oldProtect);
                }
                if (g_pfnGetProcAddress && (void*)thunk->u1.Function == (void*)g_pfnGetProcAddress) {
                    VirtualProtect(&thunk->u1.Function, sizeof(void*), PAGE_READWRITE, &oldProtect);
                    thunk->u1.Function = (ULONG_PTR)Hooked_GetProcAddress;
                    VirtualProtect(&thunk->u1.Function, sizeof(void*), oldProtect, &oldProtect);
                }
                if (g_pfnVirtualAllocEx && (void*)thunk->u1.Function == (void*)g_pfnVirtualAllocEx) {
                    VirtualProtect(&thunk->u1.Function, sizeof(void*), PAGE_READWRITE, &oldProtect);
                    thunk->u1.Function = (ULONG_PTR)Hooked_VirtualAllocEx;
                    VirtualProtect(&thunk->u1.Function, sizeof(void*), oldProtect, &oldProtect);
                }
                if (g_pfnWriteProcessMemory && (void*)thunk->u1.Function == (void*)g_pfnWriteProcessMemory) {
                    VirtualProtect(&thunk->u1.Function, sizeof(void*), PAGE_READWRITE, &oldProtect);
                    thunk->u1.Function = (ULONG_PTR)Hooked_WriteProcessMemory;
                    VirtualProtect(&thunk->u1.Function, sizeof(void*), oldProtect, &oldProtect);
                }
                if (g_pfnVirtualProtect && (void*)thunk->u1.Function == (void*)g_pfnVirtualProtect) {
                    VirtualProtect(&thunk->u1.Function, sizeof(void*), PAGE_READWRITE, &oldProtect);
                    thunk->u1.Function = (ULONG_PTR)Hooked_VirtualProtect;
                    VirtualProtect(&thunk->u1.Function, sizeof(void*), oldProtect, &oldProtect);
                }
                if (g_pfnVirtualProtectEx && (void*)thunk->u1.Function == (void*)g_pfnVirtualProtectEx) {
                    VirtualProtect(&thunk->u1.Function, sizeof(void*), PAGE_READWRITE, &oldProtect);
                    thunk->u1.Function = (ULONG_PTR)Hooked_VirtualProtectEx;
                    VirtualProtect(&thunk->u1.Function, sizeof(void*), oldProtect, &oldProtect);
                }
            }
            else if (IsCaseInsensitiveEqual(moduleName, "ntdll.dll")) {
                if (g_pfnNtCreateThreadEx && (void*)thunk->u1.Function == (void*)g_pfnNtCreateThreadEx) {
                    VirtualProtect(&thunk->u1.Function, sizeof(void*), PAGE_READWRITE, &oldProtect);
                    thunk->u1.Function = (ULONG_PTR)Hooked_NtCreateThreadEx;
                    VirtualProtect(&thunk->u1.Function, sizeof(void*), oldProtect, &oldProtect);
                }
                if (g_pfnLdrLoadDll && (void*)thunk->u1.Function == (void*)g_pfnLdrLoadDll) {
                    VirtualProtect(&thunk->u1.Function, sizeof(void*), PAGE_READWRITE, &oldProtect);
                    thunk->u1.Function = (ULONG_PTR)Hooked_LdrLoadDll;
                    VirtualProtect(&thunk->u1.Function, sizeof(void*), oldProtect, &oldProtect);
                }
                if (g_pfnLdrLoadDllStub && (void*)thunk->u1.Function == (void*)g_pfnLdrLoadDllStub) {
                    VirtualProtect(&thunk->u1.Function, sizeof(void*), PAGE_READWRITE, &oldProtect);
                    thunk->u1.Function = (ULONG_PTR)Hooked_LdrLoadDll;
                    VirtualProtect(&thunk->u1.Function, sizeof(void*), oldProtect, &oldProtect);
                }
            }
            else if (IsCaseInsensitiveEqual(moduleName, "user32.dll")) {
                if (g_pfnSetWindowsHookExW && (void*)thunk->u1.Function == (void*)g_pfnSetWindowsHookExW) {
                    VirtualProtect(&thunk->u1.Function, sizeof(void*), PAGE_READWRITE, &oldProtect);
                    thunk->u1.Function = (ULONG_PTR)Hooked_SetWindowsHookExW;
                    VirtualProtect(&thunk->u1.Function, sizeof(void*), oldProtect, &oldProtect);
                }
            }
            thunk++;
        }
        importDesc++;
    }
}

void StartManualMapDetection() {
    DWORD pid = GetCurrentProcessId();
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) return;
    
    InitializeWhitelist();
    InitializeExeDirectory();
    
    HMODULE hMods[1024];
    DWORD cbNeeded;
    if (EnumProcessModules(GetCurrentProcess(), hMods, sizeof(hMods), &cbNeeded)) {
        for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            TrackModuleLoad(hMods[i]);
        }
    }
    g_modules_tracked = true;
    
    InstallIATHooks();
    
    MonitorLoadedModules();
    MonitorThreadCreation();
    
    std::thread t([hProc, pid]() {
        Sleep(100);
        
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (!hNtdll) {
            CloseHandle(hProc);
            return;
        }
        PFN_NtQueryVirtualMemory NtQVM =
            reinterpret_cast<PFN_NtQueryVirtualMemory>(GetProcAddress(hNtdll, "NtQueryVirtualMemory"));
        PFN_NtTerminateProcess NtTP =
            reinterpret_cast<PFN_NtTerminateProcess>(GetProcAddress(hNtdll, "NtTerminateProcess"));
        if (!NtQVM) {
            CloseHandle(hProc);
            return;
        }
        
        std::map<uintptr_t, RegionEntropy> entropyTracker;
        double fragmentedSusp = false;
        
        std::vector<FoundPE> initial_pe = scan_process_memory_for_pe(pid, hProc, NtQVM, entropyTracker, fragmentedSusp);
        std::set<uintptr_t> known_pe_bases;
        for (const auto& f : initial_pe) {
            known_pe_bases.insert(f.base);
        }

        std::vector<FoundCodeCave> initial_caves = scan_for_code_caves(hProc);
        std::set<uintptr_t> known_code_caves;
        for (const auto& cc : initial_caves) {
            known_code_caves.insert(cc.cave_start);
        }

        std::set<uintptr_t> baseline_private_exec;
        {
            MEMORY_BASIC_INFORMATION mbiBaseline = {};
            uintptr_t addrBaseline = 0;
            while (VirtualQueryEx(hProc, reinterpret_cast<LPCVOID>(addrBaseline), &mbiBaseline, sizeof(mbiBaseline)) == sizeof(mbiBaseline)) {
                if (mbiBaseline.State == MEM_COMMIT &&
                    mbiBaseline.Type == MEM_PRIVATE &&
                    is_executable_protection(mbiBaseline.Protect) &&
                    mbiBaseline.RegionSize > 0x800) { 
                    baseline_private_exec.insert(addrBaseline);
                }
                addrBaseline += mbiBaseline.RegionSize;
                if (addrBaseline == 0) break;
            }
        }
        
        while (true) {
            Sleep(200);  
            bool injectedDetected = false;

            std::set<uintptr_t> current_module_bases;
            {
                HMODULE hModsNow[1024];
                DWORD cbNeededNow = 0;
                if (EnumProcessModules(GetCurrentProcess(), hModsNow, sizeof(hModsNow), &cbNeededNow)) {
                    for (unsigned int i = 0; i < (cbNeededNow / sizeof(HMODULE)); ++i) {
                        current_module_bases.insert(reinterpret_cast<uintptr_t>(hModsNow[i]));
                    }
                }
            }

            std::vector<FoundPE> found_pe = scan_process_memory_for_pe(pid, hProc, NtQVM, entropyTracker, fragmentedSusp);
            for (const auto& f : found_pe) {
                auto itKnown = known_pe_bases.find(f.base);

                HMODULE hModFromAddr = nullptr;
                BOOL hasModuleHandle = GetModuleHandleExW(
                    GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
                    reinterpret_cast<LPCWSTR>(f.base),
                    &hModFromAddr
                );

                if (!hasModuleHandle || !hModFromAddr) {
                    injectedDetected = true;
                    VirtualFreeEx(hProc, reinterpret_cast<LPVOID>(f.base), 0, MEM_RELEASE);
                    break;
                }

                if (itKnown == known_pe_bases.end()) {
                    wchar_t modPathW[MAX_PATH] = { 0 };
                    if (GetModuleFileNameW(hModFromAddr, modPathW, MAX_PATH)) {
                        std::wstring modPath = ToLowerW(modPathW);
                        bool isSystemDll =
                            modPath.find(L"c:\\windows\\system32\\") == 0 ||
                            modPath.find(L"c:\\windows\\syswow64\\") == 0 ||
                            modPath.find(L"c:\\windows\\winsxs\\") == 0;

                        size_t lastSlash = modPath.find_last_of(L"\\/");
                        std::wstring filename = (lastSlash != std::wstring::npos)
                            ? modPath.substr(lastSlash + 1)
                            : modPath;

                        bool isAllowed = false;
                        {
                            std::lock_guard<std::mutex> lock(g_allowed_dlls_mutex);
                            isAllowed = (g_allowed_dlls.find(filename) != g_allowed_dlls.end());
                        }

                        bool isFromExeDir = false;
                        if (!g_exe_directory.empty()) {
                            if (modPath.find(g_exe_directory) == 0) {
                                isFromExeDir = true;
                            }
                        }

                        if (isSystemDll || isAllowed || isFromExeDir) {
                            known_pe_bases.insert(f.base);
                            continue;
                        }
                    }

                    injectedDetected = true;
                    VirtualFreeEx(hProc, reinterpret_cast<LPVOID>(f.base), 0, MEM_RELEASE);
                    break;
                } else {
                    if (f.is_dll) {
                        bool isInCurrentModules = (current_module_bases.find(f.base) != current_module_bases.end());
                        
                        HMODULE hModCheck = nullptr;
                        BOOL hasModuleHandleCheck = GetModuleHandleExW(
                            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            reinterpret_cast<LPCWSTR>(f.base),
                            &hModCheck
                        );
                        
                        if (!isInCurrentModules || !hasModuleHandleCheck || !hModCheck) {
                            wchar_t modPathW[MAX_PATH] = { 0 };
                            bool isSystemDll = false;
                            bool isAllowed = false;
                            bool isFromExeDir = false;
                            
                            if (hModFromAddr && GetModuleFileNameW(hModFromAddr, modPathW, MAX_PATH)) {
                                std::wstring modPath = ToLowerW(modPathW);
                                isSystemDll =
                                    modPath.find(L"c:\\windows\\system32\\") == 0 ||
                                    modPath.find(L"c:\\windows\\syswow64\\") == 0 ||
                                    modPath.find(L"c:\\windows\\winsxs\\") == 0;

                                size_t lastSlash = modPath.find_last_of(L"\\/");
                                std::wstring filename = (lastSlash != std::wstring::npos)
                                    ? modPath.substr(lastSlash + 1)
                                    : modPath;

                                {
                                    std::lock_guard<std::mutex> lock(g_allowed_dlls_mutex);
                                    isAllowed = (g_allowed_dlls.find(filename) != g_allowed_dlls.end());
                                }

                                if (!g_exe_directory.empty()) {
                                    if (modPath.find(g_exe_directory) == 0) {
                                        isFromExeDir = true;
                                    }
                                }
                            }
                            
                            if (!isSystemDll && !isAllowed && !isFromExeDir) {
                                injectedDetected = true;
                                VirtualFreeEx(hProc, reinterpret_cast<LPVOID>(f.base), 0, MEM_RELEASE);
                                break;
                            }
                        } else {
                            wchar_t modPathW[MAX_PATH] = { 0 };
                            if (GetModuleFileNameW(hModFromAddr, modPathW, MAX_PATH)) {
                                std::wstring modPath = ToLowerW(modPathW);
                                bool isSystemDll =
                                    modPath.find(L"c:\\windows\\system32\\") == 0 ||
                                    modPath.find(L"c:\\windows\\syswow64\\") == 0 ||
                                    modPath.find(L"c:\\windows\\winsxs\\") == 0;

                                size_t lastSlash = modPath.find_last_of(L"\\/");
                                std::wstring filename = (lastSlash != std::wstring::npos)
                                    ? modPath.substr(lastSlash + 1)
                                    : modPath;

                                bool isAllowed = false;
                                {
                                    std::lock_guard<std::mutex> lock(g_allowed_dlls_mutex);
                                    isAllowed = (g_allowed_dlls.find(filename) != g_allowed_dlls.end());
                                }

                                bool isFromExeDir = false;
                                if (!g_exe_directory.empty()) {
                                    if (modPath.find(g_exe_directory) == 0) {
                                        isFromExeDir = true;
                                    }
                                }

                                if (!isSystemDll && !isAllowed && !isFromExeDir) {
                                    injectedDetected = true;
                                    VirtualFreeEx(hProc, reinterpret_cast<LPVOID>(f.base), 0, MEM_RELEASE);
                                    break;
                                }
                            }
                        }
                    }

                    if (f.no_header_high_entropy ||
                        !f.valid_sections ||
                        f.vad_anomaly ||
                        f.rpm_section_error ||
                        f.mismatched_base_no_reloc ||
                        f.suspicious_imports) {
                        injectedDetected = true;
                        VirtualFreeEx(hProc, reinterpret_cast<LPVOID>(f.base), 0, MEM_RELEASE);
                        break;
                    }
                }
            }

            if (!injectedDetected) {
                std::vector<FoundCodeCave> caves = scan_for_code_caves(hProc);
                for (const auto& cc : caves) {
                    if (known_code_caves.find(cc.cave_start) == known_code_caves.end()) {
                        if (cc.cave_size > 0x100 && cc.entropy > 3.8) {
                            injectedDetected = true;
                            break;
                        }
                        if (cc.cave_size > 0x800) {
                            injectedDetected = true;
                            break;
                        }
                        HMODULE hModFromCave = nullptr;
                        if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, reinterpret_cast<LPCWSTR>(cc.cave_start), &hModFromCave)) {
                            if (cc.cave_size > 0x400) {
                                injectedDetected = true;
                                break;
                            }
                        }
                    }
                }
                for (const auto& cc : caves) {
                    known_code_caves.insert(cc.cave_start);
                }
            }

            if (!injectedDetected) {
                MEMORY_BASIC_INFORMATION mbi = {};
                uintptr_t addrScan = 0;
                while (VirtualQueryEx(hProc, reinterpret_cast<LPCVOID>(addrScan), &mbi, sizeof(mbi)) == sizeof(mbi)) {
                    if (mbi.State == MEM_COMMIT &&
                        mbi.Type == MEM_PRIVATE &&
                        is_executable_protection(mbi.Protect) &&
                        mbi.RegionSize > 0x800) {

                        if (baseline_private_exec.find(addrScan) == baseline_private_exec.end()) {
                            HMODULE hModFromAddr = nullptr;
                            BOOL hasModuleHandle = GetModuleHandleExW(
                                GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
                                reinterpret_cast<LPCWSTR>(addrScan),
                                &hModFromAddr
                            );

                            if (!hasModuleHandle || !hModFromAddr) {
                                if (mbi.RegionSize > 0x8000) {
                                    injectedDetected = true;
                                    break;
                                }
                                
                                SIZE_T readSize = (std::min)(static_cast<SIZE_T>(0x1000), mbi.RegionSize);
                                std::vector<BYTE> sample(static_cast<size_t>(readSize));
                                SIZE_T bytesRead = 0;
                                if (addrScan != 0 &&
                                    ReadProcessMemory(hProc, reinterpret_cast<LPCVOID>(addrScan), sample.data(), readSize, &bytesRead) &&
                                    bytesRead > 0) {
                                    sample.resize(bytesRead);
                                    double ent = compute_entropy(sample);
                                    if (ent > 4.8) {
                                        injectedDetected = true;
                                        break;
                                    }
                                    if (mbi.RegionSize > 0x2000 && ent > 4.2) {
                                        injectedDetected = true;
                                        break;
                                    }
                                    if (mbi.RegionSize > 0x3000) {
                                        injectedDetected = true;
                                        break;
                                    }
                                } else {
                                    if (mbi.RegionSize > 0x2000) {
                                        injectedDetected = true;
                                        break;
                                    }
                                }
                            }
                        }
                    }

                    addrScan += mbi.RegionSize;
                    if (addrScan == 0) break;
                }
            }

            if (injectedDetected) {
                TerminateProcess(GetCurrentProcess(), 0xDEADBEEF);
                ExitProcess(0xDEADBEEF);
                BOOL termRes = TerminateProcess(hProc, 1);
                if (!termRes && NtTP) {
                    NtTP(hProc, 1);
                }
                if (NtTP) {
                    NtTP(hProc, 1);
                }
                break;
            }
        }
        CloseHandle(hProc);
        });
    t.detach();
}
