#include "dscan/Report.hpp"
#include <fstream>
#include <iostream>

namespace dscan {

static std::wstring to_wstring(const std::string& s) {
    return std::wstring(s.begin(), s.end());
}

void write_report(const std::vector<Finding>& findings, const Config& cfg) {
    if (cfg.reportPath.empty()) return;

#ifdef _WIN32
    std::wofstream out(cfg.reportPath.c_str());
#else
    std::string path(cfg.reportPath.begin(), cfg.reportPath.end());
    std::wofstream out(path.c_str());
#endif
    if (!out) {
        std::wcerr << L"Failed to open report file: " << cfg.reportPath << std::endl;
        return;
    }

    if (cfg.format == OutputFormat::Text) {
        for (const auto& f : findings) {
            out << to_string(f.worst) << L": " << f.path << L" (" << f.size << L" bytes)\n";
            for (const auto& r : f.results) {
                if (severity(r.verdict) > 0)
                    out << L"  - " << to_wstring(r.method) << L": " << to_wstring(r.detail) << L"\n";
            }
        }
    } else if (cfg.format == OutputFormat::Json) {
        out << L"[\n";
        for (size_t i = 0; i < findings.size(); ++i) {
            const auto& f = findings[i];
            std::wstring escapedPath;
            for (wchar_t c : f.path) {
                if (c == L'\\') escapedPath += L"\\\\";
                else if (c == L'\"') escapedPath += L"\\\"";
                else escapedPath += c;
            }
            out << L"  {\n"
                << L"    \"path\": \"" << escapedPath << L"\",\n"
                << L"    \"size\": " << f.size << L",\n"
                << L"    \"verdict\": \"" << to_wstring(to_string(f.worst)) << L"\"\n"
                << L"  }" << (i + 1 < findings.size() ? L"," : L"") << L"\n";
        }
        out << L"]\n";
    } else if (cfg.format == OutputFormat::Csv) {
        out << L"Verdict,Path,Size,Details\n";
        for (const auto& f : findings) {
            out << to_wstring(to_string(f.worst)) << L",\"" << f.path << L"\"," << f.size << L",\"";
            for (const auto& r : f.results) {
                if (severity(r.verdict) > 0)
                    out << to_wstring(r.method) << L": " << to_wstring(r.detail) << L"; ";
            }
            out << L"\"\n";
        }
    }
    // CSV omitted for brevity
}

}
