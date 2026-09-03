#include "dscan/platform/WinSys.hpp"
#include "dscan/Report.hpp"
#include <fstream>
#include <iostream>

namespace dscan {

static std::string to_utf8(const std::wstring& wstr) {
#ifdef _WIN32
    if (wstr.empty()) return "";
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, wstr.data(), (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string strTo(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.data(), (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
    return strTo;
#else
    std::string res;
    for (wchar_t c : wstr) {
        if (c < 128) res += (char)c;
        else res += '?';
    }
    return res;
#endif
}

void write_report(const std::vector<Finding>& findings, const Config& cfg) {
    if (cfg.reportPath.empty()) return;

#ifdef _WIN32
    std::ofstream out(cfg.reportPath.c_str());
#else
    std::string path(cfg.reportPath.begin(), cfg.reportPath.end());
    std::ofstream out(path.c_str());
#endif
    if (!out) {
        std::wcerr << L"Failed to open report file: " << cfg.reportPath << std::endl;
        return;
    }

    if (cfg.format == OutputFormat::Text) {
        for (const auto& f : findings) {
            out << to_string(f.worst) << ": " << to_utf8(f.path) << " (" << f.size << " bytes)\n";
            for (const auto& r : f.results) {
                if (severity(r.verdict) > 0)
                    out << "  - " << r.method << ": " << r.detail << "\n";
            }
        }
    } else if (cfg.format == OutputFormat::Json) {
        out << "[\n";
        for (size_t i = 0; i < findings.size(); ++i) {
            const auto& f = findings[i];
            std::string utf8Path = to_utf8(f.path);
            std::string escapedPath;
            for (char c : utf8Path) {
                if (c == '\\') escapedPath += "\\\\";
                else if (c == '\"') escapedPath += "\\\"";
                else escapedPath += c;
            }
            out << "  {\n"
                << "    \"path\": \"" << escapedPath << "\",\n"
                << "    \"size\": " << f.size << ",\n"
                << "    \"verdict\": \"" << to_string(f.worst) << "\"\n"
                << "  }" << (i + 1 < findings.size() ? "," : "") << "\n";
        }
        out << "]\n";
    } else if (cfg.format == OutputFormat::Csv) {
        out << "Verdict,Path,Size,Details\n";
        for (const auto& f : findings) {
            out << to_string(f.worst) << ",\"" << to_utf8(f.path) << "\"," << f.size << ",\"";
            for (const auto& r : f.results) {
                if (severity(r.verdict) > 0)
                    out << r.method << ": " << r.detail << "; ";
            }
            out << "\"\n";
        }
    }
}

}
