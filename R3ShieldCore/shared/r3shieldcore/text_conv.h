// text_conv.h —— UTF-8 ⇄ UTF-16 的**唯一**一份转换（铁律 127）。
//
//   为什么单独抽出来：
//     本项目的文本要在四个地方过界 —— 日志文件（UTF-8）、管道（UTF-8）、
//     Win32 界面（UTF-16）、以及各处的 `printf` 诊断（当前代码页）。
//     每处各写一遍 `MultiByteToWideChar` 就会漂：有的用 `CP_UTF8` 有的用
//     `CP_ACP`、有的按 NUL 截断有的按显式长度、失败时有的返回空串
//     有的返回半个串 —— 而"编码不对"表现为**乱码或整行截断**，
//     不是崩溃，最容易带着上生产（铁律 252 就是同族）。
//
//   语义（两个方向一致，别改）：
//     · 按**显式长度**转，不依赖结尾 NUL（生产者可能刚好填满整段）；
//     · 失败（空串 / 非法序列 / 系统调用返回 0）⇒ 返回**空串**，
//       绝不返回半截 —— 半截的 UTF-8 会让下游解码器吃错字节。
#pragma once
#ifndef R3SHIELDCORE_TEXT_CONV_H
#define R3SHIELDCORE_TEXT_CONV_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <string>

namespace R3ShieldCoreText
{
	inline std::wstring Utf8ToWide(const std::string& utf8) noexcept
	{
		if (utf8.empty()) {
			return std::wstring();
		}

		const int need = ::MultiByteToWideChar(CP_UTF8, 0, utf8.data(),
			static_cast<int>(utf8.size()), nullptr, 0);
		if (need <= 0) {
			return std::wstring();
		}

		std::wstring out(static_cast<size_t>(need), L'\0');
		::MultiByteToWideChar(CP_UTF8, 0, utf8.data(),
			static_cast<int>(utf8.size()), out.data(), need);
		return out;
	}

	inline std::string WideToUtf8(const std::wstring& wide) noexcept
	{
		if (wide.empty()) {
			return std::string();
		}

		const int need = ::WideCharToMultiByte(CP_UTF8, 0, wide.data(),
			static_cast<int>(wide.size()), nullptr, 0, nullptr, nullptr);
		if (need <= 0) {
			return std::string();
		}

		std::string out(static_cast<size_t>(need), '\0');
		::WideCharToMultiByte(CP_UTF8, 0, wide.data(),
			static_cast<int>(wide.size()), out.data(), need, nullptr, nullptr);
		return out;
	}
}  // namespace R3ShieldCoreText

#endif  // R3SHIELDCORE_TEXT_CONV_H
