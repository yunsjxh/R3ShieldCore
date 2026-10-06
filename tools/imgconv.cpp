//
// imgconv.cpp - 把 BMP 转成 PNG（WIC）。支持裁剪。
//
// 为什么不用 bmp2png.exe：那个用 GDI+，本机上加载 1920x1080 的 32 位 BMP
// 会直接段错误。WIC 走的是系统编解码器，稳得多。
//
// 用法:
//   imgconv <输入.bmp> <输出.png>
//   imgconv <输入.bmp> <输出.png> crop <l> <t> <r> <b>
//
#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <wincodec.h>
#include <shlwapi.h>
#include <stdio.h>
#include <stdlib.h>

#pragma comment(lib, "windowscodecs.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "shlwapi.lib")

template <typename T>
static void SafeRelease(T** pp)
{
	if (*pp) { (*pp)->Release(); *pp = nullptr; }
}

// 在 COM 里把窄字符路径转成宽字符（这里直接用 ACP）。
static void ToWide(const char* in, WCHAR* out, int cch)
{
	MultiByteToWideChar(CP_ACP, 0, in, -1, out, cch);
}

int main(int argc, char** argv)
{
	if (argc < 3) {
		printf("usage: imgconv <in.bmp> <out.png> [crop <l> <t> <r> <b>]\n");
		return 1;
	}

	WCHAR inPath[MAX_PATH] = {};
	WCHAR outPath[MAX_PATH] = {};
	ToWide(argv[1], inPath, MAX_PATH);
	ToWide(argv[2], outPath, MAX_PATH);

	bool crop = (argc >= 8 && _stricmp(argv[3], "crop") == 0);
	UINT cropL = 0, cropT = 0, cropR = 0, cropB = 0;
	if (crop) {
		cropL = (UINT)atoi(argv[4]);
		cropT = (UINT)atoi(argv[5]);
		cropR = (UINT)atoi(argv[6]);
		cropB = (UINT)atoi(argv[7]);
	}

	HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
	if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) {
		printf("CoInitializeEx failed 0x%08lX\n", (unsigned long)hr);
		return 1;
	}

	IWICImagingFactory* factory = nullptr;
	hr = CoCreateInstance(CLSID_WICImagingFactory, nullptr, CLSCTX_INPROC_SERVER,
		IID_PPV_ARGS(&factory));
	if (FAILED(hr)) {
		printf("CoCreateInstance failed 0x%08lX\n", (unsigned long)hr);
		return 1;
	}

	IWICBitmapDecoder* decoder = nullptr;
	hr = factory->CreateDecoderFromFilename(inPath, nullptr, GENERIC_READ,
		WICDecodeMetadataCacheOnDemand, &decoder);
	if (FAILED(hr)) {
		printf("decode failed 0x%08lX (path=%ls)\n", (unsigned long)hr, inPath);
		SafeRelease(&factory);
		return 1;
	}

	IWICBitmapFrameDecode* frame = nullptr;
	hr = decoder->GetFrame(0, &frame);
	if (FAILED(hr)) {
		printf("GetFrame failed 0x%08lX\n", (unsigned long)hr);
		SafeRelease(&decoder);
		SafeRelease(&factory);
		return 1;
	}

	UINT width = 0, height = 0;
	frame->GetSize(&width, &height);
	printf("source: %u x %u\n", width, height);

	// 需要的话先裁一刀。
	IWICBitmapSource* source = frame;
	IWICBitmapClipper* clipper = nullptr;
	if (crop) {
		if (cropR > width) { cropR = width; }
		if (cropB > height) { cropB = height; }
		WICRect rect = { (INT)cropL, (INT)cropT, (INT)(cropR - cropL), (INT)(cropB - cropT) };
		hr = factory->CreateBitmapClipper(&clipper);
		if (SUCCEEDED(hr)) {
			hr = clipper->Initialize(frame, &rect);
			if (SUCCEEDED(hr)) {
				source = clipper;
			}
		}
		printf("crop: %d,%d - %d,%d\n", rect.X, rect.Y, rect.X + rect.Width, rect.Y + rect.Height);
	}

	// 转成 24 位 BGR，避免 alpha 通道导致 PNG 看着发灰。
	IWICFormatConverter* converter = nullptr;
	hr = factory->CreateFormatConverter(&converter);
	if (SUCCEEDED(hr)) {
		hr = converter->Initialize(source, GUID_WICPixelFormat24bppBGR,
			WICBitmapDitherTypeNone, nullptr, 0.0, WICBitmapPaletteTypeCustom);
	}
	if (FAILED(hr)) {
		printf("converter init failed 0x%08lX\n", (unsigned long)hr);
		SafeRelease(&clipper);
		SafeRelease(&frame);
		SafeRelease(&decoder);
		SafeRelease(&factory);
		return 1;
	}

	IWICBitmapEncoder* encoder = nullptr;
	hr = factory->CreateEncoder(GUID_ContainerFormatPng, nullptr, &encoder);

	// 编码器必须绑到一个真实的输出流上。传 nullptr 给 Initialize 不是合法用法，
	// 会让后续 CreateNewFrame 报 E_INVALIDARG(0x80070057)。
	IStream* outStream = nullptr;
	if (SUCCEEDED(hr)) {
		hr = SHCreateStreamOnFileEx(outPath, STGM_CREATE | STGM_WRITE | STGM_SHARE_DENY_WRITE,
			FILE_ATTRIBUTE_NORMAL, TRUE, nullptr, &outStream);
	}
	if (SUCCEEDED(hr)) {
		hr = encoder->Initialize(outStream, WICBitmapEncoderNoCache);
	}
	printf("encoder init -> 0x%08lX\n", (unsigned long)hr);

	UINT outWidth = crop ? (cropR - cropL) : width;
	UINT outHeight = crop ? (cropB - cropT) : height;

	IWICBitmapFrameEncode* encFrame = nullptr;
	IPropertyBag2* props = nullptr;
	if (SUCCEEDED(hr)) {
		hr = encoder->CreateNewFrame(&encFrame, &props);
	}
	if (SUCCEEDED(hr)) {
		hr = encFrame->Initialize(props);
	}
	if (SUCCEEDED(hr)) {
		hr = encFrame->SetSize(outWidth, outHeight);
	}
	if (SUCCEEDED(hr)) {
		WICPixelFormatGUID fmt = GUID_WICPixelFormat24bppBGR;
		hr = encFrame->SetPixelFormat(&fmt);
		printf("SetPixelFormat -> 0x%08lX (got %08lX-%04X-%04X)\n",
			(unsigned long)hr, fmt.Data1, fmt.Data2, fmt.Data3);
	}
	if (SUCCEEDED(hr)) {
		hr = encFrame->WriteSource(converter, nullptr);
	}
	if (SUCCEEDED(hr)) {
		hr = encFrame->Commit();
	}
	if (SUCCEEDED(hr)) {
		hr = encoder->Commit();
	}
	printf("final -> 0x%08lX\n", (unsigned long)hr);

	SafeRelease(&outStream);
	SafeRelease(&props);
	SafeRelease(&encFrame);
	SafeRelease(&encoder);
	SafeRelease(&converter);
	SafeRelease(&clipper);
	SafeRelease(&frame);
	SafeRelease(&decoder);
	SafeRelease(&factory);

	if (FAILED(hr)) {
		printf("encode failed 0x%08lX\n", (unsigned long)hr);
		return 1;
	}

	printf("saved %ls\n", outPath);
	return 0;
}
