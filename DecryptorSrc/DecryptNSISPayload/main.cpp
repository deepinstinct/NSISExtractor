#include <stdio.h>
#include <Windows.h>
#include <wincrypt.h>

// Since RtlDecompressBuffer is a function inside WDK, just load it dynamically
typedef NTSTATUS(__stdcall *RtlDecompressBuffer)(
	_In_  USHORT CompressionFormat,
	_Out_ PUCHAR UncompressedBuffer,
	_In_  ULONG  UncompressedBufferSize,
	_In_  PUCHAR CompressedBuffer,
	_In_  ULONG  CompressedBufferSize,
	_Out_ PULONG FinalUncompressedSize
	);

typedef struct fileOutputDetails {
	DWORD	compressedBufferSize;
	DWORD	uncompressedBufferSize;
	DWORD	encryptedContentSize;
	PBYTE	beginningOfEncryptedData;
} encDetails;

PBYTE OpenAndReadFile(LPSTR filePath, DWORD *fileSize)
{
	BYTE	*fileContent = NULL;
	DWORD	numberOfBytesRead = 0;

	HANDLE hFile = CreateFileA(filePath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (NULL == hFile) {
		printf("Could not open NSIS file. GetLastError = %d\n", GetLastError());
		goto end;
	}

	*fileSize = GetFileSize(hFile, NULL);

	fileContent = (PBYTE)VirtualAlloc(NULL, *fileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if (NULL == fileContent) {
		printf("Allocation failed for fileContent. GetLastError = %d\n", GetLastError());
		goto end;
	}

	if (FALSE == ReadFile(hFile, fileContent, *fileSize, &numberOfBytesRead, NULL)) {
		printf("ReadFile failed. GetLastError = %d\n", GetLastError());
		goto end;
	}

	if (0 == numberOfBytesRead) {
		goto end;
	}

end:
	if (NULL != hFile) {
		CloseHandle(hFile);
		hFile = NULL;
	}

	return fileContent;
}

PBYTE DecryptContent(PVOID encContent, DWORD encryptedContentSize, BYTE* encKey, DWORD encKeyLenInBytes)
{
	HCRYPTPROV	hProv = NULL;
	HCRYPTHASH	hHash = NULL;
	HCRYPTKEY	hKey = NULL;

	if (FALSE == CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
		// printf("CryptAcquireContext failed. GetLastError = %d\n", GetLastError());
		return NULL;
	}

	if (FALSE == CryptCreateHash(hProv, 0x8003, 0, 0, &hHash)) {
		// printf("CryptCreateHash failed. GetLastError = %d\n", GetLastError());
		return NULL;
	}

	// CryptHashData requires exact size without null-terminated, so decrease it by 1
	if (FALSE == CryptHashData(hHash, encKey, encKeyLenInBytes, CRYPT_USERDATA)) {
		// printf("CryptHashData failed. GetLastError = %d\n", GetLastError());
		return NULL;
	}

	if (FALSE == CryptDeriveKey(hProv, CALG_AES_256, hHash, 1, &hKey)) {
		// printf("CryptDeriveKey failed. GetLastError = %x\n", GetLastError());
		return NULL;
	}

	if (FALSE == CryptDestroyHash(hHash)) {
		// printf("CryptDestroyHash failed. GetLastError = %x\n", GetLastError());
		return NULL;
	}

	if (FALSE == CryptDecrypt(hKey, NULL, TRUE, NULL, (BYTE*)encContent, &encryptedContentSize)) {
		// printf("CryptDecrypt failed. GetLastError = %d\n", GetLastError());
		return NULL;
	}

	if (FALSE == CryptDestroyKey(hKey)) {
		// printf("CryptDestroyKey failed. GetLastError = %d\n", GetLastError());
		return NULL;
	}

	if (FALSE == CryptReleaseContext(hProv, 0)) {
		// printf("CryptReleaseContext failed. GetLastError = %d\n", GetLastError());
		return NULL;
	}

	return (PBYTE)encContent;
}

PBYTE ExtractDataAndDecrypt(PBYTE codeContent, LPWSTR encKey, DWORD encKeyLenInBytes, DWORD *finalUncompressedSize, DWORD currentIndex, DWORD fileSize)
{
	encDetails details = { 0 };
	PDWORD	encHeader = NULL;
	PVOID	encryptedContent = NULL;
	PBYTE	decryptedContent = NULL, decompressContent = NULL;
	RtlDecompressBuffer _RtlDecompressBuffer = (RtlDecompressBuffer)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "RtlDecompressBuffer");
	
	encHeader = (PDWORD)(codeContent + currentIndex);

	details.beginningOfEncryptedData = (codeContent + currentIndex + 0x10);

	details.uncompressedBufferSize = *(encHeader + 0x2) + 0x3E8;

	encryptedContent = VirtualAlloc(NULL, details.uncompressedBufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if (NULL == encryptedContent) {
		// printf("Allocation failed for uncompressed size. GetLastError = %d\n", GetLastError());
		goto end;
	}

	details.encryptedContentSize = *(encHeader + 0x2);

	// Since we are about to copy the encrypted data, it must be smaller than its file size
	if (details.encryptedContentSize > fileSize) {
		goto end;
	}

	if ((DWORD)details.beginningOfEncryptedData - (DWORD)codeContent + details.encryptedContentSize > fileSize) {
		goto end;
	}

	CopyMemory(encryptedContent, details.beginningOfEncryptedData, details.encryptedContentSize);

	decryptedContent = DecryptContent(encryptedContent, details.encryptedContentSize, (PBYTE)encKey, encKeyLenInBytes - 1);

	if (NULL == decryptedContent) {
		goto end;
	}

	details.uncompressedBufferSize = *(encHeader + 0x1);

	decompressContent = (PBYTE)VirtualAlloc(NULL, details.uncompressedBufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if (NULL == decompressContent) {
		// printf("Allocation failed for decompressContent. GetLastError = %d\n", GetLastError());
		goto end;
	}
	
	details.compressedBufferSize = (DWORD)*encHeader;

	// Decompress it
	if (0 == _RtlDecompressBuffer(COMPRESSION_FORMAT_LZNT1 | COMPRESSION_ENGINE_MAXIMUM, decompressContent, details.uncompressedBufferSize, decryptedContent, details.compressedBufferSize, finalUncompressedSize)) {
		// printf("_RtlDecompressBuffer failed. GetLastError = %d", GetLastError());
		goto end;
	}

	*finalUncompressedSize = details.uncompressedBufferSize;

end:
	if (NULL != encryptedContent) {
		// Release what we don't need anymore
		VirtualFree(encryptedContent, details.uncompressedBufferSize, MEM_DECOMMIT | MEM_RELEASE);
		encryptedContent = NULL;
	}

	return decompressContent;

}

int main(int argc, char **argv[])
{
	PBYTE	nsisContent = NULL;
	PBYTE	codeContent = NULL;
	LPWSTR	encKey = NULL;
	DWORD	keyLen = 0, keyLenUnicodeBytesSize = 0, uncompressedSize = 0, fileSize = 0, currentIndex = 0;
	PBYTE	uncompressedContent = NULL;
	FILE	*fp = NULL;

	if (4 != argc) {
		printf("Usage: %s InputFile EncKey RansomwareOutput", argv[0]);
		return 0;
	}

	codeContent = OpenAndReadFile((LPSTR)argv[1], &fileSize);

	// Convert the key to unicode
	keyLen = strlen((char*)argv[2]);

	keyLenUnicodeBytesSize = keyLen * 2 + 1;

	encKey = (LPWSTR)malloc(keyLenUnicodeBytesSize);

	MultiByteToWideChar(CP_OEMCP, 0, (LPCCH)argv[2], -1, encKey, keyLen * 2 + 1);

	// Since the header is in different location every time, use brute force to extract the uncompressed content
	for (currentIndex = 0; currentIndex < fileSize; currentIndex++) {
		uncompressedContent = ExtractDataAndDecrypt(codeContent, encKey, keyLenUnicodeBytesSize, &uncompressedSize, currentIndex, fileSize);
		if (NULL == uncompressedContent) {
			continue;
		} else if (uncompressedContent[0] == 'M' && uncompressedContent[1] == 'Z') {
			fopen_s(&fp, (char*)argv[3], "wb");
			fwrite(uncompressedContent, sizeof(BYTE), uncompressedSize, fp);
			fclose(fp);
			VirtualFree(uncompressedContent, uncompressedSize, MEM_DECOMMIT | MEM_RELEASE);
			break;
		}
		else {
			VirtualFree(uncompressedContent, uncompressedSize, MEM_DECOMMIT | MEM_RELEASE);
		}
	}

	return 0;
}