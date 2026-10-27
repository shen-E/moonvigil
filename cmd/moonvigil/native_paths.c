#include <stdint.h>
#include <moonbit.h>

#ifdef _WIN32
#include <windows.h>
#include <stdlib.h>

/* Paths arrive as borrowed, NUL-terminated UTF-8 bytes. */
static wchar_t *wide_path(const char *path) {
  int size = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1, NULL, 0);
  if (!size) return NULL;
  wchar_t *result = malloc((size_t)size * sizeof(wchar_t));
  if (!result) return NULL;
  if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1, result, size)) {
    free(result);
    return NULL;
  }
  return result;
}

static HANDLE open_identity(const char *path) {
  wchar_t *wide = wide_path(path);
  if (!wide) return INVALID_HANDLE_VALUE;
  HANDLE handle = CreateFileW(wide, 0,
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
      OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
  free(wide);
  return handle;
}

MOONBIT_FFI_EXPORT int32_t moonvigil_same_file(const char *left, const char *right) {
  HANDLE a = open_identity(left);
  HANDLE b = open_identity(right);
  BY_HANDLE_FILE_INFORMATION ai, bi;
  int same = a != INVALID_HANDLE_VALUE && b != INVALID_HANDLE_VALUE &&
      GetFileInformationByHandle(a, &ai) && GetFileInformationByHandle(b, &bi) &&
      ai.dwVolumeSerialNumber == bi.dwVolumeSerialNumber &&
      ai.nFileIndexHigh == bi.nFileIndexHigh && ai.nFileIndexLow == bi.nFileIndexLow;
  if (a != INVALID_HANDLE_VALUE) CloseHandle(a);
  if (b != INVALID_HANDLE_VALUE) CloseHandle(b);
  return same;
}

MOONBIT_FFI_EXPORT int32_t moonvigil_is_link(const char *path) {
  wchar_t *wide = wide_path(path);
  if (!wide) return 1;
  DWORD attributes = GetFileAttributesW(wide);
  free(wide);
  return attributes != INVALID_FILE_ATTRIBUTES &&
      (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
}
#else
#include <sys/stat.h>

MOONBIT_FFI_EXPORT int32_t moonvigil_same_file(const char *left, const char *right) {
  struct stat a, b;
  return stat(left, &a) == 0 && stat(right, &b) == 0 &&
      a.st_dev == b.st_dev && a.st_ino == b.st_ino;
}

MOONBIT_FFI_EXPORT int32_t moonvigil_is_link(const char *path) {
  struct stat info;
  return lstat(path, &info) == 0 && S_ISLNK(info.st_mode);
}
#endif
