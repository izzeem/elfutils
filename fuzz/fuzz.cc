#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <err.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdbool.h>

const char* __asan_default_options() { return "detect_leaks=0"; }

extern "C" void process_file (int fd, const char *fname, bool only_one);

extern "C" int ignore_stdout(void) {
  int fd = open("/dev/null", O_WRONLY);
  if (fd == -1) {
    warn("open(\"/dev/null\") failed");
    return -1;
  }

  int ret = 0;
  if (dup2(fd, STDOUT_FILENO) == -1) {
    warn("failed to redirect stdout to /dev/null\n");
    ret = -1;
  }

  if (close(fd) == -1) {
    warn("close");
    ret = -1;
  }

  return ret;
}

extern "C" int delete_file(const char *pathname) {
  int ret = unlink(pathname);
  if (ret == -1) {
    warn("failed to delete \"%s\"", pathname);
  }

  free((void *)pathname);

  return ret;
}

extern "C" char *buf_to_file(const uint8_t *buf, size_t size) {
  char *pathname = strdup("/dev/shm/fuzz-XXXXXX");
  if (pathname == nullptr) {
    return nullptr;
  }

  int fd = mkstemp(pathname);
  if (fd == -1) {
    warn("mkstemp(\"%s\")", pathname);
    free(pathname);
    return nullptr;
  }

  size_t pos = 0;
  while (pos < size) {
    int nbytes = write(fd, &buf[pos], size - pos);
    if (nbytes <= 0) {
      if (nbytes == -1 && errno == EINTR) {
        continue;
      }
      warn("write");
      goto err;
    }
    pos += nbytes;
  }

  if (close(fd) == -1) {
    warn("close");
    goto err;
  }

  return pathname;

err:
  delete_file(pathname);
  return nullptr;
}

// fuzz_target.cc
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    ignore_stdout();
    if (Size==0) {
      return 0;
    }
    char* fname = buf_to_file(Data, Size);
    process_file(open(fname, O_RDONLY), fname, true);
    free(fname);
    return 0;
}
