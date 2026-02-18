#include "wrapper.h"

void event(const u32 id, hashcat_ctx_t *hashcat_ctx, const void *buf, const size_t len)
{
  gocat_ctx_t *worker_tuple = (gocat_ctx_t*)hashcat_ctx;
  callback(id, hashcat_ctx, worker_tuple->gowrapper, (void*)buf, (size_t)len);
}

void freeargv(int argc, char **argv)
{
  for (int i = 0; i < argc; i++)
  {
    free(argv[i]);
  }
  free(argv);
}
