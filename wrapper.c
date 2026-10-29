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

// status_destroy frees the strings hashcat_get_status allocates. It mirrors hashcat's
// status_status_destroy, which libhashcat no longer exports as of v8.0.0.
void status_destroy(hashcat_ctx_t *hashcat_ctx, hashcat_status_t *hashcat_status)
{
  const status_ctx_t *status_ctx = hashcat_ctx->status_ctx;

  if (status_ctx == NULL) return;

  if (status_ctx->accessible == false) return;

  hcfree(hashcat_status->hash_target);
  hcfree(hashcat_status->hash_name);
  hcfree(hashcat_status->session);
  hcfree(hashcat_status->time_estimated_absolute);
  hcfree(hashcat_status->time_estimated_relative);
  hcfree(hashcat_status->time_started_absolute);
  hcfree(hashcat_status->time_started_relative);
  hcfree(hashcat_status->speed_sec_all);
  hcfree(hashcat_status->guess_base);
  hcfree(hashcat_status->guess_mod);
  hcfree(hashcat_status->guess_mod_q);
  hcfree(hashcat_status->guess_charset);
  hcfree(hashcat_status->cpt);

  for (int device_id = 0; device_id < hashcat_status->device_info_cnt; device_id++)
  {
    device_info_t *device_info = hashcat_status->device_info_buf + device_id;

    hcfree(device_info->speed_sec_dev);
    hcfree(device_info->guess_candidates_dev);
    hcfree(device_info->hwmon_dev);
  }
}
