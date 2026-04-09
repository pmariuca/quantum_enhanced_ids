#pragma once
#include "ml_buffer.h"

int  ml_client_init(const char *socket_path);
void ml_client_close(void);

// Returns probability [0.0, 1.0] or -1.0 on error
float ml_client_infer(const ml_pid_buffer_t *buf);