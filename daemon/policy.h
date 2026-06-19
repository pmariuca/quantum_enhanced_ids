#ifndef QKS_POLICY_H
#define QKS_POLICY_H

#include "qks_message_user.h"
#include <stdbool.h>

enum qks_policy_result {
    QKS_POLICY_ALLOW = 1,
    QKS_POLICY_DENY  = 0,
    QKS_POLICY_UNKNOWN = 2
};

bool qks_policy_load(const char *path_json);
bool qks_policy_merge_local(const char *path);
enum qks_policy_result qks_policy_eval(const struct qks_event_msg *ev,
                                       const char **reason_out,
                                       bool *suppress_log_out);

#endif