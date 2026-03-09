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
enum qks_policy_result qks_policy_eval(const struct qks_event_msg *ev, const char **reason_out);

#endif