// SPDX-License-Identifier: GPL-2.0-only
//
// sentry-native's logger hands over a printf format and its arguments (a
// `va_list`), which Rust can't format: this formats them, and passes the
// text on to Warlock's log, so that what the SDK says about itself (a
// request WinHTTP couldn't send, say) reaches the Event Log, not a service's
// stderr, which goes nowhere.

#include <stdarg.h>
#include <stdio.h>

#include <sentry.h>

typedef void (*warlock_sentry_log_t)(int level, const char *message);

static void logger(sentry_level_t level, const char *message, va_list args,
                   void *userdata) {
  char text[1024];
  vsnprintf(text, sizeof text, message, args);
  ((warlock_sentry_log_t)userdata)((int)level, text);
}

void warlock_sentry_set_logger(sentry_options_t *options,
                               warlock_sentry_log_t log) {
  sentry_options_set_logger(options, logger, (void *)log);
}
