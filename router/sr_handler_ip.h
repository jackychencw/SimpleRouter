#ifndef SR_HANDLER_IP_H
#define SR_HANDLER_IP_H

#include <netinet/in.h>
#include <sys/time.h>
#include <stdio.h>

#include "sr_protocol.h"
void sr_handle_ip(struct sr_instance *sr,
                  uint8_t *packet,
                  unsigned int len,
                  struct sr_if *iface);
#endif