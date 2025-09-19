#ifndef PACKET_H
#define PACKET_H

#pragma once
#include <linux/ctype.h>

struct kpacket_header {
  u16 magic;
  u8 cmd_id;
  u16 payload_len;
  u8 flags;
  u32 seq_id;
};

struct kpacket {
  struct kpacket_header header;
  u8 payload[];
};

#endif
