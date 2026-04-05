// handler_storage_proof.h
#ifndef _HANDLER_STORAGE_PROOF_H
#define _HANDLER_STORAGE_PROOF_H
#include "buffer.h"
// VERIFY_VK_STORAGE (0x64) — verify MPT storage proof of VK hash
int handler_storage_proof(uint8_t p1, uint8_t p2, buffer_t *cdata);
#endif
