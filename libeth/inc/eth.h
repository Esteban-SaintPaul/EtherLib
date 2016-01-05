#include <string.h>
#include "drvEnc28j60.h"

#define inet_addr(a,b,c,d)	( ((uint32_t)a) | ((uint32_t)b << 8) | ((uint32_t)c << 16) | ((uint32_t)d << 24) )

int eth_service();
int eth_init();
int eth_open_socket();
int eth_close_socket();
int eth_read_socket();
int eth_write_socket();
int eth_set_ip(uint8_t a, uint8_t b, uint8_t c, uint8_t d);
int eth_set_gw(uint8_t a, uint8_t b, uint8_t c, uint8_t d);
int eth_set_mask(uint8_t a, uint8_t b, uint8_t c, uint8_t d);
int eth_set_mac(uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint8_t e, uint8_t f);