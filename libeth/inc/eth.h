#include <string.h>
#include "drvEnc28j60.h"

#define inet_addr(a,b,c,d)	( ((uint32_t)a) | ((uint32_t)b << 8) | ((uint32_t)c << 16) | ((uint32_t)d << 24) )

typedef struct __attribute__((__packed__)) eth_frame {
        uint8_t mac_dest[6];    // 00 11 11 22 22 33
        uint8_t mac_origen[6];  // 00 24 be 5b 41 84
        uint8_t tipo[2];        // 08 00 // protocolo IP // 08 06 ARP
} eth_frame_t;

int eth_service();
int eth_init();
int eth_open_socket();
int eth_close_socket();
int eth_write_socket(eth_frame_t *frame_ethernet, uint8_t *buffer, uint32_t cantidad );
int eth_read_socket(eth_frame_t *eth, uint8_t *datos, uint32_t *cantidad);
int eth_set_ip(uint8_t a, uint8_t b, uint8_t c, uint8_t d);
int eth_set_gw(uint8_t a, uint8_t b, uint8_t c, uint8_t d);
int eth_set_mask(uint8_t a, uint8_t b, uint8_t c, uint8_t d);
int eth_set_mac(uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint8_t e, uint8_t f);
int eth_set_puerto(uint32_t (*a)(eth_frame_t*) , uint16_t puerto);
uint16_t tcp_checksum_data(uint8_t *data_p, uint32_t size_dat);
/*
	eth_in :	estructura delpaquete leido
	buffer:		datos a enviar
	size_buffer:	tamaño en bytes de los datos a enviar
	num_frag:	número de fragmento
	cant_frag:	cantidad de fragmentos
	check_data:	checksum tcp si es el paquete cero
	size_arch:	tamaño del archivo completo sin fragmentar
*/
int eth_write_data(eth_frame_t *eth_in, uint8_t *buffer, uint16_t size_buffer, uint16_t num_frag, uint16_t cant_frag, uint32_t check_data, uint32_t size_arch);
