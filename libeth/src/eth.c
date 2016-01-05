#include <stdlib.h>
#include <string.h>
#include "eth.h"

#define TIPO_ARP		6
#define TIPO_IP			0
#define TIPO_NO_SOPORTADO	-1

#define MAX_DATOS		1500

#define inet_addr(a,b,c,d)      ( ((uint32_t)a) | ((uint32_t)b << 8) | ((uint32_t)c << 16) | ((uint32_t)d << 24) )

typedef struct __attribute__((__packed__)) eth_frame {
        uint8_t mac_dest[6];	// 00 11 11 22 22 33
        uint8_t mac_origen[6];	// 00 24 be 5b 41 84
        uint8_t tipo[2];	// 08 00 // protocolo IP // 08 06 ARP
} eth_frame_t;

typedef struct __attribute__((__packed__)) arp_frame {
        uint8_t hardware[2];	// 00 01 Ethernet
        uint8_t protocolo[2];	// 08 00 Protocolo IP
        uint8_t tam_hardware;	// 06	 6 bytes mac
        uint8_t tam_prot;	// 04	 4 bytes ip
        uint8_t operacion[2];	// 00 01 request (requerimiento IP)
        uint8_t mac_origen[6];	// 00 24 be 5b 41 84
        uint8_t ip_origen[4];	// 0a 00 00 14
        uint8_t mac_destino[6];	// 00 00 00 00 00 00
        uint8_t ip_destino[4];	// 0a 00 00 1f
} arp_frame_t;

typedef struct __attribute__((__packed__)) ip_frame {
        uint8_t ver_hlen;		// 45	4 ver 5*4=20 bytes
        uint8_t tipo_servicio;		// 00
        uint8_t longitud[2];		// 00 1f 84bytes de longitud + 14eth = 98
        uint8_t identificacion[2];	// 78 bb identif.
        uint8_t band_desplazamiento[2];	// 010 00000 reservado(0) no_frag(1) mas_frag(0) fragmento_offset(00000)
        uint8_t tiempo_vida;		// 40 tiemp de vida del paquete
        uint8_t protocolo;		// 01 ICMP
        uint8_t suma_verif[2];		// ad dd checksum
        uint8_t ip_origen[4];		// oa 00 00 14 ip origen
        uint8_t ip_dest[4];		/// 0a 00 00 1f ip destino
	//opciones
} ip_frame_t;


typedef struct __attribute__((__packed__)) icmp_frame {
	uint8_t tipo;		// 08	(08 solicitud eco) (00 respuesta eco)
	uint8_t codigo;		// 00	(00 solicitud eco) (00 respuesta eco)
	uint8_t sum_verif[2];	// 43 a2
	uint8_t ident[2];
	uint8_t sec[2];
//	datos;
} icmp_frame_t;

int eth_arp_frame(eth_frame_t *frame);		// envía un eco ARP con la MAC de la placa
int eth_ip_frame(eth_frame_t *frame);		// trata un paquete si es IP (llama a eth_icmp_frame() o a eth_tcp_frame según tipo de paquete IP)
int eth_icmp_frame(eth_frame_t *eth_in);	// envía respuesta eco ICMP si corresponde
int eth_tcp_frame(eth_frame_t *eth_in);		// trata paquetes TCP
uint16_t icmp_checksum(ip_frame_t *ip);		// Calcula el checksum ICMP
uint16_t ip_checksum(ip_frame_t *ip);		// Calcula el checksum IP
int eth_comp(uint8_t* a, uint8_t* b, int n);	// compara arrays de char, retorna 0(iguales) menor a cero(si son distintos)


uint8_t my_mac[]= {0x00,0x11,0x22,0x33,0x44,0x55};
uint8_t broadcast_mac[]= {0xff,0xff,0xff,0xff,0xff,0xff};
uint8_t my_ip[]= {10,0,0,31};
uint8_t my_mask[]= {255,255,255,0};
uint8_t my_gw[]= {10,0,0,1};


int eth_tcp_frame(eth_frame_t *eth_in){

	return(0);
}

uint16_t ip_checksum(ip_frame_t *ip){

	uint32_t acumulador, aux;
	uint32_t i;
	uint32_t max;
	uint16_t *indice;
	uint16_t ret;

	// Apunto a la cabecera IP
	indice = (uint16_t*) ip;
	// calculo el largo de la cabecera
	max = (uint32_t)ip->ver_hlen;
	max = max & 0xf;	// los 4 bits bajos son el tamaño de la cabecera en palabras de 32 bits
	max = max * 2;		// son el doble en palabras de 16 bits
	acumulador = 0;
	aux = 0;

	for(i=0 ; i < max ; i++){	// sumo invirtiendo los bytes (de little endian a big endian)
		acumulador += (indice[i] << 8) & 0xff00;
		acumulador += (indice[i] >> 8) & 0x00ff;
	}
	while (acumulador > 0xffff){	// si supera los 16 bits sumo el excedente
		aux = acumulador & 0xffff;
		acumulador = aux + ( acumulador >> 16 );
	}
	ret = (uint16_t) acumulador;
	return(~ret);	// retorno el complemento, listo
}

uint16_t icmp_checksum(ip_frame_t *ip){

	uint32_t acumulador, aux;
	uint32_t i;
	uint32_t max;
	uint16_t *indice;
	uint16_t ret;
	uint8_t aux_u8;
	uint16_t aux_u16;

	// calculo el inicio del encabezado ICMP
	aux = (uint32_t) ip;
	aux_u8 = ip->ver_hlen & 0xf;
	aux_u8 = aux_u8 * 4;
	aux = (uint32_t) aux_u8 + aux;
	// Apunto al comienzo de la cabecera ICMP
	indice = (uint16_t*) aux;

	// Calculo el largo en palabras de 16 bits
	aux_u16 = (uint16_t) ip->longitud[0];// invierto los bytes
	aux_u16 = aux_u16 << 8;
	aux_u16 += (uint16_t) ip->longitud[1];
	aux_u16 -= 20;		// le resto la cabecera IP

	max = aux_u16 / 2;
	acumulador = 0;
	aux = 0;

	for(i=0 ; i < max ; i++){	// Sumo invirtiendo los bytes(están el little endian)
		acumulador += (indice[i] << 8) & 0xff00;
		acumulador += (indice[i] >> 8) & 0x00ff;
	}
	while (acumulador > 0xffff){	// Si da mas de 0xffff el excedente se suma 
		aux = acumulador & 0xffff;
		acumulador = aux + ( acumulador >> 16 );
	}
	ret = (uint16_t) acumulador;	// retorno una palabra de 16 bits
	return(~ret);
}


int eth_icmp_frame(eth_frame_t *eth_in){
	uint32_t aux_u32;
	uint16_t aux_u16, i;
	uint8_t aux_u8;
	ip_frame_t *ip_in;
	icmp_frame_t *icmp_in;
	pbuf_t buffer_out;
	eth_frame_t *eth_out;
	ip_frame_t *ip_out;
	icmp_frame_t *icmp_out;
	uint16_t largo_de_paquete;
	uint8_t *datos_in, *datos_out;
	uint16_t max_datos;

	// a partir del frame ethernet apunto al paquete IP
	aux_u32 = (uint32_t) eth_in;
	aux_u32 += sizeof(eth_frame_t);
	ip_in = (ip_frame_t*) aux_u32;

	//Obtengo la longitud de cabecera IP
	aux_u8 = ip_in->ver_hlen;	// los 4 bits mas bajos son la longitud en palabras de 32 bits
	aux_u8 = aux_u8 & 0x0f;
	aux_u8 = aux_u8 * 4;		// lo paso a palabras de 8 bits (bytes)

	// apunto al paquete ICMP
	aux_u32 = (uint32_t) ip_in;
	aux_u32 += (uint32_t) aux_u8;
	icmp_in = (icmp_frame_t*) aux_u32;

	// verifico algunos datos
	if( 0x08 != icmp_in->tipo) return(-1); // atiendo solo solicitud de eco
	if( 0x00 != icmp_in->codigo) return(-2); // atiendo solo solicitud de eco

	// Creo el paquete de retorno
	// Dierecciono cabecera Ethernet
	eth_out = (eth_frame_t*) buffer_out.payload;

	eth_out->mac_dest[0] = eth_in->mac_origen[0];	//retorno al remitente
	eth_out->mac_dest[1] = eth_in->mac_origen[1];
	eth_out->mac_dest[2] = eth_in->mac_origen[2];
	eth_out->mac_dest[3] = eth_in->mac_origen[3];
	eth_out->mac_dest[4] = eth_in->mac_origen[4];
	eth_out->mac_dest[5] = eth_in->mac_origen[5];

	eth_out->mac_origen[0] = my_mac[0];	// me coloco como remitente
	eth_out->mac_origen[1] = my_mac[1];
	eth_out->mac_origen[2] = my_mac[2];
	eth_out->mac_origen[3] = my_mac[3];
	eth_out->mac_origen[4] = my_mac[4];
	eth_out->mac_origen[5] = my_mac[5];

	eth_out->tipo[0] = 0x08;		// paquete IP (ICMP, ETHERNET)
	eth_out->tipo[1] = 0x00;

	// Completo cabecera IP
	aux_u32 = (uint32_t) eth_out;		// apunto a la cahecera IP
	aux_u32 += sizeof(eth_frame_t);
 	ip_out = (ip_frame_t*) aux_u32;

	ip_out->ver_hlen = 0x45;			// Versión 4, cabecera con 5 palabras de 32 bits
	ip_out->tipo_servicio = 00;			// No se por que se coloca 00
	ip_out->longitud[0] = ip_in->longitud[0];	// retoro el mismo paquete con igual longitud
	ip_out->longitud[1] = ip_in->longitud[1];
	ip_out->identificacion[0] = 0x00;		// identifica como paquete único
	ip_out->identificacion[1] = ip_in->identificacion[1] + 10;
	ip_out->band_desplazamiento[0] = 0x40;	// 010(sin fragmentos) 0000000000000(sin desplazamiento)
	ip_out->band_desplazamiento[1] = 0x00;
	ip_out->tiempo_vida = 0x40;		// tiempo que viajará por la red
	ip_out->protocolo = 0x01;		// 01 ICMP, 06 tcp
	ip_out->suma_verif[0] = 0x00;		// para calcular se ponen a cero
	ip_out->suma_verif[1] = 0x00;
	ip_out->ip_origen[0] = my_ip[0];	// Yo soy el origen
	ip_out->ip_origen[1] = my_ip[1];
	ip_out->ip_origen[2] = my_ip[2];
	ip_out->ip_origen[3] = my_ip[3];
	ip_out->ip_dest[0] = ip_in->ip_origen[0]; // retorno eco al remitente
	ip_out->ip_dest[1] = ip_in->ip_origen[1];
	ip_out->ip_dest[2] = ip_in->ip_origen[2];
	ip_out->ip_dest[3] = ip_in->ip_origen[3];

	aux_u16 = ip_checksum(ip_out);		// calculo el checksum de la cabecera IP
	ip_out->suma_verif[1] = (uint8_t) aux_u16 & 0xff;
	aux_u16 = aux_u16 >> 8;
	ip_out->suma_verif[0] = (uint8_t) aux_u16 & 0xff;

	// Completo paquete ICMP
	aux_u32 = (uint32_t) ip_out;
	aux_u32 += 20;			// desplazamiento hasta el final de la cabecera IP
	icmp_out = (icmp_frame_t*) aux_u32;

	icmp_out->tipo = 0x00;		// respuesta eco
	icmp_out->codigo = 0x00;
	icmp_out->sum_verif[0] = 0x00;
	icmp_out->sum_verif[1] = 0x00;
	icmp_out->ident[0] = icmp_in->ident[0];	// retorno el mismo identificador
	icmp_out->ident[1] = icmp_in->ident[1];
	icmp_out->sec[0] = icmp_in->sec[0];	// retorno la misma secuencia
	icmp_out->sec[1] = icmp_in->sec[1];

	// calculo el largo de los datos
	aux_u16 = (uint16_t) ip_out->longitud[0];// invierto los bytes
	aux_u16 = aux_u16 << 8;
	aux_u16 += (uint16_t) ip_out->longitud[1];
	aux_u16 -= 20;		// le resto la cabecera IP
	aux_u16 -=  8;		// le resto la cabecera ICMP
	max_datos = aux_u16;

	// apunto a los datos de salida
	aux_u32 = (uint32_t) icmp_out;
	aux_u32 += sizeof(icmp_frame_t);
	datos_out = (uint8_t*) aux_u32;
	// apunto a los datos de entada
	aux_u32 = (uint32_t) icmp_in;
	aux_u32 += sizeof(icmp_frame_t);
	datos_in = (uint8_t*) aux_u32;

	for(i=0 ; i < max_datos ; i++){	//copio los datos
		datos_out[i] = datos_in[i];
	}
	largo_de_paquete = 14 /*ETH*/+ 20 /*IP*/ + 8 /*ICMP*/+ aux_u16 /*datos*/;
	aux_u16 = icmp_checksum(ip_out);
	icmp_out->sum_verif[1] = (uint8_t) aux_u16 & 0xff;
	aux_u16 = aux_u16 >> 8;
	icmp_out->sum_verif[0] = (uint8_t) aux_u16 & 0xff;

	// lo envío
	buffer_out.length = largo_de_paquete;
	drvEnc28j60_packetSend(&buffer_out);	// envío rspuerta eco

/*
	uint8_t tipo;		// 08	(08 solicitud eco) (00 respuesta eco)
	uint8_t codigo;		// 00	(00 solicitud eco) (00 respuesta eco)
	uint8_t sum_verif[2];	// 43 a2
*/

/*
        uint8_t ver_hlen;		// 45	4 ver 5*4=20 bytes
        uint8_t tipo_servicio;		// 00
        uint8_t longitud[2];		// 00 1f 84bytes de longitud + 14eth = 98
        uint8_t identificacion[2];	// 78 bb identif.
        uint8_t band_desplazamiento[2];	// 010 00000 reservado(0) no_frag(1) mas_frag(0) fragmento_offset(00000)
        uint8_t tiempo_vida;		// 40 tiemp de vida del paquete
        uint8_t protocolo;		// 01 ICMP
        uint8_t suma_verif[2];		// ad dd checksum
        uint8_t ip_origen[4];		// oa 00 00 14 ip origen
        uint8_t ip_dest[4];		/// 0a 00 00 1f ip destino
*/
	return(0);
}


int eth_ip_frame(eth_frame_t *eth_in){
	uint32_t aux_u32;
	ip_frame_t *ip_in;
	uint8_t aux_u8;

	// a partir del frame ethernet apunto al paquete IP
	aux_u32 = (uint32_t) eth_in;
	aux_u32 += sizeof(eth_frame_t);
	ip_in = (ip_frame_t*) aux_u32;

	aux_u8 = ip_in->ver_hlen;	// verifico que sea ip version 4
	aux_u8 = aux_u8 >> 4;
	aux_u8 = aux_u8 & 0x0f;
	if(aux_u8 != 4)return(-1);

	switch(ip_in->protocolo){
	case 01:			//ICMP
		eth_icmp_frame(eth_in);
		break;
	case 06:			//TCP
		eth_tcp_frame(eth_in);
		break;
	default:
		return(-2);
	}
	return(0);
/*        uint8_t ver_hlen;		// 45	4 ver 5*4=20 bytes
        uint8_t tipo_servicio;		// 00
        uint8_t longitud[2];		// 00 1f 84bytes de longitud + 14eth = 98
        uint8_t identificacion[2];	// 78 bb identif.
        uint8_t band_desplazamiento[2];	// 010 00000 reservado(0) no_frag(1) mas_frag(0) fragmento_offset(00000)
        uint8_t tiempo_vida;		// 40 tiemp de vida del paquete
        uint8_t protocolo;		// 01 ICMP
        uint8_t suma_verif[2];		// ad dd checksum
        uint8_t ip_origen[4];		// oa 00 00 14 ip origen
        uint8_t ip_dest[4];		/// 0a 00 00 1f ip destino
*/
}



int eth_arp_frame(eth_frame_t *eth_in){

	uint32_t aux;
	uint16_t largo_de_paquete;
	arp_frame_t *arp_in;
	arp_frame_t *arp_out;
	eth_frame_t *eth_out;
	pbuf_t buffer_out;

	// a partir del frame ethernet apunto al paquete ARP
	aux = (uint32_t) eth_in;
	aux += sizeof(eth_frame_t);
	arp_in = (arp_frame_t*) aux;

	// Chequeo que sea protocolo Ethernet
	if( arp_in->hardware[0] != 0x00 || arp_in->hardware[1] != 0x01) return(-1);
	// Chequeo que sea protocolo IP
	if( arp_in->protocolo[0] != 0x08 || arp_in->protocolo[1] != 0x00) return(-2);
	// Chequeo el tamaño hardware = 6 bytes
	if( arp_in->tam_hardware != 0x06 ) return(-3);
	// Chequeo el tamaño del protocolo IP = 4 (ipv4)
	if( arp_in->tam_prot != 0x04 ) return(-4);
	// Chequeo que sea la operación request (requerimiento de IP)
	if( arp_in->operacion[0] != 0x00 || arp_in->operacion[1] != 0x01) return(-5);

	// Apunto ala cabecera ethernet del paquete de salida
	eth_out = (eth_frame_t*) buffer_out.payload;

	//cargo la cabecera de ethernet de salida
	eth_out->mac_dest[0] = eth_in->mac_origen[0]; // Mac destino
	eth_out->mac_dest[1] = eth_in->mac_origen[1];
	eth_out->mac_dest[2] = eth_in->mac_origen[2];
	eth_out->mac_dest[3] = eth_in->mac_origen[3];
	eth_out->mac_dest[4] = eth_in->mac_origen[4];
	eth_out->mac_dest[5] = eth_in->mac_origen[5];

	eth_out->mac_origen[0] = my_mac[0];	//retorno mi MAC
	eth_out->mac_origen[1] = my_mac[1];
	eth_out->mac_origen[2] = my_mac[2];
	eth_out->mac_origen[3] = my_mac[3];
	eth_out->mac_origen[4] = my_mac[4];
	eth_out->mac_origen[5] = my_mac[5];

	eth_out->tipo[0] = 0x08;	// tipo ARP
	eth_out->tipo[1] = 0x06;

	// Apunto al paquete ARP
	aux = (uint32_t) eth_out;
	aux += sizeof(eth_frame_t);
	arp_out = (arp_frame_t*) aux;

	arp_out->hardware[0] = 0x00;	// Protocolo Ethernet
	arp_out->hardware[1] = 0x01;

	arp_out->protocolo[0] = 0x08;	// Protocolo IP
	arp_out->protocolo[1] = 0x00;

	arp_out->tam_hardware = 0x06;	// Tamaño de MAC en bytes

	arp_out->tam_prot = 0x04;	// Tamaño IPv4 en bytes

	arp_out->operacion[0] = 0x00;	// operación ARP eco
	arp_out->operacion[1] = 0x02;

	arp_out->mac_origen[0] = my_mac[0]; // MAC origen
	arp_out->mac_origen[1] = my_mac[1];
	arp_out->mac_origen[2] = my_mac[2];
	arp_out->mac_origen[3] = my_mac[3];
	arp_out->mac_origen[4] = my_mac[4];
	arp_out->mac_origen[5] = my_mac[5];

	arp_out->ip_origen[0] = my_ip[0];
	arp_out->ip_origen[1] = my_ip[1];
	arp_out->ip_origen[2] = my_ip[2];
	arp_out->ip_origen[3] = my_ip[3];

	arp_out->mac_destino[0] = arp_in->mac_origen[0]; // MAC destino (remitente)
	arp_out->mac_destino[1] = arp_in->mac_origen[1];
	arp_out->mac_destino[2] = arp_in->mac_origen[2];
	arp_out->mac_destino[3] = arp_in->mac_origen[3];
	arp_out->mac_destino[4] = arp_in->mac_origen[4];
	arp_out->mac_destino[5] = arp_in->mac_origen[5];

	arp_out->ip_destino[0] = arp_in->ip_origen[0];	// IP destino
	arp_out->ip_destino[1] = arp_in->ip_origen[1];
	arp_out->ip_destino[2] = arp_in->ip_origen[2];
	arp_out->ip_destino[3] = arp_in->ip_origen[3];

	largo_de_paquete = sizeof(eth_frame_t) + sizeof(arp_frame_t);
	buffer_out.length = largo_de_paquete;
	drvEnc28j60_packetSend(&buffer_out);	// envío rspuerta eco

	return(0);
}


int eth_tipo_frame(eth_frame_t *frame){
	if( frame->tipo[0] == 0x08 && frame->tipo[1] == 0x06) return(TIPO_ARP);
	if( frame->tipo[0] == 0x08 && frame->tipo[1] == 0x00) return(TIPO_IP);
	return(TIPO_NO_SOPORTADO);
}

int eth_comp(uint8_t* a, uint8_t* b, int n){
	int i;
	for(i=0; i < n ; i++){
		if( 0 != a[i] - b[i] )return (-1);
	}
	return(0);
}

int eth_service(){
	err_t ret;
	pbuf_t buffer_in;
	eth_frame_t *eth_frame_p;
	int tipo;

	/******************************************************
		drvEnc28j60_packetRec()
	Retorna :
		ERR_VAL no hay paquete
		ERR_IF  hay paquete pero con error
		ERR_OK  hay paquete sin errores
	******************************************************/
	ret = drvEnc28j60_packetRecv(&buffer_in);
	if(ret != ERR_OK ) return(ret);

	eth_frame_p = (eth_frame_t*) buffer_in.payload; // Apunto al frame ethernet

	/* Atiendo las llamadas Broadcast y a mi MAC */
	if( 0 == eth_comp(broadcast_mac, eth_frame_p->mac_dest, 6 ) ||  0 == eth_comp(my_mac, eth_frame_p->mac_dest, 6 ) ){
		tipo= eth_tipo_frame(eth_frame_p);
		switch (tipo){
		case TIPO_ARP:	// Manejo el servicio ARP
			eth_arp_frame(eth_frame_p);
			break;
		case TIPO_IP:	// Manejo el servicio IP (ICMP , TCP)
			eth_ip_frame(eth_frame_p);
			break;
		default:
			return(ERR_OK);
		}
	}

	return(ERR_OK);
}


int eth_set_mac(uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint8_t e, uint8_t f){

	my_mac[0] = a;
	my_mac[1] = b;
	my_mac[2] = c;
	my_mac[3] = d;
	my_mac[4] = e;
	my_mac[5] = f;

	return(0);
}

int eth_set_ip(uint8_t a, uint8_t b, uint8_t c, uint8_t d){

	my_ip[0] = a;
	my_ip[1] = b;
	my_ip[2] = c;
	my_ip[3] = d;

	return(0);
}

int eth_set_gw(uint8_t a, uint8_t b, uint8_t c, uint8_t d){

	my_gw[0] = a;
	my_gw[1] = b;
	my_gw[2] = c;
	my_gw[3] = d;

	return(0);
}

int eth_set_mask(uint8_t a, uint8_t b, uint8_t c, uint8_t d){

	my_mask[0] = a;
	my_mask[1] = b;
	my_mask[2] = c;
	my_mask[3] = d;

	return(0);
}

int eth_init(){

	drvEnc28j60_init(my_mac);

	return(0);
}

int eth_open_socket(){

	return(0);
}

int eth_close_socket(){

	return(0);
}

int eth_read_socket(){

	return(0);
}

int eth_write_socket(){

	return(0);
}
