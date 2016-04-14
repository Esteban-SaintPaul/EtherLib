#include <stdlib.h>
#include <string.h>
#include "eth.h"

#define TIPO_ARP		6
#define TIPO_IP			0
#define TIPO_NO_SOPORTADO	-1
#define TIPO_ICMP		0x01
#define TIPO_TCP		0x06

// máximo tamaño de datos por paquete
#define MAX_DATOS		1500
#define MAX_PUERTOS		1024

// Valores de flags atendidos en TCP
#define	ETH_FIN		0x01
#define ETH_SYN		0x02
#define ETH_RST		0x04
#define ETH_PUSH	0x08
#define ETH_ACK		0x10
#define ETH_URG		0x20
#define ETH_ENC		0x40
#define ETH_CWR		0x80


/*
  Se pasa a definir en el archivo cabecera eth.h, esto es necesario para
poder usarlo en la definición de "eth_write_socket(eth_frame_t* eth_in)"

typedef struct __attribute__((__packed__)) eth_frame {
        uint8_t mac_dest[6];	// 00 11 11 22 22 33
        uint8_t mac_origen[6];	// 00 24 be 5b 41 84
        uint8_t tipo[2];	// 08 00 // protocolo IP // 08 06 ARP
} eth_frame_t;
*/

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

typedef struct __attribute__((__packed__)) tcp_frame {
	uint8_t puerto_origen[2];	// 89 43 cualquier puerto
	uint8_t puerto_dest[2];		// 00 50 puerto 80 decimal
	uint8_t secuencia[4];		// 84 a9 7e 8a número de inicio de secuencia
	uint8_t acknew[4];		// 00 00 00 00 número de asentimiento (bytes aceptados)
	uint8_t tam_RES_NONCE;		// a0 a(tamaño de cabecera en palabras de 32 bits), 000 (RES siempre cero), 0(NONCE)
	uint8_t flag;			// 00 tam 00 00 02 , 0(CWR), 0(ECN), 0(URG), 0(ACK), 0(PUSH), 0(RES), 1(SYC), 0(FIN)
	uint8_t ventana[2];		// 72 10
	uint8_t checksum[2];		// 14 61 suma de verificación
	uint8_t punt_urg[2];		// 00 00 puntero urgente
//	opciones (10*4) - 20 = 20 bytes de opciones, 0 datos
} tcp_frame_t;

int eth_arp_frame(eth_frame_t *frame);		// envía un eco ARP con la MAC de la placa
int eth_ip_frame(eth_frame_t *frame);		// trata un paquete si es IP (llama a eth_icmp_frame() o a eth_tcp_frame según tipo de paquete IP)
int eth_icmp_frame(eth_frame_t *eth_in);	// envía respuesta eco ICMP si corresponde
int eth_tcp_frame(eth_frame_t *eth_in);		// trata paquetes TCP
uint16_t icmp_checksum(ip_frame_t *ip);		// Calcula el checksum ICMP
uint16_t ip_checksum(ip_frame_t *ip);		// Calcula el checksum IP
uint16_t tcp_checksum(ip_frame_t *ip);		// calcula el checksum TCP
int eth_comp(uint8_t* a, uint8_t* b, int n);	// compara arrays de char, retorna 0(iguales) menor a cero(si son distintos)
int eth_retorno_paquete(eth_frame_t *eth_in, uint8_t tipo, uint8_t *datos, uint16_t cantidad); //crea y envía paquetes (tipo ETH_SYN-ETH_ACK)
uint32_t u8_a_u32( uint8_t a,uint8_t b, uint8_t c, uint8_t d ); // convierte de 4 char a 1 palabra de 32 bits
int eth_read_paquete(eth_frame_t *eth, uint8_t *datos, uint16_t *cantidad);

//uint16_t tcp_checksum_data(uint8_t *data_p, uint32_t size_dat);	// calcula checksum de datos (tcp)
uint16_t tcp_checksum_header(ip_frame_t *ip, uint16_t size_dat); //calcula el chacksum de las cabeceras TCP

uint8_t my_mac[]= {0x00,0x11,0x22,0x33,0x44,0x55};
uint8_t broadcast_mac[]= {0xff,0xff,0xff,0xff,0xff,0xff};
uint8_t my_ip[]= {10,0,0,31};
uint8_t my_mask[]= {255,255,255,0};
uint8_t my_gw[]= {10,0,0,1};

uint32_t (*eth_puerto[MAX_PUERTOS])(eth_frame_t *eth_in);	//listado de punteros a servicios por puerto

uint32_t eth_tcp_estado[MAX_PUERTOS];	// estado de la conexión tcp
#define ETH_ESPERANDO_SYN	1
#define ETH_ESPERANDO_ACK	2
#define ETH_CONECTADO		3

//#define ETH_SIZE_FRAG	1024
#define ETH_SIZE_FRAG	80	// siempre en múltiplos de 8, tamaño del fragmento
uint16_t eth_identificacion = 3;	// identifica cada paquete o grupo de fregmentos

int eth_retorno_fragmento(eth_frame_t *eth_in, uint8_t *buffer, uint16_t size_arch, uint16_t frag, uint16_t cant_frag);


int eth_write_data(eth_frame_t *eth_in, uint8_t *buffer, uint16_t size_buffer, uint16_t num_frag, uint16_t cant_frag, uint32_t check_data, uint32_t size_arch){
	uint32_t aux_u32;
	uint32_t checksum;
	uint16_t aux_u16;
	uint16_t i;
	uint8_t aux_u8;
	uint32_t secuencia;
	uint8_t tipo;
	uint8_t *datos_p;
	uint32_t datos_c;

	ip_frame_t *ip_in;
	tcp_frame_t *tcp_in;
	pbuf_t buffer_out;

	eth_frame_t *eth_out;
	ip_frame_t *ip_out;
	tcp_frame_t *tcp_out;

	uint16_t largo_de_paquete;
	uint8_t *datos_out;
	uint16_t size_datos_in;

	// fijo el tipo de paquete
	tipo = ( ETH_PUSH | ETH_ACK );

	// a partir del frame ethernet apunto al paquete IP
	aux_u32 = (uint32_t) eth_in;
	aux_u32 += sizeof(eth_frame_t);
	ip_in = (ip_frame_t*) aux_u32;

	//Obtengo la longitud de cabecera IP
	aux_u8 = ip_in->ver_hlen;	// los 4 bits mas bajos son la longitud en palabras de 32 bits
	aux_u8 = aux_u8 & 0x0f;
	aux_u8 = aux_u8 * 4;		// lo paso a palabras de 8 bits (bytes)

	// apunto al paquete TCP
	aux_u32 = (uint32_t) ip_in;
	aux_u32 += (uint32_t) aux_u8;
	tcp_in = (tcp_frame_t*) aux_u32;

	// calculo el largo de los datos de entrada
	aux_u16 = (uint16_t) ip_in->longitud[0];// invierto los bytes
	aux_u16 = aux_u16 << 8;
	aux_u16 += (uint16_t) ip_in->longitud[1];
	aux_u16 -= (uint16_t) aux_u8;		// le resto la cabecera IP
	aux_u8 = tcp_in->tam_RES_NONCE >> 4;	//tomo los 4 bits mas altos, son el tamaño de la cabecera tcp
	aux_u8 *= 4;				// lo paso a palabras de 8 bits
	aux_u16 -= (uint16_t) aux_u8;		// le resto la cabecera TCP
	size_datos_in = aux_u16;

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

if(num_frag != 0){
ip_out->ver_hlen = 0x45;			// Versión 4, cabecera con 6 palabras de 32 bits (20 bytes)
} else{
ip_out->ver_hlen = 0x45;			// Versión 4, cabecera con 6 palabras de 32 bits (20 bytes)
}


	ip_out->tipo_servicio = 00;			// No se por que se coloca 00

	aux_u16 = 20;		//largo de la cabecera IP
//aux_u16 = 24;		//largo de la cabecera IP
	if(num_frag != 0 ){ // si no es el 0 no llevan cabecera TCP
		aux_u16 += size_buffer;	// tamaño de datos + cabecera IP
	} else {
		aux_u16 += 24; // tamaño del paquete 0, IP + TCP sin datos
	}
	ip_out->longitud[1] = (uint8_t) ( aux_u16 & 0x00FF );
	aux_u16 >>= 8;
	ip_out->longitud[0] = (uint8_t) ( aux_u16 & 0x00FF );

	aux_u16 = eth_identificacion;
	ip_out->identificacion[1] = (uint8_t) ( aux_u16 & 0x00FF );		// identifica como paquete único
	aux_u16 >>= 8;
	ip_out->identificacion[0] = (uint8_t) ( aux_u16 & 0x00FF );		// identifica como paquete único

	if( num_frag != (cant_frag - 1) ){ //no es el último, es fragmentado
		aux_u16 = 0x2000; 	// 001----- -------- flag de fragmentado
	} else { //es el último fragmento
//		aux_u16 = 0x4000; 	// 010----- -------- flag de fragmentado
		aux_u16 = 0x0000; 	// 000----- -------- flag de fragmentado
	}
	if( num_frag != 0 ){
		aux_u16 += (24 / 8) + ((512 * (num_frag -1)) / 8);
//		aux_u16 += (20 / 8) + ((512 * (num_frag -1)) / 8);
	}
	ip_out->band_desplazamiento[0] = (uint8_t) (( aux_u16 >> 8 ) & 0x00ff);
	ip_out->band_desplazamiento[1] = (uint8_t) ( aux_u16 & 0x00ff );

	ip_out->tiempo_vida = 0x40;		// tiempo que viajará por la red
	ip_out->protocolo = 0x06;		// 01 ICMP, 06 tcp
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

if(num_frag == 0){
	// Completo paquete tcp
	aux_u32 = (uint32_t) ip_out;
//aux_u32 += 24;			// desplazamiento hasta el final de la cabecera IP
	aux_u32 += 20;			// desplazamiento hasta el final de la cabecera IP
	tcp_out = (tcp_frame_t*) aux_u32;
	tcp_out->puerto_origen[0] = tcp_in->puerto_dest[0];	//puerto origen
	tcp_out->puerto_origen[1] = tcp_in->puerto_dest[1];
	tcp_out->puerto_dest[0] = tcp_in->puerto_origen[0];	//puerto destino
	tcp_out->puerto_dest[1] = tcp_in->puerto_origen[1];	//puerto destino
	aux_u32 = u8_a_u32(tcp_in->secuencia[0], tcp_in->secuencia[1], tcp_in->secuencia[2], tcp_in->secuencia[3] ); // Cambio el número de 4 byites a palabra de 32

	aux_u32 = u8_a_u32(tcp_in->secuencia[0], tcp_in->secuencia[1], tcp_in->secuencia[2], tcp_in->secuencia[3] ); // Cambio el número de 4 byites a palabra de 32
	aux_u32 += size_datos_in;	// valido que recibí los datos enviados
	secuencia = u8_a_u32(tcp_in->acknew[0], tcp_in->acknew[1], tcp_in->acknew[2], tcp_in->acknew[3]);

	tcp_out->acknew[3] = aux_u32 & 0x000000ff;	// invierto el número y lo asigno de a 8 bits
	tcp_out->acknew[2] = (aux_u32 >> 8) & 0x000000ff;
	tcp_out->acknew[1] = (aux_u32 >> 16) & 0x000000ff;
	tcp_out->acknew[0] = (aux_u32 >> 24) & 0x000000ff;
	tcp_out->secuencia[3] = secuencia & 0x000000ff;	// invierto el número y lo asigno de a 8 bits
	tcp_out->secuencia[2] = (secuencia >> 8) & 0x000000ff;
	tcp_out->secuencia[1] = (secuencia >> 16) & 0x000000ff;
	tcp_out->secuencia[0] = (secuencia >> 24) & 0x000000ff;
	tcp_out->tam_RES_NONCE = 0x60;	// 5 bytes
	tcp_out->flag = tipo ;	// Tipo de paquete (flag syn, ack etc.)
	tcp_out->ventana[1] = 0x72;	// un valor fijo, por ahora
	tcp_out->ventana[0] = 0x10;
	tcp_out->checksum[0] = 0x00;
	tcp_out->checksum[1] = 0x00;
	tcp_out->punt_urg[0] = 0x00;	// no usa puntero urgente
	tcp_out->punt_urg[1] = 0x00;

	// Me paro al comienzo de los datos
	aux_u32 = (uint32_t) tcp_out;
	aux_u32 += 24;
	datos_out = (uint8_t*) aux_u32;

} else {
	aux_u32 = (uint32_t) ip_out;	// los siguientes fragmentos no tienen encabezado TCP
	aux_u32 += sizeof(ip_frame_t);
	datos_out = (uint8_t*) aux_u32;
}


	if(num_frag !=0){
		datos_p =  buffer; // me paro en el buffer
	}

	if( num_frag == 0 ){	// si es el primero, tiene cabecera TCP por lo que envío 20 bytes menos de datos
		datos_c = 24;	// Solo tiene la cabecera TCP
	} else {
		datos_c = size_buffer;// solo iene datos
	}

	if(num_frag != 0){
		for( i=0 ; i < datos_c ; i++){	//copio los datos
				datos_out[i] = datos_p[i];
		}
	}
	// calculo el largo del paquete Ethernet
	largo_de_paquete = 0;
	if(num_frag == 0){	// Solo el primer paquete tiene el encabezado TCP
		largo_de_paquete = 24;/*TCP*/
	} else {
		largo_de_paquete += datos_c;	// Agregamos los datos
	}

	largo_de_paquete += 14 /*ETH*/+ 20 /*IP*/;// los demás encabezados
//largo_de_paquete += 14 /*ETH*/+ 24 /*IP*/;// los demás encabezados

//-----------------------------------------------------------------------
// Hay que solucionar el problema del checksum
	if(num_frag == 0){
		//aux_u16 = tcp_checksum(ip_out);
		checksum = tcp_checksum_header(ip_out, size_arch) + check_data;
		while(checksum > 0x0000ffff){
			aux_u32 = checksum >> 16;
			checksum &= 0x0000ffff;
			checksum += aux_u32;
		}
		checksum = ~checksum;	//invierto los bits
		checksum &= 0x0000ffff;	//lo limito a 16 bits
		tcp_out->checksum[1] = (uint8_t) checksum & 0xff;
		checksum = checksum >> 8;
		tcp_out->checksum[0] = (uint8_t) checksum & 0xff;
	}

//-----------------------------------------------------------------------
	// lo envío
	buffer_out.length = largo_de_paquete;
	drvEnc28j60_packetSend(&buffer_out);	// envío respuesta

	return(0);
}



uint16_t tcp_checksum_data(uint8_t *data_p, uint32_t size_dat){
	// *data_p  : Apuntador a los datos
	// size_dat : Tamaño de los datos en palabras de 8 bits
	uint32_t aux_u32;	// variable auxiliar
	uint32_t i;		// contador
	uint32_t acu;		// acumulador

	for( i = 0, acu = 0; i < size_dat  ; i++ ){	// recorro todos los datos
		acu += (uint32_t) data_p[i] << 8;	// coloco dato en parte alta
		i++;					// apunto al siguiente dato
		if(i < size_dat){
			acu += (uint32_t) data_p[i];	// coloco dato en parte baja
		} else { i--; }
		while(acu > 0x0000ffff ){		// es mayor a 16 bits
			aux_u32 = acu >> 16;		// tomo el excedente
			acu &= 0x0000ffff;		// borro el excedente del acumulado
			acu += aux_u32;			// sumo el excedente al acumulado
		}
	}
	acu &= 0x0000ffff;				//
	return( (uint16_t) acu );			// retorno acumulado acotado a 16 bits
}

uint16_t tcp_checksum_header(ip_frame_t *ip, uint16_t size_dat){
	uint32_t aux_u32;
	uint32_t i;
	uint32_t acu;		// acumulador
	uint16_t size_hip;	// tamaño de cabecera ip
	uint16_t size_ip;	// tamaño del frame ip (ip = hip + htcp + dat)
	uint16_t size_htcp;	// tamaño de cabecera tcp
//	uint16_t size_dat;	// tamaño de datos
	tcp_frame_t *tcp;
	uint8_t *puntero;

	//Obtengo la longitud de cabecera IP
	size_hip = (uint16_t) ip->ver_hlen;	// los 4 bits mas bajos son la longitud en palabras de 32 bits
	size_hip &= 0x000f;
	size_hip *= 4;		// lo paso a palabras de 8 bits (bytes)

	// apunto al paquete TCP
	aux_u32 = (uint32_t) ip;		// me paro el el comienzo del frame ip
	aux_u32 += (uint32_t) size_hip;		// me corro hasta finalizar la cabecera ip
	tcp = (tcp_frame_t*) aux_u32;	// guardo esto como el inicio de la cabecera tcp
	puntero = (uint8_t*) aux_u32;	// tambien me guardo un puntero al inicio de la cabecera tcp

	// obtengo tamaño de cabecera tcp
	size_htcp = (uint16_t) tcp->tam_RES_NONCE >> 4;
	size_htcp *= 4;

	// obtengo el largo del frame ip
	size_ip = (uint16_t) ip->longitud[0];// invierto los bytes
	size_ip <<= 8;
	size_ip += (uint16_t) ip->longitud[1];

	// calculo la cantidad de datos
//	size_dat = size_ip - size_hip - size_htcp;

	//----------------------------------------------------
	// Seudo cabecera TCP
	acu = (uint32_t) ip->ip_origen[0] << 8;
	acu += (uint32_t) ip->ip_origen[1];
	acu += (uint32_t) ip->ip_origen[2] << 8;
	acu += (uint32_t) ip->ip_origen[3];

	acu += (uint32_t) ip->ip_dest[0] << 8;
	acu += (uint32_t) ip->ip_dest[1];
	acu += (uint32_t) ip->ip_dest[2] << 8;
	acu += (uint32_t) ip->ip_dest[3];

	acu += (uint32_t) ip->protocolo;	//TCP 0x06, UDP 0x11

	acu += (uint32_t) size_htcp + size_dat;
	//----------------------------------------------------
	// suma la cabecera
	for( i = 0; i < size_htcp  ; i++ ){
		acu += (uint32_t) puntero[i] << 8;
		i++;
		if(i < size_htcp){
			acu += (uint32_t) puntero[i];
		} else { i--; }
		while(acu > 0x0000ffff ){
			aux_u32 = acu >> 16;
			acu &= 0x0000ffff;
			acu += aux_u32;
		}
	}
	acu &= 0x0000ffff;
	return( (uint16_t) acu );
}




int eth_write_socket(eth_frame_t *eth, uint8_t *datos, uint32_t cantidad){

	uint16_t aux_u16;
	uint16_t num_frag;
	uint16_t cant_frag;

	aux_u16 = (uint16_t) cantidad;

	if( cantidad < ETH_SIZE_FRAG ){	// no maneja fragmentación 
		eth_retorno_paquete(eth, ( ETH_PUSH | ETH_ACK ), datos, aux_u16 );//retorno syn-ack
	} else {
		// ejemplo de como retornarlo fragmentado
		eth_identificacion++;

		cant_frag = (uint16_t) cantidad / ETH_SIZE_FRAG;
		if( 0 != (cant_frag % ETH_SIZE_FRAG ) )cant_frag++;

		for(num_frag=0; num_frag < cant_frag; num_frag++){
			eth_retorno_fragmento(eth , datos, aux_u16, num_frag, cant_frag); // retorna un fragmento ip
		}

//		eth_retorno_fragmento(eth , datos, aux_u16, 1, 2); // retorna un fragmento ip
	}
	return(0);
}


int eth_retorno_fragmento(eth_frame_t *eth_in, uint8_t *buffer, uint16_t size_arch, uint16_t frag, uint16_t cant_frag){
	uint32_t aux_u32;
	uint32_t checksum;
	uint16_t aux_u16;
	uint16_t i;
	uint8_t aux_u8;
	uint32_t secuencia;
	uint8_t tipo;
	uint8_t *datos_p;
	uint32_t datos_c;

	ip_frame_t *ip_in;
	tcp_frame_t *tcp_in;
	pbuf_t buffer_out;

	eth_frame_t *eth_out;
	ip_frame_t *ip_out;
	tcp_frame_t *tcp_out;

	uint16_t largo_de_paquete;
//	uint8_t *datos_in
	uint8_t *datos_out;
//	uint16_t max_datos;
	uint16_t size_datos_in;

	// fijo el tipo de paquete
	tipo = ( ETH_PUSH | ETH_ACK );

	// a partir del frame ethernet apunto al paquete IP
	aux_u32 = (uint32_t) eth_in;
	aux_u32 += sizeof(eth_frame_t);
	ip_in = (ip_frame_t*) aux_u32;

	//Obtengo la longitud de cabecera IP
	aux_u8 = ip_in->ver_hlen;	// los 4 bits mas bajos son la longitud en palabras de 32 bits
	aux_u8 = aux_u8 & 0x0f;
	aux_u8 = aux_u8 * 4;		// lo paso a palabras de 8 bits (bytes)

	// apunto al paquete TCP
	aux_u32 = (uint32_t) ip_in;
	aux_u32 += (uint32_t) aux_u8;
	tcp_in = (tcp_frame_t*) aux_u32;

	// calculo el largo de los datos de entrada
	aux_u16 = (uint16_t) ip_in->longitud[0];// invierto los bytes
	aux_u16 = aux_u16 << 8;
	aux_u16 += (uint16_t) ip_in->longitud[1];
	aux_u16 -= (uint16_t) aux_u8;		// le resto la cabecera IP
	aux_u8 = tcp_in->tam_RES_NONCE >> 4;	//tomo los 4 bits mas altos, son el tamaño de la cabecera tcp
	aux_u8 *= 4;				// lo paso a palabras de 8 bits
	aux_u16 -= (uint16_t) aux_u8;		// le resto la cabecera TCP
	size_datos_in = aux_u16;

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

	ip_out->ver_hlen = 0x45;			// Versión 4, cabecera con 5 palabras de 32 bits (20 bytes)
	ip_out->tipo_servicio = 00;			// No se por que se coloca 00
/*
	if(frag == 0){ aux_u16 = 40;}		//largo de la cabecera ip + cabecera tcp
	else {aux_u16 = 20;}		//solo la ip para el resto de los fregmentos
*/
	aux_u16 = 20;		//largo de la cabecera IP
	if(frag != ( cant_frag -1 ) ){
		aux_u16 += ETH_SIZE_FRAG;	// si no es el último fragmento manda 1024
	} else {
		aux_u16 += 20 + size_arch - ( ETH_SIZE_FRAG * frag ); // el tamaño total menos todos los fragmentos enviados
	}
	ip_out->longitud[1] = (uint8_t) ( aux_u16 & 0x00FF );
	aux_u16 >>= 8;
	ip_out->longitud[0] = (uint8_t) ( aux_u16 & 0x00FF );

	aux_u16 = eth_identificacion;
	ip_out->identificacion[1] = (uint8_t) ( aux_u16 & 0x00FF );		// identifica como paquete único
	aux_u16 >>= 8;
	ip_out->identificacion[0] = (uint8_t) ( aux_u16 & 0x00FF );		// identifica como paquete único

	if( frag != (cant_frag - 1) ){ //no es el último, es fragmentado
		aux_u16 = 0x2000; 	// 001----- -------- flag de fragmentado
	} else { //es el último fragmento
//		aux_u16 = 0x4000; 	// 010----- -------- flag de fragmentado
		aux_u16 = 0x0000; 	// 000----- -------- flag de fragmentado
	}
	aux_u16 = aux_u16 + ( ((ETH_SIZE_FRAG * frag) )/ 8 );	// ---xxxxx xxxxxxxx número de fragmento (en palabras de 64 bits)

	ip_out->band_desplazamiento[0] = (uint8_t) (( aux_u16 >> 8 ) & 0x00ff);
	ip_out->band_desplazamiento[1] = (uint8_t) ( aux_u16 & 0x00ff );

	ip_out->tiempo_vida = 0x40;		// tiempo que viajará por la red
	ip_out->protocolo = 0x06;		// 01 ICMP, 06 tcp
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

if(frag == 0){
	// Completo paquete tcp
	aux_u32 = (uint32_t) ip_out;
	aux_u32 += 20;			// desplazamiento hasta el final de la cabecera IP
	tcp_out = (tcp_frame_t*) aux_u32;
	tcp_out->puerto_origen[0] = tcp_in->puerto_dest[0];	//puerto origen
	tcp_out->puerto_origen[1] = tcp_in->puerto_dest[1];
	tcp_out->puerto_dest[0] = tcp_in->puerto_origen[0];	//puerto destino
	tcp_out->puerto_dest[1] = tcp_in->puerto_origen[1];	//puerto destino
	aux_u32 = u8_a_u32(tcp_in->secuencia[0], tcp_in->secuencia[1], tcp_in->secuencia[2], tcp_in->secuencia[3] ); // Cambio el número de 4 byites a palabra de 32

	aux_u32 = u8_a_u32(tcp_in->secuencia[0], tcp_in->secuencia[1], tcp_in->secuencia[2], tcp_in->secuencia[3] ); // Cambio el número de 4 byites a palabra de 32
	aux_u32 += size_datos_in;	// valido que recibí los datos enviados
	secuencia = u8_a_u32(tcp_in->acknew[0], tcp_in->acknew[1], tcp_in->acknew[2], tcp_in->acknew[3]);

	tcp_out->acknew[3] = aux_u32 & 0x000000ff;	// invierto el número y lo asigno de a 8 bits
	tcp_out->acknew[2] = (aux_u32 >> 8) & 0x000000ff;
	tcp_out->acknew[1] = (aux_u32 >> 16) & 0x000000ff;
	tcp_out->acknew[0] = (aux_u32 >> 24) & 0x000000ff;
	tcp_out->secuencia[3] = secuencia & 0x000000ff;	// invierto el número y lo asigno de a 8 bits
	tcp_out->secuencia[2] = (secuencia >> 8) & 0x000000ff;
	tcp_out->secuencia[1] = (secuencia >> 16) & 0x000000ff;
	tcp_out->secuencia[0] = (secuencia >> 24) & 0x000000ff;
	tcp_out->tam_RES_NONCE = 0x50;	// 5 bytes
	tcp_out->flag = tipo ;	// Tipo de paquete (flag syn, ack etc.)
	tcp_out->ventana[1] = 0x72;	// un valor fijo, por ahora
	tcp_out->ventana[0] = 0x10;
	tcp_out->checksum[0] = 0x00;
	tcp_out->checksum[1] = 0x00;
	tcp_out->punt_urg[0] = 0x00;	// no usa puntero urgente
	tcp_out->punt_urg[1] = 0x00;

	// Me paro al comienzo de los datos
	aux_u32 = (uint32_t) tcp_out;
	aux_u32 += sizeof(tcp_frame_t);
	datos_out = (uint8_t*) aux_u32;

} else {
	aux_u32 = (uint32_t) ip_out;	// los siguientes fragmentos no tienen encabezado TCP
	aux_u32 += sizeof(ip_frame_t);
	datos_out = (uint8_t*) aux_u32;
}


	aux_u32 = (uint32_t) buffer;	// Me paro en el buffer
	aux_u32 += (uint32_t) ( frag * ETH_SIZE_FRAG ); // me corro hasta los datos a enviar
	if(frag != 0) aux_u32 -= 20;	// corro el tamaño de la cabecera TCP 
	datos_p = (uint8_t*) aux_u32;	// Lo asigno a un puntero

	if( frag != ( cant_frag -1 ) ){	// Si no es el último fragmento envío 1024 bytes
		if( frag == 0 ){	// si es el primero, tiene cabecera TCP por lo que envío 20 bytes menos de datos
			datos_c = ETH_SIZE_FRAG - 20;
		} else {
			datos_c = ETH_SIZE_FRAG;
		}
	} else {			// Si es el último sumo la cabecera TCP + datos y le resto todos los fragmentos enviados
		datos_c = (uint32_t) ( 20 + size_arch - ( frag * ETH_SIZE_FRAG) );
	}

	for( i=0 ; i < datos_c ; i++){	//copio los datos
			datos_out[i] = datos_p[i];
	}

	// calculo el largo del paquete Ethernet
	largo_de_paquete = 0;
	if(frag == 0){	// Solo el primer paquete tiene el encabezado TCP
		largo_de_paquete = sizeof(tcp_frame_t);/*TCP*/
	}
	largo_de_paquete += datos_c;	// Agregamos los datos

	largo_de_paquete += 14 /*ETH*/+ 20 /*IP*/;// los demás encabezados

//-----------------------------------------------------------------------
// Hay que solucionar el problema del checksum
	if(frag == 0){
		//aux_u16 = tcp_checksum(ip_out);
		checksum = tcp_checksum_header(ip_out, size_arch) + tcp_checksum_data(buffer, size_arch);
		while(checksum > 0x0000ffff){
			aux_u32 = checksum >> 16;
			checksum &= 0x0000ffff;
			checksum += aux_u32;
		}
		checksum = ~checksum;	//invierto los bits
		checksum &= 0x0000ffff;	//lo limito a 16 bits
		tcp_out->checksum[1] = (uint8_t) checksum & 0xff;
		checksum = checksum >> 8;
		tcp_out->checksum[0] = (uint8_t) checksum & 0xff;
	}

//-----------------------------------------------------------------------
	// lo envío
	buffer_out.length = largo_de_paquete;
	drvEnc28j60_packetSend(&buffer_out);	// envío respuesta

	return(0);
}


int eth_read_socket(eth_frame_t *eth, uint8_t *datos, uint32_t *cantidad){
	uint16_t cant;

	eth_read_paquete(eth, datos, &cant);

	*cantidad = (uint32_t) cant;
	return(0);
}

int eth_read_paquete(eth_frame_t *eth_in, uint8_t *datos, uint16_t *cantidad){

	uint32_t size_heth;	//Tamaño cabecera ETHETNET
	uint32_t size_hip;	//Tamaño cabecera IP
	uint32_t size_htcp;	//Tamaño cabecera TCP
	uint32_t size_datos_in;	//Tamaño de array de datos

	ip_frame_t *ip_in;	//Puntero a cabecera IP
	tcp_frame_t *tcp_in;	//Puntero a cabecera TCP
	uint8_t *dat_in;	//Puntero a datos de entrada

	uint32_t aux_u32;	// Variable auxiliar

	// Tamaño cabecera ETHERNET
	size_heth = sizeof(eth_frame_t);

	// a partir del frame ethernet apunto al paquete IP
	aux_u32 = (uint32_t) eth_in;
	aux_u32 += size_heth;
	ip_in = (ip_frame_t*) aux_u32;

	//Obtengo la longitud de cabecera IP
	size_hip = (uint32_t) ip_in->ver_hlen;	// los 4 bits mas bajos son la longitud en palabras de 32 bits
	size_hip &= 0x0000000f;
	size_hip *= 4;		// lo paso a palabras de 8 bits (bytes)

	// apunto al paquete TCP
	aux_u32 = (uint32_t) ip_in;
	aux_u32 += size_hip;
	tcp_in = (tcp_frame_t*) aux_u32;

	// calculo tamaño cabecera TCP
	size_htcp = (uint32_t) tcp_in->tam_RES_NONCE >> 4;	//tomo los 4 bits mas altos, son el tamaño de la cabecera tcp
	size_htcp *= 4;				// lo paso a palabras de 8 bits

	// calculo el largo de los datos de entrada
	size_datos_in = (uint32_t) ip_in->longitud[0];// invierto los bytes
	size_datos_in = size_datos_in << 8;
	size_datos_in += (uint32_t) ip_in->longitud[1];
	size_datos_in -= size_hip;		//resto largo de cabecera IP
	size_datos_in -= size_htcp;		//resto largo de cabecera TCP

	// Apunto a datos de entrada
	aux_u32 = (uint32_t) tcp_in;
	aux_u32 += size_htcp;
	dat_in = (uint8_t*) aux_u32;

	for(aux_u32=0; aux_u32 < size_datos_in; aux_u32++){
		datos[aux_u32] = dat_in[aux_u32];
	}

	*cantidad = (uint16_t) size_datos_in;

	return(0);
}


uint16_t tcp_checksum(ip_frame_t *ip){
	uint32_t aux_u32;
	uint32_t i;
	uint32_t acu;		// acumulador
	uint16_t size_hip;	// tamaño de cabecera ip
	uint16_t size_ip;	// tamaño del frame ip (ip = hip + htcp + dat)
	uint16_t size_htcp;	// tamaño de cabecera tcp
	uint16_t size_dat;	// tamaño de datos
	tcp_frame_t *tcp;
	uint8_t *puntero;

	//Obtengo la longitud de cabecera IP
	size_hip = (uint16_t) ip->ver_hlen;	// los 4 bits mas bajos son la longitud en palabras de 32 bits
	size_hip &= 0x000f;
	size_hip *= 4;		// lo paso a palabras de 8 bits (bytes)

	// apunto al paquete TCP
	aux_u32 = (uint32_t) ip;		// me paro el el comienzo del frame ip
	aux_u32 += (uint32_t) size_hip;		// me corro hasta finalizar la cabecera ip
	tcp = (tcp_frame_t*) aux_u32;	// guardo esto como el inicio de la cabecera tcp
	puntero = (uint8_t*) aux_u32;	// tambien me guardo un puntero al inicio de la cabecera tcp

	// obtengo tamaño de cabecera tcp
	size_htcp = (uint16_t) tcp->tam_RES_NONCE >> 4;
	size_htcp *= 4;

	// obtengo el largo del frame ip
	size_ip = (uint16_t) ip->longitud[0];// invierto los bytes
	size_ip <<= 8;
	size_ip += (uint16_t) ip->longitud[1];

	// calculo la cantidad de datos
	size_dat = size_ip - size_hip - size_htcp;

	//----------------------------------------------------
	// Seudo cabecera TCP
	acu = (uint32_t) ip->ip_origen[0] << 8;
	acu += (uint32_t) ip->ip_origen[1];
	acu += (uint32_t) ip->ip_origen[2] << 8;
	acu += (uint32_t) ip->ip_origen[3];

	acu += (uint32_t) ip->ip_dest[0] << 8;
	acu += (uint32_t) ip->ip_dest[1];
	acu += (uint32_t) ip->ip_dest[2] << 8;
	acu += (uint32_t) ip->ip_dest[3];

	acu += (uint32_t) ip->protocolo;	//TCP 0x06, UDP 0x11

	acu += (uint32_t) size_htcp + size_dat;
	//----------------------------------------------------
	// suma la cabecera y datos
	aux_u32 = size_htcp + size_dat;
	for( i = 0; i < aux_u32  ; i++ ){
		acu += (uint32_t) puntero[i] << 8;
		i++;
		if(i < aux_u32){
			acu += (uint32_t) puntero[i];
		} else { i--; }
	}
	while(acu > 0x0000ffff ){
		aux_u32 = acu >> 16;
		acu &= 0x0000ffff;
		acu += aux_u32;
	}
	acu = ~acu & 0x0000ffff;
	return( (uint16_t) acu );
}


int eth_retorno_paquete(eth_frame_t *eth_in, uint8_t tipo, uint8_t *buffer, uint16_t cantidad){
	uint32_t aux_u32;
	uint16_t aux_u16;
	uint16_t i;
	uint8_t aux_u8;
	uint32_t secuencia;

	ip_frame_t *ip_in;
	tcp_frame_t *tcp_in;
	pbuf_t buffer_out;

	eth_frame_t *eth_out;
	ip_frame_t *ip_out;
	tcp_frame_t *tcp_out;

	uint16_t largo_de_paquete;
//	uint8_t *datos_in
	uint8_t *datos_out;
//	uint16_t max_datos;
	uint16_t size_datos_in;

	// a partir del frame ethernet apunto al paquete IP
	aux_u32 = (uint32_t) eth_in;
	aux_u32 += sizeof(eth_frame_t);
	ip_in = (ip_frame_t*) aux_u32;

	//Obtengo la longitud de cabecera IP
	aux_u8 = ip_in->ver_hlen;	// los 4 bits mas bajos son la longitud en palabras de 32 bits
	aux_u8 = aux_u8 & 0x0f;
	aux_u8 = aux_u8 * 4;		// lo paso a palabras de 8 bits (bytes)

	// apunto al paquete TCP
	aux_u32 = (uint32_t) ip_in;
	aux_u32 += (uint32_t) aux_u8;
	tcp_in = (tcp_frame_t*) aux_u32;

	// calculo el largo de los datos de entrada
	aux_u16 = (uint16_t) ip_in->longitud[0];// invierto los bytes
	aux_u16 = aux_u16 << 8;
	aux_u16 += (uint16_t) ip_in->longitud[1];
	aux_u16 -= (uint16_t) aux_u8;		// le resto la cabecera IP
	aux_u8 = tcp_in->tam_RES_NONCE >> 4;	//tomo los 4 bits mas altos, son el tamaño de la cabecera tcp
	aux_u8 *= 4;				// lo paso a palabras de 8 bits
	aux_u16 -= (uint16_t) aux_u8;		// le resto la cabecera TCP
	size_datos_in = aux_u16;

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

	ip_out->ver_hlen = 0x45;			// Versión 4, cabecera con 5 palabras de 32 bits (20 bytes)
	ip_out->tipo_servicio = 00;			// No se por que se coloca 00
	if(tipo == (ETH_SYN | ETH_ACK)){
		ip_out->longitud[0] = 0x00;	// retoro el mismo paquete con igual longitud
		ip_out->longitud[1] = 40;	// 20 bytes ip + 20 bytes TCP
	}
	if(tipo == ETH_ACK){
		ip_out->longitud[0] = 0x00;	// retoro el mismo paquete con igual longitud
		ip_out->longitud[1] = 40;	// 20 bytes ip + 20 bytes TCP
	}
	if(tipo == ( ETH_FIN | ETH_ACK ) ){
		ip_out->longitud[0] = 0x00;	// retoro el mismo paquete con igual longitud
		ip_out->longitud[1] = 40;	// 20 bytes ip + 20 bytes TCP
	}
	if(tipo == ( ETH_PUSH | ETH_ACK ) ){
		aux_u16 = 40;		//largo de la cabecera ip + cabecera tcp
		aux_u16 += cantidad;	//le sumo los datos
		ip_out->longitud[1] = (uint8_t) ( aux_u16 & 0x00FF );	// retoro el mismo paquete con igual longitud
		aux_u16 >>= 8;
		ip_out->longitud[0] = (uint8_t) ( aux_u16 & 0x00FF );	// datos a enviar
	}
	ip_out->identificacion[0] = 0x00;		// identifica como paquete único
	ip_out->identificacion[1] = ip_in->identificacion[1] + 10;
	ip_out->band_desplazamiento[0] = 0x40;	// 010(sin fragmentos) 0000000000000(sin desplazamiento)
	ip_out->band_desplazamiento[1] = 0x00;
	ip_out->tiempo_vida = 0x40;		// tiempo que viajará por la red
	ip_out->protocolo = 0x06;		// 01 ICMP, 06 tcp
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

	// Completo paquete tcp
	aux_u32 = (uint32_t) ip_out;
	aux_u32 += 20;			// desplazamiento hasta el final de la cabecera IP
	tcp_out = (tcp_frame_t*) aux_u32;
	tcp_out->puerto_origen[0] = tcp_in->puerto_dest[0];	//puerto origen
	tcp_out->puerto_origen[1] = tcp_in->puerto_dest[1];
	tcp_out->puerto_dest[0] = tcp_in->puerto_origen[0];	//puerto destino
	tcp_out->puerto_dest[1] = tcp_in->puerto_origen[1];	//puerto destino
	aux_u32 = u8_a_u32(tcp_in->secuencia[0], tcp_in->secuencia[1], tcp_in->secuencia[2], tcp_in->secuencia[3] ); // Cambio el número de 4 byites a palabra de 32
	if(tipo == (ETH_SYN | ETH_ACK)){
		aux_u32++;	// Le sumo 1 a secuencia
		secuencia = 22;	// asigno un número inicial para la secuencia mia
	}
	if(tipo == ETH_ACK){
		aux_u32 = u8_a_u32(tcp_in->secuencia[0], tcp_in->secuencia[1], tcp_in->secuencia[2], tcp_in->secuencia[3] ); // Cambio el número de 4 byites a palabra de 32
		aux_u32++;
		secuencia = u8_a_u32(tcp_in->acknew[0], tcp_in->acknew[1], tcp_in->acknew[2], tcp_in->acknew[3]);
	}
	if(tipo == (ETH_FIN | ETH_ACK) ){
		aux_u32 = u8_a_u32(tcp_in->secuencia[0], tcp_in->secuencia[1], tcp_in->secuencia[2], tcp_in->secuencia[3] ); // Cambio el número de 4 byites a palabra de 32
		aux_u32 += size_datos_in;	// valido que recibí los datos enviados
		secuencia = u8_a_u32(tcp_in->acknew[0], tcp_in->acknew[1], tcp_in->acknew[2], tcp_in->acknew[3]);
	}
	if(tipo == (ETH_PUSH | ETH_ACK) ){
		aux_u32 = u8_a_u32(tcp_in->secuencia[0], tcp_in->secuencia[1], tcp_in->secuencia[2], tcp_in->secuencia[3] ); // Cambio el número de 4 byites a palabra de 32
		aux_u32 += size_datos_in;	// valido que recibí los datos enviados
		secuencia = u8_a_u32(tcp_in->acknew[0], tcp_in->acknew[1], tcp_in->acknew[2], tcp_in->acknew[3]);
	}
	tcp_out->acknew[3] = aux_u32 & 0x000000ff;	// invierto el número y lo asigno de a 8 bits
	tcp_out->acknew[2] = (aux_u32 >> 8) & 0x000000ff;
	tcp_out->acknew[1] = (aux_u32 >> 16) & 0x000000ff;
	tcp_out->acknew[0] = (aux_u32 >> 24) & 0x000000ff;
	tcp_out->secuencia[3] = secuencia & 0x000000ff;	// invierto el número y lo asigno de a 8 bits
	tcp_out->secuencia[2] = (secuencia >> 8) & 0x000000ff;
	tcp_out->secuencia[1] = (secuencia >> 16) & 0x000000ff;
	tcp_out->secuencia[0] = (secuencia >> 24) & 0x000000ff;
	tcp_out->tam_RES_NONCE = 0x50;	// 5 bytes
	tcp_out->flag = tipo ;	// Tipo de paquete (flag syn, ack etc.)
	tcp_out->ventana[1] = 0x72;	// un valor fijo, por ahora
	tcp_out->ventana[0] = 0x10;
	tcp_out->checksum[0] = 0x00;
	tcp_out->checksum[1] = 0x00;
	tcp_out->punt_urg[0] = 0x00;	// no usa puntero urgente
	tcp_out->punt_urg[1] = 0x00;

//---------------------------------------------------------

	// calculo el largo de los datos
	aux_u16 = (uint16_t) ip_out->longitud[0];// invierto los bytes
	aux_u16 = aux_u16 << 8;
	aux_u16 += (uint16_t) ip_out->longitud[1];
	aux_u16 -= sizeof(ip_frame_t);		// le resto la cabecera IP
	aux_u16 -= sizeof(tcp_frame_t);		// le resto la cabecera TCP
//	max_datos = aux_u16;

	// apunto a los datos de salida
	aux_u32 = (uint32_t) tcp_out;
	aux_u32 += sizeof(tcp_frame_t);
	datos_out = (uint8_t*) aux_u32;
/*
	// apunto a los datos de entada
	aux_u32 = (uint32_t) icmp_in;
	aux_u32 += sizeof(icmp_frame_t);
	datos_in = (uint8_t*) aux_u32;
*/
	if( tipo == ( ETH_PUSH | ETH_ACK ) ){
		for( i=0 ; i < cantidad ; i++){	//copio los datos
			datos_out[i] = buffer[i];
		}
	} else {
		cantidad = 0;
	}

	largo_de_paquete = 14 /*ETH*/+ 20 /*IP*/ + 20 /*TCP*/+ cantidad /*datos*/;

	aux_u16 = tcp_checksum(ip_out);
	tcp_out->checksum[1] = (uint8_t) aux_u16 & 0xff;
	aux_u16 = aux_u16 >> 8;
	tcp_out->checksum[0] = (uint8_t) aux_u16 & 0xff;

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

int eth_tcp_frame(eth_frame_t *eth_in){

	uint32_t aux_u32;
//	uint16_t aux_u16;
	uint8_t aux_u8;
	ip_frame_t *ip_in;
	tcp_frame_t *tcp_in;
	uint16_t puerto;

	// a partir del frame ethernet apunto al paquete IP
	aux_u32 = (uint32_t) eth_in;
	aux_u32 += sizeof(eth_frame_t);
	ip_in = (ip_frame_t*) aux_u32;

	// Chequeo que sea para mi ( ¿es mi IP? )
	if( 0 != eth_comp(ip_in->ip_dest, my_ip, 4)) return(-1);

	//Obtengo la longitud de cabecera IP
	aux_u8 = ip_in->ver_hlen;	// los 4 bits mas bajos son la longitud en palabras de 32 bits
	aux_u8 = aux_u8 & 0x0f;
	aux_u8 = aux_u8 * 4;		// lo paso a palabras de 8 bits (bytes)

	// apunto al paquete TCP
	aux_u32 = (uint32_t) ip_in;
	aux_u32 += (uint32_t) aux_u8;
	tcp_in = (tcp_frame_t*) aux_u32;

	// Verifico que el puerto esté abierto
	puerto = (uint16_t) tcp_in->puerto_dest[0];	// cambio el orden de los bytes
	puerto = (puerto << 8) & 0xff00;
	puerto += (uint16_t) tcp_in->puerto_dest[1];

	if( eth_puerto[puerto] == NULL) return(-2);// está cerrado el puerto

	switch (tcp_in->flag){
	case ETH_SYN:
		if(eth_tcp_estado[puerto] == ETH_ESPERANDO_SYN){
//			eth_tcp_estado[puerto] = ETH_ESPERANDO_ACK;
			eth_tcp_estado[puerto] = ETH_CONECTADO;
			eth_retorno_paquete(eth_in, ( ETH_SYN | ETH_ACK ), 0, 0 );//retorno syn-ack
		} //else RST
		break;
	case ETH_ACK:
		if(eth_tcp_estado[puerto] == ETH_ESPERANDO_ACK){
			eth_tcp_estado[puerto] = ETH_CONECTADO;
		} else{// else RST
//????????????????????????prueba enviar ACK
//			eth_retorno_paquete(eth_in, ETH_ACK , 0, 0);//retorno fin-ack
			eth_tcp_estado[puerto] = ETH_ESPERANDO_SYN;
		}
		break;
	case ETH_FIN:
		break;
	case ETH_RST:
		break;
	case ( ETH_PUSH | ETH_ACK ):
		eth_puerto[puerto](eth_in);		// ejecuto el servicio
		eth_tcp_estado[puerto] = ETH_ESPERANDO_SYN;// hago esto para que vuelva a conectar , hay que arreglarlo
//	eth_retorno_paquete(eth_in, (ETH_FIN | ETH_ACK) , 0, 0);//retorno fin-ack
		break;
//--------------------------------------------------------------------
	case ( ETH_FIN | ETH_ACK ):
		eth_retorno_paquete(eth_in, ETH_ACK , 0, 0);//retorno fin-ack
		eth_tcp_estado[puerto] = ETH_ESPERANDO_SYN;// hago esto para que vuelva a conectar , hay que arreglarlo
		break;
	}

	return(0);
}

uint32_t u8_a_u32( uint8_t a,uint8_t b, uint8_t c, uint8_t d ){
	uint32_t aux_u32, acu;

	aux_u32 = (uint32_t) a;
	acu = aux_u32  << 24;
	aux_u32 = (uint32_t) b;
	acu += aux_u32  << 16;
	aux_u32 = (uint32_t) c;
	acu += aux_u32  << 8;
	aux_u32 = (uint32_t) d;
	acu += aux_u32 ;
	return(acu);
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
	case TIPO_ICMP:			//ICMP = 0x01
		eth_icmp_frame(eth_in);
		break;
	case TIPO_TCP:			//TCP = 0x06
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
	// verifico que sea para mi
	if( 0  != eth_comp(my_ip, arp_in->ip_destino, 4 )) return(-6);

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

int eth_set_puerto(uint32_t (*a)(eth_frame_t*) , uint16_t puerto){
	eth_puerto[puerto] = a;		// asigno función a puerto
	eth_tcp_estado[puerto] = ETH_ESPERANDO_SYN;// cambio a estado esperando SYN
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
	uint32_t i;

	// Inicio los puertos tcp cerrados (NULL)
	for(i=0; i < MAX_PUERTOS; i++){
		eth_puerto[i] = (uint32_t (*)()) NULL;
		eth_tcp_estado[i] = (uint32_t) NULL;
	}

	//Inicio el controlador ethernet enc28j60 y asigno MAC
	drvEnc28j60_init(my_mac);

	return(0);
}

int eth_open_socket(){

	return(0);
}

int eth_close_socket(){
//	eth_tcp_estado[puerto] = ETH_ESPERANDO_SYN;	//cierro la conexión pero no el puero, quedo esperando un paquete SYN
	return(0);
}


