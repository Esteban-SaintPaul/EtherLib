//#include <stdio.h>
#include "stm32f4xx_rcc.h"
#include "stm32f4xx_gpio.h"
#include "eth.h"		/* Librería Ethernet */

/* Definiciones locales */
int init_portd(); /* Inicio los leds en el puerto "D" */
uint32_t http(eth_frame_t* eth_in); //servidor web
uint32_t nfs(eth_frame_t* eth_in); //servidor de prueba
int comparar(uint8_t *a, uint8_t *b, int cantidad); //compara dos cadenas (solo cantidad de elementos) retona cero si son iguales.

/* Inicio */
int main(void) {
	uint32_t i;

	init_portd();

	/* Configuración de inicio LIBETH */
	eth_set_mac(0x00,0x11,0x11,0x22,0x22,0x33);
	eth_set_ip(10,0,0,31);
	eth_set_mask(255,255,255,0);
	eth_set_gw(10,0,0,1);
	eth_init();
	eth_set_puerto( http, 80 );	// seteo un servidor web en el puerto 80
	eth_set_puerto( nfs, 517 );	// seteo utro servidor web wn el puerto 517

//ERR_VAL no hay paquete
//ERR_IF  hay paquete pero con error
//ERR_OK  hay paquete sin errores

	while (1) {

		eth_service();

//		if(i == ERR_OK ) GPIO_ToggleBits(GPIOD, GPIO_Pin_12);
		for (i = 0; i < 1000; ++i){;}
		GPIO_ToggleBits(GPIOD, GPIO_Pin_13 | GPIO_Pin_14 | GPIO_Pin_15);
	}
}


uint32_t http(eth_frame_t* eth_in){
	uint8_t buffer[1500];
	uint32_t size_dat;

	uint8_t index[] = {"GET /index.html "};

	// tamaños: html=100, http=72, total=172
	uint8_t pagina_404[] = {"HTTP/1.1 404 NOT FOUND\r\nContent-Type: text/html\r\nContent-Length: 100\r\n\r\n<HTML><TITLE>PAGINA NO ENCONTRADA</TITLE><BODY><H1>ERROR 404 PAGINA NO ENCONTRADA</H1></BODY></HTML>"};

	// tamaños: html=100, http=65, total=165
	uint8_t pagina_index[] = {"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 100\r\n\r\n<HTML><TITLE>PAGINA ENCONTRADA   </TITLE><BODY><H1>STM32F4DISCOVERY LIBETH 0.7   </H1></BODY></HTML>"};

	eth_read_socket( eth_in, buffer, &size_dat);	// Leo la petición entrante
	if( 0 == comparar( index, buffer, 15) ){
		eth_write_socket( eth_in, pagina_index, 165 );	// Envío la web 404
	} else {
		eth_write_socket( eth_in, pagina_404, 172 );	// Envío la web 404
	}
   return(0);
}

uint32_t nfs(eth_frame_t* eth_in){
	uint8_t buffer[1500];
	uint32_t size_dat;

	uint8_t index[] = {"GET /nfs "};

	// tamaños: html=100, http=72, total=172
	uint8_t pagina_404[] = {"HTTP/1.1 404 NOT FOUND\r\nContent-Type: text/html\r\nContent-Length: 100\r\n\r\n<HTML><TITLE>PAGINA NO ENCONTRADA</TITLE><BODY><H1>ERROR 404 PAGINA NO ENCONTRADA</H1></BODY></HTML>"};

	// tamaños: html=100, http=65, total=165
	uint8_t pagina_index[] = {"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 100\r\n\r\n<HTML><TITLE>PAGINA ENCONTRADA   </TITLE><BODY><H1>STM32F4DISCOVERY LIBETH 0.7nfs</H1></BODY></HTML>"};

	eth_read_socket( eth_in, buffer, &size_dat);	// Leo la petición entrante
	if( 0 == comparar( index, buffer, 8) ){
		eth_write_socket( eth_in, pagina_index, 165 );	// Envío la web 404
	} else {
		eth_write_socket( eth_in, pagina_404, 172 );	// Envío la web 404
	}
   return(0);
}

/* Función para iniciar el puerto "D" , esencialmente los Leds de la placa */
int init_portd(){
	GPIO_InitTypeDef GPIO_InitStruct;
	RCC_AHB1PeriphClockCmd(RCC_AHB1Periph_GPIOD, ENABLE);
	GPIO_InitStruct.GPIO_Pin = GPIO_Pin_15 | GPIO_Pin_14 | GPIO_Pin_13 | GPIO_Pin_12;
	GPIO_InitStruct.GPIO_Mode = GPIO_Mode_OUT;
	GPIO_InitStruct.GPIO_Speed = GPIO_Speed_100MHz;
	GPIO_InitStruct.GPIO_OType = GPIO_OType_PP;
	GPIO_InitStruct.GPIO_PuPd = GPIO_PuPd_NOPULL;
	GPIO_Init(GPIOD, &GPIO_InitStruct);
	return(0);
}

int comparar(uint8_t *a, uint8_t *b, int cantidad){
	int ret, i;

	for( i = 0, ret = 0 ; (i < cantidad ) && ( ret == 0 ) ; i++){
		ret = a[i] - b[i];
	}
	return( (int) ret );
}
