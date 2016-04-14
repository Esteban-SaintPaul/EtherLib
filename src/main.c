#include <stdio.h>
#include "stm32f4xx_rcc.h"
#include "stm32f4xx_gpio.h"
#include "eth.h"		/* Librería Ethernet */
#include "litefs.h"		// librería de litefs
#include "ramdisk.h"		// librería de disco en RAM
#include "disco.h"		// Disco en RAM

//------------------------------------------------------------------------
typedef struct device {
	uint32_t (*read)(uint8_t *dato, uint8_t *disco, uint32_t bloque);
	uint32_t (*write)(uint8_t *dato, uint8_t *disco, uint32_t bloque);
} device_t;

uint32_t litefs_open(device_t *dev);
uint32_t copy_url(uint8_t *buffer, uint8_t *url);
uint32_t litefs_search(device_t *dev,uint8_t *url, block_arch_t *arch);	// busco la página en el disco
uint32_t litefs_send(eth_frame_t* eth_in, device_t *dev, block_arch_t *arch);

//------------------------------------------------------------------------


/* Definiciones locales */
int init_portd(); /* Inicio los leds en el puerto "D" */
uint32_t http(eth_frame_t* eth_in); //servidor web
uint32_t nfs(eth_frame_t* eth_in); //servidor de prueba
int comparar(uint8_t *a, uint8_t *b, int cantidad); //compara dos cadenas (solo cantidad de elementos) retona cero si son iguales.

device_t dev;

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

// terminar de definir como agregar la página web imagen paraprobarfragmentación
uint32_t http(eth_frame_t* eth_in){
	uint8_t buffer[1500];
	uint32_t size_dat;

	uint8_t index[] = {"GET /index.html "};

	// tamaños: html=100, http=72, total=172
	uint8_t pagina_404[] = {"HTTP/1.1 404 NOT FOUND\r\nContent-Type: text/html\r\nContent-Length: 100\r\n\r\n<HTML><TITLE>PAGINA NO ENCONTRADA</TITLE><BODY><H1>ERROR 404 PAGINA NO ENCONTRADA</H1></BODY></HTML>"};

	// tamaños: html=100, http=65, total=165
	uint8_t pagina_index[] = {"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 100\r\n\r\n<HTML><TITLE>PAGINA ENCONTRADA   </TITLE><BODY><H1>STM32F4DISCOVERY LIBETH 0.7   </H1></BODY></HTML>"};

	eth_read_socket( eth_in, buffer, &size_dat);	// Leo la petición entrante


	device_t dev;			// struct device_t { *(read)() *(write)() }
	uint8_t url[MAX_NAME_FILE];	// nombre del archivo pedido
//	block_list_t block;		// superblock LiteFS
	block_arch_t arch;		// registro de archivo LiteFS
	uint32_t ret;			// variable genérica

	// seteo el dispositivo como ramdisk
	dev.read = read_ramdisk;
	dev.write = write_ramdisk;


	// intento abrirlo como formateado en litefs
	ret = litefs_open(&dev);	// es como mount, verifica el tipo de fs, etc
	if( ret != 0) {
		eth_write_socket( eth_in, pagina_404, 172 );	// Envío la web 404
		return(1); // error de dispositivo (no puede abrirse)
	}

	ret =copy_url(buffer, url);	// copio el nombre de la página pedida

	ret = litefs_search(&dev, url, &arch);	// busco la página en el disco

	if( ret == 0) { // retorno error 404
		litefs_send(eth_in, &dev, &arch);
	}else {
		eth_write_socket( eth_in, pagina_404, 172 );	// Envío la web 404
	}
	return(0);

//--------------------------------------------------------------------------
//	agregaresta funcion cuando esté creada!
//	litefs_send(eth_in, &dev, &arch);// envío la página
//--------------------------------------------------------------------------
/*
	if( 0 == comparar( index, buffer,  strlen((const char *)index) ) ){
		eth_write_socket( eth_in, pagina_index, 165 );	// Envío la web 404
	} else {
		eth_write_socket( eth_in, pagina_404, 172 );	// Envío la web 404
	}
   return(0);
*/
}

uint32_t litefs_search(device_t *dev,uint8_t *url, block_arch_t *arch){	// busco la página en el disco
	uint32_t i;
	uint32_t aux;
	uint32_t sel_arch;
	uint32_t max_arch;
	uint8_t buffer[512];
	block_list_t *p;

	// Abrimos el disco y verificamos el sistema de archivos (bloque 0)
	dev->read(buffer, disco, 0);
	p= (block_list_t *) buffer;
	if(0xEE != p->tipo_block) return(1);// El disco no tiene formato LiteFS

	// obtengo la cantidad de archivos
	max_arch = p->n_file;

	// Tiene archivos?
	if(p->n_file == 0) return(2); // El disco no tiene archivos

	i=0;
	sel_arch = 1;
	do {
		i++;
		// obtengo los metadatos del archivo
		dev->read( (uint8_t *) arch, disco, sel_arch);
		// comparo los nombres del archivo contra la url pedida (0 = son iguales, != 0 son distintos)
		aux = comparar( url, arch->name, strlen((const char *) arch->name) );
		// si no es el buscado, pasamos al siguiente
		if(aux != 0) sel_arch = arch->end_arch + 1;
	} while ( (i < max_arch) && (aux != 0) );

	if(aux == 0) return(0);	// Encontramos el archivo buscado

	return(3);// No había ningún archivo con ese nombre
}


uint32_t copy_url(uint8_t *buffer, uint8_t *url){

	uint32_t i;
	uint32_t j;

	i = 0;
	//salteo la primer palabra, busco el caracter espacio
	while(buffer[i] != ' '){ // caracter 0x20
		i++;
	}
	i++;	//aquí se que es espacio, aumento un lugar
	i++;	//aquí se que es espacio, aumento un lugar

	j = 0;
	while(buffer[i] != ' '){ // caracter 0x20
		url[j] = buffer[i];
		i++;
		j++;
	}
	url[j] = 0;	// caracter fin de cadena

	return(j);
}

uint32_t litefs_open(device_t *dev){
	uint8_t buffer[512];
	block_list_t *p;
	uint32_t ret;

	ret = 0;
	dev->read(buffer, disco, 0);
	p= (block_list_t *) buffer;
	if(0xEE != p->tipo_block) ret = 1;

	return(ret);
}



uint32_t litefs_send(eth_frame_t* eth_in, device_t *dev, block_arch_t *arch){
	uint32_t cant_bloques;
	uint32_t num_bloque;
	uint32_t tam_arch;
	uint32_t cant_bytes;
	uint32_t i;
	uint32_t checksum;
	uint8_t buffer[512];

	cant_bloques = arch->end_arch - arch->init_arch + 1;	// cant de bloques
	tam_arch = arch->size_arch;				// tamaño de archivos en bytes;
	num_bloque = arch->init_arch;				// primer bloque del archivo

	checksum = 0;		// inicio el acumulador en 0
	cant_bytes = 512;	// asigno los bytes a enviar
	for( i = 0; i < cant_bloques; i++){
		dev->read( buffer, disco, num_bloque + i);
		if( (num_bloque + i) != arch->end_arch){	// ni no es el último
			tam_arch -= 512;	// decremento los bytes que voy a enviar
		} else {
			cant_bytes = tam_arch;	// asigno los bytes que quedan
		}

		//eth_write_socket() envía un fragmento de datos
		//eth_in	remitente
		//buffer	datos a enviar
		//cant_bytes	tamaño en bytes de los datos
		//i+1		número de fragmento, salteo el paquete 0, comienzo con el 1
		//cant_bloques+1	cantidad de fragmentos que enviaré
		//arch->size_arch	tamaño del archivosin fragmentar
		eth_write_data( eth_in, buffer, cant_bytes, i + 1, cant_bloques + 1, 0, arch->size_arch);
		checksum += tcp_checksum_data( buffer, cant_bytes);
	}
	i=0;
	while(checksum > 0x0000FFFF){	// lo acoto a 16 bits en complemento a uno
		i = checksum >> 16;
		checksum &= 0x0000FFFF;
		checksum += i;
	}

	//eth_write_data() envía un fragmento de datos
	//eth_in	remitente
	//buffer	datos a enviar
	//0	tamaño en bytes de los datos, archivo completo
	//0		num de fragmento 0, contiene la cabecera TCP
	//0	cantidad de fragmentos que enviaré
	//arch->size_arch
	eth_write_data( eth_in, buffer, 0, 0, 0, checksum, arch->size_arch);

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
