#include "ramdisk.h"

// read_ramdisk() lee el número "bloque" desde "disco" y lo carga en "dato"
uint32_t read_ramdisk(uint8_t *dato, uint8_t *disco, uint32_t bloque){

	uint32_t aux, i;
	uint8_t *p;

	aux = (uint32_t) disco;
	aux += SIZE_BLOCK_RAMDISK * bloque;
	p = (uint8_t *) aux;

	for(i = 0; i < SIZE_BLOCK_RAMDISK ; i++){
		dato[i] = p[i];
	}
	return(i);
}

// write_ramdisk() lee el "dato" y lo carga en el número "bloque" en el "disco"
uint32_t write_ramdisk(uint8_t *dato, uint8_t *disco, uint32_t bloque){

	uint32_t aux, i;
	uint8_t *p;

	aux = (uint32_t) disco;
	aux += SIZE_BLOCK_RAMDISK * bloque;
	p = (uint8_t *) aux;

	for(i = 0; i < SIZE_BLOCK_RAMDISK ; i++){
		p[i] = dato[i];
	}
	return(i);
}
