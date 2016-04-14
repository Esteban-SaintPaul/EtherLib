#include <stdint.h>


#define SIZE_BLOCK_RAMDISK 512

// read_ramdisk() lee el número "bloque" desde "disco" y lo carga en "dato"
uint32_t read_ramdisk(uint8_t *dato, uint8_t *disco, uint32_t bloque);

// write_ramdisk() lee el "dato" y lo carga en el número "bloque" en el "disco"
uint32_t write_ramdisk(uint8_t *dato, uint8_t *disco, uint32_t bloque);

