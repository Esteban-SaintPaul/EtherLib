#include <stdlib.h>

typedef struct block_list {	// índice de sistema de archivos
	uint8_t tipo_block;	// Tipo de sistema de Archivo 0xEE
	uint32_t size_block;	// Cantidad de bloques de 512 bytes que ocupa el índice
	uint32_t size_disk;	// bloques de disco total
	uint32_t n_file;	// cantidad de archivos
	uint8_t res[100];	// reservado para mejoras futuras
	uint8_t name[399];	// Nombre del disco o partición
} __attribute__((packed)) block_list_t;

typedef struct block_arch {	// descriptor de archivo
	uint8_t tipo_arch;	// Tipo de archivo (0 = texto, 1 = binario)
	uint32_t size_arch;	// Tamaño de archivo en bytes
	uint32_t init_arch;	// ubicación del primer bloque (los bloques son de 512 bytes)
	uint32_t end_arch;	// ubicación del últmo bloque
	uint8_t res[100];	// reservado para mejoras futuras
	uint8_t name[399];	// nombre del archivo + ruta
} __attribute__((packed)) block_arch_t;

#define MAX_NAME_FILE 256
