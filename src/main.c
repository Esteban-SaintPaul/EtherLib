//#include <stdio.h>
#include "stm32f4xx_rcc.h"
#include "stm32f4xx_gpio.h"
#include "eth.h"		/* Librería Ethernet */

/* Definiciones locales */
int init_portd(); /* Inicio los leds en el puerto "D" */

uint32_t http(){

        return(0);
}


/* Inicio */
int main(void) {

	init_portd();

	/* Configuración de inicio LIBETH */
	eth_set_mac(0x00,0x11,0x11,0x22,0x22,0x33);
	eth_set_ip(10,0,0,31);
	eth_set_mask(255,255,255,0);
	eth_set_gw(10,0,0,1);
	eth_init();

	eth_set_puerto( http, 80 );

//ERR_VAL no hay paquete
//ERR_IF  hay paquete pero con error
//ERR_OK  hay paquete sin errores

	while (1) {
		int i;

		i = eth_service();
		if(i == ERR_OK ) GPIO_ToggleBits(GPIOD, GPIO_Pin_12);

		for (i = 0; i < 1000; ++i){;}
//		GPIO_ToggleBits(GPIOD, GPIO_Pin_13 | GPIO_Pin_14 | GPIO_Pin_15);
	}
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
