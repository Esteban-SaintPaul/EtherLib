/* Archivos cabecera */
#include <string.h>
#include "stm32f4xx_gpio.h"
#include "stm32f4xx_rcc.h"
#include "stm32f4xx_spi.h"
#include "drvEnc28j60.h"
#include "delay.h"

/* Definiciones locales */
#define USE_MASSERT  /* si se borra esta línea se desactiva el cotrol deparámetros a funciones del driver */

#ifdef  USE_MASSERT
/**
 * @brief  La macro assert_param es usada para chequear los parámetros de funciones.
 * @param  expr: Si la expreción es falsa se llama a la función assert_failed
 *   para reportar el nombre del archivo fuente y el número de linea
 *   de la llamada que falló.
 *   Si la expreción es verdadera, retorna sin valor.
 * @retval None
 */
#define mASSERT(expr) ((expr) ? (void)0 : massert((unsigned char *) __FILE__, __LINE__))

void massert(unsigned char * apFile, unsigned long line);
#else
#define mASSERT(expr) ((void)0)
#endif /* USE_MASSERT */


static uint8_t s_enc28j60_current_bank = 0;
static uint16_t s_enc28j60_rxrdpt = 0;

/**
 * Initialize SPI interface and peripheral pins
 */
static void drvEnc28j60_hw_init(void) {
	SPI_InitTypeDef SPI_InitStructure;
	GPIO_InitTypeDef GPIO_InitStructure;

	// Enable the SPI clock
	SPIx_CLK_INIT(SPIx_CLK, ENABLE);

	// SPI configuration
	SPI_InitStructure.SPI_Direction = SPI_Direction_2Lines_FullDuplex;
	SPI_InitStructure.SPI_Mode = SPI_Mode_Master;
	SPI_InitStructure.SPI_DataSize = SPI_DataSize_8b;
	SPI_InitStructure.SPI_CPOL = SPI_CPOL_Low;
	SPI_InitStructure.SPI_CPHA = SPI_CPHA_1Edge;
	SPI_InitStructure.SPI_NSS = SPI_NSS_Soft;
	SPI_InitStructure.SPI_BaudRatePrescaler = SPI_BaudRatePrescaler_8; /* Max 20MHz */
	SPI_InitStructure.SPI_FirstBit = SPI_FirstBit_MSB;
	SPI_InitStructure.SPI_CRCPolynomial = 7;
	SPI_Init(SPIx, &SPI_InitStructure);

	// Enable GPIO clocks
	RCC_AHB1PeriphClockCmd(
			RCC_AHB1Periph_GPIOE | SPIx_SCK_GPIO_CLK | SPIx_MISO_GPIO_CLK | SPIx_MOSI_GPIO_CLK | SPIx_CS_GPIO_CLK | ENC28J60_RESET_GPIO_CLK
					| ENC28J60_INT_GPIO_CLK, ENABLE);
	// Enable SYSCFG clock
	RCC_APB2PeriphClockCmd(RCC_APB2Periph_SYSCFG, ENABLE);

	// SPI GPIO Configuration
	// Connect SPI pins to AF
	GPIO_PinAFConfig(SPIx_SCK_GPIO_PORT, SPIx_SCK_SOURCE, SPIx_SCK_AF);
	GPIO_PinAFConfig(SPIx_MISO_GPIO_PORT, SPIx_MISO_SOURCE, SPIx_MISO_AF);
	GPIO_PinAFConfig(SPIx_MOSI_GPIO_PORT, SPIx_MOSI_SOURCE, SPIx_MOSI_AF);

	GPIO_InitStructure.GPIO_Mode = GPIO_Mode_AF;
	GPIO_InitStructure.GPIO_Speed = GPIO_Speed_50MHz;
	GPIO_InitStructure.GPIO_OType = GPIO_OType_PP;
	GPIO_InitStructure.GPIO_PuPd = GPIO_PuPd_UP;

	// SPI SCK pin configuration
	GPIO_InitStructure.GPIO_Pin = SPIx_SCK_PIN;
	GPIO_Init(SPIx_SCK_GPIO_PORT, &GPIO_InitStructure);

	// SPI MISO pin configuration
	GPIO_InitStructure.GPIO_Pin = SPIx_MISO_PIN;
	GPIO_Init(SPIx_MISO_GPIO_PORT, &GPIO_InitStructure);

	// SPI MOSI pin configuration
	GPIO_InitStructure.GPIO_Pin = SPIx_MOSI_PIN;
	GPIO_Init(SPIx_MOSI_GPIO_PORT, &GPIO_InitStructure);

	// Configure SPI CS pin in output pushpull mode
	GPIO_InitStructure.GPIO_Pin = SPIx_CS_PIN;
	GPIO_InitStructure.GPIO_Mode = GPIO_Mode_OUT;
	GPIO_InitStructure.GPIO_PuPd = GPIO_PuPd_UP;
	GPIO_Init(SPIx_CS_GPIO_PORT, &GPIO_InitStructure);

	// Configure Reset pin in output pushpull mode
	GPIO_InitStructure.GPIO_Pin = ENC28J60_RESET_PIN;
	GPIO_InitStructure.GPIO_Mode = GPIO_Mode_OUT;
	GPIO_InitStructure.GPIO_PuPd = GPIO_PuPd_UP;
	GPIO_Init(ENC28J60_RESET_GPIO_PORT, &GPIO_InitStructure);
	GPIO_ResetBits(ENC28J60_RESET_GPIO_PORT, ENC28J60_RESET_PIN);
	delay_nms(100);
	GPIO_SetBits(ENC28J60_RESET_GPIO_PORT, ENC28J60_RESET_PIN);
	delay_nms(100);

	// Disable Accelerometer on STM32F4 discovery board
	GPIO_InitStructure.GPIO_Pin = GPIO_Pin_3;
	GPIO_Init(GPIOE, &GPIO_InitStructure);
	GPIO_SetBits(GPIOE, GPIO_Pin_3);

	// Set CS High for ENC28J60
	GPIO_SetBits(SPIx_CS_GPIO_PORT, SPIx_CS_PIN);

	// Enable SPI
	SPI_Cmd(SPIx, ENABLE);
}

/**
 *  This function sends a data_byte byte over SPIx bus and read back input byte.
 *
 * @param data_byte the byte to be sent.
 * @return the returned byte if any.
 *
 */
static unsigned char drvEnc28j60_readWriteByte(unsigned char data_byte) {
	unsigned char recvData;

	/* TX must be empty */
	mASSERT(SET == SPI_I2S_GetFlagStatus(SPIx, SPI_I2S_FLAG_TXE));

	/* Send byte through the SPIx peripheral */
	SPI_I2S_SendData(SPIx, data_byte);

	/* Wait to receive a byte */
	while (SPI_I2S_GetFlagStatus(SPIx, SPI_I2S_FLAG_RXNE) == RESET) {
	};
	recvData = SPI_I2S_ReceiveData(SPIx);

	return recvData;
}

static void drvEnc28j60_select(void) {
	GPIO_ResetBits(SPIx_CS_GPIO_PORT, SPIx_CS_PIN);
}

static void drvEnc28j60_unselect(void) {
	GPIO_SetBits(SPIx_CS_GPIO_PORT, SPIx_CS_PIN);
}

/**
 * Read operation from ENC28J60
 * @param cmd
 * @param addr
 * @return
 */
static uint8_t enc28j60_opRead(uint8_t cmd, uint8_t addr) {
	uint8_t data;

	drvEnc28j60_select();
	drvEnc28j60_readWriteByte(cmd | (addr & ENC28J60_ADDR_MASK));
	data = drvEnc28j60_readWriteByte(0xFF);
	if (addr & ENC28J60_MACMII) {
		data = drvEnc28j60_readWriteByte(0xFF);
	}
	drvEnc28j60_unselect();
	return data;
}

/**
 * Write operation command to ENC28J60
 * @param cmd, the command
 * @param addr, the address
 * @param data, the data
 */
static void drvEnc28j60_opWrite(uint8_t cmd, uint8_t addr, uint8_t data) {
	drvEnc28j60_select();
	drvEnc28j60_readWriteByte(cmd | (addr & ENC28J60_ADDR_MASK));
	drvEnc28j60_readWriteByte(data);
	drvEnc28j60_unselect();
}

/**
 * Read Rx/Tx buffer (at ERDPT)
 */
static void drvEnc28j60_bufferRead(uint8_t *buffer, uint16_t len) {
	drvEnc28j60_select();
	drvEnc28j60_readWriteByte(ENC28J60_SPI_RBM);
	while (len--) {
		*(buffer++) = drvEnc28j60_readWriteByte(0xFF);
	}
	drvEnc28j60_unselect();
}

/**
 * Write Rx/Tx buffer (at EWRPT)
 */
static void drvEnc28j60_bufferWrite(const uint8_t * buffer, uint16_t len) {
	drvEnc28j60_select();
	drvEnc28j60_readWriteByte(ENC28J60_SPI_WBM);
	while (len--)
		drvEnc28j60_readWriteByte(*(buffer++));
	drvEnc28j60_unselect();
}

/**
 * Set the register's bank
 * @param addr the register who's bank needs to be selected
 */
static void drvEnc28j60_bankSet(uint8_t addr) {
	uint8_t bank;

	if (REQUIRE_BANK_SWITCH(addr) && ((addr & ENC28J60_BANK_MASK) != s_enc28j60_current_bank)) {
		bank = (addr & ENC28J60_BANK_MASK) >> 5;

		drvEnc28j60_opWrite(ENC28J60_SPI_BFC, ECON1, ECON1_BSEL1 | ECON1_BSEL0);
		drvEnc28j60_opWrite(ENC28J60_SPI_BFS, ECON1, bank);

		s_enc28j60_current_bank = (addr & ENC28J60_BANK_MASK);
	}
}

/**
 * Read register from ENC28J60
 * @param addr the register's address
 * @return the byte with the the register's value
 */
static uint8_t drvEnc28j60_rcr(uint8_t addr) {
	drvEnc28j60_bankSet(addr);
	return enc28j60_opRead(ENC28J60_SPI_RCR, addr);
}

/**
 * Write register
 */
static void drvEnc28j60_wcr(uint8_t addr, uint8_t data) {
	drvEnc28j60_bankSet(addr);
	drvEnc28j60_opWrite(ENC28J60_SPI_WCR, addr, data);
}

/**
 * Write register pair
 */
static void drvEnc28j60_wcr16(uint8_t addr, uint16_t data) {
	drvEnc28j60_bankSet(addr);
	drvEnc28j60_opWrite(ENC28J60_SPI_WCR, addr, data);
	drvEnc28j60_opWrite(ENC28J60_SPI_WCR, addr + 1, data >> 8);
}
/**
 * Clear bits in register (reg &= ~mask)
 */
static void drvEnc28j60_bfc(uint8_t addr, uint8_t mask) {
	drvEnc28j60_bankSet(addr);
	drvEnc28j60_opWrite(ENC28J60_SPI_BFC, addr, mask);
}

/**
 * Set bits in register (reg |= mask)
 */
static void drvEnc28j60_bfs(uint8_t addr, uint8_t mask) {
	drvEnc28j60_bankSet(addr);
	drvEnc28j60_opWrite(ENC28J60_SPI_BFS, addr, mask);
}

/**
 * Initiate software reset
 */
static void drvEnc28j60_reset(void) {
	drvEnc28j60_select();
	drvEnc28j60_readWriteByte(ENC28J60_SPI_SR);
	drvEnc28j60_unselect();
	s_enc28j60_current_bank = ENC28J60_BANK0;
	/**
	 *  errata :: After sending an SPI Reset command, the PHY clock is stopped but the ESTAT.CLKRDY bit is not cleared.
	 */
}

// Write PHY register
static void drvEnc28j60_phyWrite(uint8_t addr, uint16_t data) {
	drvEnc28j60_wcr(MIREGADR, addr);
	drvEnc28j60_wcr16(MIWR, data);
	delay_nus(11); /* 10.24 us */
	while (drvEnc28j60_rcr(MISTAT) & MISTAT_BUSY) {
	};
}

/**
 * Wait until the ENC28J60's clock becomes fully operational
 */
static void drvEnc28j60_waitForClkRdy(void) {
	while (ESTAT_CLKRDY != (ESTAT_CLKRDY & drvEnc28j60_rcr(ESTAT))) {
	};
}

static void drvEnc28j60_setMacAddr(uint8_t hwaddr[6]) {
	drvEnc28j60_wcr(MAADR5, hwaddr[0]);
	drvEnc28j60_wcr(MAADR4, hwaddr[1]);
	drvEnc28j60_wcr(MAADR3, hwaddr[2]);
	drvEnc28j60_wcr(MAADR2, hwaddr[3]);
	drvEnc28j60_wcr(MAADR1, hwaddr[4]);
	drvEnc28j60_wcr(MAADR0, hwaddr[5]);
}

err_t drvEnc28j60_init(uint8_t *mac) {

	drvEnc28j60_hw_init();
	drvEnc28j60_waitForClkRdy();

	// Reset ENC28J60
	drvEnc28j60_reset();

	// Setup Rx buffer
	drvEnc28j60_wcr16(ERXST, ENC28J60_RXSTART);
	drvEnc28j60_wcr16(ERXND, ENC28J60_RXEND);
	drvEnc28j60_wcr16(ERXRDPT, ENC28J60_RXSTART);
	s_enc28j60_rxrdpt = ENC28J60_RXSTART;

	// Setup Tx buffer
	drvEnc28j60_wcr16(ETXST, ENC28J60_TXSTART);
	drvEnc28j60_wcr16(ETXND, ENC28J60_TXSTART);
	drvEnc28j60_wcr16(EWRPT, ENC28J60_TXSTART);

	// Setup MAC
	drvEnc28j60_wcr(MACON1, MACON1_TXPAUS | MACON1_RXPAUS | MACON1_MARXEN); // Enable flow control, Enable MAC Rx
	drvEnc28j60_wcr(MACON2, 0); // Clear reset
	drvEnc28j60_wcr(MACON3, MACON3_PADCFG0 | MACON3_TXCRCEN | MACON3_FRMLNEN | MACON3_FULDPX); //  Enable padding,Enable crc & frame len chk
	drvEnc28j60_wcr16(MAMXFL, ENC28J60_MAXFRAME);
	drvEnc28j60_wcr(MABBIPG, 0x15); // Set inter-frame gap
	drvEnc28j60_wcr(MAIPGL, 0x12);
	drvEnc28j60_wcr(MAIPGH, 0x00);
	drvEnc28j60_setMacAddr(mac); // Set MAC address

	// Setup PHY
	drvEnc28j60_phyWrite(PHCON1, PHCON1_PDPXMD); // Force full-duplex mode
	drvEnc28j60_phyWrite(PHCON2, PHCON2_HDLDIS); // Disable loopback
	drvEnc28j60_phyWrite(PHLCON, PHLCON_LEDA_LINK_STATUS | PHLCON_LEDB_TXRX_ACTIVITY | PHLCON_LFRQ0 | PHLCON_STRCH);

	// Enable Rx packets
	drvEnc28j60_bfs(ECON1, ECON1_RXEN);

	// Reset transmit buffer
	drvEnc28j60_bfs(ECON1, ECON1_TXRST);
	drvEnc28j60_bfc(ECON1, ECON1_TXRST);

	delay_nms(100);

	return ERR_OK;
}

err_t drvEnc28j60_packetSend(pbuf_t *packet) {
	while (drvEnc28j60_rcr(ECON1) & ECON1_TXRTS) {
		// TXRTS may not clear - ENC28J60 bug. We must reset transmit logic in case of Tx error
		if (drvEnc28j60_rcr(EIR) & EIR_TXERIF) {
			drvEnc28j60_bfs(ECON1, ECON1_TXRST);
			drvEnc28j60_bfc(ECON1, ECON1_TXRST);
		}
	}

	drvEnc28j60_wcr16(EWRPT, ENC28J60_TXSTART);
	drvEnc28j60_wcr16(ETXST, ENC28J60_TXSTART);
	drvEnc28j60_wcr16(ETXND, ENC28J60_TXSTART + packet->length);

	// Write per-packet control byte
	drvEnc28j60_opWrite(ENC28J60_SPI_WBM, 0, 0x00);

	// Write packet
	drvEnc28j60_bufferWrite(packet->payload, packet->length);

	// Send the contents of the transmit buffer onto the network
	drvEnc28j60_bfs(ECON1, ECON1_TXRTS);

	return ERR_OK;
}

err_t drvEnc28j60_packetRecv(pbuf_t *packet) {
	uint16_t rxlen, status;
	err_t err;

	// Check if a packet has been received and buffered
	if (0 == drvEnc28j60_rcr(EPKTCNT)) {
		return ERR_VAL;
	}

	// Set the read pointer to the start of the received packet
	drvEnc28j60_wcr16(ERDPT, s_enc28j60_rxrdpt);

	// Read the next packet pointer
	drvEnc28j60_bufferRead((void *) &s_enc28j60_rxrdpt, sizeof(s_enc28j60_rxrdpt));

	// read the packet length
	drvEnc28j60_bufferRead((void *) &rxlen, sizeof(rxlen));

	// read the receive status
	drvEnc28j60_bufferRead((void *) &status, sizeof(status));

	if ((status & RSV_RECEIVED_OK) && rxlen <= ENC28J60_MAXFRAME ) {
		rxlen -= ENC28J60_SIZE_CRC;
		drvEnc28j60_bufferRead(packet->payload, rxlen);
		err = ERR_OK;
	} else {
		err = ERR_IF;
	}

	// Set Rx read pointer to next packet (must be ODD)
	if (((s_enc28j60_rxrdpt - 1) < ENC28J60_RXSTART) || ((s_enc28j60_rxrdpt - 1) > ENC28J60_RXEND)) {
		drvEnc28j60_wcr16(ERXRDPT, ENC28J60_RXEND);
	} else {
		drvEnc28j60_wcr16(ERXRDPT, s_enc28j60_rxrdpt - 1);
	}
	// Decrement the packet counter indicate we are done with this packet
	drvEnc28j60_bfs(ECON2, ECON2_PKTDEC);
	packet->length = rxlen;

	return err;
}

/*******************************************************************************
 * @brief   ASSERT() functions.
 *
 *
 * @file    massert.c
 * @author  pleyman ()
 * @date    2013-02-25
 * @version 1.0
 *
 * @since   2013-02-25 Initial version.
 ******************************************************************************/

#ifdef  USE_MASSERT

void massert(unsigned char * apFile, unsigned long line) {

	while (1) {} ;
}

#endif /* USE_MASSERT */

