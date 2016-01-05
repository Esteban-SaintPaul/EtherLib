/*******************************************************************************
 * @brief   stm32f4xx SPI interface for ENC28J60 Ethernet controller.
 *
 *
 * @file    drvEnc28j60.h
 * @author  masu (masu@noemail.non)
 * @date    2013-02-25
 * @version 1.0
 *
 * @note    This is a note.
 *
 * @since   2013-02-13 Initial version.
 ******************************************************************************/

#ifndef __ERR_H__
#define __ERR_H__

#include <stdint.h>

// Error structures
typedef int8_t err_t;

#define ERR_OK						0    // No error, everything OK.
#define ERR_MEM					-1    // Out of memory error.
#define ERR_BUF					-2    // Buffer error.
#define ERR_TIMEOUT			-3    // Timeout.
#define ERR_RTE					-4    // Routing problem.
#define ERR_INPROGRESS	-5    // Operation in progress.
#define ERR_VAL					-6    // Illegal value.
#define ERR_WOULDBLOCK	-7    // Operation would block.
#define ERR_USE					-8    // Address in use.
#define ERR_ISCONN				-9    // Already connected.

#define ERR_ABRT					-10   // Connection aborted.
#define ERR_RST					-11   // Connection reset.
#define ERR_CLSD					-12   // Connection closed.
#define ERR_CONN				-13   // Not connected.

#define ERR_ARG					-14   // Illegal argument.
#define ERR_IF						-15   // Low-level error.

#endif /* __ERR_H__ */

#ifndef __PBUF_H__
#define __PBUF_H__

#define PBUF_MAX_ELEMENTS		8
/*
enum buffer_state {
	PBUF_FREE, PBUF_OCCUPIED
};
*/
typedef struct pbuf {
//	enum buffer_state state; // State of the buffer
	uint8_t payload[1518]; // Actual packet buffer is 1500 bytes + 18 bytes
	uint16_t length; // Packet length
} pbuf_t;

#endif /* __PBUF_H__ */


#ifndef __DRV_ENC28J60_H__
#define __DRV_ENC28J60_H__

#include "stm32f4xx_gpio.h"

/* SPIx Communication Interface */
/*
 * SPI1 SCK  PA05 -> ENC28J60(SCK)
 * SPI1 MISO PA06 -> ENC28J60(SO)
 * SPI1 MOSI PA07 -> ENC28J60(SI)
 * SPI1 NSS  PA04 -> ENC28J60(CS)
 */

#define SPIx												SPI1
#define SPIx_CLK										RCC_APB2Periph_SPI1
#define SPIx_CLK_INIT								RCC_APB2PeriphClockCmd
#define SPIx_IRQn										SPI1_IRQn
#define SPIx_IRQHANDLER						SPI1_IRQHandler

#define SPIx_SCK_PIN								GPIO_Pin_5
#define SPIx_SCK_GPIO_PORT					GPIOA
#define SPIx_SCK_GPIO_CLK						RCC_AHB1Periph_GPIOA
#define SPIx_SCK_SOURCE						GPIO_PinSource5
#define SPIx_SCK_AF									GPIO_AF_SPI1

#define SPIx_MISO_PIN								GPIO_Pin_6
#define SPIx_MISO_GPIO_PORT				GPIOA
#define SPIx_MISO_GPIO_CLK					RCC_AHB1Periph_GPIOA
#define SPIx_MISO_SOURCE						GPIO_PinSource6
#define SPIx_MISO_AF								GPIO_AF_SPI1

#define SPIx_MOSI_PIN								GPIO_Pin_7
#define SPIx_MOSI_GPIO_PORT				GPIOA
#define SPIx_MOSI_GPIO_CLK					RCC_AHB1Periph_GPIOA
#define SPIx_MOSI_SOURCE						GPIO_PinSource7
#define SPIx_MOSI_AF								GPIO_AF_SPI1

#define SPIx_CS_PIN									GPIO_Pin_4
#define SPIx_CS_GPIO_PORT					GPIOA
#define SPIx_CS_GPIO_CLK						RCC_AHB1Periph_GPIOA

#define ENC28J60_RESET_PIN					GPIO_Pin_3
#define ENC28J60_RESET_GPIO_PORT		GPIOA
#define ENC28J60_RESET_GPIO_CLK		RCC_AHB1Periph_GPIOA

#define ENC28J60_INT_PIN						GPIO_Pin_1
#define ENC28J60_INT_GPIO_PORT			GPIOA
#define ENC28J60_INT_GPIO_CLK				RCC_AHB1Periph_GPIOA

/*!< Buffer partitions */
#define ENC28J60_BUFSTART	0
#define ENC28J60_BUFSIZE	0x2000
#define ENC28J60_BUFEND		(ENC28J60_BUFSIZE-1)

#define ENC28J60_MINFRAME	64
#define ENC28J60_MAXFRAME	1518

#define ENC28J60_RXSTART	0 /*!< errata :: Receive buffer must start at 0000h */
#define ENC28J60_RXEND		(4*ENC28J60_MAXFRAME-1)
#define ENC28J60_TXSTART	ENC28J60_RXEND
#define ENC28J60_TXEND		(ENC28J60_BUFSIZE-1)

#define ENC28J60_SIZE_CRC	4

/*!< Instruction set */
#define ENC28J60_SPI_RCR	0x00	/*!< Read Control Register */
#define ENC28J60_SPI_RBM	0x3A	/*!< Read Buffer Memory */
#define ENC28J60_SPI_WCR	0x40	/*!< Write Control Register */
#define ENC28J60_SPI_WBM	0x7A	/*!< Write Buffer Memory */
#define ENC28J60_SPI_BFS	0x80	/*!< Bit Field Set */
#define ENC28J60_SPI_BFC	0xA0	/*!< Bit Field Clear */
#define ENC28J60_SPI_SR		0xFF	/*!< System Reset Command */

/*!< Mask */
#define ENC28J60_ADDR_MASK	0x1F
#define ENC28J60_BANK_MASK	0x60

#define ENC28J60_BANK0		0x00
#define ENC28J60_BANK1		0x20
#define ENC28J60_BANK2		0x40
#define ENC28J60_BANK3		0x60
#define ENC28J60_MACMII		0x80

/*
 * Main registers
 */
#define EIE 				(0x1B | ENC28J60_BANK0)
#define EIR 				(0x1C | ENC28J60_BANK0)
#define ESTAT 				(0x1D | ENC28J60_BANK0)
#define ECON2 				(0x1E | ENC28J60_BANK0)
#define ECON1 				(0x1F | ENC28J60_BANK0)

// Buffer read pointer
#define ERDPTL 				(0x00 | ENC28J60_BANK0)
#define ERDPTH 				(0x01 | ENC28J60_BANK0)
#define ERDPT				ERDPTL

// Buffer write pointer
#define EWRPTL 				(0x02 | ENC28J60_BANK0)
#define EWRPTH 				(0x03 | ENC28J60_BANK0)
#define EWRPT				EWRPTL

// Tx packet start pointer
#define ETXSTL 				(0x04 | ENC28J60_BANK0)
#define ETXSTH 				(0x05 | ENC28J60_BANK0)
#define ETXST				ETXSTL

// Tx packet end pointer
#define ETXNDL 				(0x06 | ENC28J60_BANK0)
#define ETXNDH 				(0x07 | ENC28J60_BANK0)
#define ETXND				ETXNDL

// Rx FIFO start pointer
#define ERXSTL 				(0x08 | ENC28J60_BANK0)
#define ERXSTH 				(0x09 | ENC28J60_BANK0)
#define ERXST				ERXSTL

// Rx FIFO end pointer
#define ERXNDL 				(0x0A | ENC28J60_BANK0)
#define ERXNDH 				(0x0B | ENC28J60_BANK0)
#define ERXND				ERXNDL

// Rx FIFO read pointer
#define ERXRDPTL 			(0x0C | ENC28J60_BANK0)
#define ERXRDPTH 			(0x0D | ENC28J60_BANK0)
#define ERXRDPT				ERXRDPTL

// Rx FIFO write pointer
#define ERXWRPTL 			(0x0E | ENC28J60_BANK0)
#define ERXWRPTH 			(0x0F | ENC28J60_BANK0)
#define ERXWRPT				ERXWRPTL

// DMA source block start pointer
#define EDMASTL 			(0x10 | ENC28J60_BANK0)
#define EDMASTH 			(0x11 | ENC28J60_BANK0)
#define EDMAST				EDMASTL

// DMA source block end pointer
#define EDMANDL 			(0x12 | ENC28J60_BANK0)
#define EDMANDH 			(0x13 | ENC28J60_BANK0)
#define EDMAND				EDMANDL

// DMA destination pointer
#define EDMADSTL 			(0x14 | ENC28J60_BANK0)
#define EDMADSTH 			(0x15 | ENC28J60_BANK0)
#define	EDMADST				EDMADSTL

// DMA checksum
#define EDMACSL 			(0x16 | ENC28J60_BANK0)
#define EDMACSH 			(0x17 | ENC28J60_BANK0)
#define EDMACS				EDMACSL

// Hash table registers
#define EHT0 				(0x00 | ENC28J60_BANK1)
#define EHT1 				(0x01 | ENC28J60_BANK1)
#define EHT2 				(0x02 | ENC28J60_BANK1)
#define EHT3 				(0x03 | ENC28J60_BANK1)
#define EHT4 				(0x04 | ENC28J60_BANK1)
#define EHT5 				(0x05 | ENC28J60_BANK1)
#define EHT6 				(0x06 | ENC28J60_BANK1)
#define EHT7 				(0x07 | ENC28J60_BANK1)

// Pattern match registers
#define EPMM0 				(0x08 | ENC28J60_BANK1)
#define EPMM1 				(0x09 | ENC28J60_BANK1)
#define EPMM2 				(0x0A | ENC28J60_BANK1)
#define EPMM3 				(0x0B | ENC28J60_BANK1)
#define EPMM4 				(0x0C | ENC28J60_BANK1)
#define EPMM5 				(0x0D | ENC28J60_BANK1)
#define EPMM6 				(0x0E | ENC28J60_BANK1)
#define EPMM7 				(0x0F | ENC28J60_BANK1)
#define EPMCSL 				(0x10 | ENC28J60_BANK1)
#define EPMCSH 				(0x11 | ENC28J60_BANK1)
#define EPMOL 				(0x14 | ENC28J60_BANK1)
#define EPMOH 				(0x15 | ENC28J60_BANK1)

// Wake-on-LAN interrupt registers
#define EWOLIE 				(0x16 | ENC28J60_BANK1)
#define EWOLIR 				(0x17 | ENC28J60_BANK1)

// Receive filters mask
#define ERXFCON 			(0x18 | ENC28J60_BANK1)

// Packet counter
#define EPKTCNT 			(0x19 | ENC28J60_BANK1)

// MAC control registers
#define MACON1 				(0x00 | ENC28J60_BANK2 | ENC28J60_MACMII)
#define MACON2 				(0x01 | ENC28J60_BANK2 | ENC28J60_MACMII)
#define MACON3 				(0x02 | ENC28J60_BANK2 | ENC28J60_MACMII)
#define MACON4 				(0x03 | ENC28J60_BANK2 | ENC28J60_MACMII)

// MAC Back-to-back gap
#define MABBIPG 			(0x04 | ENC28J60_BANK2 | ENC28J60_MACMII)

// MAC Non back-to-back gap
#define MAIPGL 				(0x06 | ENC28J60_BANK2 | ENC28J60_MACMII)
#define MAIPGH 				(0x07 | ENC28J60_BANK2 | ENC28J60_MACMII)

// Collision window & rexmit timer
#define MACLCON1 			(0x08 | ENC28J60_BANK2 | ENC28J60_MACMII)
#define MACLCON2 			(0x09 | ENC28J60_BANK2 | ENC28J60_MACMII)

// Max frame length
#define MAMXFLL 			(0x0A | ENC28J60_BANK2 | ENC28J60_MACMII)
#define MAMXFLH 			(0x0B | ENC28J60_BANK2 | ENC28J60_MACMII)
#define MAMXFL				MAMXFLL

// MAC-PHY support register
#define MAPHSUP 			(0x0D | ENC28J60_BANK2 | ENC28J60_MACMII)
#define MICON 				(0x11 | ENC28J60_BANK2 | ENC28J60_MACMII)

// MII registers
#define MICMD 				(0x12 | ENC28J60_BANK2 | ENC28J60_MACMII)
#define MIREGADR 			(0x14 | ENC28J60_BANK2 | ENC28J60_MACMII)

#define MIWRL 				(0x16 | ENC28J60_BANK2 | ENC28J60_MACMII)
#define MIWRH 				(0x17 | ENC28J60_BANK2 | ENC28J60_MACMII)
#define MIWR				MIWRL

#define MIRDL 				(0x18 | ENC28J60_BANK2 | ENC28J60_MACMII)
#define MIRDH 				(0x19 | ENC28J60_BANK2 | ENC28J60_MACMII)
#define MIRD				MIRDL

// MAC Address
#define MAADR1 				(0x00 | ENC28J60_BANK3 | ENC28J60_MACMII)
#define MAADR0 				(0x01 | ENC28J60_BANK3 | ENC28J60_MACMII)
#define MAADR3 				(0x02 | ENC28J60_BANK3 | ENC28J60_MACMII)
#define MAADR2 				(0x03 | ENC28J60_BANK3 | ENC28J60_MACMII)
#define MAADR5 				(0x04 | ENC28J60_BANK3 | ENC28J60_MACMII)
#define MAADR4 				(0x05 | ENC28J60_BANK3 | ENC28J60_MACMII)

// Built-in self-test
#define EBSTSD 				(0x06 | ENC28J60_BANK3)
#define EBSTCON 			(0x07 | ENC28J60_BANK3)
#define EBSTCSL 			(0x08 | ENC28J60_BANK3)
#define EBSTCSH 			(0x09 | ENC28J60_BANK3)
#define MISTAT 				(0x0A | ENC28J60_BANK3 | ENC28J60_MACMII)

// Revision ID
#define EREVID 				(0x12 | ENC28J60_BANK3)

// Clock output control register
#define ECOCON 				(0x15 | ENC28J60_BANK3)

// Flow control registers
#define EFLOCON 			(0x17 | ENC28J60_BANK3)
#define EPAUSL 				(0x18 | ENC28J60_BANK3)
#define EPAUSH 				(0x19 | ENC28J60_BANK3)

// PHY registers
#define PHCON1 				0x00
#define PHSTAT1 			0x01
#define PHID1 				0x02
#define PHID2 				0x03
#define PHCON2 				0x10
#define PHSTAT2 			0x11
#define PHIE 				0x12
#define PHIR 				0x13
#define PHLCON 				0x14

// EIE
#define EIE_INTIE			0x80
#define EIE_PKTIE			0x40
#define EIE_DMAIE			0x20
#define EIE_LINKIE			0x10
#define EIE_TXIE			0x08
#define EIE_WOLIE			0x04
#define EIE_TXERIE			0x02
#define EIE_RXERIE			0x01

// EIR
#define EIR_PKTIF			0x40
#define EIR_DMAIF			0x20
#define EIR_LINKIF			0x10
#define EIR_TXIF			0x08
#define EIR_WOLIF			0x04
#define EIR_TXERIF			0x02
#define EIR_RXERIF			0x01

// ESTAT
#define ESTAT_INT			0x80
#define ESTAT_LATECOL		0x10
#define ESTAT_RXBUSY		0x04
#define ESTAT_TXABRT		0x02
#define ESTAT_CLKRDY		0x01

// ECON2
#define ECON2_AUTOINC		0x80
#define ECON2_PKTDEC		0x40
#define ECON2_PWRSV			0x20
#define ECON2_VRPS			0x08

// ECON1
#define ECON1_TXRST			0x80
#define ECON1_RXRST			0x40
#define ECON1_DMAST			0x20
#define ECON1_CSUMEN		0x10
#define ECON1_TXRTS			0x08
#define ECON1_RXEN			0x04
#define ECON1_BSEL1			0x02
#define ECON1_BSEL0			0x01

// EWOLIE
#define EWOLIE_UCWOLIE		0x80
#define EWOLIE_AWOLIE		0x40
#define EWOLIE_PMWOLIE		0x10
#define EWOLIE_MPWOLIE		0x08
#define EWOLIE_HTWOLIE		0x04
#define EWOLIE_MCWOLIE		0x02
#define EWOLIE_BCWOLIE		0x01

// EWOLIR
#define EWOLIR_UCWOLIF		0x80
#define EWOLIR_AWOLIF		0x40
#define EWOLIR_PMWOLIF		0x10
#define EWOLIR_MPWOLIF		0x08
#define EWOLIR_HTWOLIF		0x04
#define EWOLIR_MCWOLIF		0x02
#define EWOLIR_BCWOLIF		0x01

// ERXFCON
#define ERXFCON_UCEN		0x80
#define ERXFCON_ANDOR		0x40
#define ERXFCON_CRCEN		0x20
#define ERXFCON_PMEN		0x10
#define ERXFCON_MPEN		0x08
#define ERXFCON_HTEN		0x04
#define ERXFCON_MCEN		0x02
#define ERXFCON_BCEN		0x01

// MACON1
#define MACON1_LOOPBK		0x10
#define MACON1_TXPAUS		0x08
#define MACON1_RXPAUS		0x04
#define MACON1_PASSALL		0x02
#define MACON1_MARXEN		0x01

// MACON2
#define MACON2_MARST		0x80
#define MACON2_RNDRST		0x40
#define MACON2_MARXRST		0x08
#define MACON2_RFUNRST		0x04
#define MACON2_MATXRST		0x02
#define MACON2_TFUNRST		0x01

// MACON3
#define MACON3_PADCFG2		0x80
#define MACON3_PADCFG1		0x40
#define MACON3_PADCFG0		0x20
#define MACON3_TXCRCEN		0x10
#define MACON3_PHDRLEN		0x08
#define MACON3_HFRMEN		0x04
#define MACON3_FRMLNEN		0x02
#define MACON3_FULDPX		0x01

// MACON4
#define MACON4_DEFER		0x40
#define MACON4_BPEN			0x20
#define MACON4_NOBKOFF		0x10
#define MACON4_LONGPRE		0x02
#define MACON4_PUREPRE		0x01

// MAPHSUP
#define MAPHSUP_RSTINTFC	0x80
#define MAPHSUP_RSTRMII		0x08

// MICON
#define MICON_RSTMII		0x80

// MICMD
#define MICMD_MIISCAN		0x02
#define MICMD_MIIRD			0x01

// EBSTCON
#define EBSTCON_PSV2		0x80
#define EBSTCON_PSV1		0x40
#define EBSTCON_PSV0		0x20
#define EBSTCON_PSEL		0x10
#define EBSTCON_TMSEL1		0x08
#define EBSTCON_TMSEL0		0x04
#define EBSTCON_TME			0x02
#define EBSTCON_BISTST		0x01

// MISTAT
#define MISTAT_NVALID		0x04
#define MISTAT_SCAN			0x02
#define MISTAT_BUSY			0x01

// ECOCON
#define ECOCON_COCON2		0x04
#define ECOCON_COCON1		0x02
#define ECOCON_COCON0		0x01

// EFLOCON
#define EFLOCON_FULDPXS		0x04
#define EFLOCON_FCEN1		0x02
#define EFLOCON_FCEN0		0x01

// PHCON1
#define PHCON1_PRST			0x8000
#define PHCON1_PLOOPBK		0x4000
#define PHCON1_PPWRSV		0x0800
#define PHCON1_PDPXMD		0x0100

// PHSTAT1
#define PHSTAT1_PFDPX		0x1000
#define PHSTAT1_PHDPX		0x0800
#define PHSTAT1_LLSTAT		0x0004
#define PHSTAT1_JBSTAT		0x0002

// PHCON2
#define PHCON2_FRCLNK		0x4000
#define PHCON2_TXDIS		0x2000
#define PHCON2_JABBER		0x0400
#define PHCON2_HDLDIS		0x0100

// PHSTAT2
#define PHSTAT2_TXSTAT		0x2000
#define PHSTAT2_RXSTAT		0x1000
#define PHSTAT2_COLSTAT		0x0800
#define PHSTAT2_LSTAT		0x0400
#define PHSTAT2_DPXSTAT		0x0200
#define PHSTAT2_PLRITY		0x0010

// PHIE
#define PHIE_PLNKIE			0x0010
#define PHIE_PGEIE			0x0002

// PHIR
#define PHIR_PLNKIF			0x0010
#define PHIR_PGIF			0x0004

// PHLCON
#define PHLCON_LACFG3		0x0800
#define PHLCON_LACFG2		0x0400
#define PHLCON_LACFG1		0x0200
#define PHLCON_LACFG0		0x0100
#define PHLCON_LBCFG3		0x0080
#define PHLCON_LBCFG2		0x0040
#define PHLCON_LBCFG1		0x0020
#define PHLCON_LBCFG0		0x0010
#define PHLCON_LFRQ1		0x0008
#define PHLCON_LFRQ0		0x0004
#define PHLCON_STRCH		0x0002

#define PHLCON_LEDA_LINK_STATUS		(PHLCON_LACFG2)
#define PHLCON_LEDB_TXRX_ACTIVITY	(PHLCON_LBCFG2 | PHLCON_LBCFG1 | PHLCON_LBCFG0)

#define REQUIRE_BANK_SWITCH(addr)	(((addr) & ENC28J60_ADDR_MASK) < EIE)

// Receive status vectors
#define RSV_RECEIVED_OK		0x0080

#define IFNAME0 'e'
#define IFNAME1 'n'

err_t drvEnc28j60_init(uint8_t *mac);
err_t drvEnc28j60_packetSend(pbuf_t *packet);
err_t drvEnc28j60_packetRecv(pbuf_t *packet);

#endif /* __DRV_ENC28J60_H__ */

