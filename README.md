# EtherLib
Introducción:

Con el espíritu de adquirir conocimientos sobre la llamada "pila TCP/IP" se me ocurrió la idea de investigar, pero ir creando mientras obtenía información, lo que es el sistema de intercambio de paquetes entre computadoreas.
Dado que el realizar un sistema operatvo completo no me fué posible, solo logré que corrieran procesos en paralelo con un microkernel que cree hace algún tiempo, me dispuse a crear solo una librería que con llamadas sencillas que pudiera dotar a alguna placa con procesador ARM, de conectividad IP.
Lo primero fué adoptar una placa base para el proyecto, lo que luego de investigar un poco y con el consejo de Water Adad (un amigazo), compré una placa de nobre stm32f4discovery. Esta no cuenta con adaptador de red, pero en su interior tiene un potente procesador de 32 bits que puede correr hasta 168 Mhz (stm32f407vg), puertos digitales de entrada y salida, I2C, USART, conversores analógicos a digital y PWM.
Una gran incorporación a esta placa es el circuito integrado stlink/2 que nos permite grabar nuestro programa en su interior, como así tambien realizar depuración en linea.
Para solucionar la adaptación a red, compré un adaptador de nombre enc28j60, este es el mas económico que pude ver, pero con una contra, no encontre facilmente un código para su manejo, hasta que di con la web de Patrick Leyman (http://patrickleyman.be/blog/). Allí es donde encontré el código que permitía manejar correctamente el adaptador. Además el implemetó un bosquejo de lo que sería el manejo de la pila TCP/IP, pero como lo que quiero es entender a fondo el funcionamiento de la pila, eliminé este código así quedaba lo mas limpio y liviano posible.

Objetivo:

Como objetivo general propongo que la librería en su versión 1.0 pueda manejar protocolos ARP, ICMP y TCP todos estos entrantes con archivos de transferencia sin fragmentar.
Lo que especifico en la primera línea es que intento que sea funcional primero, porque entrar en la fragmentación para enviar y recibir archivos mas grandes supone algo mas de tiempo y creo que implementar primero una librería básica es mejor para aprender. También con la palabra entrante, limito la aplicación a que funcione inicialmente como servidor, que habilite los puertos y permita conexiones entrantes, logicamnete que también se conecte mediante TCP para enviar archivos pero que no sea quien tire la primera piedra...
Dejaremos esa puerta abierta para la versión 2

Avences:

Esta es la versión 0.7
Hasta hoy implementé el del protocolo ARP lo básico para que responda con la IP asignada a la placa, por lo que en una red ethernet contestará este tipo de mensaje.
Como segundo paso implementé también el servicio ICMP para que conteste los paquetes eco, de esta manera al conectar el conjunto placa base-enc28j60 con un cable de red a una PC nos retornará el famoso PING.
El sistema realiza la conexión en tres pasos llamada "three way handshake" deTCP
Si intentamos ver cualquier página web, por ejemplo "http://10.0.0.31/index.html" nos retorna el error 404 de http! ¿Genial no?

Inicio:

 - Hardware

Para iniciar debemos tener una placa stm32f4discovery, cable de conexión USB y placa enc28j60 (esta última la adquirí en Openhacks.)
Para conectar la placa ST a la enc28j60 se deben cablear los siguientes pines:

SPI1 SCK  PA05 -> ENC28J60(SCK)

SPI1 MISO PA06 -> ENC28J60(SO)

SPI1 MOSI PA07 -> ENC28J60(SI)

SPI1 NSS  PA04 -> ENC28J60(CS)


 - Software

Como sistema operativo utilizo Debian GNU/Linux 8. Dado que se me rompió el dísco rígido y no pude recuperar nada, instalé esta versión de cero, y la sorpersa mas grande es que el compilador, GNU para ARM GCC está disponible desde los repositorios como gcc-arm-none-eabi.
Tambien necesario es el software de Texane st-link, este se utiliza para grabar el programa en nuestra placa ST y el st-util que es un servidor para realizar depuración desde el gdb-arm-none-eabi en el puerto 4242.

