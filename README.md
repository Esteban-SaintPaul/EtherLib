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

Hasta hoy implementé el del protocolo ARP lo básico para que responda con la IP asignada a la placa, por lo que en una red ethernet contestará este tipo de mensaje.
Como segundo paso implementé también el servicio ICMP para que conteste los paquetes eco, de esta manera al conectar el conjunto placa base-enc28j60 con un cable de red a una PC nos retornará el famoso PING.
