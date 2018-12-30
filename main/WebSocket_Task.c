#include "WebSocket_Task.h"
#include "debug.h"
#include "esp_system.h"
#include "esp_log.h"
#include "lwip/opt.h"


#ifdef __cplusplus
extern "C"
{
#endif

#include "freertos/FreeRTOS.h"
#include "hwcrypto/sha.h"
#include "esp_system.h"
#include "wpa2/utils/base64.h"
#include <string.h>
#include <stdlib.h>
#include <string.h>
#include <stdlib.h>
#include "esp_log.h"
#include "freertos/timers.h"

#ifdef __cplusplus
}
#endif
/*************************************************************/

#define WS_PORT 9998	   /**< \brief TCP Port for the Server*/
#define WS_CLIENT_KEY_L 24 /**< \brief Length of the Client Key*/
#define SHA1_RES_L 20	  /**< \brief SHA1 result*/
#define WS_STD_LEN 125	 /**< \brief Maximum Length of standard length frames*/
#define WS_SPRINTF_ARG_L 4 /**< \brief Length of sprintf argument for string (%.*s)*/

/** \brief Opcode according to RFC 6455*/
typedef enum
{
	WS_OP_CON = 0x0, /*!< Continuation Frame*/
	WS_OP_TXT = 0x1, /*!< Text Frame*/
	WS_OP_BIN = 0x2, /*!< Binary Frame*/
	WS_OP_CLS = 0x8, /*!< Connection Close Frame*/
	WS_OP_PIN = 0x9, /*!< Ping Frame*/
	WS_OP_PON = 0xa  /*!< Pong Frame*/
} WS_OPCODES;


//reference to the RX queue
extern QueueHandle_t WebSocket_rx_queue;

//Reference to open websocket connection
static struct netconn *WS_conn = NULL;

const char WS_sec_WS_keys[] = "Sec-WebSocket-Key:";
const char WS_sec_conKey[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const char WS_srv_hs[] =
	"HTTP/1.1 101 Switching Protocols \r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %.*s\r\n\r\n";

static const char *SOCKET_TAG = (char*)"WEBSOCKET";


err_t WS_write_data(char *p_data, size_t length)
{

	//check if we have an open connection
	if (WS_conn == NULL){
		return ERR_CONN;
	}

	//currently only frames with a payload length <WS_STD_LEN are supported
	if (length > WS_STD_LEN){
		return ERR_VAL;
	}

	//netconn_write result buffer
	err_t result;

	//prepare header
	WS_frame_header_t hdr;
	hdr.FIN = 0x1;
	hdr.payload_length = length;
	hdr.mask = 0;
	hdr.reserved = 0;
	hdr.opcode = WS_OP_TXT;

	//send header
	result = netconn_write(WS_conn, &hdr, sizeof(WS_frame_header_t),
						   NETCONN_COPY);

	//check if header was send
	if (result != ERR_OK)
	{
		return result;
	}
	else
	{
		ESP_LOGI(SOCKET_TAG, "NETCONN WRITE ERR :%d", result);
	}

	//send payload
	return netconn_write(WS_conn, p_data, length, NETCONN_COPY);
}

err_t WS_write_data_keep_alive(char *p_data, size_t length)
{

	//check if we have an open connection
	if (WS_conn == NULL)
		return ERR_CONN;

	//currently only frames with a payload length <WS_STD_LEN are supported
	if (length > WS_STD_LEN)
		return ERR_VAL;

	//netconn_write result buffer
	err_t result;

	//prepare header
	WS_frame_header_t hdr;
	hdr.FIN = 0x1;
	hdr.payload_length = length;
	hdr.mask = 0;
	hdr.reserved = 0;
	hdr.opcode = WS_OP_PON;

	//send header
	result = netconn_write(WS_conn, &hdr, sizeof(WS_frame_header_t),
						   NETCONN_COPY);

	//check if header was send
	if (result != ERR_OK)
		return result;

	//send payload
	return netconn_write(WS_conn, p_data, length, NETCONN_COPY);
}

static void ws_server_netconn_serve(struct netconn *conn)
{

	//Netbuf
	struct netbuf *inbuf;

	//message buffer
	char *buf;

	//pointer to buffer (multi purpose)
	char *p_buf;

	//Pointer to SHA1 input
	char *p_SHA1_Inp;

	//Pointer to SHA1 result
	char *p_SHA1_result;

	//multi purpose number buffer
	uint16_t i;

	//will point to payload (send and receive
	char *p_payload;

	//Frame header pointer
	WS_frame_header_t *p_frame_hdr;

	//allocate memory for SHA1 input
	p_SHA1_Inp = (char *)heap_caps_malloc(
		WS_CLIENT_KEY_L + sizeof(WS_sec_conKey), MALLOC_CAP_8BIT);
	
	// check null pointer
	if(p_SHA1_Inp ==  NULL){
		ESP_LOGE(SOCKET_TAG, "failed to allocate memory : p_SHA1_Inp\n");	
		esp_restart();
	}

	//TODO: allocate memory for SHA1 result: 
	p_SHA1_result = (char *)heap_caps_malloc(SHA1_RES_L, MALLOC_CAP_8BIT);

	// check null pointer
	if(p_SHA1_result ==  NULL){
		ESP_LOGE(SOCKET_TAG, "failed to allocate memory : p_SHA1_result\n");	
		esp_restart();
	}

	//Check if malloc suceeded
	if ((p_SHA1_Inp != NULL) && (p_SHA1_result != NULL))
	{
		netconn_set_recvtimeout(conn, 10000); // receive timeout in milliseconds

		err_t error_code = netconn_recv(conn, &inbuf);
		//receive handshake request

		if (error_code == ERR_OK)
		{
		
			//read buffer
			err_t netbuf_data_err = netbuf_data(inbuf, (void **)&buf, &i);
			
			ESP_LOGI(SOCKET_TAG, "netbuf_data_err code : %d\n", netbuf_data_err);
			
			//write static key into SHA1 Input
			for (i = 0; i < sizeof(WS_sec_conKey); i++)
				p_SHA1_Inp[i + WS_CLIENT_KEY_L] = WS_sec_conKey[i];

			//find Client Sec-WebSocket-Key: p_buf is pointer to client key
			p_buf = strstr(buf, WS_sec_WS_keys);

			//check if needle "Sec-WebSocket-Key:" was found
			if (p_buf != NULL)
			{

				//get Client Key
				for (i = 0; i < WS_CLIENT_KEY_L; i++)
					p_SHA1_Inp[i] = *(p_buf + sizeof(WS_sec_WS_keys) + i);

				// calculate hash
				esp_sha(SHA1, (unsigned char *)p_SHA1_Inp, strlen(p_SHA1_Inp),
						(unsigned char *)p_SHA1_result);

				
				//hex to base64
				p_buf = (char *)base64_encode((unsigned char *)p_SHA1_result,
											  SHA1_RES_L, (size_t *)&i);

				netbuf_delete(inbuf); //we dont require inbuf now. as buf and p_buf are not related to it now
				
				buf = NULL;
				
				inbuf = NULL;
				
				//free SHA1 input
				heap_caps_free(p_SHA1_Inp);

				//free SHA1 result
				heap_caps_free(p_SHA1_result);
				//allocate memory for handshake
				p_payload = (char *)heap_caps_malloc(
					sizeof(WS_srv_hs) + i - WS_SPRINTF_ARG_L,
					MALLOC_CAP_8BIT);

				// check null pointer
				if(p_payload ==  NULL){
					ESP_LOGE(SOCKET_TAG, "failed to allocate memory : p_payload\n");	
					esp_restart();
				}
				
				//check if malloc suceeded
				if (p_payload != NULL)
				{

					//prepare handshake
					sprintf(p_payload, WS_srv_hs, i - 1, p_buf);

					//send handshake
					netconn_write(conn, p_payload, strlen(p_payload),
								  NETCONN_COPY);

					//free base 64 encoded sec key
					heap_caps_free(p_buf);

					//free handshake memory
					heap_caps_free(p_payload);
					
					//set pointer to open WebSocket connection
					WS_conn = conn;
					/***********************************************Websocket connect**********************************/
					ESP_LOGI(SOCKET_TAG, "Websocket Connected :) ");
					
					err_t netconn_recv_err;
					//Wait for new data
					do
					{
						netconn_recv_err = netconn_recv(conn, &inbuf);

						if (netconn_recv_err == ESP_OK)
						{
							//read data from inbuf
							netbuf_data(inbuf, (void **)&buf, &i);

							//get pointer to header
							p_frame_hdr = (WS_frame_header_t *)buf;

							//check if clients wants to close the connection
							if (p_frame_hdr->opcode == WS_OP_CLS)
							{
								/*****************************************socket disconnected****************************/
								ESP_LOGE(SOCKET_TAG, "Websocket disconnected by client:) \n");
								
								netbuf_delete(inbuf);
								break;
							}

							//check clients send the ping opcode
							if (p_frame_hdr->opcode == WS_OP_PIN)
							{

								static char keep_alive[] = "";
								ESP_LOGE(SOCKET_TAG, "Ping received :) ");
								WS_write_data_keep_alive(keep_alive,
														 strlen(keep_alive));
								ESP_LOGI(SOCKET_TAG, "Pong send :) ");


								if (p_frame_hdr->payload_length > 0)
								{
									ESP_LOGI(SOCKET_TAG, "Ping payload = %d\n", p_frame_hdr->payload_length);
									configASSERT((p_frame_hdr->payload_length) > 0);
								}else{
									//free input buffer
									netbuf_delete(inbuf);
									inbuf=NULL;
									continue;
								}
							}

							//get payload length
							if (p_frame_hdr->payload_length <= WS_STD_LEN)
							{

								//get beginning of mask or payload
								p_buf = (char *)&buf[sizeof(WS_frame_header_t)];

								//check if content is masked
								if (p_frame_hdr->mask)
								{

									//allocate memory for decoded message
									p_payload = (char *)heap_caps_malloc(
										p_frame_hdr->payload_length + 1,
										MALLOC_CAP_8BIT);

									//check if malloc succeeded
									if (p_payload != NULL)
									{

										//decode playload
										for (i = 0; i < p_frame_hdr->payload_length;
											 i++)
											p_payload[i] = (p_buf + WS_MASK_L)[i] ^ p_buf[i % WS_MASK_L];

										//add 0 terminator
										p_payload[p_frame_hdr->payload_length] = 0;
									}
								}
								else
								{
									//content is not masked
									p_payload = p_buf;
								}
								//do stuff
								if ((p_payload != NULL) && (p_frame_hdr->opcode == WS_OP_TXT))
								{

									//prepare FreeRTOS message
									WebSocket_frame_t __ws_frame;
									__ws_frame.conenction = conn;
									__ws_frame.frame_header = *p_frame_hdr;
									__ws_frame.payload_length =
										p_frame_hdr->payload_length;
									__ws_frame.p_Payload = p_payload;

									add_to_websocket_queue(WebSocket_rx_queue, __ws_frame);
								}
								else
								{
									configASSERT(p_payload != NULL);        // only for debug
								}

								//free payload buffer (in this demo done by the receive task)
								//if (p_frame_hdr->mask && p_payload != NULL)
								//free(p_payload);

							} //p_frame_hdr->payload_length<126

							//free input buffer
							netbuf_delete(inbuf);
							inbuf = NULL;
						}
						else
						{
							ESP_LOGI(SOCKET_TAG, "netconn_recv_err : %d\n", netconn_recv_err);
						}

						if (inbuf != NULL)
						{
							//we need to free inbuf
							free(inbuf);
						}
					} while (netconn_recv_err == ERR_OK);

					//while(netconn_recv(conn, &inbuf)==ERR_OK)
				} //p_payload!=NULL
			}	 //check if needle "Sec-WebSocket-Key:" was found
		}		  //receive handshake
		else
		{
			ESP_LOGE(SOCKET_TAG, " Error code = %d\n", error_code);
		}
	} //p_SHA1_Inp!=NULL&p_SHA1_result!=NULL

	//release pointer to open WebSocket connection
	WS_conn = NULL;

	// Close the connection	
	err_t netconn_close_err = netconn_close(conn);
	ESP_LOGI(SOCKET_TAG, "netconn_close_err : %d\n", netconn_close_err);
	//Delete connection
	err_t netconn_delete_err = netconn_delete(conn);
	ESP_LOGI(SOCKET_TAG, "netconn_delete_err : %d\n", netconn_delete_err);
}

bool add_to_websocket_queue(QueueHandle_t WebSocket_rx_queue, WebSocket_frame_t const __ws_frame)
{
	//send message
	bool is_success = xQueueGenericSend(WebSocket_rx_queue, &__ws_frame, QUEUE_FULL_WAIT_PERIOD,
										queueSEND_TO_BACK);
	if (is_success == pdTRUE)
	{
		ESP_LOGI(SOCKET_TAG, "Websocket message sent sucess");
	}
	else
	{
		ESP_LOGE(SOCKET_TAG, " Websocket message sent fail");
	}

	return is_success;
}


void ws_server(void *pvParameters)
{

	//connection references
	struct netconn *newconn;

	struct netconn *conn = netconn_new(NETCONN_TCP);
	if (conn)
	{
		err_t netconn_bind_err = netconn_bind(conn, NULL, WS_PORT);
		if (netconn_bind_err == ERR_OK)
		{
			//set up new TCP listener
			err_t netconn_listen_err = netconn_listen(conn);
			if (netconn_listen_err == ERR_OK)
			{
				ESP_LOGI(SOCKET_TAG, "netconn listen failed");
			}
			else
			{
				ESP_LOGI(SOCKET_TAG, "netconn listen err : %d\n", netconn_listen_err);
				ESP_LOGI(SOCKET_TAG, "netconn listen failed\n");
			}
		}
		else
		{
			ESP_LOGI(SOCKET_TAG, "netconn_bind_err : %d\n", netconn_bind_err);
			ESP_LOGI(SOCKET_TAG, "netconn bind failed\n");
		}
	}

	err_t netconn_accept_err;
	//wait for connections
	do
	{
		netconn_accept_err = netconn_accept(conn, &newconn);
		if (netconn_accept_err == ERR_OK)
		{
			ws_server_netconn_serve(newconn);

		}

		else if (netconn_accept_err == ERR_TIMEOUT)
		{
			ESP_LOGI(SOCKET_TAG, "Netconn accept timeout err %d : \n", netconn_accept_err);
		}
		else
		{
			ESP_LOGI(SOCKET_TAG, "Netconn accept err %d : \n", netconn_accept_err);
		}

	} while (netconn_accept_err == ERR_OK);

	//close connection
	err_t netconn_close_err = netconn_close(conn);
	ESP_LOGI(SOCKET_TAG, "netconn_close_err : %d\n", netconn_close_err);
    //delete connection	
    err_t netconn_delete_err = netconn_delete(conn);
	ESP_LOGI(SOCKET_TAG, "netconn_delete_err : %d\n", netconn_delete_err);

}
