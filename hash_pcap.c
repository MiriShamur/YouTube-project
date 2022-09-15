#include <net/ethernet.h> //For ether_header
#include <netinet/ip.h>   //Provides declarations for ip header
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <string.h>
#include <time.h>
#include <netinet/udp.h> //Provides declarations for udp header
#include <signal.h>
#include "hashtable.c"
#include <json-c/json.h>

#define size_malloc 99990000
int json();
void check_packet_info(const u_char *packet, struct pcap_pkthdr packet_header);
int check_ip_version(struct iphdr *iph);
transaction *create_new_transaction(struct iphdr *iph, __time_t pack_time, int size, f_tuple *tuple, int trans_id);
connection *create_new_connection(int size, struct iphdr *iph, __time_t pack_time, f_tuple *tuple);
int append_line(char *lines);
f_tuple *create_f_tupel(const u_char *packet, struct iphdr *iph);
void add_packet_to_transaction(const u_char *packet, struct iphdr *iph, connection *conn, __time_t pack_time);
void empty_the_write_to_CSV_file(char write_to_CSV_file[]);
int is_new_request(const u_char *packet, struct iphdr *iph);
int is_connection_timeout(transaction *trans, __time_t packet_time);
int add_to_hash(connection *conn);
int new_conn_and_append_to_hash(const u_char *packet, struct iphdr *iph, f_tuple *tuple, __time_t packet_time);
int is_udp(int protocol);
int check_trans(transaction *trans);
void statistics_file();
int add_new_trans_to_conn(const u_char *packet, struct iphdr *iph, __time_t packet_time, connection *conn);
int save_trans(connection *conn);
int close_hash();
int is_ser_to_cli(const u_char *packet, struct iphdr *iph);

void sig_handler(int signo)
{
   if (signo == SIGINT)
   {
      close_hash();
      printf("close\n");
      exit(0);
   }
}
int MAX_NUMBER_OF_CONNECTIONS;
int REQUEST_PACKET_THRESHOLD;
int MINIMUM_VIDEO_CONNECTION_SIZE;
int NUM_IP_BYTE;
int YouTube_PORT;
int UDP_PROTOCOL;
int VIDEO_CONNECTION_TIMEOUT;
int IPV;
int INBOUND_PACKETS_IN_RANGE_MIN;
int CONN_SIZE_CHARS;
int ZERO;

double diff_time;
uint16_t dest_port;
uint16_t source_port;
uint16_t pack_size;
int connect_id;
int pack_num;
int time_req;
char SCV_file[20] = "documentation.csv";
FILE *fp;
ht *ht_connection;
char buffer[1024];
struct json_object *parsed_json;
struct sockaddr_in source, dest;
clock_t start;
__time_t Last_packet_time;
char write_to_CSV_file[size_malloc];
char buff[20];
struct tm *ltime;
struct in_addr *addr_cli;
struct in_addr *addr_srv;
char addr_c[16];
char addr_s[16];

int main(int argc, char const *argv[])
{
   if (signal(SIGINT, sig_handler) == SIG_ERR)
      printf("\ncan't catch SIGINT\n");

   start = clock();
   ht_connection = ht_create();
   int i, j = 0;

   fp = fopen("config.json", "r");
   fread(buffer, 1024, 1, fp);
   fclose(fp);
   parsed_json = json_tokener_parse(buffer);
   json();
   connect_id = 0;
   time_req = 0;
   pack_num = 0;
   addr_cli = malloc(sizeof(struct in_addr));
   addr_srv = malloc(sizeof(struct in_addr));
   if (addr_srv == NULL || addr_cli == NULL)
   {
      return 0;
   }
   empty_the_write_to_CSV_file(write_to_CSV_file);
   sprintf(write_to_CSV_file, "Conn_id, Client_ip, Server_ip, IP_protocol, UDP_client_port, UDP_server_port, Transaction_id, Start_time, num_in_packets, num_out_packets,max_packet_size_in,min_packet_size_in, max_diff_time, min_diff_time,sum_squareln_bound_packet_time_diff,RTT\n");

   if (append_line(write_to_CSV_file) < 0)
   {
      printf("Unable to write .txt file.\n");
      return -1;
   }
   char *device;                        /* Name of device (e.g. eth0, wlan0) */
   char error_buffer[PCAP_ERRBUF_SIZE]; /* Size defined in pcap.h */
   struct timeval st_ts;
   const u_char *packet;
   struct pcap_pkthdr packet_header;
   pcap_t *handle = pcap_open_offline("capture_file.pcap", error_buffer);
   if (handle == NULL)
   {
      fprintf(stderr, "Could not open device %s: %s\n", device, error_buffer);
      return 1;
   }
   if (error_buffer == NULL)
   {
      fprintf(stderr, "\nUnable to open the file.\n");
      return 1;
   }
   packet = pcap_next(handle, &packet_header);
   while (packet)
   {
      check_packet_info(packet, packet_header);
      packet = pcap_next(handle, &packet_header);
      j++;
   }
   if (packet == NULL)
   {
      printf("No packet found.\n");
   }
   printf("\nnum packets = %d \n", j);
   printf("all time: %ld \n", clock() - start);
   pcap_close(handle);

   statistics_file();
   close_hash();
   return 0;
}
void check_packet_info(const u_char *packet, struct pcap_pkthdr packet_header)
{
   struct iphdr *iph = (struct iphdr *)(packet + sizeof(struct ethhdr));
   // check if(ip_header==v4)
   if (check_ip_version(iph) == 1)
   {
      // check if(protocol==17){
      if (is_udp(iph->protocol) == 1)
      {
         f_tuple *tuple = create_f_tupel(packet, iph);
         if (tuple == NULL)
         {
            printf("is't not youtube\n");
            return;
         }
         connection *conn = ht_get(ht_connection, tuple);
         if (conn == NULL)
         {
            // if(pack_size>700)
            if (is_new_request(packet, iph) == 1)
            {
               new_conn_and_append_to_hash(packet, iph, tuple, packet_header.ts.tv_sec);
            }
            return;
         }
         else
         {
            if (is_ser_to_cli(packet, iph) == 1 && is_new_request(packet, iph) == 1)
            {
               if (save_trans(conn) != 1)
               {
                  return;
               }
               // check if(time_req<20sec || sum transaction>1000){
               if (is_connection_timeout(conn->trans, packet_header.ts.tv_sec) == 1 || conn->sum_transaction >= MAX_NUMBER_OF_CONNECTIONS)
               {
                  if (conn->size > MINIMUM_VIDEO_CONNECTION_SIZE)
                  {
                     if (append_line(conn->last_transactions) < 0)
                     {
                        printf("Unable to write .txt file.\n");
                        return;
                     }
                     new_conn_and_append_to_hash(packet, iph, tuple, packet_header.ts.tv_sec);
                     return;
                  }
               }
               else if (add_new_trans_to_conn(packet, iph, packet_header.ts.tv_sec, conn) != 1)
               {
                  printf("cnot..\n");
                  return;
               }
            }
            else if (is_connection_timeout(conn->trans, packet_header.ts.tv_sec) != 1)
            {
               add_packet_to_transaction(packet, iph, conn, packet_header.ts.tv_sec);
               return;
            }
            else
               return;
         }
         printf("prtocol not udp\n");
         return;
      }
      printf("ip not v4\n");
   }

   return;
}

// Create new transaction
transaction *create_new_transaction(struct iphdr *iph, __time_t pack_time, int size, f_tuple *tuple, int trans_id)
{
   transaction *trans = (transaction *)malloc(sizeof(transaction));
   if (trans == NULL)
   {
      return NULL;
   }
   trans->tuple = tuple;
   trans->num_out_packets = 1;
   trans->num_in_packets = 0;
   trans->transaction_id = trans_id;
   trans->start_time = pack_time;
   trans->packet_time = pack_time;
   trans->min_size = size;
   trans->max_size = size;
   trans->max_packet_time_diff = 0.0;
   trans->min_packet_time_diff = 9999999.9;
   return trans;
}

// Create new connection
connection *create_new_connection(int size, struct iphdr *iph, __time_t pack_time, f_tuple *tuple)
{
   connection *conn = (connection *)malloc(sizeof(connection));
   if (conn == NULL)
   {
      printf("malloc filed\n");
      return NULL;
   }
   conn->trans = create_new_transaction(iph, pack_time, size, tuple, 0);
   if (conn->trans == NULL)
   {
      printf("not trans\n");
      return NULL;
   }
   conn->last_transactions = (char *)malloc(size_malloc);
   if (conn->last_transactions == NULL)
   {
      printf("not conn\n");
      return NULL;
   }
   empty_the_write_to_CSV_file(conn->last_transactions);
   conn->connection_id = connect_id;
   connect_id++;
   conn->size = size;
   conn->sum_transaction = 0;
   return conn;
}

int add_new_trans_to_conn(const u_char *packet, struct iphdr *iph, __time_t packet_time, connection *conn)
{
   conn->trans = create_new_transaction(iph, packet_time, pack_size, conn->trans->tuple, (conn->sum_transaction + 1));
   if (conn->trans == NULL)
   {
      printf("trans not create");
      return -1;
   }
   conn->size += pack_size;
   conn->sum_transaction++;
   // printf("trans num:%d added succes to conn:%d\n", conn->trans->transaction_id, conn->connection_id);
   return 1;
}

// Check if ip version is a ipv
int check_ip_version(struct iphdr *iph)
{
   return (unsigned int)iph->version == IPV ? 1 : 0;
}
// Write to file
int append_line(char *lines)
{
   FILE *file = fopen(SCV_file, "a");
   if (file == NULL)
   {
      printf("Unable to open file.\n");
      return -1;
   }
   // SHF_ASSERT(NULL != file, "shf.log: ERROR: fopen('%s', 'a') failed", SCV_file);
   fprintf(file, "%s", lines);
   fclose(file);
   empty_the_write_to_CSV_file(lines);
   return 1;
}

// make a statistics
void statistics_file()
{
   FILE *file = fopen("statistics.csv", "a");
   if (file == NULL)
   {
      printf("Unable to open file.\n");
      return;
   }
   fprintf(file, "videos connections  have been watched, %d \n", connect_id);
   fclose(file);
   return;
}

// Create 5_tuple
// Return a new 5_tuple
f_tuple *create_f_tupel(const u_char *packet, struct iphdr *iph)
{
   unsigned short iphdrlen;
   iphdrlen = iph->ihl * 4;
   struct udphdr *udph = (struct udphdr *)(packet + iphdrlen + sizeof(struct ethhdr));
   f_tuple *tuple = (f_tuple *)malloc(sizeof(f_tuple));
   tuple->protocol = iph->protocol;
   // pack_size to other funcs
   pack_size = udph->len;
   memset(&source, 0, sizeof(source));
   source.sin_addr.s_addr = iph->saddr;
   memset(&dest, 0, sizeof(dest));
   dest.sin_addr.s_addr = iph->daddr;
   source_port = ntohs(udph->source);
   dest_port = ntohs(udph->dest);
   if (dest_port == YouTube_PORT)
   {
      tuple->server_port = YouTube_PORT;
      tuple->client_port = source_port;
      tuple->server_ip = dest.sin_addr.s_addr;
      tuple->client_ip = source.sin_addr.s_addr;
   }
   else if (source_port == YouTube_PORT)
   {
      tuple->server_port = YouTube_PORT;
      tuple->client_port = dest_port;
      tuple->server_ip = source.sin_addr.s_addr;
      tuple->client_ip = dest.sin_addr.s_addr;
   }
   else
      return NULL;
   return tuple;
}

// Add packet to transaction
void add_packet_to_transaction(const u_char *packet, struct iphdr *iph, connection *conn, __time_t pack_time)
{
   printf("add packet%d to trans:%d, conn:%d\n", conn->trans->num_in_packets + conn->trans->num_out_packets, conn->trans->transaction_id, conn->connection_id);
   if (dest_port == YouTube_PORT)
   {
      if (pack_size < INBOUND_PACKETS_IN_RANGE_MIN)
      {
         return;
      }
      conn->trans->num_in_packets++;
   }
   else if (source_port == YouTube_PORT)
   {
      conn->trans->num_out_packets++;
   }
   if (conn->trans->max_size < pack_size)
   {
      conn->trans->max_size = pack_size;
   }
   else if (conn->trans->min_size > pack_size)
   {
      conn->trans->min_size = pack_size;
   }
   // printf("%ld",pack_time-conn->trans->packet_time);
   diff_time = difftime(pack_time, conn->trans->packet_time);
   if (conn->trans->max_packet_time_diff < diff_time)
   {
      conn->trans->max_packet_time_diff = diff_time;
   }
   else if (conn->trans->min_packet_time_diff > diff_time)
   {
      conn->trans->min_packet_time_diff = diff_time;
   }
   conn->trans->packet_time = pack_time;
   conn->size += pack_size;
   return;
}

// Restart the write to SCV file in a '\0'
void empty_the_write_to_CSV_file(char write_to_CSV_file[])
{
   int i = 0;
   for (i = 0; i < size_malloc; i++)
   {
      write_to_CSV_file[i] = '\0';
   }
}
// Check if it's new request
int is_new_request(const u_char *packet, struct iphdr *iph)
{
   return pack_size > REQUEST_PACKET_THRESHOLD ? 1 : -1;
}

// Checks if a period of time has passed since the previous packet
int is_connection_timeout(transaction *trans, __time_t packet_time)
{
   return packet_time - trans->packet_time > VIDEO_CONNECTION_TIMEOUT ? 1 : -1;
}

// Add transaction to hash
int add_to_hash(connection *conn)
{
   return ht_set(ht_connection, conn->trans->tuple, conn) == NULL ? -1 : 1;
}

// Create new connection and append to hash table
int new_conn_and_append_to_hash(const u_char *packet, struct iphdr *iph, f_tuple *tuple, __time_t packet_time)
{
   connection *conn = create_new_connection(pack_size, iph, packet_time, tuple);
   if (add_to_hash(conn) < 0)
   {
      perror("the hash full--not insert to hash\n");
      return -1;
   }
   // printf("trans num:%d added succes to conn:%d\n", conn->trans->transaction_id, conn->connection_id);
   return 1;
}

// Check if protocol is udp
int is_udp(int protocol)
{
   return protocol == UDP_PROTOCOL ? 1 : -1;
}

// close all the connections
int close_hash()
{
   int i;
   FILE *file = fopen(SCV_file, "a");
   if (file == NULL)
   {
      printf("Unable to open file.\n");
      return -1;
   }
   for (i = 0; i < ht_connection->capacity; i++)
   {
      if (ht_connection->entries[i].key.client_ip != 0 && ht_connection->entries[i].value->size > MINIMUM_VIDEO_CONNECTION_SIZE)
      {
         printf("append conn: %d ind=%d\n", ht_connection->entries[i].value->connection_id, i);
         save_trans(ht_connection->entries[i].value);
         fprintf(file, "%s",ht_connection->entries[i].value->last_transactions);
      }
      free((void *)ht_connection->entries[i].value);
   }
   free((void *)ht_connection->entries);
   free((void *)ht_connection);
   fclose(file);
   return 1;
}

// save transaction
int save_trans(connection *conn)
{
   addr_cli->s_addr = conn->trans->tuple->client_ip;
   addr_srv->s_addr = conn->trans->tuple->server_ip;
   strcpy(addr_c, inet_ntoa(*addr_cli));
   strcpy(addr_s, inet_ntoa(*addr_srv));
   ltime = localtime(&conn->trans->start_time);
   strftime(buff, sizeof(buff), "%H:%M:%S", ltime);
   sprintf(conn->last_transactions, "%s %d", conn->last_transactions, conn->connection_id);
   sprintf(conn->last_transactions, "%s, %s, %s", conn->last_transactions, addr_c, addr_s);
   sprintf(conn->last_transactions, "%s, %d", conn->last_transactions, conn->trans->tuple->protocol);
   sprintf(conn->last_transactions, "%s, %d", conn->last_transactions, conn->trans->tuple->client_port);
   sprintf(conn->last_transactions, "%s, %d, %d", conn->last_transactions, conn->trans->tuple->server_port, conn->trans->transaction_id);
   sprintf(conn->last_transactions, "%s, %s", conn->last_transactions, buff);
   sprintf(conn->last_transactions, "%s, %d, %d", conn->last_transactions, conn->trans->num_in_packets, conn->trans->num_out_packets);
   sprintf(conn->last_transactions, "%s, %d, %d", conn->last_transactions, conn->trans->max_size, conn->trans->min_size);
   sprintf(conn->last_transactions, "%s, %f, %f\n", conn->last_transactions, conn->trans->max_packet_time_diff, conn->trans->min_packet_time_diff);
   return 1;
}

// return 1 if packet from yhe server and 2 if from client
int is_ser_to_cli(const u_char *packet, struct iphdr *iph)
{
   if (dest_port == YouTube_PORT)
   {
      return 1;
   }
   if (source_port == YouTube_PORT)
   {
      return 2;
   }
   return -1;
}

int json()
{
   struct json_object *INT_REQUEST_PACKET_THRESHOLD;
   struct json_object *INT_MAX_NUMBER_OF_CONNECTIONS;
   struct json_object *INT_CONN_SIZE_CHARS;
   struct json_object *INT_YouTube_PORT;
   struct json_object *INT_NUM_IP_BYTE;
   struct json_object *INT_MINIMUM_VIDEO_CONNECTION_SIZE;
   struct json_object *INT_INBOUND_PACKETS_IN_RANGE_MIN;
   struct json_object *INT_IPV;
   struct json_object *INT_UDP_PROTOCOL;
   struct json_object *INT_VIDEO_CONNECTION_TIMEOUT;
   struct json_object *INT_ZERO;
   json_object_object_get_ex(parsed_json, "REQUEST_PACKET_THRESHOLD", &INT_REQUEST_PACKET_THRESHOLD);
   json_object_object_get_ex(parsed_json, "MAX_NUMBER_OF_CONNECTIONS", &INT_MAX_NUMBER_OF_CONNECTIONS);
   json_object_object_get_ex(parsed_json, "CONN_SIZE_CHARS", &INT_CONN_SIZE_CHARS);
   json_object_object_get_ex(parsed_json, "INBOUND_PACKETS_IN_RANGE_MIN", &INT_INBOUND_PACKETS_IN_RANGE_MIN);
   json_object_object_get_ex(parsed_json, "IPV", &INT_IPV);
   json_object_object_get_ex(parsed_json, "VIDEO_CONNECTION_TIMEOUT", &INT_VIDEO_CONNECTION_TIMEOUT);
   json_object_object_get_ex(parsed_json, "UDP_PROTOCOL", &INT_UDP_PROTOCOL);
   json_object_object_get_ex(parsed_json, "MINIMUM_VIDEO_CONNECTION_SIZE", &INT_MINIMUM_VIDEO_CONNECTION_SIZE);
   json_object_object_get_ex(parsed_json, "YouTube_PORT", &INT_YouTube_PORT);
   json_object_object_get_ex(parsed_json, "NUM_IP_BYTE", &INT_NUM_IP_BYTE);
   json_object_object_get_ex(parsed_json, "ZERO", &INT_ZERO);
   REQUEST_PACKET_THRESHOLD = json_object_get_int(INT_REQUEST_PACKET_THRESHOLD);
   MINIMUM_VIDEO_CONNECTION_SIZE = json_object_get_int(INT_MINIMUM_VIDEO_CONNECTION_SIZE);
   INBOUND_PACKETS_IN_RANGE_MIN = json_object_get_int(INT_INBOUND_PACKETS_IN_RANGE_MIN);
   MAX_NUMBER_OF_CONNECTIONS = json_object_get_int(INT_MAX_NUMBER_OF_CONNECTIONS);
   YouTube_PORT = json_object_get_int(INT_YouTube_PORT);
   UDP_PROTOCOL = json_object_get_int(INT_UDP_PROTOCOL);
   IPV = json_object_get_int(INT_IPV);
   VIDEO_CONNECTION_TIMEOUT = json_object_get_int(INT_VIDEO_CONNECTION_TIMEOUT);
   NUM_IP_BYTE = json_object_get_int(INT_NUM_IP_BYTE);
   CONN_SIZE_CHARS = json_object_get_int(INT_CONN_SIZE_CHARS);
   ZERO = json_object_get_int(INT_ZERO);
   printf("MAX_NUMBER_OF_CONNECTIONS: %d\n", json_object_get_int(INT_MAX_NUMBER_OF_CONNECTIONS));
   return 0;
}