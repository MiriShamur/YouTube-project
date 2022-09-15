#include <stdlib.h>
typedef struct
{
  int client_ip;
  int server_ip;
  int client_port;
  int server_port;
  int protocol;
} f_tuple;

typedef struct
{
  int transaction_id;
  int num_in_packets;
  int num_out_packets;
  int min_size;
  int max_size;
  double min_packet_time_diff;
  double max_packet_time_diff;
  __time_t start_time;
  __time_t packet_time;
  f_tuple *tuple;
} transaction;

typedef struct
{
  int connection_id;
  int sum_transaction;
  int size;
  transaction *trans;
  char *last_transactions;
} connection;
