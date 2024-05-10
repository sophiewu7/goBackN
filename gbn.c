#include "gbn.h"

#define MAX_ATTEMPT 5
#define MAX_WINDOW_SIZE 128

state_t s;

/* Reference for alarm related code: https://www.gnu.org/software/libc/manual/html_node/Handler-Returns.html */
volatile sig_atomic_t timeout_flag = 0;

void sig_handler(int signum){
	timeout_flag = 1;
}

void setup_signal_handler() {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sig_handler;
    sigaction(SIGALRM, &sa, NULL);
}

void gbn_init()
{
	/* helper function that initialize s*/
	s.state = CLOSED;
	s.window_size = 1;
	s.seq_num = 0;
	s.seq_tail = 0;
	setup_signal_handler(); 
}

uint16_t checksum(uint16_t *buf, int nwords)
{
	uint32_t sum;

	for (sum = 0; nwords > 0; nwords--)
		sum += *buf++;
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	return ~sum;
}

uint16_t checksum_hdr(gbnhdr *hdr) {
    size_t buf_size = sizeof(hdr->type) + sizeof(hdr->seqnum) + DATALEN;
    uint8_t *buffer = malloc(buf_size);
    if (!buffer) {
        perror("Failed to allocate memory for checksum calculation\n");
        return 0;
    }

    size_t offset = 0;
    memcpy(buffer + offset, &hdr->type, sizeof(hdr->type));
    offset += sizeof(hdr->type);
    memcpy(buffer + offset, &hdr->seqnum, sizeof(hdr->seqnum));
    offset += sizeof(hdr->seqnum);

    memcpy(buffer + offset, hdr->data, DATALEN);

    uint16_t result = checksum((uint16_t *)buffer, buf_size / 2);

    free(buffer);
    return result;
}


void fill_hdr(uint8_t type, uint8_t seqnum, gbnhdr *hdr){
	/* helper function for filling in gbnhdr */
	hdr->type = type;
	hdr->seqnum = seqnum;
	memset(hdr->data, '\0', DATALEN);
	hdr->payload_len = 0;
	hdr->checksum = checksum_hdr(hdr);
}

void prepare_packet(uint8_t type, uint8_t seq_num, const uint8_t *buf, size_t len, size_t packet_index, size_t packet_count, gbnhdr *packet) {
    fill_hdr(type, seq_num, packet);
    size_t bytes_to_copy = ((packet_index + 1) * DATALEN < len) ? DATALEN : len - packet_index * DATALEN;
    const uint8_t *src = buf + packet_index * DATALEN;
    memcpy(packet->data, src, bytes_to_copy);
    packet->checksum = checksum_hdr(packet);
    
    packet->payload_len = (packet_index == packet_count - 1) ? bytes_to_copy : DATALEN;

    if (bytes_to_copy != DATALEN) {
        packet->data[bytes_to_copy] = '\0';
    }
}

int valid_checksum(gbnhdr *compare){
    /* helper function used to validate whether gbnhdr is corrputed or not*/
	gbnhdr temp = {0};
	temp = *compare;
	temp.checksum = 0;
	temp.checksum = checksum_hdr(&temp);
	return temp.checksum == compare->checksum;
}

void print_gbnhdr(const gbnhdr *hdr) {
	/* helper function to help us print out gbnhdr */
	printf("============================gbhhdr package details============================\n");
    if (hdr == NULL) {
        printf("gbnhdr is NULL\n");
        return;
    }
    printf("Type: %u\n", hdr->type);
    printf("SeqNum: %u\n", hdr->seqnum);
    printf("Checksum: %u\n", hdr->checksum);
    printf("Data: ");
	int i;
    for (i = 0; i < DATALEN; ++i) {
        printf("%02x ", hdr->data[i]);
    }
    printf("\n");
	printf("===========================================================================\n");
}

int validate_dataack_hdr(uint8_t dataack_seqnum, uint8_t *last_ack_num, uint32_t *last_ack_idx, int *dataack_idx){
	int i;
	uint8_t unack_seqnum = *last_ack_num + 1;
	for (i = 0; i < s.window_size; i++){
		if (dataack_seqnum == unack_seqnum){
			*dataack_idx = *last_ack_idx + 1 + i;
			*last_ack_idx = *dataack_idx;
			*last_ack_num = dataack_seqnum;
			s.window_size = (s.window_size * 2 < MAX_WINDOW_SIZE) ? (s.window_size * 2) : MAX_WINDOW_SIZE;
			return 1;
		}
		unack_seqnum++;
	}
	*dataack_idx = -1;
	return 0;
}

ssize_t gbn_send(int sockfd, const void *buf, size_t len, int flags){
	
	/* TODO: Your code here. */
	if (s.state != ESTABLISHED){
		perror("gbn_send incorrect state, connection not established.\n");
		return(-1);
	}

	/* Hint: Check the data length field 'len'.
	 *       If it is > DATALEN, you will have to split the data
	 *       up into multiple packets - you don't have to worry
	 *       about getting more than N * DATALEN.
	 */

	int packet_count = (int) len / DATALEN;
	if (len % DATALEN != 0){
		packet_count++;
	}

	uint32_t packet_index = 0;
	uint32_t packet_head = packet_index;
	uint8_t seq_num = s.seq_num;
	uint8_t seq_head = seq_num;
	uint8_t last_ack_num = s.seq_num - 1;
	uint32_t last_ack_idx = packet_index - 1;

	int attempt = 0;

	while ((last_ack_idx != (packet_count - 1)) || (packet_index < packet_count && attempt < MAX_ATTEMPT)){
		if (timeout_flag){
			attempt++;
			timeout_flag = 0;
			packet_index = packet_head;
			seq_num = seq_head;
			s.seq_num = seq_head;
			s.window_size = (s.window_size / 2 == 0) ? 1 : (s.window_size / 2);
			alarm(TIMEOUT);
			continue;
		}
		while (packet_index < packet_count && packet_index < packet_head + s.window_size){
			gbnhdr packet = {0};
			prepare_packet(DATA, seq_num, buf, len, packet_index, packet_count, &packet);
			if (maybe_sendto(sockfd, (char *)&packet, sizeof(packet), 0, &s.addr, s.addr_len) == -1){
				perror("gbn_send failed to send packet.\n");
				continue;
			}
			if (packet_index == packet_head){
				alarm(TIMEOUT);
			}
			packet_index++;
			seq_num++;
		}
		while (packet_head < packet_index){
			if (timeout_flag){
				packet_index = packet_head;
				break;
			}
			gbnhdr dataack_hdr = {0};
			if (maybe_recvfrom(sockfd, (char *)&dataack_hdr, sizeof(dataack_hdr), 0, (struct sockaddr *)&s.addr, &s.addr_len) == -1){
				perror("gbn_send fail to recv DATAACK.\n");
				break;
			}
			int dataack_idx = -1;
			if (dataack_hdr.type == DATAACK){
				if (valid_checksum(&dataack_hdr) == 1){
					if (validate_dataack_hdr(dataack_hdr.seqnum, &last_ack_num, &last_ack_idx, &dataack_idx) == 1){
						packet_head = dataack_idx + 1;
						seq_head = (uint8_t)(dataack_hdr.seqnum + 1);
						s.seq_num = seq_head;
						alarm(TIMEOUT);
						attempt = 0;
						if (packet_index < packet_count && packet_index < packet_head + s.window_size){
							gbnhdr packet = {0};
							prepare_packet(DATA, seq_num, buf, len, packet_index, packet_count, &packet);
							if (maybe_sendto(sockfd, (char *)&packet, sizeof(packet), 0, &s.addr, s.addr_len) == -1){
								perror("gbn_send failed to send packet.\n");
								continue;
							}
							packet_index++;
							seq_num++;
						}
					}
				}
			} 
		}
	}
	if (attempt == MAX_ATTEMPT){
		perror("gbn_send reached max attempt, unable to send.\n");
		return(-1);
	}
	return 0;
}

ssize_t gbn_recv(int sockfd, void *buf, size_t len, int flags){

	/* TODO: Your code here. */
	if (s.state != ESTABLISHED){
		perror("gbn_recv incorrect state, connection not established.\n");
		return(-1);
	}

	gbnhdr dataack_hdr = {0};
	gbnhdr packet = {0};

	while (s.state == ESTABLISHED){
		if (timeout_flag){
			timeout_flag = 0;
			return 0;
		}
		if (maybe_recvfrom(sockfd, (char *)&packet, sizeof(packet), 0, (struct sockaddr *)&s.addr, &s.addr_len) == -1){
			perror("gbn_recv fail to recv DATA.\n");
			continue;
		}
		if (packet.type == DATA){
			if (valid_checksum(&packet) == 1 && packet.seqnum == (uint8_t)(s.seq_num + 1)){
				s.seq_num++;
				fill_hdr(DATAACK, s.seq_num, &dataack_hdr);
				if (maybe_sendto(sockfd, (char *)&dataack_hdr, sizeof(dataack_hdr), 0, &s.addr, s.addr_len) == -1){
					perror("gbn_send failed to send packet.\n");
					continue;
				}
				memcpy(buf, packet.data, sizeof(packet.data));
				return packet.payload_len;
			} else {
				fill_hdr(DATAACK, s.seq_num, &dataack_hdr);
				if (maybe_sendto(sockfd, (char *)&dataack_hdr, sizeof(dataack_hdr), 0, &s.addr, s.addr_len) == -1){
					perror("gbn_send failed to send packet.\n");
					continue;
				}
			}
		} else if (packet.type == FIN){
			if (valid_checksum(&packet) == 1 && packet.seqnum == 0){
				s.seq_num++;
				s.state = FIN_RCVD;
				return 0;
			} else {
				perror("gbn_recv FIN packet corrupted.\n");
			}
		}
	}
	return(-1);
}

int gbn_close(int sockfd){

	/* TODO: Your code here. */
	gbnhdr fin_hdr = {0};
	gbnhdr finack_hdr = {0};
	int attempt = 0;

	while (s.state != CLOSED || attempt >= MAX_ATTEMPT){
		if (timeout_flag){
			timeout_flag = 0;
			s.seq_num--;
			attempt++;
			alarm(TIMEOUT);
			if (s.state == FIN_SENT){
				s.state = ESTABLISHED;
			} else if (s.state == FIN_RCVD){
				s.state = CLOSED;
				break;
			}
		}
		if (s.state == ESTABLISHED){
			fill_hdr(FIN, 0, &fin_hdr);
			alarm(TIMEOUT);
			if (maybe_sendto(sockfd, (char *)&fin_hdr, sizeof(fin_hdr), 0, &s.addr, s.addr_len) == -1){
				perror("gbn_close failed to send FIN packet at ESTABLISHED state.\n");
				continue;
			}
			s.state = FIN_SENT;
			s.seq_num++;
		} else if (s.state == FIN_SENT){
			if (maybe_recvfrom(sockfd, (char *)&finack_hdr, sizeof(finack_hdr), 0, (struct sockaddr *)&s.addr, &s.addr_len) == -1){
				perror("gbn_close FINACK recvfrom failed\n");
				continue;
			}
			if (finack_hdr.type == FINACK && valid_checksum(&finack_hdr) && finack_hdr.seqnum == 0){
				fill_hdr(FIN, 0, &fin_hdr);
				if (maybe_sendto(sockfd, (char *)&fin_hdr, sizeof(fin_hdr), 0, &s.addr, s.addr_len) == -1){
					perror("gbn_close failed to send FIN packet at FIN_SENT state.\n");
					continue;
				}
				s.state = CLOSED;
				attempt = 0;
				break;
			}
		} else if (s.state == FIN_RCVD){
			fill_hdr(FINACK, 0, &finack_hdr);
			alarm(TIMEOUT);
			if (maybe_sendto(sockfd, (char *)&finack_hdr, sizeof(finack_hdr), 0, &s.addr, s.addr_len) == -1){
				perror("gbn_close failed to send FIN packet at ESTABLISHED state.\n");
				continue;
			}
			s.seq_num++;
			if (maybe_recvfrom(sockfd, (char *)&fin_hdr, sizeof(fin_hdr), 0, (struct sockaddr *)&s.addr, &s.addr_len) == -1){
				perror("gbn_connect FIN_RCVD last FIN recvfrom failed\n");
				continue;
			}
			if (fin_hdr.type == FIN && valid_checksum(&fin_hdr) && finack_hdr.seqnum == 0){
				fill_hdr(FIN, 0, &fin_hdr);
				if (maybe_sendto(sockfd, (char *)&fin_hdr, sizeof(fin_hdr), 0, &s.addr, s.addr_len) == -1){
					perror("gbn_close failed to send FIN packet at FIN_SENT state.\n");
					continue;
				}
				s.state = CLOSED;
				attempt = 0;
				break;
			}
		} else {
			break;
		}
	}
	if (s.state == CLOSED){
		close(sockfd);
		return 0;
	}
	return(-1);
}

int gbn_connect(int sockfd, const struct sockaddr *server, socklen_t socklen){

	/* TODO: Your code here. */
	if (s.state == ESTABLISHED){
		perror("gbn_connect connection has already established, cannot established again.\n");
		return(-1);
	}

	int attempt = 0;

	memcpy(&s.addr, server, socklen);
	s.addr_len = socklen;

	gbnhdr syn_hdr = {0};
	gbnhdr synack_hdr = {0};

	while (attempt < MAX_ATTEMPT){
		if (timeout_flag){
			attempt++;
			timeout_flag = 0;
			s.state = CLOSED;
			continue;
		}
		if (s.state == CLOSED){
			fill_hdr(SYN, 0, &syn_hdr);
			alarm(TIMEOUT);
			if (maybe_sendto(sockfd, (char *)&syn_hdr, sizeof(syn_hdr), 0, server, socklen) == -1){
				perror("gbn_connect SYN sendto failed\n");
				continue;
			}
			s.state = SYN_SENT;
		} else if (s.state == SYN_SENT){
			if (maybe_recvfrom(sockfd, (char *)&synack_hdr, sizeof(synack_hdr), 0, (struct sockaddr *)&s.addr, &s.addr_len) == -1){
				perror("gbn_connect SYNACK recvfrom failed\n");
				continue;
			}
			if (synack_hdr.type == SYNACK){
				if (valid_checksum(&synack_hdr) == 1){
					alarm(0);
					s.seq_num++;
					fill_hdr(SYNACK, 0, &synack_hdr);
					maybe_sendto(sockfd, (char *)&synack_hdr, sizeof(synack_hdr), 0, server, socklen);
					s.state = ESTABLISHED;
					break;
				} else {
					perror("gbn_connect recv corrupted SYNACK, retransmit\n");
					s.state = CLOSED;
					attempt++;
					continue;
				}
			} else if (synack_hdr.type == RST){
				s.state = CLOSED;
				return(-1);
			} else {
				perror("gbn_connect recv unknown packet type\n");
				continue;
			}
		}
	}

	if (s.state == ESTABLISHED){
		return 0;
	}

	perror("gbn_connect failed to connect.\n");
	return(-1);
}

int gbn_listen(int sockfd, int backlog){

	/* TODO: Your code here. */
	return 0;
}

int gbn_bind(int sockfd, const struct sockaddr *server, socklen_t socklen){
	/* TODO: Your code here. */
	return bind(sockfd, server, socklen);
}	

int gbn_socket(int domain, int type, int protocol){
		
	/*----- Randomizing the seed. This is used by the rand() function -----*/
	srand((unsigned)time(0));
	
	/* TODO: Your code here. */
	gbn_init();
	s.fd = socket(domain, type, protocol);
	return s.fd;
}

int gbn_accept(int sockfd, struct sockaddr *client, socklen_t *socklen){

	/* TODO: Your code here. */
	if (s.state != CLOSED){
		gbnhdr rst_hdr = {0};
		fill_hdr(RST, 0, &rst_hdr);
		if (maybe_sendto(sockfd, (char *)&rst_hdr, sizeof(rst_hdr), 0, client, *socklen) == -1){
			perror("gbn_accept RST sendto failed\n");
		}
		perror("gbn_accept connection already established. Receiver continue to talk with previously connected sender.\n");
		return s.fd;
	}

	int attempt = 0;

	memcpy(&s.addr, client, *socklen);
	s.addr_len = *socklen;

	gbnhdr syn_hdr = {0};
	gbnhdr synack_hdr = {0};
	gbnhdr synack_hdr_last = {0};

	while (attempt < MAX_ATTEMPT){
		if (timeout_flag){
			attempt++;
			timeout_flag = 0;
			continue;
		}
		if (s.state == CLOSED){
			if (maybe_recvfrom(sockfd, (char *)&syn_hdr, sizeof(syn_hdr), 0, client, socklen) == -1){
				perror("gbn_accept recv SYN failed\n");
				continue;
			}	
			if (syn_hdr.type == SYN){
				if (valid_checksum(&syn_hdr) == 1){
					s.state = SYN_RCVD;
				} else {
					perror("gbn_accept recv corrupted SYN.\n");
				}
				continue;
			} else {
				perror("gbn_accept recv unknown packet type.\n");
				continue;
			}
		} else if (s.state == SYN_RCVD){
			fill_hdr(SYNACK, 0, &synack_hdr);
			alarm(TIMEOUT);
			if (maybe_sendto(sockfd, (char *)&synack_hdr, sizeof(synack_hdr), 0, client, *socklen) == -1){
				perror("gbn_accept SYNACK sendto failed, retransmit.\n");
				continue;
			}
			if (maybe_recvfrom(sockfd, (char *)&synack_hdr_last, sizeof(synack_hdr_last), 0, client, socklen) == -1){
				perror("gbn_accept recv SYNACK failed\n");
				continue;
			}
			if (synack_hdr_last.type == SYNACK){
				if (valid_checksum(&synack_hdr_last) == 1){
					alarm(0);
					s.state = ESTABLISHED;
					break;
				} else {
					perror("gbn_accept recv corrupted SYNACK.\n");
					continue;
				}
			} else {
				perror("gbn_accept recv unknown packet type.\n");
				continue;
			}
		}
	}

	if (s.state == ESTABLISHED){
		s.fd = sockfd;
		return s.fd;
	}

	perror("gbn_accept failed to connect.\n");
	return(-1);

}


ssize_t maybe_recvfrom(int  s, char *buf, size_t len, int flags, struct sockaddr *from, socklen_t *fromlen){

	/*----- Packet not lost -----*/
	if (rand() > LOSS_PROB*RAND_MAX){


		/*----- Receiving the packet -----*/
		int retval = recvfrom(s, buf, len, flags, from, fromlen);

		/*----- Packet corrupted -----*/
		if (rand() < CORR_PROB*RAND_MAX){
			/*----- Selecting a random byte inside the packet -----*/
			int index = (int)((len-1)*rand()/(RAND_MAX + 1.0));

			/*----- Inverting a bit -----*/
			char c = buf[index];
			if (c & 0x01)
				c &= 0xFE;
			else
				c |= 0x01;
			buf[index] = c;
		}

		return retval;
	}
	/*----- Packet lost -----*/
	return(len);  /* Simulate a success */
}

ssize_t maybe_sendto(int  s, const void *buf, size_t len, int flags, \
                     const struct sockaddr *to, socklen_t tolen){

    char *buffer = malloc(len);
    memcpy(buffer, buf, len);
    
    
    /*----- Packet not lost -----*/
    if (rand() > LOSS_PROB*RAND_MAX){
        /*----- Packet corrupted -----*/
        if (rand() < CORR_PROB*RAND_MAX){
            
            /*----- Selecting a random byte inside the packet -----*/
            int index = (int)((len-1)*rand()/(RAND_MAX + 1.0));

            /*----- Inverting a bit -----*/
            char c = buffer[index];
            if (c & 0x01)
                c &= 0xFE;
            else
                c |= 0x01;
            buffer[index] = c;
        }

        /*----- Sending the packet -----*/
        int retval = sendto(s, buffer, len, flags, to, tolen);
        free(buffer);
        return retval;
    }
    /*----- Packet lost -----*/
    else
        return(len);  /* Simulate a success */
}