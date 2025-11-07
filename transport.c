// transport.c  (pure-C, macOS/Clang)
// Reliable UDP: 3-way HS, sliding window, in-order delivery,
// 1s RTO, fast-retransmit (3 dupACKs), non-blocking I/O.
// Heavily instrumented for debugging.

/*
  Diagnostics:
  - dump_sendq(): first 20 nodes of send queue with (seq,len), totals
  - ACK processing prints BEFORE/AFTER freeing + what was freed + new head seq
  - Payload reception prints seq, expected, and receive-queue length
  - burst_retransmit(): (now head-only) prints head seq
  - Window sanity logs; once-per-second stall heartbeat
*/

#include "consts.h"
#include "transport.h"
#include "io.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

// -------- receive buffer ----------
typedef struct rcv_node {
    struct rcv_node* next;
    uint16_t seq;   // host order (packet index)
    uint16_t len;   // host order (payload bytes)
    uint8_t  data[];
} rcv_node;

// -------- context ----------
typedef struct {
    int sockfd;
    struct sockaddr_in* addr;

    int state; // SERVER_START / CLIENT_START / NORMAL
    bool syn_sent;
    bool synack_sent;

    uint16_t my_isn;
    uint16_t my_next_seq_after_syn;

    uint16_t peer_isn;
    bool     have_peer_isn;
    uint16_t expected_peer_seq;

    buffer_node* s_head;
    buffer_node* s_tail;
    size_t       unacked_bytes;
    uint16_t     last_ack_seen;
    int          dup_acks;

    size_t peer_win_bytes;   // advertised by peer (bytes)
    rcv_node* r_head;

    struct timeval last_new_ack_time;
    struct timeval last_stall_log;
} ctx_t;

// -------- util debug helpers ----------
static void dump_sendq(buffer_node* head) {
    size_t total_pkts = 0, total_bytes = 0;
    fprintf(stderr, "[SNDQ] head-> ");
    buffer_node* it = head;
    int shown = 0;
    while (it && shown < 20) {
        uint16_t s = ntohs(it->pkt.seq);
        uint16_t l = ntohs(it->pkt.length);
        fprintf(stderr, "(%hu,%hu) ", s, l);
        total_pkts++; total_bytes += l;
        it = it->next; shown++;
    }
    if (it) fprintf(stderr, "... ");
    fprintf(stderr, " | totals pkts=%zu bytes=%zu\n", total_pkts, total_bytes);
}

static size_t rcv_len(rcv_node* h) {
    size_t n=0; while (h) { n++; h=h->next; } return n;
}

// -------- helpers ----------
static void set_nonblocking(int fd) {
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl >= 0) fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

static buffer_node* make_send_node(uint16_t seq_h, uint16_t ack_h,
                                   uint16_t flags, const uint8_t* payload,
                                   uint16_t len_h) {
    // allocate enough so payload sits immediately after embedded packet
    buffer_node* n = (buffer_node*) calloc(1, sizeof(buffer_node) + len_h);
    n->next = NULL;
    n->pkt.seq    = htons(seq_h);
    n->pkt.ack    = htons(ack_h);
    n->pkt.length = htons(len_h);
    n->pkt.win    = htons(MAX_WINDOW);   // large advertised receive window
    n->pkt.flags  = flags;               // flags are NOT network-ordered by spec
    n->pkt.unused = 0;
    if (len_h && payload) memcpy(n->pkt.payload, payload, len_h);
    return n;
}

static ssize_t send_pkt(ctx_t* c, packet* p) {
    print_diag(p, SEND);
    size_t sz = sizeof(packet) + ntohs(p->length);
    return sendto(c->sockfd, p, sz, 0,
                  (struct sockaddr*) c->addr, sizeof(*c->addr));
}

static void push_tail(buffer_node** head, buffer_node** tail, buffer_node* n) {
    if (!*head) { *head = *tail = n; return; }
    (*tail)->next = n; *tail = n;
}

static void free_head_until_ack(buffer_node** head, buffer_node** tail,
                                uint16_t ack_host, size_t* unacked_bytes,
                                size_t* freed_pkts, size_t* freed_bytes) {
    *freed_pkts = 0; *freed_bytes = 0;
    while (*head) {
        uint16_t h = ntohs((*head)->pkt.seq);
        uint16_t l = ntohs((*head)->pkt.length);
        if (h < ack_host) {
            buffer_node* old = *head;
            *head = (*head)->next;
            if (!*head) *tail = NULL;
            if (l) { *unacked_bytes -= l; *freed_bytes += l; }
            (*freed_pkts)++;
            free(old);
        } else break;
    }
}

static rcv_node* rcv_insert(rcv_node* head, rcv_node* n, uint16_t expected) {
    // Drop stale packet (older than what we've already delivered)
    if (n->seq < expected) {
        // stale: we already cumulatively ACKed past this; ignore it
        free(n);
        return head;
    }

    if (!head || head->seq > n->seq) { n->next = head; return n; }
    rcv_node* cur = head;
    while (cur->next && cur->next->seq < n->seq) cur = cur->next;
    if ((cur->seq == n->seq) || (cur->next && cur->next->seq == n->seq)) {
        free(n); return head; // duplicate
    }
    n->next = cur->next; cur->next = n; return head;
}

static void rcv_flush(rcv_node** head, uint16_t* expected_seq,
                      void (*output_p)(uint8_t*, size_t)) {
    // scrub any stale nodes
    while (*head && (*head)->seq < *expected_seq) {
        rcv_node* old = *head; *head = (*head)->next;
        free(old);
    }
    // deliver in-order data
    while (*head && (*head)->seq == *expected_seq) {
        output_p((*head)->data, (*head)->len);
        rcv_node* old = *head; *head = (*head)->next;
        (*expected_seq)++;
        free(old);
    }
}

// -------- send helpers --------
static void send_syn(ctx_t* c) {
    buffer_node* n = make_send_node(c->my_isn, c->expected_peer_seq, SYN, NULL, 0);
    push_tail(&c->s_head, &c->s_tail, n);
    send_pkt(c, &n->pkt);
}
static void send_synack(ctx_t* c, uint16_t ack_to_client) {
    buffer_node* n = make_send_node(c->my_isn, ack_to_client, SYN|ACK, NULL, 0);
    push_tail(&c->s_head, &c->s_tail, n);
    send_pkt(c, &n->pkt);
}

// **** FIX 1: ACK-only packets use a non-advancing seq in NORMAL
static void send_ack_only(ctx_t* c, uint16_t cur_seq_host_ignored, uint16_t ack_host) {
    (void)cur_seq_host_ignored; // ignored on purpose
    packet p; memset(&p, 0, sizeof(p));
    uint16_t seq_for_ack =
        (c->state == NORMAL) ? c->my_next_seq_after_syn   // non-advancing (OK)
                             : (uint16_t)(c->my_isn + 1);
    p.seq    = htons(seq_for_ack);
    p.ack    = htons(ack_host);
    p.length = htons(0);
    p.win    = htons(MAX_WINDOW);
    p.flags  = ACK;
    p.unused = 0;
    send_pkt(c, &p);
}

static void send_data(ctx_t* c, const uint8_t* buf, uint16_t len_h,
                      uint16_t seq_h, uint16_t ack_h) {
    buffer_node* n = make_send_node(seq_h, ack_h, ACK, buf, len_h);
    push_tail(&c->s_head, &c->s_tail, n);
    send_pkt(c, &n->pkt);
    c->unacked_bytes += len_h;
}

// **** FIX 2: Retransmit policy — head-only (safer, avoids window ping-pong)
static void burst_retransmit(ctx_t* c) {
    if (!c->s_head) return;
    uint16_t head = ntohs(c->s_head->pkt.seq);
    fprintf(stderr, "[RETX] retransmit HEAD seq=%hu (unacked=%zu win=%zu)\n",
            head, c->unacked_bytes, c->peer_win_bytes);
    print_diag(&c->s_head->pkt, RTOD);
    send_pkt(c, &c->s_head->pkt);
}

// -------- main loop ----------
void listen_loop(int sockfd, struct sockaddr_in* addr, int type,
                 ssize_t (*input_p)(uint8_t*, size_t),
                 void (*output_p)(uint8_t*, size_t)) {

    ctx_t c; memset(&c, 0, sizeof(c));
    c.sockfd = sockfd; c.addr = addr; c.state = type;
    c.peer_win_bytes = MIN_WINDOW; // 1012 bytes initial
    gettimeofday(&c.last_stall_log, NULL);

    set_nonblocking(sockfd);

    srand((unsigned)(time(NULL) ^ getpid()));
    c.my_isn = (uint16_t)(rand() % 1000);
    c.my_next_seq_after_syn = c.my_isn + 1;

    gettimeofday(&c.last_new_ack_time, NULL);

    if (c.state == CLIENT_START && !c.syn_sent) {
        send_syn(&c); c.syn_sent = true;
        c.last_ack_seen = 0;
        gettimeofday(&c.last_new_ack_time, NULL);
    }

    for (;;) {
        // ----- receive all available -----
        for (;;) {
            uint8_t raw[sizeof(packet) + MAX_PAYLOAD] = {0};
            packet* pkt = (packet*) raw;
            socklen_t sl = sizeof(*addr);
            ssize_t r = recvfrom(sockfd, raw, sizeof(raw), MSG_DONTWAIT,
                                 (struct sockaddr*)addr, &sl);
            if (r < 0) {
                if (errno==EAGAIN || errno==EWOULDBLOCK) break;
                else break;
            }
            if (r < (ssize_t)sizeof(packet)) continue;

            print_diag(pkt, RECV);

            uint16_t pseq = ntohs(pkt->seq);
            uint16_t pack = ntohs(pkt->ack);
            uint16_t plen = ntohs(pkt->length);
            uint16_t pwin = ntohs(pkt->win);
            bool     psyn = (pkt->flags & SYN) != 0;
            bool     packf= (pkt->flags & ACK) != 0;
            (void)packf;

            // --- Peer window sanity ---
            if (pwin == 0) {
                // Keep the old window; optionally clamp to 1 to avoid deadlock.
                fprintf(stderr, "[WARN] peer sent WIN=0; keeping old=%zu (clamped)\n",
                        c.peer_win_bytes);
                if (c.peer_win_bytes == 0)
                    c.peer_win_bytes = 1;
            } else {
                if (pwin > MAX_WINDOW) {
                    fprintf(stderr, "[WARN] clamping peer WIN=%u to MAX_WINDOW=%d\n",
                            pwin, (int)MAX_WINDOW);
                    pwin = MAX_WINDOW;
                }
                // Use the current advertised value directly (no running max).
                c.peer_win_bytes = pwin;
            }

            // --- handshake ---
            if (c.state == SERVER_START) {
                if (psyn) {
                    c.peer_isn = pseq; c.have_peer_isn = true;
                    c.expected_peer_seq = c.peer_isn + 1;
                    send_synack(&c, c.expected_peer_seq);
                    c.synack_sent = true;
                    gettimeofday(&c.last_new_ack_time, NULL);
                    fprintf(stderr, "[HS] SERVER got SYN %hu, sent SYN|ACK (ack=%hu)\n",
                            pseq, c.expected_peer_seq);
                }
                if (pack && c.synack_sent) {
                    if (pack >= c.my_isn + 1) {
                        c.state = NORMAL;
                        fprintf(stderr, "[HS] SERVER -> NORMAL (peer acked our SYN: %hu)\n", pack);
                    }
                }
            } else if (c.state == CLIENT_START) {
                if (psyn && pack) {
                    c.peer_isn = pseq; c.have_peer_isn = true;
                    c.expected_peer_seq = c.peer_isn + 1;
                    if (pack >= c.my_isn + 1) {
                        uint16_t seq_for_ack = c.my_next_seq_after_syn; // equals my_isn+1 here
                        send_ack_only(&c, seq_for_ack, c.expected_peer_seq);
                        c.state = NORMAL;
                        fprintf(stderr, "[HS] CLIENT got SYN|ACK (seq=%hu,ack=%hu) -> NORMAL\n",
                                pseq, pack);
                    }
                }
            }

            // --- ACK processing ---
            if (pack) {
                size_t before_bytes = c.unacked_bytes;
                uint16_t head_before = c.s_head ? ntohs(c.s_head->pkt.seq) : 0;
                size_t freed_pkts=0, freed_bytes=0;

                free_head_until_ack(&c.s_head, &c.s_tail, pack,
                                    &c.unacked_bytes, &freed_pkts, &freed_bytes);

                uint16_t head_after = c.s_head ? ntohs(c.s_head->pkt.seq) : 0;

                if (freed_pkts || freed_bytes) {
                    fprintf(stderr, "[ACK] FREE ack=%hu freed_pkts=%zu freed_bytes=%zu "
                                    "unacked: %zu->%zu head: %hu->%hu\n",
                            pack, freed_pkts, freed_bytes,
                            before_bytes, c.unacked_bytes,
                            head_before, head_after);
                }

                if (pack > c.last_ack_seen) {
                    c.last_ack_seen = pack; c.dup_acks = 0;
                    gettimeofday(&c.last_new_ack_time, NULL);
                    fprintf(stderr, "[ACK] NEW ack=%hu now_unacked=%zu win=%zu\n",
                            pack, c.unacked_bytes, c.peer_win_bytes);
                } else if (pack == c.last_ack_seen && c.s_head != NULL) {
                    c.dup_acks++;
                    fprintf(stderr, "[ACK] DUP ack=%hu dup_count=%d head=%hu unacked=%zu\n",
                            pack, c.dup_acks,
                            c.s_head ? ntohs(c.s_head->pkt.seq) : 0,
                            c.unacked_bytes);
                    if (c.dup_acks >= DUP_ACKS && c.s_head) {
                        fprintf(stderr, "[FR] Fast-retransmit HEAD seq=%hu\n",
                                ntohs(c.s_head->pkt.seq));
                        burst_retransmit(&c);  // head-only
                        c.dup_acks = 0;
                    }
                }
            }

            // --- payload reception ---
            if (plen > 0) {
                rcv_node* n = (rcv_node*) malloc(sizeof(rcv_node) + plen);
                n->next = NULL; n->seq = pseq; n->len = plen;
                memcpy(n->data, pkt->payload, plen);
                c.r_head = rcv_insert(c.r_head, n, c.expected_peer_seq);

                if (!c.have_peer_isn) {
                    c.peer_isn = pseq - 1; c.expected_peer_seq = c.peer_isn + 1;
                    c.have_peer_isn = true;
                }
                uint16_t before = c.expected_peer_seq;
                size_t rlen_before = rcv_len(c.r_head);
                rcv_flush(&c.r_head, &c.expected_peer_seq, output_p);
                size_t rlen_after = rcv_len(c.r_head);

                fprintf(stderr, "[RCV] pseq=%hu plen=%hu expect:%hu->%hu rbuf:%zu->%zu\n",
                        pseq, plen, before, c.expected_peer_seq, rlen_before, rlen_after);

                // dedicated ACK: we ignore the provided seq in send_ack_only
                uint16_t seq_for_ack =
                    (c.state==NORMAL) ? (uint16_t)(c.my_next_seq_after_syn - 1)
                                      : (uint16_t)(c.my_isn+1);
                (void)seq_for_ack;
                send_ack_only(&c, 0, c.expected_peer_seq);
            }
        } // end inner recv loop

        // ----- retransmission timer -----
        if (c.s_head) {
            struct timeval now; gettimeofday(&now, NULL);
            if (TV_DIFF(now, c.last_new_ack_time) >= RTO) {
                fprintf(stderr,
                        "[RTO] Timeout; retransmit HEAD seq=%hu (unacked=%zu win=%zu)\n",
                        ntohs(c.s_head->pkt.seq), c.unacked_bytes, c.peer_win_bytes);
                burst_retransmit(&c);  // head-only
                // do NOT reset last_new_ack_time here
            }
        }

        // ----- sending side -----
        if (c.state == NORMAL) {
            size_t avail = (c.peer_win_bytes > c.unacked_bytes)
                               ? (c.peer_win_bytes - c.unacked_bytes) : 0;

            struct timeval now; gettimeofday(&now, NULL);
            if (avail == 0 && c.s_head &&
                TV_DIFF(now, c.last_stall_log) > 1000000) { // 1s heartbeat
                fprintf(stderr, "[STALL] avail=0 unacked=%zu win=%zu head_seq=%hu\n",
                        c.unacked_bytes, c.peer_win_bytes,
                        ntohs(c.s_head->pkt.seq));
                dump_sendq(c.s_head);
                c.last_stall_log = now;
            }

            while (avail > 0) {
                size_t want = (avail > MAX_PAYLOAD) ? MAX_PAYLOAD : avail;

                uint8_t inbuf[MAX_PAYLOAD];
                ssize_t r = input_p(inbuf, want);   // read only what we can send now
                if (r <= 0) break;

                uint16_t chunk = (uint16_t)r;       // r <= want
                uint16_t seq_to_use = c.my_next_seq_after_syn;

                send_data(&c, inbuf, chunk, seq_to_use, c.expected_peer_seq);
                c.my_next_seq_after_syn++;

                avail = (c.peer_win_bytes > c.unacked_bytes)
                            ? (c.peer_win_bytes - c.unacked_bytes) : 0;

                fprintf(stderr, "[SEND] data seq=%hu len=%hu unacked=%zu win=%zu avail=%zu\n",
                        seq_to_use, chunk, c.unacked_bytes, c.peer_win_bytes, avail);
            }
        } else if (c.state == CLIENT_START && !c.syn_sent) {
            send_syn(&c); c.syn_sent = true;
        }

        usleep(1000);
    }
}
