# Project 1: Reliable Data Transport Protocol

## Design Overview
This project implements a reliable data transport protocol on top of UDP, inspired by TCP-style mechanisms. The design includes sliding windows, cumulative acknowledgments, retransmission timers, and congestion control using a fixed window size. Packets are acknowledged cumulatively based on sequence numbers, and retransmissions are triggered by either timeouts (RTO) or triple duplicate ACKs (fast retransmit). The protocol maintains two circular buffers for sent and received packets, each managing their own sequence tracking and window space.

## Design Choices
- **Stop-and-Wait → Sliding Window:** We extended a simple stop-and-wait base into a full sliding window to improve throughput.
- **Cumulative ACKs:** Simplifies bookkeeping while ensuring in-order delivery.
- **Linked Packet Buffers:** Implemented linked lists for send and receive queues for clarity and dynamic memory management.
- **Timeouts and Fast Retransmit:** Added both RTO-based retransmissions and duplicate-ACK detection for responsiveness.

## Problems Encountered
Initially, large transfers stalled due to retransmission logic not correctly advancing the head sequence number. Both sides entered infinite RTO loops because acknowledgments for the retransmitted packet were being ignored. There were also issues with duplicated commits and unflushed buffers that caused incomplete file transfers.

## Solutions
We carefully restructured retransmission and ACK handling:
- Fixed sequence tracking so the sender removes fully acknowledged packets.
- Flushed receive buffers properly once data was written to stdout.
- Ensured the receiver sends final ACKs to close out the connection cleanly.

After these fixes, the implementation reliably transfers multi-megabyte files with matching SHA-1 hashes on both sides.

---

**Author:** Mahmoud Elsayed  
**Repository:** [melsayed52/cs118-p1](https://github.com/melsayed52/cs118-p1)
