# CS 5450: Networked and Distributed Systems Homework 1: Go-back-n

## Description of the Protocol

### What's Go-Back-N

Go-Back-N is a sliding window protocol designed to optimize the utlization of bandwidth and ensure reliable data transfer at the transport layer. The objective of this lab is to utilize the unreliable UDP system call alongside the Go-Back-N mechanism to facilitate a reliable data transfer between a sender and a receiver.

The sender uses `gbn_send()` function to slice the buffer passed in into smaller pieces and encapsulate them into packets. We add a payload_len field to keep track of the actual length of the data payload of the packet since the last sliced buffer could have a length that is smaller than DATALEN. The sender attempts to dispatch a group of packets within a bounded window size to expedite the transmission. The first packet in the window initiates a timer for retransmission of all packets in the window upon timeout. Upon receiving an acknowledgment from the receiver, the sender verifies if the sequence number of the acknowledgment matches any packets within the current window. If it does, the start of the sliding window shifts to the acknowledged packet plus one. Then the window size would be dynamically adjusted based on a congestion control mechanism. At the implementation level, we detect congestion by timeout. If the acknowledgment number does not match, the sender continues to send the remaining packets in the window and waits for a timeout to trigger retransmission. If timeout, the window size will be reset or divided by a factor based on the congestion mechanism chosen (we did 2 based on the hint of the handout) and retransmit will be invoked. During retransmission, all packets in the window are sent together, rather than individually. **(Appendix C Figure 1)**


The receiver, `using function gbn_recv()`, listens for packets and checks their validity by verifying the packet's checksum to ensure it is not corrupted, confirming the data type is DATA, and checking if the sequence number is the expected one (the last acknowledged sequence number plus one). If the checkes pass, the receiver will send back an acknowledgement with sequence number carried by the packet received. **(Appendix C Figure 2)** If these check fail, the receiver will still send back an acknowledgement with the sequence number carried by the last valid packet received. This is a way to inform sender the last valid packet receiver having so the sender would know which ones should be retransmitted. 


For this lab, we decided to simply initialize the sequence number to 0, increment the sequence number by 1, and the sequence number corresponds to a packet, rather than the byte. But, in real-life scenarios such as TCP, the initialization could be randomized and the incrementation refers to the byte payload. 

And we are aware that the sequence number is type `uint8_t` which is significantly smaller than the buffer size, so we faced a sequence number wrap-around issue. Based on the lecture, the maximum window size should be set to `(Maximum Sequence + 1) / 2`.

**A more detailed description and illustration of how we implemented Go-Back-N can be found in the appendices of this report.**

## Performance Optimization

Following the lab instructions, we used an "attempt" variable. This ensures that if a packet is sent five times without an acknowledgment, the connection stops. This greatly helps our sender to terminate during the stablished connection period when there is no receiver listening and helps to close both the sender and the receiver.

Our strategy for controlling congestion is to dynamically the window size dynamically. We double the window size with each acknowledgment, following the slow start method from lectures. Initially, the window size is 1, which doubles on successful transmissions and halves when a timeout happens. Basically, when we receive an acknowledgment successfully, we will assume that the transmission is correctly set up and transfer is doable. So we want to send as many packets as possible under this condition. When timeout, there may be congestion or other situations going on, so we want to be more conservative and set fewer packets. We limit the window size to a maximum of 128, as advised in lectures because the window size should be less than or equal to half of the maximum sequence number, which is 255.

For timeouts, we use a default setting of 1 second from the header file. We are aware that we could use RTT and the method introduced in the lecture to dynamically change the timeout time. But as suggested in the handout, a predetermined value is sufficient. Hence, we kept with the default timeout value and only modified the window size.


## Appendix

We will note down the logistic for our program in this appendix.

## Appendix A: Establish Connection

We used the state provided in the header file to implement a three-way handshake similar to the TCP protocol, as shown in the figure below. We do aware that `gbn_accept()` needs to return the socket of the established connection.
![image](https://hackmd.io/_uploads/Byx6IQl2p.png)


## Appendix B: Close Connection

We use a four-way handshake to close the connection. The receiver will listen to both packet type DATA and FIN in `gbn_recv()`. Once FIN is received, switch state to FIN_RCVD, send out FINACK, and wait for FINACK to close. If tried five attemps, force socket and connection close.

![image](https://hackmd.io/_uploads/ryTbqQe2a.png)

## Appendix C: Data Transmission

We added a payload_len field in our packet header so that when returning from `gbn_recv()` we can return the length of the actual data that needs to be written to the file.

To deal with sequence number wrap-around, we have a helper function that uses the last_ack_seq to validate the sequence number of the acknowledgment packet and find its corresponding position in the actual buffer.

Our sender only set a timer for the head of our window. Only retransmit when a timeout occurs. Otherwise, transmit what was left in the window. The window shifts and changes when a new valid acknowledgment is received.

As the receiver only acknowledges data in order, when receiving out-of-order data, the receiver will send back the acknowledgment with the sequence number of the last packet it received.

When the sender receives an acknowledgment, it will shift its window to the sequence number of the acknowledgment + 1 because the receiver has just told the sender that it received the packet up to this acknowledgment.

![image](https://hackmd.io/_uploads/SycEnXl2p.png)

![image](https://hackmd.io/_uploads/ryFSnXenT.png)
