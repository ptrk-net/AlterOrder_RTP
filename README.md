# AlterOrder_RTP

This application allow to hide a message on specific RTP traffic flow. It implements both the encoder and the decoder, and needs IPTABLES to capture the traffic and modify the PDU order.

The algorithm it's based on the one Zhang et al [1] submitted. Basically, they suggest altering the order of the video and audio PDU using parity to hide the message. Note that the number of video and audio PDU sent it's 1:5.

Linephone v.3.9.1 is mandatory as it separates voice and video content in two different PDUs.

# How it works

The program transforms the message to hide into bits, starts to capture each packet with IPTABLES and NFQUEUE and processes an algorithm depends on which mode it's executing.

- Encoder:
  1) It uses the video PDU to mark the new bit and audio PDU to set the bit.
  2) It sends the audio PDU while arriving.
  3) If a video PDU wants to reach the network, it'll check the parity of the number of audio PDU that has been sent. When suits the bit that should be hidden, it'll send the video PDU. If not, it'll retain all the video PDUs until an audio PDU arrives and allows to get the correct parity.
  4) When the message has been finished, it'll send a 0-type PDU to inform the decoder and will let pass through all the rest of RTP PDUs.
    
- Decoder:
  1) Just gets the parity from the audio PDUs between video PDUs.
  2) It prints out each character (8 bits) at the moment it's completed.
    
# Possible improvements

- It's not bidirectional, like the RTP traffic.
- There is no protocol to control the hidden communication. This means there are neither flow nor error control mechanisms, so if just a packet get lost, it changes completely the final message. Develop a protocol should take into account that any long pattern could be used to attack the communication with a properly trained machine learning algorithm.

# Configuration

As it's been said, IPTABLES it's needed differently depending on which end uses it. 

- Encoder: uses the chain that identifies the moment just before sending the packet.

`$ sudo iptables -t mangle -A POSTROUTING -p UDP --match multiport --dports 7078,9078 -j NFQUEUE --queue-num 1`

- Decoder: uses the chain meant to be just when the packets arrive.

`$ sudo iptables -t mangle -A INPUT -p UDP --match multiport --dports 7078,9078 -j NFQUEUE --queue-num 1`

Furthermore, the program needs the fnfqueue library.

# Execution

Basically, the arguments allow to decode a message hidden in the RTP network traffic or encode a message that can be passed as a parameter or read from a file.

`$ python3 ./AlterOrder_RTP.py [-v|-d] (decoder|encoder (ncc|cc [\'Message\'|-t file_name]))`



<br><br>
[1] Xiaosong Zhang, Liehuang Zhu, Xianmin Wang, Changyou Zhang, Hongfei Zhu, Yu-an Tan. A packet-reordering covert channel over VoLTE voice and video traffics. Journal of Network and Computer Applications, 26 (2019) 29–38.
