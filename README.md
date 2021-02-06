# AlterOrder_RTP

This application allow to hide a message on specific RTP traffic flow. It implements both the encoder and the decoder, and needs IPTABLES to capture the traffic and modify the PDU order.

The algorithm it's based on the one Zhang et al [1] submitted. Basically, they suggest to alter the order of the video and audio PDU using parity to hide the message.

Linephone v.3.9.1 is mandatory as it separates voice and video content in two different PDUs.

# How it works




