# Dockerfile placeholder.
#
# This file will build the discovery service with a multi-stage Go build.
# Runtime image must include libpcap support for gopacket/pcap and should be
# able to run both PCAP mode and live capture mode when the container is granted
# the required Linux capabilities.
