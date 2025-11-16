package org.example.parser;

import org.example.model.PacketInfo;
import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.*;

import java.net.InetAddress;

public class PacketParser {

    public PacketInfo parse(Packet packet) {
        PacketInfo info = new PacketInfo();
        info.timestamp = System.currentTimeMillis();
        info.packetLength = packet.length();

        // IPv4 or IPv6
        IpPacket ipPkt = packet.get(IpV4Packet.class);
        if (ipPkt == null) {
            ipPkt = packet.get(IpV6Packet.class);
        }

        if (ipPkt == null) {
            info.protocol = "NON-IP";
            return info;
        }

        InetAddress srcAddr = ipPkt.getHeader().getSrcAddr();
        InetAddress dstAddr = ipPkt.getHeader().getDstAddr();

        info.sourceIp = srcAddr != null ? srcAddr.getHostAddress() : null;
        info.destinationIp = dstAddr != null ? dstAddr.getHostAddress() : null;

        IpNumber proto = ipPkt.getHeader().getProtocol();

        // TCP
        if (proto == IpNumber.TCP) {
            info.protocol = "TCP";
            TcpPacket tcp = packet.get(TcpPacket.class);
            if (tcp != null) {
                info.sourcePort = tcp.getHeader().getSrcPort().valueAsInt();
                info.destinationPort = tcp.getHeader().getDstPort().valueAsInt();

                info.syn = tcp.getHeader().getSyn();
                info.ack = tcp.getHeader().getAck();
                info.fin = tcp.getHeader().getFin();
                info.rst = tcp.getHeader().getRst();
                info.psh = tcp.getHeader().getPsh();
                info.urg = tcp.getHeader().getUrg();
            }
        }

        // UDP
        else if (proto == IpNumber.UDP) {
            info.protocol = "UDP";
            UdpPacket udp = packet.get(UdpPacket.class);

            if (udp != null) {
                info.sourcePort = udp.getHeader().getSrcPort().valueAsInt();
                info.destinationPort = udp.getHeader().getDstPort().valueAsInt();

                // DNS detection (no DnsPacket)
                if (info.sourcePort == 53 || info.destinationPort == 53) {
                    parseDns(info, udp.getPayload());
                }
            }
        }

        // ICMP
        else if (proto == IpNumber.ICMPV4 || proto == IpNumber.ICMPV6) {
            info.protocol = "ICMP";
        }

        // Other protocols
        else {
            info.protocol = "OTHER";
        }

        return info;
    }

    /**
     * Manual DNS parsing (works with Pcap4J 1.8.2).
     */
    private void parseDns(PacketInfo info, Packet udpPayload) {
        if (udpPayload == null) return;

        byte[] raw = udpPayload.getRawData();
        if (raw == null || raw.length < 12) return; // not valid DNS

        try {
            int idx = 12; // DNS header size = 12 bytes
            StringBuilder qname = new StringBuilder();

            // Parse QNAME
            while (idx < raw.length) {
                int len = raw[idx] & 0xFF;
                idx++;

                if (len == 0) break; // end of qname
                if (idx + len > raw.length) break;

                qname.append(new String(raw, idx, len)).append(".");
                idx += len;
            }

            if (qname.length() > 0) {
                info.dnsQueryName = qname.substring(0, qname.length() - 1);
            }

            // QTYPE is next 2 bytes
            idx++;
            if (idx + 2 <= raw.length) {
                int qtype = ((raw[idx] & 0xFF) << 8) | (raw[idx + 1] & 0xFF);
                info.dnsQueryType = String.valueOf(qtype);
            }

        } catch (Exception ignored) {}
    }
}
