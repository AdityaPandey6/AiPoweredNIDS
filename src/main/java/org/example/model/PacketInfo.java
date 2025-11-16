package org.example.model;

public class PacketInfo {
    public String sourceIp;
    public String destinationIp;
    public Integer sourcePort;
    public Integer destinationPort;
    public long timestamp;
    public String protocol;
    public int packetLength;
//  Flags
    public boolean syn;
    public boolean ack;
    public boolean fin;
    public boolean rst;
    public boolean psh;
    public boolean urg;

    public String dnsQueryName;
    public String dnsQueryType;

    @Override
    public String toString() {
        return "PacketInfo{" +
                "ts=" + timestamp +
                ", src=" + sourceIp +
                ":" + (sourcePort==null?"-":sourcePort) +
                ", dst=" + destinationIp +
                ":" + (destinationPort==null?"-":destinationPort) +
                ", proto=" + protocol +
                ", len=" + packetLength +
                ", flags=[SYN=" + syn + ",ACK=" + ack + ",FIN=" + fin + ",RST=" + rst + "]" +
                (dnsQueryName != null ? ", dns=" + dnsQueryName + "/" + dnsQueryType : "") +
                '}';
    }
}
