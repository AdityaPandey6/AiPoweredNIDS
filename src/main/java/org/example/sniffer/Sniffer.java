package org.example.sniffer;

import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;

public class Sniffer {

    private final String interfaceName;
    private PcapHandle handle;

    public Sniffer(String interfaceName) {
        this.interfaceName = interfaceName;
    }

    public void start() throws PcapNativeException, NotOpenException {
        // List interfaces (optional)
        System.out.println("Available Interfaces:");
        for (PcapNetworkInterface nif : Pcaps.findAllDevs()) {
            System.out.println(" - " + nif.getName() + " | " + nif.getDescription());
        }

        // Pick interface
        PcapNetworkInterface nif = Pcaps.getDevByName(interfaceName);

        if (nif == null) {
            System.err.println("❌ Interface not found: " + interfaceName);
            return;
        }

        System.out.println("Using interface: " + nif.getName());

        int snapshotLength = 65536;
        int timeout = 50;

        handle = nif.openLive(
                snapshotLength,
                PcapNetworkInterface.PromiscuousMode.PROMISCUOUS,
                timeout
        );

        System.out.println("Sniffer started. Listening on " + interfaceName + "...");

        // Capture loop
        while (true) {
            Packet packet = handle.getNextPacket();
            if (packet != null) {
                System.out.println("📦 Packet: " + packet);
            }
        }
    }

    public void stop() {
        if (handle != null && handle.isOpen()) {
            handle.close();
        }
    }
}
