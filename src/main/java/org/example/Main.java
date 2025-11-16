package org.example;

import org.example.sniffer.Sniffer;

public class Main {

    public static void main(String[] args) throws Exception {

        String iface = "wlo1";

        Sniffer sniffer = new Sniffer(iface);
        sniffer.start();

        // If you want graceful shutdown later:
        // Runtime.getRuntime().addShutdownHook(new Thread(sniffer::stop));
    }
}
