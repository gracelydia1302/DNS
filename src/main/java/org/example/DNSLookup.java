package org.example;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.UnknownHostException;

public class DNSLookup {

    private static final int DNS_PORT = 53;
    private static final int BUFFER_SIZE = 512; // DNS messages are typically less than this size

    public static void main(String[] args) {
        if (args.length != 2) {
            System.out.println("Usage: java DNSLookup <DNS server IP> <domain name>");
            System.exit(1);
        }

        String dnsServerIp = args[0];
        String domainName = args[1];

        try {
            byte[] dnsQuery = createDNSQuery(domainName);
            byte[] response = sendQuery(dnsServerIp, dnsQuery);
            String ipAddress = parseDNSResponse(response);
            System.out.println(ipAddress);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static byte[] createDNSQuery(String domainName) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();

        // Transaction ID (2 bytes)
        bos.write(new byte[]{0x12, 0x34});

        // Flags (2 bytes)
        bos.write(new byte[]{0x01, 0x00});

        // Number of Questions (2 bytes)
        bos.write(new byte[]{0x00, 0x01});

        // Number of Answer RRs (2 bytes)
        bos.write(new byte[]{0x00, 0x00});

        // Number of Authority RRs (2 bytes)
        bos.write(new byte[]{0x00, 0x00});

        // Number of Additional RRs (2 bytes)
        bos.write(new byte[]{0x00, 0x00});

        // Question section
        for (String label : domainName.split("\\.")) {
            bos.write((byte) label.length());
            bos.write(label.getBytes());
        }
        bos.write(0x00); // End of domain name

        // QTYPE (2 bytes) - A record
        bos.write(new byte[]{0x00, 0x01});

        // QCLASS (2 bytes) - IN
        bos.write(new byte[]{0x00, 0x01});

        return bos.toByteArray();
    }

    private static byte[] sendQuery(String dnsServerIp, byte[] query) throws IOException {
        DatagramSocket socket = new DatagramSocket();
        InetAddress dnsServerAddress = InetAddress.getByName(dnsServerIp);

        DatagramPacket requestPacket = new DatagramPacket(query, query.length, dnsServerAddress, DNS_PORT);
        socket.send(requestPacket);

        DatagramPacket responsePacket = new DatagramPacket(new byte[BUFFER_SIZE], BUFFER_SIZE);
        socket.receive(responsePacket);

        socket.close();
        return responsePacket.getData();
    }

    private static String parseDNSResponse(byte[] response) {
        int offset = 12; // Skip the header (12 bytes)

        // Skip the question section
        while (response[offset] != 0x00) {
            offset += response[offset] + 1;
        }
        offset += 5; // Skip null byte and QTYPE/QCLASS

        // Answer section
        if (response[offset + 1] == 0x00 && response[offset + 2] == 0x01) { // Type A
            offset += 10; // Skip NAME, TYPE, CLASS, TTL, and RDLENGTH

            // IP address (4 bytes)
            String ipAddress = (response[offset] & 0xFF) + "." +
                    (response[offset + 1] & 0xFF) + "." +
                    (response[offset + 2] & 0xFF) + "." +
                    (response[offset + 3] & 0xFF);
            return ipAddress;
        }
        return "No A record found";
    }
}