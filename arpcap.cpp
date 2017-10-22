#include <unistd.h>
#include <arpa/inet.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <execinfo.h>
#include <cstring>
#include <string>
#include <stdexcept>
#include <system_error>
#include <sstream>
#include <iostream>
#include <iomanip>

typedef int arp_fd;
typedef int interface_id;
typedef unsigned char mac_address_data[6];
typedef unsigned char ip_address_data[4];

/// Plain old data structure to hold arp address information.
struct arp_address_data
{
    mac_address_data sender_mac;;
    ip_address_data sender_ip;
    mac_address_data target_mac;
    ip_address_data target_ip;
};

/// Converts numeric mac address bits to a human-readable string.
std::string mac_ntoa(mac_address_data mac)
{
    std::stringstream s;
    for (int d = 0; d != 6 ; ++d)
    {
      s << std::setfill('0') << std::setw(sizeof(char)*2);
      s << std::hex << (int)mac[d];
      if (d != 5) s << ":";
    }
    return s.str();
}

/// Converts numeric ip address bits to a human-readable string.
std::string ip_ntoa(ip_address_data ip)
{
    in_addr ip_a = {};
    memcpy(&ip_a.s_addr, ip, sizeof(uint32_t));
    return inet_ntoa(ip_a); 
}

/// Plain old data structure to hold ethernet packet data.
struct ethernet_packet_data
{
    /// Constructor.
    ethernet_packet_data(unsigned char* ptr=0, ssize_t len=0)
        : pointer_to_data(ptr), data_length(len) { };
    /// Holds pointer to raw packet data.
    unsigned char* pointer_to_data;
    /// Size of raw packet data.
    ssize_t data_length;
};

/// Dumps a stack trace to stderr.
void print_trace()
{
    void *trace_elems[20];
    int trace_elem_count(backtrace( trace_elems, 20 ));
    char **stack_syms(backtrace_symbols( trace_elems, trace_elem_count ));
    for ( int i = 0 ; i < trace_elem_count ; ++i )
    {
        std::cerr << stack_syms[i] << "\n";
    }
    free(stack_syms);
}

/** 
 * Creates an ARP socket.
 * @returns Returns a file descriptor for arp socket operations.
 */
arp_fd create_arp_socket()
{
    arp_fd result = socket(AF_PACKET, SOCK_RAW, htons(ETHERTYPE_ARP));
    if (result <= 0)
    {
        throw std::system_error(1,std::generic_category(),
            "Could not create socket.");
    }
    return result;
}

/**
 * Get interface ID based on interface name.
 * @param interface_name : Name of interface to get ID of.
 * @return Returns the interface ID of given interface.
 */
interface_id get_interface_id(const std::string& interface_name)
{
    interface_id result=-1;
    ifreq ifr = {};
    arp_fd fd = create_arp_socket();
    if (interface_name.length() > (IFNAMSIZ - 1))
    {
        throw std::invalid_argument("Interface name too long.");
    }
    strncpy(ifr.ifr_name, interface_name.c_str(), 
        sizeof(char)*interface_name.length());
    if (ioctl(fd, SIOCGIFINDEX, &ifr) == -1)
    {
        throw std::system_error(2,std::generic_category(),
            "ioctl failed.");
    }
    result = ifr.ifr_ifindex;
    close(fd);
    return result;
}

/**
 * Starts listening for arp traffic.
 * @param interface : Interface ID of interface to listen on.
 * @return Returns an open file descriptor from which arp packets can be read.
 */
arp_fd listen_for_arp(interface_id interface)
{
    arp_fd fd = create_arp_socket();
    sockaddr_ll saddrll = {};
    saddrll.sll_family = AF_PACKET;
    saddrll.sll_ifindex = interface;
    sockaddr* saddr = reinterpret_cast<sockaddr*>(&saddrll);
    const sockaddr* csaddr = const_cast<const sockaddr*>(saddr);
    int bind_result = bind(fd,csaddr,sizeof(sockaddr_ll));
    if (bind_result < 0)
    {
        if (fd > 0) close(fd);
        throw std::system_error(3,std::generic_category(),
            "Could not bind socket.");
    }
    return fd;
}

/**
 * Reads an ethernet packet from file descriptor.
 *
 * This is a blocking call.
 *
 * @param fd : File descriptor to read packet from.
 * @param buffer_size : Packet buffer size (optional, defaults to 60).
 * @return Returns a pointer to the raw ethernet packet data.
 */
ethernet_packet_data* read_ethernet_packet(int fd, int buffer_size=60)
{
    ethernet_packet_data* result = new ethernet_packet_data();
    unsigned char* buffer = new unsigned char[buffer_size];
    ssize_t rxlen = read(fd, buffer, buffer_size);
    if (rxlen == -1)
    {
        delete result;
        throw std::system_error(4,std::generic_category(),
            "Could not read from socket.");
    }
    result->pointer_to_data = buffer;
    result->data_length = rxlen;
    return result;
}


void parse_arp(ethernet_packet_data* packet_data)
{
    unsigned char* data = packet_data->pointer_to_data;
    static const ssize_t minimum_size = sizeof(ethhdr)+sizeof(arphdr)
        + sizeof(arp_address_data);
    if (packet_data->data_length < minimum_size)
    {
        std::cerr << "Received too small of a packet ";
        std::cerr << "(got "+std::to_string(packet_data->data_length);
        std::cerr << " bytes, need " << std::to_string(minimum_size);
        std::cerr << " bytes)." << std::endl;
        return;
    }
    ethhdr* rcv_resp = reinterpret_cast<ethhdr*>(data);
    arphdr* arp_resp = reinterpret_cast<arphdr*>(data + sizeof(ethhdr));
    if (ntohs(rcv_resp->h_proto) != ETHERTYPE_ARP) {
        std::cerr << "Not an ARP packet" << std::endl;
        return;
    }
    std::string out = "ARP opcode=";
    uint16_t opcode = ntohs(arp_resp->ar_op);
    switch(opcode)
    {
        case ARPOP_REQUEST:
            out += "REQUEST";
            break;
        case ARPOP_REPLY:
            out += "REPLY";
            break;
        case ARPOP_RREQUEST:
            out += "RARP REQUEST";
            break;
        case ARPOP_RREPLY:
            out += "RARP REPLY";
            break;
        case ARPOP_InREQUEST:
            out += "InARP REQUEST";
            break;
        case ARPOP_InREPLY:
            out += "InARP REPLY";
            break;
        case ARPOP_NAK:
            out += "(ATM)ARP NAK";
            break;
        default:
            out += "UNKNOWN ("+std::to_string(opcode)+")";
            break;
    }
    out += " size="+std::to_string(packet_data->data_length);
    data += sizeof(ethhdr) + sizeof(arphdr);
    arp_address_data arp_addr_info = {};
    arp_addr_info = *reinterpret_cast<arp_address_data*>(data);
    out += " sender_mac=";
    out += mac_ntoa(arp_addr_info.sender_mac);
    out += " sender_ip=";
    out += ip_ntoa(arp_addr_info.sender_ip);
    out += " target_mac=";
    out += mac_ntoa(arp_addr_info.target_mac);
    out += " target_ip=";
    out += ip_ntoa(arp_addr_info.target_ip);
    std::cout << out << std::endl;
}

int main(int argc, char* argv[])
{
    arp_fd fd = 0;
    if (argc != 2)
    {
        std::cerr << "Missing argument: interface name." << std::endl;
        std::cerr << "Usage: " << argv[0] << " <interface name>" << std::endl;
        return 1;
    }
    try
    {
        interface_id ifid = get_interface_id(argv[1]);
        fd = listen_for_arp(ifid);
        while(true)
        {
            ethernet_packet_data* data = read_ethernet_packet(fd);
            if (data)
            {
                parse_arp(data);
            }
        }
        close(fd);
    }
    catch(std::system_error e)
    {
        std::cerr << e.what() << std::endl;
        print_trace();
        if (fd > 0) close(fd);
        return 1;
    }
    return 0;
}
