/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2017 Alexander Afanasyev
 *
 * This program is free software: you can redistribute it and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software Foundation, either version
 * 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program.
 * If not, see <http://www.gnu.org/licenses/>.
 */

#include "simple-router.hpp"
#include "core/utils.hpp"

#include <fstream>

namespace simple_router {

void SimpleRouter::handleArp(const Buffer& packet, const std::string& inIface){
  std::cout << "Handling ARP packet" << std::endl;
  // check the validity of arp header
  // size
  if(packet.size() < sizeof(arp_hdr)){
    std::cout<< "ARP header has insufficient length, ignored." << std::endl;
    return;
  }
  auto* arp_ptr = (struct arp_hdr*)((uint8_t*)packet.data() + sizeof(ethernet_hdr));
  // type
  if(ntohs(arp_ptr->arp_hrd) != arp_hrd_ethernet){
    std::cout<< "ARP hardware type is not ethernet, ignored." << std::endl;
    return;
  }
  // addr len
  if(arp_ptr->arp_hln != 0x06){
    std::cout<< "ARP hardware has invalid address length, ignored." << std::endl;
    return;
  }
  // proto type
  if(ntohs(arp_ptr->arp_pro) != ethertype_ip){
    std::cout<< "ARP protocol type is not IPv4, ignored." << std::endl;
    return;
  }
  // proto len
  if(arp_ptr->arp_pln != 0x04){
    std::cout<< "ARP protocol has invalid address length, ignored." << std::endl;
    return;
  }
  // opcode
  if(ntohs(arp_ptr->arp_op) != arp_op_request && ntohs(arp_ptr->arp_op) != arp_op_reply){
    std::cout<< "ARP opcode is not request or reply, ignored." << std::endl;
    return;
  }
  
  // handle request or reply
  const Interface* iface = findIfaceByName(inIface);
  // request
  if(ntohs(arp_ptr->arp_op) == arp_op_request){
    if(arp_ptr->arp_tip == iface->ip){
      handleArpRequest(packet, inIface);
    }
    else{
      std::cout << "Arp destination is not the router, ignored." << std::endl;
    }
  }
  // reply
  else{
    handleArpReply(packet);
  }
}

void handleArpRequest(const Buffer& packet, const std::string& inIface){
  std::cout << "Handling ARP request" << std::endl;

  // ARP request
  ethernet_hdr* req_eth = (ethernet_hdr*)(packet.data());
  arp_hdr* req_arp = (arp_hdr*)((u_int8_t*)req_eth + sizeof(ethernet_hdr));
  // ARP reply
  Buffer* reply = new Buffer(packet);
  ethernet_hdr* rep_eth = (ethernet_hdr*)(reply->data());
  arp_hdr* rep_arp = (arp_hdr*)((uint8_t*)rep_eth + sizeof(ethernet_hdr));
  
  // update params
  const Interface* iface = findIfaceByName(inIface);
  // ethernet
  std::memcpy(rep_eth->ether_shost, iface->addr.data(), ETHER_ADDR_LEN);
  std::memcpy(rep_eth->ether_dhost, req_eth->ether_shost, ETHER_ADDR_LEN);
  // arp
  rep_arp->arp_sip = req_arp->arp_tip;
  rep_arp->arp_tip = req_arp->arp_sip;
  rep_arp->arp_op = htons(0x0002);
  std::memcpy(rep_arp->arp_sha, iface->addr.data(), 6);
  std::memcpy(rep_arp->arp_tha, req_arp->arp_sha, 6);

  // send reply
  sendPacket(*reply, inIface);

}

void handleArpReply(const Buffer& packet){
  std::cout << "Handling ARP reply" << std::endl;

  arp_hdr* arp_ptr = (arp_hdr*)((uint8_t*)packet.data() + sizeof(ethernet_hdr));
  uint32_t sender_ip = arp_ptr->arp_sip;
  Buffer sender_mac(arp_ptr->arp_sha, arp_ptr->arp_sha + 6);
  
  // pairing IP/MAC
  if (!m_arp.lookup(sender_ip)) {
    auto arp_req = m_arp.insertArpEntry(sender_mac, sender_ip);
    if (arp_req) {
      std::cout << "Handle queued requests for the IP/MAC" << std::endl;
      for (const auto& packet : arp_req->packets) {
        handlePacket(packet.packet, packet.iface);
      }
      m_arp.removeRequest(arp_req);
      } else {
        std::cout << "No queued requests for the IP/MAC" << std::endl;
      }
    } else {
      std::cout << "IP/MAC already exists" << std::endl;
    }
}

void sendArpRequest(uint32_t ip){
  
}

void SimpleRouter::handleIPv4(const Buffer& packet, const std::string& inIface){
  std::cout << "Handling IPv4 packet" << std::endl;
  // check the validity of ip header
  // size
  if(packet.size() < sizeof(ip_hdr)){
    std::cout<< "IP header has insufficient length, ignored." << std::endl;
    return;
  }
  auto* ip_ptr = (struct ip_hdr*)((uint8_t*)packet.data() + sizeof(ethernet_hdr));
  // version
  if((ip_ptr->ip_vhl & 0xf0) != 0x40){
    std::cout<< "IP version is not 4, ignored." << std::endl;
    return;
  }
  // header len
  if((ip_ptr->ip_vhl & 0x0f) < 5){
    std::cout<< "IP header length is less than 5, ignored." << std::endl;
    return;
  }
  // total len
  if(ntohs(ip_ptr->ip_len) != packet.size()){
    std::cout<< "IP total length is not equal to packet size, ignored." << std::endl;
    return;
  }
  // ttl
  if(ip_ptr->ip_ttl == 0){
    std::cout<< "IP ttl is 0, ignored." << std::endl;
    return;
  }
  // checksum
  if(ip_ptr->ip_sum != 0){
    std::cout<< "IP checksum is not 0, ignored." << std::endl;
    return;
  }
  // protocol
  if(ip_ptr->ip_p != ip_protocol_icmp && ip_ptr->ip_p != ip_protocol_tcp && ip_ptr->ip_p != ip_protocol_udp){
    std::cout<< "IP protocol is not ICMP, TCP or UDP, ignored." << std::endl;
    return;
  }
  // src addr
  if(findIfaceByIp(ip_ptr->ip_src) == nullptr){
    std::cout<< "IP source address is not the router, ignored." << std::endl;
    return;
  }
  // dest addr
  if(findIfaceByIp(ip_ptr->ip_dst) == nullptr){
    std::cout<< "IP destination address is not the router, ignored." << std::endl;
    return;
  }

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// IMPLEMENT THIS METHOD
void
SimpleRouter::handlePacket(const Buffer& packet, const std::string& inIface)
{
  std::cerr << "Got packet of size " << packet.size() << " on interface " << inIface << std::endl;

  const Interface* iface = findIfaceByName(inIface);
  if (iface == nullptr) {
    std::cerr << "Received packet, but interface is unknown, ignoring" << std::endl;
    return;
  }

  std::cerr << getRoutingTable() << std::endl;

  // FILL THIS IN

  // check the validity of ethernet header
  // size
  if(packet.size() < sizeof(ethernet_hdr)){
    std::cout<< "Ethernet header has insufficient length, ignored." << std::endl;
    return;
  }
  // type
  ethernet_hdr* eth_hdr = (ethernet_hdr*) packet.data();
  uint16_t eth_type = ethertype((uint8_t*)eth_ptr);
  if(eth_type != ethertype_ip && eth_type != ethertype_arp){
    std::cout<< "Ethernet frame has unsupported type, ignored." << std::endl;
    return;
  }
  // dest addr
  if (std::memcmp(eth_ptr->ether_dhost, iface->addr.data(), 6) ||
    std::all_of(eth_ptr->ether_dhost, eth_ptr->ether_dhost + 6, [](uint8_t a) { return a == 0xff; })) {
    // 指向路由或广播
    if (std::memcmp(eth_ptr->ether_dhost, iface->addr.data(), 6)) {
        std::cout << "Destination host is the interface MAC address of router" << std::endl;
    } else {
      std::cout << "Destination host is broadcast address" << std::endl;
    }
  } else {
    // 非法目的地址
    std::cout << "Destination host is invalid, ignoring" << std::endl;
    return;
  }

  // handle by size
  // arp
  if(eth_type == ethertype_arp){
    handleArp(packet, inIface);
  }
  else{
    handleIPv4(packet, inIface);
  }
}
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.
SimpleRouter::SimpleRouter()
  : m_arp(*this)
{
}

void
SimpleRouter::sendPacket(const Buffer& packet, const std::string& outIface)
{
  m_pox->begin_sendPacket(packet, outIface);
}

bool
SimpleRouter::loadRoutingTable(const std::string& rtConfig)
{
  return m_routingTable.load(rtConfig);
}

void
SimpleRouter::loadIfconfig(const std::string& ifconfig)
{
  std::ifstream iff(ifconfig.c_str());
  std::string line;
  while (std::getline(iff, line)) {
    std::istringstream ifLine(line);
    std::string iface, ip;
    ifLine >> iface >> ip;

    in_addr ip_addr;
    if (inet_aton(ip.c_str(), &ip_addr) == 0) {
      throw std::runtime_error("Invalid IP address `" + ip + "` for interface `" + iface + "`");
    }

    m_ifNameToIpMap[iface] = ip_addr.s_addr;
  }
}

void
SimpleRouter::printIfaces(std::ostream& os)
{
  if (m_ifaces.empty()) {
    os << " Interface list empty " << std::endl;
    return;
  }

  for (const auto& iface : m_ifaces) {
    os << iface << "\n";
  }
  os.flush();
}

const Interface*
SimpleRouter::findIfaceByIp(uint32_t ip) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [ip] (const Interface& iface) {
      return iface.ip == ip;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByMac(const Buffer& mac) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [mac] (const Interface& iface) {
      return iface.addr == mac;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByName(const std::string& name) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [name] (const Interface& iface) {
      return iface.name == name;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

void
SimpleRouter::reset(const pox::Ifaces& ports)
{
  std::cerr << "Resetting SimpleRouter with " << ports.size() << " ports" << std::endl;

  m_arp.clear();
  m_ifaces.clear();

  for (const auto& iface : ports) {
    auto ip = m_ifNameToIpMap.find(iface.name);
    if (ip == m_ifNameToIpMap.end()) {
      std::cerr << "IP_CONFIG missing information about interface `" + iface.name + "`. Skipping it" << std::endl;
      continue;
    }

    m_ifaces.insert(Interface(iface.name, iface.mac, ip->second));
  }

  printIfaces(std::cerr);
}


} // namespace simple_router {
