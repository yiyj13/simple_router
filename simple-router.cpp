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
  Buffer* req = new Buffer(sizeof(ethernet_hdr) + sizeof(arp_hdr));
  // look up the routing table
  RoutingTableEntry entry = m_routingTable.lookup(ip);
  const Interface* outIface = findIfaceByName(entry.ifName);
  
  // handle ethernet header
  ethernet_hdr* eth_ptr = (ethernet_hdr*)(req->data());
  std::memcpy(eth_ptr->ether_shost, outIface->addr.data(), ETHER_ADDR_LEN);
  std::memset(eth_ptr->ether_dhost, 0xff, ETHER_ADDR_LEN);
  eth_ptr->ether_type = htons(ethertype_arp);

  // handle ARP
  arp_hdr* req_arp = (arp_hdr*)((uint8_t*)req_eth + sizeof(ethernet_hdr));
  req_arp->arp_hrd = htons(0x0001);
  req_arp->arp_pro = htons(0x0800);
  req_arp->arp_hln = 0x06;
  req_arp->arp_pln = 0x04;
  req_arp->arp_op = htons(0x01);
  req_arp->arp_sip = outIface->ip;
  req_arp->arp_tip = ip;
  std::memcpy(req_arp->arp_sha, outIface->addr.data(), ETHER_ADDR_LEN);
  std::memset(req_arp->arp_tha, 0xff, ETHER_ADDR_LEN);
    
  // send request
  sendPacket(*req, outIface->name);
}

void SimpleRouter::handleIPv4(const Buffer& packet, const std::string& inIface){
  std::cout << "Handling IPv4 packet" << std::endl;
  // check the validity of ip header
  // size
  if(packet.size() < sizeof(ethernet_hdr) + sizeof(ip_hdr)){
    std::cout<< "IP header has insufficient length, ignored." << std::endl;
    return;
  }
  // checksum
  ip_hdr* ip_ptr = (ip_hdr*)((uint8_t*)packet.data() + sizeof(ethernet_hdr));
  if(cksum(ip_ptr, sizeof(ip_ptr)) != 0xffff){
    std::cout<< "IP header checksum is invalid, ignored." << std::endl;
    return;
  }
  
  // classify datagrams
  const Interface* destIface = findIfaceByIp(ip_ptr->ip_dst);
  if (destIface != nullptr) {// destinated to the router  
    std::cout << "IP packet destinated to the router." << std::endl;
    // ICMP
    if (ip_ptr->ip_p == ip_protocol_icmp) {
      std::cout << "Handle ICMP." << std::endl;
      handleICMP(packet, inIface);
    }
    // TCP & UDP
    else {
      std::cout << "Sent Port unreachable." << std::endl;
      handleICMPPortUnreachable(packet, inIface);
    }
  }
  else{// to be forwarded
  std::cout << "Datagrams to be forwarded." << std::endl;
    if (ip_ptr->ip_ttl == 1) {// 超时
    std::cout << "Sent time exceeded message." << std::endl;
      handleICMPTimeExceeded(packet, inIface);
    }
    else{
      auto routing_entry = m_routingTable.lookup(ip_ptr->ip_dst);
      auto arp_entry = m_arp.lookup(ip_ptr->ip_dst);
      if(arp_entry == nullptr){
        m_arp.queueRequest(ip_ptr->ip_dst, packet, inIface);
      }
      else{
        forwardIPv4(packet, inIface);
      }
    }
  }
}

void SimpleRouter::forwardIPv4(const Buffer& packet, const std::string& inIface){
  ip_hdr* ip_ptr = (ip_hdr*)((uint8_t*)packet.data() + sizeof(ethernet_hdr));
  RoutingTableEntry entry = m_routingTable.lookup(ip_ptr->ip_dst);
  auto arp_entry = m_arp.lookup(ip_ptr->ip_dst);

  const Interface* outIface = findIfaceByName(routing_entry.ifName);
  Buffer* forward = new Buffer(packet);
  ethernet_hdr* fwd_eth = (ethernet_hdr*)((uint8_t*)forward->data());
  std::memcpy(fwd_eth->ether_dhost, arp_entry->mac.data(), ETHER_ADDR_LEN);
  std::memcpy(fwd_eth->ether_shost, outIface->addr.data(), ETHER_ADDR_LEN);
  ip_hdr* fwd_ip = (ip_hdr*)((uint8_t*)forward->data() + sizeof(ethernet_hdr));
  fwd_ip->ip_ttl--;
  fwd_ip->ip_sum = 0;
  fwd_ip->ip_sum = cksum(fwd_ip, sizeof(ip_hdr));

  sendPacket(*forward, routing_entry.ifName);
}

void SimpleRouter::handleICMP(const Buffer& packet, const std::string& inIface){
  std::cout << "Handling ICMP packet" << std::endl;
  // check the validity of icmp header
  // size
  if(packet.size() < sizeof(icmp_hdr) + sizeof(ip_hdr) + sizeof(ethernet_hdr)){
    std::cout << "ICMP header has insufficient length, ignored." << std::endl;
    return;
  }
  // type
  icmp_hdr* icmp_ptr = (icmp_hdr*)((uint8_t*)packet.data() + sizeof(ip_hdr) + sizeof(ethernet_hdr));
  if(icmp_ptr->icmp_type != 0x08 || icmp_ptr->icmp_code != 0x00){
    std::cout << "ICMP type is not echo request, ignored." << std::endl;
    return;
  }
  // checksum
  if (cksum((uint8_t*)icmp_ptr, packet.size() - sizeof(ip_hdr) - sizeof(ethernet_hdr)) != 0xffff) {
    std::cout << "ICMP header checksum is invalid, ignored." << std::endl;
    return;
  }

  ethernet_hdr* eth_ptr = (struct ethernet_hdr*)((uint8_t*)packet.data());
  ip_hdr* ip_ptr = (struct ip_hdr*)((uint8_t*)packet.data() + sizeof(ethernet_hdr));

  // look up the tables
  auto routing_entry = m_routingTable.lookup(ip_ptr->ip_src);
  auto arp_entry= m_arp.lookup(ip_ptr->ip_src);
  if(arpEntry == nullptr){
    m_arp.queueRequest(ip_ptr->ip_src, packet, inIface);
    return;
  }
  else{
    // send echo reply
    Buffer* reply = new Buffer(packet);
    const Interface* outIface = findIfaceByName(routing_entry.ifName);

    // ethernet header
    ethernet_hdr* rep_eth = (struct ethernet_hdr*)((uint8_t*)reply->data());
    std::memcpy(rep_eth->ether_dhost, eth_ptr->ether_shost, ETHER_ADDR_LEN);
    std::memcpy(rep_eth->ether_shost, eth_ptr->ether_dhost, ETHER_ADDR_LEN);

    // ip header
    ip_hdr* rep_ip = (struct ip_hdr*)((uint8_t*)reply->data() + sizeof(ethernet_hdr));
    rep_ip->ip_id = 0;
    rep_ip->ip_src = ip_ptr->ip_dst;
    rep_ip->ip_dst = ip_ptr->ip_src;
    rep_ip->ip_ttl = 64;
    rep_ip->ip_sum = 0;
    rep_ip->ip_sum = cksum((uint8_t*)rep_ip, sizeof(ip_hdr));

    // icmp header
    icmp_hdr* rep_icmp = (struct icmp_hdr*)((uint8_t*)reply->data() + sizeof(ip_hdr) + sizeof(ethernet_hdr));
    rep_icmp->icmp_type = 0x00;
    rep_icmp->icmp_code = 0x00;
    rep_icmp->icmp_sum = 0;
    rep_icmp->icmp_sum = cksum((uint8_t*)rep_icmp, reply->size() - sizeof(ip_hdr) - sizeof(ethernet_hdr));
    
    sendPacket(*reply, outIface->name);
  }
}

void SimpleRouter::handleICMPPortUnreachable(const Buffer& packet,const std::string& inIface){
  ethernet_hdr* eth_ptr = (struct ethernet_hdr*)((uint8_t*)packet.data());
  ip_hdr* ip_ptr = (struct ip_hdr*)((uint8_t*)packet.data() + sizeof(ethernet_hdr));
  
  // look up ARP table
  auto routing_entry = m_routingTable.lookup(ip_ptr->ip_src);
  auto arp_entry= m_arp.lookup(ip_ptr->ip_src);
  if(arp_entry == nullptr){
    m_arp.queueRequest(ip_ptr->ip_src, packet, inIface);
    return;
  }
  else{
    // send echo reply
    Buffer* reply = new Buffer(sizeof(struct ethernet_hdr)+sizeof(struct ip_hdr)+sizeof(icmp_t3_hdr));
    const Interface* outIface = findIfaceByName(routing_entry.ifName);

    ethernet_hdr* rep_eth = (struct ethernet_hdr*)((uint8_t*)reply->data());
    ip_hdr* rep_ip = (struct ip_hdr*)((uint8_t*)reply->data() + sizeof(ethernet_hdr));
    icmp_hdr* rep_icmp = (struct icmp_hdr*)((uint8_t*)reply->data() + sizeof(ethernet_hdr)) + sizeof(ip_hdr);
    std::memcpy(rep_eth, eth_ptr, sizeof(ethernet_hdr));
    std::memcpy(rep_ip, ip_ptr, sizeof(ip_hdr));

    // ethernet header
    std::memcpy(rep_eth->ether_shost, outIface->addr.data(), ETHER_ADDR_LEN);
    std::memcpy(rep_eth->ether_dhost, arp_entry->mac.data(), ETHER_ADDR_LEN);

    // ip header
    rep_ip->ip_id = 0;
    rep_ip->ip_p = ip_protocol_icmp;
    rep_ip->ip_len = htons(sizeof(ip_hdr) + sizeof(icmp_t3_hdr));
    rep_ip->ip_src = outIface->ip;
    rep_ip->ip_dst = ip_ptr->ip_src;
    rep_ip->ip_ttl = 64;
    rep_ip->ip_sum = 0;
    rep_ip->ip_sum = cksum((uint8_t*)rep_ip, sizeof(ip_hdr));

    // icmp header
    rep_icmp->icmp_type = 0x03;
    rep_icmp->icmp_code = 0x03;
    rep_icmp->next_mtu = 0;
    rep_icmp->unused = 0;
    std::memcpy((uint8_t*)rep_icmp->data, (uint8_t*)ip_ptr, ICMP_DATA_SIZE);
    rep_icmp->icmp_sum = 0;
    rep_icmp->icmp_sum = cksum((uint8_t*)rep_icmp, sizeof(icmp_t3_hdr));
    
    sendPacket(*reply, outIface->name);
  }
}

void SimpleRouter::handleICMPTimeExceeded(const Buffer& packet,const std::string& inIface){
  ethernet_hdr* eth_ptr = (struct ethernet_hdr*)((uint8_t*)packet.data());
  ip_hdr* ip_ptr = (struct ip_hdr*)((uint8_t*)packet.data() + sizeof(ethernet_hdr));
  
  // look up ARP table
  auto routing_entry = m_routingTable.lookup(ip_ptr->ip_src);
  auto arp_entry= m_arp.lookup(ip_ptr->ip_src);
  if(arp_entry == nullptr){
    m_arp.queueRequest(ip_ptr->ip_src, packet, inIface);
    return;
  }
  else{
    // send echo reply
    Buffer* reply = new Buffer(sizeof(struct ethernet_hdr)+sizeof(struct ip_hdr)+sizeof(icmp_t3_hdr));
    const Interface* outIface = findIfaceByName(routing_entry.ifName);

    ethernet_hdr* rep_eth = (struct ethernet_hdr*)((uint8_t*)reply->data());
    ip_hdr* rep_ip = (struct ip_hdr*)((uint8_t*)reply->data() + sizeof(ethernet_hdr));
    icmp_hdr* rep_icmp = (struct icmp_hdr*)((uint8_t*)reply->data() + sizeof(ethernet_hdr)) + sizeof(ip_hdr);
    std::memcpy(rep_eth, eth_ptr, sizeof(ethernet_hdr));
    std::memcpy(rep_ip, ip_ptr, sizeof(ip_hdr));

    // ethernet header
    std::memcpy(rep_eth->ether_shost, outIface->addr.data(), ETHER_ADDR_LEN);
    std::memcpy(rep_eth->ether_dhost, arp_entry->mac.data(), ETHER_ADDR_LEN);

    // ip header
    rep_ip->ip_id = 0;
    rep_ip->ip_p = ip_protocol_icmp;
    rep_ip->ip_len = htons(sizeof(ip_hdr) + sizeof(icmp_t3_hdr));
    rep_ip->ip_src = outIface->ip;
    rep_ip->ip_dst = ip_ptr->ip_src;
    rep_ip->ip_ttl = 64;
    rep_ip->ip_sum = 0;
    rep_ip->ip_sum = cksum((uint8_t*)rep_ip, sizeof(ip_hdr));

    // icmp header
    rep_icmp->icmp_type = 11;
    rep_icmp->icmp_code = 0;
    rep_icmp->next_mtu = 0;
    rep_icmp->unused = 0;
    std::memcpy((uint8_t*)rep_icmp->data, (uint8_t*)ip_ptr, ICMP_DATA_SIZE);
    rep_icmp->icmp_sum = 0;
    rep_icmp->icmp_sum = cksum((uint8_t*)rep_icmp, sizeof(icmp_t3_hdr));
    
    sendPacket(*reply, outIface->name);
  }
}

void SimpleRouter::handleICMPHostUnreachable(const Buffer& packet){
  ethernet_hdr* eth_ptr = (struct ethernet_hdr*)((uint8_t*)packet.data());
  ip_hdr* ip_ptr = (struct ip_hdr*)((uint8_t*)packet.data() + sizeof(ethernet_hdr));
  
  // look up ARP table
  auto routing_entry = m_routingTable.lookup(ip_ptr->ip_src);
  auto arp_entry= m_arp.lookup(ip_ptr->ip_src);

  // send reply
  Buffer* reply = new Buffer(sizeof(struct ethernet_hdr)+sizeof(struct ip_hdr)+sizeof(icmp_t3_hdr));
  const Interface* outIface = findIfaceByName(routing_entry.ifName);

  ethernet_hdr* rep_eth = (struct ethernet_hdr*)((uint8_t*)reply->data());
  ip_hdr* rep_ip = (struct ip_hdr*)((uint8_t*)reply->data() + sizeof(ethernet_hdr));
  icmp_hdr* rep_icmp = (struct icmp_hdr*)((uint8_t*)reply->data() + sizeof(ethernet_hdr)) + sizeof(ip_hdr);
  std::memcpy(rep_eth, eth_ptr, sizeof(ethernet_hdr));
  std::memcpy(rep_ip, ip_ptr, sizeof(ip_hdr));

  // ethernet header
  std::memcpy(rep_eth->ether_shost, outIface->addr.data(), ETHER_ADDR_LEN);
  std::memcpy(rep_eth->ether_dhost, arp_entry->mac.data(), ETHER_ADDR_LEN);

  // ip header
  rep_ip->ip_id = 0;
  rep_ip->ip_p = ip_protocol_icmp;
  rep_ip->ip_len = htons(sizeof(ip_hdr) + sizeof(icmp_t3_hdr));
  rep_ip->ip_src = outIface->ip;
  rep_ip->ip_dst = ip_ptr->ip_src;
  rep_ip->ip_ttl = 64;
  rep_ip->ip_sum = 0;
  rep_ip->ip_sum = cksum((uint8_t*)rep_ip, sizeof(ip_hdr));

  // icmp header
  rep_icmp->icmp_type = 3;
  rep_icmp->icmp_code = 1;
  rep_icmp->next_mtu = 0;
  rep_icmp->unused = 0;
  std::memcpy((uint8_t*)rep_icmp->data, (uint8_t*)ip_ptr, ICMP_DATA_SIZE);
  rep_icmp->icmp_sum = 0;
  rep_icmp->icmp_sum = cksum((uint8_t*)rep_icmp, sizeof(icmp_t3_hdr));
  
  sendPacket(*reply, outIface->name);
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
