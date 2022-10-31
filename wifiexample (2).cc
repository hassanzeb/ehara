
#include "ns3/command-line.h"
#include "ns3/config.h"
#include "ns3/uinteger.h"
#include "ns3/double.h"
#include "ns3/string.h"
#include "ns3/log.h"
#include "ns3/yans-wifi-helper.h"
#include "ns3/mobility-helper.h"
#include "ns3/ipv4-address-helper.h"
#include "ns3/yans-wifi-channel.h"
#include "ns3/mobility-model.h"
#include "ns3/ipv4-static-routing-helper.h"
#include "ns3/ipv4-list-routing-helper.h"
#include "ns3/internet-stack-helper.h"
#include "ns3/netanim-module.h"
#include "ns3/energy-module.h"
#include "ns3/applications-module.h"
#include "ns3/on-off-helper.h"
#include "ns3/packet-sink-helper.h"
#include "ns3/test.h"
#include "ns3/simulator.h"
#include "ns3/simple-channel.h"
#include "ns3/simple-net-device.h"
#include "ns3/socket.h"
#include "ns3/boolean.h"
#include "ns3/double.h"
#include "ns3/string.h"
#include "ns3/config.h"
#include "ns3/data-rate.h"
#include "ns3/uinteger.h"

#include "ns3/names.h"
#include "ns3/log.h"
#include "ns3/node.h"
#include "ns3/inet-socket-address.h"
#include "ns3/random-variable-stream.h"

#include "ns3/ipv4-l3-protocol.h"
#include "ns3/ipv4-static-routing.h"
#include "ns3/udp-socket-factory.h"
#include "ns3/udp-socket.h"
#include "ns3/packet-sink.h"

#include "ns3/internet-stack-helper.h"
#include "ns3/ipv4-list-routing-helper.h"
#include "ns3/ipv4-static-routing-helper.h"
#include "ns3/ipv4-address-helper.h"
#include "ns3/simple-net-device-helper.h"
#include "ns3/packet-sink-helper.h"
#include "ns3/on-off-helper.h"
#include "ns3/trace-helper.h"

#include "ns3/traffic-control-layer.h"

#include <string>
#include <limits>
#include <functional>
#include "ns3/wifi-net-device.h"
#include "ns3/wifi-mac.h"
using namespace ns3;

NS_LOG_COMPONENT_DEFINE ("WifiSimpleAdhocGrid");
void RecvInitp (Ptr<Socket> socket, Ptr<Packet> p, Ipv4Address receiver, Ipv4Address src, uint16_t port);
void SendReply (Ptr<Socket> socket, Ipv4Address sender, Ipv4Address receiver, Ipv4Address leader, uint16_t port);
void ReceivePacket (Ptr<Socket> socket);
void ForwardPacket(Ptr<Socket> socket,Ipv4Address sender, Ipv4Address receiver, Ipv4Address dst, Ipv4Address leader, uint16_t port);
void RecvReply (Ptr<Socket> socket, Ptr<Packet> p, Ipv4Address receiver, Ipv4Address sender);

Ptr<Socket>
 SetupPacketReceive (Ipv4Address addr, Ptr<Node> node, uint16_t port)
 {
  TypeId tid = TypeId::LookupByName ("ns3::UdpSocketFactory");
  Ptr<Socket> sink = Socket::CreateSocket (node, tid);
  InetSocketAddress local = InetSocketAddress (addr, port);
   sink->Bind (local);
   sink->SetRecvCallback (MakeCallback (&ReceivePacket));
   return sink;
 }

 void SendReply (Ptr<Socket> socket, Ipv4Address sender,Ipv4Address receiver,  Ipv4Address leader, uint16_t port)
 {
Ptr<Node> n1 =socket->GetNode();

Ptr<Packet> packet = Create<Packet> ();

   RepHeader repHeader;
       repHeader.SetOrigin(receiver);
       repHeader.SetLeader(leader);
       repHeader.SetRemEng(0);
          repHeader.SetRemEng1(0);  
           repHeader.SetRemEng2(0);  
        repHeader.Sethp(1); 
        repHeader.Sethp1(2); 
        repHeader.Sethp2(1); 
        repHeader.Seteh(2);
        repHeader.Seteh1(2);  
          repHeader.Seteh2(0);    
          /////////////////
        SocketIpTtlTag tag;
      tag.SetTtl (2);
      packet->AddPacketTag (tag);
      packet->AddHeader (repHeader);
      TypeHeader tHeader (EHARATYPE_REPP);
      packet->AddHeader (tHeader);
       //uint32_t n1 =socket->GetNode()->GetId();
 /////==========================Method 1==============================    
//Ptr<Node> n = socket->GetNode();
//Ptr<NetDevice> dev = n->GetDevice(0);
//Ptr<WifiNetDevice> wifi_dev = DynamicCast<WifiNetDevice> (dev);
//Ptr <WifiNetDevice> dev = DynamicCast <WifiNetDevice> (n->GetDevice (0));
//wifi_dev->Send (packet Mac48Address::GetBroadcast(), 0x0800); 
/////==========================Method 2============================== 
//TypeId tid = TypeId::LookupByName ("ns3::UdpSocketFactory");
//Ptr<Socket> source = Socket::CreateSocket (n1, tid);
 
//InetSocketAddress remote = InetSocketAddress (sender, port);
//source->Bind (remote);
//source->Connect (remote); 
//source->Send (packet);
/////==========================Method 3============================== 

socket->SendTo (packet, 0, InetSocketAddress (receiver, port));

 }
void ForwardPacket(Ptr<Socket> socket,Ipv4Address sender, Ipv4Address receiver, Ipv4Address dst, Ipv4Address leader, uint16_t port)
{

std::cout<<"forward function called" <<std::endl;
  InitpHeader initpHeader;
Ptr<Node> n1 =socket->GetNode();
//uint32_t id = socket->GetNode ()->GetId();
 Ptr<Ipv4> ipv4 = n1->GetObject<Ipv4> ();
         Ipv4InterfaceAddress iaddr = ipv4->GetAddress (1,0); 
         Ipv4Address myip1 = iaddr.GetLocal ();
         
    Ptr<Packet> p = Create<Packet> ();

         initpHeader.SetPrnt(myip1);
         initpHeader.SetLeader(leader);
       initpHeader.SetRemEng(0);
          initpHeader.SetRemEng1(0);  
           initpHeader.SetRemEng2(0);  
        initpHeader.Sethp(1); 
        initpHeader.Sethp1(2); 
        initpHeader.Sethp2(1); 
        initpHeader.Seteh(2);
        initpHeader.Seteh1(2);  
          initpHeader.Seteh2(0);    
          /////////////////
        SocketIpTtlTag tag;
      tag.SetTtl (2);
      p->AddPacketTag (tag);
      p->AddHeader (initpHeader);
      TypeHeader tHeader (EHARATYPE_INITP);
      p->AddHeader (tHeader);  
InetSocketAddress remote = InetSocketAddress (dst, port);
//socket->SetAllowBroadcast (true);
socket->Connect (remote);
//socket->Send (p);
socket->SendTo (p, 0, InetSocketAddress (dst, port));

}

void RecvReply (Ptr<Socket> socket)
 {
 
 std::cout<<"Reply Received"<<std::endl;
 }
void
ReceivePacket (Ptr<Socket> socket)
{

  Ptr<Packet> packet;
  
  Address from;
  
  while ((packet = socket->RecvFrom (from)))
    {
     
   Address sourceAddress;
   InetSocketAddress iaddr12 = InetSocketAddress::ConvertFrom (from);
   Ipv4Address sender = iaddr12.GetIpv4 ();
   uint16_t port = iaddr12.GetPort ();
  Ptr<Node> n1 =socket->GetNode();

   Ptr<Ipv4> ipv4 = n1->GetObject<Ipv4> ();
         Ipv4InterfaceAddress iaddr1 = ipv4->GetAddress (1,0); 
         Ipv4Address receiver = iaddr1.GetLocal (); 
                
         ////////////////////////////////
  TypeHeader tHeader (EHARATYPE_INITP);
  packet->RemoveHeader (tHeader);
  if (!tHeader.IsValid ())
    {
    NS_LOG_DEBUG ("EAHARA message " << packet->GetUid () << " with unknown type received: " << tHeader.Get () << ". Drop");
      return; // drop
    }
  switch (tHeader.Get ())
    {
    case EHARATYPE_INITP:
      {
        RecvInitp (socket, packet, sender, receiver, port);
        break;
      }
    case EHARATYPE_REPP:
      {
       RecvReply (socket);
        break;
      }
    
    }
         
    }
}
void RecvInitp (Ptr<Socket> socket, Ptr<Packet> p, Ipv4Address sender, Ipv4Address receiver, uint16_t port)
{

 InitpHeader initpHeader;
 p->RemoveHeader (initpHeader);
Ipv4Address dst = initpHeader.GetDst();

Ipv4Address leader = initpHeader.GetLeader();
Ptr<Node> n1 =socket->GetNode();

 std::cout<<"i-------" << receiver<<"received packet from"<<sender<<" and hop is"<<initpHeader.GetHopCount()<<"Dst is"<<dst<<std::endl;
 if (initpHeader.GetHopCount()==1){
 for (  uint32_t j = 1; j <= 3; j++)
 {
 }
 
 //uint16_t dd = 
 }
 else if(initpHeader.GetHopCount()==2){}
 else if(initpHeader.GetHopCount()==3){}
 else{}
    uint8_t hop = initpHeader.GetHopCount () + 1;
  initpHeader.SetHopCount (hop);
 SendReply(socket, sender, receiver, leader, port);
 ForwardPacket(socket, sender, receiver, dst, leader, port);
}

  static void GenerateTraffic (Ptr<Socket> socket, uint32_t pktSize,
                             uint32_t pktCount, Time pktInterval, uint16_t eh_port)
{
  if (pktCount > 0)
    {
       Ptr<Packet> packet = Create<Packet> ();
    Ipv4Address dst = "10.1.1.12";
    Ptr<Node> n1 =socket->GetNode();
 Ptr<Ipv4> ipv4 = n1->GetObject<Ipv4> ();
         Ipv4InterfaceAddress iaddr = ipv4->GetAddress (1,0); 
         Ipv4Address source = iaddr.GetLocal (); 
     InitpHeader initpHeader; 
    initpHeader.SetSource (source);
    initpHeader.SetPrnt (source);
     initpHeader.SetLeader (source); 
     initpHeader.SetDst (dst);
          initpHeader.SetHopCount (1);
       initpHeader.SetRemEng(1);
          initpHeader.SetRemEng1(1);  
           initpHeader.SetRemEng2(0);  
        initpHeader.Sethp(1); 
        initpHeader.Sethp1(1); 
        initpHeader.Sethp2(1); 
        initpHeader.Seteh(2);
        initpHeader.Seteh1(2);  
          initpHeader.Seteh2(0);    
   
         
     packet->AddHeader (initpHeader);
      TypeHeader tHeader (EHARATYPE_INITP);
      packet->AddHeader (tHeader); 
 
   
      socket->Send (packet);
      Simulator::Schedule (pktInterval, &GenerateTraffic,
                           socket, pktSize,pktCount - 1, pktInterval, eh_port);
    }
  else
    {
      socket->Close ();
    }
}


int main (int argc, char *argv[])
{
  std::string phyMode ("DsssRate1Mbps");
  uint16_t eh_port=30;
  double distance = 50;  // m
  uint32_t packetSize = 10; // bytes
  uint32_t numPackets = 1;
  uint32_t numNodes = 12;  // by default, 5x5
  uint32_t sinkNode = 11;
  uint32_t sourceNode = 0;
  double interval = 1.0; // seconds
  bool verbose = false;
  bool tracing = true;
   double startTime = 0.0; 
  CommandLine cmd (__FILE__);
  cmd.AddValue ("phyMode", "Wifi Phy mode", phyMode);
  cmd.AddValue ("distance", "distance (m)", distance);
  cmd.AddValue ("packetSize", "size of application packet sent", packetSize);
  cmd.AddValue ("numPackets", "number of packets generated", numPackets);
  cmd.AddValue ("interval", "interval (seconds) between packets", interval);
  cmd.AddValue ("verbose", "turn on all WifiNetDevice log components", verbose);
  cmd.AddValue ("tracing", "turn on ascii and pcap tracing", tracing);
  cmd.AddValue ("numNodes", "number of nodes", numNodes);
    cmd.AddValue ("startTime", "Simulation start time", startTime);
  cmd.AddValue ("sinkNode", "Receiver node number", sinkNode);
  cmd.AddValue ("sourceNode", "Sender node number", sourceNode);
  cmd.Parse (argc, argv);
  // Convert to time object
  Time interPacketInterval = Seconds (interval);

  // Fix non-unicast data rate to be the same as that of unicast
  Config::SetDefault ("ns3::WifiRemoteStationManager::NonUnicastMode",
                      StringValue (phyMode));
  // disable fragmentation for frames below 2200 bytes
  Config::SetDefault ("ns3::WifiRemoteStationManager::FragmentationThreshold",
                      StringValue ("2200"));
  // turn off RTS/CTS for frames below 2200 bytes
  Config::SetDefault ("ns3::WifiRemoteStationManager::RtsCtsThreshold",
                      StringValue ("2200"));
  NodeContainer c;
  c.Create (numNodes);

  // The below set of helpers will help us to put together the wifi NICs we want
  WifiHelper wifi;
  if (verbose)
    {
      wifi.EnableLogComponents ();  // Turn on all Wifi logging
    }

  YansWifiPhyHelper wifiPhy;
  // set it to zero; otherwise, gain will be added
  wifiPhy.Set ("RxGain", DoubleValue (-10) );
  // ns-3 supports RadioTap and Prism tracing extensions for 802.11b
  wifiPhy.SetPcapDataLinkType (WifiPhyHelper::DLT_IEEE802_11_RADIO);

  YansWifiChannelHelper wifiChannel;
  wifiChannel.SetPropagationDelay ("ns3::ConstantSpeedPropagationDelayModel");
  wifiChannel.AddPropagationLoss ("ns3::FriisPropagationLossModel");
  wifiPhy.SetChannel (wifiChannel.Create ());

  // Add an upper mac and disable rate control
  WifiMacHelper wifiMac;
  wifi.SetStandard (WIFI_STANDARD_80211b);
  wifi.SetRemoteStationManager ("ns3::ConstantRateWifiManager",
                                "DataMode",StringValue (phyMode),
                                "ControlMode",StringValue (phyMode));
  // Set it to adhoc mode
  wifiMac.SetType ("ns3::AdhocWifiMac");
  NetDeviceContainer devices = wifi.Install (wifiPhy, wifiMac, c);

  MobilityHelper mobility;
  Ptr<ListPositionAllocator> positionAlloc = CreateObject<ListPositionAllocator> ();
  positionAlloc->Add (Vector (0.0, 0.0, 0.0));
  positionAlloc->Add (Vector (2 * distance, 0.0, 0.0));
  mobility.SetPositionAllocator (positionAlloc);
  mobility.SetMobilityModel ("ns3::ConstantPositionMobilityModel");
  mobility.Install (c);

  // Enable OLSR
    InternetStackHelper internet;
  internet.Install (c);
  
  Ipv4AddressHelper ipv4;
  NS_LOG_INFO ("Assign IP Addresses.");
  ipv4.SetBase ("10.1.1.0", "255.255.255.0");
  Ipv4InterfaceContainer i = ipv4.Assign (devices);
   
OnOffHelper onoff1 ("ns3::UdpSocketFactory",Address ());
   onoff1.SetAttribute ("OnTime", StringValue ("ns3::ConstantRandomVariable[Constant=1.0]"));
  onoff1.SetAttribute ("OffTime", StringValue ("ns3::ConstantRandomVariable[Constant=0.0]"));
 
  for (  uint32_t k = 1; k <= numNodes - 1; k++)
   {
    Ptr<Socket> sink = SetupPacketReceive (i.GetAddress (k), c.Get (k), eh_port);
  
        AddressValue remoteAddress (InetSocketAddress (i.GetAddress (k), eh_port));
       onoff1.SetAttribute ("Remote", remoteAddress);
  
        Ptr<UniformRandomVariable> var = CreateObject<UniformRandomVariable> ();
       ApplicationContainer temp = onoff1.Install (c.Get (k));
       temp.Start (Seconds (var->GetValue (100.0,101.0)));
       temp.Stop (Seconds (startTime));///
    }

for (  uint32_t k = 0; k <= numNodes - 1; k++)
   {
   TypeId tid = TypeId::LookupByName ("ns3::UdpSocketFactory");
  Ptr<Socket> source = Socket::CreateSocket (c.Get (sourceNode), tid);
 
  InetSocketAddress remote = InetSocketAddress (i.GetAddress (k, 0), eh_port);
  
  source->Connect (remote); 
Simulator::Schedule (Seconds (30.0), &GenerateTraffic,
                       source, packetSize, numPackets, interPacketInterval, eh_port); 
  }
  if (tracing == true)
    {
      AsciiTraceHelper ascii;
      wifiPhy.EnableAsciiAll (ascii.CreateFileStream ("wifitr.tr"));
      wifiPhy.EnablePcap ("wifipcap", devices);
      // Trace routing tables
    }


AnimationInterface anim("wifixml.xml");
anim.SetConstantPosition(c.Get(11),97.0,45.0);
anim.SetConstantPosition(c.Get(10),91.0,70.0);
anim.SetConstantPosition(c.Get(9),70.0,77.0);
anim.SetConstantPosition(c.Get(8),77.0,30.0);
anim.SetConstantPosition(c.Get(7),76.0,56.0);
anim.SetConstantPosition(c.Get(6),47.0,77.0);
anim.SetConstantPosition(c.Get(5),56.0,55.0);
anim.SetConstantPosition(c.Get(4),49.0,24.0);
anim.SetConstantPosition(c.Get(3),26.0,73.0);
anim.SetConstantPosition(c.Get(2),31.0,50.0);
anim.SetConstantPosition(c.Get(1),24.0,24.0);
anim.SetConstantPosition(c.Get(0),2.0,50.0);
  Simulator::Stop (Seconds (50.0));
  Simulator::Run ();
  Simulator::Destroy ();

  return 0;
}

