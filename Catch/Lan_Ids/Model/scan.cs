﻿using SharpPcap;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Data;
using PacketDotNet;

namespace Ng_IDS.Model
{
    class scan
    {
        public bool Attack { get; set; }
        public string Attacker_mac { get; set; }
        public string[] Attack_data = new string[10];
        public void ScanAttack(CaptureEventArgs e,string Interface,string ip)
        {
            var mypacket = Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data);
            var arp = (ARPPacket)mypacket.Extract(typeof(ARPPacket));
            if (arp !=null)
            {
                var Operation = arp.Operation.ToString();

                if (arp.SenderProtocolAddress.ToString() == ip) 
                {
                    if (arp.Operation == ARPOperation.Response)
                    {
                        var dec = arp.SenderHardwareAddress.ToString();
                        var decip = arp.SenderProtocolAddress.ToString();
                        ado a = new ado();
                        DataTable dt = a.selectname("Router", Interface);
                        if (dt.Rows.Count > 0)
                        {
                            // Attack = false;
                            foreach (DataRow item in dt.Rows)
                            {
                                string mac = item["mac_ad"].ToString();
                                if (dec == mac)
                                {
                                    Attack = false;
                                }
                                else
                                {
                                    Attack = true;
                                    Attack_data[0] = "arp spofing";
                                    Attack_data[1] = decip.ToString();
                                    Attack_data[2] = dec.ToString();
                                    Attack_data[3] = DateTime.Now.ToShortTimeString();
                                    Attacker_mac = dec;
                                    // true data
                                    Attack_data[4] = mac;
                                    Attack_data[5] = item["ip"].ToString();
                                    Attack_data[6] = item["date"].ToString();
                                    Attack_data[7] = item["name"].ToString();
                                }
                            }
                        }
                        else
                        {
                            //  Attack = false;
                        }
                        // Attack = true;

                    }
                }

            }
        }

        public void ScanDhcp(CaptureEventArgs e,string Interface)
        {
            var mypacket = Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data);
            var udp = (UdpPacket)mypacket.Extract(typeof(UdpPacket));
            if (udp != null)
            {
                if (udp.DestinationPort == 68)
                {
                    var DestinationHwAddress = EthernetPacket.GetEncapsulated(mypacket).DestinationHwAddress;
                    var SourceHwAddress = EthernetPacket.GetEncapsulated(mypacket).SourceHwAddress;
                    var DestinationipAddress = IpPacket.GetEncapsulated(mypacket).DestinationAddress;
                    var SourceipAddress = IpPacket.GetEncapsulated(mypacket).SourceAddress;
                    ado a = new ado();
                    DataTable dt = a.selectmac(SourceHwAddress.ToString(), Interface);
                    // if mac address of router excist that mean he is router 
                    if (dt.Rows.Count > 0)
                    {
                        Attack = false;
                    }
                    else
                    {
                        Attack = true;
                        Attack_data[0] = "DHCP spofing";
                        Attack_data[1] = SourceipAddress.ToString();
                        Attack_data[2] = SourceHwAddress.ToString();
                        Attack_data[3] = DateTime.Now.ToShortTimeString();
                    }
                }
            }
        }

        public void ScanDNS(CaptureEventArgs e)
        {
            var mypacket = Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data);
            var udp = (UdpPacket)mypacket.Extract(typeof(UdpPacket));
            if (udp !=null)
            {
                if (udp.DestinationPort == (ushort)53)
                {

                }
            }
        }

        public void ScanHTTP(CaptureEventArgs e)
        {
            var mypacket = Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data);
            var tcp = (TcpPacket)mypacket.Extract(typeof(TcpPacket));
            if (tcp != null)
            {
                if (tcp.DestinationPort == 80)
                {
                    
                }
            }
        }

        public void CreatesignatureTCP(CaptureEventArgs e, int port, string data) 
        {
            var mypacket = Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data);
            var tcp = (TcpPacket)mypacket.Extract(typeof(TcpPacket));
            if (tcp != null)
            {
                if (tcp.DestinationPort == port)
                {

                }
            }
        }

        /// <summary>
        /// A fraggle attack is a variation of a Smurf attack where an attacker sends a large amount of UDP traffic to ports         7 (echo) and 19 (chargen) to an IP Broadcast Address, with the intended victim's spoofed source IP address. It         works very similarly to the Smurf attack in that many computers on the network will respond to this traffic by sending         traffic back to the spoofed source IP of the victim, flooding it with traffic.[4]
        /// </summary>
        public void FraggleAttack() 
        { 

        }

        /// <summary>
        /// A SYN flood is a form of denial-of-service attack in which an attacker sends a succession of SYN requests to a             target's system in an attempt to consume enough server resources to make the system unresponsive to legitimate traffic
        /// </summary>
        public void SYN_flood_Attack() 
        { 

        }


    }
}
