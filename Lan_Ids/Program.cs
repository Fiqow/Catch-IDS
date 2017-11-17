using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using SharpPcap.WinPcap;
using SharpPcap;
using System.Data;
using PacketDotNet;
using System.Net.NetworkInformation;
using System.Net;
using Ng_IDS.Model;
using System.Threading;
using System.Runtime.InteropServices;
using System.Net.Sockets;
using System.IO;
using System.Collections;

namespace Open_HIDS
{
    class Program
    {

        static int devIndex;
        static public string gat { get; set; }
        static public string Hip { get; set; }
        static public string Hmac { get; set; }                                          
        static public string Hinter { get; set; }
        static public string Hdefullt { get; set; }
        static public string Rip { get; set; }
        static public string Rmac { get; set; }
        static public bool RunArp { get; set; }
        static public bool RunDhcp { get; set; }
        static public bool RunAll { get; set; }
        static public bool scan { get; set; }
        //Real-time Analysis
        static string commend;
        public static int num { get; set; }
        static void Main(string[] args)
        {
            //  Console.BackgroundColor = ConsoleColor.Red;

            //   Console.ForegroundColor = ConsoleColor.Yellow;
            


            Console.Title = "Catch";
                                 Console.WriteLine(@" 
                      /$$$$$$              /$$               /$$      
                     /$$__  $$            | $$              | $$      
                    | $$  \__/  /$$$$$$  /$$$$$$    /$$$$$$$| $$$$$$$ 
                    | $$       |____  $$|_  $$_/   /$$_____/| $$__  $$
                    | $$        /$$$$$$$  | $$    | $$      | $$  \ $$
                    | $$    $$ /$$__  $$  | $$ /$$| $$      | $$  | $$
                    |  $$$$$$/|  $$$$$$$  |  $$$$/|  $$$$$$$| $$  | $$
                     \______/  \_______/   \___/   \_______/|__/  |__/

                                                ");
    Console.WriteLine("                     Welcome To catch is Host Based Intrusion Detection Systems");
    Console.WriteLine("                     Catch Mitm Attack and Clear Text Protocols");
    Console.WriteLine("                     Forged  by @mr_128bit using SharpPcap and PacketDotNet");
    Console.WriteLine("                     Copyright 2017  abdurhman Ibrahim (a.dhom@yahoo.com)");
    Console.WriteLine("                     VERSION:1.0");
            Console.WriteLine(Environment.NewLine);
            // chick if data Excet
            if (!File.Exists("data.sqlite"))
            {
                ado o = new ado();
                o.creatDB();
                
            }
            if (!File.Exists("ports.port"))
            {
                create_file();
            }
            //========================================
            // Print SharpPcap version
            // string ver = SharpPcap.Version.VersionString;
            //   Console.WriteLine("SharpPcap {0}\n", ver);

            // Retrieve the device list
            try
            {
               var devic = WinPcapDeviceList.Instance;
            }
            catch (Exception)
            {

                 Console.WriteLine("No interfaces found! Make sure libpcap/WinPcap is properly installed on the local machine.");
               Thread.Sleep(5000);
                 return;
            }
            var devices = WinPcapDeviceList.Instance;


            // If no devices were found print an error
            if (devices.Count < 1)
            {
                Console.WriteLine("No devices were found on this machine please make sure you have installed a winpcap");
                return;
            }

            Console.WriteLine("The following devices are available on this machine Please choose one:");
            Console.WriteLine("----------------------------------------------------------------------");
            Console.WriteLine();

            int i = 0;

            // Print out the available devices
            //if (true)
          //  {
           //     Console.WriteLine("No interfaces found! Make sure libpcap/WinPcap is properly installed on the local machine.");
         // /
          //  }
            foreach (var dev in devices)
            {
                Console.WriteLine("{0}) {1}", i, dev.Description);
                Console.WriteLine(Environment.NewLine);
                i++;
            }

            Console.WriteLine();
            Console.Write("------ Please choose a device : ");

            i = int.Parse(Console.ReadLine());
            



            devIndex = i;
            if (devices.Count < i)
            {
                Console.WriteLine("------{0} is incorrect : ", i.ToString());
                Console.WriteLine("------ Please choose a device : ");
                i = int.Parse(Console.ReadLine());
                if (devices.Count < i)
                {
                    return;
                }
                // ;
            }

            
            var device = devices[i];
            // Console.Write("-- Please Enter IP ADDRESS: ");
            //  string MYIP = Console.ReadLine();
            //  IPAAA = MYIP.ToString();
            device.Open(DeviceMode.Promiscuous, 1000);
            // pc Data 
            num = 0;
            foreach (var item in device.Addresses)
            {
                if (item.Addr.ipAddress != null)
                {
                    // get ip v4 from list 
                    if (item.Addr.ipAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                    {
                        int inf = Array.IndexOf(device.Addresses.ToArray(), item);
                        num = inf;
                    }
                }

            }
            Console.WriteLine(Environment.NewLine);
            Console.WriteLine("Interface : {0}",device.Description);
          //  var devg = CaptureDeviceList.Instance[devIndex];
            //devg.Open(DeviceMode.Promiscuous, 1000);

            Hip = device.Addresses[num].Addr.ToString();
            Hmac = device.MacAddress.ToString();
           
            if (device.Interface.GatewayAddress == null)
            {
               
                Console.WriteLine("You don't have GatewayAddress");
                Console.ReadKey();
                return;
            }
            gat = device.Interface.GatewayAddress.ToString();
            Hdefullt = device.Interface.GatewayAddress.ToString();
            Hinter = device.Description.Replace("'", "");
            Console.WriteLine(Environment.NewLine); 
            Console.WriteLine("IP Address : {0}",device.Addresses[num].Addr);
            Console.WriteLine(Environment.NewLine);
            Console.WriteLine("MAC Address : {0}",device.MacAddress.ToString());
            if (IPAddress.Parse(gat).AddressFamily == AddressFamily.InterNetworkV6)
            {
                Console.WriteLine("Catch can't find Your GatewayAddress Please Enter Your GatewayAddress : ");
                var g = Console.ReadLine();
       //         if (string.IsNullOrWhiteSpace(g))
         //       {
        //            Console.WriteLine("Please Enter without no Space");
        //            g = Console.ReadLine();
          //          gat = g;
          //      }
                gat = g; 
            }
            

            Console.WriteLine(Environment.NewLine);
            Console.WriteLine("Defult Gatway : {0}",gat);
            Console.WriteLine(Environment.NewLine);
            Console.WriteLine("__________________________Router_______________________________");
            Console.WriteLine("Router IP Address : {0}", gat);
            
            // IF IPV6 PLEAS ENTAR THE DEFULT 

            string myip = device.Addresses[num].Addr.ToString();

            try
            {
                IPAddress address = IPAddress.Parse(gat);
            }
            catch (Exception ex)
            {

                Console.WriteLine(ex.Message + " " + gat);
                Thread.Sleep(3000);
                return;
                
            }
            if (string.IsNullOrEmpty(gat)!= null)
            {
                    EthernetPacket eth = Protect_Arp(device.MacAddress.ToString(), "FFFFFFFFFFFF", myip, gat);
                    device.SendPacket(eth);
            }

            Thread th = new Thread(() => {
            device.OnPacketArrival += new PacketArrivalEventHandler(device_OnPacketArrival);
            });
            th.Start();
            Rmac = getGAtWatWayMac(device,gat);
            if (Rmac == "")
            {
                Console.WriteLine("You are Not connected to Router Try Agin");
                
                Console.ReadKey();
                return;
                
            }
           
            Console.WriteLine("Router MAC Address : {0}", Rmac);

            Rip = gat;

            device.StartCapture();
            //------------------------Softwer Stard-----------------------------
            //====Start IPS -help You See All commend 
            Console.WriteLine(Environment.NewLine);



            // Inserting data First Check if Excit 
            // add pc
            ado a = new ado();
            if (a.checkpc(Hip,Hmac,Hinter).Rows.Count > 0)
            {
                
            }
            else
            {
                Data d = new Data() { date = DateTime.Now.ToString(), inter = Hinter, name="Pc", ip= Hip, mac=Hmac };
                a.insert(d);
            }

            if (a.selectname("Router", Hinter).Rows.Count > 0)
            {
                int id = 0;                
                DataTable dt = a.selectname("Router", Hinter);
                
                foreach (DataRow  item in dt.Rows)
                {
                    string ip = item[4].ToString();
                    string mac = item[3].ToString();
                    string Time = item[5].ToString();
                    id = Convert.ToInt32(item[0]);
                    if (mac == Rmac)
                    {
                        
                        //Console.WriteLine("Mac {0}", mac);
                       // Console.WriteLine("Rmac {0}", Rmac);
                    }
                    else
                    {
                        
                        cheeck(new ado(),ip, mac, Time, id);
                    }

                    
                }


               
                

            }
            else 
            {
                Data d = new Data() { inter = Hinter, date= DateTime.Now.ToString(), ip = Rip, mac = Rmac, name = "Router"};
                a.insert(d);
            }

            Runcmd();


            // Console.ReadKey();
        }

        static void device_OnPacketArrival(object sender, CaptureEventArgs e)
        {
            // check router 
           // ado a = new ado();
           // DataTable dt = a.selectname("Router", Hinter.Replace("'", ""));
                scan s = new scan();
                if (RunArp == true)
                {
                    s.ScanAttack(e, Hinter,Rip);
                }
                if (RunDhcp == true)
                {
                    s.ScanDhcp(e, Hinter);
                }
                if (s.Attack == true)
                {
                    for (int i = 0; i < 3; i++)
                    {
                        System.Media.SystemSounds.Hand.Play();
                        Console.WriteLine("********************* You Have Been Attacked **************************");
                        Console.WriteLine(Environment.NewLine);
                        Console.WriteLine("Attack Name : {0} , Time : {1} , Attacker HardwareAddress : {2} , Attacker ip address : {3} ", s.Attack_data[0], s.Attack_data[3], s.Attack_data[2], s.Attack_data[1]);
                        Console.WriteLine(Environment.NewLine);
                        Console.WriteLine("Old data  {0} {1} {2} {3}  ", s.Attack_data[4], s.Attack_data[5], s.Attack_data[6], s.Attack_data[7]);
                        System.Media.SystemSounds.Hand.Play();
                    }
                    // Save to DB
                    log.attackLog(s);
                }

                //throw new NotImplementedException();
                var txt = File.ReadAllLines("ports.port");
                var tcp = (from t in txt where t.Contains("tcp") select t).ToArray();
                //var comments = (from t in txt where t.StartsWith("#") select t).ToArray();
             /*   foreach (var item in tcp)
                {
                    int  inte = Array.IndexOf(tcp,item);
                    string cm = txt[inte+1];

                    string r = item.Replace("tcp", "");
                    int p = Convert.ToInt16(r);

                    if (cm.StartsWith("#"))
                    {

                        scanTCP(e, p, cm);
                    }
                    else
                    {
                        string commend = "You Are Using insecur Protocol";
                        scanTCP(e, p, commend);
                    }
                   

                   

                }*/
             /*   var udp = (from t in txt where t.Contains("udp") select t).ToArray();
                foreach (var item in udp)
                {
                    // comment
                    int inte = Array.IndexOf(udp, item);

                    string cm = txt[inte + 1];

                    string r = item.Replace("udp", "");
                    int p = Convert.ToInt16(r);
                    //scanUDP(e, p);
                    if (cm.StartsWith("#"))
                    {

                        scanUDP(e, p, cm);
                        throw new Exception("");
                    }
                    else
                    {
                        string commend = "You Are Using insecur Protocol";
                        scanUDP(e, p, commend);
                    }
                }*/
                if (scan == true)
                {
                    foreach (var item in txt)
                    {
                        //tcp
                        if (item.Contains("tcp"))
                        {
                            int inte = Array.IndexOf(txt, item);
                            string cm = txt[inte + 1];

                            string r = item.Replace("tcp", "");
                            int p = Convert.ToInt16(r);

                            if (cm.StartsWith("#"))
                            {

                                scanTCP(e, p, cm);
                                // throw new Exception("");
                               
                            }
                            else
                            {
                                string commend = "You Are using non - encrypted Clear Text Protocol Pleas Use secure Protocol";
                                scanTCP(e, p, commend);
                                
                            }
                        }
                        // udp
                        if (item.Contains("udp"))
                        {
                            // comment
                            int inte = Array.IndexOf(txt, item);
                            string cm = txt[inte + 1];

                            string r = item.Replace("udp", "");
                            int p = Convert.ToInt16(r);
                            if (cm.StartsWith("#"))
                            {

                                scanUDP(e, p, cm);
                                // if you need error use this commend
                                // throw new Exception("");
                            }
                            else
                            {
                                string commend = "You Are using non-encrypted Clear Text Protocol  Pleas Use secure Protocol";
                                scanUDP(e, p, commend);
                            }

                        }
                    }
                }
               
            

        }

        public static void Runcmd()
        {
            Cmd();
            Console.WriteLine("For More Informaton On A Specific Command , Type -help command-name");
            commend = Console.ReadLine();
            if (commend.Equals("--start arp"))
            {
                Console.WriteLine(" Success start Arp spoofing Detection Tool ");
                RunArp = true;
            }
            else if (commend == "--start dhcp")
            {
                Console.WriteLine(" Success start Dhcp spoofing Detection Tool");
                RunDhcp = true;
            }
            else if (commend == "--start all")
            {
                Console.WriteLine(" Success Start All Tools");
                RunArp = true;
                RunDhcp = true;
                scan = true;
            }
            else if (commend == "--attacks")
            {
                if (!File.Exists("AttacksDB.txt"))
                {
                    Console.WriteLine("There IS no Attack in Databese");
                    //var txt = File.ReadAllLines("AttacksDB.txt");
                    Thread.Sleep(1000);
                    Runcmd();
                }
          
                else
                {
                    var txt = File.ReadAllLines("AttacksDB.txt");
                    foreach (var item in txt)
                    {
                        Console.WriteLine(item);
                    }
                    Console.WriteLine("Hit Enter To Return ");
                   
                    if (Console.ReadKey().Key == ConsoleKey.Enter)
                    {
                        Thread.Sleep(500);
                        Runcmd();
                    }
                    //Thread.Sleep(10000);
                    //Runcmd();
                }
            }
            else if (commend == "--start scan")
            {
                scan = true;
                Console.WriteLine("Start Scan");
            }
            else if (commend == "-help")
            {
                Runcmd();
            }
            else
            {
                Console.WriteLine(commend + " is not Recognize as Command,");
                Thread.Sleep(1000);
                Runcmd();
            }
        }
        public static string getGAtWatWayMac(WinPcapDevice dev,string GatewayAddress) 
        {
            RawCapture packet;

            // Capture packets using GetNextPacket()

            while ((packet = dev.GetNextPacket()) != null)
            {

                var mypacket = Packet.ParsePacket(packet.LinkLayerType, packet.Data);
                var arp = (ARPPacket)mypacket.Extract(typeof(ARPPacket));


                if (arp != null)
                {
                    // get arp rep
                    if (arp.Operation == ARPOperation.Response)
                    {
                        if (arp.SenderProtocolAddress.Address == IPAddress.Parse(GatewayAddress).Address)
                        {
                            return arp.SenderHardwareAddress.ToString();
                        }
                    }
                }


            }
            return ""; 

        }
        public static EthernetPacket Protect_Arp(string Router_mac, string My_pc_mac, string Router_ip, string My_pc_ip)
        {
                var eth = new EthernetPacket(PhysicalAddress.Parse(Router_mac), PhysicalAddress.Parse(My_pc_mac), EthernetPacketType.Arp);
                var arp = new ARPPacket(ARPOperation.Request, PhysicalAddress.Parse(My_pc_mac), IPAddress.Parse(My_pc_ip), PhysicalAddress.Parse(Router_mac), IPAddress.Parse(Router_ip));
                eth.PayloadPacket = arp;
                return eth;

        }

        static void scanTCP(CaptureEventArgs e, int port, string cm)
        {
            var _packet = Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data);
            var tcp = (TcpPacket)_packet.Extract(typeof(TcpPacket));
            if (tcp != null)
            {
                if (tcp.DestinationPort == port)
                {
                    var dst_ip = IpPacket.GetEncapsulated(_packet).DestinationAddress.ToString();
                    var src_ip = IpPacket.GetEncapsulated(_packet).SourceAddress.ToString();
                    Console.WriteLine("******************************************************************************");
                    Console.WriteLine(cm+" {0}", port.ToString());
                    Console.WriteLine("Source: {0} " + "Destination: {1}",src_ip,dst_ip);
                   
                }

            }
        }

        static void scanUDP(CaptureEventArgs e, int port, string cm)
        {
            var _packet = Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data);
            var udp = (UdpPacket)_packet.Extract(typeof(UdpPacket));
            if (udp != null)
            {
                if (udp.DestinationPort == port)
                {
                    var dst_ip = IpPacket.GetEncapsulated(_packet).DestinationAddress.ToString();
                    var src_ip = IpPacket.GetEncapsulated(_packet).SourceAddress.ToString();
                    Console.WriteLine("********************************************************************");
                    Console.WriteLine(cm + " {0}", port.ToString());
                    Console.WriteLine("Source: {0} " + "Destination: {1}", src_ip, dst_ip);
                    
                }

            }
        }

        static void create_file() 
        {
            using (StreamWriter write = new StreamWriter("ports.port", true))
            {
               
write.WriteLine("80 tcp");
write.WriteLine("#You Are using Clear Text Protocol http Pleas Use secure Protocol Https");
write.WriteLine("21 tcp");
write.WriteLine("#You Are using Clear Text Protocol FTP Pleas Use secure Protocol like SFTP or FTPS");
write.WriteLine("143 tcp");
write.WriteLine("#You Are using Clear Text Protocol IMAP Pleas Use secure Protocol IMAP with ssl");
write.WriteLine("20 tcp");
write.WriteLine("#You Are using Clear Text Protocol FTP Pleas Use secure Protocol like SFTP or FTPS");
write.WriteLine("110 tcp");
write.WriteLine("#You Are using Clear Text Protocol POP3 Pleas Use secure Protocol POP3 with ssl");
write.WriteLine("23 tcp");
write.WriteLine("#You Are using Clear Text Protocol Telnet Pleas Use secure Protocol like SSH");
write.WriteLine("25 tcp");
write.WriteLine("#You Are using Clear Text Protocol SMTP Pleas Use secure Protocol SMTP with ssl");
            }
        }
        public static void Cmd() 
        {

            Console.WriteLine(@"
            Catch  Rules

            --start arp    For Staring Arp Attack detection (Arp spoofing MITM)
            --start dhcp  For Starting Dhcp Attack detection (Dhcp spoofing MITM )
            --start scan  this is notify you when you use Clear Text Protocol 
               Like (Http) or (Telent)  

            --Start All   this commend to start program with all future
            --attacks     To see all previous Attacks

            Next VERSION We will Add All These Futures  
            MAC address spoofing detection
            STP Attacks detection
            CDP Attacks detection
            DNS spoofing detection
            Port Stealing detection
            Vlan Attacks  detection
            all DOS ATTACks detection on lan 

            like SYN FLoods and Ping OF Death Attacks

            and We Will also add  Scan detection (Nmap) and More Futures 
             
            ");
            
        }

        public static void cheeck(ado a, string ip, string mac, string Time, int id) 
        {
            Console.WriteLine("Are You Ching The Router {0}", Environment.MachineName);
            Console.WriteLine("The old Data IP address: {0}, Mac address {1}, Time : {2} , And Interface : {3} , and ID = {4}", ip, mac, Time, Hinter,id);
            
            Console.Write(Environment.NewLine);
            Console.WriteLine("Yas   If You Chose Yas the Catch will consider this is You Router");
            Console.WriteLine("No    if You Chose No the Catch will consider this is Attack So please be careful what You chose ");
            string ch = Console.ReadLine();
            if (ch == "Yas")
            {
                //Delete old 
               // 
                a.Delete(id);
                Console.WriteLine("Delete Old Data {0}", id.ToString());
                
                Data d = new Data() { inter = Hinter, date = DateTime.Now.ToString(), ip = Rip, mac = Rmac, name = "Router" };
                a.insert(d);
            }
            if (ch == "no")
            {
                Console.WriteLine("********************* You Have Been Attacked **************************");
            }
        }


    }
}
