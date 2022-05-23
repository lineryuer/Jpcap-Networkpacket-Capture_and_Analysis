package Jpcap_Test;

import jpcap.packet.*;

// 分析数据包类,分析并统计抓包个数;
class AnalyzePacket {
    private static Packet packet;

    AnalyzePacket(Packet packet) {
        AnalyzePacket.packet = packet;
    }

    private static int packetCount = 0;
    private static int packetPacketCount = 0;
    private static int ipPacketCount = 0;
    private static int tcpPacketCount = 0;
    private static int udpPacketCount = 0;
    private static int icmpPacketCount = 0;
    private static int arpPacketCount = 0;
    private static int elsePacketCount = 0;
    private static int tcpPacketLength = 0;
    private static int udpPacketLength = 0;

    public void analyzePacket() {
        packetCount++;

        /* 数链层,显示数据包的帧头部,每一个数据包都有,都要解析 */
        // EthernetPacket类继承 DataPacket类;
        EthernetPacket dataLink = (EthernetPacket) packet.datalink;// DatalinkPacket datalink: 数据链路层报头/以太帧报头;
        System.out.println("以太帧首部 : " + dataLink.toString());// 描述以太帧的字符串
        System.out.println("源mac地址 : " + dataLink.getSourceAddress());// 源mac地址
        System.out.println("目的mac地址 : " + dataLink.getDestinationAddress());// 目的mac地址
        System.out.println("帧类型 : " + dataLink.frametype);// 帧类型

        /* 网络层,显示数据包的IP首部 */
        /* instanceof 关键字,左边是对象，右边是类，返回类型是Boolean类型。
           它的具体作用是测试左边的对象是否是右边类或者该类的子类创建的实例对象，是，则返回true，否则返回false。*/
        /* getClass(): 返回此 Object 的运行时类。*/
        if (packet instanceof jpcap.packet.Packet) {

            if (packet.getClass().equals(Packet.class)) {
                // 抓取到packet数据包,协议字段为-30516,-30440,105...等,尚不清楚这些是什么数据包;
                packetPacketCount++;

            } else if (packet.getClass().equals(IPPacket.class)) {
                ipPacketCount++;
                // IP数据包, IPPacket类继承 Packet类,包括 IPV4和 IPV6;
                IPPacket ipPacket = (IPPacket) packet;// 将 packet类转成 IPPacket类;
                System.out.println("IP报文首部 : " + ipPacket.toString());
                System.out.println("版本version ：" + ipPacket.version);
                System.out.println("时间戳sec(秒) : " + ipPacket.sec);
                System.out.println("时间戳usec(毫秒) : " + ipPacket.usec);
                System.out.println("源IP : " + ipPacket.src_ip.getHostAddress());
                System.out.println("目的IP : " + ipPacket.dst_ip.getHostAddress());
                System.out.println("协议protocol : " + ipPacket.protocol);
                System.out.println("优先权priority：" + ipPacket.priority);
                System.out.println("生存时间hop：" + ipPacket.hop_limit);
                System.out.println("标志位RF:保留位必须为false: " + ipPacket.rsv_frag);
                System.out.println("标志位DF:是否允许分片: " + ipPacket.dont_frag);
                System.out.println("标志位MF:后面是否还有分片: " + ipPacket.more_frag);
                System.out.println("片偏移offset：" + ipPacket.offset);
                // 抓到的flowable 流标签的包,是ipv6数据包;
                System.out.println("标识ident：" + ipPacket.ident);

        /* 传输层,显示数据包的 ICMP/ TCP/ UDP 首部 */
            } else if (packet.getClass().equals(TCPPacket.class)) {
                tcpPacketCount++;
                // TCP数据报,TCPPacket类继承 IPPacket类;
                TCPPacket tcpPacket = (TCPPacket) packet;// 将 TCPPacket类转成 IPPacket类;
                tcpPacketLength += tcpPacket.len;// 计算TCP报文的总长度

                System.out.println("TCP报文首部：" + tcpPacket.toString());
                System.out.println("标志位DF:是否允许分片: " + tcpPacket.dont_frag);
                System.out.println("标志位MF:后面是否还有分片: " + tcpPacket.more_frag);
                System.out.println("片偏移offset：" + tcpPacket.offset);
                System.out.println("标识ident：" + tcpPacket.ident);
                System.out.println("TCP报文");
                System.out.println("源端口src_port：" + tcpPacket.src_port);
                System.out.println("目的端口dst_port：" + tcpPacket.dst_port);
                System.out.println("seq序号：" + tcpPacket.sequence);
                System.out.println("窗口大小window：" + tcpPacket.window);
                System.out.println("ACK标志：" + tcpPacket.ack);// boolean ack :ACK标志
                System.out.println("ack：" + tcpPacket.ack_num);// long ack_num :确认号
                System.out.println("TCP报文长度length：" + tcpPacket.length);

            } else if (packet.getClass().equals(UDPPacket.class)) {
                udpPacketCount++;
                // UDP数据报,UDPPacket类继承 IPPacket类;
                UDPPacket udpPacket = (UDPPacket) packet;
                udpPacketLength += udpPacket.len;// 计算UDP报文的总长度

                System.out.println("UDP报文首部：" + udpPacket.toString());
                System.out.println("标志位DF:是否允许分片: " + udpPacket.dont_frag);
                System.out.println("标志位MF:后面是否还有分片: " + udpPacket.more_frag);
                System.out.println("片偏移offset：" + udpPacket.offset);
                System.out.println("标识ident：" + udpPacket.ident);
                System.out.println("UDP报文");
                System.out.println("源端口src_port：" + udpPacket.src_port);
                System.out.println("目的端口dst_port：" + udpPacket.dst_port);
                System.out.println("UDP报文长度length：" + udpPacket.length);

            } else if (packet.getClass().equals(ICMPPacket.class)) {
                icmpPacketCount++;
                // ICMP数据报,ICMPPacket类继承 IPPacket类;
                ICMPPacket icmpPacket = (ICMPPacket) packet;
                System.out.println("ICMP报文首部：" + icmpPacket.toString());// 只包含报文类型和代码;
                System.out.println("标志位DF:是否允许分片: " + icmpPacket.dont_frag);
                System.out.println("标志位MF:后面是否还有分片: " + icmpPacket.more_frag);
                System.out.println("片偏移offset：" + icmpPacket.offset);
                System.out.println("标识ident：" + icmpPacket.ident);
                System.out.println("ICMP报文类型type：" + icmpPacket.type);
                System.out.println("ICMP报文代码code：" + icmpPacket.code);

        /* 网络层,显示ARP数据包的首部 */
            } else if (packet.getClass().equals(ARPPacket.class)) {
                arpPacketCount++;
                // ARP数据包,ARPPacket类继承 Packet类;
                ARPPacket arpPacket = (ARPPacket) packet;// 将 packet类转成 ARPPacket类;
                System.out.println("硬件类型hardtop : " + arpPacket.hardtype);
                System.out.println("协议类型prototype : " + arpPacket.prototype);
                System.out.println("操作字段operation : " + arpPacket.operation);
                System.out.println("IP首部 : " + arpPacket.toString());// String toString: 返回描述此数据包的字符串;
                System.out.println("发送方硬件地址 : " + arpPacket.getSenderHardwareAddress());
                System.out.println("接收方硬件地址 : " + arpPacket.getTargetHardwareAddress());
                System.out.println("发送方IP地址 : " + arpPacket.getSenderProtocolAddress());
                System.out.println("接收方IP地址 : " + arpPacket.getTargetProtocolAddress());

            } else {
                elsePacketCount++;
                System.out.println("协议类型 ：GGP、EGP、JGP协议或OSPF协议或ISO的第4类运输协议TP4");
            }

        } else {
            System.out.println("未抓取到数据包!!");
        }

        // 抓包统计结果
        System.out.println("数据报类型 : " + packet.getClass());
        System.out.println("截止到目前：");
        System.out.println("|——*捕获到的数据包的总数为：" + packetCount);
        System.out.println("|——*捕获到的packet数据包的总数为：" + packetPacketCount);
        System.out.println("|——*捕获到ip数据包的总数为：" + ipPacketCount);
        System.out.println("|——*捕获到tcp数据包的总数为：" + tcpPacketCount + ",数据包总长度为" + tcpPacketLength);
        System.out.println("|——*捕获到udp数据包的总数为：" + udpPacketCount + ",数据包总长度为" + udpPacketLength);
        System.out.println("|——*捕获到icmp数据包的总数为：" + icmpPacketCount);
        System.out.println("|——*捕获到arp数据包的总数为：" + arpPacketCount);
        System.out.println("|——*捕获到其他数据包的总数为：" + elsePacketCount);
        System.out.println("----------------------------------------------------------------------");
    }
}
