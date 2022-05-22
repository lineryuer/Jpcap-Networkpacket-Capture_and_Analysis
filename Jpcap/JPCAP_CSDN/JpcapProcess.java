package JPCAP_CSDN;

import jpcap.JpcapCaptor;
import jpcap.NetworkInterface;
import jpcap.PacketReceiver;
import jpcap.packet.Packet;
import java.io.IOException;
import java.util.Scanner;

// 类 Receiver实现了 PacketReceiver接口的 receivePacket()方法;
class Receiver implements PacketReceiver {
    @Override
    // 重写 PacketReceiver接口中的 receivePacket()方法;
    // 实现类中的处理接收到的 Packet 对象的方法,每个 Packet对象代表从指定网络接口上抓取到的数据包;
    // 抓到的包将调用这个 PacketReceiver对象中的 receivePacket(Packet packet)方法处理；
    public void receivePacket(Packet packet) {
        System.out.println(packet);// 直接将捕获的包输出,不做任何处
        System.out.println("---------------------------------------");
    }
}

public class JpcapProcess {
    public static void main(String[] args) {

        // 第一步,获得网卡设备列表;
        NetworkInterface[] devices = JpcapCaptor.getDeviceList();
        if (devices.length == 0) {
            System.out.println("无网卡信息！");
            return;
        }
        // 将本机上所有网卡名称及其网卡描述全部显示出来;
        // 这些信息可以在 wireshark中的网络接口处看到,是一一对应的,或者在cmd 用ipconfig /all 可以全部显示;
        int k = -1;// 网络设备序号
        for (NetworkInterface n : devices) {
            k++;
            // NetworkInterface 类中的 name和 description方法可以显示设备的名称和描述信息;
            System.out.println("序号" + k + "  " + n.name + "    |    " + n.description);
        }
        System.out.println("-------------------------------------------");

        Scanner sc = new Scanner(System.in);
        System.out.println("请选择您要监听的网卡序号：");
        int index = sc.nextInt();

        //第二步,监听选中的网卡;
        try {
            // 参数一:选择一个网卡，调用 JpcapCaptor.openDevice()连接，返回一个 JpcapCaptor类的对象 jpcap;
            // 参数二:限制每一次收到一个数据包，只提取该数据包中前1512个字节;
            // 参数三:设置为非混杂模式,才可以使用下面的捕获过滤器方法;
            // 参数四:指定超时的时间;

            JpcapCaptor jpcap = JpcapCaptor.openDevice(devices[index], 2000, false, 10000);

        //第三步,捕获数据包;
            // 调用 processPacket()方法, count = -1对该方法无影响,主要受 to_ms控制,改成其他数值则会控制每一次捕获包的数目;
            // 换而言之,影响 processPacket()方法的因素有且只有两个,分别是count 和 to_ms;
            // 抓到的包将调用这个 new Receiver()对象中的 receivePacket(Packet packet)方法处理；
            jpcap.setFilter("arp", true);
            jpcap.processPacket(4, new Receiver());

        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            System.out.println("抓取数据包时出现异常!!");
        }
    }
}
