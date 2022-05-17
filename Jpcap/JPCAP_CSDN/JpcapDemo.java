package JPCAP_CSDN;

import jpcap.JpcapCaptor;
import jpcap.NetworkInterface;
import jpcap.packet.IPPacket;
import jpcap.packet.Packet;
import java.io.IOException;
import java.util.Scanner;

/**
 * @author Lineryue
 */
public class JpcapDemo {
    public static void main(String[] args) {
        /*--------第一步,显示网络设备列表--------- */
        // 返回你所有的网络设备数组,一般就是网卡;
        NetworkInterface[] devices = JpcapCaptor.getDeviceList();
        int k = -1;
        // 显示所有网络设备的名称和描述信息;
        // 要注意的是,显示出来的网络设备在不同网络环境下是不同的,可以在控制台使用 ipconfig /all命令查看;
        for (NetworkInterface n : devices) {
            k++;
            System.out.println("序号 " + k + "   " + n.name + "     |     " + n.description);
        }

        /*--------第二步,选择网卡并打开网卡连接--------*/
        // 选择网卡序号;
        // 注意!每台设备连接网络的网卡不同,选择正确的网卡才能捕获到数据包;
        System.out.println("请输入你想要监听的网卡序号: ");
        Scanner sc = new Scanner(System.in);
        int index = sc.nextInt();

        JpcapCaptor jpcap = null;

        // 打开网卡连接,此时还未开始捕获数据包;
        try {
            jpcap = JpcapCaptor.openDevice(devices[index], 1512, true,6000);
        } catch (IOException e) {
            e.printStackTrace();
            System.out.println("抓取数据包时出现异常!!");
        }

        /*--------第三步,捕获数据包--------*/
        // Packet getPacket() 捕捉并返回一个数据包。这是 JpcapCaptor实例中四种捕捉包的方法之一;
        // 受到 to_ms参数影响,但一次只抓一个包并返回;
        // 将抓到的包传给 Packet类的一个对象 packet;
        // 捕获四个数据包;
        int i = 0;
        while (i < 4) {
            Packet packet = jpcap.getPacket();
            System.out.println(packet);
            i++;// 捕获四个数据包
        }
    }
}
