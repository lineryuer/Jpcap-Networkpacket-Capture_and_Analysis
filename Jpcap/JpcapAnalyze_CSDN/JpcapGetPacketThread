package Jpcap_Test;

import jpcap.JpcapCaptor;
import jpcap.NetworkInterface;

import java.io.IOException;

// 测试类
public class JpcapGetPacketThread {
    public static void main(String[] args) {
        NetworkInterface[] devices = JpcapCaptor.getDeviceList();
        int k = -1;
        for (NetworkInterface n : devices) {
            k++;
            System.out.println("序号" + k + "  " + n.name + "    |    " + n.description);
        }
        System.out.println("--------------------------------------------------------");
        // 启动一个网卡;
        JpcapCaptor jpcap = null;
        try {
            // 注意! getPacket()方法不受to_ms 参数的影响;此处网卡的选择因不同电脑而异
            jpcap = JpcapCaptor.openDevice(devices[7], 4800, true, 200);
        } catch (IOException e) {
            e.printStackTrace();
            System.out.println("抓取数据包时出现异常!!");
        }
        // 创建抓包任务 c1;
        CaptureThread c1 = new CaptureThread(jpcap);
        // 创建抓抓包线程 t1;
        Thread t1 = new Thread(c1);
        // 启动 t1线程,开始抓包并分析;
        t1.start();
        // 主线程休眠5秒,此处控制抓包时间;
        try {
            Thread.sleep(5000);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        // 停止抓包,将控制抓包任务的变量设为false;
        c1.run = false;
    }
}
