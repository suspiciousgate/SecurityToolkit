from portscanner import PortScanner
from trafficanalyzer import TrafficAnalyzer
from penetrationtester import PenetrationTester
from systemprotector import SystemProtector
from webtrafficmonitor import WebTrafficMonitor
from reporter import Reporter
from database import Database

class SecurityToolkit:
    def __init__(self):
        self.port_scanner = PortScanner()
        self.traffic_analyzer = TrafficAnalyzer()
        self.penetration_tester = PenetrationTester()
        self.system_protector = SystemProtector()
        self.web_traffic_monitor = WebTrafficMonitor()
        self.reporter = Reporter()
        self.database = Database()

    def menu(self):
        while True:
            print("\n--- Security Toolkit ---")
            print("1. Scan ports")
            print("2. Analyze network traffic")
            print("3. Penetration Testing")
            print("4. Suspicious IP Blocking")
            print("5. Web traffic monitor")
            print("6. Security Reports")
            print("7. Exit")
            choice = input("Select an option")

            if choice == '1':
                target = input("Enter ip or hostname to scan")
                self.port_scanner.scan_ports(target)
            elif choice == '2':
                self.traffic_analyzer.analyze_traffic()
            elif choice == '3':
                url = input("Enter the URL to test")
                self.penetration_tester.test_website(url)
            elif choice == '4':
                ip = input("Enter the IP to block")
                self.system_protector.block_ip(ip)
            elif choice == '5':
                self.web_traffic_monitor.monitor_http_traffic()
            elif choice == '6':
                self.reporter.generate_report()
            elif choice == '7':
                break
            else:
                print("Invalid option")

if __name__ == "__main__":
    toolkit = SecurityToolkit()
    toolkit.menu()
