try:

    import nmap  # import nmap.py module
    import xlwt
    import requests
    from getmac import get_mac_address
    import sqlite3
    import geocoder
    import datetime
    import time
    import datetime
    import pandas as pd
    print("All Modules loaded .. ")

except Exception as e:

    print("Some Modules are missing {}".format(e))


class Location(object):

    def __init__(self):
        pass

    def get_locations(self):

        """
        :return: Lat and Long
        """
        try:
            g = geocoder.ip('me')
            my_string=g.latlng
            longitude=my_string[0]
            latitude=my_string[1]

            return longitude,latitude
        except:
            print('Error make sure you have Geo-Coder Installed ')


class DateandTime(object):

    def __init__(self):
        pass

    @ staticmethod
    def get_time_date():
        try:
            """
            :return:  date and time
            """
            my = datetime.datetime.now()
            data_time = '{}:{}:{}'.format(my.hour,my.minute,my.second)
            data_date = '{}/{}/{}'.format(my.day,my.month,my.year)
            return data_date,data_time
        except:
            print('could now get date and time ')

    def convert_timestamp(self,timestamp):
        timestamp = 1554506464
        dt_object = datetime.fromtimestamp(timestamp)
        return dt_object


class Mac(object):

    def __init__(self):
        pass

    @staticmethod
    def get_Mac_Address(IP='192.168.1.1'):
        mac = get_mac_address(ip=IP)  # using 'get_mac_address' from 'getmac' import
        return mac

    @staticmethod
    def vendor(mac=''):

        if len(str(mac)) <= 2:
            return "Not Found"
        else:
            try:
                vendor_mac = mac.split(":")
                mac_vendor = ''.join(vendor_mac)[0:6]
                url = "https://macvendors.com/query/{}".format(mac_vendor)
                r = requests.get(url)
                vendor_mac_v = r.text
            except:
                return "Not Found"

            if len(vendor_mac_v) > 20:
                mac_vendor_name = "Not Found"
            else:
                mac_vendor_name = r.text
        return mac, mac_vendor_name


class Scanner(object):

    def __init__(self, network):
        self.network = network
        self.macobj  = Mac()
        self.geo = Location()
        self.dt = DateandTime()

    @property

    def scan(self):

        ipV  = []
        macV = []
        VendorV = []
        longitudeV = []
        latitudeV = []
        dtV =[]
        tmV =[]


        if len(self.network) == 0:
            self.network = '192.168.1.1/24'
        else:
            longitude,latitude = self.geo.get_locations()
            ddate, ttime = self.dt.get_time_date()
            network = self.network + '/24'

        print('Starting Scan ...... ')

        nm = nmap.PortScanner()
        nm.scan(hosts=network, arguments='-sn')  # define nmap arguments here
        hosts_list = [(x, nm[x]['status']['state']) for x in nm.all_hosts()]

        for host, status in hosts_list:
            mac = self.macobj.get_Mac_Address(IP=host)
            mac_vendor = self.macobj.vendor(mac=mac)[1]

            ipV.append(host)
            macV.append(mac)
            VendorV.append(mac_vendor)
            longitudeV.append(longitude)
            latitudeV.append(latitude)
            dtV.append(ddate)
            tmV.append(ttime)

        data = list(zip(ipV, macV, VendorV,longitudeV, latitudeV ,dtV ,tmV))
        df = pd.DataFrame(data=data, columns=["Ip", "Mac","Vendor", "Longitude", "Latitude", "Date", "Time"])
        print(df)



if __name__ == "__main__":
    network = '10.12.56.1'

    scan = Scanner(network=network)

    scan.scan