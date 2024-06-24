import subprocess
import netaddr
import csv
from ipaddress import ip_network
from res import tools
import csv
import ipaddress
from tempfile import NamedTemporaryFile
import shutil

status = 'Unkown'

def main(p , s):
  
    if p >= 1 or p <= 0:
        print("p has to be within ]0, 1[")
        quit()


    sensor_list_cmd = "sbs db exec \"select serial_number, id from sensor;\""
    sensor_list_bytes = subprocess.check_output(sensor_list_cmd, shell=True)
    sensor_list = sensor_list_bytes.decode()

    # Subnet List for printing
    subnet_list = []

    idx=0
    for line in sensor_list.splitlines():
        idx = idx + 1
    #    print(idx, line.split("|")[0], ":")
        sensor_id = line.split("|")[1]

        ip_pairs_cmd = "sbs db exec \"select ca.ip as ip_a, cb.ip as ip_b from activity a left join activity_tag at on a.id = at.activity_id left join component ca on ca.id = a.cmp_a_component_id left join component cb on cb.id = a.cmp_b_component_id where a.sensor_id = '"+sensor_id+"' and at.tag_id ='ARP' and ca.ip is not NULL and ca.mac != 'ff:ff:ff:ff:ff:ff' and cb.ip is not NULL and cb.mac != 'ff:ff:ff:ff:ff:ff';\""
        
        ip_pairs_bytes = subprocess.check_output(ip_pairs_cmd, shell=True)
        ip_pairs = ip_pairs_bytes.decode()
        
        networkDict = {}
        networkList = []
        for line in ip_pairs.splitlines():
            ips = line.split("|")
            net = netaddr.spanning_cidr([netaddr.IPAddress(ips[0]), netaddr.IPAddress(ips[1])])
            if net in networkDict:
                networkDict[net]=networkDict[net]+1
            else:
                networkDict[net]=1
                networkList.append(net)
        
        def byMask(e):
            return e.prefixlen
        
        networkTotalDict = {}
        networkTrueTotalDict = {}
        networkList.sort(key=byMask)
        for n in networkList:
            for nn in networkList:
                if nn in n:
                    # compute distance between n and nn, and inflate the weight the further away it is
                    distance_grow_factor = 1 + nn.prefixlen - n.prefixlen
                    space_expand_factor = nn.prefixlen
                    if n in networkTotalDict:
                        networkTotalDict[n]=networkTotalDict[n]+(networkDict[nn]*distance_grow_factor*space_expand_factor)
                        networkTrueTotalDict[n]=networkTrueTotalDict[n]+networkDict[nn]
                    else:
                        networkTotalDict[n]=networkDict[nn]*distance_grow_factor*space_expand_factor
                        networkTrueTotalDict[n]=networkDict[nn]
        
        for n in networkList:
            subnet_list.append(n)
            weighted_total = networkTotalDict[n]
            true_total = networkTrueTotalDict[n]
            specific = networkDict[n]
            # this deserves a few lines of explanation
            # the basic idea is: check if there are more than x% of the ARP flows from this network that span
            # "over the full extent of that network" (cannot be reduced to a subnet), then that network is
            # considered valid. This is expressed by specific/true_total > args.p
            #
            # However, to make sure we do not merge "too large" networks in case of poorly configured machines,
            # each of the flows of the subnetworks are grown proportionally the smaller the subnetwork is.
            # This is expressed by specific/weighted_total > args.p
            #
            # Furthermore, to accomodate for small networks, which can occur on lighter sensors monitoring
            # tiny LANs, we introduce a linear "grow" component `s` which inflates the "large" network.
            #
            # Examples:
            # 1
            #  subnet A 192.168.0.0/26 has 3 ARP flows
            #  subnet B 192.168.0.64/26 has 4 ARP flows
            #  subnet C 192.168.0.0/25 has 1 ARP flow
            # with a p=0.1 && s=0, C isn't considered valid as 1/(1+3*2+4*2) < 0.1
            # with a p=0.1 && s=1, C is considered valid as (1+1)/(1+3*2+4*2+1) > 0.1
            # 2
            #  subnet A 192.168.0.0/26 has 34 ARP flows
            #  subnet B 192.168.0.64/26 has 42 ARP flows
            #  subnet C 192.168.0.0/25 has 1 ARP flow
            # with a p=0.1 && s=0, C isn't considered valid as 1/(1+34*2+42*2) < 0.1
            # with a p=0.1 && s=1, C isn't considered valid as (1+1)/(1+34*2+42*2+1) < 0.1
            if ((specific+s)*n.prefixlen)/(weighted_total+s) > p and not n.is_link_local() and not n.is_loopback():
    #            if args.v:
    #                print("   WELL-CONFIGURED NETWORK:", n)
    #                print("                           ", specific, "exactly in this net")
    #                print("                           ", true_total-specific, "inside a smaller subnet")
    #                print("                           ", true_total, "in total")
    #                print("                            --> Scores:", (specific+s)*n.prefixlen, "for the border and", weighted_total, "overall.")
    #            else:
    #                print("   WELL-CONFIGURED NETWORK:", n, "\t-->", specific, "activities exactly in this net,", true_total-specific, "inside a smaller subnet for a total of", true_total)
                for nn in networkList[:]:
                    if nn != n and nn in n:
                        networkList.remove(nn)
            else:
    #           if args.v:
    #                print(" /!\ MISCONFIGURED NETWORK:", n)
    #                print("                           ", specific, "exactly in this net")
    #                print("                           ", true_total-specific, "inside a smaller subnet")
    #                print("                           ", true_total, "in total")
    #                print("                            --> Scores:", (specific+s)*n.prefixlen, "for the border and", weighted_total, "overall.")
    #            else:
    #                print(" /!\ MISCONFIGURED NETWORK:", n, "\t-->", specific, "activities exactly in this net,", true_total-specific, "inside a smaller subnet for a total of", true_total)
    #                print("     Suspicious activities:")
                    for line in ip_pairs.splitlines():
                        ips = line.split("|")
                        net = netaddr.spanning_cidr([netaddr.IPAddress(ips[0]), netaddr.IPAddress(ips[1])])
    #                    if net == n:
    #                        print("                          [", ips[0], "<--->", ips[1], "]")

    #print (subnet_list)

    with open('subnets.csv', 'w', newline='') as csvfile:
        csvwriter = csv.writer(csvfile)
        # Write the header to the CSV file, if needed
        csvwriter.writerow(['Subnet','WellConfigured/NotWellConfigured','group-name','group-description','group-color','group-industrial-impact'])

        sorted_networks = sorted(subnet_list, key=lambda net: net.prefixlen, reverse=False)   
        for subnet in sorted_networks:
            # Determine if the subnet is well-configured or misconfigured
            status = 'Well-Configured' if ((specific+s)*subnet.prefixlen)/(weighted_total+s) > p and not subnet.is_link_local() and not subnet.is_loopback() else 'Misconfigured'
            # Write each subnet and its status to the CSV file
            csvwriter.writerow([str(subnet), status,str(subnet),'group-description','#441e91','0'])
        
    tools.removeduplicateline()
    #tools.compare_networks()
    
    
if __name__ == "__main__":
    main()