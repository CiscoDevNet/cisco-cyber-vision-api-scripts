import netaddr
import csv   

def compute_subnets(raw_data, p, s):
    # Subnet List for printing

    wellconfigured = set()
    notwellconfigured = set()

    for ips_list in raw_data.values():
        
        networkDict = {}
        networkList = []
        for ips in ips_list:
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
            weighted_total = networkTotalDict[n]
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
                wellconfigured.add(n)
            else:
                notwellconfigured.add(n)
    
    # remove overlapping
    for n in list(wellconfigured):
        for nn in list(wellconfigured):
            if nn != n and nn in n:
                wellconfigured.discard(nn)
            if nn != n and n in nn:
                wellconfigured.discard(n)
    for n in list(notwellconfigured):
        for nn in list(notwellconfigured):
            if nn != n and nn in n:
                notwellconfigured.discard(nn)
            if nn != n and n in nn:
                notwellconfigured.discard(n)

    return wellconfigured, notwellconfigured

def write_subnets(wellconfigured, notwellconfigured):
    with open('subnets.csv', 'w', newline='') as csvfile:
        csvwriter = csv.writer(csvfile)
        # Write the header to the CSV file, if needed
        csvwriter.writerow(['Subnet','WellConfigured/NotWellConfigured','group-name','group-description','group-color','group-industrial-impact'])

        sorted_networks = sorted(list(wellconfigured))    
        for subnet in sorted_networks:
            status = 'Well-Configured'
            # Write each subnet and its status to the CSV file
            csvwriter.writerow([str(subnet), status,str(subnet),'group-description','#441e91','0'])

        # sorted_networks = sorted(list(notwellconfigured))   
        # for subnet in sorted_networks:
        #     status = 'Misconfigured'
        #     # Write each subnet and its status to the CSV file
        #     csvwriter.writerow([str(subnet), status,str(subnet),'group-description','#441e91','0'])

        print("LOG: Exported %d subnets into subnets.csv"%len(wellconfigured))
    