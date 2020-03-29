using System;
using System.Net;
using System.Threading.Tasks;

namespace CubeDns
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("=== Cube64128 DNS Client v1.0 ===\n");
            if (args.Length < 2 || args.Length > 5)
            {
                Console.WriteLine("Too few/many arguments.");
                return;
            }
            try
            {
                switch (args[0])
                {
                    case "--os-resolver":
                        var result = DnsResolvers.OSResolver(args[1]);
                        // PTR query
                        if (result.qTYPE == DnsResolvers.QTYPE.PTR)
                        {
                            Console.WriteLine($"IP: {args[1]}\nHostname: {result.hostname}");
                        }
                        else
                        {
                            Console.WriteLine($"Hostname: {args[1]}\nAddresses:");
                            foreach (IPAddress address in result.ips)
                            {
                                Console.WriteLine($"\t{address}");
                            }
                        }
                        break;
                    case "--cube-resolver":
                        try
                        {
                            if (args.Length == 2) // name
                                DnsResolvers.CubeResolver(args[1], IPAddress.Parse("1.1.1.1"));
                            else if (args.Length == 3) // name + dns
                                DnsResolvers.CubeResolver(args[1], IPAddress.Parse(args[2]));
                            else if (args.Length == 4) // name + dns + QTYPE
                                DnsResolvers.CubeResolver(args[1], IPAddress.Parse(args[2]), (DnsResolvers.QTYPE)Enum.Parse(typeof(DnsResolvers.QTYPE), args[3]));
                            else if (args.Length == 5 && args[4] == "DoH") // name + dns + QTYPE + QueryTransport
                                DnsResolvers.CubeResolver(args[1], null, (DnsResolvers.QTYPE)Enum.Parse(typeof(DnsResolvers.QTYPE), args[3]), (DnsResolvers.QueryTransport)Enum.Parse(typeof(DnsResolvers.QueryTransport), args[4]), args[2]);
                            else
                                DnsResolvers.CubeResolver(args[1], IPAddress.Parse(args[2]), (DnsResolvers.QTYPE)Enum.Parse(typeof(DnsResolvers.QTYPE), args[3]), (DnsResolvers.QueryTransport)Enum.Parse(typeof(DnsResolvers.QueryTransport), args[4]));
                        }
                        catch (FormatException e)
                        {
                            Console.WriteLine($"Invalid DNS server: {args[2]}\nException thrown: {e}");
                        }
                        break;
                    case "--dns-over-https":
                        if (args.Length == 2) // name
                            DnsResolvers.DoHJson(args[1]);
                        else if (args.Length == 3) // name + dns
                            DnsResolvers.DoHJson(args[1], args[2]);
                        else if (args.Length == 4) // name + dns + QTYPE
                            DnsResolvers.DoHJson(args[1], args[2], (DnsResolvers.QTYPE)Enum.Parse(typeof(DnsResolvers.QTYPE), args[3]));
                        else if (args.Length == 5) // name + dns + QTYPE + DNSSEC (do)
                            DnsResolvers.DoHJson(args[1], args[2], (DnsResolvers.QTYPE)Enum.Parse(typeof(DnsResolvers.QTYPE), args[3]), Boolean.Parse(args[4]));
                        break;
                    default:
                        Console.WriteLine($@"Invalid argument: ""{args[0]}""");
                        break;
                }
            }
            catch (Exception e)
            {
                Console.WriteLine($"{e}");
            }
        }
    }
}
