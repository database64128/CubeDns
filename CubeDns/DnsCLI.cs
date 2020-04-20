using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text;

namespace CubeDns
{
    class DnsCLI
    {
        public static void ArgsParser(string[] args)
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
                        PrintOSResolver(args);
                        break;
                    case "--cube-resolver":
                        PrintCubeResolver(args);
                        break;
                    case "--doh-json":
                        PrintDoHJson(args);
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

        public static void PrintOSResolver(string[] args)
        {
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
        }

        public static void PrintCubeResolver(string[] args)
        {
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
                else if (args.Length == 5)
                    DnsResolvers.CubeResolver(args[1], IPAddress.Parse(args[2]), (DnsResolvers.QTYPE)Enum.Parse(typeof(DnsResolvers.QTYPE), args[3]), (DnsResolvers.QueryTransport)Enum.Parse(typeof(DnsResolvers.QueryTransport), args[4]));
                else
                    return;
            }
            catch (FormatException e)
            {
                Console.WriteLine($"Invalid DNS server: {args[2]}\nException thrown: {e}");
            }
        }

        public static void PrintDoHJson(string[] args)
        {
            (string responseBody, DoHResponse doHResponse) result;

            try
            {
                if (args.Length == 2) // name
                    result = DnsResolvers.DoHJson(args[1]);
                else if (args.Length == 3) // name + dns
                    result = DnsResolvers.DoHJson(args[1], args[2]);
                else if (args.Length == 4) // name + dns + QTYPE
                    result = DnsResolvers.DoHJson(args[1], args[2], (DnsResolvers.QTYPE)Enum.Parse(typeof(DnsResolvers.QTYPE), args[3]));
                else if (args.Length == 5) // name + dns + QTYPE + DNSSEC (do)
                    result = DnsResolvers.DoHJson(args[1], args[2], (DnsResolvers.QTYPE)Enum.Parse(typeof(DnsResolvers.QTYPE), args[3]), Boolean.Parse(args[4]));
                else
                {
                    Console.WriteLine("Invalid arguments.");
                    return;
                }

                Console.WriteLine($"####### Response JSON #######\n{result.responseBody}\n");
                foreach (DoHAnswer doHAnswer in result.doHResponse.Answer)
                {
                    Console.WriteLine($"####### Parsed Response #######\n{doHAnswer.data}\n");
                }
            }
            catch (HttpRequestException e)
            {
                Console.WriteLine($"{e}");
            }
        }
    }
}
