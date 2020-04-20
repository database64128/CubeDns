using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace CubeDns
{
    /// <summary>
    ///  DNSoverHTTPS JSON response class.
    /// </summary>
    public class DoHResponse
    {
        public int Status { get; set; }
        public bool TC { get; set; }
        public bool RD { get; set; }
        public bool RA { get; set; }
        public bool AD { get; set; }
        public bool CD { get; set; }
        public DoHQuestion[] Question { get; set; }
        public DoHAnswer[] Answer { get; set; }
    }

    /// <summary>
    ///  DNSoverHTTPS JSON question class.
    /// </summary>
    public class DoHQuestion
    {
        public string name { get; set; }
        public int type { get; set; }
    }

    /// <summary>
    ///  DNSoverHTTPS JSON answer class.
    /// </summary>
    public class DoHAnswer
    {
        public string name { get; set; }
        public int type { get; set; }
        public int TTL { get; set; }
        public string data { get; set; }
    }

    /// <summary>
    ///  Provides DNS resolver functions.
    /// </summary>
    public static class DnsResolvers
    {
        public static int DnsTimeout { get; set; } = 5000;

        public enum QueryTransport { Udp, Tcp, DoT, DoH }

        public enum QTYPE
        {
            A = 1,
            NS = 2,
            CNAME = 5,
            SOA = 6,
            PTR = 12,
            MX = 15,
            TXT = 16,
            AAAA = 28,
            SRV = 33
        }

        static Random rnd = new Random();
        //static byte[] queryID = new byte[2];

        /// <summary>
        ///  Uses host OS's APIs to resolve a hostname (Dns.GetHostAddress()) or an IP address(Dns.GetHostEntry()).
        /// </summary>
        public static (string hostname, IPAddress[] ips, QTYPE qTYPE) OSResolver(string name)
        {
            string hostname;
            IPAddress[] ips;
            QTYPE qTYPE = 0;

            // if name is an IPAddress, do a PTR query
            if (IPAddress.TryParse(name, out IPAddress ip))
            {
                IPHostEntry entry = Dns.GetHostEntry(ip);
                hostname = entry.HostName;
                ips = new IPAddress[] { ip };
                qTYPE = QTYPE.PTR;
            }
            else // if name is a hostname
            {
                hostname = name;
                ips = Dns.GetHostAddresses(name);
                foreach (IPAddress address in ips)
                {
                    if (address.AddressFamily == AddressFamily.InterNetwork)
                        qTYPE |= QTYPE.A;
                    else
                        qTYPE |= QTYPE.AAAA;
                }
            }

            return (hostname, ips, qTYPE);
        }

        /// <summary>
        ///  Translates a hostname string to QNAME in a DNS query.
        /// </summary>
        private static byte[] HostnameToQNAME(string hostname)
        {
            List<byte> QNAME = new List<byte>(hostname.Length + 2);
            int prevDotPos = -1, searchPosition = 0;
            searchPosition = hostname.IndexOf('.', searchPosition);
            while (searchPosition != -1)
            {
                // save length
                QNAME.Add((byte)(searchPosition - prevDotPos - 1));
                // save data
                QNAME.AddRange(Encoding.ASCII.GetBytes(hostname.Substring(prevDotPos + 1, searchPosition - prevDotPos - 1)));
                prevDotPos = searchPosition;
                // continue searching
                if (++searchPosition >= hostname.Length)
                    break;
                searchPosition = hostname.IndexOf('.', searchPosition);
            }
            // append remaining and 0
            QNAME.Add((byte)(hostname.Length - prevDotPos - 1));
            QNAME.AddRange(Encoding.ASCII.GetBytes(hostname.Substring(prevDotPos + 1)));
            QNAME.Add(0x00);
            // convert to byte array
            return QNAME.ToArray();
        }

        /// <summary>
        ///  Translates an IPv4 address to QNAME for a rDNS/PTR query.
        /// </summary>
        private static byte[] IPv4ToQNAME(IPAddress ipv4)
        {
            byte[] bytesIPv4 = ipv4.GetAddressBytes();
            Array.Reverse(bytesIPv4);
            StringBuilder domain = new StringBuilder(28);
            foreach (byte byteIPv4 in bytesIPv4)
            {
                domain.Append(byteIPv4);
                domain.Append('.');
            }
            domain.Append("in-addr.arpa");
            return HostnameToQNAME(domain.ToString());
        }

        /// <summary>
        ///  Translates an IPv6 address to QNAME for a rDNS/PTR query.
        /// </summary>
        private static byte[] IPv6ToQNAME(IPAddress ipv6)
        {
            char[] address = BitConverter.ToString(ipv6.GetAddressBytes()).Replace("-", "").ToCharArray();
            Array.Reverse(address);
            StringBuilder domain = new StringBuilder(72);
            foreach (char c in address)
            {
                domain.Append(c);
                domain.Append('.');
            }
            domain.Append("ip6.arpa");
            return HostnameToQNAME(domain.ToString());
        }

        /// <summary>
        ///  Makes a query datagram containing a header and a question.
        ///  Returns a byte array.
        /// </summary>
        private static byte[] MakeQueryDatagram(byte[] QNAME, QTYPE qTYPE, QueryTransport queryTransport)
        {
            byte[] query;
            byte[] header = new byte[12];
            Span<byte> headerSpan = new Span<byte>(header);
            byte[] question = new byte[QNAME.Length + 4];

            // BEGIN Header
            // ID
            // generate random ID
            rnd.NextBytes(headerSpan.Slice(start: 0, length: 2));
            //   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
            // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            // |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
            header[2] = 0x01; // RD == 1
            header[3] = 0x00;
            // QDCOUNT
            // No support for multiple questions in one query
            // as it's not supported by any DNS server implementation
            header[4] = 0x00;
            header[5] = 0x01;
            // ANCOUNT
            header[6] = 0x00;
            header[7] = 0x00;
            // NSCOUNT
            header[8] = 0x00;
            header[9] = 0x00;
            // ARCOUNT
            header[10] = 0x00;
            header[11] = 0x00;
            // END Header

            // BEGIN Question
            Array.Copy(QNAME, question, QNAME.Length);
            // QTYPE
            byte[] qTYPE4Bytes = new byte[4];
            BinaryPrimitives.WriteInt32BigEndian(qTYPE4Bytes, (int)qTYPE);
            question[QNAME.Length] = qTYPE4Bytes[2];
            question[QNAME.Length + 1] = qTYPE4Bytes[3];
            // QCLASS: IN
            question[QNAME.Length + 2] = 0x00;
            question[QNAME.Length + 3] = 0x01;
            // END Question

            // make query message based on queryTransport
            if (queryTransport == QueryTransport.Udp || queryTransport == QueryTransport.DoH) // Udp || DoH
            {
                query = new byte[header.Length + question.Length];
                Array.Copy(header, query, header.Length);
                Array.Copy(question, 0, query, header.Length, question.Length);
            }
            else // Tcp || DoT
            {
                query = new byte[2 + header.Length + question.Length];
                // Tcp Message Length
                byte[] tcpMsgLengthBytes = new byte[4];
                BinaryPrimitives.WriteInt32BigEndian(tcpMsgLengthBytes, header.Length + question.Length);
                Array.Copy(tcpMsgLengthBytes, 2, query, 0, 2);
                Array.Copy(header, 0, query, 2, 12); // header.Length == 12
                Array.Copy(question, 0, query, 14, question.Length); // 2 + 12 == 14
            }

            return query;
        }

        /// <summary>
        ///  Sends a DNS query via UDP.
        /// </summary>
        private static bool TryUdpQuery(byte[] query, IPAddress dns, out Span<byte> response)
        {
            UdpClient udpClient = new UdpClient();
            udpClient.Client.ReceiveTimeout = DnsTimeout;
            IPEndPoint dnsEndPoint = new IPEndPoint(dns, 53);
            try
            {
                // send the query
                udpClient.Connect(dnsEndPoint);
                udpClient.Send(query, query.Length);
                // receive the response
                response = new Span<byte>(udpClient.Receive(ref dnsEndPoint));
                udpClient.Close();
                return true;
            }
            catch (SocketException e) when (e.ErrorCode == 10060)
            {
                Console.WriteLine($"SocketException {e.ErrorCode}: DNS request timed out.");
                response = null;
                return false;
            }
        }

        /// <summary>
        ///  Sends a DNS query via TCP.
        /// </summary>
        private static bool TryTcpQuery(byte[] query, IPAddress dns, out Span<byte> response)
        {
            TcpClient tcpClient = new TcpClient();
            tcpClient.Client.ReceiveTimeout = DnsTimeout;
            IPEndPoint dnsEndPoint = new IPEndPoint(dns, 53);
            try
            {
                // send the query
                tcpClient.Connect(dnsEndPoint);
                NetworkStream networkStream = tcpClient.GetStream();
                networkStream.Write(query, 0, query.Length);
                // receive the response
                byte[] responseBytes = new byte[65535]; // the max length of a DNS message via TCP is 65535 bytes
                Int32 bytesReceived = networkStream.Read(responseBytes);
                // resize the array to remove empty bytes
                Array.Resize(ref responseBytes, bytesReceived);
                networkStream.Close();
                tcpClient.Close();
                response = new Span<byte>(responseBytes);
                return true;
            }
            catch (IOException e) when (e.InnerException.GetType().Name == "SocketException")
            {
                Console.WriteLine($"SocketException: {e}");
                //throw e.InnerException;
                tcpClient.Close();
                response = null;
                return false;
            }
            catch (SocketException e) when (e.ErrorCode == 10060) // it seems 10060 can only be the InnerException above
            {
                Console.WriteLine($"SocketException {e.ErrorCode}: Connection timed out.");
                tcpClient.Close();
                response = null;
                return false;
            }
            catch (SocketException e) when (e.ErrorCode == 10061)
            {
                Console.WriteLine($"SocketException {e.ErrorCode}: Connection refused.");
                tcpClient.Close();
                response = null;
                return false;
            }
            catch (ObjectDisposedException e) //when (e.ErrorCode == ?)
            {
                Console.WriteLine($"ObjectDisposedException: {e}");
                tcpClient.Close();
                response = null;
                return false;
            }
        }

        /// <summary>
        ///  Sends a DNS query via DNS over TLS.
        /// </summary>
        private static bool TryDoTQuery
            (
            byte[] query,
            IPAddress dns,
            //int port,
            out Span<byte> response
            )
        {
            TcpClient tcpClient = new TcpClient();
            tcpClient.Client.ReceiveTimeout = DnsTimeout;
            IPEndPoint dnsEndPoint = new IPEndPoint(dns, 853);
            try
            {
                tcpClient.Connect(dnsEndPoint);
                SslStream sslStream = new SslStream(tcpClient.GetStream());
                sslStream.AuthenticateAsClient(dns.ToString());
                sslStream.Write(query);
                sslStream.Flush();
                // receive the response
                byte[] responseBytes = new byte[65535]; // the max length of a DNS message via TCP is 65535 bytes
                Int32 bytesReceived = sslStream.Read(responseBytes);
                // resize the array to remove empty bytes
                Array.Resize(ref responseBytes, bytesReceived);
                tcpClient.Close();
                response = new Span<byte>(responseBytes);
                return true;
            }
            catch (AuthenticationException e)
            {
                Console.WriteLine($"{e}");
                tcpClient.Close();
                response = null;
                return false;
            }
            catch (IOException e) when (e.InnerException.GetType().Name == "SocketException")
            {
                Console.WriteLine($"SocketException: {e}");
                tcpClient.Close();
                response = null;
                return false;
            }
            catch (SocketException e) when (e.ErrorCode == 10061)
            {
                Console.WriteLine($"SocketException {e.ErrorCode}: Connection refused.");
                tcpClient.Close();
                response = null;
                return false;
            }
        }

        /// <summary>
        ///  Sends a DNS query via DNS over HTTPS.
        /// </summary>
        private static bool TryDoHQuery
            (
            byte[] query,
            out Span<byte> response,
            string dns = "https://cloudflare-dns.com/dns-query"
            )
        {
            HttpClient client = new HttpClient();
            client.Timeout = TimeSpan.FromSeconds(10);
            client.DefaultRequestHeaders.Add("Accept", "application/dns-message");
            client.DefaultRequestVersion = HttpVersion.Version20;
            ByteArrayContent byteArrayContent = new ByteArrayContent(query);
            byteArrayContent.Headers.ContentType = new MediaTypeHeaderValue("application/dns-message");

            try
            {
                HttpResponseMessage httpResponseMessage = client.PostAsync(dns, byteArrayContent).Result;
                Console.WriteLine($"Status Code: {httpResponseMessage.StatusCode}");
                response = new Span<byte>(httpResponseMessage.Content.ReadAsByteArrayAsync().Result);
                return httpResponseMessage.IsSuccessStatusCode;
            }
            catch (AggregateException e)
            {
                Console.WriteLine($"{e.InnerException}");
                response = null;
                return false;
            }
            catch (HttpRequestException e)
            {
                Console.WriteLine($"{e}");
                response = null;
                return false;
            }
        }

        /// <summary>
        ///  Translates the NAME in a DNS response to a hostname string.
        ///  Can handle extra bytes after the actual NAME.
        /// </summary>
        private static string NAMEToHostname(ReadOnlySpan<byte> NAME, ReadOnlySpan<byte> DnsMessage, QueryTransport queryTransport)
        {
            int pos = 0;
            StringBuilder hostname = new StringBuilder(256);
            while (NAME[pos] != 0x00)
            {
                // if compressed
                if (NAME[pos] >= 0xc0)
                {
                    // extract offset into a new array
                    var byteOffset = NAME.Slice(pos, 2).ToArray();
                    byteOffset[0] &= 0b0011_1111;
                    int offset = BinaryPrimitives.ReadUInt16BigEndian(byteOffset);
                    // recursively get hostname and append to hostname
                    if (queryTransport == QueryTransport.Tcp || queryTransport == QueryTransport.DoT)
                        offset += 2; // in a Tcp and DoT message, offset is relative to the header ID.
                    hostname.Append(NAMEToHostname(DnsMessage.Slice(offset, DnsMessage.Length - offset), DnsMessage, queryTransport));
                    hostname.Append('.');
                    // reached the end of NAME
                    break;
                }
                else
                {
                    hostname.Append(Encoding.ASCII.GetString(NAME.Slice(start: pos + 1, length: NAME[pos])));
                    hostname.Append('.');
                    pos += (NAME[pos] + 1);
                }
            }
            // remove the last '.'
            if (hostname.Length != 0)
                hostname.Remove(hostname.Length - 1, 1);
            return hostname.ToString();
        }

        /// <summary>
        ///  Finds the NAME in a message starting from an offset.
        ///  Precisely extracts the NAME.
        ///  Translates the NAME to a string.
        ///  Moves forward the offset and returns the string.
        /// </summary>
        private static string HandleNAMEinMessage(ReadOnlySpan<byte> response, ref int offset, QueryTransport queryTransport)
        {
            int oldOffset = offset;
            ReadOnlySpan<byte> bytesNAME;
            if (response[offset] >= 0xc0) // domain name is compressed
            {
                bytesNAME = response.Slice(offset, 2);
                offset += 2;
            }
            else
            {
                // offset is relative to response
                offset = offset + MemoryExtensions.IndexOf(response.Slice(offset), (byte)0x00);
                bytesNAME = response.Slice(oldOffset, offset - oldOffset + 1);
                offset++;
            }
            return NAMEToHostname(bytesNAME, response, queryTransport);
        }

        /// <summary>
        ///  Parses an Resource Record (RR) in a message starting from an offset.
        ///  Moves forward the offset.
        /// </summary>
        private static void ParseRR(ReadOnlySpan<byte> response, ref int offset, QueryTransport queryTransport)
        {
            string NAME = HandleNAMEinMessage(response, ref offset, queryTransport);

            var bytesTYPE = response.Slice(offset, 2);
            var bytesCLASS = response.Slice(offset + 2, 2);
            var bytesTTL = response.Slice(offset + 4, 4);
            var bytesRDLENGTH = response.Slice(offset + 8, 2);

            UInt16 TYPE = BinaryPrimitives.ReadUInt16BigEndian(bytesTYPE);
            UInt16 CLASS = BinaryPrimitives.ReadUInt16BigEndian(bytesCLASS);
            UInt32 TTL = BinaryPrimitives.ReadUInt32BigEndian(bytesTTL);
            UInt16 RDLENGTH = BinaryPrimitives.ReadUInt16BigEndian(bytesRDLENGTH);
            var bytesRDATA = response.Slice(offset + 10, RDLENGTH);

            offset += 10 + RDLENGTH;

            // print info
            Console.WriteLine($@"
NAME: {NAME}
TYPE: {TYPE}
CLASS: {CLASS}
TTL: {TTL}
RDLENGTH: {RDLENGTH}
RDATA: ");
            // parse RDATA based on TYPE
            if (TYPE == 1 || TYPE == 28) // IPv4 or IPv6
            {
                IPAddress address = new IPAddress(bytesRDATA);
                Console.WriteLine($"\t{address}");
            }
            else if (TYPE == 2 || TYPE == 12) // NS or PTR
            {
                string PTRDNAME = NAMEToHostname(bytesRDATA, response, queryTransport);
                Console.WriteLine($"\t{PTRDNAME}");
            }
            else // print raw data
            {
                string RDATA_hex = BitConverter.ToString(bytesRDATA.ToArray());
                Console.WriteLine($"\t{RDATA_hex}");
            }
        }

        /// <summary>
        ///  Parses the response message.
        /// </summary>
        private static void ParseResponse(ReadOnlySpan<byte> response, int queryLength, QTYPE qTYPE, QueryTransport queryTransport)
        {
            int offset = 0,
                tcpMsgLength = 0,
                questionOffset = 0;
            // Tcp & DoT pre-processing
            if (queryTransport == QueryTransport.Tcp || queryTransport == QueryTransport.DoT)
            {
                // save TcpMsgLength and remove it
                byte[] bytesTcpMsgLength = new byte[4];
                Array.Copy(response.Slice(start: 0, length: 2).ToArray(), 0, bytesTcpMsgLength, 2, 2);
                tcpMsgLength = BinaryPrimitives.ReadInt32BigEndian(bytesTcpMsgLength);
                offset = 2;
            }

            // read header
            var bytesID = response.Slice(start: offset, length: 2);
            var bytesHeaderStuff = response.Slice(start: offset + 2, length: 2);

            var bytesQDCOUNT = response.Slice(start: offset + 4, length: 2);
            var bytesANCOUNT = response.Slice(start: offset + 6, length: 2);
            var bytesNSCOUNT = response.Slice(start: offset + 8, length: 2);
            var bytesARCOUNT = response.Slice(start: offset + 10, length: 2);

            // parse header
            int QR = (bytesHeaderStuff[0] & 0b1000_0000) >> 7;
            int OPCODE = (bytesHeaderStuff[0] & 0b0111_1000) >> 3;
            int AA = (bytesHeaderStuff[0] & 0b0000_0100) >> 2;
            int TC = (bytesHeaderStuff[0] & 0b0000_0010) >> 1;
            int RD = bytesHeaderStuff[0] & 0b0000_0001;
            int RA = (bytesHeaderStuff[1] & 0b1000_0000) >> 7;
            int Z = (bytesHeaderStuff[1] & 0b0111_0000) >> 4;
            int RCODE = bytesHeaderStuff[1] & 0b0000_1111;

            UInt16 QDCOUNT = BinaryPrimitives.ReadUInt16BigEndian(bytesQDCOUNT);
            UInt16 ANCOUNT = BinaryPrimitives.ReadUInt16BigEndian(bytesANCOUNT);
            UInt16 NSCOUNT = BinaryPrimitives.ReadUInt16BigEndian(bytesNSCOUNT);
            UInt16 ARCOUNT = BinaryPrimitives.ReadUInt16BigEndian(bytesARCOUNT);

            // checks

            /*if (bytesID[0] != 0x20
                || bytesID[1] != 0x40
                || QR != 1
                || OPCODE != 0
                || TC != 0
                || RCODE != 0
                || QDCOUNT != 1)
            {
                Console.WriteLine($"Warning: header checks failed.");
            }*/

            // read question
            // length of QNAME is unknown
            // look for 0x00
            questionOffset = offset + 12;
            // offset is relative to response
            offset = questionOffset + MemoryExtensions.IndexOf(response.Slice(questionOffset), (byte)0x00);
            if (offset == -1)
            {
                Console.WriteLine("Error parsing response: invalid QNAME.");
                return;
            }
            var bytesQNAME = response.Slice(start: questionOffset, length: offset - questionOffset + 1);
            var bytesQTYPE = response.Slice(start: offset + 1, length: 2);
            var bytesQCLASS = response.Slice(start: offset + 3, length: 2);
            // parse question
            string QNAME = NAMEToHostname(bytesQNAME, response, queryTransport);
            UInt16 QTYPE = BinaryPrimitives.ReadUInt16BigEndian(bytesQTYPE);
            UInt16 QCLASS = BinaryPrimitives.ReadUInt16BigEndian(bytesQCLASS);

            // print info
            Console.WriteLine($@"Received bytes: {response.Length}

####### HEADER #######
ID: {BinaryPrimitives.ReadUInt16BigEndian(bytesID)}
QR: {QR}
OPCODE: {OPCODE}
AA: {AA}
TC: {TC}
RD: {RD}
RA: {RA}
Z: {Z}
RCODE: {RCODE}
QDCOUNT: {QDCOUNT}
ANCOUNT: {ANCOUNT}
NSCOUNT: {NSCOUNT}
ARCOUNT: {ARCOUNT}

####### QUESTION #######
QNAME: {QNAME}
QTYPE: {QTYPE}
QCLASS: {QCLASS}");

            offset += 5;
            // Parse all RRs
            for (int i = 0; i < ANCOUNT; i++)
            {
                Console.WriteLine($"\n####### ANSWER #{i} #######");
                ParseRR(response, ref offset, queryTransport);
            }
            for (int i = 0; i < NSCOUNT; i++)
            {
                Console.WriteLine($"\n####### AUTHORITY #{i} #######");
                ParseRR(response, ref offset, queryTransport);
            }
            for (int i = 0; i < ARCOUNT; i++)
            {
                Console.WriteLine($"\n####### ADDITIONAL #{i} #######");
                ParseRR(response, ref offset, queryTransport);
            }
        }

        /// <summary>
        ///  The resolver public interface.
        /// </summary>
        public static void CubeResolver
            (
            string name,
            IPAddress dns,
            QTYPE qTYPE = QTYPE.A,
            QueryTransport queryTransport = QueryTransport.Udp,
            string DoHURI = "https://cloudflare-dns.com/dns-query"
            )
        {
            byte[] QNAME;
            // if name is an IPAddress, do a PTR query
            if (IPAddress.TryParse(name, out IPAddress ip))
            {
                qTYPE = QTYPE.PTR;
                if (ip.AddressFamily == AddressFamily.InterNetwork)
                {
                    QNAME = IPv4ToQNAME(ip);
                }
                else
                {
                    QNAME = IPv6ToQNAME(ip);
                }
            }
            else // if name is a hostname
            {
                QNAME = HostnameToQNAME(name);
            }

            byte[] query = MakeQueryDatagram(QNAME, qTYPE, queryTransport);
            if (queryTransport == QueryTransport.Udp)
            {
                if (TryUdpQuery(query, dns, out Span<byte> response))
                {
                    ParseResponse(response, query.Length, qTYPE, queryTransport);
                }
                else // Udp failed, fallback to Tcp
                {
                    // change queryTransport and remake query message
                    Console.WriteLine($"UDP query failed. Fallback to TCP.");
                    queryTransport = QueryTransport.Tcp;
                    query = MakeQueryDatagram(QNAME, qTYPE, queryTransport);
                }
            }
            if (queryTransport == QueryTransport.Tcp)
            {
                if (TryTcpQuery(query, dns, out Span<byte> response))
                {
                    ParseResponse(response, query.Length, qTYPE, queryTransport);
                }
                else // Tcp failed, fallback to DoT
                {
                    // change queryTransport and remake query message
                    Console.WriteLine($"TCP query failed. Fallback to DNS over TLS.");
                    queryTransport = QueryTransport.DoT;
                    query = MakeQueryDatagram(QNAME, qTYPE, queryTransport);
                }
            }
            if (queryTransport == QueryTransport.DoT)
            {
                if (TryDoTQuery(query, dns, out Span<byte> response))
                {
                    ParseResponse(response, query.Length, qTYPE, queryTransport);
                }
                else // DoT failed
                {
                    Console.WriteLine($"DNS over TLS query failed.");
                }
            }
            if (queryTransport == QueryTransport.DoH)
            {
                if (TryDoHQuery(query, out Span<byte> response, DoHURI))
                {
                    ParseResponse(response, query.Length, qTYPE, queryTransport);
                }
                else // DoH failed
                {
                    Console.WriteLine($"DNS over HTTPS query failed.");
                }
            }
        }

        /// <summary>
        ///  DNS over HTTPS using JSON format.
        ///  Returns HTTPS response body and parsed Json class.
        ///  Throws HttpRequestException.
        /// </summary>
        public static (string responseBody, DoHResponse doHResponse) DoHJson
            (
            string name,
            string dns = "https://cloudflare-dns.com/dns-query",
            QTYPE qTYPE = QTYPE.A,
            bool dnssec = true
            )
        {
            // make query URI
            StringBuilder queryURI = new StringBuilder(dns, 256);
            queryURI.Append($"?name={name}&type={qTYPE}");
            if (dnssec)
            {
                queryURI.Append($"&do=true");
            }
            // init HttpClient and send query
            HttpClient client = new HttpClient();
            client.Timeout = TimeSpan.FromSeconds(10);
            client.DefaultRequestHeaders.Add("Accept", "application/dns-json");
            client.DefaultRequestVersion = HttpVersion.Version20;

            string responseBody = client.GetStringAsync(queryURI.ToString()).Result;
            DoHResponse doHResponse = JsonSerializer.Deserialize<DoHResponse>(responseBody);

            return (responseBody, doHResponse);
        }
    }
}
