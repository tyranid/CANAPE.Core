//    CANAPE Core Network Testing Library
//    Copyright (C) 2017 James Forshaw
//    Based in part on CANAPE Network Testing Tool
//    Copyright (C) 2014 Context Information Security
//
//    This program is free software: you can redistribute it and/or modify
//    it under the terms of the GNU General Public License as published by
//    the Free Software Foundation, either version 3 of the License, or
//    (at your option) any later version.
//
//    This program is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//    GNU General Public License for more details.
//
//    You should have received a copy of the GNU General Public License
//    along with this program.  If not, see <http://www.gnu.org/licenses/>.
using CANAPE.Utils;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;

namespace CANAPE.Net.Protocols.Parser
{
    /// <summary>
    /// A class to parse and reconstruct a DNS packet from an array
    /// </summary>
    public class DNSPacket
    {
        /// <summary>
        /// DNS type
        /// </summary>
        public enum DNSType : ushort
        {
            /// <summary>
            /// A record
            /// </summary>
            A = 1,
            /// <summary>
            /// NS record
            /// </summary>
            NS = 2,
            /// <summary>
            /// MS record
            /// </summary>
            MD = 3,
            /// <summary>
            /// MF record
            /// </summary>
            MF = 4,
            /// <summary>
            /// CNAME record
            /// </summary>
            CNAME = 5,
            /// <summary>
            /// SOA record
            /// </summary>
            SOA = 6,
            /// <summary>
            /// MB record
            /// </summary>
            MB = 7,
            /// <summary>
            /// MG record
            /// </summary>
            MG = 8,
            /// <summary>
            /// MR record
            /// </summary>
            MR = 9,
            /// <summary>
            /// NULL record
            /// </summary>
            NULL = 10,
            /// <summary>
            /// WKS record
            /// </summary>
            WKS = 11,
            /// <summary>
            /// PTR record
            /// </summary>
            PTR = 12,
            /// <summary>
            /// HINFO record
            /// </summary>
            HINFO = 13,
            /// <summary>
            /// MINFO record
            /// </summary>
            MINFO = 14,
            /// <summary>
            /// MX record
            /// </summary>
            MX = 15,
            /// <summary>
            /// TXT record
            /// </summary>
            TXT = 16,
            /// <summary>
            /// AAAA record
            /// </summary>
            AAAA = 28,
            /// <summary>
            /// AXFR record
            /// </summary>
            AXFR = 252,
            /// <summary>
            /// MAILB record
            /// </summary>
            MAILB = 253,
            /// <summary>
            /// MAILA record
            /// </summary>
            MAILA = 254,
            /// <summary>
            /// A records
            /// </summary>
            AllRecords = 255
        }

        /// <summary>
        /// DNS Class type
        /// </summary>
        public enum DNSClass : ushort
        {
            /// <summary>
            /// IN type
            /// </summary>
            IN = 1,
            /// <summary>
            /// CS type
            /// </summary>
            CS = 2,
            /// <summary>
            /// CH type
            /// </summary>
            CH = 3,
            /// <summary>
            /// HS type
            /// </summary>
            HS = 4,
            /// <summary>
            /// Any class type
            /// </summary>
            AnyClass = 255
        }

        /// <summary>
        /// DNS question
        /// </summary>
        public class DNSQuestion
        {
            /// <summary>
            /// Name
            /// </summary>
            public string QName { get; set; }
            /// <summary>
            /// Type
            /// </summary>
            public DNSType QType { get; set; }
            /// <summary>
            /// Class
            /// </summary>
            public DNSClass QClass { get; set; }
        }

        /// <summary>
        /// Base resource record
        /// </summary>
        public abstract class DNSRRBase
        {
            /// <summary>
            /// Name
            /// </summary>
            public string Name { get; set; }
            /// <summary>
            /// Type
            /// </summary>
            public DNSType Type { get; set; }
            /// <summary>
            /// Class
            /// </summary>
            public DNSClass Class { get; set; }
            /// <summary>
            /// TTL
            /// </summary>
            public uint TimeToLive { get; set; }

            /// <summary>
            /// Write record to write
            /// </summary>
            /// <param name="writer">The writer</param>
            /// <param name="stringCache">String cache</param>
            public void ToWriter(DataWriter writer, Dictionary<string, int> stringCache)
            {
                DNSPacket.WriteString(Name, writer, stringCache);
                writer.WriteUInt16((ushort)Type, false);
                writer.WriteUInt16((ushort)Class, false);
                writer.WriteUInt32(TimeToLive, false);

                long currPos = writer.GetStream().Position;
                writer.WriteUInt16(0, false);
                WriteData(writer, stringCache);
                long endPos = writer.GetStream().Position;

                writer.GetStream().Position = currPos;

                if ((endPos - currPos - 2) > (long)ushort.MaxValue)
                {
                    throw new ArgumentException(String.Format("RR data cannot be longer than {0}", ushort.MaxValue));
                }

                writer.WriteUInt16((ushort)(endPos - currPos - 2), false);
                writer.GetStream().Position = endPos;
            }

            /// <summary>
            /// Write extra data
            /// </summary>
            /// <param name="writer">Writer</param>
            /// <param name="stringCache">String cache</param>
            public abstract void WriteData(DataWriter writer, Dictionary<string, int> stringCache);
        }

        /// <summary>
        /// DNS opcode
        /// </summary>
        public enum DNSOpcode
        {
            /// <summary>
            /// Query
            /// </summary>
            QUERY = 0,
            /// <summary>
            /// IQuery
            /// </summary>
            IQUERY,
            /// <summary>
            /// Status
            /// </summary>
            STATUS,
        }

        /// <summary>
        /// DNS response code
        /// </summary>
        public enum DNSRCode
        {
            /// <summary>
            /// No error
            /// </summary>
            NoError = 0,
            /// <summary>
            /// Format error
            /// </summary>
            FormatError,
            /// <summary>
            /// Server failure
            /// </summary>
            ServerFailure,
            /// <summary>
            /// Name error
            /// </summary>
            NameError,
            /// <summary>
            /// No implemented
            /// </summary>
            NotImplemented,
            /// <summary>
            /// Refused
            /// </summary>
            Refused
        }

        /// <summary>
        /// Unknown resource record
        /// </summary>
        [Guid("B5F0ACD5-54B7-4C5C-AB45-AF8044EA3027")]
        public class UnknownDNSRR : DNSRRBase
        {
            /// <summary>
            /// Extra data
            /// </summary>
            public byte[] RData { get; set; }

            /// <summary>
            /// Write data block
            /// </summary>
            /// <param name="writer">The writer</param>
            /// <param name="stringCache">The string cache</param>
            public override void WriteData(DataWriter writer, Dictionary<string, int> stringCache)
            {
                writer.WriteBytes(RData);
            }
        }

        /// <summary>
        /// CNAME RR
        /// </summary>
        [Guid("C28F870B-2EBE-4B7B-8BF9-000000000000")]
        public class CNameDNSRR : DNSRRBase
        {
            /// <summary>
            /// The CNAME
            /// </summary>
            public string CName { get; set; }

            /// <summary>
            /// Constructor
            /// </summary>
            /// <param name="data"></param>
            /// <param name="rdata"></param>
            public CNameDNSRR(byte[] data, byte[] rdata)
            {
                CName = ReadString(data, new DataReader(new MemoryStream(rdata)));
            }

            /// <summary>
            /// Constructor
            /// </summary>
            public CNameDNSRR()
            {
                CName = String.Empty;
            }

            /// <summary>
            /// Write data block
            /// </summary>
            /// <param name="writer">The writer</param>
            /// <param name="stringCache">The string cache</param>
            public override void WriteData(DataWriter writer, Dictionary<string, int> stringCache)
            {
                WriteString(CName, writer, stringCache);
            }
        }

        /// <summary>
        /// 
        /// </summary>
        [Guid("C28F870B-2EBE-4B7B-8BF9-000000000001")]
        public class ADNSRR : DNSRRBase
        {
            /// <summary>
            /// 
            /// </summary>
            public IPAddress Address { get; set; }

            /// <summary>
            /// 
            /// </summary>
            /// <param name="rdata"></param>
            public ADNSRR(byte[] rdata)
            {
                if (rdata.Length != 4)
                {
                    throw new ArgumentException("Invalid length for IPv4 address");
                }

                Address = new IPAddress(rdata);
            }

            /// <summary>
            /// 
            /// </summary>
            public ADNSRR()
            {
                Address = IPAddress.Any;
            }

            /// <summary>
            /// Write data block
            /// </summary>
            /// <param name="writer">The writer</param>
            /// <param name="stringCache">The string cache</param>
            public override void WriteData(DataWriter writer, Dictionary<string, int> stringCache)
            {
                if (Address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
                {
                    throw new ArgumentException("Must provide a IPv4 address for a A record");
                }

                writer.WriteBytes(Address.GetAddressBytes());
            }
        }

        /// <summary>
        /// 
        /// </summary>
        [Guid("C28F870B-2EBE-4B7B-8BF9-000000000002")]
        public class AAAADNSRR : DNSRRBase
        {
            /// <summary>
            /// 
            /// </summary>
            public IPAddress Address { get; set; }

            /// <summary>
            /// 
            /// </summary>
            /// <param name="rdata"></param>
            public AAAADNSRR(byte[] rdata)
            {
                if (rdata.Length != 16)
                {
                    throw new ArgumentException("Invalid length for IPv6 address");
                }

                Address = new IPAddress(rdata);
            }

            /// <summary>
            /// 
            /// </summary>
            public AAAADNSRR()
            {
                Address = IPAddress.IPv6Any;
            }

            /// <summary>
            /// Write data block
            /// </summary>
            /// <param name="writer">The writer</param>
            /// <param name="stringCache">The string cache</param>
            public override void WriteData(DataWriter writer, Dictionary<string, int> stringCache)
            {
                if (Address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetworkV6)
                {
                    throw new ArgumentException("Must provide a IPv6 address for a AAAA record");
                }

                writer.WriteBytes(Address.GetAddressBytes());
            }
        }

        /// <summary>
        /// 
        /// </summary>
        [Guid("C28F870B-2EBE-4B7B-8BF9-000000000003")]
        public class PTRDNSRR : DNSRRBase
        {
            /// <summary>
            /// 
            /// </summary>
            public string Ptr { get; set; }

            /// <summary>
            /// 
            /// </summary>
            /// <param name="data"></param>
            /// <param name="rdata"></param>
            public PTRDNSRR(byte[] data, byte[] rdata)
            {
                Ptr = ReadString(data, new DataReader(new MemoryStream(rdata)));
            }

            /// <summary>
            /// 
            /// </summary>
            public PTRDNSRR()
            {
                Ptr = String.Empty;
            }

            /// <summary>
            /// Write data block
            /// </summary>
            /// <param name="writer">The writer</param>
            /// <param name="stringCache">The string cache</param>
            public override void WriteData(DataWriter writer, Dictionary<string, int> stringCache)
            {
                WriteString(Ptr, writer, stringCache);
            }
        }

        /// <summary>
        /// Id field
        /// </summary>
        public ushort Id { get; set; }

        /// <summary>
        /// Is query
        /// </summary>
        public bool Query { get; set; }

        /// <summary>
        /// Is AA
        /// </summary>
        public bool AuthoritiveAnswer { get; set; }

        /// <summary>
        /// DNS Opcode
        /// </summary>
        public DNSOpcode Opcode { get; set; }

        /// <summary>
        /// If truncated
        /// </summary>
        public bool Truncation { get; set; }

        /// <summary>
        /// Recursion desired
        /// </summary>
        public bool RecursionDesired { get; set; }

        /// <summary>
        /// Recursion available
        /// </summary>
        public bool RecursionAvailable { get; set; }

        /// <summary>
        /// Response code
        /// </summary>
        public DNSRCode ResponseCode { get; set; }

        /// <summary>
        /// List of questions
        /// </summary>
        public DNSQuestion[] Questions { get; set; }

        /// <summary>
        /// List of answers
        /// </summary>
        public DNSRRBase[] Answers { get; set; }

        /// <summary>
        /// Name servers
        /// </summary>
        public DNSRRBase[] NameServers { get; set; }

        /// <summary>
        /// Additional records
        /// </summary>
        public DNSRRBase[] Additional { get; set; }

        private static string ReadString(byte[] data, DataReader reader)
        {
            Encoding encoding = new BinaryEncoding();
            StringBuilder name = new StringBuilder();
            int len = reader.ReadByte();

            while (len != 0)
            {
                if ((len & 0xC0) != 0)
                {
                    int ofs = (len & ~0xC0) << 8;

                    ofs |= reader.ReadByte();

                    MemoryStream stm = new MemoryStream(data);
                    stm.Position = ofs;

                    name.Append(ReadString(data, new DataReader(stm)));

                    break;
                }
                else
                {
                    name.Append(reader.ReadString(len)).Append(".");
                }

                len = reader.ReadByte();
            }

            return name.ToString();
        }

        private static DNSQuestion ReadQuestion(byte[] data, DataReader reader)
        {
            DNSQuestion q = new DNSQuestion();

            q.QName = ReadString(data, reader);
            q.QType = (DNSType)reader.ReadUInt16(false);
            q.QClass = (DNSClass)reader.ReadUInt16(false);

            return q;
        }

        private static DNSRRBase ReadResourceRecord(byte[] data, DataReader reader)
        {
            DNSRRBase rr = null;

            string name = ReadString(data, reader);
            DNSType type = (DNSType)reader.ReadUInt16(false);
            DNSClass cls = (DNSClass)reader.ReadUInt16(false);
            uint ttl = reader.ReadUInt32(false);
            ushort rlen = reader.ReadUInt16(false);
            byte[] rdata = reader.ReadBytes(rlen);

            switch (type)
            {
                case DNSType.CNAME:
                    {
                        CNameDNSRR newRec = new CNameDNSRR(data, rdata);
                        rr = newRec;
                    }
                    break;
                case DNSType.A:
                    {
                        ADNSRR aRec = new ADNSRR(rdata);
                        rr = aRec;
                    }
                    break;
                case DNSType.AAAA:
                    {
                        AAAADNSRR aRec = new AAAADNSRR(rdata);
                        rr = aRec;
                    }
                    break;
                case DNSType.PTR:
                    {
                        PTRDNSRR aRec = new PTRDNSRR(data, rdata);
                        rr = aRec;
                    }
                    break;
                default:
                    {
                        UnknownDNSRR newRec = new UnknownDNSRR();
                        newRec.RData = rdata;
                        rr = newRec;
                    }
                    break;
            }

            rr.Name = name;
            rr.Class = cls;
            rr.Type = type;
            rr.TimeToLive = ttl;

            return rr;
        }

        private static DNSRRBase[] ReadResourceRecords(byte[] data, DataReader reader, int count)
        {
            DNSRRBase[] records = new DNSRRBase[count];

            for (int i = 0; i < count; ++i)
            {
                records[i] = ReadResourceRecord(data, reader);
            }

            return records;
        }

        private static bool GetBooleanFlag(ushort flags, int pos)
        {
            return ((flags >> (15 - pos)) & 1) == 1;
        }

        private static int GetFlagValue(ushort flags, int pos)
        {
            return (flags >> (15 - pos - 3)) & 0xF;
        }

        private static ushort SetBooleanFlag(ushort flags, int pos, bool value)
        {
            if (value)
            {
                return (ushort)(flags | (1 << (15 - pos)));
            }
            else
            {
                return flags;
            }
        }

        private static ushort SetFlagValue(ushort flags, int pos, int val)
        {
            return (ushort)(flags | (val << (15 - pos - 3)));
        }

        /// <summary>
        /// Create from an array
        /// </summary>
        /// <param name="data">The data</param>
        /// <returns>The parsed DNS packet</returns>
        public static DNSPacket FromArray(byte[] data)
        {
            DataReader reader = new DataReader(new MemoryStream(data));

            DNSPacket ret = new DNSPacket();

            ret.Id = reader.ReadUInt16(false);

            ushort flags = reader.ReadUInt16(false);

            ret.Query = GetBooleanFlag(flags, 0);
            ret.Opcode = (DNSOpcode)GetFlagValue(flags, 1);
            ret.AuthoritiveAnswer = GetBooleanFlag(flags, 5);
            ret.Truncation = GetBooleanFlag(flags, 6);
            ret.RecursionDesired = GetBooleanFlag(flags, 7);
            ret.RecursionAvailable = GetBooleanFlag(flags, 8);
            ret.ResponseCode = (DNSRCode)GetFlagValue(flags, 12);

            ushort qdcount = reader.ReadUInt16(false);
            ushort ancount = reader.ReadUInt16(false);
            ushort nscount = reader.ReadUInt16(false);
            ushort arcount = reader.ReadUInt16(false);

            if (qdcount > 0)
            {
                DNSQuestion[] questions = new DNSQuestion[qdcount];

                for (int i = 0; i < qdcount; i++)
                {
                    questions[i] = ReadQuestion(data, reader);
                }

                ret.Questions = questions;
            }

            if (ancount > 0)
            {
                ret.Answers = ReadResourceRecords(data, reader, ancount);
            }

            if (nscount > 0)
            {
                ret.NameServers = ReadResourceRecords(data, reader, nscount);
            }

            if (arcount > 0)
            {
                ret.Additional = ReadResourceRecords(data, reader, arcount);
            }

            return ret;
        }

        private static void WriteStringPart(string value, DataWriter writer, Dictionary<string, int> stringCache)
        {
            Encoding encoding = new BinaryEncoding();

            if (String.IsNullOrEmpty(value) || (value == "."))
            {
                writer.WriteByte(0);
            }
            else
            {
                if (stringCache.ContainsKey(value))
                {
                    ushort pos = (ushort)(0xC000 | stringCache[value]);
                    writer.WriteUInt16(pos, false);
                }
                else
                {
                    string[] values = value.Split(new[] { '.' }, 2, StringSplitOptions.RemoveEmptyEntries);

                    if (values[0].Length > 63)
                    {
                        throw new InvalidDataException("DNS names components cannot be longer than 63 characters");
                    }

                    long currPos = writer.GetStream().Position;
                    writer.WriteByte((byte)(values[0].Length & 0x3F));
                    writer.WriteString(values[0]);
                    stringCache.Add(value, (int)currPos);

                    if (values.Length > 1)
                    {
                        WriteStringPart(values[1], writer, stringCache);
                    }
                    else
                    {
                        WriteStringPart(null, writer, stringCache);
                    }
                }
            }
        }

        private static void WriteString(string value, DataWriter writer, Dictionary<string, int> stringCache)
        {
            value = value.TrimEnd().TrimEnd('.');

            WriteStringPart(value, writer, stringCache);
        }

        /// <summary>
        /// Convert to an array
        /// </summary>
        /// <returns>The data</returns>
        public byte[] ToArray()
        {
            MemoryStream stm = new MemoryStream();
            DataWriter writer = new DataWriter(stm);
            Dictionary<string, int> stringCache = new Dictionary<string, int>();

            writer.WriteUInt16(Id, false);

            ushort flags = 0;

            flags = SetBooleanFlag(flags, 0, Query);
            flags = SetFlagValue(flags, 1, (int)Opcode);
            flags = SetBooleanFlag(flags, 5, AuthoritiveAnswer);
            flags = SetBooleanFlag(flags, 6, Truncation);
            flags = SetBooleanFlag(flags, 7, RecursionDesired);
            flags = SetBooleanFlag(flags, 8, RecursionAvailable);
            flags = SetFlagValue(flags, 12, (int)ResponseCode);

            writer.WriteUInt16(flags, false);
            writer.WriteUInt16(Questions != null ? (ushort)Questions.Length : (ushort)0, false);
            writer.WriteUInt16(Answers != null ? (ushort)Answers.Length : (ushort)0, false);
            writer.WriteUInt16(NameServers != null ? (ushort)NameServers.Length : (ushort)0, false);
            writer.WriteUInt16(Additional != null ? (ushort)Additional.Length : (ushort)0, false);

            if (Questions != null)
            {
                foreach (DNSQuestion q in Questions)
                {
                    WriteString(q.QName, writer, stringCache);
                    writer.WriteUInt16((ushort)q.QType, false);
                    writer.WriteUInt16((ushort)q.QClass, false);
                }
            }

            if (Answers != null)
            {
                foreach (DNSRRBase rr in Answers)
                {
                    rr.ToWriter(writer, stringCache);
                }
            }

            if (NameServers != null)
            {
                foreach (DNSRRBase rr in NameServers)
                {
                    rr.ToWriter(writer, stringCache);
                }
            }

            if (Additional != null)
            {
                foreach (DNSRRBase rr in Additional)
                {
                    rr.ToWriter(writer, stringCache);
                }
            }

            return stm.ToArray();
        }
    }
}
