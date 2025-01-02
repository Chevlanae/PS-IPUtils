using System;
using System.Threading;
using System.Linq;
using System.Management.Automation;
using System.Text.RegularExpressions;
using System.Collections;
using System.Collections.Generic;

namespace IPUtils
{

    public class IPArrayShared : IEnumerable
    {
        private string[] _Array;

        public IPArrayShared(long size)
        {
            _Array = new string[size];
        }
        
        public string this[long i]
        {
            get
            {
                lock (_Array)
                {
                    return _Array[i];
                }
            }
            set
            {
                lock (_Array)
                {
                    _Array[i] = value;
                }
            }
        }

        public int Length
        {
            get
            {
                lock (_Array)
                {
                    return _Array.Length;
                }
            }
        }

        public IEnumerator GetEnumerator()
        {
            lock (_Array)
            {
                return _Array.GetEnumerator();
            }
        }

        public List<string> ToList()
        {
            return new List<string>(_Array);
        }
    }

    //Instance class for generating a block of 256 IP addresses
    //Used for multithreading in NewIPRange
    public class IPBlock
    {
        //Array of length 4, represents the block's largest possible IP address.
        private int[] TopEnd;

        //Array of length 4, represents the block's smallest possible IP address.
        private int[] LowEnd;

        private IPArrayShared IPs;

        private long IndexOffset;

        public IPBlock(int[] topE, int[] lowE, IPArrayShared ipArray, long indexOffset)
        {
            TopEnd = topE;
            LowEnd = lowE;
            IPs = ipArray;
            IndexOffset = indexOffset;
        }

        public void Gen()
        {
            foreach (int b4 in Enumerable.Range(1, TopEnd[3]))
            {
                IPs[IndexOffset + (b4 - 1)] = (LowEnd[0] + TopEnd[0]) + "." + (LowEnd[1] + TopEnd[1]) + "." + (LowEnd[2] + TopEnd[2]) + "." + (LowEnd[3] + b4);
            }
        }
    }

    public static class IPRegex
    {
        public static class Patterns
        {
            public const string Byte = "(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)";
            public const string IPAddress = Byte + "\\." + Byte + "\\." + Byte + "\\." + Byte;
            public const string PrefixLength = "(3[0-2]|2[0-9]|1[0-9]|[1-9])";
            public const string CIDR = IPAddress + "/" + PrefixLength;
            public const string SubnetByte = "(255|254|252|248|240|224|192|128|0+)";
            public const string SubnetMask = "(255\\.255\\.255\\." + SubnetByte + ")|(255\\.255\\." + SubnetByte + "\\.0)|(255\\." + SubnetByte + "\\.0\\.0)|(" + SubnetByte + "\\.0\\.0\\.0)";
        }

        static public Regex Byte = new Regex(Patterns.Byte);
        static public Regex IPAddress = new Regex(Patterns.IPAddress);
        static public Regex PrefixLength = new Regex(Patterns.PrefixLength);
        static public Regex CIDR = new Regex(Patterns.CIDR);
        static public Regex SubnetByte = new Regex(Patterns.SubnetByte);
        static public Regex SubnetMask = new Regex(Patterns.SubnetMask);
    }

    [Cmdlet(VerbsCommon.New, "IPRange")]
    public class NewIPRange : Cmdlet
    {
        //Standard CIDR string
        [Parameter(
            Position = 0,
            ValueFromPipeline = true,
            Mandatory = true
        )]
        [ValidatePattern(IPRegex.Patterns.CIDR)]
        public string CIDR
        {
            get { return cidr; }
            set { cidr = value; }
        }
        private string cidr = "0.0.0.0/0";


        //Toggle multithreading
        [Parameter()]
        public SwitchParameter Threading
        {
            get { return threading; }
            set { threading = value; }
        }
        private bool threading;

        //Toggle timestamp function
        [Parameter()]
        public SwitchParameter Time
        {
            get { return time; }
            set { time = value; }
        }
        private bool time;

        //Main
        protected override void ProcessRecord()
        {
            //Smallest possible IP address
            int[] lowEnd = Array.ConvertAll(cidr.Split('/')[0].Split('.'), new Converter<string, int>(int.Parse));

            //Prefix length
            int prefixLength = int.Parse(cidr.Split('/')[1]);

            //Calculate subnet mask from prefixLength
            //https://learn.microsoft.com/en-us/dotnet/api/system.bitconverter.getbytes?view=netstandard-2.0
            byte[] subnetMask = BitConverter.GetBytes(UInt32.MaxValue << (32 - prefixLength));

            //Reverse array if system is little endian (not tested on big endian machines, I don't even know where to find those).
            //https://learn.microsoft.com/en-us/dotnet/api/system.bitconverter.islittleendian?view=netstandard-2.0
            if (BitConverter.IsLittleEndian) Array.Reverse(subnetMask);

            //Calculate wildcardMask
            //https://en.wikipedia.org/wiki/Wildcard_mask
            byte[] wildcardMask = Array.ConvertAll(subnetMask, new Converter<byte, byte>(b => (byte)(~b & byte.MaxValue)));

            //Compare wildcardMask and lowEnd for invalid values, throw exception if invalid
            for (int i = 0; i < 4; i++)
            {
                if ((wildcardMask[i] + lowEnd[i]) > 255)
                {
                    Exception err = new Exception(
                        "\'" + lowEnd[i] + "\'" + " in \'" + cidr +
                        "\' will produce an invalid IP range with the given prefix length. \'" +
                        lowEnd[i] + "\' will produce bytes in excess of the maximum value, 255."
                    );
                    ThrowTerminatingError(new ErrorRecord(err, "Invalid CIDR", ErrorCategory.InvalidArgument, cidr));
                }
            }

            //Timestamp used to calculate the total time of execution
            DateTime timestamp = DateTime.Now;

            //Calculate total amount of IP blocks needed
            //Always 1 block if total amount of IPs is less than 255
            long ipCount = 1;
            ipCount *= wildcardMask[0] + 1;
            ipCount *= wildcardMask[1] + 1;
            ipCount *= wildcardMask[2] + 1;
            ipCount *= wildcardMask[3] == 0 ? 1 : wildcardMask[3];

            //Generate IPs on multiple threads
            //Blocks of 255 individual IP addresses will be assigned an individual thread
            //IP addresses are written sequentially.
            if (threading)
            {
                List<Thread> threads = new List<Thread>();
                IPArrayShared IPs = new IPArrayShared(ipCount);

                //IPBlock index offset
                long offset = 0;

                //Calculate IP bytes and start threads
                //Format: 255.255.255.255 => b1.b2.b3.b4
                foreach (int b1 in Enumerable.Range(0, wildcardMask[0] + 1))
                {
                    foreach (int b2 in Enumerable.Range(0, wildcardMask[1] + 1))
                    {
                        foreach (int b3 in Enumerable.Range(0, wildcardMask[2] + 1))
                        {
                            //Largest IP address in the block
                            int[] topEnd = new int[4];
                            topEnd[0] = b1;
                            topEnd[1] = b2;
                            topEnd[2] = b3;
                            topEnd[3] = wildcardMask[3];

                            //Set new block
                            IPBlock ipBlock = new IPBlock(topEnd, lowEnd, IPs, offset);

                            //queue thread
                            Thread thread = new Thread(ipBlock.Gen);
                            thread.Start();
                            threads.Add(thread);

                            //Increment offset
                            offset += wildcardMask[3];
                        }
                    }
                }

                WriteObject(IPs);

                while (threads.Any((t) => t.IsAlive)) Thread.Sleep(10);
            }

            //Single thread
            else
            {
                foreach (int b1 in Enumerable.Range(0, wildcardMask[0] + 1))
                {
                    foreach (int b2 in Enumerable.Range(0, wildcardMask[1] + 1))
                    {
                        foreach (int b3 in Enumerable.Range(0, wildcardMask[2] + 1))
                        {
                            foreach (int b4 in Enumerable.Range(1, wildcardMask[3]))
                            {
                                WriteObject((lowEnd[0] + b1) + "." + (lowEnd[1] + b2) + "." + (lowEnd[2] + b3) + "." + (lowEnd[3] + b4));
                            }
                        }
                    }
                }
            }

            //Calculate timespan of execution and write to console
            if (time)
            {
                TimeSpan timespan = DateTime.Now - timestamp;

                Console.WriteLine(ipCount + " IP addresses generated in " + String.Format("{0:0.00}", timespan.TotalSeconds) + " seconds");
            }
        }

        protected override void EndProcessing()
        {
            //Trigger garbage collection
            GC.Collect();
        }
    }

    [Cmdlet(VerbsData.Convert, "Subnet")]
    public class ConvertSubnet : Cmdlet
    {
        [Parameter(Position = 0, Mandatory = true)]
        public string Input;

        protected override void ProcessRecord()
        {
            try 
            {
                if (IPRegex.SubnetMask.IsMatch(Input))
                {
                    byte[] bytes = Array.ConvertAll(Input.Split('.'), new Converter<string, byte>(byte.Parse));

                    if (BitConverter.IsLittleEndian) Array.Reverse(bytes);

                    uint subnetValue = BitConverter.ToUInt32(bytes, 0);
                    int prefixLength = 0;

                    while (subnetValue > 0)
                    {
                        subnetValue <<= 1;
                        prefixLength++;
                    }

                    WriteObject(prefixLength);
                }

                else if (IPRegex.PrefixLength.IsMatch(Input))
                {
                    byte[] SubnetBytes = BitConverter.GetBytes(UInt32.MaxValue << (32 - int.Parse(Input)));

                    if (BitConverter.IsLittleEndian) Array.Reverse(SubnetBytes);

                    string[] subnetMask = Array.ConvertAll(SubnetBytes, new Converter<byte, string>(b => b.ToString()));

                    WriteObject(String.Join(".", subnetMask));
                }
                else throw new FormatException("Invalid Input. Input must be either a valid subnet mask (ex. 255.255.255.0) or a prefix length between 0-32.");
            }

            catch(FormatException ex)
            {
                ErrorRecord err = new ErrorRecord(
                    ex,
                    "1",
                    ErrorCategory.InvalidArgument,
                    Input
                );

                ThrowTerminatingError(err);
            }
        }
    }
}
