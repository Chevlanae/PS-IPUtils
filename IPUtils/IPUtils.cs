using System;
using System.Threading;
using System.Linq;
using System.Management.Automation;
using System.Text.RegularExpressions;

namespace IPUtils
{
    //Instance class for generating a block of 256 IP addresses
    //Used for multithreading in NewIPRange
    public class IPBlock
    {
        //Array of length 4, represents the block's largest possible IP address.
        public int[] TopEnd;

        //Array of length 4, represents the block's smallest possible IP address.
        public int[] LowEnd;

        public string[] IPs;

        public IPBlock(int[] topE, int[] lowE)
        {
            TopEnd = topE;
            LowEnd = lowE;
            IPs = new string[topE[3] + 1];
        }

        public void Gen()
        {
            foreach (int b4 in Enumerable.Range(0, TopEnd[3] + 1))
            {
                IPs[b4] = (LowEnd[0] + TopEnd[0]) + "." + (LowEnd[1] + TopEnd[1]) + "." + (LowEnd[2] + TopEnd[2]) + "." + (LowEnd[3] + b4);
            }
        }
    }

    public class IPRegex
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

        public Regex Byte;
        public Regex IPAddress;
        public Regex PrefixLength;
        public Regex CIDR;
        public Regex SubnetByte;
        public Regex SubnetMask;

        public IPRegex()
        {
            Byte = new Regex(Patterns.Byte);
            IPAddress = new Regex(Patterns.IPAddress);
            PrefixLength = new Regex(Patterns.PrefixLength);
            CIDR = new Regex(Patterns.CIDR);
            SubnetByte = new Regex(Patterns.SubnetByte);
            SubnetMask = new Regex(Patterns.SubnetMask);
        }
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
            byte[] subnetMask = System.BitConverter.GetBytes(UInt32.MaxValue << (32 - prefixLength));

            //Reverse array if system is little endian (not tested on big endian machines, I don't even know where to find those).
            //https://learn.microsoft.com/en-us/dotnet/api/system.bitconverter.islittleendian?view=netstandard-2.0
            if (System.BitConverter.IsLittleEndian) Array.Reverse(subnetMask);

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

            //Generate IPs on multiple threads
            //Blocks of 256 individual IP addresses will be assigned an individual thread
            //Once a thread is finished with it's block, the IP addresses are written sequentially.
            if (threading)
            {

                //Calculate total amount of IP blocks needed
                //Always 1 block if total amount of IPs is less than 255
                int blockCount = 1;
                blockCount *= wildcardMask[0] + 1;
                blockCount *= wildcardMask[1] + 1;
                blockCount *= wildcardMask[2] + 1;

                //Init block array with the size of blockCount
                Tuple<IPBlock, Thread>[]  IPBlocks = new Tuple<IPBlock, Thread>[blockCount];

                //IPBlocks index
                int i = 0;

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
                            IPBlock ipBlock = new IPBlock(topEnd, lowEnd);
                            
                            //Pass block's generator method to thread
                            Thread threadCaller = new Thread(new ThreadStart(ipBlock.Gen), 0);

                            //Assign block and thread to block array
                            IPBlocks[i] = new Tuple<IPBlock, Thread>(ipBlock, threadCaller);

                            //Increment index
                            i++;
                        }
                    }
                }

                foreach (Tuple<IPBlock, Thread> block in IPBlocks) block.Item2.Start();

                //Wait for threads and write the received data
                foreach (Tuple<IPBlock, Thread> block in IPBlocks)
                {
                    //Wait
                    block.Item2.Join();

                    //Write
                    foreach (string ip in block.Item1.IPs)
                    {
                        WriteObject(ip);
                    }
                }

                //Calculate timespan of execution and write to console
                if(time)
                {
                    TimeSpan timespan = DateTime.Now - timestamp;

                    Console.ForegroundColor = ConsoleColor.Cyan;
                    Console.WriteLine((blockCount * (wildcardMask[3] + 1)) + " IP addresses generated in " + String.Format("{0:0.00}", timespan.TotalSeconds) + " seconds");
                }
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
                            foreach (int b4 in Enumerable.Range(0, wildcardMask[3] + 1))
                            {
                                WriteObject((lowEnd[0] + b1) + "." + (lowEnd[1] + b2) + "." + (lowEnd[2] + b3) + "." + (lowEnd[3] + b4));
                            }
                        }
                    }
                }

                //Calculate timespan of execution and write to console
                if (time)
                {
                    TimeSpan timespan = DateTime.Now - timestamp;

                    Console.ForegroundColor = ConsoleColor.Cyan;
                    Console.WriteLine(
                        (wildcardMask[0] + 1) * (wildcardMask[1] + 1) * (wildcardMask[2] + 1) * (wildcardMask[3] + 1) + 
                        " IP addresses generated in " + String.Format("{0:0.00}", timespan.TotalSeconds) + " seconds"
                    );
                }
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
                IPRegex reg = new IPRegex();
                if (reg.SubnetMask.IsMatch(Input))
                {
                    byte[] bytes = Array.ConvertAll(Input.Split('.'), new Converter<string, byte>(byte.Parse));

                    if (System.BitConverter.IsLittleEndian) Array.Reverse(bytes);

                    uint subnetValue = System.BitConverter.ToUInt32(bytes, 0);
                    int prefixLength = 0;

                    while (subnetValue > 0)
                    {
                        subnetValue <<= 1;
                        prefixLength++;
                    }

                    WriteObject(prefixLength);
                }

                else if (reg.PrefixLength.IsMatch(Input))
                {
                    byte[] SubnetBytes = System.BitConverter.GetBytes(UInt32.MaxValue << (32 - int.Parse(Input)));

                    if (System.BitConverter.IsLittleEndian) Array.Reverse(SubnetBytes);

                    string[] subnetMask = Array.ConvertAll(SubnetBytes, new Converter<byte, string>(b => b.ToString()));

                    WriteObject(String.Join(".", subnetMask));
                }
            }

            catch(FormatException e)

            {
                ErrorRecord err = new ErrorRecord(
                    new Exception("Invalid Input. Input must be either a valid subnet mask or a prefix length between 0-32."),
                    "Invalid Argument",
                    ErrorCategory.InvalidArgument,
                    Input
                );

                ThrowTerminatingError(err);
            }
        }
    }
}
