using System;
using System.Threading;
using System.Linq;
using System.Management.Automation;

namespace IPUtils
{
    //Instance class for generating a /24 block of IP addresses
    //Used for multithreading in the NewIPRange class
    public class IP24Block
    {
        //Array of length 4, represents the block's largest possible IP address.
        public int[] TopEnd
        {
            get { return topEnd; }
            set { topEnd = value; }
        }
        private int[] topEnd;

        //Array of length for
        public int[] LowEnd
        {
            get { return lowEnd; }
            set { lowEnd = value; }
        }
        private int[] lowEnd;

        public string[] IPs;

        public IP24Block(int[] topE, int[] lowE)
        {
            topEnd = topE;
            lowEnd = lowE;
            IPs = new string[topEnd[4]];
        }

        public void Gen()
        {
            foreach (int b4 in Enumerable.Range(1, topEnd[3]))
            {
                IPs[b4 - 1] = (lowEnd[0] + topEnd[0]) + "." + (lowEnd[1] + topEnd[1]) + "." + (lowEnd[2] + topEnd[2]) + "." + (lowEnd[3] + b4);
            }
        }
    }

    public static class Regex
    {
        public const string Byte = "(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)";
        public const string IPAddress = Byte + "\\." + Byte + "\\." + Byte + "\\." + Byte;
        public const string PrefixLength = "(3[0-2]|2[0-9]|1[0-9]|[1-9])";
        public const string CIDR = IPAddress + "/" + PrefixLength;
        public const string subnetByte = "(255|254|252|248|240|224|192|128|0+)";
        public const string SubnetMask = "(255\\.255\\.255\\." + subnetByte + ")|(255\\.255\\." + subnetByte + "\\.0)|(255\\." + subnetByte + "\\.0\\.0)|(" + subnetByte + "\\.0\\.0\\.0)";
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
        [ValidatePattern(Regex.CIDR)]
        public string CIDR
        {
            get { return cidr; }
            set { cidr = value; }
        }
        private string cidr = "0.0.0.0/0";

        [Parameter(Position = 1)]
        public SwitchParameter Threading
        {
            get { return threading; }
            set { threading = value; }
        }
        private bool threading;


        public Tuple<IP24Block, Thread>[] IPBlocks
        {
            get { return ipBlocks; }
            set { ipBlocks = value; }
        }
        private Tuple<IP24Block, Thread>[] ipBlocks;


        //Main
        protected override void ProcessRecord()
        {
            //Smallest possible IP address
            int[] lowEnd = Array.ConvertAll(cidr.Split('/')[0].Split('.'), new Converter<string, int>(int.Parse));

            //Prefix length
            int prefixLength = int.Parse(cidr.Split('/')[1]);

            //Generate subnet mask
            byte[] subnetMask = System.BitConverter.GetBytes(UInt32.MaxValue << (32 - prefixLength));

            if (System.BitConverter.IsLittleEndian)
            {
                Array.Reverse(subnetMask);
            }

            //Generate index mask
            int[] indexMask = Array.ConvertAll(subnetMask, new Converter<byte, int>(b => ~b & byte.MaxValue));

            //Check IP for invalid values, throw exception if invalid
            for (int i = 0; i < 4; i++)
            {
                if ((indexMask[i] + lowEnd[i]) > 255)
                {
                    Exception err = new Exception(
                        "\'" + lowEnd[i] + "\'" + " in \'" + cidr +
                        "\' will produce an invalid IP range with the given prefix length. \'" +
                        lowEnd[i] + "\' will produce bytes in excess of the maximum value, 255."
                    );
                    ThrowTerminatingError(new ErrorRecord(err, "Invalid CIDR", ErrorCategory.InvalidArgument, cidr));
                }
            }

            if (threading)
            {

                //Calculate total amount of IP blocks needed
                //(approx. total amount of IPs divided by 255)
                //Always 1 block if total amount of IPs is less than 255
                int blockCount = 1;
                blockCount *= indexMask[0] != 0 ? indexMask[0] + 1 : 1;
                blockCount *= indexMask[1] != 0 ? indexMask[1] + 1 : 1;
                blockCount *= indexMask[2] != 0 ? indexMask[2] + 1 : 1;

                //Init block array
                IPBlocks = new Tuple<IP24Block, Thread>[blockCount];

                //Generate threads
                int i = 0;
                foreach (int b1 in Enumerable.Range(0, indexMask[0] + 1))
                {
                    foreach (int b2 in Enumerable.Range(0, indexMask[1] + 1))
                    {
                        foreach (int b3 in Enumerable.Range(0, indexMask[2] + 1))
                        {
                            //Set block info
                            int[] topEnd = new int[3];
                            topEnd[0] = b1;
                            topEnd[1] = b2;
                            topEnd[2] = b3;
                            topEnd[3] = indexMask[3];

                            IP24Block ipBlock = new IP24Block(topEnd, lowEnd);
                            
                            //Pass block method to thread
                            Thread threadCaller = new Thread(new ThreadStart(ipBlock.Gen));

                            //Start thread
                            threadCaller.Start();

                            //Assign block and thread to block array
                            IPBlocks[i] = new Tuple<IP24Block, Thread>(ipBlock, threadCaller);

                            i++;
                        }
                    }
                }

                //Wait for threads and write the received data
                foreach (Tuple<IP24Block, Thread> block in IPBlocks)
                {
                    block.Item2.Join();

                    foreach (string ip in block.Item1.IPs)
                    {
                        WriteObject(ip);
                    }
                }
            } 
            else 
            {
                //Generate IPs
                foreach (int b1 in Enumerable.Range(0, indexMask[0] + 1))
                {
                    foreach (int b2 in Enumerable.Range(0, indexMask[1] + 1))
                    {
                        foreach (int b3 in Enumerable.Range(0, indexMask[2] + 1))
                        {
                            foreach (int b4 in Enumerable.Range(1, indexMask[3]))
                            {
                                WriteObject((lowEnd[0] + b1) + "." + (lowEnd[1] + b2) + "." + (lowEnd[2] + b3) + "." + (lowEnd[3] + b4));
                            }
                        }
                    }
                }
            }
        }
    }

    [Cmdlet(VerbsData.Convert, "SubnetMask")]
    public class ConvertSubnetMask : Cmdlet
    {
        [Parameter(Position = 0, Mandatory = true)]
        [ValidatePattern(Regex.SubnetMask)]
        public string SubnetMask
        {
            get { return subnetMask; }
            set { subnetMask = value; }
        }
        private string subnetMask = "0.0.0.0";

        protected override void ProcessRecord()
        {
            byte[] bytes = Array.ConvertAll(subnetMask.Split('.'), new Converter<string, byte>(byte.Parse));

            if (System.BitConverter.IsLittleEndian)
            {
                Array.Reverse(bytes);
            }

            uint subnetValue = System.BitConverter.ToUInt32(bytes, 0);
            int prefixLength = 0;

            while (subnetValue > 0)
            {
                subnetValue <<= 1;
                prefixLength++;

            }

            WriteObject(prefixLength);
        }
    }

    [Cmdlet(VerbsData.Convert, "PrefixLength")]
    public class ConvertPrefixLength : Cmdlet
    {

        [Parameter(Position = 0, Mandatory = true)]
        [ValidatePattern(Regex.PrefixLength)]
        public string PrefixLength
        {
            get { return prefixLength; }
            set { prefixLength = value; }
        }
        private string prefixLength = "0";

        protected override void ProcessRecord()
        {
            byte[] subnetBytes = System.BitConverter.GetBytes(UInt32.MaxValue << (32 - int.Parse(prefixLength)));

            if (System.BitConverter.IsLittleEndian)
            {
                Array.Reverse(subnetBytes);
            }

            string[] subnetMask = Array.ConvertAll(subnetBytes, new Converter<byte, string>(b => b.ToString()));

            WriteObject(String.Join(".", subnetMask));
        }
    }
}
