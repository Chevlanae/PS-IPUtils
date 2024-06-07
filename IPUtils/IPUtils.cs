using System;
using System.Threading;
using System.Linq;
using System.Management.Automation;

namespace IPUtils
{
    //Instance class for generating a block of IP addresses
    //Used for multithreading in NewIPRange
    public class IPBlock
    {
        //Array of length 4, represents the block's largest possible IP address.
        public int[] TopEnd;

        //Array of length 4, represents the block's smallest possible IP address.
        public int[] LowEnd;

        public string[] IPs;

        public virtual void Gen() { }
    }

    public class IPBlock24 : IPBlock
    {
        public IPBlock24(int[] topE, int[] lowE)
        {
            TopEnd = topE;
            LowEnd = lowE;
            IPs = new string[topE[3] + 1];
        }

        public override void Gen()
        {
            foreach (int b4 in Enumerable.Range(0, TopEnd[3] + 1))
            {
                IPs[b4] = (LowEnd[0] + TopEnd[0]) + "." + (LowEnd[1] + TopEnd[1]) + "." + (LowEnd[2] + TopEnd[2]) + "." + (LowEnd[3] + b4);
            }
        }
    }

    public class IPBlock16 : IPBlock 
    {
        public IPBlock16(int[] topE, int[] lowE)
        {
            TopEnd = topE;
            LowEnd = lowE;
            IPs = new string[topE[2] * 255];
        }

        public override void Gen()
        {
            foreach (int b3 in Enumerable.Range(0, TopEnd[2] + 1))
            {
                int[] bytes = new int[4];
                bytes[0] = TopEnd[0];
                bytes[1] = TopEnd[1];
                bytes[2] = b3;
                bytes[3] = 255;

                IPBlock24 block24 = new IPBlock24(bytes, LowEnd);

                block24.Gen();

                int i = 0;
                foreach (string ip in block24.IPs)
                {
                    IPs[i + (b3 * 255)] = ip;
                    i++;
                }
            }
        }
    }
    public class IPBlock8 : IPBlock { }
    public class IPBlock2 : IPBlock { }

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


        public Tuple<IPBlock24, Thread>[] IPBlocks
        {
            get { return ipBlocks; }
            set { ipBlocks = value; }
        }
        private Tuple<IPBlock24, Thread>[] ipBlocks;


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
                //(total amount of IPs divided by 255)
                //Always 1 block if total amount of IPs is less than 255
                int blockCount = 1;
                blockCount *= indexMask[0] + 1;
                blockCount *= indexMask[1] + 1;
                blockCount *= indexMask[2] + 1;

                //Init block array
                IPBlocks = new Tuple<IPBlock24, Thread>[blockCount];

                //Generate threads
                int i = 0;
                foreach (int b1 in Enumerable.Range(0, indexMask[0] + 1))
                {
                    foreach (int b2 in Enumerable.Range(0, indexMask[1] + 1))
                    {
                        foreach (int b3 in Enumerable.Range(0, indexMask[2] + 1))
                        {
                            int[] bytes = new int[4];
                            bytes[0] = b1;
                            bytes[1] = b2;
                            bytes[2] = b3;
                            bytes[3] = indexMask[3];

                            //Set block info
                            IPBlock24 ipBlock = new IPBlock24(bytes, lowEnd);
                            
                            //Pass block method to thread
                            Thread threadCaller = new Thread(new ThreadStart(ipBlock.Gen));

                            //Start thread
                            threadCaller.Start();

                            //Assign block and thread to block array
                            IPBlocks[i] = new Tuple<IPBlock24, Thread>(ipBlock, threadCaller);

                            i++;
                        }
                    }
                }

                //Wait for threads and write the received data
                foreach (Tuple<IPBlock24, Thread> block in IPBlocks)
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
                            foreach (int b4 in Enumerable.Range(0, indexMask[3] + 1))
                            {
                                WriteObject((lowEnd[0] + b1) + "." + (lowEnd[1] + b2) + "." + (lowEnd[2] + b3) + "." + (lowEnd[3] + b4));
                            }
                        }
                    }
                }
            }
        }

        protected override void EndProcessing()
        {
            System.GC.Collect();
        }
    }

    [Cmdlet(VerbsCommon.Get, "Prefix")]
    public class GetPrefix : Cmdlet
    {
        [Parameter()]
        [ValidatePattern(Regex.SubnetMask)]
        public string SubnetMask
        {
            get { return subnetMask; }
            set { subnetMask = value; }
        }
        private string subnetMask = "0.0.0.0";

        [Parameter()]
        [ValidatePattern(Regex.PrefixLength)]
        public string PrefixLength
        {
            get { return prefixLength; }
            set { prefixLength = value; }
        }
        private string prefixLength = "0";

        protected override void ProcessRecord()
        {

            if(SubnetMask != "0.0.0.0")
            {
                byte[] bytes = Array.ConvertAll(SubnetMask.Split('.'), new Converter<string, byte>(byte.Parse));

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

            else if (PrefixLength != "0")
            {
                byte[] subnetBytes = System.BitConverter.GetBytes(UInt32.MaxValue << (32 - int.Parse(PrefixLength)));

                if (System.BitConverter.IsLittleEndian) Array.Reverse(subnetBytes);

                string[] subnetMask = Array.ConvertAll(subnetBytes, new Converter<byte, string>(b => b.ToString()));

                WriteObject(String.Join(".", subnetMask));
            }

            else
            {
                ErrorRecord err = new ErrorRecord(
                    new Exception("Please use either the -SubnetMask or -PrefixLength parameters"), 
                    "Invalid Argument", 
                    ErrorCategory.InvalidArgument, 
                    subnetMask
                );

                ThrowTerminatingError(err);
            }
        }
    }
}
