using System;
using System.Linq;
using System.Management.Automation;

namespace IPUtils
{

    [Cmdlet(VerbsCommon.New, "IPRange")]
    public class NewIPRange : Cmdlet
    {
        //Standard CIDR string
        [Parameter(
            Position = 0,
            ValueFromPipeline = true,
            Mandatory = true
        )]
        [ValidatePattern("^(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/(3[0-2]|2[0-9]|1[0-9]|[1-9])$")]
        public string CIDR
        {
            get { return cidr; }
            set { cidr = value; }
        }
        private string cidr = "0.0.0.0/0";

        //Main
        protected override void ProcessRecord()
        {
            //Smallest possible IP address
            string[] lowEndStr = cidr.Split('/')[0].Split('.');
            int[] lowEnd = Array.ConvertAll(lowEndStr, new Converter<string, int>(int.Parse));
            
            //Prefix length
            int prefixLength = int.Parse(cidr.Split('/')[1]);

            //Generate subnet mask
            byte[] subnetMask;

            if (System.BitConverter.IsLittleEndian)
            {
                subnetMask = System.BitConverter.GetBytes(UInt32.MaxValue << (32 - prefixLength));
                Array.Reverse(subnetMask);
            }
            else
            {
                subnetMask = System.BitConverter.GetBytes(UInt32.MaxValue >> (32 - prefixLength));
            }

            //Generate index mask
            int[] indexMask = Array.ConvertAll(subnetMask, new Converter<byte, int>(b => ~b & byte.MaxValue));

            //Check IP for invalid values, throw exception if invalid
            for(int i = 0; i < 4; i++)
            {
                if ((indexMask[i] + lowEnd[i]) > 255)
                {
                    Exception err = new Exception(
                        "\'" + lowEnd[i] + "\'" + " in \'" + cidr + 
                        "\' will produce an invalid IP range with the given prefix length. \'" + 
                        lowEnd[i] +
                        "\' will produce bytes in excess of the maximum value, 255."
                    );
                    ThrowTerminatingError(new ErrorRecord(err, "Invalid IP", ErrorCategory.InvalidArgument, cidr));
                }
            }

            //Generate IPs
            foreach (int b1 in Enumerable.Range(0, indexMask[0] + 1) )
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