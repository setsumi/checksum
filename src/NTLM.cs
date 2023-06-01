using System;
using System.Diagnostics.Contracts;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace System.Security.Cryptography
{
    [System.Runtime.InteropServices.ComVisible(true)]
    public abstract class MD4 : HashAlgorithm
    {
        static MD4()
        {
            CryptoConfig.AddAlgorithm(typeof(MD4CryptoServiceProvider), "System.Security.Cryptography.MD4");
        }

        protected MD4()
        {
            HashSizeValue = 128;
        }

        new static public MD4 Create()
        {
            return Create("System.Security.Cryptography.MD4");
        }

        new static public MD4 Create(string algName)
        {
            return (MD4)CryptoConfig.CreateFromName(algName);
        }
    }

    [System.Runtime.InteropServices.ComVisible(true)]
    public sealed class MD4CryptoServiceProvider : MD4
    {
        internal static class Utils
        {
            internal static Type UtilsType = Type.GetType("System.Security.Cryptography.Utils");

            public static T InvokeInternalMethodOfType<T>(object o, object pType, string methodName, params object[] args)
            {
                var internalType = (pType is string internalTypeName) ? Type.GetType(internalTypeName) : (Type)pType;
                var internalMethods = internalType.GetMethods(BindingFlags.NonPublic | BindingFlags.FlattenHierarchy | (o == null ? BindingFlags.Static : 0));
                var internalMethod = internalMethods.Where(m => m.Name == methodName && m.GetParameters().Length == args.Length).Single();
                return (T)internalMethod?.Invoke(o, args);
            }

            public static T GetInternalPropertyValueOfInternalType<T>(object o, object pType, string propertyName)
            {
                var internalType = (pType is string internalTypeName) ? Type.GetType(internalTypeName) : (Type)pType;
                var internalProperty = internalType.GetProperty(propertyName, BindingFlags.NonPublic | (o == null ? BindingFlags.Static : 0));
                return (T)internalProperty.GetValue(o);
            }

            internal static SafeHandle CreateHash(int algid)
            {
                return InvokeInternalMethodOfType<SafeHandle>(null, UtilsType, "CreateHash", GetInternalPropertyValueOfInternalType<object>(null, UtilsType, "StaticProvHandle"), algid);
            }

            internal static void HashData(SafeHandle h, byte[] data, int ibStart, int cbSize)
            {
                InvokeInternalMethodOfType<object>(null, UtilsType, "HashData", h, data, ibStart, cbSize);
            }

            internal static byte[] EndHash(SafeHandle h)
            {
                return InvokeInternalMethodOfType<byte[]>(null, UtilsType, "EndHash", h);
            }
        }

        internal const int ALG_CLASS_HASH = (4 << 13);
        internal const int ALG_TYPE_ANY = (0);
        internal const int ALG_SID_MD4 = 2;
        internal const int CALG_MD4 = (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_MD4);

        [System.Security.SecurityCritical]
        private SafeHandle _safeHashHandle = null;

        [System.Security.SecuritySafeCritical]
        public MD4CryptoServiceProvider()
        {
            if (CryptoConfig.AllowOnlyFipsAlgorithms)
                throw new InvalidOperationException("Cryptography_NonCompliantFIPSAlgorithm");
            Contract.EndContractBlock();
            // cheat with Reflection
            _safeHashHandle = Utils.CreateHash(CALG_MD4);
        }

        protected override void Dispose(bool disposing)
        {
            if (_safeHashHandle != null && !_safeHashHandle.IsClosed)
                _safeHashHandle.Dispose();
            base.Dispose(disposing);
        }

        public override void Initialize()
        {
            if (_safeHashHandle != null && !_safeHashHandle.IsClosed)
                _safeHashHandle.Dispose();

            _safeHashHandle = Utils.CreateHash(CALG_MD4);
        }

        protected override void HashCore(byte[] rgb, int ibStart, int cbSize)
        {
            Utils.HashData(_safeHashHandle, rgb, ibStart, cbSize);
        }

        protected override byte[] HashFinal()
        {
            return Utils.EndHash(_safeHashHandle);
        }
    }
}

static class Ext
{
    public static HashAlgorithm MD4Singleton;

    static Ext()
    {
        MD4Singleton = System.Security.Cryptography.MD4.Create();
    }

    public static byte[] MD4(this string s)
    {
        return MD4Singleton.ComputeHash(System.Text.Encoding.Unicode.GetBytes(s));
    }

    public static string AsHexString(this byte[] bytes)
    {
        return String.Join("", bytes.Select(h => h.ToString("X2")));
    }
}

static class NTLM
{
    /*
    source:
      https://www.codeproject.com/Articles/328761/NTLM-Hash-Generator
    */
    public static string Ntlm(string key)
    {
        const uint INIT_A = 0x67452301;
        const uint INIT_B = 0xefcdab89;
        const uint INIT_C = 0x98badcfe;
        const uint INIT_D = 0x10325476;

        const uint SQRT_2 = 0x5a827999;
        const uint SQRT_3 = 0x6ed9eba1;

        char[] itoa16 = new[] { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

        uint[] nt_buffer = new uint[16];
        uint[] output = new uint[4];
        char[] hex_format = new char[32];

        //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        // Prepare the string for hash calculation
        //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        int i = 0;
        int length = key.Length;
        //The length of key need to be <= 27
        for (; i < length / 2; i++)
        {
            nt_buffer[i] = (key[2 * i] | ((uint)key[2 * i + 1] << 16));
        }

        //padding
        if (length % 2 == 1)
        {
            nt_buffer[i] = (uint)key[length - 1] | 0x800000;
        }
        else
        {
            nt_buffer[i] = 0x80;
        }

        //put the length
        nt_buffer[14] = (uint)length << 4;

        //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        // NTLM hash calculation
        //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        uint a = INIT_A;
        uint b = INIT_B;
        uint c = INIT_C;
        uint d = INIT_D;

        /* Round 1 */
        a += (d ^ (b & (c ^ d))) + nt_buffer[0]; a = (a << 3) | (a >> 29);
        d += (c ^ (a & (b ^ c))) + nt_buffer[1]; d = (d << 7) | (d >> 25);
        c += (b ^ (d & (a ^ b))) + nt_buffer[2]; c = (c << 11) | (c >> 21);
        b += (a ^ (c & (d ^ a))) + nt_buffer[3]; b = (b << 19) | (b >> 13);

        a += (d ^ (b & (c ^ d))) + nt_buffer[4]; a = (a << 3) | (a >> 29);
        d += (c ^ (a & (b ^ c))) + nt_buffer[5]; d = (d << 7) | (d >> 25);
        c += (b ^ (d & (a ^ b))) + nt_buffer[6]; c = (c << 11) | (c >> 21);
        b += (a ^ (c & (d ^ a))) + nt_buffer[7]; b = (b << 19) | (b >> 13);

        a += (d ^ (b & (c ^ d))) + nt_buffer[8]; a = (a << 3) | (a >> 29);
        d += (c ^ (a & (b ^ c))) + nt_buffer[9]; d = (d << 7) | (d >> 25);
        c += (b ^ (d & (a ^ b))) + nt_buffer[10]; c = (c << 11) | (c >> 21);
        b += (a ^ (c & (d ^ a))) + nt_buffer[11]; b = (b << 19) | (b >> 13);

        a += (d ^ (b & (c ^ d))) + nt_buffer[12]; a = (a << 3) | (a >> 29);
        d += (c ^ (a & (b ^ c))) + nt_buffer[13]; d = (d << 7) | (d >> 25);
        c += (b ^ (d & (a ^ b))) + nt_buffer[14]; c = (c << 11) | (c >> 21);
        b += (a ^ (c & (d ^ a))) + nt_buffer[15]; b = (b << 19) | (b >> 13);

        /* Round 2 */
        a += ((b & (c | d)) | (c & d)) + nt_buffer[0] + SQRT_2; a = (a << 3) | (a >> 29);
        d += ((a & (b | c)) | (b & c)) + nt_buffer[4] + SQRT_2; d = (d << 5) | (d >> 27);
        c += ((d & (a | b)) | (a & b)) + nt_buffer[8] + SQRT_2; c = (c << 9) | (c >> 23);
        b += ((c & (d | a)) | (d & a)) + nt_buffer[12] + SQRT_2; b = (b << 13) | (b >> 19);

        a += ((b & (c | d)) | (c & d)) + nt_buffer[1] + SQRT_2; a = (a << 3) | (a >> 29);
        d += ((a & (b | c)) | (b & c)) + nt_buffer[5] + SQRT_2; d = (d << 5) | (d >> 27);
        c += ((d & (a | b)) | (a & b)) + nt_buffer[9] + SQRT_2; c = (c << 9) | (c >> 23);
        b += ((c & (d | a)) | (d & a)) + nt_buffer[13] + SQRT_2; b = (b << 13) | (b >> 19);

        a += ((b & (c | d)) | (c & d)) + nt_buffer[2] + SQRT_2; a = (a << 3) | (a >> 29);
        d += ((a & (b | c)) | (b & c)) + nt_buffer[6] + SQRT_2; d = (d << 5) | (d >> 27);
        c += ((d & (a | b)) | (a & b)) + nt_buffer[10] + SQRT_2; c = (c << 9) | (c >> 23);
        b += ((c & (d | a)) | (d & a)) + nt_buffer[14] + SQRT_2; b = (b << 13) | (b >> 19);

        a += ((b & (c | d)) | (c & d)) + nt_buffer[3] + SQRT_2; a = (a << 3) | (a >> 29);
        d += ((a & (b | c)) | (b & c)) + nt_buffer[7] + SQRT_2; d = (d << 5) | (d >> 27);
        c += ((d & (a | b)) | (a & b)) + nt_buffer[11] + SQRT_2; c = (c << 9) | (c >> 23);
        b += ((c & (d | a)) | (d & a)) + nt_buffer[15] + SQRT_2; b = (b << 13) | (b >> 19);

        /* Round 3 */
        a += (d ^ c ^ b) + nt_buffer[0] + SQRT_3; a = (a << 3) | (a >> 29);
        d += (c ^ b ^ a) + nt_buffer[8] + SQRT_3; d = (d << 9) | (d >> 23);
        c += (b ^ a ^ d) + nt_buffer[4] + SQRT_3; c = (c << 11) | (c >> 21);
        b += (a ^ d ^ c) + nt_buffer[12] + SQRT_3; b = (b << 15) | (b >> 17);

        a += (d ^ c ^ b) + nt_buffer[2] + SQRT_3; a = (a << 3) | (a >> 29);
        d += (c ^ b ^ a) + nt_buffer[10] + SQRT_3; d = (d << 9) | (d >> 23);
        c += (b ^ a ^ d) + nt_buffer[6] + SQRT_3; c = (c << 11) | (c >> 21);
        b += (a ^ d ^ c) + nt_buffer[14] + SQRT_3; b = (b << 15) | (b >> 17);

        a += (d ^ c ^ b) + nt_buffer[1] + SQRT_3; a = (a << 3) | (a >> 29);
        d += (c ^ b ^ a) + nt_buffer[9] + SQRT_3; d = (d << 9) | (d >> 23);
        c += (b ^ a ^ d) + nt_buffer[5] + SQRT_3; c = (c << 11) | (c >> 21);
        b += (a ^ d ^ c) + nt_buffer[13] + SQRT_3; b = (b << 15) | (b >> 17);

        a += (d ^ c ^ b) + nt_buffer[3] + SQRT_3; a = (a << 3) | (a >> 29);
        d += (c ^ b ^ a) + nt_buffer[11] + SQRT_3; d = (d << 9) | (d >> 23);
        c += (b ^ a ^ d) + nt_buffer[7] + SQRT_3; c = (c << 11) | (c >> 21);
        b += (a ^ d ^ c) + nt_buffer[15] + SQRT_3; b = (b << 15) | (b >> 17);

        output[0] = a + INIT_A;
        output[1] = b + INIT_B;
        output[2] = c + INIT_C;
        output[3] = d + INIT_D;

        //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        // Convert the hash to hex (for being readable)
        //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        for (i = 0; i < 4; i++)
        {
            int j = 0;
            uint n = output[i];
            //iterate the bytes of the integer
            for (; j < 4; j++)
            {
                uint convert = n % 256;
                hex_format[i * 8 + j * 2 + 1] = itoa16[convert % 16];
                convert = convert / 16;
                hex_format[i * 8 + j * 2 + 0] = itoa16[convert % 16];
                n = n / 256;
            }
        }

        return string.Join(string.Empty, hex_format);
    }
}
