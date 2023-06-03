using System;
using System.Text;
using System.Windows.Forms;

namespace checksum
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();

            tbInput.MaxLength = int.MaxValue;
        }

        private void tbInput_TextChanged(object sender, EventArgs e)
        {
            Info();
            Calc();
        }

        private void Info()
        {
            string str = tbInput.Text;
            string invis = "";
            bool loop = true;
            foreach (char ch in str)
            {
                var cat = char.GetUnicodeCategory(ch);
                switch (cat)
                {
                    case System.Globalization.UnicodeCategory.Control:
                    case System.Globalization.UnicodeCategory.Format:
                    case System.Globalization.UnicodeCategory.LineSeparator:
                    case System.Globalization.UnicodeCategory.NonSpacingMark:
                    case System.Globalization.UnicodeCategory.ParagraphSeparator:
                    case System.Globalization.UnicodeCategory.SpaceSeparator:
                    case System.Globalization.UnicodeCategory.SpacingCombiningMark:
                        invis = "   Warning: invisible characters";
                        loop = false;
                        break;
                }
                if (!loop) break;
            }
            label1.ForeColor = string.IsNullOrEmpty(invis) ? System.Drawing.SystemColors.ControlText : System.Drawing.Color.Red;
            label1.Text = $"chars: {str.Length}{invis}";
        }

        private void Calc()
        {
            var text_input = tbInput.Text;
            var bytes_input = Encoding.UTF8.GetBytes(text_input);

            string string_crc32;
            string string_md5;
            string string_sha1;
            string string_sha256;
            string string_sha384;
            string string_sha512;
            string string_ntlm;

            if (bytes_input.Length > 0)
            {
                var crc32 = new DamienG.Security.Cryptography.Crc32();
                var md5 = System.Security.Cryptography.MD5.Create();
                var sha1 = System.Security.Cryptography.SHA1.Create();
                var sha256 = System.Security.Cryptography.SHA256.Create();
                var sha384 = System.Security.Cryptography.SHA384.Create();
                var sha512 = System.Security.Cryptography.SHA512.Create();

                var bytes_crc32 = crc32.ComputeHash(bytes_input);
                var bytes_md5 = md5.ComputeHash(bytes_input);
                var bytes_sha1 = sha1.ComputeHash(bytes_input);
                var bytes_sha256 = sha256.ComputeHash(bytes_input);
                var bytes_sha384 = sha384.ComputeHash(bytes_input);
                var bytes_sha512 = sha512.ComputeHash(bytes_input);
                var bytes_ntlm = text_input.MD4(); // UTF-16 LE always

                string_crc32 = BitConverter.ToString(bytes_crc32).Replace("-", "").ToLowerInvariant();
                string_md5 = BitConverter.ToString(bytes_md5).Replace("-", "").ToLowerInvariant();
                string_sha1 = BitConverter.ToString(bytes_sha1).Replace("-", "").ToLowerInvariant();
                string_sha256 = BitConverter.ToString(bytes_sha256).Replace("-", "").ToLowerInvariant();
                string_sha384 = BitConverter.ToString(bytes_sha384).Replace("-", "").ToLowerInvariant();
                string_sha512 = BitConverter.ToString(bytes_sha512).Replace("-", "").ToLowerInvariant();
                string_ntlm = BitConverter.ToString(bytes_ntlm).Replace("-", "").ToLowerInvariant();
                //string_ntlm = bytes_ntlm.AsHexString().ToLowerInvariant();
                //string_ntlm = NTLM.Ntlm(text_input);
            }
            else
            {
                string_crc32 = "";
                string_md5 = "";
                string_sha1 = "";
                string_sha256 = "";
                string_sha384 = "";
                string_sha512 = "";
                string_ntlm = "";
            }

            tbOutput.Lines = new string[]
            {
                $" CRC-32: {string_crc32}",
                $"         {string_crc32.ToUpperInvariant()}",
                $"    MD5: {string_md5}",
                $"         {string_md5.ToUpperInvariant()}",
                $"  SHA-1: {string_sha1}",
                $"         {string_sha1.ToUpperInvariant()}",
                $"SHA-256: {string_sha256}",
                $"         {string_sha256.ToUpperInvariant()}",
                $"SHA-384: {string_sha384}",
                $"         {string_sha384.ToUpperInvariant()}",
                $"SHA-512: {string_sha512}",
                $"         {string_sha512.ToUpperInvariant()}",
                $"NTLM",
                $" NT/MD4: {string_ntlm}",
                $"         {string_ntlm.ToUpperInvariant()}",
                ""
            };
        }

        private void Form1_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.KeyCode == Keys.Escape)
            {
                if (DialogResult.Yes == MessageBox.Show("Quit?", "checksum", MessageBoxButtons.YesNoCancel, MessageBoxIcon.None))
                {
                    Close();
                }
            }
            else if (e.KeyCode == Keys.F5)
            {
                tbInput_TextChanged(null, null);
            }
        }

        private void Form1_Load(object sender, EventArgs e)
        {
            tbInput_TextChanged(null, null);
        }
    }
}
