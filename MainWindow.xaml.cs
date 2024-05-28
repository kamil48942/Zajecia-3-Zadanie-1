using System;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Windows;

namespace EncryptionApp
{
    public partial class MainWindow : Window
    {
        private SymmetricAlgorithm? _algorithm = null;
        private byte[]? _key = null;
        private byte[]? _iv = null;
        private Stopwatch _stopwatch = new Stopwatch(); 

        public MainWindow()
        {
            InitializeComponent();
        }

        private void GenerateKeysButton_Click(object sender, RoutedEventArgs e)
        {
            switch (AlgorithmComboBox.Text)
            {
                case "AES":
                    _algorithm = Aes.Create();
                    break;
                case "DES":
                    _algorithm = DES.Create();
                    break;
                default:
                    MessageBox.Show("Please select an encryption algorithm.");
                    return;
            }

            if (_algorithm != null)
            {
                _algorithm.GenerateKey();
                _algorithm.GenerateIV();

                _key = _algorithm.Key;
                _iv = _algorithm.IV;

                KeyText.Text = BitConverter.ToString(_key).Replace("-", "");
                IVText.Text = BitConverter.ToString(_iv).Replace("-", "");
            }
        }

        private void EncryptButton_Click(object sender, RoutedEventArgs e)
        {
            if (_algorithm == null || _key == null || _iv == null)
            {
                MessageBox.Show("Please generate keys first.");
                return;
            }

            string plainText = PlainTextBox.Text;
            byte[] plainBytes = Encoding.ASCII.GetBytes(plainText);

            _stopwatch.Stop();
            _stopwatch.Reset();
            _stopwatch.Start();

            byte[] cipherBytes = Encrypt(plainBytes);

            _stopwatch.Stop();
            EncryptionTimeLabel.Text = $"Encryption Time: {_stopwatch.ElapsedMilliseconds} ms";

            CipherTextAscii.Text = Convert.ToBase64String(cipherBytes);
            CipherTextHex.Text = BitConverter.ToString(cipherBytes).Replace("-", "");
        }

        private void DecryptButton_Click(object sender, RoutedEventArgs e)
        {
            if (_algorithm == null || _key == null || _iv == null)
            {
                MessageBox.Show("Please generate keys first.");
                return;
            }

            string cipherTextAscii = CipherTextAscii.Text;
            byte[] cipherBytes;
            try
            {
                cipherBytes = Convert.FromBase64String(cipherTextAscii);
            }
            catch (FormatException)
            {
                MessageBox.Show("Invalid cipher text format.");
                return;
            }

            _stopwatch.Stop();
            _stopwatch.Reset();
            _stopwatch.Start();

            byte[] plainBytes;
            try
            {
                plainBytes = Decrypt(cipherBytes);
            }
            catch (CryptographicException)
            {
                MessageBox.Show("Decryption failed. Check the key and IV.");
                return;
            }

            _stopwatch.Stop();
            DecryptionTimeLabel.Text = $"Decryption Time: {_stopwatch.ElapsedMilliseconds} ms";

            PlainTextBox.Text = Encoding.ASCII.GetString(plainBytes);
        }

        private byte[] Encrypt(byte[] plainBytes)
        {
            using (ICryptoTransform encryptor = _algorithm!.CreateEncryptor(_key!, _iv!))
            {
                return PerformCryptography(plainBytes, encryptor);
            }
        }

        private byte[] Decrypt(byte[] cipherBytes)
        {
            using (ICryptoTransform decryptor = _algorithm!.CreateDecryptor(_key!, _iv!))
            {
                return PerformCryptography(cipherBytes, decryptor);
            }
        }

        private byte[] PerformCryptography(byte[] data, ICryptoTransform cryptoTransform)
        {
            using (var memoryStream = new System.IO.MemoryStream())
            {
                using (var cryptoStream = new CryptoStream(memoryStream, cryptoTransform, CryptoStreamMode.Write))
                {
                    cryptoStream.Write(data, 0, data.Length);
                    cryptoStream.FlushFinalBlock();
                }
                return memoryStream.ToArray();
            }
        }
    }
}
