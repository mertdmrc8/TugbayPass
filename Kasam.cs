using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Web.Script.Serialization;
using System.Windows.Forms;

internal static class Program
{
    [STAThread]
    private static void Main()
    {
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);
        Application.Run(new KasamForm());
    }
}

public sealed class VaultPayload { public List<VaultEntry> entries { get; set; } }
public sealed class KasamSettings { public List<string> recentVaults { get; set; } public List<PinVaultRecord> pinVaults { get; set; } }
public sealed class PinVaultRecord { public string path { get; set; } public string protectedData { get; set; } }
public sealed class QuickUnlockData { public string pinSalt { get; set; } public string vaultSalt { get; set; } public string wrappedKey { get; set; } }
internal sealed class RecentVaultChoice
{
    public string Path { get; private set; }
    public RecentVaultChoice(string path) { Path = path; }
    public override string ToString() { return System.IO.Path.GetFileName(Path) + "   —   " + System.IO.Path.GetDirectoryName(Path); }
}
public sealed class VaultEntry
{
    public string id { get; set; }
    public string system { get; set; }
    public string title { get; set; }
    public string username { get; set; }
    public string password { get; set; }
    public string url { get; set; }
    public string notes { get; set; }
    public override string ToString() { return title + (String.IsNullOrEmpty(username) ? "" : "    ·    " + username); }
}
public sealed class KdfInfo { public string name { get; set; } public string hash { get; set; } public int iterations { get; set; } public string salt { get; set; } }
public sealed class CipherInfo { public string name { get; set; } public string iv { get; set; } public string ciphertext { get; set; } public string mac { get; set; } }
public sealed class VaultEnvelope { public string format { get; set; } public int version { get; set; } public KdfInfo kdf { get; set; } public CipherInfo cipher { get; set; } }

internal static class VaultCrypto
{
    public const int Iterations = 600000;
    private static readonly byte[] Prefix = Encoding.UTF8.GetBytes("kasam-vault|1|PBKDF2-HMAC-SHA-256|");

    public static byte[] RandomBytes(int count)
    {
        byte[] bytes = new byte[count];
        using (RandomNumberGenerator rng = RandomNumberGenerator.Create()) rng.GetBytes(bytes);
        return bytes;
    }

    public static byte[] DeriveKey(string password, byte[] salt, int iterations)
    {
        using (Rfc2898DeriveBytes kdf = new Rfc2898DeriveBytes(password, salt, iterations, HashAlgorithmName.SHA256))
            return kdf.GetBytes(64);
    }

    private static byte[] AuthData(byte[] salt, byte[] iv, byte[] cipher, int iterations)
    {
        byte[] header = Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(Prefix) + iterations.ToString(System.Globalization.CultureInfo.InvariantCulture) + "|AES-256-CBC-HMAC-SHA-256|");
        byte[] all = new byte[header.Length + salt.Length + iv.Length + cipher.Length];
        Buffer.BlockCopy(header, 0, all, 0, header.Length);
        Buffer.BlockCopy(salt, 0, all, header.Length, salt.Length);
        Buffer.BlockCopy(iv, 0, all, header.Length + salt.Length, iv.Length);
        Buffer.BlockCopy(cipher, 0, all, header.Length + salt.Length + iv.Length, cipher.Length);
        return all;
    }

    public static string Encrypt(byte[] key, byte[] salt, byte[] plaintext)
    {
        byte[] iv = RandomBytes(16), aesKey = new byte[32], macKey = new byte[32], ciphertext, mac;
        Buffer.BlockCopy(key, 0, aesKey, 0, 32); Buffer.BlockCopy(key, 32, macKey, 0, 32);
        using (Aes aes = Aes.Create())
        {
            aes.KeySize = 256; aes.BlockSize = 128; aes.Mode = CipherMode.CBC; aes.Padding = PaddingMode.PKCS7; aes.Key = aesKey; aes.IV = iv;
            using (ICryptoTransform enc = aes.CreateEncryptor()) ciphertext = enc.TransformFinalBlock(plaintext, 0, plaintext.Length);
        }
        using (HMACSHA256 hmac = new HMACSHA256(macKey)) mac = hmac.ComputeHash(AuthData(salt, iv, ciphertext, Iterations));
        VaultEnvelope envelope = new VaultEnvelope {
            format = "kasam-vault", version = 1,
            kdf = new KdfInfo { name = "PBKDF2-HMAC-SHA-256", hash = "SHA-256", iterations = Iterations, salt = Convert.ToBase64String(salt) },
            cipher = new CipherInfo { name = "AES-256-CBC-HMAC-SHA-256", iv = Convert.ToBase64String(iv), ciphertext = Convert.ToBase64String(ciphertext), mac = Convert.ToBase64String(mac) }
        };
        JavaScriptSerializer json = new JavaScriptSerializer(); json.MaxJsonLength = 50 * 1024 * 1024;
        Array.Clear(aesKey, 0, aesKey.Length); Array.Clear(macKey, 0, macKey.Length);
        return json.Serialize(envelope);
    }

    public static byte[] Decrypt(byte[] key, byte[] salt, byte[] iv, byte[] ciphertext, byte[] mac, int iterations)
    {
        byte[] aesKey = new byte[32], macKey = new byte[32], expected;
        Buffer.BlockCopy(key, 0, aesKey, 0, 32); Buffer.BlockCopy(key, 32, macKey, 0, 32);
        using (HMACSHA256 hmac = new HMACSHA256(macKey)) expected = hmac.ComputeHash(AuthData(salt, iv, ciphertext, iterations));
        int mismatch = expected.Length ^ mac.Length;
        for (int i = 0; i < Math.Min(expected.Length, mac.Length); i++) mismatch |= expected[i] ^ mac[i];
        Array.Clear(macKey, 0, macKey.Length);
        if (mismatch != 0) { Array.Clear(aesKey, 0, aesKey.Length); throw new CryptographicException("Kasa doğrulanamadı."); }
        using (Aes aes = Aes.Create())
        {
            aes.KeySize = 256; aes.BlockSize = 128; aes.Mode = CipherMode.CBC; aes.Padding = PaddingMode.PKCS7; aes.Key = aesKey; aes.IV = iv;
            using (ICryptoTransform dec = aes.CreateDecryptor())
            {
                byte[] plain = dec.TransformFinalBlock(ciphertext, 0, ciphertext.Length);
                Array.Clear(aesKey, 0, aesKey.Length); return plain;
            }
        }
    }
}

internal sealed class KasamForm : Form
{
    private static readonly Color Green = Color.FromArgb(0, 105, 92);
    private static readonly Color Ink = Color.FromArgb(26, 38, 42);
    private static readonly Color Muted = Color.FromArgb(96, 110, 116);
    private static readonly Color Canvas = Color.FromArgb(245, 247, 248);
    private static readonly Font EntryTitleFont = new Font("Segoe UI", 10, FontStyle.Bold);
    private static readonly Font EntryUserFont = new Font("Segoe UI", 9, FontStyle.Bold);
    private List<VaultEntry> entries = new List<VaultEntry>();
    private byte[] key, salt;
    private string vaultPath;
    private bool dirty, revealed;
    private TextBox searchBox, usernameBox, passwordBox, urlBox, notesBox, systemBox;
    private ComboBox systemFilterBox, recentVaultBox;
    private List<string> recentVaults = new List<string>();
    private List<PinVaultRecord> pinVaults = new List<PinVaultRecord>();
    private ListBox entryList;
    private Label titleLabel, statusLabel, fileLabel, countLabel;
    private Button editButton, deleteButton, revealButton, copyButton;
    private Button copySystemButton, copyUsernameButton, copyUrlButton, copyNotesButton, copyTitleButton;
    private Panel body;

    public KasamForm()
    {
        Text = "Kasam — Şifreli Kasa"; StartPosition = FormStartPosition.CenterScreen;
        Size = new Size(1080, 740); MinimumSize = new Size(850, 590); BackColor = Canvas;
        Font = new Font("Segoe UI", 9); FormClosing += OnClosing;
        try { Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath); } catch { }
        LoadSettings();
        ShowWelcome();
        Shown += delegate
        {
            if (recentVaults.Count > 0 && File.Exists(recentVaults[0]))
                BeginInvoke((MethodInvoker)delegate { if (!IsDisposed && key == null) OpenVault(recentVaults[0]); });
        };
    }

    private Button MakeButton(string text, int width, bool primary)
    {
        Button b = new Button(); b.Text = text; b.Width = width; b.Height = 40; b.FlatStyle = FlatStyle.Flat; b.Cursor = Cursors.Hand;
        b.FlatAppearance.BorderColor = Color.FromArgb(218, 226, 229); b.FlatAppearance.BorderSize = primary ? 0 : 1;
        b.FlatAppearance.MouseOverBackColor = primary ? Color.FromArgb(0, 121, 107) : Color.FromArgb(235, 242, 243);
        b.FlatAppearance.MouseDownBackColor = Color.FromArgb(0, 77, 64); b.BackColor = primary ? Green : Color.White;
        b.ForeColor = primary ? Color.White : Ink; b.Font = new Font("Segoe UI Semibold", 9); b.Margin = new Padding(3, 0, 3, 0); return b;
    }

    private Label MakeLabel(string text, int size, bool bold, Color color)
    {
        Label l = new Label(); l.Text = text; l.AutoSize = true; l.ForeColor = color;
        l.Font = new Font(bold ? "Segoe UI Semibold" : "Segoe UI", size); return l;
    }

    private void ShowWelcome()
    {
        Controls.Clear(); body = null;
        Panel p = new Panel(); p.Dock = DockStyle.Fill; p.BackColor = Canvas; Controls.Add(p);
        BrandMark brandMark = new BrandMark(); brandMark.Location = new Point(30, 23); p.Controls.Add(brandMark);
        Label brand = MakeLabel("Kasam", 17, true, Ink); brand.Location = new Point(78, 25); p.Controls.Add(brand);
        Label hero = MakeLabel("Şifreleriniz tek yerde,\r\nkontrolünüz sizde.", 28, true, Ink); hero.Location = new Point(44, 105); hero.Size = new Size(700, 95); hero.AutoSize = false; p.Controls.Add(hero);
        Label sub = MakeLabel("Hesap bilgilerinizi bu bilgisayarda şifreli bir kasa dosyasında saklayın.", 11, false, Muted); sub.Location = new Point(47, 218); sub.Size = new Size(700, 36); sub.AutoSize = false; p.Controls.Add(sub);
        Button create = MakeButton("Yeni kasa oluştur", 250, true); create.Height = 66; create.Font = new Font("Segoe UI Semibold", 12); create.Location = new Point(47, 300); p.Controls.Add(create);
        Button open = MakeButton("Farklı kasa dosyası seç", 250, false); open.Height = 66; open.Font = new Font("Segoe UI Semibold", 12); open.Location = new Point(310, 300); p.Controls.Add(open);
        Label recentLabel = MakeLabel("Son kullanılan kasalar", 10, true, Ink); recentLabel.Location = new Point(47, 400); p.Controls.Add(recentLabel);
        recentVaultBox = new ComboBox(); recentVaultBox.Location = new Point(47, 430); recentVaultBox.Size = new Size(560, 32); recentVaultBox.DropDownStyle = ComboBoxStyle.DropDownList; recentVaultBox.Font = new Font("Segoe UI", 10); p.Controls.Add(recentVaultBox);
        Button openRecent = MakeButton("Seçili kasayı aç", 175, true); openRecent.Location = new Point(620, 427); p.Controls.Add(openRecent);
        RefreshRecentVaults();
        openRecent.Enabled = recentVaultBox.Items.Count > 0;
        Label note = MakeLabel("Kasa dosyası seçimi hatırlanır; ana parolanız saklanmaz. Yerel PIN ayarlarsanız bu Windows hesabında hızlı açılış kullanabilirsiniz.", 9, false, Muted); note.Location = new Point(47, 485); note.Size = new Size(720, 42); note.AutoSize = false; p.Controls.Add(note);
        create.Click += delegate { CreateVault(); };
        open.Click += delegate { OpenVault(); };
        openRecent.Click += delegate { RecentVaultChoice choice = recentVaultBox.SelectedItem as RecentVaultChoice; if (choice != null) OpenVault(choice.Path); };
    }

    private string SettingsPath { get { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Kasam", "settings.json"); } }

    private void LoadSettings()
    {
        try
        {
            string path = SettingsPath;
            if (!File.Exists(path)) return;
            JavaScriptSerializer json = new JavaScriptSerializer();
            KasamSettings settings = json.Deserialize<KasamSettings>(File.ReadAllText(path, Encoding.UTF8));
            if (settings != null)
            {
                if (settings.recentVaults != null) recentVaults = settings.recentVaults.Where(x => !String.IsNullOrWhiteSpace(x) && File.Exists(x)).Distinct(StringComparer.OrdinalIgnoreCase).Take(10).ToList();
                if (settings.pinVaults != null) pinVaults = settings.pinVaults.Where(x => x != null && !String.IsNullOrWhiteSpace(x.path) && !String.IsNullOrWhiteSpace(x.protectedData)).ToList();
            }
        }
        catch { recentVaults = new List<string>(); }
    }

    private void SaveSettings()
    {
        try
        {
            string path = SettingsPath; Directory.CreateDirectory(Path.GetDirectoryName(path));
            JavaScriptSerializer json = new JavaScriptSerializer();
            File.WriteAllText(path, json.Serialize(new KasamSettings { recentVaults = recentVaults, pinVaults = pinVaults }), new UTF8Encoding(false));
        }
        catch { }
    }

    private void RememberVault(string path)
    {
        recentVaults.RemoveAll(x => String.Equals(x, path, StringComparison.OrdinalIgnoreCase));
        recentVaults.Insert(0, path); if (recentVaults.Count > 10) recentVaults.RemoveRange(10, recentVaults.Count - 10);
        SaveSettings();
    }

    private void RefreshRecentVaults()
    {
        if (recentVaultBox == null) return;
        recentVaultBox.BeginUpdate(); recentVaultBox.Items.Clear();
        foreach (string path in recentVaults) if (File.Exists(path)) recentVaultBox.Items.Add(new RecentVaultChoice(path));
        if (recentVaultBox.Items.Count > 0) recentVaultBox.SelectedIndex = 0;
        recentVaultBox.EndUpdate();
    }

    private void ChooseAnotherVault()
    {
        if (dirty)
        {
            DialogResult answer = MessageBox.Show("Kaydedilmemiş değişiklikler var. Evet: kaydet ve kasa seçimine dön. Hayır: değişiklikleri at. İptal: burada kal.", "Kasa değiştir", MessageBoxButtons.YesNoCancel, MessageBoxIcon.Warning);
            if (answer == DialogResult.Cancel) return;
            if (answer == DialogResult.Yes)
            {
                SaveVault(); if (dirty) return;
            }
        }
        ClearVault(); ShowWelcome();
    }

    private void CreateVault()
    {
        using (PasswordDialog dialog = new PasswordDialog("Yeni kasa oluştur", true))
        {
            if (dialog.ShowDialog(this) != DialogResult.OK) return;
            salt = VaultCrypto.RandomBytes(16);
            try { key = VaultCrypto.DeriveKey(dialog.Password, salt, VaultCrypto.Iterations); }
            catch (Exception ex) { MessageBox.Show("Anahtar oluşturulamadı.\r\n" + ex.Message, "Kasam", MessageBoxButtons.OK, MessageBoxIcon.Error); return; }
        }
        entries = new List<VaultEntry>(); vaultPath = null; dirty = true; ShowVault();
    }

    private void OpenVault()
    {
        using (OpenFileDialog picker = new OpenFileDialog())
        {
            picker.Title = "Şifreli kasa dosyasını aç"; picker.Filter = "Kasam kasa dosyası (*.vault)|*.vault";
            if (picker.ShowDialog(this) != DialogResult.OK) return;
            OpenVault(picker.FileName);
        }
    }

    private void OpenVault(string path)
    {
        try
        {
            FileInfo info = new FileInfo(path); if (info.Length > 50L * 1024 * 1024) throw new InvalidDataException("Kasa dosyası 50 MB sınırını aşıyor.");
            JavaScriptSerializer json = new JavaScriptSerializer(); json.MaxJsonLength = 50 * 1024 * 1024;
            VaultEnvelope envelope = json.Deserialize<VaultEnvelope>(File.ReadAllText(path, Encoding.UTF8));
            if (envelope == null || envelope.format != "kasam-vault" || envelope.version != 1 || envelope.kdf == null || envelope.cipher == null || envelope.kdf.name != "PBKDF2-HMAC-SHA-256" || envelope.kdf.hash != "SHA-256" || envelope.cipher.name != "AES-256-CBC-HMAC-SHA-256") throw new InvalidDataException("Bu dosya geçerli bir Kasam kasası değil.");
            int iterations = envelope.kdf.iterations; if (iterations < 100000 || iterations > 2000000) throw new InvalidDataException("Kasa dosyasındaki şifreleme ayarları desteklenmiyor.");
            byte[] fileSalt = Convert.FromBase64String(envelope.kdf.salt), iv = Convert.FromBase64String(envelope.cipher.iv), cipher = Convert.FromBase64String(envelope.cipher.ciphertext), mac = Convert.FromBase64String(envelope.cipher.mac);
            if (fileSalt.Length != 16 || iv.Length != 16 || cipher.Length < 16 || mac.Length != 32) throw new InvalidDataException("Kasa dosyası eksik veya bozuk.");
            byte[] candidateKey = null, plaintext = null;
            PinVaultRecord pinRecord = FindPinRecord(path);
            QuickUnlockData quickData = null;
            if (pinRecord != null)
            {
                try
                {
                    quickData = UnprotectQuickUnlockData(pinRecord);
                    if (quickData == null || quickData.vaultSalt != Convert.ToBase64String(fileSalt)) throw new CryptographicException("Hızlı açılış kaydı bu kasa ile eşleşmiyor.");
                }
                catch { RemoveQuickPin(path); quickData = null; }
            }
            if (quickData != null)
            {
                int failures = 0, quickResult = 0; // 1 = opened, 2 = use master, 3 = cancelled
                while (failures < 5 && quickResult == 0)
                {
                    using (PinUnlockDialog pinDialog = new PinUnlockDialog())
                    {
                        DialogResult result = pinDialog.ShowDialog(this);
                        if (pinDialog.UseMasterPassword) { quickResult = 2; break; }
                        if (result == DialogResult.Cancel) { quickResult = 3; break; }
                        if (result != DialogResult.OK) { quickResult = 3; break; }
                        try
                        {
                            byte[] pinSalt = Convert.FromBase64String(quickData.pinSalt);
                            byte[] pinKey = VaultCrypto.DeriveKey(pinDialog.Pin, pinSalt, VaultCrypto.Iterations);
                            VaultEnvelope wrapped = json.Deserialize<VaultEnvelope>(quickData.wrappedKey);
                            if (wrapped == null || wrapped.kdf == null || wrapped.cipher == null) throw new CryptographicException("PIN kaydı bozuk.");
                            byte[] wrappedSalt = Convert.FromBase64String(wrapped.kdf.salt);
                            byte[] wrappedIv = Convert.FromBase64String(wrapped.cipher.iv);
                            byte[] wrappedCipher = Convert.FromBase64String(wrapped.cipher.ciphertext);
                            byte[] wrappedMac = Convert.FromBase64String(wrapped.cipher.mac);
                            candidateKey = VaultCrypto.Decrypt(pinKey, wrappedSalt, wrappedIv, wrappedCipher, wrappedMac, wrapped.kdf.iterations);
                            Array.Clear(pinKey, 0, pinKey.Length);
                            if (candidateKey.Length != 64) throw new CryptographicException("PIN anahtarı geçersiz.");
                            plaintext = VaultCrypto.Decrypt(candidateKey, fileSalt, iv, cipher, mac, iterations);
                            quickResult = 1;
                        }
                        catch
                        {
                            if (candidateKey != null) { Array.Clear(candidateKey, 0, candidateKey.Length); candidateKey = null; }
                            if (plaintext != null) { Array.Clear(plaintext, 0, plaintext.Length); plaintext = null; }
                            failures++;
                            if (failures >= 5)
                            {
                                MessageBox.Show("PIN 5 kez yanlış girildi. Ana parola ile devam edin.", "Kasam", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                                quickResult = 2;
                            }
                            else MessageBox.Show("PIN doğru değil.", "Kasam", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                        }
                    }
                }
                if (quickResult == 3) return;
                if (quickResult == 2) { if (candidateKey != null) Array.Clear(candidateKey, 0, candidateKey.Length); candidateKey = null; }
            }
            if (candidateKey == null)
            {
                using (PasswordDialog passwordDialog = new PasswordDialog("Kasayı aç", false))
                {
                    if (passwordDialog.ShowDialog(this) != DialogResult.OK) return;
                    candidateKey = VaultCrypto.DeriveKey(passwordDialog.Password, fileSalt, iterations);
                    plaintext = VaultCrypto.Decrypt(candidateKey, fileSalt, iv, cipher, mac, iterations);
                }
            }
            VaultPayload payload = json.Deserialize<VaultPayload>(Encoding.UTF8.GetString(plaintext));
            if (payload == null || payload.entries == null) throw new InvalidDataException("Kasa içeriği geçersiz.");
            foreach (VaultEntry e in payload.entries)
            {
                if (e == null || String.IsNullOrWhiteSpace(e.title) || e.id == null || e.username == null || e.password == null || e.url == null || e.notes == null) throw new InvalidDataException("Kasadaki bir kayıt eksik veya bozuk.");
                if (String.IsNullOrWhiteSpace(e.system)) e.system = "Diğer";
            }
            if (plaintext != null) Array.Clear(plaintext, 0, plaintext.Length);
            if (key != null) Array.Clear(key, 0, key.Length);
            key = candidateKey; salt = fileSalt; entries = payload.entries; vaultPath = path; dirty = false; RememberVault(path);
            ShowVault();
        }
        catch (Exception ex)
        {
            MessageBox.Show("Ana parola yanlış veya kasa dosyası bozuk.\r\n\r\n" + ex.Message, "Kasam", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private PinVaultRecord FindPinRecord(string path)
    {
        string fullPath = Path.GetFullPath(path);
        return pinVaults.FirstOrDefault(x => String.Equals(Path.GetFullPath(x.path), fullPath, StringComparison.OrdinalIgnoreCase));
    }

    private byte[] PinEntropy(string path)
    {
        using (SHA256 sha = SHA256.Create()) return sha.ComputeHash(Encoding.UTF8.GetBytes(Path.GetFullPath(path).ToUpperInvariant()));
    }

    private QuickUnlockData UnprotectQuickUnlockData(PinVaultRecord record)
    {
        byte[] protectedBytes = Convert.FromBase64String(record.protectedData);
        byte[] clear = ProtectedData.Unprotect(protectedBytes, PinEntropy(record.path), DataProtectionScope.CurrentUser);
        try { return new JavaScriptSerializer().Deserialize<QuickUnlockData>(Encoding.UTF8.GetString(clear)); }
        finally { Array.Clear(clear, 0, clear.Length); }
    }

    private bool StoreQuickUnlockData(string path, QuickUnlockData data)
    {
        try
        {
            byte[] clear = Encoding.UTF8.GetBytes(new JavaScriptSerializer().Serialize(data));
            byte[] protectedBytes = ProtectedData.Protect(clear, PinEntropy(path), DataProtectionScope.CurrentUser);
            Array.Clear(clear, 0, clear.Length);
            string fullPath = Path.GetFullPath(path);
            PinVaultRecord record = FindPinRecord(fullPath);
            if (record == null) { record = new PinVaultRecord { path = fullPath }; pinVaults.Add(record); }
            record.path = fullPath; record.protectedData = Convert.ToBase64String(protectedBytes); SaveSettings(); return true;
        }
        catch { return false; }
    }

    private void RemoveQuickPin(string path)
    {
        string fullPath = Path.GetFullPath(path);
        pinVaults.RemoveAll(x => String.Equals(Path.GetFullPath(x.path), fullPath, StringComparison.OrdinalIgnoreCase)); SaveSettings();
    }

    private void ConfigureQuickPin()
    {
        if (key == null) return;
        if (String.IsNullOrWhiteSpace(vaultPath)) { MessageBox.Show("Önce kasayı bir .vault dosyasına kaydedin.", "Kasam", MessageBoxButtons.OK, MessageBoxIcon.Information); return; }
        PinVaultRecord existing = FindPinRecord(vaultPath);
        if (existing != null)
        {
            DialogResult choice = MessageBox.Show("Evet: PIN belirle veya değiştir. Hayır: bu bilgisayardaki PIN'i kaldır.", "PIN ayarı", MessageBoxButtons.YesNoCancel, MessageBoxIcon.Question);
            if (choice == DialogResult.Cancel) return;
            if (choice == DialogResult.No) { RemoveQuickPin(vaultPath); MessageBox.Show("Bu kasa için yerel PIN kaldırıldı.", "Kasam", MessageBoxButtons.OK, MessageBoxIcon.Information); return; }
        }
        using (PinSetupDialog dialog = new PinSetupDialog())
        {
            if (dialog.ShowDialog(this) != DialogResult.OK) return;
            byte[] pinSalt = VaultCrypto.RandomBytes(16);
            byte[] pinKey = VaultCrypto.DeriveKey(dialog.Pin, pinSalt, VaultCrypto.Iterations);
            string wrapped = VaultCrypto.Encrypt(pinKey, pinSalt, key);
            Array.Clear(pinKey, 0, pinKey.Length);
            QuickUnlockData data = new QuickUnlockData { pinSalt = Convert.ToBase64String(pinSalt), vaultSalt = Convert.ToBase64String(salt), wrappedKey = wrapped };
            if (!StoreQuickUnlockData(vaultPath, data)) { RemoveQuickPin(vaultPath); MessageBox.Show("PIN kaydedilemedi. Windows hesabı koruması oluşturulamadı.", "Kasam", MessageBoxButtons.OK, MessageBoxIcon.Error); return; }
            MessageBox.Show("Bu kasa artık bu Windows hesabında 4 haneli PIN ile hızlı açılabilir. Ana parola .vault dosyasını şifrelemeye devam eder.", "Kasam", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
    }

    private void ShowVault()
    {
        Controls.Clear(); body = new Panel(); body.Dock = DockStyle.Fill; body.BackColor = Canvas; Controls.Add(body);
        Panel header = new Panel { Location = new Point(20, 13), Size = new Size(ClientSize.Width - 40, 66), Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right, BackColor = Color.White };
        header.Paint += delegate(object sender, PaintEventArgs e) { using (Pen pen = new Pen(Color.FromArgb(228, 234, 236))) e.Graphics.DrawRectangle(pen, 0, 0, header.Width - 1, header.Height - 1); };
        body.Controls.Add(header);
        BrandMark brandMark = new BrandMark(); brandMark.Location = new Point(13, 12); header.Controls.Add(brandMark);
        Label brand = MakeLabel("Kasam", 16, true, Ink); brand.Location = new Point(59, 16); header.Controls.Add(brand);
        FlowLayoutPanel actions = new FlowLayoutPanel(); actions.FlowDirection = FlowDirection.LeftToRight; actions.WrapContents = false; actions.AutoSize = true; actions.Anchor = AnchorStyles.Top | AnchorStyles.Right;
        Button add = MakeButton("+ Yeni kayıt", 118, true), save = MakeButton("Kasayı kaydet", 122, false), changeMaster = MakeButton("Ana parola", 98, false), pinButton = MakeButton("PIN ayarı", 84, false), chooseVault = MakeButton("Kasa seç", 80, false), lockButton = MakeButton("Kilitle", 74, false);
        actions.Controls.AddRange(new Control[] { add, save, changeMaster, pinButton, chooseVault, lockButton }); header.Controls.Add(actions); actions.Location = new Point(header.Width - actions.Width - 12, 13);
        header.Resize += delegate { actions.Location = new Point(Math.Max(160, header.Width - actions.Width - 12), 13); };
        statusLabel = MakeLabel("", 9, false, Green); statusLabel.Location = new Point(24, 86); body.Controls.Add(statusLabel);
        fileLabel = MakeLabel("", 9, false, Muted); fileLabel.TextAlign = ContentAlignment.TopRight; fileLabel.Anchor = AnchorStyles.Top | AnchorStyles.Right; fileLabel.Location = new Point(610, 86); fileLabel.Size = new Size(ClientSize.Width - 635, 22); body.Controls.Add(fileLabel);
        SplitContainer split = new SplitContainer(); split.Location = new Point(20, 111); split.Size = new Size(ClientSize.Width - 40, ClientSize.Height - 165); split.Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right; split.SplitterDistance = 360; split.Panel1MinSize = 250; split.Panel2MinSize = 390; split.BackColor = Canvas; body.Controls.Add(split);
        Label systemFilterLabel = MakeLabel("Sistem", 9, false, Muted); systemFilterLabel.Location = new Point(10, 9); split.Panel1.Controls.Add(systemFilterLabel);
        systemFilterBox = new ComboBox(); systemFilterBox.Location = new Point(10, 30); systemFilterBox.Size = new Size(split.Panel1.Width - 20, 32); systemFilterBox.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right; systemFilterBox.DropDownStyle = ComboBoxStyle.DropDownList; systemFilterBox.Font = new Font("Segoe UI", 10); split.Panel1.Controls.Add(systemFilterBox);
        searchBox = new TextBox(); searchBox.Location = new Point(10, 72); searchBox.Size = new Size(split.Panel1.Width - 95, 32); searchBox.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right; searchBox.Font = new Font("Segoe UI", 10); split.Panel1.Controls.Add(searchBox);
        countLabel = MakeLabel("0 kayıt", 9, false, Muted); countLabel.Location = new Point(split.Panel1.Width - 78, 80); countLabel.Anchor = AnchorStyles.Top | AnchorStyles.Right; split.Panel1.Controls.Add(countLabel);
        entryList = new ListBox(); entryList.Location = new Point(6, 118); entryList.Size = new Size(split.Panel1.Width - 12, split.Panel1.Height - 128); entryList.Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right; entryList.IntegralHeight = false; entryList.DrawMode = DrawMode.OwnerDrawFixed; entryList.ItemHeight = 66; entryList.BorderStyle = BorderStyle.None; entryList.Font = new Font("Segoe UI", 10, FontStyle.Bold); entryList.BackColor = Canvas; split.Panel1.Controls.Add(entryList);
        titleLabel = MakeLabel("", 16, true, Ink); titleLabel.Location = new Point(18, 22); titleLabel.Size = new Size(Math.Max(80, split.Panel2.Width - 285), 36); titleLabel.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right; titleLabel.AutoEllipsis = true; split.Panel2.Controls.Add(titleLabel);
        copyTitleButton = MakeButton("Kopyala", 70, false); copyTitleButton.Location = new Point(split.Panel2.Width - 250, 18); copyTitleButton.Anchor = AnchorStyles.Top | AnchorStyles.Right; split.Panel2.Controls.Add(copyTitleButton);
        editButton = MakeButton("Düzenle", 78, false); editButton.Location = new Point(split.Panel2.Width - 170, 18); editButton.Anchor = AnchorStyles.Top | AnchorStyles.Right; split.Panel2.Controls.Add(editButton);
        deleteButton = MakeButton("Sil", 62, false); deleteButton.ForeColor = Color.FromArgb(180, 55, 55); deleteButton.Location = new Point(split.Panel2.Width - 82, 18); deleteButton.Anchor = AnchorStyles.Top | AnchorStyles.Right; split.Panel2.Controls.Add(deleteButton);
        TableLayoutPanel details = new TableLayoutPanel { Location = new Point(18, 68), Size = new Size(split.Panel2.Width - 36, 244), Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right, ColumnCount = 1, RowCount = 4, BackColor = Color.White, Padding = new Padding(8, 3, 8, 3), Margin = new Padding(0) };
        details.RowStyles.Add(new RowStyle(SizeType.Percent, 25)); details.RowStyles.Add(new RowStyle(SizeType.Percent, 25)); details.RowStyles.Add(new RowStyle(SizeType.Percent, 25)); details.RowStyles.Add(new RowStyle(SizeType.Percent, 25)); split.Panel2.Controls.Add(details);
        AddCopyDetailField(details, "Sistem", out systemBox, out copySystemButton);
        AddCopyDetailField(details, "Kullanıcı adı / e-posta", out usernameBox, out copyUsernameButton);
        AddCopyDetailField(details, "Parola", out passwordBox, out copyButton, true);
        AddCopyDetailField(details, "Web adresi", out urlBox, out copyUrlButton);
        Label notesLabel = MakeLabel("Notlar", 9, true, Muted); notesLabel.Location = new Point(20, 326); split.Panel2.Controls.Add(notesLabel);
        copyNotesButton = MakeButton("Kopyala", 88, false); copyNotesButton.Location = new Point(split.Panel2.Width - 108, 318); copyNotesButton.Anchor = AnchorStyles.Top | AnchorStyles.Right; split.Panel2.Controls.Add(copyNotesButton);
        notesBox = new TextBox(); notesBox.Location = new Point(18, 354); notesBox.Size = new Size(split.Panel2.Width - 36, split.Panel2.Height - 372); notesBox.Multiline = true; notesBox.ReadOnly = true; notesBox.ScrollBars = ScrollBars.Vertical; notesBox.Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right; notesBox.Font = new Font("Segoe UI", 10); split.Panel2.Controls.Add(notesBox);
        Label footer = MakeLabel("Değişiklikleri kaydedin; .vault dosyanızın yedeğini alın.", 9, false, Muted); footer.Location = new Point(22, ClientSize.Height - 39); footer.Anchor = AnchorStyles.Bottom | AnchorStyles.Left; body.Controls.Add(footer);
        add.Click += delegate { AddEntry(); };
        save.Click += delegate { SaveVault(); };
        changeMaster.Click += delegate { ChangeMasterPassword(); };
        pinButton.Click += delegate { ConfigureQuickPin(); };
        chooseVault.Click += delegate { ChooseAnotherVault(); };
        lockButton.Click += delegate { LockVault(); };
        searchBox.TextChanged += delegate { RefreshEntries(null); };
        systemFilterBox.SelectedIndexChanged += delegate { RefreshEntries(null); };
        entryList.SelectedIndexChanged += delegate { UpdateDetails(); };
        entryList.DrawItem += DrawEntryItem;
        editButton.Click += delegate { EditEntry(); };
        deleteButton.Click += delegate { DeleteEntry(); };
        revealButton.Click += delegate { ToggleReveal(); };
        copyButton.Click += delegate { CopyPassword(); };
        copyTitleButton.Click += delegate { CopyField(titleLabel.Text, "Hesap adı"); };
        copySystemButton.Click += delegate { CopyField(systemBox.Text, "Sistem"); };
        copyUsernameButton.Click += delegate { CopyField(usernameBox.Text, "Kullanıcı adı / e-posta"); };
        copyUrlButton.Click += delegate { CopyField(urlBox.Text, "Web adresi"); };
        copyNotesButton.Click += delegate { CopyField(notesBox.Text, "Notlar"); };
        split.Panel2.Resize += delegate { details.Width = split.Panel2.ClientSize.Width - 36; notesBox.Width = split.Panel2.ClientSize.Width - 36; copyNotesButton.Left = split.Panel2.ClientSize.Width - 108; };
        header.PerformLayout();
        UpdateStatus(); RefreshSystemFilter(null); RefreshEntries(null); UpdateDetails();
    }

    private void AddCopyDetailField(TableLayoutPanel table, string caption, out TextBox box, out Button copy, bool password = false)
    {
        Panel row = new Panel { Dock = DockStyle.Fill, BackColor = Color.White, Margin = new Padding(0) };
        Label label = MakeLabel(caption, 9, true, Muted); label.Location = new Point(4, 1); row.Controls.Add(label);
        box = new TextBox { Location = new Point(4, 22), Size = new Size(table.ClientSize.Width - 132, 27), Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right, ReadOnly = true, BorderStyle = BorderStyle.FixedSingle, Font = new Font("Segoe UI", 10), BackColor = Color.FromArgb(250, 251, 252) };
        if (password) box.UseSystemPasswordChar = true;
        row.Controls.Add(box);
        copy = MakeButton("Kopyala", 88, false); copy.Height = 30; copy.Location = new Point(row.Width - 96, 20); copy.Anchor = AnchorStyles.Top | AnchorStyles.Right; row.Controls.Add(copy);
        if (password)
        {
            revealButton = MakeButton("Göster", 76, false); revealButton.Height = 30; revealButton.Location = new Point(row.Width - 180, 20); revealButton.Anchor = AnchorStyles.Top | AnchorStyles.Right; row.Controls.Add(revealButton);
            box.Width = table.ClientSize.Width - 220;
        }
        TextBox resizeBox = box; Button resizeCopy = copy; Button resizeReveal = password ? revealButton : null;
        row.Resize += delegate
        {
            int inputWidth = row.Width - (password ? 220 : 108);
            resizeBox.Width = Math.Max(80, inputWidth);
            resizeCopy.Left = row.Width - 96;
            if (password) resizeReveal.Left = row.Width - 180;
        };
        table.Controls.Add(row, 0, table.Controls.Count);
    }

    private void DrawEntryItem(object sender, DrawItemEventArgs e)
    {
        e.DrawBackground();
        if (e.Index < 0 || e.Index >= entryList.Items.Count) return;
        VaultEntry entry = entryList.Items[e.Index] as VaultEntry;
        if (entry == null) return;
        bool selected = (e.State & DrawItemState.Selected) == DrawItemState.Selected;
        Rectangle card = new Rectangle(e.Bounds.Left + 3, e.Bounds.Top + 3, e.Bounds.Width - 7, e.Bounds.Height - 7);
        using (SolidBrush fill = new SolidBrush(selected ? Color.FromArgb(229, 240, 233) : Color.White)) e.Graphics.FillRectangle(fill, card);
        using (Pen border = new Pen(selected ? Green : Color.FromArgb(211, 220, 214), selected ? 2 : 1)) e.Graphics.DrawRectangle(border, card);
        Rectangle textBounds = new Rectangle(card.Left + 12, card.Top + 6, card.Width - 22, 22);
        TextRenderer.DrawText(e.Graphics, entry.title, EntryTitleFont, textBounds, Ink, TextFormatFlags.EndEllipsis | TextFormatFlags.NoPrefix | TextFormatFlags.SingleLine | TextFormatFlags.VerticalCenter);
        Rectangle userBounds = new Rectangle(card.Left + 12, card.Top + 31, card.Width - 22, 19);
        string user = String.IsNullOrWhiteSpace(entry.username) ? "Kullanıcı adı yok" : entry.username;
        TextRenderer.DrawText(e.Graphics, user, EntryUserFont, userBounds, Muted, TextFormatFlags.EndEllipsis | TextFormatFlags.NoPrefix | TextFormatFlags.SingleLine | TextFormatFlags.VerticalCenter);
    }

    private void RefreshEntries(string preferredId)
    {
        if (entryList == null) return;
        if (preferredId == null && entryList.SelectedItem is VaultEntry) preferredId = ((VaultEntry)entryList.SelectedItem).id;
        string q = (searchBox.Text ?? "").Trim(); string selectedSystem = systemFilterBox.SelectedItem as string;
        entryList.BeginUpdate(); entryList.Items.Clear();
        foreach (VaultEntry e in entries)
        {
            bool matchesSystem = String.IsNullOrEmpty(selectedSystem) || selectedSystem == "Tüm sistemler" || String.Equals(e.system, selectedSystem, StringComparison.CurrentCultureIgnoreCase);
            bool matchesSearch = q.Length == 0 || (e.title + " " + e.username + " " + e.url + " " + e.notes).IndexOf(q, StringComparison.CurrentCultureIgnoreCase) >= 0;
            if (matchesSystem && matchesSearch) entryList.Items.Add(e);
        }
        entryList.EndUpdate(); countLabel.Text = entries.Count + " kayıt";
        if (preferredId != null) for (int i = 0; i < entryList.Items.Count; i++) if (((VaultEntry)entryList.Items[i]).id == preferredId) { entryList.SelectedIndex = i; break; }
        UpdateDetails();
    }

    private List<string> GetSystems()
    {
        List<string> result = new List<string>();
        foreach (VaultEntry e in entries) if (!String.IsNullOrWhiteSpace(e.system) && !result.Contains(e.system, StringComparer.CurrentCultureIgnoreCase)) result.Add(e.system);
        result.Sort(StringComparer.CurrentCultureIgnoreCase); return result;
    }

    private void RefreshSystemFilter(string selectSystem)
    {
        if (systemFilterBox == null) return;
        string previous = selectSystem ?? systemFilterBox.SelectedItem as string;
        systemFilterBox.BeginUpdate(); systemFilterBox.Items.Clear(); systemFilterBox.Items.Add("Tüm sistemler");
        foreach (string system in GetSystems()) systemFilterBox.Items.Add(system);
        int index = previous == null ? 0 : systemFilterBox.Items.IndexOf(previous);
        systemFilterBox.SelectedIndex = index >= 0 ? index : 0; systemFilterBox.EndUpdate();
    }

    private VaultEntry SelectedEntry() { return entryList != null ? entryList.SelectedItem as VaultEntry : null; }

    private void UpdateDetails()
    {
        VaultEntry e = SelectedEntry(); bool has = e != null;
        if (titleLabel == null) return;
        titleLabel.Text = has ? e.title : ""; systemBox.Text = has ? e.system : ""; usernameBox.Text = has ? e.username : ""; passwordBox.Text = has ? e.password : ""; urlBox.Text = has ? e.url : ""; notesBox.Text = has ? e.notes : "";
        revealed = has; passwordBox.UseSystemPasswordChar = !revealed; if (revealButton != null) revealButton.Text = revealed ? "Gizle" : "Göster";
        editButton.Enabled = deleteButton.Enabled = revealButton.Enabled = copyButton.Enabled = has;
        copyTitleButton.Enabled = has && !String.IsNullOrWhiteSpace(e.title);
        copySystemButton.Enabled = has && !String.IsNullOrWhiteSpace(e.system);
        copyUsernameButton.Enabled = has && !String.IsNullOrWhiteSpace(e.username);
        copyUrlButton.Enabled = has && !String.IsNullOrWhiteSpace(e.url);
        copyNotesButton.Enabled = has && !String.IsNullOrWhiteSpace(e.notes);
    }

    private void AddEntry()
    {
        using (EntryDialog dialog = new EntryDialog(null, GetSystems())) if (dialog.ShowDialog(this) == DialogResult.OK) { entries.Add(dialog.Value); dirty = true; UpdateStatus(); RefreshSystemFilter(dialog.Value.system); RefreshEntries(dialog.Value.id); }
    }
    private void EditEntry()
    {
        VaultEntry selected = SelectedEntry(); if (selected == null) return;
        using (EntryDialog dialog = new EntryDialog(selected, GetSystems())) if (dialog.ShowDialog(this) == DialogResult.OK) { int i = entries.FindIndex(x => x.id == selected.id); if (i >= 0) entries[i] = dialog.Value; dirty = true; UpdateStatus(); RefreshSystemFilter(dialog.Value.system); RefreshEntries(dialog.Value.id); }
    }
    private void DeleteEntry()
    {
        VaultEntry selected = SelectedEntry(); if (selected == null) return;
        if (MessageBox.Show("“" + selected.title + "” kaydı silinsin mi?", "Kaydı sil", MessageBoxButtons.YesNo, MessageBoxIcon.Question) == DialogResult.Yes) { entries.RemoveAll(x => x.id == selected.id); dirty = true; UpdateStatus(); RefreshEntries(null); }
    }
    private void ToggleReveal()
    {
        if (SelectedEntry() == null) return;
        revealed = !revealed; passwordBox.UseSystemPasswordChar = !revealed; revealButton.Text = revealed ? "Gizle" : "Göster";
    }
    private void CopyPassword()
    {
        CopyField(passwordBox.Text, "Parola");
    }

    private void CopyField(string value, string caption)
    {
        if (String.IsNullOrWhiteSpace(value)) return;
        try
        {
            Clipboard.SetText(value);
            statusLabel.Text = caption + " panoya kopyalandı"; statusLabel.ForeColor = Green;
            Timer timer = new Timer { Interval = 2200 };
            timer.Tick += delegate { timer.Stop(); timer.Dispose(); UpdateStatus(); };
            timer.Start();
        }
        catch { statusLabel.Text = "Panoya kopyalanamadı"; statusLabel.ForeColor = Color.FromArgb(180, 55, 55); }
    }

    private void SaveVault()
    {
        string target = vaultPath;
        if (String.IsNullOrEmpty(target))
        {
            using (SaveFileDialog picker = new SaveFileDialog())
            {
                picker.Title = "Şifreli kasayı kaydet"; picker.Filter = "Kasam kasa dosyası (*.vault)|*.vault"; picker.DefaultExt = "vault"; picker.AddExtension = true; picker.FileName = "Kasam.vault";
                if (picker.ShowDialog(this) != DialogResult.OK) return;
                target = picker.FileName;
            }
        }
        try { PersistVault(target); MessageBox.Show("Şifreli kasa dosyası kaydedildi.", "Kasam", MessageBoxButtons.OK, MessageBoxIcon.Information); }
        catch (Exception ex) { MessageBox.Show("Kasa kaydedilemedi.\r\n" + ex.Message, "Kasam", MessageBoxButtons.OK, MessageBoxIcon.Error); }
    }

    private void PersistVault(string target)
    {
        string container = CreateVaultContainer(key, salt);
        WriteVaultFile(target, container);
        vaultPath = target; dirty = false; RememberVault(target); UpdateStatus();
    }

    private string CreateVaultContainer(byte[] encryptionKey, byte[] encryptionSalt)
    {
        JavaScriptSerializer json = new JavaScriptSerializer(); json.MaxJsonLength = 50 * 1024 * 1024;
        byte[] plaintext = Encoding.UTF8.GetBytes(json.Serialize(new VaultPayload { entries = entries }));
        return VaultCrypto.Encrypt(encryptionKey, encryptionSalt, plaintext);
    }

    private void WriteVaultFile(string target, string container)
    {
        string temp = target + ".tmp";
        File.WriteAllText(temp, container, new UTF8Encoding(false));
        if (File.Exists(target))
        {
            string backup = target + ".bak";
            try { if (File.Exists(backup)) File.Delete(backup); File.Replace(temp, target, backup, true); if (File.Exists(backup)) File.Delete(backup); }
            catch { if (File.Exists(temp)) File.Delete(temp); throw; }
        }
        else File.Move(temp, target);
    }

    private void ChangeMasterPassword()
    {
        if (key == null || salt == null) return;
        using (PasswordDialog dialog = new PasswordDialog("Ana parolayı değiştir", true))
        {
            if (dialog.ShowDialog(this) != DialogResult.OK) return;
            string pinToKeep = null;
            QuickUnlockData priorPinData = null;
            if (!String.IsNullOrEmpty(vaultPath))
            {
                PinVaultRecord pinRecord = FindPinRecord(vaultPath);
                if (pinRecord != null)
                {
                    try { priorPinData = UnprotectQuickUnlockData(pinRecord); }
                    catch { RemoveQuickPin(vaultPath); priorPinData = null; }
                    if (priorPinData != null)
                    {
                        bool pinVerified = false;
                        using (PinUnlockDialog pinDialog = new PinUnlockDialog("Ana parola değişikliği için mevcut PIN'i doğrulayın"))
                        {
                            while (!pinVerified)
                            {
                                if (pinDialog.ShowDialog(this) != DialogResult.OK || pinDialog.UseMasterPassword) return;
                                try
                                {
                                    byte[] pinSalt = Convert.FromBase64String(priorPinData.pinSalt);
                                    byte[] pinKey = VaultCrypto.DeriveKey(pinDialog.Pin, pinSalt, VaultCrypto.Iterations);
                                    JavaScriptSerializer json = new JavaScriptSerializer();
                                    VaultEnvelope wrapped = json.Deserialize<VaultEnvelope>(priorPinData.wrappedKey);
                                    byte[] wrappedSalt = Convert.FromBase64String(wrapped.kdf.salt), wrappedIv = Convert.FromBase64String(wrapped.cipher.iv), wrappedCipher = Convert.FromBase64String(wrapped.cipher.ciphertext), wrappedMac = Convert.FromBase64String(wrapped.cipher.mac);
                                    byte[] cachedKey = VaultCrypto.Decrypt(pinKey, wrappedSalt, wrappedIv, wrappedCipher, wrappedMac, wrapped.kdf.iterations);
                                    Array.Clear(pinKey, 0, pinKey.Length);
                                    pinVerified = FixedTimeEquals(cachedKey, key);
                                    Array.Clear(cachedKey, 0, cachedKey.Length);
                                    if (!pinVerified) MessageBox.Show("PIN doğru değil.", "Kasam", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                                }
                                catch { MessageBox.Show("PIN doğrulanamadı. Tekrar deneyin.", "Kasam", MessageBoxButtons.OK, MessageBoxIcon.Warning); }
                            }
                            pinToKeep = pinDialog.Pin;
                        }
                    }
                }
            }
            byte[] newSalt = VaultCrypto.RandomBytes(16);
            byte[] newKey = null;
            try
            {
                newKey = VaultCrypto.DeriveKey(dialog.Password, newSalt, VaultCrypto.Iterations);
                if (!String.IsNullOrEmpty(vaultPath))
                {
                    string replacement = CreateVaultContainer(newKey, newSalt);
                    WriteVaultFile(vaultPath, replacement);
                    if (priorPinData != null && pinToKeep != null)
                    {
                        byte[] newPinSalt = VaultCrypto.RandomBytes(16);
                        byte[] pinKey = VaultCrypto.DeriveKey(pinToKeep, newPinSalt, VaultCrypto.Iterations);
                        string wrapped = VaultCrypto.Encrypt(pinKey, newPinSalt, newKey);
                        Array.Clear(pinKey, 0, pinKey.Length);
                        QuickUnlockData updated = new QuickUnlockData { pinSalt = Convert.ToBase64String(newPinSalt), vaultSalt = Convert.ToBase64String(newSalt), wrappedKey = wrapped };
                        if (!StoreQuickUnlockData(vaultPath, updated)) RemoveQuickPin(vaultPath);
                    }
                }
                Array.Clear(key, 0, key.Length); key = newKey; salt = newSalt; dirty = String.IsNullOrEmpty(vaultPath);
                UpdateStatus();
                MessageBox.Show("Ana parola değiştirildi." + (dirty ? " Kasayı kaydettiğinizde yeni parola kullanılacak." : " Kasa dosyası yeni parolayla güncellendi."), "Kasam", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                if (newKey != null) Array.Clear(newKey, 0, newKey.Length);
                MessageBox.Show("Ana parola değiştirilemedi. Eski parola ve kasa dosyası korunuyor.\r\n\r\n" + ex.Message, "Kasam", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }
    }

    private static bool FixedTimeEquals(byte[] left, byte[] right)
    {
        if (left == null || right == null) return false;
        int difference = left.Length ^ right.Length;
        for (int i = 0; i < Math.Min(left.Length, right.Length); i++) difference |= left[i] ^ right[i];
        return difference == 0;
    }

    private void LockVault()
    {
        if (dirty && MessageBox.Show("Kaydedilmemiş değişiklikler var. Kilitlerseniz kaybolur. Kilitlensin mi?", "Kasayı kilitle", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes) return;
        ClearVault(); ShowWelcome();
    }
    private void ClearVault()
    {
        if (key != null) Array.Clear(key, 0, key.Length);
        key = null; salt = null; entries.Clear(); vaultPath = null; dirty = false;
    }
    private void UpdateStatus()
    {
        if (statusLabel == null) return;
        statusLabel.Text = dirty ? "●  Kaydedilmemiş değişiklikler" : "●  Değişiklikler kaydedildi"; statusLabel.ForeColor = dirty ? Color.FromArgb(174, 123, 32) : Green;
        fileLabel.Text = String.IsNullOrEmpty(vaultPath) ? "Yeni kasa — henüz kaydedilmedi" : Path.GetFileName(vaultPath);
    }
    private void OnClosing(object sender, FormClosingEventArgs e)
    {
        if (dirty && MessageBox.Show("Kaydedilmemiş değişiklikler var. Uygulamadan çıkılsın mı?", "Kasam", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes) e.Cancel = true;
        else ClearVault();
    }
}

internal sealed class PasswordDialog : Form
{
    private readonly TextBox first, second;
    public string Password { get; private set; }
    public PasswordDialog(string title, bool confirm)
    {
        Text = title; Size = new Size(430, confirm ? 300 : 220); StartPosition = FormStartPosition.CenterParent; FormBorderStyle = FormBorderStyle.FixedDialog; MaximizeBox = false; MinimizeBox = false; BackColor = Color.FromArgb(251,252,250); Font = new Font("Segoe UI",9);
        Label label = new Label { Text = "Ana parola", Location = new Point(24,22), AutoSize = true };
        first = new TextBox { Location = new Point(24,48), Size = new Size(365,29), UseSystemPasswordChar = true, Font = new Font("Segoe UI",11) }; Controls.Add(label); Controls.Add(first);
        second = null;
        if (confirm)
        {
            Controls.Add(new Label { Text = "Ana parola tekrar", Location = new Point(24,91), AutoSize = true });
            second = new TextBox { Location = new Point(24,117), Size = new Size(365,29), UseSystemPasswordChar = true, Font = new Font("Segoe UI",11) }; Controls.Add(second);
            Controls.Add(new Label { Text = "En az 12 karakter kullanın. Parolanızı unutursanız kasa açılamaz.", Location = new Point(24,154), Size = new Size(365,36), ForeColor = Color.FromArgb(104,115,109) });
        }
        Button cancel = new Button { Text = "İptal", Location = new Point(174, Height - 82), Size = new Size(100,36), DialogResult = DialogResult.Cancel };
        Button ok = new Button { Text = "Devam", Location = new Point(284, Height - 82), Size = new Size(105,36), BackColor = Color.FromArgb(30,101,78), ForeColor = Color.White, FlatStyle = FlatStyle.Flat };
        ok.Click += delegate
        {
            if (confirm && first.Text.Length < 12) { MessageBox.Show("Ana parola en az 12 karakter olmalı.", "Kasam", MessageBoxButtons.OK, MessageBoxIcon.Warning); return; }
            if (confirm && first.Text != second.Text) { MessageBox.Show("Girdiğiniz parolalar eşleşmiyor.", "Kasam", MessageBoxButtons.OK, MessageBoxIcon.Warning); return; }
            if (!confirm && String.IsNullOrEmpty(first.Text)) { MessageBox.Show("Ana parolanızı girin.", "Kasam", MessageBoxButtons.OK, MessageBoxIcon.Warning); return; }
            Password = first.Text; DialogResult = DialogResult.OK; Close();
        };
        Controls.Add(cancel); Controls.Add(ok); AcceptButton = ok; CancelButton = cancel; Shown += delegate { first.Focus(); };
    }
}

internal sealed class BrandMark : Control
{
    public BrandMark() { Size = new Size(36, 36); SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.UserPaint, true); }
    protected override void OnPaint(PaintEventArgs e)
    {
        base.OnPaint(e);
        e.Graphics.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
        using (System.Drawing.Drawing2D.GraphicsPath tile = RoundedRect(new Rectangle(0, 0, Width - 1, Height - 1), 10))
        using (SolidBrush background = new SolidBrush(Color.FromArgb(0, 105, 92))) e.Graphics.FillPath(background, tile);
        using (Pen shackle = new Pen(Color.White, 2.4f)) e.Graphics.DrawArc(shackle, 12, 7, 13, 15, 180, 180);
        using (System.Drawing.Drawing2D.GraphicsPath lockBody = RoundedRect(new Rectangle(9, 15, 19, 14), 3))
        using (SolidBrush body = new SolidBrush(Color.White)) e.Graphics.FillPath(body, lockBody);
        using (SolidBrush key = new SolidBrush(Color.FromArgb(0, 105, 92))) e.Graphics.FillEllipse(key, 17, 19, 3, 3);
        using (SolidBrush stem = new SolidBrush(Color.FromArgb(0, 105, 92))) e.Graphics.FillRectangle(stem, 18, 21, 1, 4);
    }
    private static System.Drawing.Drawing2D.GraphicsPath RoundedRect(Rectangle bounds, int radius)
    {
        int d = radius * 2; System.Drawing.Drawing2D.GraphicsPath path = new System.Drawing.Drawing2D.GraphicsPath();
        path.AddArc(bounds.Left, bounds.Top, d, d, 180, 90); path.AddArc(bounds.Right - d, bounds.Top, d, d, 270, 90);
        path.AddArc(bounds.Right - d, bounds.Bottom - d, d, d, 0, 90); path.AddArc(bounds.Left, bounds.Bottom - d, d, d, 90, 90); path.CloseFigure(); return path;
    }
}

internal sealed class PinSetupDialog : Form
{
    private readonly TextBox first, second;
    public string Pin { get; private set; }
    public PinSetupDialog()
    {
        Text = "Hızlı açılış PIN'i"; Size = new Size(430, 310); StartPosition = FormStartPosition.CenterParent; FormBorderStyle = FormBorderStyle.FixedDialog; MaximizeBox = false; MinimizeBox = false; BackColor = Color.FromArgb(251,252,250); Font = new Font("Segoe UI", 9);
        Controls.Add(new Label { Text = "4 haneli PIN", Location = new Point(24, 20), AutoSize = true });
        first = new TextBox { Location = new Point(24, 45), Size = new Size(365, 30), UseSystemPasswordChar = true, MaxLength = 4, Font = new Font("Segoe UI", 12) }; Controls.Add(first);
        Controls.Add(new Label { Text = "PIN'i tekrar girin", Location = new Point(24, 87), AutoSize = true });
        second = new TextBox { Location = new Point(24, 112), Size = new Size(365, 30), UseSystemPasswordChar = true, MaxLength = 4, Font = new Font("Segoe UI", 12) }; Controls.Add(second);
        Controls.Add(new Label { Text = "PIN yalnızca bu Windows hesabında hızlı açılış içindir. Kasa dosyası ana parolanızla şifreli kalır.", Location = new Point(24, 157), Size = new Size(365, 54), ForeColor = Color.FromArgb(104,115,109) });
        Button cancel = new Button { Text = "İptal", Location = new Point(174, 220), Size = new Size(100, 36), DialogResult = DialogResult.Cancel };
        Button ok = new Button { Text = "PIN'i kaydet", Location = new Point(284, 220), Size = new Size(105, 36), BackColor = Color.FromArgb(30,101,78), ForeColor = Color.White, FlatStyle = FlatStyle.Flat };
        ok.Click += delegate
        {
            if (!IsFourDigitPin(first.Text) || !IsFourDigitPin(second.Text)) { MessageBox.Show("PIN tam olarak 4 rakamdan oluşmalı.", "Kasam", MessageBoxButtons.OK, MessageBoxIcon.Warning); return; }
            if (first.Text != second.Text) { MessageBox.Show("Girdiğiniz PIN'ler eşleşmiyor.", "Kasam", MessageBoxButtons.OK, MessageBoxIcon.Warning); return; }
            Pin = first.Text; DialogResult = DialogResult.OK; Close();
        };
        Controls.Add(cancel); Controls.Add(ok); AcceptButton = ok; CancelButton = cancel; Shown += delegate { first.Focus(); };
    }
    internal static bool IsFourDigitPin(string value)
    {
        if (value == null || value.Length != 4) return false;
        foreach (char c in value) if (c < '0' || c > '9') return false;
        return true;
    }
}

internal sealed class PinUnlockDialog : Form
{
    private readonly TextBox pinBox;
    public string Pin { get; private set; }
    public bool UseMasterPassword { get; private set; }
    public PinUnlockDialog(string message = "Kasayı açmak için 4 haneli PIN'inizi girin")
    {
        Text = "PIN ile kasayı aç"; Size = new Size(440, 240); StartPosition = FormStartPosition.CenterParent; FormBorderStyle = FormBorderStyle.FixedDialog; MaximizeBox = false; MinimizeBox = false; BackColor = Color.FromArgb(251,252,250); Font = new Font("Segoe UI", 9);
        Controls.Add(new Label { Text = message, Location = new Point(24, 20), AutoSize = true });
        pinBox = new TextBox { Location = new Point(24, 49), Size = new Size(365, 30), UseSystemPasswordChar = true, MaxLength = 4, Font = new Font("Segoe UI", 12) }; Controls.Add(pinBox);
        Button cancel = new Button { Text = "İptal", Location = new Point(24, 108), Size = new Size(95, 36), DialogResult = DialogResult.Cancel };
        Button master = new Button { Text = "Ana parolayla aç", Location = new Point(128, 108), Size = new Size(145, 36) };
        Button ok = new Button { Text = "Aç", Location = new Point(284, 108), Size = new Size(105, 36), BackColor = Color.FromArgb(30,101,78), ForeColor = Color.White, FlatStyle = FlatStyle.Flat };
        master.Click += delegate { UseMasterPassword = true; DialogResult = DialogResult.Cancel; Close(); };
        ok.Click += delegate
        {
            if (!PinSetupDialog.IsFourDigitPin(pinBox.Text)) { MessageBox.Show("PIN tam olarak 4 rakamdan oluşmalı.", "Kasam", MessageBoxButtons.OK, MessageBoxIcon.Warning); return; }
            Pin = pinBox.Text; DialogResult = DialogResult.OK; Close();
        };
        Controls.Add(cancel); Controls.Add(master); Controls.Add(ok); AcceptButton = ok; CancelButton = cancel; Shown += delegate { pinBox.Clear(); pinBox.Focus(); };
    }
}

internal sealed class EntryDialog : Form
{
    private readonly TextBox title, username, password, url, notes;
    private readonly ComboBox system;
    public VaultEntry Value { get; private set; }
    public EntryDialog(VaultEntry existing, IEnumerable<string> knownSystems)
    {
        bool edit = existing != null; Text = edit ? "Kaydı düzenle" : "Yeni hesap kaydı"; Size = new Size(520, 610); StartPosition = FormStartPosition.CenterParent; FormBorderStyle = FormBorderStyle.FixedDialog; MaximizeBox = false; BackColor = Color.FromArgb(251,252,250); Font = new Font("Segoe UI",9);
        int y = 20;
        Controls.Add(new Label { Text="Sistem *", Location=new Point(25,y), AutoSize=true, ForeColor=Color.FromArgb(31,41,37) }); y += 23;
        system = new ComboBox { Location=new Point(25,y), Width=350, DropDownStyle=ComboBoxStyle.DropDown, Font=new Font("Segoe UI",10), AutoCompleteMode=AutoCompleteMode.SuggestAppend, AutoCompleteSource=AutoCompleteSource.ListItems };
        List<string> options = new List<string> { "Google", "Apple", "Microsoft", "E-posta", "Banka", "Instagram", "Facebook", "WhatsApp", "Diğer" };
        foreach (string known in knownSystems) if (!options.Contains(known, StringComparer.CurrentCultureIgnoreCase)) options.Add(known);
        options.Sort(StringComparer.CurrentCultureIgnoreCase); system.Items.AddRange(options.ToArray()); Controls.Add(system); y += 40;
        Button addSystem = new Button { Text="Listeye ekle", Location=new Point(385,y-40), Size=new Size(90,30), FlatStyle=FlatStyle.Flat };
        addSystem.Click += delegate
        {
            string value = system.Text.Trim();
            if (value.Length == 0) { MessageBox.Show("Önce eklenecek sistem adını yazın.", "Kasam", MessageBoxButtons.OK, MessageBoxIcon.Information); return; }
            if (!system.Items.Contains(value)) system.Items.Add(value);
            system.Text = value;
        };
        Controls.Add(addSystem);
        title = AddField("Hesap adı *", ref y); username = AddField("Kullanıcı adı veya e-posta", ref y); password = AddField("Parola", ref y); password.UseSystemPasswordChar = true;
        Button generate = new Button { Text = "Güçlü parola üret", Location = new Point(25,y), Size = new Size(145,30), FlatStyle = FlatStyle.Flat };
        NumericUpDown length = new NumericUpDown { Minimum = 12, Maximum = 64, Value = 20, Location = new Point(244,y + 2), Width = 60 };
        Controls.Add(generate); Controls.Add(new Label { Text = "Uzunluk", Location = new Point(185,y + 7), AutoSize = true, ForeColor = Color.FromArgb(104,115,109) }); Controls.Add(length); y += 42;
        url = AddField("Web adresi", ref y); notes = AddField("Notlar", ref y, true);
        if (edit) { system.Text=existing.system; title.Text=existing.title; username.Text=existing.username; password.Text=existing.password; url.Text=existing.url; notes.Text=existing.notes; }
        generate.Click += delegate { password.Text = PasswordGenerator.Create((int)length.Value); password.UseSystemPasswordChar = false; };
        Button cancel = new Button { Text="İptal", Location=new Point(165,520), Size=new Size(96,38), DialogResult=DialogResult.Cancel };
        Button save = new Button { Text=edit ? "Değişiklikleri kaydet" : "Kaydı ekle", Location=new Point(270,520), Size=new Size(205,38), BackColor=Color.FromArgb(30,101,78), ForeColor=Color.White, FlatStyle=FlatStyle.Flat };
        save.Click += delegate
        {
            if (String.IsNullOrWhiteSpace(system.Text)) { MessageBox.Show("Parolanın ait olduğu sistemi seçin veya yazın.", "Kasam", MessageBoxButtons.OK, MessageBoxIcon.Warning); return; }
            if (String.IsNullOrWhiteSpace(title.Text)) { MessageBox.Show("Hesap adını girin.", "Kasam", MessageBoxButtons.OK, MessageBoxIcon.Warning); return; }
            Value = new VaultEntry { id=edit ? existing.id : Guid.NewGuid().ToString("N"), system=system.Text.Trim(), title=title.Text.Trim(), username=username.Text.Trim(), password=password.Text, url=url.Text.Trim(), notes=notes.Text.Trim() };
            DialogResult = DialogResult.OK; Close();
        };
        Controls.Add(cancel); Controls.Add(save); AcceptButton=save; CancelButton=cancel; Shown += delegate { title.Focus(); };
    }
    private TextBox AddField(string caption, ref int y, bool multiline=false)
    {
        Controls.Add(new Label { Text=caption, Location=new Point(25,y), AutoSize=true, ForeColor=Color.FromArgb(31,41,37) }); y+=23;
        TextBox box = new TextBox { Location=new Point(25,y), Width=450, Font=new Font("Segoe UI",10), Multiline=multiline, Height=multiline ? 78 : 27, ScrollBars=multiline ? ScrollBars.Vertical : ScrollBars.None };
        Controls.Add(box); y += multiline ? 91 : 39; return box;
    }
}

internal static class PasswordGenerator
{
    private static int Pick(int count)
    {
        uint range = (uint)(256 / count * count); byte[] b = new byte[1];
        using (RandomNumberGenerator rng = RandomNumberGenerator.Create()) { do { rng.GetBytes(b); } while (b[0] >= range); }
        return b[0] % count;
    }
    public static string Create(int length)
    {
        string[] groups = { "ABCDEFGHJKLMNPQRSTUVWXYZ", "abcdefghijkmnopqrstuvwxyz", "23456789", "!@#$%&*+-_=?" };
        string all = String.Join("", groups); List<char> chars = new List<char>();
        foreach (string group in groups) chars.Add(group[Pick(group.Length)]);
        while (chars.Count < length) chars.Add(all[Pick(all.Length)]);
        for (int i=chars.Count-1; i>0; i--) { int j=Pick(i+1); char t=chars[i]; chars[i]=chars[j]; chars[j]=t; }
        return new String(chars.ToArray());
    }
}

