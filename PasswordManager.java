import javax.swing.*;
import javax.swing.border.*;
import javax.swing.table.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.*;
import java.awt.event.*;
import java.awt.geom.*;
import java.awt.datatransfer.*;
import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.List;
import java.util.Timer;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.awt.image.BufferedImage;
import javax.imageio.ImageIO;

// ======================== SECURE EXPORTER INTERFACES ========================
interface SecureExporter {
    void export(PasswordManager.PasswordEntry entry, String password) throws Exception;
}

interface SecureImporter {
    PasswordManager.PasswordEntry importData(File file, String password) throws Exception;
}

// ======================== SECURE IMAGE EXPORTER ========================
class SecureImageExporter implements SecureExporter {

    private byte[] generateSalt() {
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        return salt;
    }

    private SecretKey getKey(String password, byte[] salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 100000, 256);
        byte[] key = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
        return new SecretKeySpec(key, "AES");
    }

    private String encrypt(String data, String password, byte[] salt, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, getKey(password, salt), new GCMParameterSpec(128, iv));
        byte[] encrypted = cipher.doFinal(data.getBytes("UTF-8"));
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(salt);
        out.write(iv);
        out.write(encrypted);
        return Base64.getEncoder().encodeToString(out.toByteArray());
    }

    public void export(PasswordManager.PasswordEntry entry, String password) throws Exception {
        String json = "{ \"site\":\"" + entry.siteName + "\", \"user\":\"" + entry.username + "\", \"pass\":\"" + entry.encryptedPassword + "\" }";

        byte[] salt = generateSalt();
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);

        String encrypted = encrypt(json, password, salt, iv);

        // Custom image rendering
        int width = 500;
        int height = 300;
        BufferedImage img = new BufferedImage(width, height, BufferedImage.TYPE_INT_RGB);

        Graphics2D g = img.createGraphics();
        g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);

        // Background gradient
        GradientPaint gp = new GradientPaint(0, 0, new Color(30, 30, 60), width, height, new Color(10, 10, 25));
        g.setPaint(gp);
        g.fillRect(0, 0, width, height);

        // Card
        g.setColor(new Color(20, 20, 40, 220));
        g.fillRoundRect(20, 20, width - 40, height - 40, 20, 20);

        // Title
        g.setColor(Color.WHITE);
        g.setFont(new Font("Segoe UI", Font.BOLD, 20));
        g.drawString("VaultKeeper Secure Export", 40, 60);

        // Labels
        g.setFont(new Font("Segoe UI", Font.PLAIN, 14));
        g.setColor(new Color(180, 180, 220));

        g.drawString("Site:", 40, 110);
        g.drawString("Username:", 40, 140);
        g.drawString("Encrypted:", 40, 170);

        // Values
        g.setColor(Color.WHITE);
        g.drawString(entry.siteName, 150, 110);
        g.drawString(entry.username, 150, 140);

        // Show partial encrypted preview
        String preview = encrypted.substring(0, Math.min(30, encrypted.length())) + "...";
        g.setFont(new Font("Consolas", Font.PLAIN, 12));
        g.drawString(preview, 150, 170);

        g.dispose();

        // Hidden data embedding at bottom pixels
        byte[] data = encrypted.getBytes("UTF-8");
        int y = height - 1;
        int x = 0;

        for (int i = 0; i < data.length; i++) {
            int val = data[i] & 0xFF;
            img.setRGB(x, y, (val << 16) | (val << 8) | val);
            x++;
            if (x >= width) {
                x = 0;
                y--;
                if (y < height - 50) break; // limit hidden area
            }
        }

        String path = System.getProperty("user.home") + "/Desktop/secure_export.vault.png";
        ImageIO.write(img, "png", new File(path));
    }
}



// ======================== SECURE IMAGE IMPORTER ========================
class SecureImageImporter implements SecureImporter {

    private SecretKey getKey(String password, byte[] salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 100000, 256);
        byte[] key = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
        return new SecretKeySpec(key, "AES");
    }

    private String decrypt(String base64, String password) throws Exception {
        byte[] data = Base64.getDecoder().decode(base64);
        byte[] salt = Arrays.copyOfRange(data, 0, 16);
        byte[] iv = Arrays.copyOfRange(data, 16, 28);
        byte[] encrypted = Arrays.copyOfRange(data, 28, data.length);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, getKey(password, salt), new GCMParameterSpec(128, iv));
        return new String(cipher.doFinal(encrypted), "UTF-8");
    }

    public PasswordManager.PasswordEntry importData(File file, String password) throws Exception {
        BufferedImage img = ImageIO.read(file);

        StringBuilder sb = new StringBuilder();

        for (int y = img.getHeight() - 1; y >= img.getHeight() - 50; y--) {
            for (int x = 0; x < img.getWidth(); x++) {
                int rgb = img.getRGB(x, y);
                int val = (rgb >> 16) & 0xFF;

                if (val == 0) break;
                sb.append((char) val);
            }
        }

        String encrypted = sb.toString().trim();
        String json = decrypt(encrypted, password);

        String site = json.split("\"site\":\"")[1].split("\"")[0];
        String user = json.split("\"user\":\"")[1].split("\"")[0];
        String pass = json.split("\"pass\":\"")[1].split("\"")[0];

        return new PasswordManager.PasswordEntry(site, "", user, pass, "Imported", "");
    }
}




public class PasswordManager extends JFrame {

    // ======================== DATA MODELS ========================
    static class PasswordEntry implements Serializable {
        private static final long serialVersionUID = 1L;
        String id, siteName, siteUrl, username, encryptedPassword, category, notes;
        long createdAt, modifiedAt;
        int expiryDays = 90;
        PasswordEntry(String site, String url, String user, String encPass, String cat, String notes) {
            this.id = UUID.randomUUID().toString();
            this.siteName = site; this.siteUrl = url; this.username = user;
            this.encryptedPassword = encPass; this.category = cat; this.notes = notes;
            this.createdAt = this.modifiedAt = System.currentTimeMillis();
        }
        boolean isExpired() {
            long age = System.currentTimeMillis() - modifiedAt;
            return age > (long) expiryDays * 24 * 60 * 60 * 1000;
        }
        boolean isExpiringSoon() {
            long age = System.currentTimeMillis() - modifiedAt;
            long threshold = (long)(expiryDays * 0.8) * 24 * 60 * 60 * 1000;
            return age > threshold && !isExpired();
        }
        int daysUntilExpiry() {
            long age = System.currentTimeMillis() - modifiedAt;
            long remaining = (long) expiryDays * 24 * 60 * 60 * 1000 - age;
            return Math.max(0, (int)(remaining / (24 * 60 * 60 * 1000)));
        }
        String getAgeString() {
            long age = System.currentTimeMillis() - modifiedAt;
            int days = (int)(age / (24 * 60 * 60 * 1000));
            if (days == 0) return "Today";
            if (days == 1) return "1 day ago";
            if (days < 30) return days + " days ago";
            if (days < 365) return (days / 30) + " months ago";
            return (days / 365) + " years ago";
        }
    }

    static class LoginActivity implements Serializable {
        private static final long serialVersionUID = 1L;

        long lastLoginTime = 0;
        int totalLoginCount = 0;
        int failedAttempts = 0;
        long lockUntil = 0;
        List<Long> loginHistory;

        LoginActivity() {
            loginHistory = new ArrayList<>();
        }

        // Ensure list is never null after deserialization
        private Object readResolve() {
            if (loginHistory == null) {
                loginHistory = new ArrayList<>();
            }
            return this;
        }
    }

    static class UserData implements Serializable {
        private static final long serialVersionUID = 2L;
        byte[] masterHash, salt;
        List<PasswordEntry> entries = new ArrayList<>();
        boolean darkMode = true;
        int autoLockMinutes = 5;
        LoginActivity loginActivity = new LoginActivity();
    }

    // ======================== CRYPTO ENGINE ========================
    static class CryptoEngine {
        static byte[] generateSalt() {
            byte[] salt = new byte[32];
            new SecureRandom().nextBytes(salt);
            return salt;
        }
        static byte[] hashPassword(String password, byte[] salt) throws Exception {
            PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 100000, 256);
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
        }
        static String encrypt(String plaintext, String masterPassword, byte[] salt) throws Exception {
            byte[] key = hashPassword(masterPassword, salt);
            SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            byte[] iv = new byte[12]; new SecureRandom().nextBytes(iv);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, new GCMParameterSpec(128, iv));
            byte[] encrypted = cipher.doFinal(plaintext.getBytes("UTF-8"));
            byte[] combined = new byte[iv.length + encrypted.length];
            System.arraycopy(iv, 0, combined, 0, iv.length);
            System.arraycopy(encrypted, 0, combined, iv.length, encrypted.length);
            return Base64.getEncoder().encodeToString(combined);
        }
        static String decrypt(String ciphertext, String masterPassword, byte[] salt) throws Exception {
            byte[] combined = Base64.getDecoder().decode(ciphertext);
            byte[] iv = Arrays.copyOfRange(combined, 0, 12);
            byte[] encrypted = Arrays.copyOfRange(combined, 12, combined.length);
            byte[] key = hashPassword(masterPassword, salt);
            SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, keySpec, new GCMParameterSpec(128, iv));
            return new String(cipher.doFinal(encrypted), "UTF-8");
        }
        static String generatePassword(int length, boolean upper, boolean lower, boolean digits, boolean symbols) {
            String chars = "";
            if (upper) chars += "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            if (lower) chars += "abcdefghijklmnopqrstuvwxyz";
            if (digits) chars += "0123456789";
            if (symbols) chars += "!@#$%^&*()_+-=[]{}|;:,.<>?";
            if (chars.isEmpty()) chars = "abcdefghijklmnopqrstuvwxyz0123456789";
            SecureRandom rng = new SecureRandom();
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < length; i++) sb.append(chars.charAt(rng.nextInt(chars.length())));
            return sb.toString();
        }
        static int getPasswordStrength(String password) {
            if (password == null || password.isEmpty()) return 0;
            int score = 0;
            if (password.length() >= 8) score++; if (password.length() >= 12) score++; if (password.length() >= 16) score++;
            if (password.matches(".*[A-Z].*")) score++;
            if (password.matches(".*[a-z].*")) score++;
            if (password.matches(".*\\d.*")) score++;
            if (password.matches(".*[^A-Za-z0-9].*")) score++;
            return Math.min(score, 5);
        }
    }

    // ======================== STORAGE ========================
    static class Storage {
        static final String FILE = System.getProperty("user.home") + File.separator + ".vaultkeeper_data";
        static final String ACTIVITY_FILE = System.getProperty("user.home") + File.separator + ".vaultkeeper_login_activity.dat";
        static final String BACKUP_DIR = System.getProperty("user.home") + File.separator + ".vaultkeeper_backups";

        static void save(UserData data) {
            createBackup();
            try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(FILE))) {
                oos.writeObject(data);
            } catch (Exception e) { e.printStackTrace(); }
        }
        static UserData load() {
    File f = new File(FILE);
    if (!f.exists() || f.length() < 10) return null;

    try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(f))) {
        return (UserData) ois.readObject();
    } catch (Exception e) {
        e.printStackTrace();
        return null;
    }
}
        static boolean exists() { return new File(FILE).exists(); }

        static void saveLoginActivity(LoginActivity activity) {
            try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(ACTIVITY_FILE))) {
                oos.writeObject(activity);
            } catch (Exception e) { e.printStackTrace(); }
        }
        static LoginActivity loadLoginActivity() {
            try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(ACTIVITY_FILE))) {
                return (LoginActivity) ois.readObject();
            } catch (Exception e) { return new LoginActivity(); }
        }

        static void createBackup() {
            File src = new File(FILE);
            if (!src.exists()) return;
            File backupDir = new File(BACKUP_DIR);
            if (!backupDir.exists()) backupDir.mkdirs();
            String timestamp = new SimpleDateFormat("yyyyMMdd_HHmmss").format(new Date());
            File dest = new File(backupDir, "backup_" + timestamp + ".dat");
            try { Files.copy(src.toPath(), dest.toPath(), StandardCopyOption.REPLACE_EXISTING); } catch (Exception e) { e.printStackTrace(); }
            pruneBackups(5);
        }
        static void pruneBackups(int max) {
            File backupDir = new File(BACKUP_DIR);
            if (!backupDir.exists()) return;
            File[] files = backupDir.listFiles((d, n) -> n.startsWith("backup_") && n.endsWith(".dat"));
            if (files == null || files.length <= max) return;
            Arrays.sort(files, Comparator.comparingLong(File::lastModified));
            for (int i = 0; i < files.length - max; i++) files[i].delete();
        }
        static File[] getBackups() {
            File backupDir = new File(BACKUP_DIR);
            if (!backupDir.exists()) return new File[0];
            File[] files = backupDir.listFiles((d, n) -> n.startsWith("backup_") && n.endsWith(".dat"));
            if (files == null) return new File[0];
            Arrays.sort(files, Comparator.comparingLong(File::lastModified).reversed());
            return files;
        }
        static boolean restoreBackup(File backup) {
            try {
                Files.copy(backup.toPath(), new File(FILE).toPath(), StandardCopyOption.REPLACE_EXISTING);
                return true;
            } catch (Exception e) { return false; }
        }
    }

    // ======================== THEME ENGINE ========================
    static class Theme {
        Color bgDark, bgCard, bgInput, accent, accentHover, success, warning, danger;
        Color textPrimary, textSecondary, border;
        Color gradStart1, gradEnd1, gradStart2, gradEnd2;
        String name;

        static Theme dark() {
            Theme t = new Theme();
            t.name = "dark";
            t.bgDark = new Color(10, 10, 18);
            t.bgCard = new Color(18, 18, 30);
            t.bgInput = new Color(26, 26, 42);
            t.accent = new Color(99, 102, 241);
            t.accentHover = new Color(129, 140, 248);
            t.success = new Color(52, 211, 153);
            t.warning = new Color(251, 191, 36);
            t.danger = new Color(248, 113, 113);
            t.textPrimary = new Color(237, 237, 245);
            t.textSecondary = new Color(148, 148, 170);
            t.border = new Color(38, 38, 58);
            t.gradStart1 = new Color(99, 102, 241);
            t.gradEnd1 = new Color(168, 85, 247);
            t.gradStart2 = new Color(15, 15, 30);
            t.gradEnd2 = new Color(30, 20, 50);
            return t;
        }
        static Theme light() {
            Theme t = new Theme();
            t.name = "light";
            t.bgDark = new Color(245, 245, 252);
            t.bgCard = new Color(255, 255, 255);
            t.bgInput = new Color(240, 240, 248);
            t.accent = new Color(79, 70, 229);
            t.accentHover = new Color(99, 102, 241);
            t.success = new Color(16, 185, 129);
            t.warning = new Color(217, 119, 6);
            t.danger = new Color(220, 38, 38);
            t.textPrimary = new Color(15, 23, 42);
            t.textSecondary = new Color(100, 116, 139);
            t.border = new Color(226, 232, 240);
            t.gradStart1 = new Color(79, 70, 229);
            t.gradEnd1 = new Color(147, 51, 234);
            t.gradStart2 = new Color(238, 238, 248);
            t.gradEnd2 = new Color(248, 240, 255);
            return t;
        }
    }

    // ======================== TOAST NOTIFICATION SYSTEM ========================
    static class ToastManager {
        private final JFrame parent;
        private final List<JWindow> toasts = new ArrayList<>();

        ToastManager(JFrame parent) { this.parent = parent; }

        void show(String message, String type, int durationMs) {
            SwingUtilities.invokeLater(() -> {
                JWindow toast = new JWindow(parent);
                toast.setAlwaysOnTop(true);

                Color bg, fg, borderColor;
                String icon;
                switch (type) {
                    case "success": bg = new Color(16, 185, 129, 230); fg = Color.WHITE; borderColor = new Color(52, 211, 153); icon = "✓"; break;
                    case "error":   bg = new Color(220, 38, 38, 230);  fg = Color.WHITE; borderColor = new Color(248, 113, 113); icon = "✕"; break;
                    case "warning": bg = new Color(217, 119, 6, 230);  fg = Color.WHITE; borderColor = new Color(251, 191, 36); icon = "⚠"; break;
                    default:        bg = new Color(99, 102, 241, 230); fg = Color.WHITE; borderColor = new Color(129, 140, 248); icon = "ℹ"; break;
                }

                JPanel panel = new JPanel(new BorderLayout(10, 0)) {
                    protected void paintComponent(Graphics g) {
                        Graphics2D g2 = (Graphics2D) g.create();
                        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                        g2.setColor(bg);
                        g2.fillRoundRect(0, 0, getWidth(), getHeight(), 16, 16);
                        g2.setColor(borderColor);
                        g2.setStroke(new BasicStroke(1.5f));
                        g2.drawRoundRect(0, 0, getWidth()-1, getHeight()-1, 16, 16);
                        g2.dispose();
                    }
                };
                panel.setOpaque(false);
                panel.setBorder(BorderFactory.createEmptyBorder(12, 18, 12, 18));

                JLabel iconLabel = new JLabel(icon);
                iconLabel.setFont(new Font("Segoe UI", Font.BOLD, 16));
                iconLabel.setForeground(fg);
                panel.add(iconLabel, BorderLayout.WEST);

                JLabel msgLabel = new JLabel(message);
                msgLabel.setFont(new Font("Segoe UI", Font.PLAIN, 13));
                msgLabel.setForeground(fg);
                panel.add(msgLabel, BorderLayout.CENTER);

                toast.getContentPane().add(panel);
                toast.setSize(350, 48);
                toast.setBackground(new Color(0, 0, 0, 0));

                int x = parent.getX() + parent.getWidth() - 370;
                int yBase = parent.getY() + 70;
                int offset = toasts.size() * 58;
                toast.setLocation(x, yBase + offset);

                toasts.add(toast);
                toast.setVisible(true);

                new Timer().schedule(new TimerTask() {
                    public void run() {
                        SwingUtilities.invokeLater(() -> {
                            toast.dispose();
                            toasts.remove(toast);
                        });
                    }
                }, durationMs);
            });
        }
    }

    // ======================== ANIMATION ENGINE ========================
    static class AnimationEngine {
        static void fadeIn(JComponent component, int durationMs) {
            component.setVisible(true);
            Timer timer = new Timer();
            final long start = System.currentTimeMillis();
            timer.scheduleAtFixedRate(new TimerTask() {
                public void run() {
                    float elapsed = System.currentTimeMillis() - start;
                    float progress = Math.min(elapsed / durationMs, 1f);
                    SwingUtilities.invokeLater(() -> {
                        component.putClientProperty("fadeAlpha", easeOutCubic(progress));
                        component.repaint();
                    });
                    if (progress >= 1f) timer.cancel();
                }
            }, 0, 16);
        }
        static void pulse(JComponent component, int durationMs) {
            Timer timer = new Timer();
            final long start = System.currentTimeMillis();
            timer.scheduleAtFixedRate(new TimerTask() {
                public void run() {
                    float elapsed = System.currentTimeMillis() - start;
                    float progress = Math.min(elapsed / durationMs, 1f);
                    SwingUtilities.invokeLater(() -> {
                        component.putClientProperty("pulseScale", 1f + 0.05f * (float)Math.sin(progress * Math.PI));
                        component.repaint();
                    });
                    if (progress >= 1f) timer.cancel();
                }
            }, 0, 16);
        }
        static float easeOutCubic(float t) { return 1f - (float)Math.pow(1 - t, 3); }
    }

    // ======================== FONTS ========================
    static final Font FONT_TITLE = new Font("Segoe UI", Font.BOLD, 32);
    static final Font FONT_SUBTITLE = new Font("Segoe UI", Font.PLAIN, 16);
    static final Font FONT_BODY = new Font("Segoe UI", Font.PLAIN, 14);
    static final Font FONT_SMALL = new Font("Segoe UI", Font.PLAIN, 12);
    static final Font FONT_BUTTON = new Font("Segoe UI", Font.BOLD, 13);
    static final Font FONT_MONO = new Font("Consolas", Font.PLAIN, 14);

    // ======================== STATE ========================
    private UserData userData;
    private String masterPassword;
    private CardLayout cardLayout;
    private JPanel mainPanel;
    private float splashProgress = 0f;
    private Theme theme = Theme.dark();
    private Timer autoLockTimer;
    private long lastActivityTime;
    private JLabel autoLockLabel;
    private ToastManager toastManager;
    private LoginActivity loginActivity;

    // Dashboard components
    private JPanel dashPanel;
    private DefaultTableModel tableModel;
    private JTable table;
    private JTextField searchField;
    private JComboBox<String> categoryFilter;
    private JComboBox<String> sortFilter;
    private JLabel countLabel;

    // ======================== CONSTRUCTOR ========================
    public PasswordManager() {
        setTitle("VaultKeeper — Premium Password Manager");
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setSize(1100, 750);
        setMinimumSize(new Dimension(850, 620));
        setLocationRelativeTo(null);
        getContentPane().setBackground(theme.bgDark);

        toastManager = new ToastManager(this);
        loginActivity = Storage.loadLoginActivity();
        if (loginActivity == null) {
            loginActivity = new LoginActivity();
        }

        cardLayout = new CardLayout();
        mainPanel = new JPanel(cardLayout);
        mainPanel.setBackground(theme.bgDark);

        mainPanel.add(createSplashScreen(), "splash");
        mainPanel.add(createAuthScreen(), "auth");
        mainPanel.add(createDashboard(), "dashboard");

        add(mainPanel);

        Toolkit.getDefaultToolkit().addAWTEventListener(e -> resetAutoLock(),
            AWTEvent.KEY_EVENT_MASK | AWTEvent.MOUSE_EVENT_MASK | AWTEvent.MOUSE_MOTION_EVENT_MASK);

        setupShortcuts();
        setVisible(true);
        startSplashAnimation();
        new javax.swing.Timer(16, e -> repaint()).start();
    }

    // ======================== GRADIENT PANEL ========================
    private JPanel createGradientPanel(LayoutManager layout) {
        return new JPanel(layout) {
            protected void paintComponent(Graphics g) {
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                int w = getWidth(), h = getHeight();
                g2.setPaint(new GradientPaint(0, 0, theme.gradStart2, w, h, theme.gradEnd2));
                g2.fillRect(0, 0, w, h);
                // Subtle radial glow top-right
                g2.setComposite(AlphaComposite.getInstance(AlphaComposite.SRC_OVER, 0.08f));
                g2.setPaint(new RadialGradientPaint(w * 0.8f, h * 0.1f, w * 0.6f,
                    new float[]{0, 1}, new Color[]{theme.accent, new Color(0,0,0,0)}));
                g2.fillRect(0, 0, w, h);
                // Subtle radial glow bottom-left
                g2.setPaint(new RadialGradientPaint(w * 0.15f, h * 0.85f, w * 0.5f,
                    new float[]{0, 1}, new Color[]{theme.gradEnd1, new Color(0,0,0,0)}));
                g2.fillRect(0, 0, w, h);
                // Floating bubbles animation
                long t = System.currentTimeMillis();
                g2.setComposite(AlphaComposite.getInstance(AlphaComposite.SRC_OVER, 0.08f));
                for (int i = 0; i < 5; i++) {
                    double bx = (Math.sin(t * 0.0007 + i) * 0.5 + 0.5) * w;
                    double by = (Math.cos(t * 0.0009 + i) * 0.5 + 0.5) * h;
                    int size = 200 + i * 40;
                    g2.setColor(theme.accent);
                    g2.fillOval((int)bx - size/2, (int)by - size/2, size, size);
                }
                g2.setComposite(AlphaComposite.getInstance(AlphaComposite.SRC_OVER, 1f));
                g2.dispose();
            }
        };
    }

    // ======================== AUTO-LOCK ========================
    private void resetAutoLock() { lastActivityTime = System.currentTimeMillis(); }

    private void startAutoLockTimer() {
        if (autoLockTimer != null) autoLockTimer.cancel();
        lastActivityTime = System.currentTimeMillis();
        autoLockTimer = new Timer();
        autoLockTimer.scheduleAtFixedRate(new TimerTask() {
            public void run() {
                if (masterPassword == null) return;
                int lockMinutes = (userData != null) ? userData.autoLockMinutes : 5;
                long elapsed = System.currentTimeMillis() - lastActivityTime;
                long remaining = (long)lockMinutes * 60 * 1000 - elapsed;
                if (remaining <= 0) {
                    SwingUtilities.invokeLater(() -> lockVault());
                } else {
                    int secs = (int)(remaining / 1000);
                    int mins = secs / 60; secs %= 60;
                    String timeStr = String.format("Auto-lock: %d:%02d", mins, secs);
                    SwingUtilities.invokeLater(() -> {
                        if (autoLockLabel != null) {
                            autoLockLabel.setText("  ⏱ " + timeStr);
                            autoLockLabel.setForeground(remaining < 30000 ? theme.danger : remaining < 60000 ? theme.warning : theme.textSecondary);
                        }
                    });
                }
            }
        }, 0, 1000);
    }

    private void stopAutoLockTimer() { if (autoLockTimer != null) { autoLockTimer.cancel(); autoLockTimer = null; } }

    private void lockVault() {
        stopAutoLockTimer();
        masterPassword = null;
        userData = null;
        rebuildUI();
        cardLayout.show(mainPanel, "auth");
        toastManager.show("Vault locked", "info", 2000);
    }

    private void rebuildUI() {
        mainPanel.removeAll();
        mainPanel.add(createSplashScreen(), "splash");
        mainPanel.add(createAuthScreen(), "auth");
        mainPanel.add(createDashboard(), "dashboard");
        mainPanel.revalidate();
        mainPanel.repaint();
    }

    // ======================== SPLASH SCREEN ========================
    private JPanel createSplashScreen() {
        return new JPanel() {
            { setOpaque(false); }
            protected void paintComponent(Graphics g) {
                super.paintComponent(g);
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                g2.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_LCD_HRGB);
                int w = getWidth(), h = getHeight();

                // Gradient background
                g2.setPaint(new GradientPaint(0, 0, theme.gradStart2, w, h, theme.gradEnd2));
                g2.fillRect(0, 0, w, h);

                // Animated particles
                long t = System.currentTimeMillis();
                g2.setComposite(AlphaComposite.getInstance(AlphaComposite.SRC_OVER, 0.12f));
                for (int i = 0; i < 60; i++) {
                    double x = (Math.sin(t * 0.001 + i * 1.3) * 0.5 + 0.5) * w;
                    double y = (Math.cos(t * 0.0008 + i * 0.9) * 0.5 + 0.5) * h;
                    float size = (float)(2 + Math.sin(t * 0.002 + i) * 3);
                    g2.setColor(theme.accent);
                    g2.fill(new Ellipse2D.Float((float)x, (float)y, size, size));
                }
                g2.setComposite(AlphaComposite.getInstance(AlphaComposite.SRC_OVER, 1f));

                int cx = w / 2, cy = h / 2 - 60;
                drawShieldIcon(g2, cx, cy, 50, splashProgress);

                g2.setFont(new Font("Segoe UI", Font.BOLD, 42));
                String title = "VaultKeeper";
                FontMetrics fm = g2.getFontMetrics();
                int tx = cx - fm.stringWidth(title) / 2, ty = cy + 90;
                g2.setPaint(new GradientPaint(tx, ty - 30, theme.gradStart1, tx + fm.stringWidth(title), ty, theme.gradEnd1));
                g2.drawString(title, tx, ty);

                g2.setFont(FONT_SUBTITLE);
                g2.setColor(theme.textSecondary);
                String sub = "Your passwords, encrypted & protected";
                fm = g2.getFontMetrics();
                g2.drawString(sub, cx - fm.stringWidth(sub) / 2, ty + 35);

                int barW = 300, barH = 4;
                int barX = cx - barW / 2, barY = ty + 70;
                g2.setColor(theme.border);
                g2.fillRoundRect(barX, barY, barW, barH, barH, barH);
                g2.setPaint(new GradientPaint(barX, barY, theme.gradStart1, barX + barW, barY, theme.gradEnd1));
                g2.fillRoundRect(barX, barY, (int)(barW * splashProgress), barH, barH, barH);
                // Glow effect
                g2.setComposite(AlphaComposite.getInstance(AlphaComposite.SRC_OVER, 0.6f));
                g2.setColor(theme.accentHover);
                g2.fillOval(barX + (int)(barW * splashProgress) - 6, barY - 4, 12, 12);
                g2.setComposite(AlphaComposite.getInstance(AlphaComposite.SRC_OVER, 1f));

                // Spiral animation
                long time = System.currentTimeMillis();
                g2.setStroke(new BasicStroke(1.5f));
                g2.setColor(new Color(theme.accent.getRed(), theme.accent.getGreen(), theme.accent.getBlue(), 80));
                for (int i = 0; i < 3; i++) {
                    double angle = time * 0.001 + i * 2;
                    int radius = 120 + i * 20;
                    int sx = (int)(cx + Math.cos(angle) * radius);
                    int sy = (int)(cy + Math.sin(angle) * radius);
                    g2.drawOval(sx - 20, sy - 20, 40, 40);
                }
                g2.dispose();
            }
        };
    }

    private void drawShieldIcon(Graphics2D g2, int cx, int cy, int size, float progress) {
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        float alpha = Math.min(progress * 2, 1f);
        g2.setComposite(AlphaComposite.getInstance(AlphaComposite.SRC_OVER, alpha * 0.15f));
        g2.setPaint(new RadialGradientPaint(cx, cy, size * 2, new float[]{0, 1}, new Color[]{theme.accent, new Color(0,0,0,0)}));
        g2.fillOval(cx - size * 2, cy - size * 2, size * 4, size * 4);

        g2.setComposite(AlphaComposite.getInstance(AlphaComposite.SRC_OVER, alpha));
        Path2D shield = new Path2D.Double();
        shield.moveTo(cx, cy - size);
        shield.curveTo(cx + size * 0.8, cy - size * 0.6, cx + size, cy - size * 0.2, cx + size * 0.8, cy + size * 0.4);
        shield.lineTo(cx, cy + size);
        shield.lineTo(cx - size * 0.8, cy + size * 0.4);
        shield.curveTo(cx - size, cy - size * 0.2, cx - size * 0.8, cy - size * 0.6, cx, cy - size);
        shield.closePath();

        g2.setPaint(new GradientPaint(cx - size, cy, theme.gradStart1, cx + size, cy, theme.gradEnd1));
        g2.fill(shield);
        g2.setColor(new Color(255, 255, 255, 40));
        g2.setStroke(new BasicStroke(2f));
        g2.draw(shield);

        if (progress > 0.5f) {
            float checkAlpha = Math.min((progress - 0.5f) * 4, 1f);
            g2.setComposite(AlphaComposite.getInstance(AlphaComposite.SRC_OVER, checkAlpha));
            g2.setColor(Color.WHITE);
            g2.setStroke(new BasicStroke(3f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));
            int s = size / 3;
            g2.drawLine(cx - s, cy, cx - s / 3, cy + s);
            g2.drawLine(cx - s / 3, cy + s, cx + s, cy - s);
        }
        g2.setComposite(AlphaComposite.getInstance(AlphaComposite.SRC_OVER, 1f));
    }

    private void startSplashAnimation() {
        Timer timer = new Timer();
        final long start = System.currentTimeMillis();
        timer.scheduleAtFixedRate(new TimerTask() {
            public void run() {
                float elapsed = System.currentTimeMillis() - start;
                splashProgress = Math.min(elapsed / 2000f, 1f);
                mainPanel.repaint();
                if (splashProgress >= 1f) {
                    timer.cancel();
                    SwingUtilities.invokeLater(() -> cardLayout.show(mainPanel, "auth"));
                }
            }
        }, 0, 16);
    }

    // ======================== AUTH SCREEN ========================
    private JPanel createAuthScreen() {
        // Ensure loginActivity is never null
        if (loginActivity == null) {
            loginActivity = new LoginActivity();
        }
        JPanel panel = createGradientPanel(new GridBagLayout());

       boolean isNew = !new File(Storage.FILE).exists();

        // Glass card
        JPanel card = new JPanel() {
            protected void paintComponent(Graphics g) {
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                g2.setColor(new Color(theme.bgCard.getRed(), theme.bgCard.getGreen(), theme.bgCard.getBlue(), 220));
                g2.fillRoundRect(0, 0, getWidth(), getHeight(), 24, 24);
                g2.setColor(theme.border);
                g2.setStroke(new BasicStroke(1f));
                g2.drawRoundRect(0, 0, getWidth()-1, getHeight()-1, 24, 24);
                g2.dispose();
            }
        };
        card.setOpaque(false);
        card.setLayout(new BoxLayout(card, BoxLayout.Y_AXIS));
        card.setBorder(BorderFactory.createEmptyBorder(40, 45, 40, 45));
        card.setPreferredSize(new Dimension(420, isNew ? 520 : 530));

        // Shield icon
        JPanel shieldPanel = new JPanel() {
            { setOpaque(false); setPreferredSize(new Dimension(80, 80)); setMaximumSize(new Dimension(80, 80)); }
            protected void paintComponent(Graphics g) {
                Graphics2D g2 = (Graphics2D) g.create();
                drawShieldIcon(g2, 40, 40, 30, 1f);
                g2.dispose();
            }
        };
        shieldPanel.setAlignmentX(Component.CENTER_ALIGNMENT);
        card.add(shieldPanel);
        card.add(Box.createVerticalStrut(15));

        JLabel titleLabel = styledLabel("VaultKeeper", new Font("Segoe UI", Font.BOLD, 26), theme.textPrimary);
        titleLabel.setAlignmentX(Component.CENTER_ALIGNMENT);
        card.add(titleLabel);

        JLabel subLabel = styledLabel(isNew ? "Create your master password" : "Enter your master password", FONT_SUBTITLE, theme.textSecondary);
        subLabel.setAlignmentX(Component.CENTER_ALIGNMENT);
        card.add(subLabel);
        card.add(Box.createVerticalStrut(8));

        // Login activity info
        if (!isNew && loginActivity.totalLoginCount > 0) {
            String lastLogin = loginActivity.lastLoginTime > 0 ?
                new SimpleDateFormat("MMM dd, yyyy HH:mm").format(new Date(loginActivity.lastLoginTime)) : "Never";
            JLabel activityLabel = styledLabel("Last login: " + lastLogin + "  |  Total: " + loginActivity.totalLoginCount, FONT_SMALL, theme.textSecondary);
            activityLabel.setAlignmentX(Component.CENTER_ALIGNMENT);
            card.add(activityLabel);
        }

        // Lock check
        if (loginActivity.lockUntil > System.currentTimeMillis()) {
            long remainSec = (loginActivity.lockUntil - System.currentTimeMillis()) / 1000;
            JLabel lockLabel = styledLabel("Account locked. Try again in " + remainSec + "s", FONT_BODY, theme.danger);
            lockLabel.setAlignmentX(Component.CENTER_ALIGNMENT);
            card.add(Box.createVerticalStrut(10));
            card.add(lockLabel);
            // start countdown timer
            Timer lockTimer = new Timer();
            lockTimer.scheduleAtFixedRate(new TimerTask() {
                public void run() {
                    long rem = (loginActivity.lockUntil - System.currentTimeMillis()) / 1000;
                    if (rem <= 0) {
                        lockTimer.cancel();
                        SwingUtilities.invokeLater(() -> { rebuildUI(); cardLayout.show(mainPanel, "auth"); });
                    } else {
                        SwingUtilities.invokeLater(() -> lockLabel.setText("Account locked. Try again in " + rem + "s"));
                    }
                }
            }, 0, 1000);
            panel.add(card);
            return panel;
        }

        card.add(Box.createVerticalStrut(25));

        card.add(wrapLeft(styledLabel("Master Password", FONT_SMALL, theme.textSecondary)));
        card.add(Box.createVerticalStrut(6));
        JPanel passRow = new JPanel(new BorderLayout(6, 0));
        passRow.setOpaque(false);
        passRow.setMaximumSize(new Dimension(Integer.MAX_VALUE, 44));
        JPasswordField passField = styledPasswordField("Enter master password");
        passRow.add(passField, BorderLayout.CENTER);
        JButton togglePass = createToggleButton();
        togglePass.addActionListener(e -> {
            if (passField.getEchoChar() == 0) {
                passField.setEchoChar('●');
                togglePass.setText("👁");
            } else {
                passField.setEchoChar((char)0);
                togglePass.setText("🔒");
            }
        });
        passRow.add(togglePass, BorderLayout.EAST);
        card.add(passRow);
        card.add(Box.createVerticalStrut(10));

        // Strength bar for new password
        JPanel strengthPanel = new JPanel(new BorderLayout(8, 0));
        strengthPanel.setOpaque(false);
        strengthPanel.setMaximumSize(new Dimension(Integer.MAX_VALUE, 20));
        JProgressBar strengthBar = new JProgressBar(0, 5);
        strengthBar.setStringPainted(false);
        strengthBar.setPreferredSize(new Dimension(200, 6));
        strengthBar.setBackground(theme.bgInput);
        strengthBar.setForeground(theme.accent);
        strengthBar.setBorderPainted(false);
        JLabel strengthLabel = styledLabel("", FONT_SMALL, theme.textSecondary);
        strengthPanel.add(strengthBar, BorderLayout.CENTER);
        strengthPanel.add(strengthLabel, BorderLayout.EAST);

        JPasswordField cf = null;
        if (isNew) {
            card.add(strengthPanel);
            card.add(Box.createVerticalStrut(12));
            card.add(wrapLeft(styledLabel("Confirm Password", FONT_SMALL, theme.textSecondary)));
            card.add(Box.createVerticalStrut(6));
            cf = styledPasswordField("Confirm password");
            cf.setMaximumSize(new Dimension(Integer.MAX_VALUE, 44));
            card.add(cf);
            card.add(Box.createVerticalStrut(10));
        }

        final JPasswordField confirmField = cf;
        passField.addKeyListener(new KeyAdapter() {
            public void keyReleased(KeyEvent e) {
                int str = CryptoEngine.getPasswordStrength(new String(passField.getPassword()));
                strengthBar.setValue(str);
                String[] labels = {"", "Very Weak", "Weak", "Fair", "Strong", "Very Strong"};
                Color[] colors = {theme.danger, theme.danger, theme.warning, theme.warning, theme.success, theme.success};
                strengthLabel.setText(labels[str]);
                strengthLabel.setForeground(colors[str]);
                strengthBar.setForeground(colors[str]);
            }
        });

        JLabel errorLabel = styledLabel("", FONT_SMALL, theme.danger);
        errorLabel.setAlignmentX(Component.CENTER_ALIGNMENT);
        card.add(errorLabel);
        card.add(Box.createVerticalStrut(8));

        // Failed attempts label
        if (!isNew && loginActivity.failedAttempts > 0) {
            JLabel attemptsLabel = styledLabel("Failed attempts: " + loginActivity.failedAttempts + "/3", FONT_SMALL, theme.warning);
            attemptsLabel.setAlignmentX(Component.CENTER_ALIGNMENT);
            card.add(attemptsLabel);
            card.add(Box.createVerticalStrut(5));
        }

        JButton loginBtn = createPremiumButton(isNew ? "Create Vault" : "Unlock Vault");
        loginBtn.setMaximumSize(new Dimension(Integer.MAX_VALUE, 46));
        loginBtn.setAlignmentX(Component.CENTER_ALIGNMENT);
        card.add(loginBtn);

        loginBtn.addActionListener(e -> {
            String pw = new String(passField.getPassword());
            if (pw.isEmpty()) { errorLabel.setText("Password cannot be empty"); AnimationEngine.pulse(errorLabel, 300); return; }
            if (isNew) {
                if (pw.length() < 8) { errorLabel.setText("Minimum 8 characters required"); return; }
                String confirm = new String(confirmField.getPassword());
                if (!pw.equals(confirm)) { errorLabel.setText("Passwords do not match"); return; }
                try {
                    userData = new UserData();
                    userData.salt = CryptoEngine.generateSalt();
                    userData.masterHash = CryptoEngine.hashPassword(pw, userData.salt);
                    masterPassword = pw;
                    loginActivity.totalLoginCount = 1;
                    loginActivity.lastLoginTime = System.currentTimeMillis();
                    loginActivity.failedAttempts = 0;
                    if (loginActivity.loginHistory == null) {
                        loginActivity.loginHistory = new ArrayList<>();
                    }
                    loginActivity.loginHistory.add(System.currentTimeMillis());
                    userData.loginActivity = loginActivity;
                    Storage.save(userData);
                    Storage.saveLoginActivity(loginActivity);
                    rebuildUI(); refreshDashboard();
                    cardLayout.show(mainPanel, "dashboard");
                    startAutoLockTimer();
                    toastManager.show("Vault created successfully!", "success", 3000);
                } catch (Exception ex) { errorLabel.setText("Error: " + ex.getMessage()); }
            } else {

    if (!Storage.exists()) {
        errorLabel.setText("No vault exists. Please create one first.");
        return;
    }

    try {
        userData = Storage.load();

        if (userData == null || userData.salt == null || userData.masterHash == null) {
            errorLabel.setText("Vault is corrupted. Please create a new one.");
            return;
        }

if (userData == null) {
    errorLabel.setText("No vault found. Please create a new one.");
    return;
}

byte[] hash = CryptoEngine.hashPassword(pw, userData.salt);
                    if (Arrays.equals(hash, userData.masterHash)) {
                        masterPassword = pw;
                        loginActivity.totalLoginCount++;
                        loginActivity.lastLoginTime = System.currentTimeMillis();
                        loginActivity.failedAttempts = 0;
                        if (loginActivity.loginHistory == null) {
                            loginActivity.loginHistory = new ArrayList<>();
                        }
                        loginActivity.loginHistory.add(System.currentTimeMillis());
                        userData.loginActivity = loginActivity;
                        Storage.saveLoginActivity(loginActivity);
                        theme = userData.darkMode ? Theme.dark() : Theme.light();
                        rebuildUI(); refreshDashboard();
                        cardLayout.show(mainPanel, "dashboard");
                        startAutoLockTimer();
                        toastManager.show("Welcome back!", "success", 2500);
                        checkExpiryWarnings();
                    } else {
                        loginActivity.failedAttempts++;
                        Storage.saveLoginActivity(loginActivity);
                        if (loginActivity.failedAttempts >= 3) {
                            loginActivity.lockUntil = System.currentTimeMillis() + 60000; // 1 min lock
                            Storage.saveLoginActivity(loginActivity);
                            rebuildUI(); cardLayout.show(mainPanel, "auth");
                            toastManager.show("Too many failed attempts. Locked for 60s.", "error", 5000);
                        } else {
                            int remaining = 3 - loginActivity.failedAttempts;
                            errorLabel.setText("Incorrect password. " + remaining + " attempt(s) remaining.");
                            AnimationEngine.pulse(errorLabel, 300);
                        }
                    }
                } catch (Exception ex) { errorLabel.setText("Error: " + ex.getMessage()); }
            }
        });

        KeyListener enterKey = new KeyAdapter() {
            public void keyPressed(KeyEvent e) { if (e.getKeyCode() == KeyEvent.VK_ENTER) loginBtn.doClick(); }
        };
        passField.addKeyListener(enterKey);
        if (cf != null) cf.addKeyListener(enterKey);

        panel.add(card);
        return panel;
    }

    private void checkExpiryWarnings() {
        if (userData == null) return;
        int expired = 0, expiring = 0;
        for (PasswordEntry entry : userData.entries) {
            if (entry.isExpired()) expired++;
            else if (entry.isExpiringSoon()) expiring++;
        }
        if (expired > 0) toastManager.show(expired + " password(s) have EXPIRED!", "error", 4000);
        if (expiring > 0) toastManager.show(expiring + " password(s) expiring soon", "warning", 4000);
    }

    // ======================== DASHBOARD ========================
    private JPanel createDashboard() {
        // Ensure loginActivity is never null before accessing its fields
        if (loginActivity == null) {
            loginActivity = new LoginActivity();
        }
        dashPanel = createGradientPanel(new BorderLayout());

        // ---- Top bar ----
        JPanel topBar = new JPanel(new BorderLayout()) {
            protected void paintComponent(Graphics g) {
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setColor(new Color(theme.bgCard.getRed(), theme.bgCard.getGreen(), theme.bgCard.getBlue(), 180));
                g2.fillRect(0, 0, getWidth(), getHeight());
                // Bottom gradient line
                g2.setPaint(new GradientPaint(0, getHeight()-2, theme.gradStart1, getWidth(), getHeight()-2, theme.gradEnd1));
                g2.fillRect(0, getHeight()-2, getWidth(), 2);
                g2.dispose();
            }
        };
        topBar.setOpaque(false);
        topBar.setBorder(BorderFactory.createEmptyBorder(10, 25, 10, 25));

        JPanel leftTop = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        leftTop.setOpaque(false);
        JPanel shieldSmall = new JPanel() {
            { setOpaque(false); setPreferredSize(new Dimension(28, 28)); }
            protected void paintComponent(Graphics g) {
                Graphics2D g2 = (Graphics2D) g.create();
                drawShieldIcon(g2, 14, 14, 11, 1f);
                g2.dispose();
            }
        };
        leftTop.add(shieldSmall);
        leftTop.add(styledLabel("VaultKeeper", new Font("Segoe UI", Font.BOLD, 17), theme.textPrimary));
        autoLockLabel = styledLabel("  ⏱ Auto-lock: 5:00", FONT_SMALL, theme.textSecondary);
        leftTop.add(autoLockLabel);
        topBar.add(leftTop, BorderLayout.WEST);

        JPanel rightTop = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));
        rightTop.setOpaque(false);

        JButton themeBtn = createSmallButton(theme.name.equals("dark") ? "Light" : "Dark");
        addHoverEffect(themeBtn);
        themeBtn.addActionListener(e -> {
            theme = theme.name.equals("dark") ? Theme.light() : Theme.dark();
            if (userData != null) { userData.darkMode = theme.name.equals("dark"); Storage.save(userData); }
            rebuildUI(); refreshDashboard(); cardLayout.show(mainPanel, "dashboard"); startAutoLockTimer();
            toastManager.show("Theme changed to " + theme.name, "info", 1500);
        });
        rightTop.add(themeBtn);

        JButton backupBtn = createSmallButton("Backup");
        addHoverEffect(backupBtn);
        backupBtn.addActionListener(e -> showBackupDialog());
        rightTop.add(backupBtn);

        JButton importBtn = createSmallButton("Import");
        addHoverEffect(importBtn);
        importBtn.addActionListener(e -> importFromCSV());
        rightTop.add(importBtn);

        JButton exportBtn = createSmallButton("Export");
        addHoverEffect(exportBtn);
        exportBtn.addActionListener(e -> exportToCSV());
        rightTop.add(exportBtn);

       

        // --- Secure Image Import ---
        JButton importImgBtn = createSmallButton("Import Image");
        addHoverEffect(importImgBtn);
        importImgBtn.addActionListener(e -> {
            JFileChooser fc = new JFileChooser();
            fc.setFileFilter(new FileNameExtensionFilter("PNG Images", "png"));
            if (fc.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
                String pwd = JOptionPane.showInputDialog(this, "Enter password:");
                try {
                    SecureImporter importer = new SecureImageImporter();
                    PasswordEntry entry = importer.importData(fc.getSelectedFile(), pwd);
                    // Preview dialog for imported credential
                    JDialog preview = createPremiumDialog("Preview Imported Credential", 400, 300);
                    JPanel p = createDialogPanel();

                    p.add(wrapLeft(styledLabel("Site: " + entry.siteName, FONT_BODY, theme.textPrimary)));
                    p.add(Box.createVerticalStrut(10));
                    p.add(wrapLeft(styledLabel("Username: " + entry.username, FONT_BODY, theme.textPrimary)));
                    p.add(Box.createVerticalStrut(10));

                    String decrypted = CryptoEngine.decrypt(entry.encryptedPassword, masterPassword, userData.salt);
                    p.add(wrapLeft(styledLabel("Password: " + decrypted, FONT_BODY, theme.textPrimary)));

                    p.add(Box.createVerticalStrut(20));

                    JButton importVaultBtn = createPremiumButton("Import to Vault");
                    importVaultBtn.addActionListener(ev -> {
                        userData.entries.add(entry);
                        Storage.save(userData);
                        refreshDashboard();
                        preview.dispose();
                        toastManager.show("Imported successfully!", "success", 2000);
                    });

                    p.add(importVaultBtn);

                    preview.add(p);
                    preview.setVisible(true);
                } catch (Exception ex) {
                    toastManager.show("Import failed", "error", 2000);
                }
            }
        });
        rightTop.add(importImgBtn);

      

        JButton genBtn = createSmallButton("Generator");
        addHoverEffect(genBtn);
        genBtn.addActionListener(e -> showPasswordGenerator());
        rightTop.add(genBtn);

        JButton settingsBtn = createSmallButton("Settings");
        addHoverEffect(settingsBtn);
        settingsBtn.addActionListener(e -> showSettingsDialog());
        rightTop.add(settingsBtn);

        // Activity button
        JButton activityBtn = createSmallButton("Activity");
        addHoverEffect(activityBtn);
        activityBtn.addActionListener(e -> showActivityLog());
        rightTop.add(activityBtn);

        JButton lockBtn = createSmallButton("Lock");
        addHoverEffect(lockBtn);
        lockBtn.addActionListener(e -> lockVault());
        rightTop.add(lockBtn);

        topBar.add(rightTop, BorderLayout.EAST);
        dashPanel.add(topBar, BorderLayout.NORTH);

        // ---- Content ----
        JPanel content = new JPanel(new BorderLayout());
        content.setOpaque(false);
        content.setBorder(BorderFactory.createEmptyBorder(20, 25, 20, 25));

        // Stats row
        JPanel statsRow = new JPanel(new GridLayout(1, 5, 12, 0));
        statsRow.setOpaque(false);
        statsRow.setBorder(BorderFactory.createEmptyBorder(0, 0, 16, 0));

        int total = userData != null ? userData.entries.size() : 0;
        int expiredCount = 0, expiringCount = 0, strongCount = 0;
        if (userData != null) {
            for (PasswordEntry entry : userData.entries) {
                if (entry.isExpired()) expiredCount++;
                else if (entry.isExpiringSoon()) expiringCount++;
                try {
                    String dec = CryptoEngine.decrypt(entry.encryptedPassword, masterPassword, userData.salt);
                    if (CryptoEngine.getPasswordStrength(dec) >= 4) strongCount++;
                } catch (Exception ignored) {}
            }
        }

statsRow.add(createStatCard("", "Total", String.valueOf(total), theme.accent));
statsRow.add(createStatCard("", "Strong", String.valueOf(strongCount), theme.success));
statsRow.add(createStatCard("", "Expiring", String.valueOf(expiringCount), theme.warning));
statsRow.add(createStatCard("", "Expired", String.valueOf(expiredCount), theme.danger));
statsRow.add(createStatCard("", "Logins", String.valueOf(loginActivity.totalLoginCount), theme.gradEnd1));

        JPanel topContent = new JPanel(new BorderLayout());
        topContent.setOpaque(false);
        topContent.add(statsRow, BorderLayout.NORTH);

        // Action bar
        JPanel actionBar = new JPanel(new BorderLayout());
        actionBar.setOpaque(false);
        actionBar.setBorder(BorderFactory.createEmptyBorder(0, 0, 12, 0));

        JPanel leftAction = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        leftAction.setOpaque(false);
        searchField = createPremiumTextField("🔍 Search passwords...");
        searchField.setPreferredSize(new Dimension(240, 38));
        searchField.addKeyListener(new KeyAdapter() { public void keyReleased(KeyEvent e) { refreshDashboard(); } });
        leftAction.add(searchField);

        categoryFilter = createPremiumComboBox(new String[]{"All Categories", "Social", "Email", "Finance", "Work", "Shopping", "Other"});
        categoryFilter.setPreferredSize(new Dimension(150, 38));
        categoryFilter.addActionListener(e -> refreshDashboard());
        leftAction.add(categoryFilter);

        sortFilter = createPremiumComboBox(new String[]{"Sort: Newest", "Sort: Oldest", "Sort: A-Z", "Sort: Z-A", "Sort: Strength"});
        sortFilter.setPreferredSize(new Dimension(140, 38));
        sortFilter.addActionListener(e -> refreshDashboard());
        leftAction.add(sortFilter);

        countLabel = styledLabel("0 passwords", FONT_SMALL, theme.textSecondary);
        leftAction.add(Box.createHorizontalStrut(8));
        leftAction.add(countLabel);
        actionBar.add(leftAction, BorderLayout.WEST);

        JPanel rightAction = new JPanel(new FlowLayout(FlowLayout.RIGHT, 0, 0));
        rightAction.setOpaque(false);
        JButton addBtn = createPremiumButton("+ Add Password");
        addBtn.addActionListener(e -> showAddEditDialog(null));
        rightAction.add(addBtn);
        actionBar.add(rightAction, BorderLayout.EAST);

        topContent.add(actionBar, BorderLayout.SOUTH);
        content.add(topContent, BorderLayout.NORTH);

        // Table
        String[] cols = {"Site", "Username", "Category", "Age", "Status", "Strength", "Actions"};
        tableModel = new DefaultTableModel(cols, 0) {
            public boolean isCellEditable(int r, int c) { return c == 6; }
        };
        table = new JTable(tableModel);
        table.setRowHeight(48);
        table.setShowGrid(false);
        table.setIntercellSpacing(new Dimension(0, 0));
        table.setBackground(theme.bgCard);
        table.setForeground(theme.textPrimary);
        table.setSelectionBackground(new Color(theme.accent.getRed(), theme.accent.getGreen(), theme.accent.getBlue(), 30));
        table.setSelectionForeground(theme.textPrimary);
        table.setFont(FONT_BODY);
        table.setFillsViewportHeight(true);

        // Header
        JTableHeader header = table.getTableHeader();
        header.setBackground(theme.bgInput);
        header.setForeground(theme.textSecondary);
        header.setFont(new Font("Segoe UI", Font.BOLD, 12));
        header.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, theme.border));
        header.setPreferredSize(new Dimension(0, 40));

        // Custom cell renderer
        table.setDefaultRenderer(Object.class, new DefaultTableCellRenderer() {
            public Component getTableCellRendererComponent(JTable t, Object v, boolean sel, boolean foc, int r, int c) {
                JLabel lbl = (JLabel) super.getTableCellRendererComponent(t, v, sel, foc, r, c);
                lbl.setBorder(BorderFactory.createEmptyBorder(0, 12, 0, 12));
                lbl.setFont(FONT_BODY);
                if (!sel) lbl.setBackground(r % 2 == 0 ? theme.bgCard : new Color(
                    theme.bgInput.getRed(), theme.bgInput.getGreen(), theme.bgInput.getBlue(), 60));
                lbl.setForeground(theme.textPrimary);
                // Status pill
                if (c == 4 && v != null) {
                    String status = v.toString();
                    if (status.equals("Expired")) lbl.setForeground(theme.danger);
                    else if (status.equals("Expiring")) lbl.setForeground(theme.warning);
                    else lbl.setForeground(theme.success);
                }
                // Strength
                if (c == 5 && v != null) {
                    String str = v.toString();
                    if (str.contains("Strong") || str.contains("Very")) lbl.setForeground(theme.success);
                    else if (str.contains("Fair")) lbl.setForeground(theme.warning);
                    else lbl.setForeground(theme.danger);
                }
                return lbl;
            }
        });

        // Action column
        table.getColumnModel().getColumn(6).setCellRenderer((t, v, sel, foc, r, c) -> {
            JPanel p = new JPanel(new FlowLayout(FlowLayout.CENTER, 4, 6));
            p.setBackground(sel ? table.getSelectionBackground() :
                (r % 2 == 0 ? theme.bgCard : new Color(theme.bgInput.getRed(), theme.bgInput.getGreen(), theme.bgInput.getBlue(), 60)));
            String[] btns = {"View", "Copy", "Edit", "Delete"};
            for (String b : btns) {
                JLabel btn = new JLabel(b);
                btn.setFont(new Font("Segoe UI", Font.PLAIN, 14));
                btn.setForeground(theme.textPrimary); // FIX: make visible in dark theme
                btn.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
                p.add(btn);
            }
            return p;
        });
        table.getColumnModel().getColumn(6).setCellEditor(new DefaultCellEditor(new JCheckBox()) {
            private JPanel panel;
            private int editRow;
            public Component getTableCellEditorComponent(JTable t, Object v, boolean sel, int r, int c) {
                editRow = r;
                panel = new JPanel(new FlowLayout(FlowLayout.CENTER, 4, 6));
                panel.setBackground(theme.bgCard);
                String[][] actions = {{"View","View"}, {"Copy","Copy"}, {"Edit","Edit"}, {"Delete","Delete"}};
                for (String[] a : actions) {
                    JLabel btn = new JLabel(a[0]);
                    btn.setFont(new Font("Segoe UI", Font.PLAIN, 14));
                    btn.setForeground(theme.textPrimary); // FIX: visible text
                    btn.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
                    btn.setToolTipText(a[1]);
                    final String action = a[1];
                    btn.addMouseListener(new MouseAdapter() {
                        public void mouseClicked(MouseEvent e) {
                            stopCellEditing();
                            PasswordEntry entry = getEntryAtRow(editRow);
                            if (entry == null) return;
                            switch (action) {
                                case "View": showViewDialog(entry); break;
                                case "Copy": copyPassword(entry); break;
                                case "Edit": showAddEditDialog(entry); break;
                                case "Delete": deleteEntry(entry); break;
                            }
                        }
                    });
                    panel.add(btn);
                }
                return panel;
            }
            public Object getCellEditorValue() { return ""; }
        });

        table.getColumnModel().getColumn(0).setPreferredWidth(140);
        table.getColumnModel().getColumn(1).setPreferredWidth(140);
        table.getColumnModel().getColumn(2).setPreferredWidth(90);
        table.getColumnModel().getColumn(3).setPreferredWidth(80);
        table.getColumnModel().getColumn(4).setPreferredWidth(70);
        table.getColumnModel().getColumn(5).setPreferredWidth(80);
        table.getColumnModel().getColumn(6).setPreferredWidth(120);

        JScrollPane scrollPane = new JScrollPane(table);
        scrollPane.setBorder(BorderFactory.createLineBorder(theme.border, 1));
        scrollPane.getViewport().setBackground(theme.bgCard);
        scrollPane.setBackground(theme.bgCard);

        // Empty state overlay
        JPanel tableWrapper = new JPanel(new BorderLayout());
        tableWrapper.setOpaque(false);
        tableWrapper.add(scrollPane, BorderLayout.CENTER);

        content.add(tableWrapper, BorderLayout.CENTER);
        dashPanel.add(content, BorderLayout.CENTER);

        return dashPanel;
    }

    // ======================== EMPTY STATE ========================
    private JPanel createEmptyState() {
        JPanel empty = new JPanel() {
            protected void paintComponent(Graphics g) {
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                g2.setColor(theme.bgCard);
                g2.fillRoundRect(0, 0, getWidth(), getHeight(), 16, 16);
                g2.dispose();
            }
        };
        empty.setOpaque(false);
        empty.setLayout(new BoxLayout(empty, BoxLayout.Y_AXIS));
        empty.setBorder(BorderFactory.createEmptyBorder(60, 40, 60, 40));

        JPanel icon = new JPanel() {
            { setOpaque(false); setPreferredSize(new Dimension(80, 80)); setMaximumSize(new Dimension(80, 80)); }
            protected void paintComponent(Graphics g) {
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                g2.setColor(new Color(theme.accent.getRed(), theme.accent.getGreen(), theme.accent.getBlue(), 25));
                g2.fillOval(0, 0, 80, 80);
                g2.setFont(new Font("Segoe UI", Font.PLAIN, 36));
                g2.setColor(theme.accent);
                FontMetrics fm = g2.getFontMetrics();
                g2.drawString("🔑", 40 - fm.stringWidth("🔑")/2, 50);
                g2.dispose();
            }
        };
        icon.setAlignmentX(Component.CENTER_ALIGNMENT);
        empty.add(icon);
        empty.add(Box.createVerticalStrut(20));

        JLabel title = styledLabel("No passwords yet", new Font("Segoe UI", Font.BOLD, 20), theme.textPrimary);
        title.setAlignmentX(Component.CENTER_ALIGNMENT);
        empty.add(title);
        empty.add(Box.createVerticalStrut(8));

        JLabel desc = styledLabel("Add your first password to get started", FONT_BODY, theme.textSecondary);
        desc.setAlignmentX(Component.CENTER_ALIGNMENT);
        empty.add(desc);
        empty.add(Box.createVerticalStrut(20));

        JButton addBtn = createPremiumButton("+ Add Your First Password");
        addBtn.setAlignmentX(Component.CENTER_ALIGNMENT);
        addBtn.addActionListener(e -> showAddEditDialog(null));
        empty.add(addBtn);

        return empty;
    }

    // ======================== STAT CARD ========================
    private JPanel createStatCard(String emoji, String label, String value, Color color) {
        JPanel card = new JPanel() {
            protected void paintComponent(Graphics g) {
                float scale = 1f;
                Object s = getClientProperty("scale");
                if (s instanceof Float) scale = (Float) s;

                Graphics2D g2 = (Graphics2D) g.create();
                g2.scale(scale, scale);

                // Shadow elevation on hover
                if (scale > 1f) {
                    g2.setColor(new Color(0, 0, 0, 40));
                    g2.fillRoundRect(6, 6, getWidth() - 6, getHeight() - 6, 16, 16);
                }

                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                Color base = theme.bgCard;
                if (scale > 1f) {
                    base = base.brighter();
                }
                g2.setColor(new Color(base.getRed(), base.getGreen(), base.getBlue(), 200));
                g2.fillRoundRect(0, 0, getWidth(), getHeight(), 16, 16);
                g2.setColor(theme.border);
                g2.drawRoundRect(0, 0, getWidth()-1, getHeight()-1, 16, 16);
                // Top accent line
                g2.setPaint(new GradientPaint(0, 0, color, getWidth(), 0, new Color(color.getRed(), color.getGreen(), color.getBlue(), 60)));
                g2.fillRoundRect(0, 0, getWidth(), 3, 3, 3);
                g2.dispose();
            }
        };
        card.setOpaque(false);
        card.setLayout(new BoxLayout(card, BoxLayout.Y_AXIS));
        card.setBorder(BorderFactory.createEmptyBorder(14, 16, 14, 16));

        JLabel emojiLabel = styledLabel(label, FONT_SMALL, theme.textSecondary);
        emojiLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        card.add(emojiLabel);
        card.add(Box.createVerticalStrut(6));

        JLabel valueLabel = styledLabel(value, new Font("Segoe UI", Font.BOLD, 24), color);
        valueLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        card.add(valueLabel);

        addHoverEffect(card);

        return card;
    }

    // ======================== REFRESH DASHBOARD ========================
    private void refreshDashboard() {
        if (tableModel == null || userData == null) return;
        tableModel.setRowCount(0);

        String search = searchField != null ? searchField.getText().toLowerCase().trim() : "";
        String cat = categoryFilter != null ? (String) categoryFilter.getSelectedItem() : "All Categories";
        String sortOpt = sortFilter != null ? (String) sortFilter.getSelectedItem() : "Sort: Newest";

        List<PasswordEntry> filtered = new ArrayList<>();
        for (PasswordEntry entry : userData.entries) {
            boolean matchSearch = search.isEmpty() || entry.siteName.toLowerCase().contains(search)
                || entry.username.toLowerCase().contains(search) || entry.category.toLowerCase().contains(search)
                || (entry.notes != null && entry.notes.toLowerCase().contains(search));
            boolean matchCat = "All Categories".equals(cat) || entry.category.equals(cat);
            if (matchSearch && matchCat) filtered.add(entry);
        }

        // Sort
        switch (sortOpt) {
            case "Sort: Oldest": filtered.sort(Comparator.comparingLong(e -> e.createdAt)); break;
            case "Sort: A-Z": filtered.sort(Comparator.comparing(e -> e.siteName.toLowerCase())); break;
            case "Sort: Z-A": filtered.sort((a, b) -> b.siteName.compareToIgnoreCase(a.siteName)); break;
            case "Sort: Strength": filtered.sort((a, b) -> {
                try {
                    int sa = CryptoEngine.getPasswordStrength(CryptoEngine.decrypt(a.encryptedPassword, masterPassword, userData.salt));
                    int sb = CryptoEngine.getPasswordStrength(CryptoEngine.decrypt(b.encryptedPassword, masterPassword, userData.salt));
                    return Integer.compare(sb, sa);
                } catch (Exception e) { return 0; }
            }); break;
            default: filtered.sort((a, b) -> Long.compare(b.createdAt, a.createdAt)); break;
        }

        for (PasswordEntry entry : filtered) {
            String status = entry.isExpired() ? "Expired" : entry.isExpiringSoon() ? "Expiring" : "OK";
            String strength = "?";
            try {
                String dec = CryptoEngine.decrypt(entry.encryptedPassword, masterPassword, userData.salt);
                String[] labels = {"", "Very Weak", "Weak", "Fair", "Strong", "Very Strong"};
                strength = labels[CryptoEngine.getPasswordStrength(dec)];
            } catch (Exception ignored) {}
            tableModel.addRow(new Object[]{entry.siteName, entry.username, entry.category, entry.getAgeString(), status, strength, "..."});
        }

        if (countLabel != null) countLabel.setText(filtered.size() + " password" + (filtered.size() != 1 ? "s" : ""));

        // Show empty state if no entries at all
        if (userData.entries.isEmpty() && dashPanel != null) {
            // Find the center content and check
            Component[] comps = dashPanel.getComponents();
            // We handle this in the table wrapper
        }
    }

    private PasswordEntry getEntryAtRow(int row) {
        if (userData == null || row < 0) return null;
        String search = searchField != null ? searchField.getText().toLowerCase().trim() : "";
        String cat = categoryFilter != null ? (String) categoryFilter.getSelectedItem() : "All Categories";
        String sortOpt = sortFilter != null ? (String) sortFilter.getSelectedItem() : "Sort: Newest";

        List<PasswordEntry> filtered = new ArrayList<>();
        for (PasswordEntry entry : userData.entries) {
            boolean matchSearch = search.isEmpty() || entry.siteName.toLowerCase().contains(search)
                || entry.username.toLowerCase().contains(search) || entry.category.toLowerCase().contains(search);
            boolean matchCat = "All Categories".equals(cat) || entry.category.equals(cat);
            if (matchSearch && matchCat) filtered.add(entry);
        }

        switch (sortOpt) {
            case "Sort: Oldest": filtered.sort(Comparator.comparingLong(e -> e.createdAt)); break;
            case "Sort: A-Z": filtered.sort(Comparator.comparing(e -> e.siteName.toLowerCase())); break;
            case "Sort: Z-A": filtered.sort((a, b) -> b.siteName.compareToIgnoreCase(a.siteName)); break;
            default: filtered.sort((a, b) -> Long.compare(b.createdAt, a.createdAt)); break;
        }

        return row < filtered.size() ? filtered.get(row) : null;
    }

    // ======================== VIEW DIALOG ========================
    private void showViewDialog(PasswordEntry entry) {
        JDialog dialog = createPremiumDialog("View Password", 440, 480);
        JPanel panel = createDialogPanel();

        panel.add(wrapLeft(styledLabel(entry.siteName, new Font("Segoe UI", Font.BOLD, 20), theme.textPrimary)));
        panel.add(Box.createVerticalStrut(20));

        addDetailRow(panel, "URL", entry.siteUrl.isEmpty() ? "—" : entry.siteUrl);
        addDetailRow(panel, "Username", entry.username);

        panel.add(wrapLeft(styledLabel("Password", FONT_SMALL, theme.textSecondary)));
        panel.add(Box.createVerticalStrut(4));
        JPanel passRow = new JPanel(new BorderLayout(6, 0));
        passRow.setOpaque(false);
        passRow.setMaximumSize(new Dimension(Integer.MAX_VALUE, 38));
        JTextField passDisplay = createPremiumTextField("••••••••");
        passDisplay.setEditable(false);
        passDisplay.setFont(FONT_MONO);
        try { passDisplay.setText("••••••••"); } catch (Exception ignored) {}
        passRow.add(passDisplay, BorderLayout.CENTER);

        JPanel passBtns = new JPanel(new FlowLayout(FlowLayout.RIGHT, 4, 0));
        passBtns.setOpaque(false);
        JButton showBtn = createToggleButton();
        final boolean[] shown = {false};
        showBtn.addActionListener(e -> {
            try {
                if (shown[0]) {
                    passDisplay.setText("••••••••");
                    showBtn.setText("👁");
                } else {
                    passDisplay.setText(CryptoEngine.decrypt(entry.encryptedPassword, masterPassword, userData.salt));
                    showBtn.setText("🔒");
                }
                shown[0] = !shown[0];
            } catch (Exception ex) { passDisplay.setText("Error"); }
        });
        passBtns.add(showBtn);
        JButton copyBtn = createToggleButton();
        copyBtn.setText("📋");
        copyBtn.addActionListener(e -> { copyPassword(entry); });
        passBtns.add(copyBtn);
        passRow.add(passBtns, BorderLayout.EAST);
        panel.add(passRow);
        panel.add(Box.createVerticalStrut(12));

        addDetailRow(panel, "Category", entry.category);
        addDetailRow(panel, "Notes", entry.notes == null || entry.notes.isEmpty() ? "—" : entry.notes);
        addDetailRow(panel, "Created", new SimpleDateFormat("MMM dd, yyyy").format(new Date(entry.createdAt)));
        addDetailRow(panel, "Modified", entry.getAgeString());
        addDetailRow(panel, "Expires in", entry.daysUntilExpiry() + " days");

        panel.add(Box.createVerticalStrut(20));

        // Button container (premium aligned)
        JPanel btnContainer = new JPanel(new BorderLayout(10, 0));
        btnContainer.setOpaque(false);
        btnContainer.setMaximumSize(new Dimension(Integer.MAX_VALUE, 50));

        // Left: Close button (small)
        JButton closeBtn = createPremiumButton("Close");
        closeBtn.setPreferredSize(new Dimension(120, 42));
        closeBtn.addActionListener(e -> dialog.dispose());
        btnContainer.add(closeBtn, BorderLayout.WEST);

        // Right: Export button (primary focus)
        JButton exportImgBtn = createPremiumButton("Export as Secure Image");
        exportImgBtn.setPreferredSize(new Dimension(240, 42));
        exportImgBtn.addActionListener(e -> {
            String pwd = JOptionPane.showInputDialog(dialog, "Enter export password (min 6 chars):");
            if (pwd != null && pwd.length() >= 6) {
                try {
                    SecureExporter exporter = new SecureImageExporter();
                    exporter.export(entry, pwd);
                    toastManager.show("Image exported to Desktop!", "success", 2000);
                } catch (Exception ex) {
                    toastManager.show("Export failed", "error", 2000);
                }
            }
        });
        btnContainer.add(exportImgBtn, BorderLayout.EAST);

        panel.add(btnContainer);

        JScrollPane scrollPane = new JScrollPane(panel);
scrollPane.setBorder(null);
scrollPane.getVerticalScrollBar().setUnitIncrement(16);
scrollPane.getViewport().setBackground(theme.bgCard);

dialog.add(scrollPane);
        dialog.setVisible(true);
    }

    private void addDetailRow(JPanel panel, String label, String value) {
        panel.add(wrapLeft(styledLabel(label, FONT_SMALL, theme.textSecondary)));
        panel.add(Box.createVerticalStrut(3));
        JLabel val = styledLabel(value, FONT_BODY, theme.textPrimary);
        val.setAlignmentX(Component.LEFT_ALIGNMENT);
        panel.add(val);
        panel.add(Box.createVerticalStrut(10));
    }

    private void copyPassword(PasswordEntry entry) {
        try {
            String decrypted = CryptoEngine.decrypt(entry.encryptedPassword, masterPassword, userData.salt);
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(decrypted), null);
            toastManager.show("Password copied to clipboard!", "success", 2000);
            // Auto-clear after 30 seconds
            new Timer().schedule(new TimerTask() {
                public void run() {
                    Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(""), null);
                }
            }, 30000);
        } catch (Exception ex) { toastManager.show("Failed to copy password", "error", 2000); }
    }

   private void setupShortcuts() {
    int mask = Toolkit.getDefaultToolkit().getMenuShortcutKeyMaskEx();

    JRootPane root = getRootPane();

    InputMap im = root.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW);
    ActionMap am = root.getActionMap();

    im.put(KeyStroke.getKeyStroke(KeyEvent.VK_N, mask), "newEntry");
    am.put("newEntry", new AbstractAction() {
        public void actionPerformed(ActionEvent e) {
            showAddEditDialog(null);
        }
    });

    im.put(KeyStroke.getKeyStroke(KeyEvent.VK_F, mask), "focusSearch");
    am.put("focusSearch", new AbstractAction() {
        public void actionPerformed(ActionEvent e) {
            if (searchField != null) searchField.requestFocus();
        }
    });

    im.put(KeyStroke.getKeyStroke(KeyEvent.VK_L, mask), "lockVault");
    am.put("lockVault", new AbstractAction() {
        public void actionPerformed(ActionEvent e) {
            lockVault();
        }
    });

    im.put(KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0), "escape");
    am.put("escape", new AbstractAction() {
        public void actionPerformed(ActionEvent e) {
            Window w = KeyboardFocusManager.getCurrentKeyboardFocusManager().getActiveWindow();
            if (w instanceof JDialog) {
                w.dispose();
            }
        }
    });
}
         


    private void showActivityLog() {
        JDialog dialog = createPremiumDialog("Activity Log", 450, 500);
        JPanel panel = createDialogPanel();

        if (loginActivity == null) {
            panel.add(styledLabel("No activity available", FONT_BODY, theme.textSecondary));
        } else {

            panel.add(wrapLeft(styledLabel("Login Activity", new Font("Segoe UI", Font.BOLD, 18), theme.textPrimary)));
            panel.add(Box.createVerticalStrut(15));

            panel.add(wrapLeft(styledLabel("Total Logins: " + loginActivity.totalLoginCount, FONT_BODY, theme.textPrimary)));
            panel.add(Box.createVerticalStrut(8));

            panel.add(wrapLeft(styledLabel("Failed Attempts: " + loginActivity.failedAttempts, FONT_BODY, theme.warning)));
            panel.add(Box.createVerticalStrut(8));

            String lastLogin = loginActivity.lastLoginTime > 0
                    ? new SimpleDateFormat("MMM dd, yyyy HH:mm").format(new Date(loginActivity.lastLoginTime))
                    : "Never";

            panel.add(wrapLeft(styledLabel("Last Login: " + lastLogin, FONT_BODY, theme.textPrimary)));
            panel.add(Box.createVerticalStrut(15));

            panel.add(wrapLeft(styledLabel("Login History:", FONT_BODY, theme.textSecondary)));
            panel.add(Box.createVerticalStrut(10));

            if (loginActivity.loginHistory != null && !loginActivity.loginHistory.isEmpty()) {
                for (Long time : loginActivity.loginHistory) {
                    String formatted = new SimpleDateFormat("MMM dd, yyyy HH:mm").format(new Date(time));
                    panel.add(wrapLeft(styledLabel("• " + formatted, FONT_SMALL, theme.textPrimary)));
                    panel.add(Box.createVerticalStrut(5));
                }
            } else {
                panel.add(wrapLeft(styledLabel("No history available", FONT_SMALL, theme.textSecondary)));
            }
        }

        panel.add(Box.createVerticalStrut(20));

        JButton closeBtn = createPremiumButton("Close");
        closeBtn.addActionListener(e -> dialog.dispose());
        panel.add(closeBtn);

        JScrollPane scroll = new JScrollPane(panel);
        scroll.setBorder(null);
        scroll.getViewport().setBackground(theme.bgCard);

        dialog.add(scroll);
        dialog.setVisible(true);
    }

    private void deleteEntry(PasswordEntry entry) {
        int confirm = JOptionPane.showConfirmDialog(
            this,
            "Are you sure you want to delete this password?\nThis action cannot be undone.",
            "Confirm Delete",
            JOptionPane.YES_NO_OPTION,
            JOptionPane.WARNING_MESSAGE
        );
        if (confirm == JOptionPane.YES_OPTION) {
            userData.entries.remove(entry);
            Storage.save(userData);
            rebuildUI(); refreshDashboard();
            cardLayout.show(mainPanel, "dashboard"); startAutoLockTimer();
            toastManager.show("Password deleted", "info", 2000);
        }
    }

    // ======================== ADD/EDIT DIALOG ========================
    private void showAddEditDialog(PasswordEntry existing) {
        JDialog dialog = createPremiumDialog(existing == null ? "Add Password" : "Edit Password", 480, 640);
        JPanel panel = createDialogPanel();

        panel.add(wrapLeft(styledLabel(existing == null ? "✨ Add New Password" : "✏ Edit Password",
            new Font("Segoe UI", Font.BOLD, 20), theme.textPrimary)));
        panel.add(Box.createVerticalStrut(20));

        panel.add(wrapLeft(styledLabel("Site Name *", FONT_SMALL, theme.textSecondary)));
        panel.add(Box.createVerticalStrut(4));
        JTextField siteField = createPremiumTextField("e.g. Google, GitHub");
        if (existing != null) siteField.setText(existing.siteName);
        panel.add(siteField);
        panel.add(Box.createVerticalStrut(12));

        panel.add(wrapLeft(styledLabel("URL", FONT_SMALL, theme.textSecondary)));
        panel.add(Box.createVerticalStrut(4));
        JTextField urlField = createPremiumTextField("https://...");
        if (existing != null) urlField.setText(existing.siteUrl);
        panel.add(urlField);
        panel.add(Box.createVerticalStrut(12));

        panel.add(wrapLeft(styledLabel("Username / Email *", FONT_SMALL, theme.textSecondary)));
        panel.add(Box.createVerticalStrut(4));
        JTextField userField = createPremiumTextField("username or email");
        if (existing != null) userField.setText(existing.username);
        panel.add(userField);
        panel.add(Box.createVerticalStrut(12));

        panel.add(wrapLeft(styledLabel("Password *", FONT_SMALL, theme.textSecondary)));
        panel.add(Box.createVerticalStrut(4));
        JPanel passRow = new JPanel(new BorderLayout(6, 0));
        passRow.setOpaque(false);
        passRow.setMaximumSize(new Dimension(Integer.MAX_VALUE, 40));
        JTextField passField = createPremiumTextField("password");
        if (existing != null) {
            try { passField.setText(CryptoEngine.decrypt(existing.encryptedPassword, masterPassword, userData.salt)); }
            catch (Exception ex) {}
        }
        passRow.add(passField, BorderLayout.CENTER);
        JPanel passBtns = new JPanel(new FlowLayout(FlowLayout.RIGHT, 2, 0));
        passBtns.setOpaque(false);
        JButton genPassBtn = createToggleButton();
        genPassBtn.setText("🎲");
        genPassBtn.setToolTipText("Generate");
        genPassBtn.addActionListener(e -> passField.setText(CryptoEngine.generatePassword(16, true, true, true, true)));
        passBtns.add(genPassBtn);
        passRow.add(passBtns, BorderLayout.EAST);
        panel.add(passRow);

        // Strength indicator
        JPanel strengthPanel = new JPanel(new BorderLayout(8, 0));
        strengthPanel.setOpaque(false);
        strengthPanel.setMaximumSize(new Dimension(Integer.MAX_VALUE, 22));
        strengthPanel.setBorder(BorderFactory.createEmptyBorder(4, 0, 0, 0));
        JProgressBar strengthBar = new JProgressBar(0, 5);
        strengthBar.setPreferredSize(new Dimension(200, 5));
        strengthBar.setBackground(theme.bgInput);
        strengthBar.setBorderPainted(false);
        JLabel strengthLabel = styledLabel("", FONT_SMALL, theme.textSecondary);
        strengthPanel.add(strengthBar, BorderLayout.CENTER);
        strengthPanel.add(strengthLabel, BorderLayout.EAST);
        panel.add(strengthPanel);
        panel.add(Box.createVerticalStrut(12));

        passField.addKeyListener(new KeyAdapter() {
            public void keyReleased(KeyEvent e) {
                int str = CryptoEngine.getPasswordStrength(passField.getText());
                strengthBar.setValue(str);
                String[] labels = {"", "Very Weak", "Weak", "Fair", "Strong", "Very Strong"};
                Color[] colors = {theme.danger, theme.danger, theme.warning, theme.warning, theme.success, theme.success};
                strengthLabel.setText(labels[str]);
                strengthLabel.setForeground(colors[str]);
                strengthBar.setForeground(colors[str]);
            }
        });

        panel.add(wrapLeft(styledLabel("Category", FONT_SMALL, theme.textSecondary)));
        panel.add(Box.createVerticalStrut(4));
        JComboBox<String> catBox = createPremiumComboBox(new String[]{"Social", "Email", "Finance", "Work", "Shopping", "Other"});
        catBox.setMaximumSize(new Dimension(Integer.MAX_VALUE, 40));
        if (existing != null) catBox.setSelectedItem(existing.category);
        panel.add(catBox);
        panel.add(Box.createVerticalStrut(12));

        panel.add(wrapLeft(styledLabel("Expiry (days)", FONT_SMALL, theme.textSecondary)));
        panel.add(Box.createVerticalStrut(4));
        JTextField expiryField = createPremiumTextField("90");
        if (existing != null) expiryField.setText(String.valueOf(existing.expiryDays));
        panel.add(expiryField);
        panel.add(Box.createVerticalStrut(12));

        panel.add(wrapLeft(styledLabel("Notes", FONT_SMALL, theme.textSecondary)));
        panel.add(Box.createVerticalStrut(4));
        JTextArea notesArea = new JTextArea(3, 20);
        notesArea.setFont(FONT_BODY);
        notesArea.setBackground(theme.bgInput);
        notesArea.setForeground(theme.textPrimary);
        notesArea.setCaretColor(theme.textPrimary);
        notesArea.setBorder(BorderFactory.createEmptyBorder(10, 12, 10, 12));
        if (existing != null) notesArea.setText(existing.notes);
        JScrollPane noteScroll = new JScrollPane(notesArea);
        noteScroll.setBorder(BorderFactory.createLineBorder(theme.border, 1));
        noteScroll.setMaximumSize(new Dimension(Integer.MAX_VALUE, 80));
        panel.add(noteScroll);
        panel.add(Box.createVerticalStrut(20));

        JPanel btnRow = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 0));
        btnRow.setOpaque(false);
        JButton cancelBtn = createSmallButton("Cancel");
        cancelBtn.addActionListener(e -> dialog.dispose());
        JButton saveBtn = createPremiumButton("Save");
        saveBtn.addActionListener(e -> {
            String site = siteField.getText().trim(), user = userField.getText().trim(), pass = passField.getText().trim();
            if (site.isEmpty() || user.isEmpty() || pass.isEmpty()) {
                toastManager.show("Please fill all required fields", "error", 2500);
                return;
            }
            try {
                String encrypted = CryptoEngine.encrypt(pass, masterPassword, userData.salt);
                int expiry = 90;
                try { expiry = Integer.parseInt(expiryField.getText().trim()); } catch (Exception ignored) {}
                if (existing == null) {
                    PasswordEntry entry = new PasswordEntry(site, urlField.getText().trim(), user, encrypted, (String)catBox.getSelectedItem(), notesArea.getText());
                    entry.expiryDays = expiry;
                    userData.entries.add(entry);
                    toastManager.show("Password added successfully!", "success", 2500);
                } else {
                    existing.siteName = site; existing.siteUrl = urlField.getText().trim();
                    existing.username = user; existing.encryptedPassword = encrypted;
                    existing.category = (String)catBox.getSelectedItem(); existing.notes = notesArea.getText();
                    existing.expiryDays = expiry; existing.modifiedAt = System.currentTimeMillis();
                    toastManager.show("Password updated!", "success", 2500);
                }
                Storage.save(userData);
                rebuildUI(); refreshDashboard();
                cardLayout.show(mainPanel, "dashboard"); startAutoLockTimer();
                dialog.dispose();
            } catch (Exception ex) { toastManager.show("Encryption error: " + ex.getMessage(), "error", 3000); }
        });
        btnRow.add(cancelBtn); btnRow.add(saveBtn);
        panel.add(btnRow);

        dialog.add(new JScrollPane(panel) {{
            setBorder(null);
            getViewport().setBackground(theme.bgCard);
            setHorizontalScrollBarPolicy(HORIZONTAL_SCROLLBAR_NEVER);
        }});
        dialog.setVisible(true);
    }

    // ======================== PASSWORD GENERATOR ========================
    private void showPasswordGenerator() {
        JDialog dialog = createPremiumDialog("Password Generator", 420, 460);
        JPanel panel = createDialogPanel();

        panel.add(wrapLeft(styledLabel("🎲 Password Generator", new Font("Segoe UI", Font.BOLD, 20), theme.textPrimary)));
        panel.add(Box.createVerticalStrut(20));

        JTextField output = createPremiumTextField("");
        output.setFont(FONT_MONO);
        output.setEditable(false);
        output.setMaximumSize(new Dimension(Integer.MAX_VALUE, 44));
        panel.add(output);
        panel.add(Box.createVerticalStrut(16));

        panel.add(wrapLeft(styledLabel("Length", FONT_SMALL, theme.textSecondary)));
        JSlider lengthSlider = new JSlider(8, 64, 16);
        lengthSlider.setBackground(theme.bgCard);
        lengthSlider.setForeground(theme.accent);
        JLabel lenLabel = styledLabel("16 characters", FONT_BODY, theme.textPrimary);
        lengthSlider.addChangeListener(e -> lenLabel.setText(lengthSlider.getValue() + " characters"));
        panel.add(lenLabel);
        panel.add(lengthSlider);
        panel.add(Box.createVerticalStrut(12));

        JCheckBox upperCb = createPremiumCheckbox("Uppercase (A-Z)", true);
        JCheckBox lowerCb = createPremiumCheckbox("Lowercase (a-z)", true);
        JCheckBox digitsCb = createPremiumCheckbox("Digits (0-9)", true);
        JCheckBox symbolsCb = createPremiumCheckbox("Symbols (!@#$%)", true);
        panel.add(upperCb); panel.add(Box.createVerticalStrut(4));
        panel.add(lowerCb); panel.add(Box.createVerticalStrut(4));
        panel.add(digitsCb); panel.add(Box.createVerticalStrut(4));
        panel.add(symbolsCb);
        panel.add(Box.createVerticalStrut(12));

        // Strength bar
        JProgressBar strengthBar = new JProgressBar(0, 5);
        strengthBar.setPreferredSize(new Dimension(200, 5));
        strengthBar.setBackground(theme.bgInput);
        strengthBar.setBorderPainted(false);
        strengthBar.setMaximumSize(new Dimension(Integer.MAX_VALUE, 5));
        JLabel strengthLabel = styledLabel("", FONT_SMALL, theme.textSecondary);
        panel.add(strengthBar);
        panel.add(strengthLabel);
        panel.add(Box.createVerticalStrut(16));

        Runnable generate = () -> {
            String pw = CryptoEngine.generatePassword(lengthSlider.getValue(),
                upperCb.isSelected(), lowerCb.isSelected(), digitsCb.isSelected(), symbolsCb.isSelected());
            output.setText(pw);
            int str = CryptoEngine.getPasswordStrength(pw);
            strengthBar.setValue(str);
            String[] labels = {"", "Very Weak", "Weak", "Fair", "Strong", "Very Strong"};
            Color[] colors = {theme.danger, theme.danger, theme.warning, theme.warning, theme.success, theme.success};
            strengthLabel.setText(labels[str]);
            strengthLabel.setForeground(colors[str]);
            strengthBar.setForeground(colors[str]);
        };
        generate.run();

        JPanel btns = new JPanel(new FlowLayout(FlowLayout.CENTER, 10, 0));
        btns.setOpaque(false);
        JButton regenBtn = createPremiumButton("🔄 Regenerate");
        regenBtn.addActionListener(e -> generate.run());
        JButton copyBtn = createSmallButton("📋 Copy");
        copyBtn.addActionListener(e -> {
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(output.getText()), null);
            toastManager.show("Password copied!", "success", 2000);
        });
        JButton closeBtn = createSmallButton("Close");
        closeBtn.addActionListener(e -> dialog.dispose());
        btns.add(regenBtn); btns.add(copyBtn); btns.add(closeBtn);
        panel.add(btns);

        dialog.add(panel);
        dialog.setVisible(true);
    }

    // ======================== SETTINGS DIALOG ========================
    private void showSettingsDialog() {
        JDialog dialog = createPremiumDialog("Settings", 440, 380);
        JPanel panel = createDialogPanel();

        panel.add(wrapLeft(styledLabel("⚙ Settings", new Font("Segoe UI", Font.BOLD, 20), theme.textPrimary)));
        panel.add(Box.createVerticalStrut(25));

        panel.add(wrapLeft(styledLabel("Auto-lock timeout (minutes)", FONT_SMALL, theme.textSecondary)));
        JSlider lockSlider = new JSlider(1, 30, userData != null ? userData.autoLockMinutes : 5);
        lockSlider.setBackground(theme.bgCard);
        lockSlider.setForeground(theme.accent);
        JLabel lockTimeLabel = styledLabel("Timeout: " + lockSlider.getValue() + " min", FONT_BODY, theme.textPrimary);
        lockSlider.addChangeListener(e -> lockTimeLabel.setText("Timeout: " + lockSlider.getValue() + " min"));
        panel.add(lockTimeLabel);
        panel.add(lockSlider);
        panel.add(Box.createVerticalStrut(20));

        panel.add(wrapLeft(styledLabel("Default password expiry (days)", FONT_SMALL, theme.textSecondary)));
        JSlider expirySlider = new JSlider(30, 365, 90);
        expirySlider.setBackground(theme.bgCard);
        expirySlider.setForeground(theme.accent);
        JLabel expiryLabel = styledLabel("Expiry: " + expirySlider.getValue() + " days", FONT_BODY, theme.textPrimary);
        expirySlider.addChangeListener(e -> expiryLabel.setText("Expiry: " + expirySlider.getValue() + " days"));
        panel.add(expiryLabel);
        panel.add(expirySlider);
        panel.add(Box.createVerticalStrut(25));

        // Login activity info
        panel.add(wrapLeft(styledLabel("Login Activity", FONT_SMALL, theme.textSecondary)));
        panel.add(Box.createVerticalStrut(4));
        panel.add(wrapLeft(styledLabel("Total logins: " + loginActivity.totalLoginCount, FONT_BODY, theme.textPrimary)));
        String last = loginActivity.lastLoginTime > 0 ?
            new SimpleDateFormat("MMM dd, yyyy HH:mm").format(new Date(loginActivity.lastLoginTime)) : "N/A";
        panel.add(wrapLeft(styledLabel("Last login: " + last, FONT_BODY, theme.textPrimary)));
        panel.add(Box.createVerticalStrut(20));

        JPanel btns = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 0));
        btns.setOpaque(false);
        JButton cancelBtn = createSmallButton("Cancel");
        cancelBtn.addActionListener(e -> dialog.dispose());
        JButton saveBtn = createPremiumButton("Save");
        saveBtn.addActionListener(e -> {
            if (userData != null) {
                userData.autoLockMinutes = lockSlider.getValue();
                Storage.save(userData);
                startAutoLockTimer();
                toastManager.show("Settings saved!", "success", 2000);
            }
            dialog.dispose();
        });
        btns.add(cancelBtn); btns.add(saveBtn);
        panel.add(btns);

        dialog.add(panel);
        dialog.setVisible(true);
    }

    // ======================== BACKUP DIALOG ========================
    private void showBackupDialog() {
        JDialog dialog = createPremiumDialog("Backup Manager", 460, 400);
        JPanel panel = createDialogPanel();

        panel.add(wrapLeft(styledLabel("📦 Backup Manager", new Font("Segoe UI", Font.BOLD, 20), theme.textPrimary)));
        panel.add(Box.createVerticalStrut(15));

        File[] backups = Storage.getBackups();
        panel.add(wrapLeft(styledLabel("Available backups: " + backups.length + " (max 5)", FONT_SMALL, theme.textSecondary)));
        panel.add(Box.createVerticalStrut(10));

        DefaultListModel<String> listModel = new DefaultListModel<>();
        for (File f : backups) {
            String name = f.getName().replace("backup_", "").replace(".dat", "");
            long size = f.length();
            listModel.addElement(name + "  (" + (size / 1024) + " KB)");
        }
        JList<String> backupList = new JList<>(listModel);
        backupList.setFont(FONT_BODY);
        backupList.setBackground(theme.bgInput);
        backupList.setForeground(theme.textPrimary);
        backupList.setSelectionBackground(theme.accent);
        backupList.setSelectionForeground(Color.WHITE);
        JScrollPane listScroll = new JScrollPane(backupList);
        listScroll.setPreferredSize(new Dimension(400, 180));
        listScroll.setBorder(BorderFactory.createLineBorder(theme.border));
        panel.add(listScroll);
        panel.add(Box.createVerticalStrut(15));

        JPanel btns = new JPanel(new FlowLayout(FlowLayout.CENTER, 10, 0));
        btns.setOpaque(false);

        JButton createBtn = createPremiumButton("Create Backup");
        createBtn.addActionListener(e -> {
            Storage.createBackup();
            toastManager.show("Backup created!", "success", 2000);
            dialog.dispose();
        });
        btns.add(createBtn);

        JButton restoreBtn = createSmallButton("Restore Selected");
        restoreBtn.addActionListener(e -> {
            int idx = backupList.getSelectedIndex();
            if (idx < 0) { toastManager.show("Select a backup first", "warning", 2000); return; }
            int confirm = JOptionPane.showConfirmDialog(dialog,
                "Restore this backup? Current data will be overwritten.", "Confirm Restore", JOptionPane.YES_NO_OPTION);
            if (confirm == JOptionPane.YES_OPTION) {
                if (Storage.restoreBackup(backups[idx])) {
                    toastManager.show("Backup restored! Please re-login.", "success", 3000);
                    dialog.dispose();
                    lockVault();
                } else {
                    toastManager.show("Restore failed!", "error", 3000);
                }
            }
        });
        btns.add(restoreBtn);

        JButton closeBtn = createSmallButton("Close");
        closeBtn.addActionListener(e -> dialog.dispose());
        btns.add(closeBtn);
        panel.add(btns);

        dialog.add(panel);
        dialog.setVisible(true);
    }

    // ======================== CSV IMPORT ========================
    private void importFromCSV() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Import from CSV");
        chooser.setFileFilter(new FileNameExtensionFilter("CSV Files", "csv"));
        if (chooser.showOpenDialog(this) != JFileChooser.APPROVE_OPTION) return;

        File file = chooser.getSelectedFile();
        int imported = 0;
        try (BufferedReader br = new BufferedReader(new FileReader(file))) {
            String line = br.readLine(); // skip header
            while ((line = br.readLine()) != null) {
                String[] parts = line.split(",", -1);
                if (parts.length >= 4) {
                    String site = parts[0].trim().replace("\"", "");
                    String url = parts.length > 1 ? parts[1].trim().replace("\"", "") : "";
                    String user = parts[2].trim().replace("\"", "");
                    String pass = parts[3].trim().replace("\"", "");
                    String cat = parts.length > 4 ? parts[4].trim().replace("\"", "") : "Other";
                    String notes = parts.length > 5 ? parts[5].trim().replace("\"", "") : "";

                    if (!site.isEmpty() && !user.isEmpty() && !pass.isEmpty()) {
                        String encrypted = CryptoEngine.encrypt(pass, masterPassword, userData.salt);
                        PasswordEntry entry = new PasswordEntry(site, url, user, encrypted, cat, notes);
                        userData.entries.add(entry);
                        imported++;
                    }
                }
            }
            Storage.save(userData);
            rebuildUI(); refreshDashboard();
            cardLayout.show(mainPanel, "dashboard"); startAutoLockTimer();
            toastManager.show("Imported " + imported + " passwords!", "success", 3000);
        } catch (Exception e) {
            toastManager.show("Import failed: " + e.getMessage(), "error", 3000);
        }
    }

    // ======================== CSV EXPORT ========================
    private void exportToCSV() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Export to CSV");
        chooser.setSelectedFile(new File("vaultkeeper_export.csv"));
        chooser.setFileFilter(new FileNameExtensionFilter("CSV Files", "csv"));
        if (chooser.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) return;

        File file = chooser.getSelectedFile();
        try (PrintWriter pw = new PrintWriter(new FileWriter(file))) {
            pw.println("Site,URL,Username,Password,Category,Notes");
            for (PasswordEntry entry : userData.entries) {
                String decrypted = CryptoEngine.decrypt(entry.encryptedPassword, masterPassword, userData.salt);
                pw.printf("\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"%n",
                    entry.siteName, entry.siteUrl, entry.username, decrypted, entry.category, entry.notes != null ? entry.notes : "");
            }
            toastManager.show("Exported " + userData.entries.size() + " passwords!", "success", 3000);
        } catch (Exception e) {
            toastManager.show("Export failed: " + e.getMessage(), "error", 3000);
        }
    }

    // ======================== PREMIUM UI COMPONENTS ========================

    private JDialog createPremiumDialog(String title, int width, int height) {
        JDialog dialog = new JDialog(this, title, true);
        dialog.setSize(width, height);
        dialog.setLocationRelativeTo(this);
        dialog.setUndecorated(true);
        dialog.getRootPane().setBorder(new AbstractBorder() {
            public void paintBorder(Component c, Graphics g, int x, int y, int w, int h) {
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                g2.setColor(theme.border);
                g2.drawRoundRect(x, y, w-1, h-1, 16, 16);
                g2.dispose();
            }
            public Insets getBorderInsets(Component c) { return new Insets(1,1,1,1); }
        });
        dialog.setShape(new RoundRectangle2D.Double(0, 0, width, height, 16, 16));
        return dialog;
    }

    private JPanel createDialogPanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBackground(theme.bgCard);
        panel.setBorder(BorderFactory.createEmptyBorder(30, 30, 30, 30));
        return panel;
    }

    private JButton createPremiumButton(String text) {
    JButton btn = new JButton(text) {
        protected void paintComponent(Graphics g) {
            float scale = 1f;
            Object s = getClientProperty("scale");
            if (s instanceof Float) scale = (Float) s;

            Graphics2D g2 = (Graphics2D) g.create();
            g2.scale(scale, scale);

            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);

            // Shadow (elevation)
            if (scale > 1f) {
                g2.setColor(new Color(0, 0, 0, 60));
                g2.fillRoundRect(4, 6, getWidth()-4, getHeight()-4, 22, 22);
            }

            // Button background
            GradientPaint gp = new GradientPaint(
                0, 0, theme.accentHover,
                0, getHeight(), theme.accent
            );
            g2.setPaint(gp);
            g2.fillRoundRect(0, 0, getWidth(), getHeight(), 22, 22);

            // Glow effect
            if (scale > 1f) {
                g2.setComposite(AlphaComposite.getInstance(AlphaComposite.SRC_OVER, 0.25f));
                g2.setColor(Color.WHITE);
                g2.fillRoundRect(0, 0, getWidth(), getHeight()/2, 22, 22);
                g2.setComposite(AlphaComposite.getInstance(AlphaComposite.SRC_OVER, 1f));
            }

            // Text
            g2.setColor(Color.WHITE);
            g2.setFont(getFont());
            FontMetrics fm = g2.getFontMetrics();
            int x = (getWidth() - fm.stringWidth(getText())) / 2;
            int y = (getHeight() + fm.getAscent()) / 2 - 2;
            g2.drawString(getText(), x, y);

            // Ripple effect
            Object rippleTime = getClientProperty("ripple");
            if (rippleTime instanceof Long) {
                long elapsed = System.currentTimeMillis() - (Long) rippleTime;
                if (elapsed < 500) {
                    float progress = elapsed / 500f;
                    int radius = (int)(progress * getWidth());
                    Graphics2D gRipple = (Graphics2D) g.create();
                    gRipple.setComposite(AlphaComposite.getInstance(
                        AlphaComposite.SRC_OVER, 0.2f * (1 - progress)
                    ));
                    gRipple.setColor(Color.WHITE);
                    gRipple.fillOval(getWidth()/2 - radius/2, getHeight()/2 - radius/2, radius, radius);
                    gRipple.dispose();
                }
            }

            g2.dispose();
        }
    };

    btn.setContentAreaFilled(false);
    btn.setBorderPainted(false);
    btn.setFocusPainted(false);
    btn.setCursor(new Cursor(Cursor.HAND_CURSOR));
    btn.setFont(FONT_BUTTON);
    btn.setBorder(BorderFactory.createEmptyBorder(12, 22, 12, 22));

    // Smooth animation
    addHoverEffect(btn);

    // Ripple trigger
    btn.addActionListener(e -> {
        btn.putClientProperty("ripple", System.currentTimeMillis());
    });

    return btn;
}

    private JButton createSmallButton(String text) {
        JButton btn = new JButton(text) {
            protected void paintComponent(Graphics g) {
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                int w = getWidth(), h = getHeight();
                if (getModel().isRollover()) {
                    g2.setColor(new Color(theme.accent.getRed(), theme.accent.getGreen(), theme.accent.getBlue(), 25));
                } else {
                    g2.setColor(new Color(theme.bgInput.getRed(), theme.bgInput.getGreen(), theme.bgInput.getBlue(), 160));
                }
                g2.fillRoundRect(0, 0, w, h, 10, 10);
                g2.setColor(theme.border);
                g2.drawRoundRect(0, 0, w-1, h-1, 10, 10);
                g2.setFont(FONT_SMALL);
                g2.setColor(theme.textPrimary);
                FontMetrics fm = g2.getFontMetrics();
                g2.drawString(getText(), (w - fm.stringWidth(getText())) / 2, (h + fm.getAscent() - fm.getDescent()) / 2);
                g2.dispose();
            }
        };
        btn.setPreferredSize(new Dimension(text.length() * 9 + 24, 34));
        btn.setContentAreaFilled(false);
        btn.setBorderPainted(false);
        btn.setFocusPainted(false);
        btn.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        return btn;
    }

    private JButton createToggleButton() {
        JButton btn = new JButton("👁") {
            protected void paintComponent(Graphics g) {
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                if (getModel().isRollover()) {
                    g2.setColor(new Color(theme.accent.getRed(), theme.accent.getGreen(), theme.accent.getBlue(), 25));
                } else {
                    g2.setColor(theme.bgInput);
                }
                g2.fillRoundRect(0, 0, getWidth(), getHeight(), 8, 8);
                g2.setFont(new Font("Segoe UI", Font.PLAIN, 15));
                g2.setColor(theme.textSecondary);
                FontMetrics fm = g2.getFontMetrics();
                g2.drawString(getText(), (getWidth() - fm.stringWidth(getText())) / 2,
                    (getHeight() + fm.getAscent() - fm.getDescent()) / 2);
                g2.dispose();
            }
        };
        btn.setPreferredSize(new Dimension(38, 38));
        btn.setContentAreaFilled(false);
        btn.setBorderPainted(false);
        btn.setFocusPainted(false);
        btn.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        return btn;
    }

    private JTextField createPremiumTextField(String placeholder) {
        JTextField field = new JTextField() {
            protected void paintComponent(Graphics g) {
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                g2.setColor(theme.bgInput);
                g2.fillRoundRect(0, 0, getWidth(), getHeight(), 10, 10);
                // Focus border
                if (hasFocus()) {
                    g2.setColor(theme.accent);
                    g2.setStroke(new BasicStroke(1.5f));
                    g2.drawRoundRect(0, 0, getWidth()-1, getHeight()-1, 10, 10);
                } else {
                    g2.setColor(theme.border);
                    g2.drawRoundRect(0, 0, getWidth()-1, getHeight()-1, 10, 10);
                }
                g2.dispose();
                super.paintComponent(g);
                // Placeholder
                if (getText().isEmpty() && !hasFocus()) {
                    Graphics2D g3 = (Graphics2D) g.create();
                    g3.setFont(getFont());
                    g3.setColor(theme.textSecondary);
                    g3.drawString(placeholder, getInsets().left, getHeight() / 2 + g3.getFontMetrics().getAscent() / 2 - 2);
                    g3.dispose();
                }
            }
        };
        field.setFont(FONT_BODY);
        field.setForeground(theme.textPrimary);
        field.setCaretColor(theme.textPrimary);
        field.setOpaque(false);
        field.setBorder(BorderFactory.createEmptyBorder(8, 14, 8, 14));
        field.setMaximumSize(new Dimension(Integer.MAX_VALUE, 42));
        field.setPreferredSize(new Dimension(200, 42));
        return field;
    }

    private JPasswordField styledPasswordField(String placeholder) {
        JPasswordField field = new JPasswordField() {
            protected void paintComponent(Graphics g) {
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                g2.setColor(theme.bgInput);
                g2.fillRoundRect(0, 0, getWidth(), getHeight(), 10, 10);
                if (hasFocus()) {
                    g2.setColor(theme.accent);
                    g2.setStroke(new BasicStroke(1.5f));
                    g2.drawRoundRect(0, 0, getWidth()-1, getHeight()-1, 10, 10);
                } else {
                    g2.setColor(theme.border);
                    g2.drawRoundRect(0, 0, getWidth()-1, getHeight()-1, 10, 10);
                }
                g2.dispose();
                super.paintComponent(g);
                if (getPassword().length == 0 && !hasFocus()) {
                    Graphics2D g3 = (Graphics2D) g.create();
                    g3.setFont(getFont());
                    g3.setColor(theme.textSecondary);
                    g3.drawString(placeholder, getInsets().left, getHeight() / 2 + g3.getFontMetrics().getAscent() / 2 - 2);
                    g3.dispose();
                }
            }
        };
        field.setFont(FONT_BODY);
        field.setForeground(theme.textPrimary);
        field.setCaretColor(theme.textPrimary);
        field.setOpaque(false);
        field.setBorder(BorderFactory.createEmptyBorder(8, 14, 8, 14));
        field.setPreferredSize(new Dimension(200, 44));
        return field;
    }

    @SuppressWarnings("unchecked")
    private JComboBox<String> createPremiumComboBox(String[] items) {
        JComboBox<String> combo = new JComboBox<>(items);
        combo.setFont(FONT_BODY);
        combo.setBackground(theme.bgInput);
        combo.setForeground(theme.textPrimary);
        combo.setBorder(BorderFactory.createEmptyBorder());
        combo.setRenderer(new DefaultListCellRenderer() {
            public Component getListCellRendererComponent(JList<?> list, Object value, int idx, boolean sel, boolean foc) {
                JLabel lbl = (JLabel) super.getListCellRendererComponent(list, value, idx, sel, foc);
                lbl.setFont(FONT_BODY);
                lbl.setBorder(BorderFactory.createEmptyBorder(6, 12, 6, 12));
                if (sel) {
                    lbl.setBackground(theme.accent);
                    lbl.setForeground(Color.WHITE);
                } else {
                    lbl.setBackground(theme.bgInput);
                    lbl.setForeground(theme.textPrimary);
                }
                return lbl;
            }
        });
        combo.setUI(new javax.swing.plaf.basic.BasicComboBoxUI() {
            protected JButton createArrowButton() {
                JButton btn = new JButton("▾") {
                    protected void paintComponent(Graphics g) {
                        Graphics2D g2 = (Graphics2D) g.create();
                        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                        g2.setColor(theme.bgInput);
                        g2.fillRect(0, 0, getWidth(), getHeight());
                        g2.setFont(new Font("Segoe UI", Font.PLAIN, 12));
                        g2.setColor(theme.textSecondary);
                        FontMetrics fm = g2.getFontMetrics();
                        g2.drawString("▾", (getWidth() - fm.stringWidth("▾")) / 2,
                            (getHeight() + fm.getAscent() - fm.getDescent()) / 2);
                        g2.dispose();
                    }
                };
                btn.setBorder(BorderFactory.createEmptyBorder());
                btn.setContentAreaFilled(false);
                return btn;
            }
            public void paintCurrentValueBackground(Graphics g, Rectangle bounds, boolean hasFocus) {
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setColor(theme.bgInput);
                g2.fillRoundRect(bounds.x, bounds.y, bounds.width, bounds.height, 10, 10);
                g2.dispose();
            }
        });
        return combo;
    }

    private JCheckBox createPremiumCheckbox(String text, boolean selected) {
        JCheckBox cb = new JCheckBox(text, selected);
        cb.setFont(FONT_BODY);
        cb.setForeground(theme.textPrimary);
        cb.setBackground(theme.bgCard);
        cb.setFocusPainted(false);
        cb.setAlignmentX(Component.LEFT_ALIGNMENT);
        cb.setIcon(new Icon() {
            public int getIconWidth() { return 20; }
            public int getIconHeight() { return 20; }
            public void paintIcon(Component c, Graphics g, int x, int y) {
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                if (cb.isSelected()) {
                    g2.setPaint(new GradientPaint(x, y, theme.gradStart1, x+20, y+20, theme.gradEnd1));
                    g2.fillRoundRect(x, y, 20, 20, 6, 6);
                    g2.setColor(Color.WHITE);
                    g2.setStroke(new BasicStroke(2f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));
                    g2.drawLine(x+5, y+10, x+8, y+14);
                    g2.drawLine(x+8, y+14, x+15, y+6);
                } else {
                    g2.setColor(theme.bgInput);
                    g2.fillRoundRect(x, y, 20, 20, 6, 6);
                    g2.setColor(theme.border);
                    g2.drawRoundRect(x, y, 20, 20, 6, 6);
                }
                g2.dispose();
            }
        });
        return cb;
    }

    // ======================== SMOOTH HOVER EFFECT ========================
    void addHoverEffect(JComponent comp) {
        comp.setCursor(new Cursor(Cursor.HAND_CURSOR));
        comp.putClientProperty("scale", 1.0f);
        comp.putClientProperty("targetScale", 1.0f);

        javax.swing.Timer timer = new javax.swing.Timer(16, e -> {
            Float current = (Float) comp.getClientProperty("scale");
            Float target = (Float) comp.getClientProperty("targetScale");
            if (current == null) current = 1.0f;
            if (target == null) target = 1.0f;

            float newScale = current + (target - current) * 0.15f;
            if (Math.abs(newScale - target) < 0.01f) newScale = target;

            comp.putClientProperty("scale", newScale);
            comp.repaint();
        });
        timer.start();

        comp.addMouseListener(new MouseAdapter() {
    public void mouseEntered(MouseEvent e) {
        comp.putClientProperty("targetScale", 1.1f);
    }
    public void mouseExited(MouseEvent e) {
        comp.putClientProperty("targetScale", 1.0f);
    }
    public void mousePressed(MouseEvent e) {
        comp.putClientProperty("targetScale", 0.94f);
    }
    public void mouseReleased(MouseEvent e) {
        comp.putClientProperty("targetScale", 1.1f);
    }
});
    }

    // ======================== UTILITY METHODS ========================
    private JLabel styledLabel(String text, Font font, Color color) {
        JLabel label = new JLabel(text);
        label.setFont(font);
        label.setForeground(color);
        return label;
    }

    private JPanel wrapLeft(JLabel label) {
        JPanel p = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        p.setOpaque(false);
        p.setMaximumSize(new Dimension(Integer.MAX_VALUE, label.getPreferredSize().height + 4));
        p.add(label);
        return p;
    }

    private Color darken(Color c, float factor) {
        return new Color(Math.max((int)(c.getRed() * factor), 0),
            Math.max((int)(c.getGreen() * factor), 0),
            Math.max((int)(c.getBlue() * factor), 0));
    }

    // Keep old methods for compatibility
    private JTextField styledTextField(String placeholder) { return createPremiumTextField(placeholder); }
    private JButton styledButton(String text, boolean primary) { return primary ? createPremiumButton(text) : createSmallButton(text); }
    private JButton miniButton(String text) { return createToggleButton(); }

    // ======================== MAIN ========================
    public static void main(String[] args) {
        try {
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
            UIManager.put("ScrollBar.width", 8);
            UIManager.put("ScrollBar.thumbArc", 999);
            UIManager.put("ScrollBar.thumbInsets", new Insets(2, 2, 2, 2));
        } catch (Exception ignored) {}
        SwingUtilities.invokeLater(PasswordManager::new);
    }
}


    