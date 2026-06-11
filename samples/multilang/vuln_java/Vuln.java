import java.sql.*;

public class Vuln {
    public void getUser(String id) throws Exception {
        Connection conn = DriverManager.getConnection("jdbc:sqlite::memory:");
        Statement stmt = conn.createStatement();
        // Vulnerable: string concatenation leads to SQL injection
        String query = "SELECT * FROM users WHERE id=" + id;
        ResultSet rs = stmt.executeQuery(query);
    }
}
