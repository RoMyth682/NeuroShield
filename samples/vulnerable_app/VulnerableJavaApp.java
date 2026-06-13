import java.sql.*;
import java.util.Scanner;

public class VulnerableJavaApp {
    
    // Hardcoded credentials - Security vulnerability
    private static final String DB_USER = "admin";
    private static final String DB_PASSWORD = "password123";
    private static final String DB_URL = "jdbc:mysql://localhost:3306/mydb";
    
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("Enter username:");
        String username = scanner.nextLine();
        
        // SQL Injection vulnerability
        String query = "SELECT * FROM users WHERE username = '" + username + "'";
        executeQuery(query);
        
        // Hardcoded API key
        String apiKey = "sk-1234567890abcdefghijklmnop";
        System.out.println("Using API key: " + apiKey);
        
        scanner.close();
    }
    
    // Weak encryption method
    public static String encryptPassword(String password) {
        return "encrypted_" + password; // Not actually encrypted
    }
    
    // Command injection vulnerability
    public static void executeCommand(String userInput) {
        try {
            Runtime.getRuntime().exec("cmd /c " + userInput);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // Insecure deserialization
    public static Object deserializeData(byte[] data) {
        try {
            java.io.ByteArrayInputStream bis = new java.io.ByteArrayInputStream(data);
            java.io.ObjectInputStream ois = new java.io.ObjectInputStream(bis);
            return ois.readObject(); // Vulnerable to deserialization attacks
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
    
    // No input validation
    public static int divideNumbers(String numerator, String denominator) {
        int num = Integer.parseInt(numerator);
        int denom = Integer.parseInt(denominator);
        return num / denom; // Can cause division by zero or NumberFormatException
    }
    
    // Insecure random number generation
    public static String generateSessionToken() {
        java.util.Random random = new java.util.Random();
        return "token_" + random.nextInt(1000); // Predictable random
    }
    
    // Path traversal vulnerability
    public static String readFile(String filename) {
        try {
            java.nio.file.Path path = java.nio.file.Paths.get(filename);
            return new String(java.nio.file.Files.readAllBytes(path));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
    
    public static void executeQuery(String query) {
        Connection conn = null;
        try {
            Class.forName("com.mysql.cj.jdbc.Driver");
            conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
            Statement stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery(query);
            
            while (rs.next()) {
                System.out.println("User: " + rs.getString("username"));
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            if (conn != null) {
                try {
                    conn.close();
                } catch (SQLException e) {
                    e.printStackTrace();
                }
            }
        }
    }
}
