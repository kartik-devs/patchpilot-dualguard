package shop;
import java.sql.*;
public class LoginDao {
    private final Connection conn;
    public LoginDao(Connection c) { this.conn = c; }
    public boolean authenticate(String user, String pass) throws Exception {
        Statement st = conn.createStatement();
        String sql = "SELECT id FROM accounts WHERE user = '" + user + "' AND pass = '" + pass + "'";
        ResultSet rs = st.executeQuery(sql);
        return rs.next();
    }
}
