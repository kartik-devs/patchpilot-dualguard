package shop;
import java.io.*;
import javax.servlet.http.*;
public class ProfileServlet extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String nick = req.getParameter("nick");
        PrintWriter out = resp.getWriter();
        out.println("<h1>Hello " + nick + "</h1>");
    }
}
