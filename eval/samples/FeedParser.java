package feed;
import javax.xml.parsers.*;
import org.w3c.dom.Document;
import java.io.InputStream;
public class FeedParser {
    public Document parse(InputStream in) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        DocumentBuilder db = dbf.newDocumentBuilder();
        return db.parse(in);
    }
}
