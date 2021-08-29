import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Collections;

public class Main {
    public static void main(String[] args) throws IOException, NoSuchAlgorithmException {
        File file = new File("./resources/doc.txt");
        FileInputStream stream = new FileInputStream(file);

        MessageDigest digest = MessageDigest.getInstance("SHA-256");

        byte[] bytes = digest.digest(stream.readAllBytes());

        StringBuilder sb = new StringBuilder();
        for(byte b: bytes) {
            sb.append(String.format("%02x", b));
        }

        Path output = Paths.get("./resources/output.txt");
        Files.write(output, Collections.singleton(sb.toString()), StandardCharsets.UTF_8);
    }
}
