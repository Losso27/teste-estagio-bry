import org.bouncycastle.asn1.pkcs.SignedData;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public class Main {
    public static void main(String[] args) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException, OperatorCreationException, CMSException {

        KeyStore ks = KeyStore.getInstance("pkcs12");
        char[] password = "123456789".toCharArray();
        File file = new File("./src/main/resources/doc.txt");
        FileInputStream stream = new FileInputStream(file);
        byte[] data = stream.readAllBytes();

        ks.load(new FileInputStream("./src/main/resources/pkcs12/DesafioEstagioJava.p12"), password);
        Certificate cert = ks.getCertificate("f22c0321-1a9a-4877-9295-73092bb9aa94");
        PrivateKey key = (PrivateKey) ks.getKey("f22c0321-1a9a-4877-9295-73092bb9aa94", password);

        CMSSignedDataGenerator cmsGenerator = new CMSSignedDataGenerator();
        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withRSA").build(key);
        Security.addProvider(new BouncyCastleProvider());

        cmsGenerator.addSignerInfoGenerator(
                new JcaSignerInfoGeneratorBuilder(
                        new JcaDigestCalculatorProviderBuilder().setProvider("BC").build())
                        .build(contentSigner, (X509Certificate) cert));

        CMSSignedData cms = cmsGenerator.generate(new CMSProcessableByteArray(data), true);
        Path output = Paths.get("./src/main/resources/output.p7s");
        Files.write(output, cms.getEncoded());
    }
}
