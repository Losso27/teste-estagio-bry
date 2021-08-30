import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.Store;

import java.io.*;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class Main {
    public static void main(String[] args) throws CMSException, KeyStoreException, CertificateException, NoSuchAlgorithmException, OperatorCreationException {

        KeyStore ks = KeyStore.getInstance("pkcs12");
        char[] password = "123456789".toCharArray();
        byte[] signedData = null;

        try {
        ks.load(new FileInputStream("./src/main/resources/pkcs12/DesafioEstagioJava.p12"), password);
        File file = new File("./src/main/resources/signed-doc.p7s");
        FileInputStream stream = new FileInputStream(file);
        signedData = stream.readAllBytes();
        } catch (IOException e)  {
            System.out.println("Erro ao ler os arquivos");
            System.exit(0);
        }

        Certificate cert = ks.getCertificate("f22c0321-1a9a-4877-9295-73092bb9aa94");
        List<Certificate> certList = new ArrayList<>();
        certList.add(cert);
        Store certs = new JcaCertStore(certList);


        CMSSignedData cmsSignedData = new CMSSignedData(ContentInfo.getInstance(signedData));

        SignerInformationStore signers = cmsSignedData.getSignerInfos();
        SignerInformation signer = signers.getSigners().iterator().next();
        Collection<X509CertificateHolder> certCollection = certs.getMatches(signer.getSID());
        X509CertificateHolder certificateHolder = certCollection.iterator().next();

        System.out.println(signer.verify(new JcaSimpleSignerInfoVerifierBuilder().build(certificateHolder)));
    }
}
