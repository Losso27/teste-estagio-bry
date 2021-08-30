package com.example.etapa4;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;
import org.springframework.context.annotation.Bean;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.NoSuchElementException;

public class CertificateManager {
    //Onde os certificados ficarão armazendos
    List<Certificate> certList;

    public CertificateManager () {
        certList = new ArrayList<>();
    }

    public byte[] sign(byte[] data, byte[] certBytes, char[] password, String alias) throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException, UnrecoverableKeyException, CMSException, OperatorCreationException {
        //Setup das chaves e do certificado
        KeyStore ks = KeyStore.getInstance("pkcs12");
        ks.load(new ByteArrayInputStream(certBytes), password);
        PrivateKey key = (PrivateKey) ks.getKey(alias, password);
        Certificate cert = ks.getCertificate(alias);
        certList.add(cert);

        //Setup para a assinatura
        CMSSignedDataGenerator cmsGenerator = new CMSSignedDataGenerator();
        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withRSA").build(key);
        Security.addProvider(new BouncyCastleProvider());
        cmsGenerator.addSignerInfoGenerator(
                new JcaSignerInfoGeneratorBuilder(
                        new JcaDigestCalculatorProviderBuilder().setProvider("BC").build())
                        .build(contentSigner, (X509Certificate) cert));

        //Assinatura do arquivo
        CMSSignedData cms = cmsGenerator.generate(new CMSProcessableByteArray(data), true);
        return cms.getEncoded();
    }

    public boolean verify(byte[] signedData) throws CertificateException, CMSException, OperatorCreationException {

        //upload dos certificados já usados para assinatura
        Store certs = new JcaCertStore(certList);

        //Setup do arquivo assinado
        CMSSignedData cmsSignedData = new CMSSignedData(ContentInfo.getInstance(signedData));

        //Busca os assinatarios do documento
        SignerInformationStore signers = cmsSignedData.getSignerInfos();
        SignerInformation signer = signers.getSigners().iterator().next();

        //Acha a intersecção com os assinatario do certificado
        Collection<X509CertificateHolder> certCollection = certs.getMatches(signer.getSID());
        X509CertificateHolder certificateHolder;

        //caso não haja nenhum assinatario correspondente retorna falso
        try {
            certificateHolder = certCollection.iterator().next();
        } catch (NoSuchElementException e) {
            return false;
        }

        return signer.verify(new JcaSimpleSignerInfoVerifierBuilder().build(certificateHolder));
    }
}
