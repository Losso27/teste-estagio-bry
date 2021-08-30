package com.example.etapa4;


import org.bouncycastle.cms.CMSException;
import org.bouncycastle.operator.OperatorCreationException;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestPart;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

@RestController
public class UploadController {

    private CertificateManager certificateManager;

    public UploadController(){
        certificateManager = new CertificateManager();
    }

    @PostMapping(value = "/sign", consumes = {MediaType.ALL_VALUE})
    public byte[] fileUpload(@RequestPart("alias") String alias,
                             @RequestPart("password") String password,
                             @RequestPart("file") MultipartFile file,
                             @RequestPart("cert") MultipartFile cert) throws IOException, UnrecoverableKeyException, CertificateException, KeyStoreException, NoSuchAlgorithmException, OperatorCreationException, CMSException {
        return certificateManager.sign(file.getBytes(), cert.getBytes(), password.toCharArray(), alias);
    }

    @GetMapping(value = "/verify", consumes = {MediaType.ALL_VALUE})
    public String verifyFile(@RequestPart("file") MultipartFile file) {

        boolean test;
        try {
            test = certificateManager.verify(file.getBytes());
        } catch (CertificateException | OperatorCreationException | CMSException | IOException e) {
            return "INVALIDO";
        }

        if(test){
            return "VALIDO";
        } else {
            return "INVALIDO";
        }
    }

}
