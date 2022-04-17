package cz.vutbr.feec;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Arrays;

class KeyStoreLoader {

    private static final String DEFAULT_PASSWORD = "secret";
    private static final Logger logger = LoggerFactory.getLogger(KeyStoreLoader.class);

    private X509Certificate[] certificateChain;
    private X509Certificate certificate;
    private KeyPair keyPair;

    KeyStoreLoader load(Path baseDir, String file, String alias) throws Exception {
        return load(baseDir, file, alias, DEFAULT_PASSWORD);
    }

    KeyStoreLoader load(Path baseDir, String file, String alias, String password) throws Exception {
        char[] pass = password.toCharArray();
        KeyStore keyStore = KeyStore.getInstance("PKCS12");

        Path keystore = baseDir.resolve(file);

        logger.info("Loading KeyStore at {}", keystore);
        keyStore.load(Files.newInputStream(keystore), pass);

        Key privateKey = keyStore.getKey(alias, pass);
        if (privateKey instanceof PrivateKey) {
            certificate = (X509Certificate) keyStore.getCertificate(alias);
            certificateChain = Arrays.stream(keyStore.getCertificateChain(alias))
                    .map(X509Certificate.class::cast)
                    .toArray(X509Certificate[]::new);
            PublicKey serverPublicKey = certificate.getPublicKey();
            keyPair = new KeyPair(serverPublicKey, (PrivateKey) privateKey);
        }
        return this;
    }

    public X509Certificate getCertificate() {
        return certificate;
    }

    public X509Certificate[] getCertificateChain() {
        return certificateChain;
    }

    KeyPair getKeyPair() {
        return keyPair;
    }
}
