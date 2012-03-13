package es.codemotion.provider;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Collections;
import java.util.List;

import junit.framework.Assert;

import org.junit.Before;
import org.junit.Test;

public class SunMSCAPITest
{
    private KeyStore keyStore;
    private byte[] data;
    private String alias;
    private PrivateKey privateKey;
    private Provider provider;
    private Certificate certificate;

    @Before
    public void init() throws Exception
    {
        keyStore = KeyStore.getInstance("Windows-MY");
        keyStore.load(null, null);

        data = "test".getBytes();
        alias = keyStore.aliases().nextElement();

        certificate = keyStore.getCertificate(alias);
        privateKey = (PrivateKey) keyStore.getKey(alias, null);
        provider = keyStore.getProvider();
    }

    @Test
    public void showAliases() throws Exception
    {
        List<String> aliasList = Collections.list(keyStore.aliases());

        for (String alias : aliasList)
        {
            System.out.println(alias);
        }

        Assert.assertFalse(aliasList.isEmpty());
    }

    @Test
    public void pkcs1Signature() throws Exception
    {
        byte[] signatureValue = sign();

        Assert.assertNotNull(signatureValue);
        Assert.assertTrue(signatureValue.length > 0);
    }

    private byte[] sign() throws NoSuchAlgorithmException, InvalidKeyException, SignatureException
    {
        Signature signature = Signature.getInstance("SHA1withRSA", provider);
        signature.initSign(privateKey);
        signature.update(data);

        byte[] signatureValue = signature.sign();
        return signatureValue;
    }

    @Test
    public void verifiySignature() throws KeyStoreException, NoSuchAlgorithmException,
            CertificateException, IOException, UnrecoverableKeyException, InvalidKeyException,
            SignatureException
    {
        byte[] signatureValue = sign();

        Signature signature = Signature.getInstance("SHA1withRSA", provider);
        signature.initVerify(certificate);
        signature.update(data);

        Assert.assertTrue(signature.verify(signatureValue));
    }
}
