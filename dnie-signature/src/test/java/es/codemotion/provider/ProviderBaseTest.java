package es.codemotion.provider;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.Certificate;

import junit.framework.Assert;

import org.junit.Before;
import org.junit.Test;

import es.codemotion.signers.Signer;

public abstract class ProviderBaseTest
{
    protected KeyStore keyStore;
    protected Provider provider;

    protected PrivateKey privateKey;
    protected Certificate certificate;
    private final Signer signer;
    
    public ProviderBaseTest(Signer signer)
    {
        this.signer = signer;        
    }
    
    @Before 
    public void init() throws Exception
    {
        initKeyStore();

        String alias = keyStore.aliases().nextElement();

        certificate = keyStore.getCertificate(alias);
        privateKey = (PrivateKey) keyStore.getKey(alias, null);
    }
    
    @Test 
    public void signAndVerify() throws Exception
    {
        byte[] data = "test".getBytes();
        byte[] signatureValue = signer.sign(privateKey, data, provider);

        Assert.assertNotNull(signatureValue);
        Assert.assertTrue(signatureValue.length > 0);
        Assert.assertTrue(signer.verify(certificate, data, signatureValue));
    }
    
    protected abstract void initKeyStore() throws Exception;
}