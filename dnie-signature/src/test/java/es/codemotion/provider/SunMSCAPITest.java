package es.codemotion.provider;

import java.security.KeyStore;

import es.codemotion.signers.PKCS1Signer;

public class SunMSCAPITest extends ProviderBaseTest
{
    public SunMSCAPITest()
    {
        super(new PKCS1Signer());
    }

    @Override
    protected void initKeyStore() throws Exception
    {
        keyStore = KeyStore.getInstance("Windows-MY");
        keyStore.load(null, null);
    }
}