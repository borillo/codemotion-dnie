package es.codemotion.provider;

import java.security.KeyStore;
import java.security.Security;

import org.dnieprov.jce.provider.DnieProvider;

import es.codemotion.signers.PKCS1Signer;

public class DNIeJavaTest extends ProviderBaseTest
{
    public DNIeJavaTest()
    {
        super(new PKCS1Signer());
    }

    @Override
    protected void initKeyStore() throws Exception
    {
        provider = new DnieProvider();
        Security.addProvider(provider);

        keyStore = KeyStore.getInstance("DNIe", provider);
        keyStore.load(null, null);
    }
}