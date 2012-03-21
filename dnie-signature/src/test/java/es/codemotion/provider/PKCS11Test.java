package es.codemotion.provider;

import java.io.ByteArrayInputStream;
import java.security.KeyStore;
import java.security.Security;
import java.util.Scanner;

import es.codemotion.signers.PKCS1Signer;

public class PKCS11Test extends ProviderBaseTest
{
    public PKCS11Test()
    {
        super(new PKCS1Signer());
    }

    @Override
    @SuppressWarnings("restriction")
    protected void initKeyStore() throws Exception
    {
        String configuration = "name=dnie\rlibrary=/usr/local/lib/opensc-pkcs11.so";
        provider = new sun.security.pkcs11.SunPKCS11(new ByteArrayInputStream(
                configuration.getBytes()));
        Security.addProvider(provider);

        System.out.print("PIN: ");
        
        Scanner scanner = new Scanner(System.in);
        String passwordInput = scanner.nextLine();
        
        keyStore = KeyStore.getInstance("PKCS11", "SunPKCS11-dnie");
        keyStore.load(null, passwordInput.trim().toCharArray());
    }
}