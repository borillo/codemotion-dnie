package es.codemotion.signers;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Signature;
import java.security.cert.Certificate;

public class PKCS1Signer implements Signer
{
    @Override
    public byte[] sign(PrivateKey privateKey, byte[] data, Provider provider)
            throws GeneralSecurityException
    {
        Signature signature = Signature.getInstance("SHA1withRSA", provider);
        signature.initSign(privateKey);
        signature.update(data);

        return signature.sign();
    }

    @Override
    public boolean verify(Certificate certificate, byte[] data, byte[] signatureValue)
            throws GeneralSecurityException
    {
        Signature signature = Signature.getInstance("SHA1withRSA");
        signature.initVerify(certificate);
        signature.update(data);

        return signature.verify(signatureValue);
    }
}