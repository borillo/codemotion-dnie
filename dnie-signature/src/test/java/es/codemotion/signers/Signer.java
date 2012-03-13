package es.codemotion.signers;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.Certificate;

public interface Signer
{
    byte[] sign(PrivateKey privateKey, byte[] data, Provider provider)
            throws GeneralSecurityException;

    boolean verify(Certificate certificate, byte[] data, byte[] signatureValue)
            throws GeneralSecurityException;
}
