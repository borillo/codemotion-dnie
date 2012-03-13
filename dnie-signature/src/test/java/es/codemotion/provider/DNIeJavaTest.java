package es.codemotion.provider;

import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Collections;

import org.dnieprov.jce.provider.DnieProvider;
import org.junit.BeforeClass;
import org.junit.Test;

import com.lowagie.text.DocumentException;
import com.lowagie.text.Font;
import com.lowagie.text.Rectangle;
import com.lowagie.text.pdf.PdfReader;
import com.lowagie.text.pdf.PdfSignatureAppearance;
import com.lowagie.text.pdf.PdfStamper;

public class DNIeJavaTest
{
    private static KeyStore keyStore;

    @BeforeClass
    public static void initDNIe() throws KeyStoreException, NoSuchAlgorithmException,
            CertificateException, IOException
    {
        Provider provider = new DnieProvider();
        Security.addProvider(provider);

        keyStore = KeyStore.getInstance("DNIe");
        keyStore.load(null, null);
    }

    @Test
    public void showCertificateInfo() throws Exception
    {
        for (String alias : Collections.list(keyStore.aliases()))
        {
            System.err.println("Alias: " + alias);

            if (keyStore.isCertificateEntry(alias))
            {
                System.err.println(">>> is cert");
                Certificate cert = keyStore.getCertificate(alias);
                System.out.println(cert);
            }
            else
            {
                System.err.println(">>> is key");
            }
        }
    }

    @Test
    public void pdfSignature() throws Exception
    {
        String inputFilename = "src/test/resources/in.pdf";
        String outputFilename = "target/out.pdf";

        for (String alias : Collections.list(keyStore.aliases()))
        {
            if (keyStore.isCertificateEntry(alias))
            {
                if (alias.contains("(FIRMA)"))
                {
                    PrivateKey key = (PrivateKey) keyStore.getKey(alias, null);
                    Certificate[] chain = keyStore.getCertificateChain(alias);

                    signPdf(inputFilename, outputFilename, key, chain);
                }
            }
        }
    }

    private void signPdf(String inputFilename, String outputFilename, PrivateKey key,
            Certificate[] chain) throws IOException, DocumentException, FileNotFoundException
    {
        PdfReader reader = new PdfReader(inputFilename);
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        PdfStamper stp = PdfStamper.createSignature(reader, bos, '\0');
        PdfSignatureAppearance sap = stp.getSignatureAppearance();
        sap.setCrypto(key, chain, null, PdfSignatureAppearance.SELF_SIGNED);
        sap.setReason("Ejemplo de firma Codemotion");
        Font font = new Font();
        font.setSize(10);
        sap.setLayer2Font(font);
        sap.setVisibleSignature(new Rectangle(210, 30, 390, 130), 1, null);
        stp.close();
        FileOutputStream fos = new FileOutputStream(outputFilename);
        fos.write(bos.toByteArray());
        fos.close();
    }
}
