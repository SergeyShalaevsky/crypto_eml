import com.objsys.asn1j.runtime.Asn1BerDecodeBuffer;
import org.apache.commons.io.IOUtils;
import org.apache.commons.mail.util.MimeMessageParser;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers;
import org.bouncycastle.cms.RecipientId;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientId;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.mail.smime.SMIMEEnveloped;
import org.bouncycastle.mail.smime.SMIMEUtil;
import ru.CryptoPro.Crypto.CryptoProvider;
import ru.CryptoPro.JCP.ASN.CryptographicMessageSyntax.*;
import ru.CryptoPro.JCP.ASN.Gost28147_89_EncryptionSyntax.Gost28147_89_Parameters;
import ru.CryptoPro.JCP.JCP;
import ru.CryptoPro.JCP.KeyStore.JCPPrivateKeyEntry;
import ru.CryptoPro.JCP.params.AlgIdSpec;
import ru.CryptoPro.JCP.params.JCPProtectionParameter;
import ru.CryptoPro.JCP.params.OID;
import ru.CryptoPro.JCP.spec.GostCipherSpec;
import ru.CryptoPro.JCP.tools.Array;
import ru.CryptoPro.reprov.RevCheck;

import javax.activation.DataSource;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.mail.Session;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Properties;

public class Decoder {
    /**
     * Режим шифрования.
     */
    private final static String CIPHER = "GOST28147";

    /**
     * Режим шифрования данных.
     */
    private final static String CIPHER_MODE = CIPHER + "/CFB/NoPadding";

    public static void main(String... args){
        try {
            String filePath = "C:\\work\\eml_decoding\\";
            Security.addProvider(new JCP()); // JCP
            Security.addProvider(new RevCheck()); // RevCheck
            Provider cryproProvider = new CryptoProvider();
            Security.addProvider(cryproProvider); // JCryptoP
            for (Provider provider: Security.getProviders()) {
                System.out.println(provider.getName());
                for (Provider.Service s: provider.getServices()){
//                    if (s.getType().equals("KeyAgreement"))
                        System.out.println("\t"+s.getType() + " " + s.getAlgorithm() + " " + s.getClassName());
                }
            }

            KeyStore keyStore = KeyStore.getInstance(JCP.HD_STORE_NAME);
            keyStore.load(null, null);

            //
            // Get a Session object with the default properties.
            //
            Properties props = System.getProperties();

            Session session = Session.getDefaultInstance(props, null);

            MimeMessage msg = new MimeMessage(session, new FileInputStream(filePath + "Аналитический отчет по требованиям на РСВ AVSOLTEK (за февраль 2020) (1).eml"));

            SMIMEEnveloped m = new SMIMEEnveloped(msg);

            // Разбор CMS-сообщения.

            Asn1BerDecodeBuffer dbuf = new Asn1BerDecodeBuffer(m.getEncoded());
            final ContentInfo all = new ContentInfo();

            all.decode(dbuf);
            dbuf.reset();

            final EnvelopedData cms = (EnvelopedData) all.content;
            KeyTransRecipientInfo key_trans;


            if (cms.recipientInfos.elements[0].getChoiceID() == RecipientInfo._KTRI) {
                key_trans = (KeyTransRecipientInfo) (cms.recipientInfos.elements[0].getElement());
            }
            else {
                throw new Exception("Unknown recipient info");
            }

            final byte[] wrapKey = key_trans.encryptedKey.value;
            final Gost28147_89_Parameters params = (Gost28147_89_Parameters)
                    cms.encryptedContentInfo.contentEncryptionAlgorithm.parameters;

            final byte[] iv = params.iv.value;
            final OID cipherOID = new OID(params.encryptionParamSet.value); // параметры шифрования данных
            final byte[] text = cms.encryptedContentInfo.encryptedContent.value;

            // Получатель - закрытый ключ.

            final JCPProtectionParameter protectionParameter =
                    new JCPProtectionParameter("1234567890".toCharArray());

            final JCPPrivateKeyEntry recipientEntry = (JCPPrivateKeyEntry) keyStore
                    .getEntry("b09b3dca-94cd-4455-9eb8-465499e84708", protectionParameter);

            // Выработка ключа согласования получателем и
            // расшифрование симметричного ключа.

            final SecretKey symmetricKey = LowJCPDecoder.unwrap(wrapKey,
                    recipientEntry.getPrivateKey());

            // Расшифрование текста на симметричном ключе.

            final GostCipherSpec spec = new GostCipherSpec(iv, cipherOID);
            Cipher cipher = Cipher.getInstance(CIPHER_MODE, CryptoProvider.PROVIDER_NAME);

            cipher.init(Cipher.DECRYPT_MODE, symmetricKey, spec, null);
            final byte[] result = cipher.doFinal(text, 0, text.length);

            Array.writeFile(filePath + "decrypted.eml", result);

            MimeMessage decryptedMessage = new MimeMessage(session, new ByteArrayInputStream(result));
            final MimeMessageParser mimeParser = new MimeMessageParser(decryptedMessage).parse();
            final List<DataSource> attachmentList = mimeParser.getAttachmentList();
            for (DataSource dataSource: attachmentList) {
                final String fileName = dataSource.getName();
                System.out.println("filename: " + fileName);
                try(FileOutputStream fileOutputStream = new FileOutputStream(filePath + dataSource.getName())) {
                    IOUtils.copy(dataSource.getInputStream(), fileOutputStream);
                }
            }
        }
        catch(Throwable th){
            th.printStackTrace();
        }
    }

    private static byte[] getContent(JceKeyTransRecipient recipientKey, RecipientInformation recipientInfo) {
        try {
            return recipientInfo.getContent(recipientKey);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
}
