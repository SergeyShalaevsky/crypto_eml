import org.bouncycastle.cms.RecipientId;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientId;
import org.bouncycastle.mail.smime.SMIMEEnveloped;
import org.bouncycastle.mail.smime.SMIMEUtil;
import ru.CryptoPro.Crypto.CryptoProvider;
import ru.CryptoPro.JCP.JCP;
import ru.CryptoPro.reprov.RevCheck;

import javax.mail.Session;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Properties;

public class Decoder {
    public static void main(String... args){
        try {
            String filePath = "C:\\work\\eml_decoding\\";
            Security.addProvider(new JCP()); // JCP
            Security.addProvider(new RevCheck()); // RevCheck
            Security.addProvider(new CryptoProvider()); // JCryptoP

            for (Provider provider: Security.getProviders()) {
                System.out.println(provider.getName());
                for (Provider.Service s: provider.getServices()){
//                    if (s.getType().equals("Cipher"))
                        System.out.println("\t"+s.getType() + " " + s.getAlgorithm() + " " + s.getClassName());
                }
            }

            KeyStore keyStore = KeyStore.getInstance(JCP.HD_STORE_NAME);
            keyStore.load(null, null);

            PrivateKey privateKey = (PrivateKey) keyStore.getKey("b09b3dca-94cd-4455-9eb8-465499e84708", "1234567890".toCharArray());
            X509Certificate cert = (X509Certificate) keyStore.getCertificate("b09b3dca-94cd-4455-9eb8-465499e84708");

            RecipientId recId = new JceKeyTransRecipientId(cert);

            //
            // Get a Session object with the default properties.
            //
            Properties props = System.getProperties();

            Session session = Session.getDefaultInstance(props, null);

            MimeMessage msg = new MimeMessage(session, new FileInputStream(filePath + "Аналитический отчет по требованиям на РСВ AVSOLTEK (за февраль 2020) (1).eml"));

            SMIMEEnveloped m = new SMIMEEnveloped(msg);

            RecipientInformationStore recipients = m.getRecipientInfos();
            RecipientInformation recipient = recipients.get(recId);

            MimeBodyPart res = SMIMEUtil.toMimeBodyPart(recipient.getContent(new JceKeyTransEnvelopedRecipient(privateKey)));

            System.out.println("Message Contents");
            System.out.println("----------------");
            System.out.println(res.getContent());
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
