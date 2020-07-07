import CAdES.configuration.container.EnvContainer2012_256;
import CAdES.configuration.container.EnvContainer2012_512;
import CAdES.configuration.container.ISignatureContainer;
import CMS_samples.CMSVerify;
import CMS_samples.CMStools;
import com.objsys.asn1j.runtime.Asn1BerDecodeBuffer;
import com.objsys.asn1j.runtime.Asn1BerEncodeBuffer;
import com.objsys.asn1j.runtime.Asn1Exception;
import com.objsys.asn1j.runtime.Asn1ObjectIdentifier;
import com.objsys.asn1j.runtime.Asn1OctetString;

import ru.CryptoPro.Crypto.CryptoProvider;

import ru.CryptoPro.JCP.ASN.CryptographicMessageSyntax.*;
import ru.CryptoPro.JCP.ASN.Gost28147_89_EncryptionSyntax.*;
import ru.CryptoPro.JCP.ASN.GostR3410_EncryptionSyntax.GostR3410_KeyTransport;
import ru.CryptoPro.JCP.ASN.GostR3410_EncryptionSyntax.GostR3410_TransportParameters;
import ru.CryptoPro.JCP.ASN.PKIX1Explicit88.*;

import ru.CryptoPro.JCP.JCP;
import ru.CryptoPro.JCP.KeyStore.JCPPrivateKeyEntry;
import ru.CryptoPro.JCP.params.*;
import ru.CryptoPro.JCP.spec.GostCipherSpec;
import ru.CryptoPro.JCP.spec.X509PublicKeySpec;
import ru.CryptoPro.JCP.tools.Array;
import ru.CryptoPro.JCP.Util.JCPInit;
import ru.CryptoPro.reprov.RevCheck;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.security.auth.x500.X500Principal;

import java.io.File;
import java.io.IOException;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.X509EncodedKeySpec;

public class LowJCPDecoder {

    /**
     * Подписываемые/шифруемые данные.
     */
    private static final byte[] DATA =
            (
                    "Security is our business.Security is our business.Security is our business.Security is our business." +
                            "Security is our business.Security is our business.Security is our business.Security is our business." +
                            "Security is our business.Security is our business.Security is our business.Security is our business." +
                            "Security is our business.Security is our business.Security is our business.Security is our business." +
                            "Security is our business.Security is our business.Security is our business.Security is our business." +
                            "Security is our business.Security is our business.Security is our business.Security is our business." +
                            "Security is our business.Security is our business.Security is our business.Security is our business." +
                            "Security is our business.Security is our business.Security is our business.Security is our business." +
                            "Security is our business.Security is our business.Security is our business.Security is our business." +
                            "Security is our business.Security is our business.Security is our business.Security is our business." +
                            "Security is our business.Security is our business.Security is our business.Security is our business." +
                            "Security is our business.Security is our business.Security is our business.Security is our business." +
                            "Security is our business.Security is our business.Security is our business.Security is our business." +
                            "Security is our business.Security is our business.Security is our business.Security is our business." +
                            "Security is our business.Security is our business.Security is our business.Security is our business." +
                            "Security is our business.Security is our business.Security is our business.Security is our business." +
                            "Security is our business.Security is our business.Security is our business.Security is our business." +
                            "Security is our business.Security is our business.Security is our business.Security is our business." +
                            "Security is our business.Security is our business.Security is our business.Security is our business." +
                            "Security is our business.Security is our business.Security is our business.Security is our business." +
                            "Security is our business.Security is our business.Security is our business.Security is our business." +
                            "Security is our business.Security is our business.Security is our business.Security is our business." +
                            "Security is our business.Security is our business.Security is our business.Security is our business." +
                            "Security is our business.Security is our business.Security is our business.Security is our business." +
                            "Security is our business.Security is our business.Security is our business.Security is our business." +
                            "Security is our business.Security is our business.Security is our business.Security is our business." +
                            "Security is our business.Security is our business.Security is our business.Security is our business." +
                            "Security is our business.Security is our business.Security is our business.Security is our business." +
                            "Security is our business.Security is our business.Security is our business.Security is our business."
            ).getBytes();

    /**
     * Контейнер получателя.
     */
    private final static ISignatureContainer RECIPIENT = new ISignatureContainer() {
        @Override
        public String getAlias() {
            return "b09b3dca-94cd-4455-9eb8-465499e84708";
        }

        @Override
        public char[] getPassword() {
            return "1234567890".toCharArray();
        }

        @Override
        public String getTsaAddress() {
            return null;
        }
    };

    /**
     * Папка с файлами.
     */
    private final static String TEST_DIR = System.getProperty("user.dir") +
            File.separator + "temp" + File.separator;

    /**
     * Режим шифрования.
     */
    private final static String CIPHER = "GOST28147";

    /**
     * Режим шифрования данных.
     */
    private final static String CIPHER_MODE = CIPHER + "/CFB/NoPadding";

    /**
     * Провайдер хранилища, подписи, хеширования.
     */
    private final static String PROVIDER_NAME = JCP.PROVIDER_NAME;

    /**
     * Провайдер шифрования.
     */
    private final static String CRYPT_PROVIDER_NAME = CryptoProvider.PROVIDER_NAME;

    /**
     * Тип контейнера.
     */
    private final static String STORE_TYPE = JCP.HD_STORE_NAME;

    /**
     * Хранилище контейнеров.
     */
    private static KeyStore keyStore;

//    static {
//        keyStore = loadKeyStore();
//    }

    /**
     * Загрузка контейнеров.
     * @return указатель на загруженные контейнеры.
     */
    public static KeyStore loadKeyStore() {

        try {

            KeyStore keyStore = KeyStore.getInstance(STORE_TYPE, PROVIDER_NAME);
            keyStore.load(null, null);

            return keyStore;

        } catch (Exception e) {
            throw new RuntimeException(e);
        }

    }

    /**
     * Зашифрование PKCS7 (Enveloped).
     *
     * @param recipientAlias - алиас получателя (сертификат).
     * @param data - исходное сообщение (PKCS7).
     * @return зашифрованное сообщение (enveloped).
     * @throws Exception
     */
    public static byte[] EncryptPKCS7(String recipientAlias,
                                      byte[] data) throws Exception {

        final X509Certificate recipientCert = (X509Certificate)
                keyStore.getCertificate(recipientAlias);

        return EncryptPKCS7(recipientCert, data);

    }

    /**
     * Извлечение параметров сертификата. Параметры шифрования
     * обычно null, поэтому будут получены параметры шифрования
     * по умолчанию.
     * У AlgIdSpec есть несколько конструкторов (с использованием
     * OID и др.).
     *
     * @param cert Сертификат.
     * @return параметры сертификата.
     * @throws Exception
     */
    public static AlgIdSpec getAlgIdSpec(X509Certificate cert)
            throws Exception {

        byte[] encoded = cert.getPublicKey().getEncoded();
        Asn1BerDecodeBuffer buf = new Asn1BerDecodeBuffer(encoded);
        SubjectPublicKeyInfo keyInfo = new SubjectPublicKeyInfo();

        try {
            keyInfo.decode(buf);
        } catch (Asn1Exception e) {
            IOException ex = new IOException("Not GOST DH public key");
            ex.initCause(e);
            throw ex;
        }

        buf.reset();
        return new AlgIdSpec(keyInfo.algorithm);

    }

    /**
     * Зашифрование сообщения (enveloped).
     *
     * @param recipientCert - сертификат получателя.
     * @param data - исходное сообщение (PKCS7).
     * @return зашифрованное сообщение (enveloped).
     * @throws Exception
     */
    public static byte[] EncryptPKCS7(X509Certificate recipientCert,
                                      byte[] data) throws Exception {

        final PublicKey recipientPublic = recipientCert.getPublicKey();

        // Генерирование симметричного ключа с параметрами
        // шифрования из контрольной панели.

        final KeyGenerator kg = KeyGenerator.getInstance(
                CMStools.SEC_KEY_ALG_NAME, CRYPT_PROVIDER_NAME);

        // Параметры шифрования симметричного ключа (по умолчанию)
        // и параметры шифрования данных (по умолчанию).

        final AlgIdSpec algIdSpec = getAlgIdSpec(recipientCert);

        final ParamsInterface recipientTransportParameters = algIdSpec.getCryptParams(); // из открытого ключа
        final ParamsInterface contentEncryptionParameters  = algIdSpec.getCryptParams(); // могут быть другие

        // Инициализация генератора.

        kg.init(contentEncryptionParameters);

        // Симметричный ключ.

        final SecretKey symmetricKey = kg.generateKey();

        // Зашифрование текста на симметричном ключе.

        Cipher cipher = Cipher.getInstance(CIPHER_MODE, CRYPT_PROVIDER_NAME);
        cipher.init(Cipher.ENCRYPT_MODE, symmetricKey, (SecureRandom) null);

        final byte[] iv = cipher.getIV();
        final byte[] text = cipher.doFinal(data, 0, data.length);

        // Зашифрование симметричного ключа.

        final byte[] keyTransport = wrap(symmetricKey, recipientPublic,
                recipientTransportParameters);

        // Формирование CMS-сообщения.

        final ContentInfo all = new ContentInfo();
        all.contentType = new Asn1ObjectIdentifier(new OID(CMStools.STR_CMS_OID_ENVELOPED).value);

        final EnvelopedData cms = new EnvelopedData();

        all.content = cms;
        cms.version = new CMSVersion(0);

        cms.recipientInfos = new RecipientInfos(1);
        cms.recipientInfos.elements = new RecipientInfo[1];
        cms.recipientInfos.elements[0] = new RecipientInfo();

        final KeyTransRecipientInfo key_trans = new KeyTransRecipientInfo();
        key_trans.version = new CMSVersion(0);

        final Asn1BerEncodeBuffer ebuf = new Asn1BerEncodeBuffer();

        final AlgorithmIdentifier id = (AlgorithmIdentifier) algIdSpec.getDecoded();
        id.encode(ebuf);

        Asn1BerDecodeBuffer dbuf = new Asn1BerDecodeBuffer(ebuf.getMsgCopy());
        key_trans.keyEncryptionAlgorithm = new KeyEncryptionAlgorithmIdentifier();
        key_trans.keyEncryptionAlgorithm.decode(dbuf);

        ebuf.reset();
        dbuf.reset();

        key_trans.rid = new RecipientIdentifier();
        final IssuerAndSerialNumber issuer = new IssuerAndSerialNumber();

        final X500Principal issuerName = recipientCert.getIssuerX500Principal();
        dbuf = new Asn1BerDecodeBuffer(issuerName.getEncoded());

        issuer.issuer = new Name();
        final RDNSequence rnd = new RDNSequence();
        rnd.decode(dbuf);

        issuer.issuer.set_rdnSequence(rnd);
        issuer.serialNumber = new CertificateSerialNumber(recipientCert.getSerialNumber());

        key_trans.rid.set_issuerAndSerialNumber(issuer);
        dbuf.reset();

        key_trans.encryptedKey = new EncryptedKey(keyTransport);
        ebuf.reset();

        cms.recipientInfos.elements[0].set_ktri(key_trans);
        cms.encryptedContentInfo = new EncryptedContentInfo();

        final OID contentType = new OID(CMStools.STR_CMS_OID_DATA);
        cms.encryptedContentInfo.contentType = new ContentType(contentType.value);

        final Gost28147_89_Parameters parameters = new Gost28147_89_Parameters();
        parameters.iv = new Gost28147_89_IV(iv);

        parameters.encryptionParamSet = new Gost28147_89_ParamSet(contentEncryptionParameters.getOID().value); // параметры шифрования данных
        cms.encryptedContentInfo.contentEncryptionAlgorithm = new ContentEncryptionAlgorithmIdentifier(
                _Gost28147_89_EncryptionSyntaxValues.id_Gost28147_89, parameters);

        cms.encryptedContentInfo.encryptedContent = new EncryptedContent(text);
        all.encode(ebuf);

        return ebuf.getMsgCopy();
    }

    /**
     * Расшифрование PKCS7 (Enveloped).
     *
     * @param recipientAlias - алиас получателя.
     * @param recipientPassword - пароль получателя.
     * @param enveloped - зашифрованное сообщение (Enveloped).
     * @param data - исходные данные (нужны при проверке detached CMS подписи).
     * @param detached - флаг detached подписи.
     * @return результат проверки.
     * @throws Exception
     */
    public static boolean DecryptPKCS7(String recipientAlias, char[]
            recipientPassword, byte[] enveloped, byte[] data, boolean
                                               detached) throws Exception {

        // Разбор CMS-сообщения.

        Asn1BerDecodeBuffer dbuf = new Asn1BerDecodeBuffer(enveloped);
        final ContentInfo all = new ContentInfo();

        all.decode(dbuf);
        dbuf.reset();

        final EnvelopedData cms = (EnvelopedData) all.content;
        KeyTransRecipientInfo key_trans;

        // Только key_trans.

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
                new JCPProtectionParameter(recipientPassword);

        final JCPPrivateKeyEntry recipientEntry = (JCPPrivateKeyEntry) keyStore
                .getEntry(recipientAlias, protectionParameter);

        // Выработка ключа согласования получателем и
        // расшифрование симметричного ключа.

        final SecretKey symmetricKey = unwrap(wrapKey,
                recipientEntry.getPrivateKey());

        // Расшифрование текста на симметричном ключе.

        final GostCipherSpec spec = new GostCipherSpec(iv, cipherOID);
        Cipher cipher = Cipher.getInstance(CIPHER_MODE, CRYPT_PROVIDER_NAME);

        cipher.init(Cipher.DECRYPT_MODE, symmetricKey, spec, null);
        final byte[] result = cipher.doFinal(text, 0, text.length);

        Array.writeFile(TEST_DIR + "cms_cms.bin", result);
        // checkPKCS7(result, detached, data, TEST_DIR + "cms_cms_data.txt");

        return true;

    }

    /**
     * Зашифрование сессионного ключа.
     *
     * @param secretKey Сессионный ключ.
     * @param recipientKey Открытый ключ получателя.
     * @return транспортная структура GostR3410_KeyTransport.
     * @throws Exception
     */
    private static byte[] wrap(SecretKey secretKey, PublicKey
            recipientKey, ParamsInterface recipientTransportParameters)
            throws Exception {

        // Определение алгоритма эфемерного ключа.

        String keyAlgorithm = recipientKey.getAlgorithm();
        String ephKeyAlgorithm = JCP.GOST_EL_DH_EPH_NAME;

        if (keyAlgorithm.equalsIgnoreCase(JCP.GOST_EL_2012_256_NAME)) {
            ephKeyAlgorithm = JCP.GOST_EPH_DH_2012_256_NAME;
        } // if
        else if (keyAlgorithm.equalsIgnoreCase(JCP.GOST_EL_2012_512_NAME)) {
            ephKeyAlgorithm = JCP.GOST_EPH_DH_2012_512_NAME;
        } // else

        // Генерация эфемерной пары.

        KeyPairGenerator kgp = KeyPairGenerator.getInstance(
                ephKeyAlgorithm, CRYPT_PROVIDER_NAME);

        // Устанавливаем нужные параметры, как у
        // получателя.

        AlgorithmParameterSpec spec = new X509PublicKeySpec(recipientKey.getEncoded());
        kgp.initialize(spec);

        // Генерируем эфемерную пару. Ключи получат
        // параметры recipientKey, а у него параметры
        // - recipientTransportParameters.

        KeyPair ephPair = kgp.generateKeyPair();

        PrivateKey privateKey = ephPair.getPrivate();
        PublicKey publicKey = ephPair.getPublic();

        byte[] syncro = new byte[8];
        SecureRandom random = SecureRandom.getInstance(JCP.CP_RANDOM, PROVIDER_NAME);
        random.nextBytes(syncro);

        IvParameterSpec iv = new IvParameterSpec(syncro);

        // Выработка ключа согласования.

        KeyAgreement ka = KeyAgreement.getInstance(privateKey.getAlgorithm(), CRYPT_PROVIDER_NAME);
        ka.init(privateKey, iv);

        ka.doPhase(recipientKey, true);
        Key dh = ka.generateSecret(CIPHER); // dh получит параметры из privateKey, т.е. recipientTransportParameters

        // Зашифрование симметричного ключа на ключе согласования
        // отправителя. Передаются параметры шифрования ключа, если
        // отличаются от тех, что у dh.

        final Cipher cipher = Cipher.getInstance(CIPHER, CRYPT_PROVIDER_NAME);
        cipher.init(Cipher.WRAP_MODE, dh, recipientTransportParameters, (SecureRandom) null);

        final byte[] wrappedKey = cipher.wrap(secretKey);

        // Упаковка параметров и ключа.

        Gost28147_89_EncryptedKey encryptedKey = new Gost28147_89_EncryptedKey();
        Asn1BerDecodeBuffer decoder = new Asn1BerDecodeBuffer(wrappedKey);
        encryptedKey.decode(decoder);

        byte[] imita = encryptedKey.macKey.value;
        byte[] wrapperKeyBytes = encryptedKey.encryptedKey.value;

        // Кодирование открытого ключа в SubjectPublicKeyInfo.

        byte[] publicKeyBytes = publicKey.getEncoded();
        SubjectPublicKeyInfo publicKeyInfo = new SubjectPublicKeyInfo();

        decoder = new Asn1BerDecodeBuffer(publicKeyBytes);
        publicKeyInfo.decode(decoder);

        // Кодирование GostR3410_KeyTransport.

        GostR3410_KeyTransport keyTransport = new GostR3410_KeyTransport();
        Asn1BerEncodeBuffer encoder = new Asn1BerEncodeBuffer();

        keyTransport.sessionEncryptedKey = new Gost28147_89_EncryptedKey(wrapperKeyBytes, imita);
        keyTransport.transportParameters = new GostR3410_TransportParameters(
                new Gost28147_89_ParamSet(recipientTransportParameters.getOID().value), // параметры шифрования ключа
                publicKeyInfo,
                new Asn1OctetString(iv.getIV()));

        keyTransport.encode(encoder);
        return encoder.getMsgCopy();

    }

    /**
     * Зашифрование сессионного ключа.
     *
     * @param wrappedKey Зашифрованный сессионный ключ (транспортная
     * структура GostR3410_KeyTransport).
     * @param recipientKey Закрытый ключ получателя.
     * @return сессионный ключ.
     * @throws Exception
     */
    public static SecretKey unwrap(byte[] wrappedKey, Key
            recipientKey) throws Exception {

        // Декодирование GostR3410_KeyTransport.

        GostR3410_KeyTransport keyTransport = new GostR3410_KeyTransport();
        Asn1BerDecodeBuffer decoder = new Asn1BerDecodeBuffer(wrappedKey);
        keyTransport.decode(decoder);

        // EncryptedKey в правильном формате для шифратора.

        byte[] wrappedKeyBytes = keyTransport.sessionEncryptedKey.encryptedKey.value;
        byte[] imita = keyTransport.sessionEncryptedKey.macKey.value;

        Asn1BerEncodeBuffer encoder = new Asn1BerEncodeBuffer();
        Gost28147_89_EncryptedKey encryptedKey = new Gost28147_89_EncryptedKey(
                new Gost28147_89_Key(wrappedKeyBytes),
                null, new Gost28147_89_MAC(imita));

        encryptedKey.encode(encoder);
        byte[] wrapped = encoder.getMsgCopy();

        // Декодирование открытого ключа.

        encoder.reset();
        keyTransport.transportParameters.ephemeralPublicKey.encode(encoder);

        byte[] encodedPublic = encoder.getMsgCopy();
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encodedPublic);

        KeyFactory kf = KeyFactory.getInstance(recipientKey.getAlgorithm(), PROVIDER_NAME);
        PublicKey publicKey = kf.generatePublic(keySpec);

        // Параметры шифрования.

        IvParameterSpec iv = new IvParameterSpec(keyTransport.transportParameters.ukm.value);
        OID transportParametersOid = new OID(keyTransport.transportParameters.encryptionParamSet.value); // параметры шифрования ключа

        CryptParamsSpec uz = CryptParamsSpec.getInstance(transportParametersOid);
        GostCipherSpec params = new GostCipherSpec(iv, uz);

        // Выработка ключа согласования.

        KeyAgreement ka = KeyAgreement.getInstance(recipientKey.getAlgorithm(), CRYPT_PROVIDER_NAME);
        ka.init(recipientKey, iv);

        ka.doPhase(publicKey, true);
        Key dh = ka.generateSecret(CIPHER); // dh получит параметры из recipientKey, т.е., по идее, transportParametersOid

        // Расшифрование сессионного ключа.

        Cipher cipher = Cipher.getInstance(CIPHER, CRYPT_PROVIDER_NAME);
        cipher.init(Cipher.UNWRAP_MODE, dh, params);

        return (SecretKey) cipher.unwrap(wrapped, null, Cipher.SECRET_KEY);

    }

    /**
     * Проверка PKCS7 подписи.
     *
     * @param signature - расшифрованная подпись.
     * @param detached  - флаг detached подписи.
     * @param data - исходные данные. Нужны при проверке detached подписи.
     * @param contentFile - файл для сохранения исходных данных.
     * @throws Exception
     */
    private static void checkPKCS7(byte[] signature, boolean detached,
                                   byte[] data, String contentFile) throws Exception {

        // 1. Проверка подписи PKCS7.

        CMSVerify.CMSVerifyEx(signature, null, detached ? data : null, PROVIDER_NAME);

        // 2. Извлечение текста, если он есть (для attached).

        final Asn1BerDecodeBuffer asnBuf = new Asn1BerDecodeBuffer(signature);
        final ContentInfo cInfo = new ContentInfo();

        cInfo.decode(asnBuf);
        final SignedData pkcs7 = (SignedData) cInfo.content;

        // 2. Сохранение текста в файл (для attached).

        if (pkcs7.encapContentInfo.eContent != null) {

            byte[] content = pkcs7.encapContentInfo.eContent.value;
            Array.writeFile(contentFile + ".data_content.txt", content);

            if (!Array.compare(content, data)) {
                throw new Exception("Invalid content");
            } // if

        } // if

    }

    /**
     * Выполнение создания PKCS7 подписи, зашифрования, расшифрования и
     * проверки подписи.
     *
     * @throws Exception
     */
    private static void test_SignEncrypt_DecryptVerify() throws Exception {

        // Данные для attached подписи. Нужны, если detached = true.
        //final byte[] data = Array.readFile(TEST_DIR + "in.txt");

        // Пусть подпишет получатель, у нас есть только его ключ.
        //PrivateKey signerKey = (PrivateKey) keyStore.getKey(RECIPIENT_ALIAS, RECIPIENT_PASSWORD);
        //X509Certificate signerCert = (X509Certificate) keyStore.getCertificate(RECIPIENT_ALIAS);

        // 1. Создание PKCS7.
	   /*
		CMSSign.createCMSEx(
				data,
				new PrivateKey[]{signerKey},
				new Certificate[]{signerCert},
				TEST_DIR + "jcp_attached_cms.bin",
				false,
				JCP.GOST_DIGEST_OID,
				JCP.GOST_EL_SIGN_OID,
				JCP.GOST_EL_SIGN_NAME,
				PROVIDER_NAME);
				*/
        // "C:\Program Files\Crypto Pro\CSP\csptest" -cmssfsign -sign -in "in.txt" -my signencr -add -out "csp_attached_cms.bin" (создание CSP)
        // "C:\Program Files\Crypto Pro\CSP\csptest" -cmssfsign -verify -in "cms_cms.bin" -my signencr (проверка подписи JCP с помощью CSP)

        // Файл с PKCS7 для зашифрования.
        final byte[] encryptingData = DATA; // Array.readFile(TEST_DIR + "jcp_attached_cms.bin");

        // 2. Зашифрование PKCS7.

        //X509Certificate recipientCert = (X509Certificate) CertificateFactory
        //	.getInstance("X.509").generateCertificate(new FileInputStream(
        //		"c:\\Support\\mironov\\primer JCP\\primer JCP.cer"));
        //

        byte[] enveloped =  EncryptPKCS7(RECIPIENT.getAlias(), encryptingData);
        // "C:\Program Files\Crypto Pro\CSP\csptest" -sfenc -encrypt -in "csp_attached_cms.bin" -out "csp_enveloped_cms.bin" -cert signenc (создание CSP)

        Array.writeFile(TEST_DIR + "jcp_enveloped_cms.bin", enveloped);

        // 3*. Расшифрование PKCS7 и проверка подписи.

        enveloped = Array.readFile(TEST_DIR + "jcp_enveloped_cms.bin");
        System.out.println( "Verified: " + DecryptPKCS7(RECIPIENT.getAlias(),
                RECIPIENT.getPassword(), enveloped, null, false) );

        // Для low data:
        // "C:\Program Files\Crypto Pro\CSP\csptest" -lowenc -decrypt -in "jcp_enveloped_cms.bin" -my gost_2012_512_exchange_dh_client
        // для CMS:
        // "C:\Program Files\Crypto Pro\CSP\csptest" -sfse -decrypt -in "jcp_enveloped_cms.bin" -out "csp_jcp_cms_data_content.txt" (проверка JCP с помощью CSP)
        // "C:\Program Files\Crypto Pro\CSP\csptest" -sfse -decrypt -in "csp_enveloped_cms.bin" -out "csp_cms_data_content.txt" (проверка CSP с помощью CSP)
        // content: *_content.txt == in.txt

    }

    /**
     * @param args
     * @throws Exception
     */
    public static void main(String[] args) throws Exception {
        JCPInit.initProviders(false);
        keyStore = loadKeyStore();
        test_SignEncrypt_DecryptVerify();
    }
}
