import org.apache.jcp.xml.dsig.internal.dom.DOMSignedInfo;
import org.apache.poi.EncryptedDocumentException;
import org.apache.poi.openxml4j.opc.OPCPackage;
import org.apache.poi.openxml4j.opc.PackageAccess;
import org.apache.poi.poifs.crypt.HashAlgorithm;
import org.apache.poi.poifs.crypt.dsig.SignatureConfig;
import org.apache.poi.poifs.crypt.dsig.SignatureInfo;
import org.apache.poi.poifs.crypt.dsig.facets.KeyInfoSignatureFacet;
import org.apache.poi.poifs.crypt.dsig.facets.OOXMLSignatureFacet;
import org.apache.poi.poifs.crypt.dsig.facets.Office2010SignatureFacet;
import org.apache.poi.poifs.crypt.dsig.facets.XAdESSignatureFacet;
import org.apache.poi.poifs.crypt.dsig.facets.XAdESXLSignatureFacet;
import org.apache.poi.util.POILogFactory;
import org.apache.poi.util.POILogger;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509ExtensionUtils;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.ocsp.*;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.w3c.dom.Document;


import javax.xml.crypto.dsig.dom.DOMSignContext;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import org.apache.poi.ooxml.util.DocumentHelper;


public class SimpleSign {
    private X509Certificate x509;
    private KeyPair keyPair;
    private File _resolvedDataDir;
    private static final POILogger LOG = POILogFactory.getLogger(SimpleSign.class);
    private static Calendar cal;

    public static void main(String[] args) {
        SimpleSign sign = new SimpleSign();
        try {
            sign.sign();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    void sign() throws Exception {
        String pfxFile = "./src/main/cert/test.pfx";

        initKeyPair(pfxFile);
        File testFile = new File("E:\\Nms\\XAdESXLSignatureFacet\\src\\main\\resources\\sample.xlsx");

        try (XSSFWorkbook wb = new XSSFWorkbook();
             FileOutputStream fos = new FileOutputStream(testFile)) {
            wb.createSheet().createRow(0).createCell(0).setCellValue("Test");
            wb.write(fos);
        }

        SignatureConfig signatureConfig = new SignatureConfig();
        signatureConfig.setDigestAlgo(HashAlgorithm.sha256);
        signatureConfig.setKey(keyPair.getPrivate());
        signatureConfig.setSigningCertificateChain(Collections.singletonList(x509));


        signatureConfig.setTspUrl("http://timestamp.digicert.com");
        signatureConfig.setTspRequestPolicy(null); // comodoca request fails, if default policy is set ...
        signatureConfig.setTspOldProtocol(false);

        signatureConfig.setXadesDigestAlgo(HashAlgorithm.sha512);
        signatureConfig.setXadesRole("Xades Reviewer");
        signatureConfig.setSignatureDescription("test xades signature");

        signatureConfig.setSignatureFacets(Arrays.asList(
                new OOXMLSignatureFacet(),
                new KeyInfoSignatureFacet(),
                new XAdESSignatureFacet(),
                new Office2010SignatureFacet(),
                new XAdESXLSignatureFacet1()
        ));

        try (OPCPackage pkg = OPCPackage.open(testFile, PackageAccess.READ_WRITE)) {
            SignatureInfo si = new SignatureInfo();
            si.setOpcPackage(pkg);
            si.setSignatureConfig(signatureConfig);
            final Document document = DocumentHelper.createDocument();
            final DOMSignContext xmlSignContext = si.createXMLSignContext(document);
            final DOMSignedInfo signedInfo = si.preSign(xmlSignContext);
            final String signatureValue = si.signDigest(xmlSignContext, signedInfo);

            // operate: postSign
            si.postSign(xmlSignContext, signatureValue);

            si.confirmSignature();
        } catch (EncryptedDocumentException e) {
            System.out.println(e.getMessage().startsWith("Export Restrictions"));
        }
    }
    private void initKeyPair(String pfxInput) throws Exception {
        char[] password = "test".toCharArray();

        File file = new File(pfxInput);
        BouncyCastleProvider provider = new BouncyCastleProvider();
        Security.addProvider(provider);

        KeyStore keystore = KeyStore.getInstance("PKCS12", provider.getName());
        keystore.load(new FileInputStream(pfxInput), password);
        String alias = (String) keystore.aliases().nextElement();
        System.out.println("alias:"+alias);
        if (file.exists()) {
            try (InputStream fis = new FileInputStream(file)) {
                keystore.load(new FileInputStream(pfxInput), password);
            }
        } else {
            keystore.load(null, password);
        }

        if (keystore.isKeyEntry(alias)) {
            Key key = keystore.getKey(alias, password);
            x509 = (X509Certificate)keystore.getCertificate(alias);
            keyPair = new KeyPair(x509.getPublicKey(), (PrivateKey)key);
        } else {
            keyPair = generateKeyPair();
            Date notBefore = cal.getTime();
            Calendar cal2 = (Calendar)cal.clone();
            cal2.add(Calendar.YEAR, 1);
            Date notAfter = cal2.getTime();
            KeyUsage keyUsage = new KeyUsage(KeyUsage.digitalSignature);

            x509 = generateCertificate(keyPair.getPublic(), notBefore, notAfter, keyPair.getPrivate(), keyUsage);

            keystore.setKeyEntry(alias, keyPair.getPrivate(), password, new Certificate[]{x509});

            if (pfxInput == null) {
                try (FileOutputStream fos = new FileOutputStream(file)) {
                    keystore.store(fos, password);
                }
            }
        }
    }
    private static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        SecureRandom random = new SecureRandom();
        keyPairGenerator.initialize(new RSAKeyGenParameterSpec(1024,
                RSAKeyGenParameterSpec.F4), random);
        return keyPairGenerator.generateKeyPair();
    }

    private static X509Certificate generateCertificate(PublicKey subjectPublicKey,
                                                       Date notBefore, Date notAfter,
                                                       PrivateKey issuerPrivateKey,
                                                       KeyUsage keyUsage)
            throws IOException, OperatorCreationException, CertificateException {
        final String signatureAlgorithm = "SHA1withRSA";
        final String subjectDn = "CN=Test";
        X500Name issuerName = new X500Name(subjectDn);

        RSAPublicKey rsaPubKey = (RSAPublicKey)subjectPublicKey;
        RSAKeyParameters rsaSpec = new RSAKeyParameters(false, rsaPubKey.getModulus(), rsaPubKey.getPublicExponent());

        SubjectPublicKeyInfo subjectPublicKeyInfo =
                SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(rsaSpec);

        DigestCalculator digestCalc = new JcaDigestCalculatorProviderBuilder()
                .setProvider("BC").build().get(CertificateID.HASH_SHA1);

        X509v3CertificateBuilder certificateGenerator = new X509v3CertificateBuilder(
                issuerName
                , new BigInteger(128, new SecureRandom())
                , notBefore
                , notAfter
                , new X500Name(subjectDn)
                , subjectPublicKeyInfo
        );

        X509ExtensionUtils exUtils = new X509ExtensionUtils(digestCalc);
        SubjectKeyIdentifier subKeyId = exUtils.createSubjectKeyIdentifier(subjectPublicKeyInfo);
        AuthorityKeyIdentifier autKeyId = exUtils.createAuthorityKeyIdentifier(subjectPublicKeyInfo);

        certificateGenerator.addExtension(Extension.subjectKeyIdentifier, false, subKeyId);
        certificateGenerator.addExtension(Extension.authorityKeyIdentifier, false, autKeyId);

        BasicConstraints bc = new BasicConstraints(0);
        certificateGenerator.addExtension(Extension.basicConstraints, false, bc);

        if (null != keyUsage) {
            certificateGenerator.addExtension(Extension.keyUsage, true, keyUsage);
        }

        JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder(signatureAlgorithm);
        signerBuilder.setProvider("BC");

        X509CertificateHolder certHolder =
                certificateGenerator.build(signerBuilder.build(issuerPrivateKey));

        return new JcaX509CertificateConverter().getCertificate(certHolder);
    }

}