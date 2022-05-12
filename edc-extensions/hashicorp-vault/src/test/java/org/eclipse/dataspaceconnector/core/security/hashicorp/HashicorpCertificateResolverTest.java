/*
 *  Copyright (c) 2022 Mercedes-Benz Tech Innovation GmbH
 *
 *  This program and the accompanying materials are made available under the
 *  terms of the Apache License, Version 2.0 which is available at
 *  https://www.apache.org/licenses/LICENSE-2.0
 *
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Contributors:
 *       Mercedes-Benz Tech Innovation GmbH - Initial Test
 *
 */

package org.eclipse.dataspaceconnector.core.security.hashicorp;

import static org.eclipse.dataspaceconnector.core.security.hashicorp.HashicorpVaultExtension.VAULT_TOKEN;
import static org.eclipse.dataspaceconnector.core.security.hashicorp.HashicorpVaultExtension.VAULT_URL;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.Optional;
import java.util.UUID;
import lombok.Getter;
import lombok.SneakyThrows;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509ExtensionUtils;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.eclipse.dataspaceconnector.junit.launcher.EdcExtension;
import org.eclipse.dataspaceconnector.spi.security.CertificateResolver;
import org.eclipse.dataspaceconnector.spi.security.Vault;
import org.eclipse.dataspaceconnector.spi.system.ServiceExtension;
import org.eclipse.dataspaceconnector.spi.system.ServiceExtensionContext;
import org.junit.ClassRule;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.shaded.org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.testcontainers.utility.DockerImageName;
import org.testcontainers.vault.VaultContainer;

@Testcontainers
@ExtendWith(EdcExtension.class)
class HashicorpCertificateResolverTest {
  private static final String DOCKER_IMAGE_NAME = "vault:1.9.6";
  private static final String TEST_TOKEN = "test-token";
  private static final Provider PROVIDER = new BouncyCastleProvider();
  private static final JcaX509CertificateConverter JCA_X509_CERTIFICATE_CONVERTER =
      new JcaX509CertificateConverter().setProvider(PROVIDER);
  private static final String SIGNATURE_ALGORITHM = "SHA256WithRSAEncryption";

  private final TestExtension testExtension = new TestExtension();

  @Container @ClassRule
  private static final VaultContainer<?> vaultContainer =
      new VaultContainer<>(DockerImageName.parse(DOCKER_IMAGE_NAME)).withVaultToken(TEST_TOKEN);

  @BeforeEach
  void beforeEach(EdcExtension extension) {
    extension.setConfiguration(
        new HashMap<>() {
          {
            put(
                VAULT_URL,
                String.format(
                    "http://%s:%s", vaultContainer.getHost(), vaultContainer.getFirstMappedPort()));
            put(VAULT_TOKEN, TEST_TOKEN);
          }
        });
    extension.registerSystemExtension(ServiceExtension.class, testExtension);
  }

  @Test
  @SneakyThrows
  void resolveCertificate_success() {
    String key = UUID.randomUUID().toString();
    X509Certificate certificateExpected = generateCertificate(5, "Test");
    String pem = convertToPem(certificateExpected);

    Vault vault = testExtension.getVault();
    vault.storeSecret(key, pem);
    CertificateResolver resolver = testExtension.getCertificateResolver();
    X509Certificate certificateResult = resolver.resolveCertificate(key);

    Assertions.assertEquals(certificateExpected, certificateResult);
  }

  @Test
  @SneakyThrows
  void resolveCertificate_malformed() {
    String key = UUID.randomUUID().toString();
    String value = UUID.randomUUID().toString();
    Vault vault = testExtension.getVault();
    vault.storeSecret(key, value);

    CertificateResolver resolver = testExtension.getCertificateResolver();
    X509Certificate certificateResult = resolver.resolveCertificate(key);
    Assertions.assertNull(certificateResult);
  }

  private static X509Certificate generateCertificate(int validity, String cn)
      throws CertificateException, OperatorCreationException, IOException, NoSuchAlgorithmException,
          NoSuchProviderException {

    KeyPair keyPair = generateKeyPair();

    Instant now = Instant.now();
    ContentSigner contentSigner =
        new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).build(keyPair.getPrivate());
    X500Name issuer =
        new X500Name(
            String.format(
                "CN=%s",
                Optional.ofNullable(cn)
                    .map(String::trim)
                    .filter(s -> !s.isEmpty())
                    .orElse("rootCA")));
    BigInteger serial = BigInteger.valueOf(now.toEpochMilli());
    Date notBefore = Date.from(now);
    Date notAfter = Date.from(now.plus(Duration.ofDays(validity)));
    PublicKey publicKey = keyPair.getPublic();
    X509v3CertificateBuilder certificateBuilder =
        new JcaX509v3CertificateBuilder(issuer, serial, notBefore, notAfter, issuer, publicKey);
    certificateBuilder =
        certificateBuilder.addExtension(
            Extension.subjectKeyIdentifier, false, createSubjectKeyId(publicKey));
    certificateBuilder =
        certificateBuilder.addExtension(
            Extension.authorityKeyIdentifier, false, createAuthorityKeyId(publicKey));
    certificateBuilder =
        certificateBuilder.addExtension(
            Extension.basicConstraints, true, new BasicConstraints(true));
    return JCA_X509_CERTIFICATE_CONVERTER.getCertificate(certificateBuilder.build(contentSigner));
  }

  private static KeyPair generateKeyPair()
      throws NoSuchAlgorithmException, NoSuchProviderException {
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", PROVIDER);
    keyPairGenerator.initialize(1024, new SecureRandom());

    return keyPairGenerator.generateKeyPair();
  }

  private static SubjectKeyIdentifier createSubjectKeyId(PublicKey publicKey)
      throws OperatorCreationException {
    SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
    DigestCalculator digCalc =
        new BcDigestCalculatorProvider().get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1));
    return new X509ExtensionUtils(digCalc).createSubjectKeyIdentifier(publicKeyInfo);
  }

  private static AuthorityKeyIdentifier createAuthorityKeyId(PublicKey publicKey)
      throws OperatorCreationException {
    SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
    DigestCalculator digCalc =
        new BcDigestCalculatorProvider().get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1));
    return new X509ExtensionUtils(digCalc).createAuthorityKeyIdentifier(publicKeyInfo);
  }

  @SneakyThrows
  private static String convertToPem(X509Certificate certificate) {
    try (ByteArrayOutputStream stream = new ByteArrayOutputStream()) {
      try (OutputStreamWriter writer = new OutputStreamWriter(stream)) {
        JcaPEMWriter pemWriter = new JcaPEMWriter(writer);
        pemWriter.writeObject(certificate);
        pemWriter.flush();
      }
      return stream.toString(StandardCharsets.UTF_8);
    }
  }

  @Getter
  private static class TestExtension implements ServiceExtension {
    private Vault vault;
    private CertificateResolver certificateResolver;

    @Override
    public void initialize(ServiceExtensionContext context) {
      vault = context.getService(Vault.class);
      certificateResolver = context.getService(CertificateResolver.class);
    }
  }
}
