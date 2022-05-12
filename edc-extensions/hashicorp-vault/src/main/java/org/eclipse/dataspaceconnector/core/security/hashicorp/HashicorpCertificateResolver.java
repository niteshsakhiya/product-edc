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
 *       Mercedes-Benz Tech Innovation GmbH - Initial API and Implementation
 *
 */

package org.eclipse.dataspaceconnector.core.security.hashicorp;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.security.Provider;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.eclipse.dataspaceconnector.spi.EdcException;
import org.eclipse.dataspaceconnector.spi.monitor.Monitor;
import org.eclipse.dataspaceconnector.spi.security.CertificateResolver;
import org.eclipse.dataspaceconnector.spi.security.Vault;
import org.jetbrains.annotations.Nullable;

/** Resolves an X.509 certificate in Hashicorp vault. */
@RequiredArgsConstructor
public class HashicorpCertificateResolver implements CertificateResolver {
  private static final Provider PROVIDER = new BouncyCastleProvider();
  private static final JcaX509CertificateConverter CONVERTER =
      new JcaX509CertificateConverter().setProvider(PROVIDER);
  @NonNull private final Vault vault;
  @NonNull private final Monitor monitor;

  @Override
  @Nullable
  public X509Certificate resolveCertificate(@NonNull String id) {
    String certificateRepresentation = vault.resolveSecret(id);
    if (certificateRepresentation == null) {
      return null;
    }
    try (Reader reader =
        new InputStreamReader(
            new ByteArrayInputStream(certificateRepresentation.getBytes(StandardCharsets.UTF_8)))) {
      PEMParser pemParser = new PEMParser(reader);
      X509CertificateHolder x509CertificateHolder = (X509CertificateHolder) pemParser.readObject();
      if (x509CertificateHolder == null) {
        monitor.warning(
            String.format("Expected PEM certificate on key %s, but value not PEM.", id));
        return null;
      }
      return CONVERTER.getCertificate(x509CertificateHolder);
    } catch (IOException | CertificateException e) {
      throw new EdcException(e.getMessage(), e);
    }
  }
}
