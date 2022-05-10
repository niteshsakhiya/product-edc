/*
 *  Copyright (c) 2020, 2021 Microsoft Corporation
 *
 *  This program and the accompanying materials are made available under the
 *  terms of the Apache License, Version 2.0 which is available at
 *  https://www.apache.org/licenses/LICENSE-2.0
 *
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Contributors:
 *       Microsoft Corporation - initial API and implementation
 *       Mercedes-Benz Tech Innovation GmbH - Adaptation for Hashicorp
 *
 */

package org.eclipse.dataspaceconnector.core.security.hashicorp;

import java.io.ByteArrayInputStream;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import org.eclipse.dataspaceconnector.spi.EdcException;
import org.eclipse.dataspaceconnector.spi.security.CertificateResolver;
import org.eclipse.dataspaceconnector.spi.security.Vault;

/** Resolves an X.509 certificate in Hashicorp vault. */
public class HashicorpCertificateResolver implements CertificateResolver {
  private static final String HEADER = "-----BEGIN CERTIFICATE-----";
  private static final String FOOTER = "-----END CERTIFICATE-----";
  private final Vault vault;

  public HashicorpCertificateResolver(Vault vault) {
    this.vault = vault;
  }

  @Override
  public X509Certificate resolveCertificate(String id) {
    try {
      String encoded = vault.resolveSecret(id);
      if (encoded == null) {
        return null;
      }
      encoded =
          encoded.replace(HEADER, "").replaceAll(System.lineSeparator(), "").replace(FOOTER, "");

      CertificateFactory fact = CertificateFactory.getInstance("X.509");
      return (X509Certificate)
          fact.generateCertificate(
              new ByteArrayInputStream(Base64.getDecoder().decode(encoded.getBytes())));
    } catch (GeneralSecurityException e) {
      throw new EdcException(e);
    }
  }
}
