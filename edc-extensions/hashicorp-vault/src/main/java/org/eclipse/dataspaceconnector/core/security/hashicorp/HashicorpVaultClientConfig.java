package org.eclipse.dataspaceconnector.core.security.hashicorp;

import lombok.Builder;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Builder
@Getter
@RequiredArgsConstructor
class HashicorpVaultClientConfig {
  private static final String VAULT_SECRET_GET_PATH = "/v1/secret/data/";

  // TO-DO: account for certificate authentication
  private final String vaultUrl;
  private final String vaultToken;
  private final String vaultName;

  public String getSecretGetUrl() {
    return String.format("%s%s%s", vaultUrl, VAULT_SECRET_GET_PATH, vaultName);
  }
}
