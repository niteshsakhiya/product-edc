package org.eclipse.dataspaceconnector.core.security.hashicorp;

import lombok.Builder;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Builder
@Getter
@RequiredArgsConstructor
class HashicorpVaultClientConfig {
  // TODO: account for certificate authentication
  private final String vaultUrl;
  private final String vaultToken;
}
