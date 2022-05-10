package org.eclipse.dataspaceconnector.core.security.hashicorp;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

import java.util.Map;
import java.util.Objects;

@Data
class HashicorpVaultEntry {
  private static final String INNER_DATA_KEY = "data";

  @JsonProperty("lease_id")
  private String leaseId;

  @JsonProperty("request_id")
  private String requestId;

  @JsonProperty("renewable")
  private Boolean renewable;

  @JsonProperty("lease_duration")
  private Long leaseDuration;

  @JsonProperty("metadata")
  private Map<String, String> metadata;

  @JsonProperty("data")
  private Map<String, Map<String, String>> data;

  @JsonProperty("wrap_info")
  private Map<String, Object> wrapInfo;

  @JsonProperty("warnings")
  private Map<String, Object> warnings;

  @JsonProperty("auth")
  private Map<String, Object> auth;

  public Map<String, String> getInnerData() {
    return Objects.requireNonNull(data.get(INNER_DATA_KEY));
  }
}
