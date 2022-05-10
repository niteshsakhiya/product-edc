package org.eclipse.dataspaceconnector.core.security.hashicorp;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Map;
import java.util.Objects;

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

  public String getLeaseId() {
    return leaseId;
  }

  public void setLeaseId(String leaseId) {
    this.leaseId = leaseId;
  }

  public String getRequestId() {
    return requestId;
  }

  public void setRequestId(String requestId) {
    this.requestId = requestId;
  }

  public Boolean getRenewable() {
    return renewable;
  }

  public void setRenewable(Boolean renewable) {
    this.renewable = renewable;
  }

  public Long getLeaseDuration() {
    return leaseDuration;
  }

  public void setLeaseDuration(Long leaseDuration) {
    this.leaseDuration = leaseDuration;
  }

  public Map<String, String> getMetadata() {
    return metadata;
  }

  public void setMetadata(Map<String, String> metadata) {
    this.metadata = metadata;
  }

  public Map<String, Map<String, String>> getData() {
    return data;
  }

  public Map<String, String> getInnerData() {
    return Objects.requireNonNull(data.get(INNER_DATA_KEY));
  }

  public void setData(Map<String, Map<String, String>> data) {
    this.data = data;
  }

  public Map<String, Object> getWrapInfo() {
    return wrapInfo;
  }

  public void setWrapInfo(Map<String, Object> wrapInfo) {
    this.wrapInfo = wrapInfo;
  }

  public Map<String, Object> getWarnings() {
    return warnings;
  }

  public void setWarnings(Map<String, Object> warnings) {
    this.warnings = warnings;
  }

  public Map<String, Object> getAuth() {
    return auth;
  }

  public void setAuth(Map<String, Object> auth) {
    this.auth = auth;
  }
}
