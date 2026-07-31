// Simple browser-compatible Openfort client
class Openfort {
  constructor(
    publishableKey,
    accessToken = undefined,
    thirdPartyProvider = undefined,
    thirdPartyTokenType = undefined,
    hotStorageURL = "http://localhost:7054",
  ) {
    this._publishableKey = publishableKey;
    this._accessToken = accessToken;
    this.thirdPartyProvider = thirdPartyProvider;
    this.thirdPartyTokenType = thirdPartyTokenType;
    this._hotStorageURL = hotStorageURL;
  }

  setAccessToken(token) {
    this._accessToken = token;
  }

  _getAuthHeaders(requestId = null) {
    const headers = {
      "Content-Type": "application/json",
    };

    // Use JWT token for authentication if available
    if (this._accessToken) {
      headers["Authorization"] = `Bearer ${this._accessToken}`;
    } else if (this._publishableKey) {
      headers["Authorization"] = `Bearer ${this._publishableKey}`;
    }

    if (this.thirdPartyProvider && this.thirdPartyTokenType) {
      headers["X-Auth-Provider"] = this.thirdPartyProvider;
      headers["X-Token-Type"] = this.thirdPartyTokenType;
    }

    if (requestId) {
      headers["x-request-id"] = requestId;
    }

    return headers;
  }

  async _makeRequest(method, endpoint, data = null, requestId = null) {
    const url = `${this._hotStorageURL}${endpoint}`;
    const options = {
      method: method,
      headers: this._getAuthHeaders(requestId),
    };

    if (data && (method === "POST" || method === "PUT")) {
      options.body = JSON.stringify(data);
    }

    try {
      const response = await fetch(url, options);

      if (!response.ok) {
        const errorText = await response.text();
        console.error(`Request failed: ${response.status} - ${errorText}`);
        throw new Error(`Request failed: ${response.status} - ${errorText}`);
      }

      // Handle 204 No Content responses
      if (response.status === 204) {
        return null;
      }

      return await response.json();
    } catch (error) {
      console.error("Request error:", error);
      throw error;
    }
  }

  async init(chainId, requestId = null) {
    return await this._makeRequest(
      "POST",
      "/v1/devices/init",
      { chainId },
      requestId,
    );
  }

  async register(chainId, address, share, requestId = null) {
    return await this._makeRequest(
      "POST",
      "/v1/devices/register",
      {
        chainId,
        address,
        share,
      },
      requestId,
    );
  }

  async getDevice(deviceID, requestId = null) {
    return await this._makeRequest(
      "GET",
      `/v1/devices/${deviceID}`,
      null,
      requestId,
    );
  }

  // V2 API methods
  async listAccounts(chainType = null, requestId = null) {
    let endpoint = "/v2/accounts";
    if (chainType) {
      endpoint += `?chainType=${encodeURIComponent(chainType)}`;
    }
    return await this._makeRequest("GET", endpoint, null, requestId);
  }

  async getShamirDevice(deviceId, requestId = null) {
    return await this._makeRequest(
      "GET",
      `/v1/devices/${deviceId}`,
      null,
      requestId,
    );
  }

  async createShamirDevice(deviceData, requestId = null) {
    return await this._makeRequest(
      "POST",
      `/v1/devices/register`,
      deviceData,
      requestId,
    );
  }

  async importShare(shareData, requestId = null) {
    return await this._makeRequest(
      "POST",
      `/v2/accounts/import-share`,
      shareData,
      requestId,
    );
  }
}

// Make it globally available
window.Openfort = Openfort;
