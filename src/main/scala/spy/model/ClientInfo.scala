/*
 * Copyright 2020-2022 David Crosson
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package spy.model

/** Everything which can be learnt about a client from a single HTTP request. */
case class ClientInfo(
  clientIP: Option[String],            // best guess of the real client IP (proxy aware)
  clientIPSource: Option[String],      // where clientIP comes from (header name or "connection")
  clientIPDetails: Option[IpDetails],
  userAgent: Option[String],
  userAgentDetails: Option[UserAgentDetails],
  connection: ConnectionDetails,
  request: RequestDetails,
  proxy: ProxyDetails,
  geo: Option[GeoHints],               // only when a CDN / cloud front-end provides it
  preferences: ClientPreferences,
  clientHints: ClientHints,
  fetchMetadata: FetchMetadata,
  navigation: NavigationDetails,
  privacy: PrivacySignals,
  tracing: TracingDetails,
  tls: Option[TlsDetails],             // terminated by spy itself, or forwarded by a trusted reverse proxy
  authorizationScheme: Option[String], // never the credentials themselves
  proxyAuthorizationScheme: Option[String],
  cookieNames: List[String],           // never the cookie values
  headers: List[HeaderEntry]           // all received headers, sensitive values redacted
)

case class HeaderEntry(name: String, value: String)

case class IpDetails(
  address: String,
  version: String, // IPv4 or IPv6
  loopback: Boolean,
  privateRange: Boolean,
  linkLocal: Boolean,
  uniqueLocal: Boolean,
  carrierGradeNat: Boolean,
  multicast: Boolean,
  unspecified: Boolean,
  documentation: Boolean,
  ipv4Mapped: Option[String],
  publiclyRoutable: Boolean,
  reverseDns: Option[String]
)

/** The client connection as seen by the client : when spy is behind a reverse proxy, data comes from forwarding headers, the raw TCP peer (the proxy) being then described in ProxyDetails.
  */
case class ConnectionDetails(
  remoteAddress: Option[String],
  remotePort: Option[Int],
  remoteAddressDetails: Option[IpDetails],
  secure: Option[Boolean],
  protocol: Option[String], // unknown when behind a reverse proxy
  viaReverseProxy: Boolean
)

case class RequestDetails(
  method: String,
  url: String,
  scheme: Option[String],
  host: Option[String],
  port: Option[Int],
  path: String,
  query: Map[String, List[String]],
  contentType: Option[String],
  contentLength: Option[Long],
  headersCount: Int,
  headersSize: Int
)

case class ForwardedElement(
  forValue: Option[String],
  by: Option[String],
  host: Option[String],
  proto: Option[String]
)

case class ProxyDetails(
  behindProxy: Boolean,
  hopsCount: Option[Int],
  trustedPeer: Boolean,          // TCP peer is a trusted proxy, so its forwarding headers are used
  clientSideChain: List[String], // forwarding chain on the client side of clientIP (client's own proxies), unverified
  trustedChain: List[String],    // trusted proxies between clientIP and the TCP peer
  peerAddress: Option[String],   // TCP peer of spy, the last proxy when behind a reverse proxy
  peerPort: Option[Int],
  peerAddressDetails: Option[IpDetails],
  peerProtocol: Option[String],  // HTTP version between the last proxy and spy
  peerSecure: Option[Boolean],
  upstreamUrl: Option[String],   // URL as received by spy from the last proxy
  forwarded: List[ForwardedElement],
  xForwardedFor: List[String],
  xForwardedProto: Option[String],
  xForwardedHost: Option[String],
  xForwardedPort: Option[String],
  xForwardedPrefix: Option[String],
  xForwardedServer: Option[String],
  xRealIP: Option[String],
  xClientIP: Option[String],
  xClusterClientIP: Option[String],
  xOriginalForwardedFor: Option[String],
  trueClientIP: Option[String],
  cfConnectingIP: Option[String],
  cfConnectingIPv6: Option[String],
  cfRay: Option[String],
  cfVisitor: Option[String],
  cfWorker: Option[String],
  fastlyClientIP: Option[String],
  akamaiEdgeScape: Option[String],
  via: List[String],
  maxForwards: Option[Int]
)

case class GeoHints(
  source: String,
  country: Option[String],
  continent: Option[String],
  region: Option[String],
  regionCode: Option[String],
  city: Option[String],
  postalCode: Option[String],
  latitude: Option[Double],
  longitude: Option[Double],
  timeZone: Option[String],
  asn: Option[String]
)

case class WeightedValue(value: String, quality: Double)

case class ClientPreferences(
  preferredLanguage: Option[String],
  languages: List[WeightedValue],
  mediaTypes: List[WeightedValue],
  encodings: List[WeightedValue],
  charsets: List[WeightedValue]
)

case class Brand(name: String, version: Option[String])

case class ClientHints(
  brands: List[Brand],
  fullVersionList: List[Brand],
  fullVersion: Option[String],
  mobile: Option[Boolean],
  platform: Option[String],
  platformVersion: Option[String],
  architecture: Option[String],
  bitness: Option[String],
  model: Option[String],
  wow64: Option[Boolean],
  formFactors: List[String],
  deviceMemoryGB: Option[Double],
  devicePixelRatio: Option[Double],
  viewportWidth: Option[Int],
  viewportHeight: Option[Int],
  width: Option[Int],
  downlinkMbps: Option[Double],
  effectiveConnectionType: Option[String],
  roundTripTimeMs: Option[Int],
  saveData: Option[Boolean],
  prefersColorScheme: Option[String],
  prefersReducedMotion: Option[String],
  prefersReducedTransparency: Option[String],
  prefersContrast: Option[String],
  forcedColors: Option[String]
)

case class FetchMetadata(
  site: Option[String],
  mode: Option[String],
  dest: Option[String],
  user: Option[Boolean],
  storageAccess: Option[String],
  purpose: Option[String]
)

case class NavigationDetails(
  referer: Option[String],
  origin: Option[String],
  upgradeInsecureRequests: Option[Boolean],
  cacheControl: Option[String],
  pragma: Option[String],
  connection: Option[String],
  keepAlive: Option[String],
  te: Option[String],
  upgrade: Option[String],
  xRequestedWith: Option[String],
  ifNoneMatch: Option[String],
  ifModifiedSince: Option[String],
  range: Option[String],
  priority: Option[String],
  expect: Option[String]
)

case class PrivacySignals(
  doNotTrack: Option[Boolean],
  globalPrivacyControl: Option[Boolean]
)

case class TracingDetails(
  requestId: Option[String],
  correlationId: Option[String],
  traceparent: Option[String],
  tracestate: Option[String],
  b3: Option[String],
  b3TraceId: Option[String],
  amazonTraceId: Option[String],
  cloudTraceContext: Option[String],
  baggage: Option[String]
)

case class CertificateInfo(
  subject: String,
  issuer: Option[String],
  serialNumber: Option[String],
  notBefore: Option[String],
  notAfter: Option[String],
  signatureAlgorithm: Option[String],
  publicKeyAlgorithm: Option[String],
  fingerprintSha1: Option[String]
)

/** The client TLS session, either terminated by spy itself (source "connection") or by a reverse proxy which forwards its details through X-SSL-* headers (source "reverse-proxy").
  */
case class TlsDetails(
  source: String,
  protocol: Option[String],
  cipherSuite: Option[String],
  sessionId: Option[String],
  sessionReused: Option[Boolean],
  serverNames: List[String],   // SNI
  alpn: Option[String],
  curve: Option[String],
  earlyData: Option[Boolean],
  clientCiphers: List[String], // cipher suites offered by the client
  clientCurves: List[String],  // curves offered by the client
  ja3: Option[String],
  ja4: Option[String],
  clientCertificateVerify: Option[String],
  peerPrincipal: Option[String],
  peerCertificates: List[CertificateInfo],
  localPrincipal: Option[String]
)

case class UserAgentDetails(
  browser: Option[String],
  browserVersion: Option[String],
  engine: Option[String],
  os: Option[String],
  osVersion: Option[String],
  deviceType: Option[String], // desktop, mobile, tablet, tv, console, bot, cli
  bot: Boolean
)
