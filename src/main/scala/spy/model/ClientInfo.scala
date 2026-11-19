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
  clientIP: Option[String],             // best guess of the real client IP (proxy aware)
  clientIPSource: Option[String],       // where clientIP comes from (header name or "connection")
  clientIPDetails: Option[IpDetails],
  userAgent: Option[String],
  userAgentDetails: Option[UserAgentDetails],
  connection: ConnectionDetails,
  request: RequestDetails,
  proxy: ProxyDetails,
  geo: Option[GeoHints],                // only when a CDN / cloud front-end provides it
  preferences: ClientPreferences,
  clientHints: ClientHints,
  fetchMetadata: FetchMetadata,
  navigation: NavigationDetails,
  privacy: PrivacySignals,
  tracing: TracingDetails,
  tls: Option[TlsDetails],              // only for HTTPS connections terminated by this service
  authorizationScheme: Option[String],  // never the credentials themselves
  proxyAuthorizationScheme: Option[String],
  cookieNames: List[String],            // never the cookie values
  headers: List[HeaderEntry]            // all received headers, sensitive values redacted
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

case class ConnectionDetails(
  remoteAddress: Option[String],
  remotePort: Option[Int],
  remoteAddressDetails: Option[IpDetails],
  secure: Option[Boolean],
  protocol: Option[String]
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
  issuer: String,
  serialNumber: String,
  notBefore: String,
  notAfter: String,
  signatureAlgorithm: String,
  publicKeyAlgorithm: String
)

case class TlsDetails(
  protocol: Option[String],
  cipherSuite: Option[String],
  sessionId: Option[String],
  serverNames: List[String], // SNI
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
