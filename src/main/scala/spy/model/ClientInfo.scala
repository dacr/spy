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

import sttp.tapir.Schema.annotations.description

// Field documentation is given through tapir @description annotations, it is rendered in the OpenAPI documentation.

@description("Everything which can be learnt about a client from a single HTTP request, absent information is omitted")
case class ClientInfo(
  @description("Best guess of the real client IP, forwarding headers being only used when sent by a trusted reverse proxy")
  clientIP: Option[String],
  @description("Where clientIP comes from : a header name (Forwarded, X-Forwarded-For, X-Real-IP, ...) or \"connection\"")
  clientIPSource: Option[String],
  @description("Classification and reverse DNS of clientIP")
  clientIPDetails: Option[IpDetails],
  @description("User-Agent header")
  userAgent: Option[String],
  @description("Browser, OS, engine and device heuristically parsed from the user agent")
  userAgentDetails: Option[UserAgentDetails],
  @description("The client connection as seen by the client, rebuilt from forwarding headers when behind a reverse proxy")
  connection: ConnectionDetails,
  @description("The request as issued by the client")
  request: RequestDetails,
  @description("Proxies and forwarding headers")
  proxy: ProxyDetails,
  @description("Geolocation hints, only when a CDN or cloud front-end provides them")
  geo: Option[GeoHints],
  @description("Content negotiation preferences (Accept-* headers)")
  preferences: ClientPreferences,
  @description("User agent client hints (Sec-CH-* and related headers)")
  clientHints: ClientHints,
  @description("Fetch metadata (Sec-Fetch-* headers)")
  fetchMetadata: FetchMetadata,
  @description("Navigation, caching and connection related headers")
  navigation: NavigationDetails,
  @description("Privacy signals (DNT, Sec-GPC)")
  privacy: PrivacySignals,
  @description("Distributed tracing and request correlation headers")
  tracing: TracingDetails,
  @description("TLS session, terminated by spy itself or forwarded by a trusted reverse proxy")
  tls: Option[TlsDetails],
  @description("Authorization header scheme, never the credentials themselves")
  authorizationScheme: Option[String],
  @description("Proxy-Authorization header scheme, never the credentials themselves")
  proxyAuthorizationScheme: Option[String],
  @description("Names of the received cookies, never their values")
  cookieNames: List[String],
  @description("All received headers, sensitive values being redacted")
  headers: List[HeaderEntry]
)

@description("A received HTTP header")
case class HeaderEntry(
  @description("header name")
  name: String,
  @description("header value, \"<redacted>\" for sensitive headers")
  value: String
)

@description("Classification of an IP address")
case class IpDetails(
  @description("the IP address")
  address: String,
  @description("IPv4 or IPv6")
  version: String,
  @description("loopback address (127.0.0.0/8, ::1)")
  loopback: Boolean,
  @description("private network address (10/8, 172.16/12, 192.168/16, IPv6 site local)")
  privateRange: Boolean,
  @description("link local address (169.254/16, fe80::/10)")
  linkLocal: Boolean,
  @description("IPv6 unique local address (fc00::/7)")
  uniqueLocal: Boolean,
  @description("carrier grade NAT shared address (100.64/10)")
  carrierGradeNat: Boolean,
  @description("multicast address")
  multicast: Boolean,
  @description("unspecified address (0.0.0.0, ::)")
  unspecified: Boolean,
  @description("documentation address (192.0.2/24, 198.51.100/24, 203.0.113/24, 2001:db8::/32, 3fff::/20)")
  documentation: Boolean,
  @description("the IPv4 address embedded in an IPv4-mapped IPv6 address")
  ipv4Mapped: Option[String],
  @description("none of the special purpose ranges above")
  publiclyRoutable: Boolean,
  @description("host name given by the reverse DNS lookup, when enabled and successful")
  reverseDns: Option[String]
)

@description(
  "The client connection as seen by the client : when spy is behind a reverse proxy, data comes from forwarding headers, " +
    "the raw TCP peer (the proxy) being then described in proxy"
)
case class ConnectionDetails(
  @description("client IP address")
  remoteAddress: Option[String],
  @description("client TCP port")
  remotePort: Option[Int],
  @description("classification and reverse DNS of remoteAddress")
  remoteAddressDetails: Option[IpDetails],
  @description("HTTPS connection")
  secure: Option[Boolean],
  @description("HTTP version used by the client, unknown behind a reverse proxy which doesn't forward it")
  protocol: Option[String],
  @description("true when these details come from the headers of a trusted reverse proxy")
  viaReverseProxy: Boolean
)

@description("The request as issued by the client, rebuilt from forwarding headers when behind a reverse proxy")
case class RequestDetails(
  @description("HTTP method")
  method: String,
  @description("full request URL")
  url: String,
  @description("http or https")
  scheme: Option[String],
  @description("requested host")
  host: Option[String],
  @description("requested port")
  port: Option[Int],
  @description("request path, including the prefix removed by the reverse proxy (X-Forwarded-Prefix)")
  path: String,
  @description("query parameters")
  query: Map[String, List[String]],
  @description("Content-Type header")
  contentType: Option[String],
  @description("Content-Length header")
  contentLength: Option[Long],
  @description("number of received headers")
  headersCount: Int,
  @description("approximate size of the received headers, in bytes")
  headersSize: Int
)

@description("An element of the RFC 7239 Forwarded header")
case class ForwardedElement(
  @description("for= parameter : the client of the proxy which added this element")
  forValue: Option[String],
  @description("by= parameter : the proxy interface which received the request")
  by: Option[String],
  @description("host= parameter : the Host received by the proxy")
  host: Option[String],
  @description("proto= parameter : the scheme used to reach the proxy")
  proto: Option[String]
)

@description("Proxies the request went through, and the raw forwarding headers")
case class ProxyDetails(
  @description("forwarding or Via headers are present, or the client IP was given by a trusted reverse proxy")
  behindProxy: Boolean,
  @description("number of proxies according to the longest of Forwarded, X-Forwarded-For and Via")
  hopsCount: Option[Int],
  @description("the TCP peer belongs to the trusted proxies networks, so its forwarding headers are used")
  trustedPeer: Boolean,
  @description(
    "Forwarding chain on the client side of clientIP : added by the proxies the client went through (its HTTP proxy for example) " +
      "or forged by the client, unverified, never used nor resolved"
  )
  clientSideChain: List[String],
  @description("trusted proxies between clientIP and the TCP peer")
  trustedChain: List[String],
  @description("TCP peer of spy, the last proxy, only when behind a trusted reverse proxy")
  peerAddress: Option[String],
  @description("TCP port of the last proxy")
  peerPort: Option[Int],
  @description("classification and reverse DNS of peerAddress")
  peerAddressDetails: Option[IpDetails],
  @description("HTTP version between the last proxy and spy")
  peerProtocol: Option[String],
  @description("HTTPS between the last proxy and spy")
  peerSecure: Option[Boolean],
  @description("URL as received by spy from the last proxy")
  upstreamUrl: Option[String],
  @description("parsed Forwarded header elements, the client first")
  forwarded: List[ForwardedElement],
  @description("X-Forwarded-For addresses, the client first")
  xForwardedFor: List[String],
  @description("X-Forwarded-Proto header")
  xForwardedProto: Option[String],
  @description("X-Forwarded-Host header")
  xForwardedHost: Option[String],
  @description("X-Forwarded-Port header")
  xForwardedPort: Option[String],
  @description("X-Forwarded-Prefix header")
  xForwardedPrefix: Option[String],
  @description("X-Forwarded-Server header")
  xForwardedServer: Option[String],
  @description("X-Real-IP header")
  xRealIP: Option[String],
  @description("X-Client-IP header")
  xClientIP: Option[String],
  @description("X-Cluster-Client-IP header")
  xClusterClientIP: Option[String],
  @description("X-Original-Forwarded-For header")
  xOriginalForwardedFor: Option[String],
  @description("True-Client-IP header (Akamai, Cloudflare enterprise)")
  trueClientIP: Option[String],
  @description("CF-Connecting-IP header (Cloudflare)")
  cfConnectingIP: Option[String],
  @description("CF-Connecting-IPv6 header (Cloudflare)")
  cfConnectingIPv6: Option[String],
  @description("CF-Ray header (Cloudflare)")
  cfRay: Option[String],
  @description("CF-Visitor header (Cloudflare)")
  cfVisitor: Option[String],
  @description("CF-Worker header (Cloudflare)")
  cfWorker: Option[String],
  @description("Fastly-Client-IP header (Fastly)")
  fastlyClientIP: Option[String],
  @description("X-Akamai-Edgescape header (Akamai)")
  akamaiEdgeScape: Option[String],
  @description("Via header entries")
  via: List[String],
  @description("Max-Forwards header")
  maxForwards: Option[Int]
)

@description("Geolocation hints provided by a CDN or a cloud front-end")
case class GeoHints(
  @description("provider of these hints : cloudflare, cloudfront, vercel, appengine or google-load-balancer")
  source: String,
  @description("country code")
  country: Option[String],
  @description("continent code")
  continent: Option[String],
  @description("region name")
  region: Option[String],
  @description("region code")
  regionCode: Option[String],
  @description("city")
  city: Option[String],
  @description("postal code")
  postalCode: Option[String],
  @description("latitude")
  latitude: Option[Double],
  @description("longitude")
  longitude: Option[Double],
  @description("time zone")
  timeZone: Option[String],
  @description("autonomous system number")
  asn: Option[String]
)

@description("A content negotiation value with its quality factor")
case class WeightedValue(
  @description("negotiated value")
  value: String,
  @description("quality factor (q=), 1.0 when not given")
  quality: Double
)

@description("Content negotiation preferences, sorted by decreasing quality")
case class ClientPreferences(
  @description("the preferred language")
  preferredLanguage: Option[String],
  @description("Accept-Language")
  languages: List[WeightedValue],
  @description("Accept")
  mediaTypes: List[WeightedValue],
  @description("Accept-Encoding")
  encodings: List[WeightedValue],
  @description("Accept-Charset")
  charsets: List[WeightedValue]
)

@description("A user agent brand")
case class Brand(
  @description("brand name")
  name: String,
  @description("brand version")
  version: Option[String]
)

@description("User agent client hints, most are only sent when requested by the server (Accept-CH)")
case class ClientHints(
  @description("Sec-CH-UA")
  brands: List[Brand],
  @description("Sec-CH-UA-Full-Version-List")
  fullVersionList: List[Brand],
  @description("Sec-CH-UA-Full-Version")
  fullVersion: Option[String],
  @description("Sec-CH-UA-Mobile")
  mobile: Option[Boolean],
  @description("Sec-CH-UA-Platform")
  platform: Option[String],
  @description("Sec-CH-UA-Platform-Version")
  platformVersion: Option[String],
  @description("Sec-CH-UA-Arch")
  architecture: Option[String],
  @description("Sec-CH-UA-Bitness")
  bitness: Option[String],
  @description("Sec-CH-UA-Model")
  model: Option[String],
  @description("Sec-CH-UA-WoW64")
  wow64: Option[Boolean],
  @description("Sec-CH-UA-Form-Factors")
  formFactors: List[String],
  @description("Sec-CH-Device-Memory / Device-Memory, in GB")
  deviceMemoryGB: Option[Double],
  @description("Sec-CH-DPR / DPR")
  devicePixelRatio: Option[Double],
  @description("Sec-CH-Viewport-Width / Viewport-Width, in CSS pixels")
  viewportWidth: Option[Int],
  @description("Sec-CH-Viewport-Height, in CSS pixels")
  viewportHeight: Option[Int],
  @description("Sec-CH-Width / Width, in physical pixels")
  width: Option[Int],
  @description("Downlink, in Mbps")
  downlinkMbps: Option[Double],
  @description("ECT : slow-2g, 2g, 3g or 4g")
  effectiveConnectionType: Option[String],
  @description("RTT, in milliseconds")
  roundTripTimeMs: Option[Int],
  @description("Save-Data")
  saveData: Option[Boolean],
  @description("Sec-CH-Prefers-Color-Scheme")
  prefersColorScheme: Option[String],
  @description("Sec-CH-Prefers-Reduced-Motion")
  prefersReducedMotion: Option[String],
  @description("Sec-CH-Prefers-Reduced-Transparency")
  prefersReducedTransparency: Option[String],
  @description("Sec-CH-Prefers-Contrast")
  prefersContrast: Option[String],
  @description("Sec-CH-Forced-Colors")
  forcedColors: Option[String]
)

@description("Fetch metadata request headers")
case class FetchMetadata(
  @description("Sec-Fetch-Site")
  site: Option[String],
  @description("Sec-Fetch-Mode")
  mode: Option[String],
  @description("Sec-Fetch-Dest")
  dest: Option[String],
  @description("Sec-Fetch-User")
  user: Option[Boolean],
  @description("Sec-Fetch-Storage-Access")
  storageAccess: Option[String],
  @description("Sec-Purpose / Purpose (prefetch, prerender)")
  purpose: Option[String]
)

@description("Navigation, caching and connection related headers")
case class NavigationDetails(
  @description("Referer")
  referer: Option[String],
  @description("Origin")
  origin: Option[String],
  @description("Upgrade-Insecure-Requests")
  upgradeInsecureRequests: Option[Boolean],
  @description("Cache-Control")
  cacheControl: Option[String],
  @description("Pragma")
  pragma: Option[String],
  @description("Connection")
  connection: Option[String],
  @description("Keep-Alive")
  keepAlive: Option[String],
  @description("TE")
  te: Option[String],
  @description("Upgrade")
  upgrade: Option[String],
  @description("X-Requested-With")
  xRequestedWith: Option[String],
  @description("If-None-Match")
  ifNoneMatch: Option[String],
  @description("If-Modified-Since")
  ifModifiedSince: Option[String],
  @description("Range")
  range: Option[String],
  @description("Priority")
  priority: Option[String],
  @description("Expect")
  expect: Option[String]
)

@description("Privacy signals")
case class PrivacySignals(
  @description("DNT (Do Not Track)")
  doNotTrack: Option[Boolean],
  @description("Sec-GPC (Global Privacy Control)")
  globalPrivacyControl: Option[Boolean]
)

@description("Distributed tracing and request correlation headers")
case class TracingDetails(
  @description("X-Request-ID")
  requestId: Option[String],
  @description("X-Correlation-ID")
  correlationId: Option[String],
  @description("traceparent (W3C trace context)")
  traceparent: Option[String],
  @description("tracestate (W3C trace context)")
  tracestate: Option[String],
  @description("b3 (Zipkin single header)")
  b3: Option[String],
  @description("X-B3-TraceId (Zipkin)")
  b3TraceId: Option[String],
  @description("X-Amzn-Trace-Id (AWS)")
  amazonTraceId: Option[String],
  @description("X-Cloud-Trace-Context (Google Cloud)")
  cloudTraceContext: Option[String],
  @description("baggage (W3C)")
  baggage: Option[String]
)

@description("An X.509 certificate")
case class CertificateInfo(
  @description("subject distinguished name")
  subject: String,
  @description("issuer distinguished name")
  issuer: Option[String],
  @description("serial number, hexadecimal")
  serialNumber: Option[String],
  @description("start of validity")
  notBefore: Option[String],
  @description("end of validity")
  notAfter: Option[String],
  @description("signature algorithm")
  signatureAlgorithm: Option[String],
  @description("public key algorithm")
  publicKeyAlgorithm: Option[String],
  @description("SHA-1 fingerprint, hexadecimal")
  fingerprintSha1: Option[String]
)

@description(
  "The client TLS session, either terminated by spy itself (source \"connection\") or by a trusted reverse proxy " +
    "which forwards its details through X-SSL-* headers (source \"reverse-proxy\")"
)
case class TlsDetails(
  @description("connection or reverse-proxy")
  source: String,
  @description("TLS protocol version")
  protocol: Option[String],
  @description("negotiated cipher suite")
  cipherSuite: Option[String],
  @description("TLS session identifier")
  sessionId: Option[String],
  @description("the TLS session was resumed")
  sessionReused: Option[Boolean],
  @description("server names requested through SNI")
  serverNames: List[String],
  @description("negotiated ALPN protocol")
  alpn: Option[String],
  @description("key exchange curve")
  curve: Option[String],
  @description("TLS 1.3 early data (0-RTT) was used")
  earlyData: Option[Boolean],
  @description("cipher suites offered by the client")
  clientCiphers: List[String],
  @description("curves offered by the client")
  clientCurves: List[String],
  @description("JA3 TLS client fingerprint")
  ja3: Option[String],
  @description("JA4 TLS client fingerprint")
  ja4: Option[String],
  @description("client certificate verification result (SUCCESS, NONE, FAILED:reason)")
  clientCertificateVerify: Option[String],
  @description("client certificate subject")
  peerPrincipal: Option[String],
  @description("client certificate chain")
  peerCertificates: List[CertificateInfo],
  @description("server certificate subject")
  localPrincipal: Option[String]
)

@description("User agent heuristically parsed")
case class UserAgentDetails(
  @description("browser or client name")
  browser: Option[String],
  @description("browser or client version")
  browserVersion: Option[String],
  @description("rendering engine")
  engine: Option[String],
  @description("operating system")
  os: Option[String],
  @description("operating system version")
  osVersion: Option[String],
  @description("desktop, mobile, tablet, tv, console, bot or cli")
  deviceType: Option[String],
  @description("crawler, bot or monitoring agent")
  bot: Boolean
)
