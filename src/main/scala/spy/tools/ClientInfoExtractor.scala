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
package spy.tools

import org.apache.pekko.http.scaladsl.model.{AttributeKeys, SslSessionInfo}
import org.apache.pekko.http.scaladsl.server.RequestContext
import spy.model.*
import sttp.tapir.model.ServerRequest

import java.net.{Inet4Address, Inet6Address, InetAddress}
import java.security.cert.X509Certificate
import java.util.HexFormat
import java.util.concurrent.{CompletableFuture, Executors, TimeUnit}
import javax.net.ssl.{ExtendedSSLSession, SNIHostName}
import scala.concurrent.{ExecutionContext, Future}
import scala.jdk.CollectionConverters.*
import scala.jdk.FutureConverters.*
import scala.util.Try

/** Extract everything which can be learnt about the client from a request.
  *
  * @param reverseDnsLookup
  *   enable reverse DNS resolution of the client IP addresses
  * @param reverseDnsTimeoutMs
  *   max time spent in a reverse DNS resolution
  */
class ClientInfoExtractor(reverseDnsLookup: Boolean, reverseDnsTimeoutMs: Long = 2000L) {

  private val dnsExecutor = Executors.newVirtualThreadPerTaskExecutor()

  // -------------------------------------------------------------------------------------------------------------------
  // Generic header helpers

  private def headerValues(req: ServerRequest, name: String): List[String] =
    req.headers(name).toList.map(_.trim).filter(_.nonEmpty)

  private def h(req: ServerRequest, name: String): Option[String] =
    headerValues(req, name) match {
      case Nil    => None
      case values => Some(values.mkString(", "))
    }

  /** comma separated list, possibly spread among several headers */
  private def hList(req: ServerRequest, name: String): List[String] =
    headerValues(req, name).flatMap(_.split(",")).map(_.trim).filter(_.nonEmpty)

  /** structured-field string ("..." quoted) */
  private def unquote(s: String): String = {
    val t = s.trim
    if (t.length >= 2 && t.startsWith("\"") && t.endsWith("\"")) t.substring(1, t.length - 1).replace("\\\"", "\"").replace("\\\\", "\\")
    else t
  }

  private def hString(req: ServerRequest, name: String): Option[String] = h(req, name).map(unquote).filter(_.nonEmpty)

  /** structured-field boolean (?1 / ?0) or plain 1/0/true/false */
  private def hBool(req: ServerRequest, name: String): Option[Boolean] = h(req, name).map(_.trim.toLowerCase).collect {
    case "?1" | "1" | "true" | "yes" | "on" => true
    case "?0" | "0" | "false" | "no" | "off" => false
  }

  private def hDouble(req: ServerRequest, name: String): Option[Double] = h(req, name).flatMap(_.trim.toDoubleOption)
  private def hInt(req: ServerRequest, name: String): Option[Int]       = h(req, name).flatMap(v => v.trim.toIntOption.orElse(v.trim.toDoubleOption.map(_.round.toInt)))

  // -------------------------------------------------------------------------------------------------------------------
  // IP helpers

  /** Extract a bare IP from values such as `1.2.3.4`, `1.2.3.4:8080`, `[2001:db8::1]:443`, `"[2001:db8::1]"` */
  def normalizeIP(raw: String): Option[InetAddress] = {
    val v    = unquote(raw).trim
    val bare =
      if (v.startsWith("[")) v.drop(1).takeWhile(_ != ']')
      else if (v.count(_ == ':') == 1) v.takeWhile(_ != ':')
      else v
    Option(bare).filter(_.nonEmpty).flatMap(b => Try(InetAddress.ofLiteral(b)).toOption) // ofLiteral never triggers DNS
  }

  private def inRange(addr: InetAddress, prefix: String, bits: Int): Boolean = {
    val net = InetAddress.ofLiteral(prefix).getAddress
    val a   = addr.getAddress
    a.length == net.length && {
      val full = bits / 8
      val rem  = bits % 8
      (0 until full).forall(i => a(i) == net(i)) &&
      (rem == 0 || ((a(full) ^ net(full)) & (0xff << (8 - rem)) & 0xff) == 0)
    }
  }

  private def ipv4Mapped(addr: InetAddress): Option[InetAddress] = addr match {
    case v6: Inet6Address =>
      val b = v6.getAddress
      if (b.take(10).forall(_ == 0) && b(10) == -1 && b(11) == -1) Some(InetAddress.getByAddress(b.drop(12))) else None
    case _                => None
  }

  private def reverseDns(addr: InetAddress): Future[Option[String]] =
    if (!reverseDnsLookup) Future.successful(None)
    else {
      CompletableFuture
        .supplyAsync(
          () => {
            val ip   = addr.getHostAddress
            val name = Try(InetAddress.getByAddress(addr.getAddress).getCanonicalHostName).toOption
            name.filter(n => n.nonEmpty && n != ip)
          },
          dnsExecutor
        )
        .completeOnTimeout(None, reverseDnsTimeoutMs, TimeUnit.MILLISECONDS)
        .exceptionally(_ => None)
        .asScala
    }

  def ipDetails(addr: InetAddress)(using ExecutionContext): Future[IpDetails] = {
    val mapped    = ipv4Mapped(addr)
    val effective = mapped.getOrElse(addr)
    val isV4      = effective.isInstanceOf[Inet4Address]
    val loopback  = effective.isLoopbackAddress
    val priv      = isV4 && (inRange(effective, "10.0.0.0", 8) || inRange(effective, "172.16.0.0", 12) || inRange(effective, "192.168.0.0", 16))
    val linkLocal = effective.isLinkLocalAddress
    val ula       = !isV4 && inRange(effective, "fc00::", 7)
    val cgnat     = isV4 && inRange(effective, "100.64.0.0", 10)
    val multicast = effective.isMulticastAddress
    val unspec    = effective.isAnyLocalAddress
    val doc       =
      if (isV4) inRange(effective, "192.0.2.0", 24) || inRange(effective, "198.51.100.0", 24) || inRange(effective, "203.0.113.0", 24)
      else inRange(effective, "2001:db8::", 32) || inRange(effective, "3fff::", 20)
    val siteLocalV6 = !isV4 && effective.isSiteLocalAddress
    val publicIP    = !(loopback || priv || linkLocal || ula || cgnat || multicast || unspec || doc || siteLocalV6)
    reverseDns(addr).map { rdns =>
      IpDetails(
        address = addr.getHostAddress,
        version = if (addr.isInstanceOf[Inet4Address]) "IPv4" else "IPv6",
        loopback = loopback,
        privateRange = priv || siteLocalV6,
        linkLocal = linkLocal,
        uniqueLocal = ula,
        carrierGradeNat = cgnat,
        multicast = multicast,
        unspecified = unspec,
        documentation = doc,
        ipv4Mapped = mapped.map(_.getHostAddress),
        publiclyRoutable = publicIP,
        reverseDns = rdns
      )
    }
  }

  // -------------------------------------------------------------------------------------------------------------------
  // Parsers

  /** RFC 7239 Forwarded header */
  def parseForwarded(values: List[String]): List[ForwardedElement] =
    values.flatMap(_.split(",")).map(_.trim).filter(_.nonEmpty).map { element =>
      val pairs = element
        .split(";")
        .toList
        .flatMap { pair =>
          pair.split("=", 2) match {
            case Array(k, v) => Some(k.trim.toLowerCase -> unquote(v))
            case _           => None
          }
        }
        .toMap
      ForwardedElement(forValue = pairs.get("for"), by = pairs.get("by"), host = pairs.get("host"), proto = pairs.get("proto"))
    }

  /** Accept-* like headers : `en-US,en;q=0.9,*;q=0.1` sorted by decreasing quality */
  def parseWeighted(values: List[String]): List[WeightedValue] =
    values
      .flatMap(_.split(","))
      .map(_.trim)
      .filter(_.nonEmpty)
      .zipWithIndex
      .map { case (item, index) =>
        val parts   = item.split(";").map(_.trim)
        val quality = parts.drop(1).collectFirst { case p if p.toLowerCase.startsWith("q=") => p.drop(2).toDoubleOption }.flatten.getOrElse(1.0d)
        val value   = (parts.head +: parts.drop(1).filterNot(_.toLowerCase.startsWith("q="))).mkString(";")
        (WeightedValue(value, quality), index)
      }
      .sortBy { case (wv, index) => (-wv.quality, index) }
      .map(_._1)

  private val brandRE = "\"((?:[^\"\\\\]|\\\\.)*)\"\\s*(?:;\\s*v\\s*=\\s*\"((?:[^\"\\\\]|\\\\.)*)\")?".r

  /** Sec-CH-UA like headers : `"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"` */
  def parseBrands(value: Option[String]): List[Brand] =
    value.toList.flatMap(v => brandRE.findAllMatchIn(v).map(m => Brand(m.group(1), Option(m.group(2)).filter(_.nonEmpty))).toList)

  // -------------------------------------------------------------------------------------------------------------------
  // Sensitive data handling

  private val sensitiveHeaders = Set(
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "api-key",
    "x-auth-token",
    "x-access-token",
    "x-csrf-token",
    "x-xsrf-token",
    "x-amz-security-token"
  )

  /** headers added by pekko-http itself, not sent by the client */
  private val syntheticHeaders = Set("timeout-access", "remote-address", "tls-session-info", "raw-request-uri")

  def isSensitive(headerName: String): Boolean = sensitiveHeaders.contains(headerName.toLowerCase)

  private def authScheme(value: Option[String]): Option[String] = value.flatMap(_.trim.split("\\s+").headOption).filter(_.nonEmpty)

  // -------------------------------------------------------------------------------------------------------------------
  // Main extraction

  private val clientIPHeaders = List(
    "X-Forwarded-For",
    "X-Real-IP",
    "True-Client-IP",
    "CF-Connecting-IP",
    "CF-Connecting-IPv6",
    "Fastly-Client-IP",
    "X-Client-IP",
    "X-Cluster-Client-IP",
    "X-Original-Forwarded-For"
  )

  def extract(req: ServerRequest)(using ExecutionContext): Future[ClientInfo] = {
    val pekkoContext = req.underlying match {
      case ctx: RequestContext => Some(ctx)
      case _                   => None
    }

    // -------- connection
    val remote        = req.connectionInfo.remote
    val remoteAddress = remote.flatMap(r => Option(r.getAddress))
    val remotePort    = remote.map(_.getPort).filter(_ > 0)

    // -------- proxies
    val forwarded = parseForwarded(headerValues(req, "Forwarded"))
    val xff       = hList(req, "X-Forwarded-For")
    val via       = hList(req, "Via")

    // -------- best client IP guess
    val fromForwarded = forwarded.iterator.flatMap(_.forValue).flatMap(normalizeIP).nextOption().map(_ -> "Forwarded")
    val fromHeaders   = clientIPHeaders.iterator.flatMap { name =>
      hList(req, name).headOption.flatMap(normalizeIP).map(_ -> name)
    }.nextOption()
    val fromRemote    = remoteAddress.map(_ -> "connection")
    val clientIP      = fromForwarded.orElse(fromHeaders).orElse(fromRemote)

    val proxy = ProxyDetails(
      behindProxy = forwarded.nonEmpty || xff.nonEmpty || via.nonEmpty || clientIP.exists(_._2 != "connection"),
      hopsCount = Some(List(forwarded.size, xff.size, via.size).max).filter(_ > 0),
      forwarded = forwarded,
      xForwardedFor = xff,
      xForwardedProto = h(req, "X-Forwarded-Proto"),
      xForwardedHost = h(req, "X-Forwarded-Host"),
      xForwardedPort = h(req, "X-Forwarded-Port"),
      xForwardedPrefix = h(req, "X-Forwarded-Prefix"),
      xForwardedServer = h(req, "X-Forwarded-Server"),
      xRealIP = h(req, "X-Real-IP"),
      xClientIP = h(req, "X-Client-IP"),
      xClusterClientIP = h(req, "X-Cluster-Client-IP"),
      xOriginalForwardedFor = h(req, "X-Original-Forwarded-For"),
      trueClientIP = h(req, "True-Client-IP"),
      cfConnectingIP = h(req, "CF-Connecting-IP"),
      cfConnectingIPv6 = h(req, "CF-Connecting-IPv6"),
      cfRay = h(req, "CF-Ray"),
      cfVisitor = h(req, "CF-Visitor"),
      cfWorker = h(req, "CF-Worker"),
      fastlyClientIP = h(req, "Fastly-Client-IP"),
      akamaiEdgeScape = h(req, "X-Akamai-Edgescape"),
      via = via,
      maxForwards = hInt(req, "Max-Forwards")
    )

    // -------- geo hints provided by CDN / cloud front ends
    val geo = {
      def latLong(v: Option[String]): (Option[Double], Option[Double]) = v.map(_.split(",").map(_.trim.toDoubleOption)) match {
        case Some(Array(lat, lon)) => (lat, lon)
        case _                     => (None, None)
      }
      val cloudflare = Option.when(h(req, "CF-IPCountry").isDefined || h(req, "CF-IPCity").isDefined)(
        GeoHints(
          source = "cloudflare",
          country = hString(req, "CF-IPCountry"),
          continent = hString(req, "CF-IPContinent"),
          region = hString(req, "CF-Region"),
          regionCode = hString(req, "CF-Region-Code"),
          city = hString(req, "CF-IPCity"),
          postalCode = hString(req, "CF-Postal-Code"),
          latitude = hDouble(req, "CF-IPLatitude"),
          longitude = hDouble(req, "CF-IPLongitude"),
          timeZone = hString(req, "CF-Timezone"),
          asn = None
        )
      )
      val cloudfront = Option.when(h(req, "CloudFront-Viewer-Country").isDefined)(
        GeoHints(
          source = "cloudfront",
          country = hString(req, "CloudFront-Viewer-Country"),
          continent = None,
          region = hString(req, "CloudFront-Viewer-Country-Region-Name"),
          regionCode = hString(req, "CloudFront-Viewer-Country-Region"),
          city = hString(req, "CloudFront-Viewer-City"),
          postalCode = hString(req, "CloudFront-Viewer-Postal-Code"),
          latitude = hDouble(req, "CloudFront-Viewer-Latitude"),
          longitude = hDouble(req, "CloudFront-Viewer-Longitude"),
          timeZone = hString(req, "CloudFront-Viewer-Time-Zone"),
          asn = hString(req, "CloudFront-Viewer-ASN")
        )
      )
      val vercel     = Option.when(h(req, "X-Vercel-IP-Country").isDefined)(
        GeoHints(
          source = "vercel",
          country = hString(req, "X-Vercel-IP-Country"),
          continent = hString(req, "X-Vercel-IP-Continent"),
          region = None,
          regionCode = hString(req, "X-Vercel-IP-Country-Region"),
          city = hString(req, "X-Vercel-IP-City").map(c => Try(java.net.URLDecoder.decode(c, "UTF-8")).getOrElse(c)),
          postalCode = hString(req, "X-Vercel-IP-Postal-Code"),
          latitude = hDouble(req, "X-Vercel-IP-Latitude"),
          longitude = hDouble(req, "X-Vercel-IP-Longitude"),
          timeZone = hString(req, "X-Vercel-IP-Timezone"),
          asn = None
        )
      )
      val appengine  = Option.when(h(req, "X-AppEngine-Country").isDefined)({
        val (lat, lon) = latLong(h(req, "X-AppEngine-CityLatLong"))
        GeoHints(
          source = "appengine",
          country = hString(req, "X-AppEngine-Country"),
          continent = None,
          region = None,
          regionCode = hString(req, "X-AppEngine-Region"),
          city = hString(req, "X-AppEngine-City"),
          postalCode = None,
          latitude = lat,
          longitude = lon,
          timeZone = None,
          asn = None
        )
      })
      val gclb       = Option.when(h(req, "X-Client-Geo-Location").isDefined || h(req, "X-Client-Region").isDefined)({
        val (lat, lon) = latLong(h(req, "X-Client-Geo-Location"))
        GeoHints(
          source = "google-load-balancer",
          country = None,
          continent = None,
          region = hString(req, "X-Client-Region"),
          regionCode = hString(req, "X-Client-Region-Subdivision"),
          city = hString(req, "X-Client-City"),
          postalCode = None,
          latitude = lat,
          longitude = lon,
          timeZone = None,
          asn = None
        )
      })
      cloudflare.orElse(cloudfront).orElse(vercel).orElse(appengine).orElse(gclb)
    }

    // -------- content negotiation
    val languages   = parseWeighted(headerValues(req, "Accept-Language"))
    val preferences = ClientPreferences(
      preferredLanguage = languages.find(l => l.value != "*" && l.quality > 0).map(_.value),
      languages = languages,
      mediaTypes = parseWeighted(headerValues(req, "Accept")),
      encodings = parseWeighted(headerValues(req, "Accept-Encoding")),
      charsets = parseWeighted(headerValues(req, "Accept-Charset"))
    )

    // -------- client hints
    val clientHints = ClientHints(
      brands = parseBrands(h(req, "Sec-CH-UA")),
      fullVersionList = parseBrands(h(req, "Sec-CH-UA-Full-Version-List")),
      fullVersion = hString(req, "Sec-CH-UA-Full-Version"),
      mobile = hBool(req, "Sec-CH-UA-Mobile"),
      platform = hString(req, "Sec-CH-UA-Platform"),
      platformVersion = hString(req, "Sec-CH-UA-Platform-Version"),
      architecture = hString(req, "Sec-CH-UA-Arch"),
      bitness = hString(req, "Sec-CH-UA-Bitness"),
      model = hString(req, "Sec-CH-UA-Model"),
      wow64 = hBool(req, "Sec-CH-UA-WoW64"),
      formFactors = hList(req, "Sec-CH-UA-Form-Factors").map(unquote),
      deviceMemoryGB = hDouble(req, "Sec-CH-Device-Memory").orElse(hDouble(req, "Device-Memory")),
      devicePixelRatio = hDouble(req, "Sec-CH-DPR").orElse(hDouble(req, "DPR")),
      viewportWidth = hInt(req, "Sec-CH-Viewport-Width").orElse(hInt(req, "Viewport-Width")),
      viewportHeight = hInt(req, "Sec-CH-Viewport-Height"),
      width = hInt(req, "Sec-CH-Width").orElse(hInt(req, "Width")),
      downlinkMbps = hDouble(req, "Downlink"),
      effectiveConnectionType = hString(req, "ECT"),
      roundTripTimeMs = hInt(req, "RTT"),
      saveData = hBool(req, "Save-Data").orElse(h(req, "Save-Data").map(_.trim.equalsIgnoreCase("on"))),
      prefersColorScheme = hString(req, "Sec-CH-Prefers-Color-Scheme"),
      prefersReducedMotion = hString(req, "Sec-CH-Prefers-Reduced-Motion"),
      prefersReducedTransparency = hString(req, "Sec-CH-Prefers-Reduced-Transparency"),
      prefersContrast = hString(req, "Sec-CH-Prefers-Contrast"),
      forcedColors = hString(req, "Sec-CH-Forced-Colors")
    )

    val fetchMetadata = FetchMetadata(
      site = h(req, "Sec-Fetch-Site"),
      mode = h(req, "Sec-Fetch-Mode"),
      dest = h(req, "Sec-Fetch-Dest"),
      user = hBool(req, "Sec-Fetch-User"),
      storageAccess = h(req, "Sec-Fetch-Storage-Access"),
      purpose = h(req, "Sec-Purpose").orElse(h(req, "Purpose")).orElse(h(req, "X-Moz")).orElse(h(req, "X-Purpose"))
    )

    val navigation = NavigationDetails(
      referer = h(req, "Referer"),
      origin = h(req, "Origin"),
      upgradeInsecureRequests = hBool(req, "Upgrade-Insecure-Requests"),
      cacheControl = h(req, "Cache-Control"),
      pragma = h(req, "Pragma"),
      connection = h(req, "Connection"),
      keepAlive = h(req, "Keep-Alive"),
      te = h(req, "TE"),
      upgrade = h(req, "Upgrade"),
      xRequestedWith = h(req, "X-Requested-With"),
      ifNoneMatch = h(req, "If-None-Match"),
      ifModifiedSince = h(req, "If-Modified-Since"),
      range = h(req, "Range"),
      priority = h(req, "Priority"),
      expect = h(req, "Expect")
    )

    val privacy = PrivacySignals(
      doNotTrack = hBool(req, "DNT"),
      globalPrivacyControl = hBool(req, "Sec-GPC")
    )

    val tracing = TracingDetails(
      requestId = h(req, "X-Request-ID"),
      correlationId = h(req, "X-Correlation-ID"),
      traceparent = h(req, "traceparent"),
      tracestate = h(req, "tracestate"),
      b3 = h(req, "b3"),
      b3TraceId = h(req, "X-B3-TraceId"),
      amazonTraceId = h(req, "X-Amzn-Trace-Id"),
      cloudTraceContext = h(req, "X-Cloud-Trace-Context"),
      baggage = h(req, "baggage")
    )

    // -------- TLS (only when TLS is terminated by this service and ssl-session-attribute is enabled)
    val tls = pekkoContext
      .flatMap(_.request.attributes.get(AttributeKeys.sslSession))
      .collect { case info: SslSessionInfo => info }
      .filterNot(info => info.session.getProtocol == null || info.session.getProtocol == "NONE") // plain HTTP placeholder session
      .map { info =>
        val session = info.session
        val sni     = session match {
          case ext: ExtendedSSLSession => Try(ext.getRequestedServerNames.asScala.toList.collect { case n: SNIHostName => n.getAsciiName }).getOrElse(Nil)
          case _                       => Nil
        }
        TlsDetails(
          protocol = Option(session.getProtocol),
          cipherSuite = Option(session.getCipherSuite),
          sessionId = Option(session.getId).filter(_.nonEmpty).map(HexFormat.of().formatHex),
          serverNames = sni,
          peerPrincipal = info.peerPrincipal.map(_.getName),
          peerCertificates = info.peerCertificates.collect { case c: X509Certificate =>
            CertificateInfo(
              subject = c.getSubjectX500Principal.getName,
              issuer = c.getIssuerX500Principal.getName,
              serialNumber = c.getSerialNumber.toString(16),
              notBefore = c.getNotBefore.toInstant.toString,
              notAfter = c.getNotAfter.toInstant.toString,
              signatureAlgorithm = c.getSigAlgName,
              publicKeyAlgorithm = c.getPublicKey.getAlgorithm
            )
          },
          localPrincipal = info.localPrincipal.map(_.getName)
        )
      }

    // -------- request
    val uri         = req.uri
    val allHeaders  = req.headers.toList.filterNot { hd =>
      syntheticHeaders.contains(hd.name.toLowerCase) || (hd.name.equalsIgnoreCase("Content-Length") && hd.value.trim == "0")
    }
    val requestInfo = RequestDetails(
      method = req.method.method,
      url = uri.toString,
      scheme = uri.scheme,
      host = uri.host,
      port = uri.port,
      path = uri.pathSegments.segments.map(_.v).mkString("/", "/", ""),
      query = req.queryParameters.toMultiMap.map { case (k, v) => k -> v.toList },
      contentType = h(req, "Content-Type"),
      contentLength = h(req, "Content-Length").flatMap(_.toLongOption).filter(_ > 0),
      headersCount = allHeaders.size,
      headersSize = allHeaders.map(hd => hd.name.length + hd.value.length + 4).sum
    )

    val cookieNames = headerValues(req, "Cookie")
      .flatMap(_.split(";"))
      .map(_.trim.takeWhile(_ != '='))
      .filter(_.nonEmpty)
      .distinct

    val headers = allHeaders.map { hd =>
      HeaderEntry(hd.name, if (isSensitive(hd.name)) "<redacted>" else hd.value)
    }

    val userAgent = h(req, "User-Agent")

    // -------- asynchronous parts (reverse DNS)
    val clientIPDetailsF = clientIP.map((addr, _) => ipDetails(addr).map(Some(_))).getOrElse(Future.successful(None))
    val remoteDetailsF   = remoteAddress match {
      case Some(addr) if clientIP.exists(_._1 == addr) => clientIPDetailsF
      case Some(addr)                                  => ipDetails(addr).map(Some(_))
      case None                                        => Future.successful(None)
    }

    for {
      clientIPDetails <- clientIPDetailsF
      remoteDetails   <- remoteDetailsF
    } yield ClientInfo(
      clientIP = clientIP.map(_._1.getHostAddress),
      clientIPSource = clientIP.map(_._2),
      clientIPDetails = clientIPDetails,
      userAgent = userAgent,
      userAgentDetails = userAgent.map(UserAgentParser.parse),
      connection = ConnectionDetails(
        remoteAddress = remoteAddress.map(_.getHostAddress),
        remotePort = remotePort,
        remoteAddressDetails = remoteDetails,
        secure = req.connectionInfo.secure,
        protocol = Option(req.protocol).filter(_.nonEmpty)
      ),
      request = requestInfo,
      proxy = proxy,
      geo = geo,
      preferences = preferences,
      clientHints = clientHints,
      fetchMetadata = fetchMetadata,
      navigation = navigation,
      privacy = privacy,
      tracing = tracing,
      tls = tls,
      authorizationScheme = authScheme(h(req, "Authorization")),
      proxyAuthorizationScheme = authScheme(h(req, "Proxy-Authorization")),
      cookieNames = cookieNames,
      headers = headers
    )
  }
}
