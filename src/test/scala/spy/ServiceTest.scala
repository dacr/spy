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
package spy

import org.apache.pekko.http.scaladsl.testkit.ScalatestRouteTest
import org.scalatest.matchers._
import org.scalatest.wordspec._
import org.apache.pekko.http.scaladsl.model.{AttributeKeys, HttpEntity, RemoteAddress}
import java.net.InetAddress
import org.apache.pekko.http.scaladsl.model.headers.RawHeader
import org.apache.pekko.http.scaladsl.testkit.RouteTestTimeout
import scala.concurrent.duration.DurationInt
import spy.model.{ClientInfo, PrivacySignals, UserAgentDetails}
import spy.routing.Health
import spy.tools.JsonImplicits


class ServiceTest extends AnyWordSpec with should.Matchers with ScalatestRouteTest with JsonImplicits {

  implicit val routeTestTimeout: RouteTestTimeout = RouteTestTimeout(10.seconds) // reverse DNS lookups may take time

  val routes = ServiceRoutes(ServiceDependencies.defaults).routes

  "Web Echo Service" should {
    "Respond OK when pinged" in {
      Get("/health") ~> routes ~> check {
        import com.github.pjfanning.pekkohttpjsoniterscala.JsoniterScalaSupport.*
        responseAs[Health] shouldBe Health(true, "alive")
      }
    }
    "Be able to return a static asset" in {
      Get("/txt/LICENSE-2.0.txt") ~> routes ~> check {
        responseAs[String] should include regex "Apache License"
      }
      Get("/txt/TERMS-OF-SERVICE.txt") ~> routes ~> check {
        responseAs[String] should include regex "WARRANTY"
      }
    }
    "Be able to return an embedded webjar asset" in {
      Get("/assets/jquery/jquery.js") ~> routes ~> check {
        responseAs[String] should include regex "jQuery JavaScript Library"
      }
    }
    "Respond a counters related home page content" in {
      info("The first content page can be slow because of templates runtime compilation")
      Get() ~> routes ~> check {
        responseAs[String] should include regex "SPY"
      }
    }
    "Respond to info request" in {
      Get("/api/info") ~> routes ~> check {
        import com.github.pjfanning.pekkohttpjsoniterscala.JsoniterScalaSupport.*
        responseAs[spy.routing.ServiceInfo].version should not be empty
      }
    }
    "Respond to myip request" in {
      Get("/api/myip") ~> routes ~> check {
        import com.github.pjfanning.pekkohttpjsoniterscala.JsoniterScalaSupport.*
        responseAs[String] shouldBe "unknown" // Since no headers provided
      }
    }
    "Respond to myclient request without any information" in {
      Get("/api/myclient") ~> routes ~> check {
        import com.github.pjfanning.pekkohttpjsoniterscala.JsoniterScalaSupport.*
        val info = responseAs[ClientInfo]
        info.clientIP shouldBe None
        info.userAgent shouldBe None
        info.request.method shouldBe "GET"
        info.request.path shouldBe "/api/myclient"
      }
    }
    "Respond to myclient request with an exhaustive set of information" in {
      val request = Get("/api/myclient?a=1&a=2&b=x").withHeaders(
        RawHeader("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.2478.80"),
        RawHeader("Forwarded", "for=\"[2001:db8:cafe::17]:4711\";proto=https;host=example.com, for=192.0.2.60"),
        RawHeader("X-Forwarded-For", "203.0.113.195, 70.41.3.18, 150.172.238.178"),
        RawHeader("Via", "1.1 proxy-a, 1.1 proxy-b"),
        RawHeader("Accept-Language", "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7"),
        RawHeader("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
        RawHeader("Sec-CH-UA", "\"Chromium\";v=\"124\", \"Microsoft Edge\";v=\"124\", \"Not-A.Brand\";v=\"99\""),
        RawHeader("Sec-CH-UA-Mobile", "?0"),
        RawHeader("Sec-CH-UA-Platform", "\"Windows\""),
        RawHeader("Sec-Fetch-Site", "none"),
        RawHeader("Sec-Fetch-User", "?1"),
        RawHeader("DNT", "1"),
        RawHeader("Sec-GPC", "1"),
        RawHeader("CF-IPCountry", "FR"),
        RawHeader("CF-IPCity", "Paris"),
        RawHeader("traceparent", "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"),
        RawHeader("Authorization", "Bearer super-secret-token"),
        RawHeader("Cookie", "session=very-secret; theme=dark")
      )
      request ~> routes ~> check {
        import com.github.pjfanning.pekkohttpjsoniterscala.JsoniterScalaSupport.*
        val raw = response.entity.asInstanceOf[HttpEntity.Strict].data.utf8String
        raw should not include "super-secret-token"
        raw should not include "very-secret"
        val info = responseAs[ClientInfo]
        info.clientIP shouldBe Some("2001:db8:cafe:0:0:0:0:17")
        info.clientIPSource shouldBe Some("Forwarded")
        info.clientIPDetails.map(_.documentation) shouldBe Some(true)
        info.clientIPDetails.map(_.publiclyRoutable) shouldBe Some(false)
        info.proxy.behindProxy shouldBe true
        info.proxy.forwarded.size shouldBe 2
        info.proxy.xForwardedFor shouldBe List("203.0.113.195", "70.41.3.18", "150.172.238.178")
        info.proxy.via shouldBe List("1.1 proxy-a", "1.1 proxy-b")
        info.proxy.hopsCount shouldBe Some(3)
        info.preferences.preferredLanguage shouldBe Some("fr-FR")
        info.preferences.mediaTypes.last.value shouldBe "*/*"
        info.clientHints.brands.map(_.name) should contain("Microsoft Edge")
        info.clientHints.mobile shouldBe Some(false)
        info.clientHints.platform shouldBe Some("Windows")
        info.fetchMetadata.user shouldBe Some(true)
        info.privacy shouldBe PrivacySignals(Some(true), Some(true))
        info.geo.map(_.source) shouldBe Some("cloudflare")
        info.geo.flatMap(_.city) shouldBe Some("Paris")
        info.tracing.traceparent shouldBe defined
        info.authorizationScheme shouldBe Some("Bearer")
        info.cookieNames shouldBe List("session", "theme")
        info.request.query shouldBe Map("a" -> List("1", "2"), "b" -> List("x"))
        info.userAgentDetails.flatMap(_.browser) shouldBe Some("Edge")
        info.userAgentDetails.flatMap(_.os) shouldBe Some("Windows")
        info.userAgentDetails.flatMap(_.deviceType) shouldBe Some("desktop")
      }
    }
    "Describe the client connection and request as seen by the client when behind a reverse proxy" in {
      val clientIP = "2a01:cb08:84cd:200:6d5f:2f36:d9c8:2b0b"
      val request  = Get("http://spy.code-examples.org/api/myclient?x=1")
        .withHeaders(
          RawHeader("X-Real-Ip", clientIP),
          RawHeader("X-Forwarded-For", clientIP),
          RawHeader("X-Forwarded-Proto", "https"),
          RawHeader("X-Forwarded-Host", "spy.code-examples.org"),
          RawHeader("X-Forwarded-Server", "thorgal")
        )
        .addAttribute(AttributeKeys.remoteAddress, RemoteAddress(InetAddress.getLoopbackAddress, Some(60036)))
      request ~> routes ~> check {
        import com.github.pjfanning.pekkohttpjsoniterscala.JsoniterScalaSupport.*
        val info = responseAs[ClientInfo]
        info.connection.viaReverseProxy shouldBe true
        info.connection.remoteAddress shouldBe Some("2a01:cb08:84cd:200:6d5f:2f36:d9c8:2b0b")
        info.connection.remoteAddressDetails.map(_.publiclyRoutable) shouldBe Some(true)
        info.connection.remotePort shouldBe None // not provided by this proxy
        info.connection.secure shouldBe Some(true)
        info.connection.protocol shouldBe None
        info.request.url shouldBe "https://spy.code-examples.org/api/myclient?x=1"
        info.request.scheme shouldBe Some("https")
        info.request.port shouldBe Some(443)
        info.proxy.peerAddress shouldBe Some("127.0.0.1")
        info.proxy.peerPort shouldBe Some(60036)
        info.proxy.peerAddressDetails.map(_.loopback) shouldBe Some(true)
        info.proxy.peerProtocol shouldBe Some("HTTP/1.1")
        info.proxy.peerSecure shouldBe Some(false)
        info.proxy.upstreamUrl shouldBe Some("http://spy.code-examples.org:80/api/myclient?x=1")
      }
    }
    "Use RFC 7239 Forwarded client port, host and the forwarded prefix" in {
      val request = Get("http://10.0.0.5:8080/api/myclient")
        .withHeaders(
          RawHeader("Forwarded", "for=\"[2001:db8::42]:51234\";proto=https;host=\"example.com:8443\""),
          RawHeader("X-Forwarded-Prefix", "/spy")
        )
        .addAttribute(AttributeKeys.remoteAddress, RemoteAddress(InetAddress.getByName("10.0.0.1"), Some(40000)))
      request ~> routes ~> check {
        import com.github.pjfanning.pekkohttpjsoniterscala.JsoniterScalaSupport.*
        val info = responseAs[ClientInfo]
        info.connection.remoteAddress shouldBe Some("2001:db8:0:0:0:0:0:42")
        info.connection.remotePort shouldBe Some(51234)
        info.request.url shouldBe "https://example.com:8443/spy/api/myclient"
        info.request.path shouldBe "/spy/api/myclient"
        info.proxy.peerAddress shouldBe Some("10.0.0.1")
      }
    }
    "Keep the TCP peer as the client connection when not behind a proxy" in {
      Get("/api/myclient").addAttribute(AttributeKeys.remoteAddress, RemoteAddress(InetAddress.getByName("192.168.1.20"), Some(50000))) ~> routes ~> check {
        import com.github.pjfanning.pekkohttpjsoniterscala.JsoniterScalaSupport.*
        val info = responseAs[ClientInfo]
        info.connection.viaReverseProxy shouldBe false
        info.connection.remoteAddress shouldBe Some("192.168.1.20")
        info.connection.remotePort shouldBe Some(50000)
        info.connection.protocol shouldBe Some("HTTP/1.1")
        info.proxy.behindProxy shouldBe false
        info.proxy.peerAddress shouldBe None
      }
    }
    "Detect command line clients" in {
      Get("/api/myclient").withHeaders(RawHeader("User-Agent", "curl/8.11.1"), RawHeader("X-Real-IP", "10.1.2.3")) ~> routes ~> check {
        import com.github.pjfanning.pekkohttpjsoniterscala.JsoniterScalaSupport.*
        val info = responseAs[ClientInfo]
        info.userAgentDetails shouldBe Some(UserAgentDetails(Some("curl"), Some("8.11.1"), None, None, None, Some("cli"), false))
        info.clientIP shouldBe Some("10.1.2.3")
        info.clientIPSource shouldBe Some("X-Real-IP")
        info.clientIPDetails.map(_.privateRange) shouldBe Some(true)
      }
    }
  }
}

