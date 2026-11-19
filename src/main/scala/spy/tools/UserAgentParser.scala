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

import spy.model.UserAgentDetails

import scala.util.matching.Regex

/** Lightweight best effort User-Agent parser, no external database involved. */
object UserAgentParser {

  private val botRE = "(?i)(bot|crawler|spider|crawl|slurp|facebookexternalhit|embedly|preview|monitor|headless|lighthouse)".r

  // (name, regex capturing the version) — order matters, first match wins
  private val cliClients: List[(String, Regex)] = List(
    "curl"              -> "(?i)\\bcurl/([\\w.\\-]+)".r,
    "Wget"              -> "(?i)\\bwget/([\\w.\\-]+)".r,
    "HTTPie"            -> "(?i)\\bhttpie/([\\w.\\-]+)".r,
    "python-requests"   -> "(?i)python-requests/([\\w.\\-]+)".r,
    "python-httpx"      -> "(?i)python-httpx/([\\w.\\-]+)".r,
    "aiohttp"           -> "(?i)aiohttp/([\\w.\\-]+)".r,
    "Python-urllib"     -> "(?i)python-urllib/([\\w.\\-]+)".r,
    "Go-http-client"    -> "(?i)go-http-client/([\\w.\\-]+)".r,
    "okhttp"            -> "(?i)okhttp/([\\w.\\-]+)".r,
    "Java"              -> "(?i)\\bjava/([\\w.\\-]+)".r,
    "Java-http-client"  -> "(?i)java-http-client/([\\w.\\-]+)".r,
    "Apache-HttpClient" -> "(?i)apache-httpclient/([\\w.\\-]+)".r,
    "node-fetch"        -> "(?i)node-fetch/([\\w.\\-]+)".r,
    "axios"             -> "(?i)axios/([\\w.\\-]+)".r,
    "undici"            -> "(?i)undici(?:/([\\w.\\-]+))?".r,
    "PostmanRuntime"    -> "(?i)postmanruntime/([\\w.\\-]+)".r,
    "insomnia"          -> "(?i)insomnia/([\\w.\\-]+)".r,
    "libwww-perl"       -> "(?i)libwww-perl/([\\w.\\-]+)".r,
    "sttp"              -> "(?i)\\bsttp/([\\w.\\-]+)".r,
    "pekko-http"        -> "(?i)pekko-http/([\\w.\\-]+)".r,
    "akka-http"         -> "(?i)akka-http/([\\w.\\-]+)".r
  )

  private val browsers: List[(String, Regex)] = List(
    "Edge"              -> "\\bEdg(?:e|A|iOS)?/([\\d.]+)".r,
    "Opera"             -> "\\b(?:OPR|Opera)/([\\d.]+)".r,
    "Vivaldi"           -> "\\bVivaldi/([\\d.]+)".r,
    "Yandex"            -> "\\bYaBrowser/([\\d.]+)".r,
    "Samsung Internet"  -> "\\bSamsungBrowser/([\\d.]+)".r,
    "UC Browser"        -> "\\bUCBrowser/([\\d.]+)".r,
    "Brave"             -> "\\bBrave/([\\d.]+)".r,
    "Firefox"           -> "\\b(?:Firefox|FxiOS)/([\\d.]+)".r,
    "Chromium"          -> "\\bChromium/([\\d.]+)".r,
    "Chrome"            -> "\\b(?:Chrome|CriOS)/([\\d.]+)".r,
    "Safari"            -> "\\bVersion/([\\d.]+).*\\bSafari/".r,
    "Internet Explorer" -> "(?:\\bMSIE ([\\d.]+)|\\bTrident/.*\\brv:([\\d.]+))".r
  )

  private val oses: List[(String, Regex)] = List(
    "Windows Phone" -> "Windows Phone(?: OS)? ([\\d.]+)".r,
    "Windows"       -> "Windows NT ([\\d.]+)".r,
    "iPadOS"        -> "iPad.*OS ([\\d_]+)".r,
    "iOS"           -> "(?:iPhone|CPU) OS ([\\d_]+)".r,
    "Android"       -> "Android ([\\d.]+)".r,
    "ChromeOS"      -> "CrOS \\S+ ([\\d.]+)".r,
    "macOS"         -> "Mac OS X ([\\d_.]+)".r,
    "HarmonyOS"     -> "HarmonyOS(?: ([\\d.]+))?".r,
    "FreeBSD"       -> "FreeBSD()".r,
    "OpenBSD"       -> "OpenBSD()".r,
    "Linux"         -> "Linux()".r
  )

  private def firstMatch(ua: String, candidates: List[(String, Regex)]): Option[(String, Option[String])] =
    candidates.iterator
      .flatMap { case (name, re) =>
        re.findFirstMatchIn(ua).map { m =>
          val version = (1 to m.groupCount).iterator.flatMap(i => Option(m.group(i))).find(_.nonEmpty)
          name -> version.map(_.replace('_', '.'))
        }
      }
      .nextOption()

  def parse(ua: String): UserAgentDetails = {
    val bot    = botRE.findFirstIn(ua).isDefined
    val cli    = firstMatch(ua, cliClients)
    val client = cli.orElse(firstMatch(ua, browsers))
    val os     = firstMatch(ua, oses)

    val engine =
      if (cli.isDefined) None
      else if (ua.contains("Gecko/") && ua.contains("Firefox")) Some("Gecko")
      else if (ua.contains("Trident/") || ua.contains("MSIE")) Some("Trident")
      else if (ua.contains("Presto/")) Some("Presto")
      else if (ua.contains("Chrome/") || ua.contains("CriOS/") || ua.contains("Edg")) Some("Blink")
      else if (ua.contains("AppleWebKit/")) Some("WebKit")
      else None

    val deviceType =
      if (bot) Some("bot")
      else if (cli.isDefined) Some("cli")
      else if ("(?i)smart-?tv|hbbtv|appletv|googletv|tizen.*tv|webos.*tv|\\bTV\\b".r.findFirstIn(ua).isDefined) Some("tv")
      else if ("(?i)playstation|xbox|nintendo".r.findFirstIn(ua).isDefined) Some("console")
      else if ("(?i)ipad|tablet|kindle|silk|playbook|(android(?!.*mobile))".r.findFirstIn(ua).isDefined) Some("tablet")
      else if ("(?i)mobi|iphone|ipod|android|windows phone|blackberry".r.findFirstIn(ua).isDefined) Some("mobile")
      else if (os.isDefined) Some("desktop")
      else None

    UserAgentDetails(
      browser = client.map(_._1),
      browserVersion = client.flatMap(_._2),
      engine = engine,
      os = os.map(_._1),
      osVersion = os.flatMap(_._2),
      deviceType = deviceType,
      bot = bot
    )
  }
}
