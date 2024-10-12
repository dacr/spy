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
package spy.routing

import org.apache.pekko.http.scaladsl.model.*
import org.apache.pekko.http.scaladsl.server.Directives.*
import org.apache.pekko.http.scaladsl.server.Route
import com.github.pjfanning.pekkohttpjson4s.Json4sSupport.*
import org.slf4j.LoggerFactory
import spy.ServiceDependencies
import spy.tools.DateTimeTools

import java.util.UUID
import scala.concurrent.ExecutionContextExecutor

case class ClientInfo(
  clientIP: String,
  userAgent: String
)

case class SpyRouting(dependencies: ServiceDependencies) extends Routing with DateTimeTools {
  private val logger = LoggerFactory.getLogger(getClass)

  val apiURL = dependencies.config.spy.site.apiURL
  val meta = dependencies.config.spy.metaInfo
  val startedDate = now()
  val instanceUUID = UUID.randomUUID().toString

  implicit val ec: ExecutionContextExecutor = scala.concurrent.ExecutionContext.global

  private def getClientIP(clientIP: RemoteAddress) = {
    clientIP.toOption.map(_.getHostAddress).getOrElse("unknown")
  }

  override def routes: Route = pathPrefix("api") {
    concat(info, myip, myclient)
  }

  def info: Route = {
    get {
      path("info") {
        complete(
          Map(
            "instanceUUID" -> instanceUUID,
            "startedOn" -> epochToUTCDateTime(startedDate),
            "version" -> meta.version,
            "buildDate" -> meta.buildDateTime
          )
        )
      }
    }
  }

  def myclient: Route = {
    path("myclient") {
      get {
        headerValueByName(headerName = "User-Agent") { userAgent =>
          extractClientIP { clientIP =>
            respondWithHeaders(noClientCacheHeaders) {
              complete {
                val info = ClientInfo(clientIP = getClientIP(clientIP), userAgent = userAgent)
                logger.info(s"ClientInfo returned to client : $info")
                info
              }
            }
          }
        }
      }
    }
  }


  def myip: Route = {
    path("myip") {
      get {
        extractClientIP { clientIP =>
          respondWithHeaders(noClientCacheHeaders) {
            complete {
              val ip = getClientIP(clientIP)
              logger.info(s"IP returned to client : $ip")
              ip
            }
          }
        }
      }
    }
  }

}
