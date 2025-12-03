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

import org.apache.pekko.http.scaladsl.server.Route
import org.slf4j.LoggerFactory
import spy.ServiceDependencies
import spy.tools.DateTimeTools
import sttp.tapir._
import sttp.tapir.json.json4s._
import sttp.tapir.server.pekkohttp.PekkoHttpServerInterpreter
import sttp.tapir.swagger.bundle.SwaggerInterpreter
import sttp.tapir.generic.auto._
import java.util.UUID
import scala.concurrent.{ExecutionContext, Future}

case class ClientInfo(
  clientIP: String,
  userAgent: String
)

case class ServiceInfo(
  instanceUUID: String,
  startedOn: String,
  version: String,
  buildDate: String
)

case class SpyRouting(dependencies: ServiceDependencies) extends Routing with DateTimeTools {
  private val logger                = LoggerFactory.getLogger(getClass)
  implicit val ec: ExecutionContext = ExecutionContext.global

  val apiURL       = dependencies.config.spy.site.apiURL
  val meta         = dependencies.config.spy.metaInfo
  val startedDate  = now()
  val instanceUUID = UUID.randomUUID().toString

  // Logic
  def getServiceInfo: Future[Either[Unit, ServiceInfo]] = Future.successful {
    Right(
      ServiceInfo(
        instanceUUID = instanceUUID,
        startedOn = epochToUTCDateTime(startedDate).toString,
        version = meta.version,
        buildDate = meta.buildDateTime.getOrElse("unknown")
      )
    )
  }

  def getMyIp(ip: Option[String]): Future[Either[Unit, String]] = Future.successful {
    val ipStr = ip.getOrElse("unknown")
    logger.info(s"IP returned to client : $ipStr")
    Right(ipStr)
  }

  def getMyClient(userAgent: Option[String], ip: Option[String]): Future[Either[Unit, ClientInfo]] = Future.successful {
    val clientInfo = ClientInfo(
      clientIP = ip.getOrElse("unknown"),
      userAgent = userAgent.getOrElse("unknown")
    )
    logger.info(s"ClientInfo returned to client : $clientInfo")
    Right(clientInfo)
  }

  // Endpoints
  val infoEndpoint = endpoint.get
    .in("api" / "info")
    .out(jsonBody[ServiceInfo])
    .name("info")
    .description("General information about the service")

  val myipEndpoint = endpoint.get
    .in("api" / "myip")
    .in(clientIp)
    .out(jsonBody[String])
    .name("myip")
    .description("Get my ip address")

  val myclientEndpoint = endpoint.get
    .in("api" / "myclient")
    .in(header[Option[String]]("User-Agent"))
    .in(clientIp)
    .out(jsonBody[ClientInfo])
    .name("myclient")
    .description("Get various information about my http client")

  // Routes
  val infoRoute     = PekkoHttpServerInterpreter().toRoute(infoEndpoint.serverLogic(_ => getServiceInfo))
  val myipRoute     = PekkoHttpServerInterpreter().toRoute(myipEndpoint.serverLogic(ip => getMyIp(ip)))
  val myclientRoute = PekkoHttpServerInterpreter().toRoute(myclientEndpoint.serverLogic { case (ua, ip) => getMyClient(ua, ip) })

  val endpoints = List(infoEndpoint, myipEndpoint, myclientEndpoint)

  val swaggerEndpoints = SwaggerInterpreter().fromEndpoints[Future](endpoints, "spy service", "1.1.0")
  val swaggerRoute     = PekkoHttpServerInterpreter().toRoute(swaggerEndpoints)

  override def routes: Route = {
    import org.apache.pekko.http.scaladsl.server.Directives.concat
    concat(infoRoute, myipRoute, myclientRoute, swaggerRoute)
  }
}
