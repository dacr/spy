/*
 * Copyright 2021 David Crosson
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

import akka.http.scaladsl.model._
import akka.http.scaladsl.server.Directives._
import akka.http.scaladsl.server.Route
import de.heikoseeberger.akkahttpjson4s.Json4sSupport._
import spy.ServiceDependencies
import spy.tools.DateTimeTools

import java.util.UUID

case class SpyRouting(dependencies: ServiceDependencies) extends Routing with DateTimeTools {
  val apiURL = dependencies.config.spy.site.apiURL
  val meta = dependencies.config.spy.metaInfo
  val startedDate = now()
  val instanceUUID = UUID.randomUUID().toString

  implicit val ec = scala.concurrent.ExecutionContext.global

  override def routes: Route = pathPrefix("api") {
    concat(info)
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

}
