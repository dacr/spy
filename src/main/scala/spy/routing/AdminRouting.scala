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

import akka.http.scaladsl.server.Directives._
import akka.http.scaladsl.server.Route
import de.heikoseeberger.akkahttpjson4s.Json4sSupport._
import spy.ServiceDependencies


case class Health(alive: Boolean = true, description: String = "alive")

object AdminRouting {
  val alive = Health()
}

case class AdminRouting(dependencies: ServiceDependencies) extends Routing {
  private def ping: Route = path("health") {
    get {
      complete(AdminRouting.alive)
    }
  }

  override def routes: Route = ping
}
