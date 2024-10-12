package spy.routing

import org.apache.pekko.http.scaladsl.model.HttpCharsets.*
import org.apache.pekko.http.scaladsl.model.{HttpEntity, HttpResponse}
import org.apache.pekko.http.scaladsl.model.MediaTypes.`text/html`
import org.apache.pekko.http.scaladsl.server.Directives.*
import org.apache.pekko.http.scaladsl.server.Route
import spy.ServiceDependencies
import spy.templates.html.HomeTemplate

import scala.concurrent.ExecutionContextExecutor

case class HomeContext(
  context: PageContext
)

case class HomeRouting(dependencies: ServiceDependencies) extends Routing {
  override def routes: Route = home

  val site = dependencies.config.spy.site
  val pageContext = PageContext(dependencies.config.spy)
  val homeContext = HomeContext(context = pageContext)
  val homeContent = HomeTemplate.render(homeContext).toString()
  val homeContentType = `text/html` withCharset `UTF-8`

  implicit val ec: ExecutionContextExecutor = scala.concurrent.ExecutionContext.global

  def home: Route = pathEndOrSingleSlash {
    get {
      complete {
        HttpResponse(entity = HttpEntity(homeContentType, homeContent), headers = noClientCacheHeaders)
      }
    }
  }
}
