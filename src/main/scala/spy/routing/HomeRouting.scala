package spy.routing

import akka.http.scaladsl.model.HttpCharsets._
import akka.http.scaladsl.model.{HttpEntity, HttpResponse}
import akka.http.scaladsl.model.MediaTypes.`text/html`
import akka.http.scaladsl.server.Directives._
import akka.http.scaladsl.server.Route
import spy.ServiceDependencies
import spy.tools.Templating
import yamusca.imports._
import yamusca.implicits._

case class HomeContext(
  context: PageContext
)

case class HomeRouting(dependencies: ServiceDependencies) extends Routing {
  override def routes: Route = home

  val site = dependencies.config.spy.site
  val pageContext = PageContext(dependencies.config.spy)

  implicit val ec = scala.concurrent.ExecutionContext.global
  implicit val pageContextConverter = ValueConverter.deriveConverter[PageContext]
  implicit val homeContextConverter = ValueConverter.deriveConverter[HomeContext]

  val templating: Templating = Templating(dependencies.config)
  val homeLayout = (context: Context) => templating.makeTemplateLayout("spy/templates/home.html")(context)

  def home: Route = pathEndOrSingleSlash {
    get {
      complete {
        val homeContext = HomeContext(
          context = pageContext
        )
        val content = homeLayout(homeContext.asContext)
        val contentType = `text/html` withCharset `UTF-8`
        HttpResponse(entity = HttpEntity(contentType, content), headers = noClientCacheHeaders)
      }
    }
  }
}
