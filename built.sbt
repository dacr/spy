name         := "spy"
organization := "fr.janalyse"
description  := "I'm not what you might think"

licenses += "NON-AI-APACHE2" -> url(s"https://github.com/non-ai-licenses/non-ai-licenses/blob/main/NON-AI-APACHE2")

scalaVersion := "3.6.4"

scalacOptions := Seq("-unchecked", "-deprecation", "-encoding", "utf8", "-feature")

lazy val versions = new {
  // client side dependencies
  val swaggerui = "5.20.7"
  val bootstrap = "5.3.5"
  val jquery    = "3.7.1"
  val awesome   = "6.7.2"

  // server side dependencies
  val pureConfig      = "0.17.8"
  val pekko           = "1.1.3"
  val pekkoHttp       = "1.1.0"
  val pekkoHttpJson4s = "3.1.0"
  val json4s          = "4.0.7"
  val logback         = "1.5.18"
  val slf4j           = "2.0.17"
  val scalatest       = "3.2.19"
  val commonsio       = "2.19.0"
  val webjarsLocator  = "0.52"
}

// client side dependencies
libraryDependencies ++= Seq(
  "org.webjars" % "swagger-ui"   % versions.swaggerui,
  "org.webjars" % "bootstrap"    % versions.bootstrap,
  "org.webjars" % "jquery"       % versions.jquery,
  "org.webjars" % "font-awesome" % versions.awesome
)

// server side dependencies
libraryDependencies ++= Seq(
  "com.github.pureconfig" %% "pureconfig-core"      % versions.pureConfig,
  "org.json4s"            %% "json4s-jackson"       % versions.json4s,
  "org.json4s"            %% "json4s-ext"           % versions.json4s,
  "org.apache.pekko"      %% "pekko-actor-typed"    % versions.pekko,
  "org.apache.pekko"      %% "pekko-http"           % versions.pekkoHttp,
  "org.apache.pekko"      %% "pekko-http-caching"   % versions.pekkoHttp,
  "org.apache.pekko"      %% "pekko-stream"         % versions.pekko,
  "org.apache.pekko"      %% "pekko-slf4j"          % versions.pekko,
  "org.apache.pekko"      %% "pekko-testkit"        % versions.pekko     % Test,
  "org.apache.pekko"      %% "pekko-stream-testkit" % versions.pekko     % Test,
  "org.apache.pekko"      %% "pekko-http-testkit"   % versions.pekkoHttp % Test,
  "com.github.pjfanning"  %% "pekko-http-json4s"    % versions.pekkoHttpJson4s,
  "org.slf4j"              % "slf4j-api"            % versions.slf4j,
  "ch.qos.logback"         % "logback-classic"      % versions.logback,
  "commons-io"             % "commons-io"           % versions.commonsio,

  "org.scalatest"         %% "scalatest"            % versions.scalatest % Test,
  "org.webjars"            % "webjars-locator"      % versions.webjarsLocator
)

Compile / mainClass    := Some("spy.Main")
packageBin / mainClass := Some("spy.Main")

Test / testOptions += {
  val rel = scalaVersion.value.split("[.]").take(2).mkString(".")
  Tests.Argument(
    "-oDF", // -oW to remove colors
    "-u",
    s"target/junitresults/scala-$rel/"
  )
}

enablePlugins(JavaServerAppPackaging)
enablePlugins(SbtTwirl)

homepage   := Some(url("https://github.com/dacr/spy"))
scmInfo    := Some(ScmInfo(url(s"https://github.com/dacr/spy.git"), s"git@github.com:dacr/spy.git"))
developers := List(
  Developer(
    id = "dacr",
    name = "David Crosson",
    email = "crosson.david@gmail.com",
    url = url("https://github.com/dacr")
  )
)
