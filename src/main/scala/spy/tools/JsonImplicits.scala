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

import com.github.plokhotnyuk.jsoniter_scala.core.JsonValueCodec
import com.github.plokhotnyuk.jsoniter_scala.macros.{CodecMakerConfig, JsonCodecMaker}
import spy.model.ClientInfo
import spy.routing.{Health, ServiceInfo}

/** jsoniter-scala codecs used by both tapir endpoints and plain pekko-http routes.
  *
  * None values and empty collections are not rendered, default values are always rendered.
  */
trait JsonImplicits {
  given stringCodec: JsonValueCodec[String]           = JsonCodecMaker.make
  given healthCodec: JsonValueCodec[Health]           = JsonCodecMaker.make(JsonImplicits.config)
  given serviceInfoCodec: JsonValueCodec[ServiceInfo] = JsonCodecMaker.make(JsonImplicits.config)
  given clientInfoCodec: JsonValueCodec[ClientInfo]   = JsonCodecMaker.make(JsonImplicits.config)
}

object JsonImplicits extends JsonImplicits {
  inline def config: CodecMakerConfig = CodecMakerConfig.withTransientDefault(false)
}
