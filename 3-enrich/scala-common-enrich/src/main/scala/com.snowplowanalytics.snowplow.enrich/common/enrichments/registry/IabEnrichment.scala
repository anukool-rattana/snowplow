/*
 * Copyright (c) 2012-2018 Snowplow Analytics Ltd. All rights reserved.
 *
 * This program is licensed to you under the Apache License Version 2.0,
 * and you may not use this file except in compliance with the Apache License Version 2.0.
 * You may obtain a copy of the Apache License Version 2.0 at http://www.apache.org/licenses/LICENSE-2.0.
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the Apache License Version 2.0 is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Apache License Version 2.0 for the specific language governing permissions and limitations there under.
 */
package com.snowplowanalytics
package snowplow
package enrich
package common
package enrichments
package registry

// Java
import java.io.File
import java.net.{InetAddress, URI}

// joda-time
import org.joda.time.DateTime

// Scala
import scala.util.control.NonFatal

// Scalaz
import scalaz.Scalaz._
import scalaz._

// json4s
import org.json4s.{DefaultFormats, Extraction, JObject, JValue}
import org.json4s.JsonDSL._

// Iglu
import iglu.client.validation.ProcessingMessageMethods._
import iglu.client.{SchemaCriterion, SchemaKey}

// IAB client
import iab.spidersandrobotsclient.{IabClient, IabResponse}

// This project
import utils.{ConversionUtils, ScalazJson4sUtils}

/**
 * Companion object. Lets us create an IabEnrichment
 * instance from a JValue.
 */
object IabEnrichment extends ParseableEnrichment {

  val supportedSchema = SchemaCriterion("com.snowplowanalytics.snowplow.enrichments",
                                        "iab_spiders_and_robots_enrichment",
                                        "jsonschema",
                                        1,
                                        0)

  /**
   * Creates an IabEnrichment instance from a JValue.
   *
   * @param config    The iab_spiders_and_robots_enrichment JSON
   * @param schemaKey The SchemaKey provided for the enrichment
   *                  Must be a supported SchemaKey for this enrichment
   * @param localMode Whether to use the local IAB database file
   *                  Enabled for tests
   * @return a configured IabEnrichment instance
   */
  def parse(config: JValue, schemaKey: SchemaKey, localMode: Boolean): ValidatedNelMessage[IabEnrichment] =
    isParseable(config, schemaKey).flatMap(conf => {
      def uri(name: String) = getUriTupleFromName(conf, name).sequenceU

      def string(name: String) = getStringFromName(conf, name).sequenceU

      (uri("ipFile")               |@| uri("excludeUseragentFile") |@| uri("includeUseragentFile")
        |@| string("httpUsername") |@| string("httpPassword")) {
        IabEnrichment(_, _, _, _, _, localMode)
      }
    })

  /**
   * Creates (URI, String) tuples used in the IabEnrichment case class.
   *
   * @param config The iab_spiders_and_robots_enrichment JSON
   * @param name   The name of the field.
   *             e.g. "ipFile", "excluseUseragentFile", "includeUseragentFile"
   * @return None if the field does not exist,
   *         Some(Failure) if the URI is invalid,
   *         Some(Success) if it is found
   */
  private def getUriTupleFromName(config: JValue, name: String): Option[ValidatedNelMessage[(String, URI, String)]] =
    if (ScalazJson4sUtils.fieldExists(config, "parameters", name)) {
      val uri = ScalazJson4sUtils.extract[String](config, "parameters", name, "uri")
      val db  = ScalazJson4sUtils.extract[String](config, "parameters", name, "database")

      (uri.toValidationNel |@| db.toValidationNel) { (uri, db) =>
        for {
          u <- getDatabaseUri(uri, db).toValidationNel: ValidatedNelMessage[URI]
        } yield (name, u, db)

      }.flatMap(x => x).some

    } else None

  /**
   * Extracts simple string fields from an enrichment JSON.
   *
   * @param config The iab_spiders_and_robots_enrichment JSON
   * @param name   The name of the lookup:
   *               "geo", "isp", "organization", "domain"
   * @return None if the field does not exist,
   *         Some(Success) if it is found
   */
  private def getStringFromName(config: JValue, name: String): Option[ValidatedNelMessage[String]] =
    if (ScalazJson4sUtils.fieldExists(config, "parameters", name)) {
      ScalazJson4sUtils.extract[String](config, "parameters", name).toValidationNel.some
    } else None

  /**
   * Convert the path to the IAB file from a
   * String to a Validation[URI].
   *
   * @param uri      URI to the IAB database file
   * @param database Name of the IAB database
   * @return a Validation-boxed URI
   */
  private def getDatabaseUri(uri: String, database: String): ValidatedMessage[URI] =
    ConversionUtils
      .stringToUri(uri + "/" + database)
      .flatMap(_ match {
        case Some(u) => u.success
        case None    => "URI to IAB file must be provided".fail
      })
      .toProcessingMessage
}

/**
 * Contains enrichments based on IAB Spiders&Robots lookup.
 *
 * @param ipFileTuple        (Full URI to the IAB excluded IP list, database name)
 * @param excludeUaFileTuple (Full URI to the IAB excluded user agent list, database name)
 * @param includeUaFileTuple (Full URI to the IAB included user agent list, database name)
 * @param httpUsername       Optional username for basic HTTP authentication
 * @param httpPassword       Optional password for basic HTTP authentication
 * @param localMode          Whether to use the local database file. Enabled for tests.
 */
case class IabEnrichment(
  ipFileTuple: Option[(String, URI, String)],
  excludeUaFileTuple: Option[(String, URI, String)],
  includeUaFileTuple: Option[(String, URI, String)],
  httpUsername: Option[String],
  httpPassword: Option[String],
  localMode: Boolean
) extends Enrichment {

  private type DbEntry = Option[(Option[URI], String)]
  private val schemaUri =
    "iglu:com.snowplowanalytics.snowplow.enrichments/iab_spiders_and_robots_enrichment/jsonschema/1-0-0"
  private implicit val formats = DefaultFormats

  // Construct a Tuple3 of all IAB files
  private val dbs: (DbEntry, DbEntry, DbEntry) = {

    def db(dbPath: Option[(String, URI, String)]): DbEntry = dbPath.map {
      case (name, uri, file) =>
        if (localMode) {
          (None, getClass.getResource(file).toURI.getPath)
        } else {
          (Some(uri), name)
        }
    }

    (db(ipFileTuple), db(excludeUaFileTuple), db(includeUaFileTuple))
  }

  // Create an IAB client based on the IAB files list
  private val iabClient = {
    def file(db: DbEntry): File = new File(db.get._2)

    new IabClient(file(dbs._1), file(dbs._2), file(dbs._3))
  }

  /**
   * Get the IAB response containing information about whether an event is a
   * spider or robot using the IAB client library.
   *
   * @param userAgent  User agent used to perform the check
   * @param ipAddress  IP address used to perform the check
   * @param accurateAt Date of the event, used to determine whether entries in the
   *                   IAB list are relevant or outdated
   * @return an IabResponse object
   */
  private[enrichments] def performCheck(userAgent: String,
                                        ipAddress: String,
                                        accurateAt: DateTime): Validation[Throwable, IabResponse] =
    Validation.fromTryCatch(iabClient.checkAt(userAgent, InetAddress.getByName(ipAddress), accurateAt.toDate))

  /**
   * Get the IAB response as a JSON context for a specific event
   *
   * @param userAgent  enriched event optional user agent
   * @param ipAddress  enriched event optional IP address
   * @param accurateAt enriched event optional datetime
   * @return IAB response as a self-describing JSON object
   */
  def getIabContext(userAgent: Option[String],
                    ipAddress: Option[String],
                    accurateAt: Option[DateTime]): Validation[String, JObject] =
    try {
      getIab(userAgent, ipAddress, accurateAt).map(addSchema)
    } catch {
      case NonFatal(exc) => exc.toString.fail
    }

  /**
   * Get IAB check response received from the client library and extracted as a JSON object
   *
   * @param userAgent enriched event optional user agent
   * @param ipAddress enriched event optional IP address
   * @param time      enriched event optional datetime
   * @return IAB response as JSON object
   */
  private def getIab(userAgent: Option[String],
                     ipAddress: Option[String],
                     time: Option[DateTime]): Validation[String, JObject] =
    (userAgent, ipAddress, time) match {
      case (Some(ua), Some(ip), Some(t)) =>
        performCheck(ua, ip, t) match {
          case Success(response) =>
            Extraction.decompose(response) match {
              case obj: JObject => obj.success
              case _            => s"Couldn't transform IAB response $response into JSON".fail
            }
          case Failure(throwable) => s"${throwable.getMessage}".fail
        }
      case _ =>
        s"One of required event fields missing. user agent: $userAgent, ip address: $ipAddress, time: $time".fail
    }

  /**
   * Add Iglu URI to JSON Object
   *
   * @param context IAB context as JSON Object
   * @return JSON Object wrapped as Self-describing JSON
   */
  private def addSchema(context: JObject): JObject =
    ("schema", schemaUri) ~ (("data", context))
}
