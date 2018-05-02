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
package snowplow.enrich.common
package enrichments
package registry

// Java
import java.net.{InetAddress, URI}

// joda-time
import org.joda.time.DateTime

// Specs2, Scalaz-Specs2 & ScalaCheck
import org.specs2.matcher.DataTables
import org.specs2.scalaz.ValidationMatchers
import org.specs2.{ScalaCheck, Specification}

// Scalaz
import scalaz._

class IabEnrichmentSpec extends Specification with DataTables with ValidationMatchers with ScalaCheck {
  def is =
    s2"""
  This is a specification to test the IabEnrichment
  performCheck should correctly perform IAB checks if possible      $e1
  """

  // When testing, localMode is set to true, so the URIs are ignored and the databases are loaded from test/resources
  val config = IabEnrichment(
    Some(("ip", new URI("/ignored-in-local-mode/"), "ip_exclude_current_cidr.txt")),
    Some(("ua_exclude", new URI("/ignored-in-local-mode/"), "exclude_current.txt")),
    Some(("ua_include", new URI("/ignored-in-local-mode/"), "include_current.txt")),
    None,
    None,
    true
  )

  def e1 =
    "SPEC NAME"                 || "USER AGENT"  | "IP ADDRESS"     | "EXPECTED SPIDER OR ROBOT" | "EXPECTED CATEGORY" | "EXPECTED REASON"   | "EXPECTED PRIMARY IMPACT" |
      "null UA/IP"              !! null          ! null             ! false                      ! "BROWSER"           ! "PASSED_ALL"        ! "NONE" |
      "valid UA/IP"             !! "Xdroid"      ! "192.168.0.1"    ! false                      ! "BROWSER"           ! "PASSED_ALL"        ! "NONE" |
      "valid UA, excluded IP"   !! "Mozilla/5.0" ! "192.168.151.21" ! true                       ! "SPIDER_OR_ROBOT"   ! "FAILED_IP_EXCLUDE" ! "UNKNOWN" |
      "invalid UA, excluded IP" !! "xonitor"     ! "192.168.0.1"    ! true                       ! "SPIDER_OR_ROBOT"   ! "FAILED_UA_INCLUDE" ! "UNKNOWN" |> {
      (_, userAgent, ipAddress, expectedSpiderOrRobot, expectedCategory, expectedReason, expectedPrimaryImpact) =>
        {
          config.performCheck(userAgent, ipAddress, DateTime.now()) must beLike {
            case Success(check) =>
              check.isSpiderOrRobot must_== expectedSpiderOrRobot and
                (check.getCategory.toString must_== expectedCategory) and
                (check.getReason.toString must_== expectedReason) and
                (check.getPrimaryImpact.toString must_== expectedPrimaryImpact)
          }
        }
    }
}
