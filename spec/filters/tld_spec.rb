require "logstash/devutils/rspec/spec_helper"
require "logstash/filters/tld"

describe LogStash::Filters::Tld do
  describe "Set to TLD" do
    config <<-CONFIG
      filter {
        tld {
        }
      }
    CONFIG

#{
#       "message" => "google.com",
#      "@version" => "1",
#    "@timestamp" => "2015-01-22T17:33:19.669Z",
#          "host" => "homer",
#      "sequence" => 0,
#           "tld" => {
#              "tld" => "com",
#              "sld" => "google",
#              "trd" => nil,
#           "domain" => "google.com",
#        "subdomain" => nil
#    }


    sample("message" => "google.com") do
      insist { subject["tld"]["tld"] } == "com"
      insist { subject["tld"]["sld"] } == "google"
      insist { subject["tld"]["trd"] } == nil
      insist { subject["tld"]["domain"] } == "google.com"
      insist { subject["tld"]["subdomain"] } == nil
    end

    sample("message" => "google.co.uk") do
      insist { subject["tld"]["tld"] } == "co.uk"
      insist { subject["tld"]["sld"] } == "google"
      insist { subject["tld"]["trd"] } == nil
      insist { subject["tld"]["domain"] } == "google.co.uk"
      insist { subject["tld"]["subdomain"] } == nil
    end

    sample("message" => "www.google.com") do
      insist { subject["tld"]["tld"] } == "com"
      insist { subject["tld"]["sld"] } == "google"
      insist { subject["tld"]["trd"] } == "www"
      insist { subject["tld"]["domain"] } == "google.com"
      insist { subject["tld"]["subdomain"] } == "www.google.com"
    end

  end
end
