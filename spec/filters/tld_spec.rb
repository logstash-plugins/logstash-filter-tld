require "logstash/devutils/rspec/spec_helper"
require "insist"
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
      insist { subject.get("tld")["tld"] } == "com"
      insist { subject.get("tld")["top_level_domain"] } == "com"
      insist { subject.get("tld")["sld"] } == "google"
      insist { subject.get("tld")["trd"] } == nil
      insist { subject.get("tld")["domain"] } == "google.com"
      insist { subject.get("tld")["subdomain"] } == nil
    end

    sample("message" => "google.co.uk") do
      insist { subject.get("tld")["tld"] } == "co.uk"
      insist { subject.get("tld")["top_level_domain"] } == "co.uk"
      insist { subject.get("tld")["sld"] } == "google"
      insist { subject.get("tld")["trd"] } == nil
      insist { subject.get("tld")["domain"] } == "google.co.uk"
      insist { subject.get("tld")["subdomain"] } == nil
    end

    sample("message" => "www.google.com") do
      insist { subject.get("tld")["tld"] } == "com"
      insist { subject.get("tld")["top_level_domain"] } == "com"
      insist { subject.get("tld")["sld"] } == "google"
      insist { subject.get("tld")["trd"] } == "www"
      insist { subject.get("tld")["domain"] } == "google.com"
      insist { subject.get("tld")["subdomain"] } == "www.google.com"
    end

  end
end
