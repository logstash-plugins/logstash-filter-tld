require "logstash/devutils/rspec/spec_helper"
require "logstash/filters/tld"
require 'public_suffix'

describe LogStash::Filters::Tld do
  context "with privte domains enabled" do

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
        sample("message" => "foo.bar.appspot.com") do
          insist { subject["tld"]["tld"] } == "appspot.com"
          insist { subject["tld"]["sld"] } == "bar"
          insist { subject["tld"]["trd"] } == "foo"
          insist { subject["tld"]["domain"] } == "bar.appspot.com"
          insist { subject["tld"]["subdomain"] } == "foo.bar.appspot.com"
        end
     end

      describe "Include only specified fields" do
        config <<-CONFIG
          filter {
            tld {
               fields => [ tld , sld ]
            }
          }
        CONFIG

        sample("message" => "google.co.uk") do
          insist { subject["tld"].length } == 2
          insist { subject["tld"]["tld"] } == "co.uk"
          insist { subject["tld"]["sld"] } == "google"
        end
      end
  end
  context "with privte domains disabled" do
      config <<-CONFIG
        filter {
          tld {
             private_domains => false
          }
        }
      CONFIG

      describe "Disable private domain parsing" do
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

        sample("message" => "foo.bar.appspot.com") do
          insist { subject["tld"]["tld"] } == "com"
          insist { subject["tld"]["sld"] } == "appspot"
          insist { subject["tld"]["trd"] } == "foo.bar"
          insist { subject["tld"]["domain"] } == "appspot.com"
          insist { subject["tld"]["subdomain"] } == "foo.bar.appspot.com"
        end
      end
  end
end
