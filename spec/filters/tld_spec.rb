require "logstash/devutils/rspec/spec_helper"
require "logstash/filters/tld"

describe LogStash::Filters::Tld do
  describe "default TLD config" do
    config <<-CONFIG
      filter {
        tld {
        }
      }
    CONFIG

    sample("message" => "google.com") do
      insist { subject.get("tld")["tld"] } == "com"
      insist { subject.get("tld")["sld"] } == "google"
      insist { subject.get("tld")["trd"] } == nil
      insist { subject.get("tld")["domain"] } == "google.com"
      insist { subject.get("tld")["subdomain"] } == nil
    end

    sample("message" => "google.co.uk") do
      insist { subject.get("tld")["tld"] } == "co.uk"
      insist { subject.get("tld")["sld"] } == "google"
      insist { subject.get("tld")["trd"] } == nil
      insist { subject.get("tld")["domain"] } == "google.co.uk"
      insist { subject.get("tld")["subdomain"] } == nil
    end

    sample("message" => "www.google.com") do
      insist { subject.get("tld")["tld"] } == "com"
      insist { subject.get("tld")["sld"] } == "google"
      insist { subject.get("tld")["trd"] } == "www"
      insist { subject.get("tld")["domain"] } == "google.com"
      insist { subject.get("tld")["subdomain"] } == "www.google.com"
    end

    sample("message" => "example.blogspot.com") do
      insist { subject.get("tld")["tld"] } == "com"
      insist { subject.get("tld")["sld"] } == "blogspot"
      insist { subject.get("tld")["trd"] } == "example"
      insist { subject.get("tld")["domain"] } == "blogspot.com"
      insist { subject.get("tld")["subdomain"] } == "example.blogspot.com"
    end
  end

  describe "default TLD config" do
    config <<-CONFIG
      filter {
        tld {
          ignore_private => false
        }
      }
    CONFIG

    sample("message" => "example.blogspot.com") do
      insist { subject.get("tld")["tld"] } == "blogspot.com"
      insist { subject.get("tld")["sld"] } == "example"
      insist { subject.get("tld")["trd"] } == nil
      insist { subject.get("tld")["domain"] } == "example.blogspot.com"
      insist { subject.get("tld")["subdomain"] } == nil
    end
  end
end
