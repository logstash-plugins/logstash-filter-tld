# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"


class LogStash::Filters::Tld < LogStash::Filters::Base

  config_name "tld"

  # The source field to parse
  config :source, :validate => :string, :default => "message"

  # The target field to place tld fields
  config :target, :validate => :string, :default => "tld"

  # Allows private (non-ICANN) domain parsing
  config :parse_private, :validate => :boolean, :default => false

  public
  def register
    # Add instance variables
    require 'public_suffix'
    # unfortunately public_suffix 1.4.6 requires this setting to be global
    PublicSuffix::List.private_domains = @parse_private
  end # def register

  public
  def filter(event)

    if @source and PublicSuffix.valid?(event.get(@source))
      domain = PublicSuffix.parse(event.get(@source))

      h = Hash.new
      h['tld'] = domain.tld
      h['sld'] = domain.sld
      h['trd'] = domain.trd
      h['domain'] = domain.domain
      h['subdomain'] = domain.subdomain
      event.set(@target, h)

      filter_matched(event)
    end
  end # def filter
end # class LogStash::Filters::Example
